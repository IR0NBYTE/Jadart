"""Tier 2: control-flow reconstruction (jadart).

Builds a control-flow graph from a function's annotated disassembly and structures
it into if/else and while constructs, so a method body reads as nested pseudo-Dart
instead of a flat labelled listing. This tier stops at the CONTROL-FLOW skeleton,
with best-effort conditions plus the calls and string constants the Tier 1 annotator
already resolved. Expression reconstruction (recovering `balance -= amount` from
sub/stur) is Tier 3 and lives in expr.py. Irreducible regions fall back to `goto Ln`
(honest, never wrong).

CFG terminators: b, b.<cond>, cbz/cbnz/tbz/tbnz, ret, br, bx, and on arm32 every other
instruction that writes PC without being a call, read off its word (branches.exits).
Calls (bl/blr) fall through.
Structuring uses forward dominators (loop back edges) + post-dominators (if merge
points), both via the Cooper-Harvey-Kennedy iterative algorithm.
"""
from __future__ import annotations

import bisect
import itertools
from collections import Counter
from operator import attrgetter
from dataclasses import dataclass, field

_COND_TERMS = ("cbz", "cbnz", "tbz", "tbnz")

#: The arm condition codes, exactly. arm64 spells a conditional branch `b.gt` and arm32
#: spells it `bgt`, so the second form has to be recognised by an exact suffix match and
#: not by "starts with b": `bl` is a CALL, and `bic`, `bfc` and `bx` are not branches at
#: all. Matching loosely would turn a call into a conditional edge, which cfgcheck would
#: then confirm as a control-flow claim the code does not make.
_CCS = frozenset({"eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
                  "hi", "ls", "ge", "lt", "gt", "le"})


def cond_of(mn: str) -> str:
    """The condition code a conditional branch carries, or "" if it is not one."""
    if mn.startswith("b.") and mn[2:] in _CCS:
        return mn[2:]
    if len(mn) == 3 and mn[0] == "b" and mn[1:] in _CCS:
        return mn[1:]
    return ""


def _is_cond(mn: str) -> bool:
    return bool(cond_of(mn)) or mn in _COND_TERMS


#: Instructions that trap and never continue at the next one: `brk`, `hlt` and `udf` on
#: arm64, `bkpt`, `udf` and `trap` on arm32 (capstone's name for the UDF word 0xe7ffdefe).
#: Dart emits `brk #0` (`bkpt #0` on arm32) after a call that does not return, so the
#: code after one is reached, when at all, by a branch from somewhere else. None of them
#: takes a condition, so the mnemonic is the whole test.
TRAPS = frozenset({"brk", "hlt", "udf", "bkpt", "trap"})


def _is_term(mn: str) -> bool:
    # `bx` is arm32's return (`bx lr`) and also its indirect branch, which is the same
    # pair of roles arm64 splits between `ret` and `br`.
    return mn in ("b", "ret", "br", "bx") or _is_cond(mn)


def _target(op: str):
    if "#" not in op:
        return None
    t = op.rsplit("#", 1)[1].strip().rstrip("]!")
    try:
        return int(t, 16) if t.startswith("0x") else int(t)
    except ValueError:
        return None


#: exit_target for an exit that names no address: a return, or an indirect jump.
EXIT_RETURN, EXIT_INDIRECT = -2, -3


@dataclass
class Block:
    addr: int
    insns: list                 # (addr, mn, op, note)
    succ: list = field(default_factory=list)   # successor block addrs, ordered
    term: str = ""              # terminator mnemonic
    cond: str = ""              # readable branch condition (for cond terminators)
    #: Where a branch out of this function goes, when it has one. A `b` or a conditional
    #: whose target is outside [lo, hi) has no successor block to point at, and dropping
    #: it left the reader with a body that simply stopped, or ran on into whatever block
    #: the structurer happened to place next: 997 such sites on the clean fixture.
    #: Recording the address lets the renderer say `goto sub_0x...` instead of nothing.
    exit_target: int = -1
    #: "return" or "jump" when the last instruction leaves the function some other way
    #: than a direct branch: arm32's `pop {fp, pc}` or `ldr pc, [r4, #3]`, say. cexit
    #: when it does so only under a condition, and otherwise falls through to succ.
    exit: str = ""
    cexit: bool = False
    #: The instruction cut (disasm.MAX_INSNS) stops a long function before its end (#70).
    #: past_cut: exit_target lies in the part left undecoded, inside this function, so it
    #: is an address there and not another function's `sub_0x...`. cut_next: where this
    #: block falls through to past the cut, or -1; the not-taken arm of a conditional at
    #: the cut was recorded nowhere, and a backward one printed as `while (true) { }`.
    past_cut: bool = False
    cut_next: int = -1
    #: True when nothing runs past this block's last instruction although it is neither a
    #: branch nor a return: a trap, or a call to a stub that throws (`ends` in build_cfg).
    #: It has no successor, and `structure` steps from it to the block after it, because
    #: that code can be a catch entry which only an exception edge leads to.
    ends_path: bool = False


#: How an unsigned comparison is spelled: the signed operator with this in front of it,
#: `x1 u< x2`, as Binary Ninja's HLIL writes it. Dart has no unsigned comparison, so
#: there is no Dart spelling to borrow as `>>>` was for the unsigned shift, and the
#: signed operator is a different predicate whenever exactly one side has its top bit
#: set: `x1 < x2` passes the negative index that a bounds check, `cmp x1, x2; b.hs`,
#: rejects. Every unsigned operator printed is built here and nowhere else.
_UNSIGNED = "u"


def _unsigned(rel: str) -> str:
    return _UNSIGNED + rel


_NEG = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", "<=": ">", ">": "<="}
_NEG.update({_unsigned(a): _unsigned(b) for a, b in list(_NEG.items()) if a[0] in "<>"})


def _balanced(text: str) -> bool:
    depth = 0
    for ch in text:
        depth += (ch == "(") - (ch == ")")
        if depth < 0:
            return False
    return depth == 0


def negate_cond(cond: str) -> str:
    """Negate a condition (then-branch is the fallthrough = branch not taken).

    `a == b && c == d`, the `cmp; cmpeq` arm32 tests a 64-bit value with, negates to
    `a != b || c != d`. Flipping only the first operator printed `a != b && c == d`, and
    2,821 of the 2,827 such conditions in arm32-2.19.6's tier 2 read that way (#70). Only
    an operator outside every parenthesis is the condition's own: the one inside
    `(x >> 1)` or a call belongs to an operand."""
    if cond.startswith("!(") and cond.endswith(")") and _balanced(cond[2:-1]):
        return cond[2:-1]
    for op, dual in ((" && ", " || "), (" || ", " && ")):
        if op in cond:
            sides = cond.split(op)
            # a quote may hold the `&&` or `||`, in a string literal tier 3 substituted
            quoted = '"' in cond or "'" in cond
            if dual in cond or quoted or not all(map(_balanced, sides)):
                return f"!({cond})"
            sides = [negate_cond(s) for s in sides]
            if any(s.startswith("!(") for s in sides):
                return f"!({cond})"
            return dual.join(sides)
    parts, depth = cond.split(" "), 0
    for i, tok in enumerate(parts):
        if depth == 0 and tok in _NEG:
            parts[i] = _NEG[tok]
            return " ".join(parts)
        depth += tok.count("(") - tok.count(")")
    return f"!({cond})"


def _tok(t: str) -> str:
    """One operand as it should read in a condition. arm64 writes immediates as `#4`, and
    spells the constant zero as a register, which is not how a comparison against zero
    should read."""
    t = t.strip()
    if t in ("xzr", "wzr"):
        return "0"
    return t[1:] if t.startswith("#") else t


def _int(t: str):
    """`#0x1c` / `4` -> int, else None."""
    t = t.strip().lstrip("#").strip()
    try:
        return int(t, 16) if t.lower().startswith(("0x", "-0x")) else int(t)
    except ValueError:
        return None


#: Relational spelling for each condition code after an integer compare. hs, lo, hi and
#: ls read the carry: they compare the operands as unsigned, and printed with the signed
#: operators they were a different test (24 of 40 random entry states of `cmp x5, x6;
#: cset x0, lo` against a CPU, #371).
_REL = {"eq": "==", "ne": "!=", "lt": "<", "le": "<=", "gt": ">", "ge": ">=",
        "mi": "<", "pl": ">="}
_CARRY = {"cc": "<", "lo": "<", "cs": ">=", "hs": ">=", "ls": "<=", "hi": ">"}
_REL.update({cc: _unsigned(rel) for cc, rel in _CARRY.items()})

#: Flag sources that set C and V to constants rather than computing them: the logical
#: operations. After one of them only Z (eq/ne) and N (mi/pl) carry information, and a
#: carry-based branch means something the operands cannot express, `b.hi` after `tst`
#: is unconditionally FALSE, not `(a & b) > 0`. Measured on the corpus binary, the
#: compiler only ever emits eq/ne there, so this guard costs nothing and closes the hole.
_LOGICAL_FLAGS = ("tst", "ands", "bics")
_Z_N_ONLY = frozenset({"eq", "ne", "mi", "pl"})


def _cond_for(ctx, mn, op) -> str:
    """The condition of a branch, given the instructions before it on its one path.

    _cond_text reads the instruction right before the branch. On arm32 the compare is
    often a step further back, or is two compares (#70), and these are read here:
    `vcmp.f64; vmrs APSR_nzcv, fpscr` compares two doubles like `fcmp`, `cmp a, b;
    cmpeq c, d; beq` is `a == b && c == d` (and `bne` its negation), and `asrs rD, rS,
    #n` leaves the bit it shifted out in C and the shifted value in N and Z."""
    cc = cond_of(mn)
    last = ctx[-1] if ctx else None
    if last is None:
        return _cond_text(None, mn, op)
    _a, lm, lo_, _n = last
    if lm == "vmrs" and len(ctx) >= 2 and ctx[-2][1].startswith(("vcmp", "vcmpe")):
        a2, _m, vo, n2 = ctx[-2]
        return _cond_text((a2, "fcmp", vo, n2), mn, op)
    if lm == "cmpeq" and len(ctx) >= 2 and ctx[-2][1] == "cmp" and cc in ("eq", "ne"):
        one = _cond_text(ctx[-2], "b" + cc, "")
        two = _cond_text((last[0], "cmp", lo_, last[3]), "b" + cc, "")
        if "?" in one or "?" in two:
            return "?"
        return f"{one} && {two}" if cc == "eq" else f"{one} || {two}"
    if lm == "asrs":
        parts = [_tok(p) for p in lo_.split(",")]
        n = _int(parts[2]) if len(parts) == 3 else None
        # `asrs r0, r0, #1` overwrites its source, so a condition naming r0 would name
        # the shifted value rather than the one the flags came from; 2 of 1,316.
        if n is not None and n > 0 and parts[0] != parts[1]:
            src = parts[1]
            if cc in ("cc", "lo", "cs", "hs"):
                bit = f"{src} & 1" if n == 1 else f"({src} >> {n - 1}) & 1"
                return f"({bit}) {'==' if cc in ('cc', 'lo') else '!='} 0"
            if cc in _REL and cc in ("eq", "ne", "mi", "pl"):
                return f"({src} >> {n}) {_REL[cc]} 0"
    return _cond_text(last, mn, op)


def _cond_text(prev_cmp, mn, op) -> str:
    """Best-effort condition for a conditional terminator, from the preceding flag-setting
    instruction and the branch. Approximate (registers, not source names).

    Only `cmp` and `fcmp` compare their two operands against each other. The others set
    the flags from a computed value and are therefore comparisons against zero, `tst`
    ands, `cmn` adds. Treating them all as `cmp` turned `tst x1, x2; b.eq` into `x1 != x2`
    when it means `(x1 & x2) == 0`: not a near miss but the wrong predicate over the wrong
    values.
    """
    cc = cond_of(mn)
    if mn in ("cbz", "cbnz"):
        reg = op.split(",")[0].strip()
        return f"{reg} == 0" if mn == "cbz" else f"{reg} != 0"
    if mn in ("tbz", "tbnz"):
        # `tbz xN, #b, #target` tests ONE bit of xN. Rendering it as `bit(<the whole
        # operand string>)` put the branch target inside what read as a function call, so
        # the printed predicate named a value that is not an input to it at all. The
        # test itself is exact and has a Dart spelling.
        parts = [p.strip() for p in op.split(",")]
        bit = _int(parts[1]) if len(parts) >= 2 else None
        if bit is None:
            return f"? {'==' if mn == 'tbz' else '!='} ?"
        reg = parts[0]
        lhs = f"{reg} & 1" if bit == 0 else f"({reg} >> {bit}) & 1"
        return f"{lhs} == 0" if mn == "tbz" else f"{lhs} != 0"
    # mi/pl are "result negative"/"not negative"; against a zero right-hand side that is
    # exactly < and >=, which is also what they mean after a cmp.
    rel = _REL.get(cc, cc)
    lhs = rhs = "?"
    if prev_cmp:
        _a, pm, po, _n = prev_cmp
        parts = [_tok(p) for p in po.split(",")]
        if pm in ("fcmp", "fcmpe") and cc in ("vs", "vc") and len(parts) >= 2:
            # V after a floating-point compare is "unordered": one side is NaN. Printed
            # as `d0 vs d1` it named no predicate at all (#70).
            nan = (f"isNaN({parts[0]})" if parts[1] in ("0", "0.0", parts[0]) else
                   f"isNaN({parts[0]}) || isNaN({parts[1]})")
            return nan if cc == "vs" else f"!({nan})"
        if pm in ("fcmp", "fcmpe") and len(parts) >= 2:
            # Two doubles have no unsigned reading: the carry conditions after `fcmp`
            # are orderings of the two values, and keep the plain operators.
            lhs, rhs, rel = parts[0], parts[1], _CARRY.get(cc, rel)
        elif pm == "cmp" and len(parts) >= 2:
            lhs = parts[0]
            rhs = parts[1] if len(parts) == 2 else _shifted(parts[1:])
            if rhs is None:
                return "?"
        elif pm in ("subs", "negs") and len(parts) >= 3:
            # `subs xD, xA, xB` sets exactly the flags `cmp xA, xB` sets; xD is the
            # destination, and reading it as the left operand compared the wrong register
            # entirely. Naming the two sources is both exact and shorter than the
            # `(xA - xB) rel 0` form it replaces.
            rhs2 = parts[2] if len(parts) == 3 else _shifted(parts[2:])
            if rhs2 is None:
                return "?"
            lhs, rhs = parts[1], rhs2
        elif pm == "cmn" and len(parts) >= 2:
            lhs, rhs = f"({parts[0]} + {parts[1]})", "0"
            if cc in _CARRY:
                if len(parts) > 2 or cc in ("hi", "ls"):
                    return f"? {rel} ?"
                rel, rhs = _carry_out(cc, parts[0], parts[1])
        elif pm == "adds" and len(parts) >= 3:
            b = parts[2] if len(parts) == 3 else _shifted(parts[2:])
            if b is None:
                return "?"
            lhs, rhs = f"({parts[1]} + {b})", "0"
            if cc in _CARRY:
                if cc in ("hi", "ls"):
                    return f"? {rel} ?"
                rel, rhs = _carry_out(cc, parts[1], b)
        elif pm in _LOGICAL_FLAGS and cc in _Z_N_ONLY:
            a, b = (parts[0], parts[1]) if pm == "tst" else (
                (parts[1], parts[2]) if len(parts) >= 3 else (parts[0], parts[-1]))
            lhs, rhs = f"({a} & {'~' if pm == 'bics' else ''}{b})", "0"
    return f"{lhs} {rel} {rhs}"


def _carry_out(cc, a, b):
    """`(rel, rhs)` for the carry condition `cc` after `a + b`, the sum on the left.

    After an add the carry is the carry out of it, and the sum wrapped exactly when it
    is below either operand, read unsigned: hs is that, lo its negation. `(x5 + x6) >=
    0` for hs was the sign of the sum, another flag (15 of 40 entry states against a
    CPU, #371). The operand named is the constant where there is one and the first
    otherwise, which in an allocation's `adds x1, x0, x2` is the top it loaded and not
    the size it computed. hi and ls also read Z, two tests of the sum in one condition,
    and the callers leave them unspelled."""
    return _unsigned(_NEG[_CARRY[cc]]), b if _int(b) is not None else a


#: `cmp x0, x1, lsl #3` compares x0 against x1<<3, and dropping the third operand made
#: the rendered predicate name the wrong value: 134 sites on the clean fixture. Rendering
#: it keeps the comparison true to the instruction; a modifier with no spelling here
#: returns None so the caller falls back to `?` rather than printing a half-read compare.
_CFG_SHIFT = {"lsl": "<<", "lsr": ">>>", "asr": ">>"}


def _shifted(parts):
    """`['x1', 'lsl #3']` -> `x1 << 3`. None when the modifier is not a plain shift."""
    if len(parts) < 2:
        return parts[0] if parts else "?"
    tail = parts[1].strip().lower().split()
    if len(tail) == 2 and tail[0] in _CFG_SHIFT:
        amt = tail[1].lstrip("#")
        try:
            n = int(amt, 0)
        except ValueError:
            return None
        # An arm64 shift amount is 0..63. Anything else is not an encoding capstone can
        # produce, so it means the operand was not what it looked like; print nothing
        # rather than a shift that cannot happen.
        if not 0 <= n < 64:
            return None
        amt = str(n)
        # Parenthesised: `x9 + x10 << 1` re-parses as `(x9 + x10) << 1` in Dart, which
        # is not what the machine did.
        return f"({parts[0]} {_CFG_SHIFT[tail[0]]} {amt})"
    return None


def build_cfg(dis, exits=None, traps=TRAPS, cut_end=None,
              ends=frozenset()) -> tuple[dict, int]:
    """Return ({addr: Block}, entry_addr) for a function's disasm
    (list of (addr, mn, op, note)).

    `exits` is branches.exits for the same rows: on arm32 the instructions that leave the
    function without being a call or a direct branch. Without it only `ret`, `br` and
    `bx` do, and arm32's usual return, `pop {fp, pc}`, ran on into the code after it in a
    quarter of its functions (#45).

    `traps` are the mnemonics that end a block with no successor (#57).

    `ends` are the ADDRESSES of instructions nothing runs past although the mnemonic does
    not say so, which in practice means a `bl` to a runtime stub that throws. Only the
    caller knows which callee cannot return (expr._ends_path), so it has to say. Without
    it such a block falls through and the structurer renders a path the machine never
    takes: `nextFocus` is three one-instruction blocks, each a `bl` to the null-cast-error
    stub, and the last printed as `throw NullCastError(); goto L_0x12c928;`, a jump out of
    a throw (#234).

    `cut_end` is where the range ends when the instruction cut stopped `dis` short of it
    (disasm.cut_end), else None. A target from the end of `dis` up to it is inside this
    function, in code not decoded, and so is the fallthrough of the last instruction
    (Block.past_cut, Block.cut_next)."""
    if not dis:
        return {}, 0
    exits = exits or {}
    addrs = [d[0] for d in dis]
    lo, hi = addrs[0], addrs[-1] + 4
    cut = cut_end if cut_end is not None and cut_end > hi else None
    leaders = {lo}
    for i, (a, mn, op, _n) in enumerate(dis):
        if _is_term(mn) or mn in traps or a in exits or a in ends:
            if i + 1 < len(dis):
                leaders.add(dis[i + 1][0])
            if _is_cond(mn) or mn == "b":
                t = _target(op)
                if t is not None and lo <= t < hi:
                    leaders.add(t)
    leaders = sorted(leaders)
    blocks = {}
    for li, la in enumerate(leaders):
        end = leaders[li + 1] if li + 1 < len(leaders) else hi
        # `dis` is address-ordered, so a block is a contiguous slice. Scanning to the end
        # of the function for every leader made this insns x blocks, about two million
        # iterations on a 4000-instruction function, for a slice bisect finds directly.
        insns = dis[bisect.bisect_left(addrs, la):bisect.bisect_left(addrs, end)]
        blk = Block(addr=la, insns=insns)
        if insns:
            a, mn, op, _n = insns[-1]
            blk.term = mn
            ex = exits.get(a)
            if ex is not None:
                cc, is_return = ex
                blk.exit = "return" if is_return else "jump"
                if cc:
                    # Leaves only when the condition holds, so it also falls through.
                    blk.cexit = True
                    blk.cond = _cond_for(insns[:-1], "b" + cc, op)
                    blk.succ = [end] if end < hi else []
                else:
                    blk.succ = []
            # `bx` covers both of arm32's uses of it: `bx lr` returns and `bx rN` is
            # an indirect branch. Either way the successor is not in this function.
            elif mn in ("ret", "br", "bx"):
                blk.succ = []
            elif mn in traps or a in ends:
                # A trap ends its block with no successor. Falling through drew an edge
                # into the code after it, and tier 2 printed that code as running next:
                # 939 `brk` on the clean fixture sat mid-range (#57). A call that cannot
                # return is the same edge wearing a `bl`: the compiler puts no trap after
                # one it has nothing to fall into (#234).
                blk.succ = []
                blk.ends_path = True
            elif mn == "b":
                t = _target(op)
                if t is not None and lo <= t < hi:
                    blk.succ = [t]
                else:
                    # Leaves the function. No successor, but it does NOT fall through
                    # either, and the terminator has to be rendered or the trail ends
                    # silently. `exit_target` is what gets printed.
                    blk.succ = []
                    blk.exit_target = t if t is not None else -1
                    blk.past_cut = cut is not None and t is not None and hi <= t < cut
            elif _is_cond(mn):
                t = _target(op)
                ft = end if end < hi else None
                blk.cond = _cond_for(insns[:-1], mn, op)
                blk.succ = []
                if t is not None and lo <= t < hi:
                    blk.succ.append(t)      # taken
                else:
                    # The taken arm leaves the function. succ would then hold only the
                    # fallthrough, and emit_cond reads succ[0] as the TAKEN arm, so the
                    # rendered `if` ran its body exactly when the branch was NOT taken.
                    # With no fallthrough either, at the MAX_INSNS cut, the target was
                    # recorded nowhere and the `if` printed with both arms empty (#58).
                    blk.exit_target = t if t is not None else -1
                    blk.past_cut = cut is not None and t is not None and hi <= t < cut
                if ft is not None:
                    blk.succ.append(ft)     # fallthrough
            else:
                blk.succ = [end] if end < hi else []
            # The last decoded instruction, when it can fall through, falls into the part
            # the cut left out. One that ends a path never does, trap or throw: there is
            # nothing for it to fall into, inside the function or past the cut (#234).
            if cut is not None and end == hi and not blk.ends_path and (
                    _is_cond(mn) or blk.cexit or not (
                        mn in ("b", "ret", "br", "bx") or mn in TRAPS or blk.exit)):
                blk.cut_next = hi
        blocks[la] = blk
    _conditions_from_the_block_before(blocks)
    return blocks, lo


def _conditions_from_the_block_before(blocks, stop=frozenset()) -> None:
    """A branch alone in its block reads the flags its one predecessor left.

    `cmp r0, r1; blt X; bgt Y` is two branches on one compare, and the second starts a
    block of its own, so it had no compare in front of it and printed `? > ?`: 4,344
    conditions of arm32-2.19.6 (#70). When the block has a single predecessor that falls
    into it and that ends in a conditional branch or exit, which set no flags, the
    flags are that block's, so its instructions are the context; a chain of such blocks
    is followed up, a few steps at most. Not up past a block of `stop`, an entry the
    callers come in at as well, with flags no edge of the graph brings (#278)."""
    preds = {}
    for a, b in blocks.items():
        for s in b.succ:
            preds.setdefault(s, []).append(a)
    for a, blk in blocks.items():
        if not blk.cond or "?" not in blk.cond or len(blk.insns) != 1 or blk.cexit:
            continue
        at, ctx = a, []
        for _ in range(8):
            if at in stop:
                break
            p = preds.get(at, [])
            if len(p) != 1:
                break
            pb = blocks[p[0]]
            if not pb.insns or pb.insns[-1][0] + 4 != at:
                break                                   # not the block falling into it
            if not (_is_cond(pb.term) or pb.cexit):
                break                       # its last instruction may set flags
            ctx = pb.insns[:-1]
            if ctx:
                break
            at = p[0]
        if ctx:
            _a, mn, op, _n = blk.insns[-1]
            cond = _cond_for(ctx, mn, op)
            if "?" not in cond:
                blk.cond = cond


def _idoms(blocks, entry, succ):
    """(idom, order): the immediate dominator of each block the entry reaches over the
    graph `succ` gives, the entry its own, and those blocks in the order a depth-first
    walk from the entry first comes to them.

    Lengauer and Tarjan's algorithm, with path compression and no balancing, as LLVM's
    Semi-NCA computes semidominators (GenericDomTreeConstruction.h). It was the
    Cooper-Harvey-Kennedy iteration, which meets the predecessors of a block by walking
    each up the tree it has so far: N checks that branch to one trap after the `ret`
    walked the trap's N predecessors up a chain N deep, 529,042 lines for 500 of them
    (#319). Semi-NCA's last step can walk that far too where a block's walk parent lies
    deep below its semidominator, so the idoms come out of the buckets instead, which
    costs one `_eval` per block. Iterative throughout, as a chain is as deep as it is
    long."""
    # The depth-first walk the order always came from, now with the parent each block
    # was first reached from: a block taken off the stack was pushed by the block whose
    # walk it is in, so the parents make a depth-first spanning tree.
    order, parent = [], []
    num, stack = {}, [(entry, -1)]
    while stack:
        n, p = stack.pop()
        if n in num or n not in blocks:
            continue
        num[n] = len(order)
        order.append(n)
        parent.append(p)
        for s in succ(n):
            if s in blocks:
                stack.append((s, num[n]))
    k = len(order)
    preds = [[] for _ in range(k)]
    for v, n in enumerate(order):
        for s in succ(n):
            w = num.get(s)
            if w is not None:
                preds[w].append(v)
    # Blocks are their walk numbers from here on. `semi[w]` is w's semidominator,
    # `up` the forest of blocks linked so far, and `label[v]` the block of least
    # semidominator on the compressed path above v.
    semi, label, up = list(range(k)), list(range(k)), [-1] * k
    dom, bucket = [0] * k, [[] for _ in range(k)]

    def _eval(v):
        # The block of least semidominator on the path from v up to the root of its
        # tree in `up`, the root left out, pointing each block on it at that root.
        if up[v] < 0:
            return v
        path, x = [], v
        while up[up[x]] >= 0:
            path.append(x)
            x = up[x]
        for y in reversed(path):
            a = up[y]
            if semi[label[a]] < semi[label[y]]:
                label[y] = label[a]
            up[y] = up[a]
        return label[v]

    for w in range(k - 1, 0, -1):
        for v in preds[w]:
            u = _eval(v)
            if semi[u] < semi[w]:
                semi[w] = semi[u]
        bucket[semi[w]].append(w)
        p = parent[w]
        up[w] = p
        for v in bucket[p]:
            u = _eval(v)
            dom[v] = u if semi[u] < semi[v] else p
        bucket[p] = []
    idom = {entry: entry}
    for w in range(1, k):
        if dom[w] != semi[w]:
            dom[w] = dom[dom[w]]
        idom[order[w]] = order[dom[w]]
    return idom, order


def _rpo(blocks, entry, succ) -> dict:
    """Reverse postorder index per block: a real topological order for the forward edges.

    `_idoms` builds its own DFS preorder, which is fine for the dominator iteration it
    feeds but is NOT a topological order, a node can appear in it before a predecessor.
    The follow-node search below propagates FORWARD along edges and needs to see a node
    only after everything that can reach it without a back edge, so it gets a proper one.
    """
    post, seen, stack = [], set(), [(entry, iter(succ(entry)))]
    seen.add(entry)
    while stack:
        node, it = stack[-1]
        for s in it:
            if s in blocks and s not in seen:
                seen.add(s)
                stack.append((s, iter(succ(s))))
                break
        else:
            post.append(node)
            stack.pop()
    return {n: i for i, n in enumerate(reversed(post))}


#: The note over a section no edge of the graph leads into. What it can be is a list, not
#: a guess: the graph has no exception edges, no targets for a jump through a register,
#: and no second entry, and dead code is possible too.
UNREACHED = ("reached by no edge in this graph: a catch entry, another entry point, a "
             "jump through a register, or dead code")


def _closure(blocks, roots, within) -> set:
    """The blocks of `within` that `roots` reach along the graph's edges, and `roots`."""
    seen, stack = set(), [r for r in roots if r in within]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        stack.extend(s for s in blocks[n].succ if s in within and s not in seen)
    return seen


def cut_off(blocks, dead, cut) -> set:
    """The blocks of `dead`, the ones no edge from the entry reaches, that only an edge
    into `cut` leads to. One another block of `dead` leads to is not among them, nor is
    anything it leads to."""
    behind = _closure(blocks, set(cut) & dead, dead)
    return behind - _closure(blocks, dead - behind, dead) if behind else set()


def entry_reach(blocks, entry) -> set:
    """The blocks `structure` places before the orphans: what the entry reaches, and the
    code after a trap or a call that cannot return it reaches (#57, #234). The rest is
    what no edge leads into, which `orphans` places after it."""
    reachable, stack = set(), [entry]
    while stack:
        n = stack.pop()
        if n in reachable or n not in blocks:
            continue
        reachable.add(n)
        blk = blocks[n]
        stack.extend(blk.succ)
        if blk.ends_path and blk.insns:
            stack.append(blk.insns[-1][0] + 4)
    return reachable


def checks_into(blocks, a, normal, placed) -> bool:
    """Whether the block at `a` has the shape MonomorphicCheckedEntryAOT emits: a check
    whose taken arm goes back into `placed`, the code above (the miss handler), and that
    falls into `normal` and nowhere else. Then `a` reaches nothing but its miss handler
    and `normal`, so `normal` and what it reaches are the body, and the check dominates
    none of it: the callers enter at `normal` too (#278)."""
    blk = blocks.get(a)
    return (blk is not None and normal in blocks and _is_cond(blk.term) and not blk.cexit
            and blk.exit_target < 0 and blk.cut_next < 0 and len(blk.succ) == 2
            and blk.succ[1] == normal and blk.succ[0] in placed)


def second_reach(blocks, placed, entries) -> frozenset:
    """The body of its own that the proven entries `entries` have: the blocks they reach
    along the graph's edges that `placed`, what the first instruction reaches, does not.
    Empty where one of them is not a block or is in `placed`. A Code with a monomorphic
    entry starts on the miss handler, so its whole body is here (#278). Not the code past
    a trap, which only the step entry_reach takes leads to: a catch entry there is
    reached by no edge from these entries either, and is a section like any other."""
    if not entries or any(e not in blocks or e in placed for e in entries):
        return frozenset()
    return frozenset(_closure(blocks, entries, set(blocks) - set(placed)))


def past_trap(blocks, entry, placed, cut) -> frozenset:
    """The blocks of `placed` that only the step past a trap or a call that cannot return
    brings in (entry_reach): no edge from the entry leads to them, nor one the caller cut
    (cut_off). Each is a section no edge leads into, as one after the body is, only
    `structure` places it among the body's sections, in address order. A block past a
    trap that an edge reaches is the body's, and so is a slow path laid out after a
    throw that an edge strip_boilerplate cut leads to, a stack check's or the one that
    boxes a Mint, through the blocks it cut off on the way (#157, #283)."""
    reach = _closure(blocks, [entry], set(blocks))
    loose = set(placed) - reach
    if not loose:
        return frozenset()
    return frozenset(loose - cut_off(blocks, set(blocks) - reach, cut))


def dominator_forest(blocks, entry, succ, roots=(), placed=frozenset()):
    """(idom, order, trees): `_idoms` from `entry`, then one tree from each of `roots`
    that `placed` leaves out, over the blocks no earlier tree took and no other root
    is, with [(root, its blocks)]. The first tree is what it was without the others.

    A block the entry reaches by no path is dominated by nothing, so a body behind a
    second entry had no loops and no joins a dominator could speak for (#278). Its
    own entry dominates it, and nothing else: the trees share no block, and an edge
    from one into another is a way in the second does not count. That is what a
    monomorphic entry needs, as the normal entry 16 bytes past it is entered by the
    callers too, so it roots a tree of its own rather than sit under the check."""
    idom, order = _idoms(blocks, entry, succ)
    trees = []
    for r in roots:
        if r not in blocks or r in idom or r in placed:
            continue
        within = {b for b in blocks if b not in placed and b not in idom
                  and (b == r or b not in roots)}
        got, more = _idoms(within, r, succ)
        idom.update(got)
        order.extend(more)
        trees.append((r, frozenset(more)))
    return idom, order, trees


def dom_numbers(idom):
    """(pre, end, kids) of the forest `idom` (dominator_forest), or None where it is not
    one: each block's place in a preorder of its tree, one count across every tree, the
    end of its subtree's run, and its children. `a` is above `b` exactly where
    pre[a] <= pre[b] < end[a], so a dominance question costs O(1) and not the walk up
    `idom` it was, which the lifter took 126,249 times for 500 loops in a row (#282).
    That is the test LLVM's DominatorTreeBase::dominates makes once updateDFSNumbers has
    run (GenericDomTree.h). Trees of different roots never overlap in it.

    A root is a block that is its own idom. A block whose idom is not in the map, or one
    on a cycle no root is on, makes it no forest: `_idoms` builds neither, as each idom
    comes before its block in the order it numbers, but a walk up `idom` stops at a
    block it saw before, and the numbers would not say what that walk does. Iterative,
    as 300 nested loops make a tree 599 deep."""
    kids, roots = {}, []
    for n, d in idom.items():
        if d == n:
            roots.append(n)
        elif d in idom:
            kids.setdefault(d, []).append(n)
        else:
            return None
    pre, seq = {}, []
    for r in roots:
        stack = [r]
        while stack:
            n = stack.pop()
            pre[n] = len(seq)
            seq.append(n)
            stack.extend(kids.get(n, ()))
    if len(seq) != len(idom):
        return None
    size = dict.fromkeys(seq, 1)
    for n in reversed(seq):
        if idom[n] != n:
            size[idom[n]] += size[n]
    return pre, {n: pre[n] + size[n] for n in seq}, kids


_SUCC = attrgetter("succ")


class LoopNest:
    """Natural-loop bodies, each the backward closure from its latches that stops at its
    header, built so that one holding another takes the inner one in whole (#332).

    N loops nested in each other have bodies of N, N - 1, ... blocks, and walking each
    one by itself walked about N * N / 2 blocks between them: 14 s of CPU at 2,000
    nested loops, 82% of it under `_render_loop`. Here the walk for an outer loop, at a
    block a body worked out before holds, adds that whole body at once and goes on from
    the blocks with an edge into it. That is the same set the plain walk gathers when
    the inner body is rooted, every block of it reached from its header inside it, and
    holds neither the outer header nor a block the outer walk would turn away: the
    plain walk takes the block it is at, so everything that reaches it, the inner header
    among them, and so every block the inner header reaches. A body counts as rooted
    (`good`) where its header is above every block of it in a dominator forest whose
    edges are the walk's: the part of a path from the root to a block after the header's
    last visit stays inside the body. One built where `num` is None, or that takes in a
    block the forest has nowhere or does not put under the header, is walked as before
    and never taken in whole. Asked inner loops first, as `prepare` does, each block is
    walked by the innermost rooted body holding it and by no other, the way a loop
    nesting forest is (Havlak 1997; LLVM's LoopInfo builds its loops bottom up too).

    `preds` maps a block to the blocks with an edge into it, `keep(header, n)` says
    whether the walk for `header` may take `n`, as each caller had it, and `num` is
    `dom_numbers` of that forest. `kids` and `own` say how each body was put together,
    for a question folded up the nest in the same way (Lifter._loop_live_in)."""

    def __init__(self, preds, keep, num):
        self.preds, self.keep = preds, keep
        self.pre, self.end = (num[0], num[1]) if num is not None else ({}, {})
        self.body: dict = {}
        self.front: dict = {}      # the blocks outside a rooted body with an edge into it
        self.kids: dict = {}       # the bodies a body took in whole, at the time
        self.own: dict = {}        # the blocks its walk took one at a time, header first
        self.by_id: dict = {}      # id() of a body -> its header, for Lifter._fold
        self.good: set = set()     # the rooted bodies
        self.clean: set = set()    # the rooted bodies none of whose parts overlap
        self._owner: dict = {}     # block -> a rooted body holding it
        self._up: dict = {}        # rooted body -> the rooted body that took it in

    def above(self, a, b) -> bool:
        """`a` is `b`, or above it, in the forest; False for a block in none."""
        pre = self.pre
        return a in pre and b in pre and pre[a] <= pre[b] < self.end[a]

    def _find(self, n):
        """The outermost rooted body found so far that holds `n`, or None."""
        r = self._owner.get(n)
        if r is None:
            return None
        up, path = self._up, []
        while r in up:
            path.append(r)
            r = up[r]
        for p in path:
            up[p] = r
        return r

    def closure(self, header, latches) -> frozenset:
        """{header} and every block `keep` lets in that reaches one of `latches` without
        passing `header`, over `preds`; the walk each caller had, taking rooted bodies
        in whole."""
        got = self.body.get(header)
        if got is not None:
            return got
        keep, preds, body, front = self.keep, self.preds, self.body, self.front
        nodes, own, kids, stack = {header}, [header], [], list(latches)
        clean = True
        while stack:
            n = stack.pop()
            if n in nodes or not keep(header, n):
                continue
            r = self._find(n)
            if r is not None and header not in body[r] and keep(header, r):
                inner = body[r]
                clean = clean and nodes.isdisjoint(inner)
                nodes |= inner
                kids.append(r)
                stack.extend(front[r])
                continue
            nodes.add(n)
            own.append(n)
            stack.extend(preds.get(n, ()))
        got = body[header] = frozenset(nodes)
        self.kids[header], self.own[header] = kids, own
        self.by_id[id(got)] = header
        above = self.above
        if all(above(header, n) for n in own) and all(above(header, r) for r in kids):
            self.good.add(header)
            if clean:
                self.clean.add(header)
            for n in own:
                self._owner.setdefault(n, header)
            for r in kids:
                self._up[r] = header
            front[header] = frozenset(itertools.chain(
                itertools.chain.from_iterable(map(preds.get, own, itertools.repeat(()))),
                *(front[r] for r in kids))) - got
        return got

    def prepare(self, headers, ask) -> None:
        """Ask `ask(h)` of each of `headers` the forest has, lowest in it first, so an
        inner loop's body is there for the outer one to take in."""
        pre = self.pre
        for h in sorted((h for h in headers if h in pre), key=pre.__getitem__,
                        reverse=True):
            ask(h)


def strong_components(nodes, succ) -> list:
    """The strongly connected pieces of the graph over `nodes` whose edges are `succ(n)`,
    those into `nodes` only, as lists, each before every piece it has an edge into.

    Tarjan's algorithm, iterative, as a chain of 8,000 loops is a walk that deep. A piece
    is complete when the walk leaves its first block, after every piece it reaches, so
    the order it completes them in, reversed, is a topological order of the pieces. Each
    block and edge is seen once (#289)."""
    index, low, on, stack, out = {}, {}, set(), [], []
    for root in nodes:
        if root in index:
            continue
        index[root] = low[root] = len(index)
        on.add(root)
        stack.append(root)
        work = [(root, iter(succ(root)))]
        while work:
            n, it = work[-1]
            for s in it:
                if s not in nodes:
                    continue
                if s not in index:
                    index[s] = low[s] = len(index)
                    on.add(s)
                    stack.append(s)
                    work.append((s, iter(succ(s))))
                    break
                if s in on:
                    low[n] = min(low[n], index[s])
            else:
                work.pop()
                if work:
                    m = work[-1][0]
                    low[m] = min(low[m], low[n])
                if low[n] == index[n]:
                    piece, x = [], None
                    while x != n:
                        x = stack.pop()
                        on.discard(x)
                        piece.append(x)
                    out.append(piece)
    out.reverse()
    return out


def structure(blocks, entry, orphans: bool = False, cut=frozenset(), entries=(),
              rest: bool = False):
    """Return a list of statements. Each is one of:
      ('asm', block_addr)
      ('if', cond, then_stmts, else_stmts)   (else_stmts may be [])
      ('loop', header_addr, body_stmts)
      ('break',) / ('continue',)
      ('goto', addr)
      ('label', addr), and ('note', text) before a section nothing leads into

    `orphans` also places every block no edge reaches, each as its own section after a
    note. Tier 2 asks for it: 8,580 instructions of the clean fixture, many of them catch
    entries, were in no statement, and nothing said so (#67).

    `cut` is where the edges the caller took out of the graph led: tier 3's
    strip_boilerplate takes the branch to a stack check's slow path and the one into the
    slow path that boxes a Mint, on purpose. A block only those edges lead to is reached
    in the machine, so it is not one the note describes, and it stays out. One another
    unreached block leads to is still placed. Tier 3 left every orphan out for the sake
    of those, which dropped 1,219 blocks of the clean fixture without a word, the body
    behind each monomorphic entry and the catch entries after a `ret` or a `b` among
    them (#266).

    `entries` are entry points the caller has proof of that no edge reaches, in the
    order their sections go: a monomorphic entry and the normal entry its check falls
    into. What they reach and the entry does not is placed first among the orphans,
    from the first of them, and structured as a body: each roots a dominator tree of
    its own (dominator_forest), so its loops are loops and its conditionals meet where
    they do, not at a goto (#278).

    A section nested too deeply to structure ends the placing, and what is left is
    counted in a note that says `disasm` lists it. With `rest`, the caller prints those
    blocks itself, and ("rest", the blocks left, in the order they would have been
    placed) stands in place of the note: tier 3 prints their rows as they are (#284).

    Loops are reconstructed by structuring the natural-loop body through the same
    recursive if/else machinery (bounded to the loop's nodes), so a conditional inside
    a loop becomes a real if/else and the loop-exit test becomes `... break;`. The
    back edge to the header closes the loop; edges leaving the loop become `break`.
    Irreducible / unexpected escapes fall back to `goto` (honest, never wrong).
    """
    fsucc = lambda n: blocks[n].succ if n in blocks else []
    # virtual exit for post-dominators: reverse edges, connect all sinks
    sinks = [a for a, b in blocks.items() if not b.succ]
    VEXIT = -1
    vblocks = dict.fromkeys(list(blocks) + [VEXIT])
    rsucc = {a: [] for a in vblocks}
    for a, b in blocks.items():
        for s in b.succ:
            rsucc[s].append(a)
    for s in sinks:
        rsucc[VEXIT].append(s)
    pidom, _ = _idoms(vblocks, VEXIT, lambda n: rsucc.get(n, []))
    reachable = entry_reach(blocks, entry)
    second = second_reach(blocks, reachable, entries) if orphans else frozenset()
    idom, order, trees = dominator_forest(blocks, entry, fsucc,
                                          entries if second else (), reachable)
    # Never None: `_idoms` gives each block it numbers an idom it numbered before it, and
    # each further tree of the forest is over blocks no earlier one took, so every walk up
    # `idom` ends at a root and the forest is one (dom_numbers).
    num = dom_numbers(idom)
    rank = {n: i for i, n in enumerate(order)}
    rpo = _rpo(blocks, entry, fsucc)
    for root, nodes in trees:
        base = len(rpo)
        rpo.update((n, base + i) for n, i in _rpo(nodes, root, fsucc).items())

    preds = {a: [] for a in blocks}
    for a, b in blocks.items():
        for s in b.succ:
            if s in preds:
                preds[s].append(a)

    # loop headers: back edge n->h where h dominates n
    def dominates(a, b):
        # `a` is `b` or above it in its tree: O(1) from the numbering, where the walk
        # up `idom` it replaces took 18 million steps for 300 nested loops (#282)
        pre, end = num[0], num[1]
        return a == b or (a in pre and b in pre and pre[a] <= pre[b] < end[a])
    loop_header = {}
    for n in blocks:
        for s in blocks[n].succ:
            if s in rank and rank[s] <= rank.get(n, 1 << 30) and dominates(s, n):
                loop_header[s] = True

    def loop_nodes(header):
        """Natural-loop node set: the header, plus every block it DOMINATES that can
        reach a latch (back-edge source) without passing through the header.

        The dominance half is the half this asked of its latches and not of the body.
        A block the entry reaches by no path is dominated by nothing, so it answers the
        reaching half and no more, and the backward walk took it in: `loop_exit` then
        counted its edge out of the set as a vote, and with the votes tied the lowest
        address won, so the structurer printed a block no run enters as the one the loop
        falls out to (#237). LLVM says the same from the other end, that for a block not
        reachable from the entry the concept of a loop is undefined, since dominance is.

        The lifter's `_back_loop` keeps such a predecessor on purpose, because there the
        question is what the loop MAY write and a handler the graph has no edge into has
        to count. Here the question is where the loop goes, and that is a claim.

        A block the entry cannot reach is not the only thing the dominance half excludes.
        In a multi-entry cycle a body block reached from outside the loop is not dominated
        by the header either, so it leaves the set and its edges into the body become exit
        votes; the back edge then reads as a `goto` to the header below the loop, which is
        what this function already does with an irreducible loop and is written down
        rather than wrong.
        """
        # The latches are the header's predecessors that it dominates, and `preds` has
        # them. Asking every block whether it jumps to the header made N loops cost
        # N * N: 3.0 million lines for 1,000 loops in a row (#301). `preds` lists them
        # in the order of `blocks`, as that scan did, and a block with both edges on the
        # header twice, which the walk skips. Not that the order could matter: the walk
        # gathers one set from any order, and it is asked only what is in it and which
        # exit most of its edges take, the lowest address first.
        #
        # A frozenset, built once per header, inner loops first, each taking in the bodies
        # of the loops inside it whole (LoopNest): walked one by one, N nested loops
        # walked N * N / 2 blocks between them (#332). The callers only ask what is in it.
        nonlocal nest, walked
        latches = [n for n in preds[header] if dominates(header, n)]
        if nest is None:
            # Walked by itself, as every loop was, while the bodies walked come to no
            # more than twice the blocks: loops side by side or a few deep. Past
            # that they are nested deep and the nest is built, which only then saves
            # more than it keeps (#332).
            nodes, stack = {header}, latches
            while stack:
                n = stack.pop()
                if n in nodes:
                    continue
                nodes.add(n)
                for p in preds.get(n, ()):
                    if p not in nodes and dominates(header, p):
                        stack.append(p)
            walked += len(nodes)
            if walked <= 2 * len(blocks):
                return nodes
            nest = LoopNest(preds, dominates, num)
            nest.prepare(loop_header, loop_nodes)
            latches = [n for n in preds[header] if dominates(header, n)]
        return nest.closure(header, latches)

    nest, walked = None, 0

    def loop_exit(nodes):
        """Which block the loop is structured to fall out to.

        A loop can leave by several edges and only one target can sit after it; every
        other one becomes a `goto` to a swept-up section. So the choice is the one the
        most edges take, which is what makes the most of them read as `break`. Ties go to
        the lowest address, which keeps the pick deterministic and, on a compiler that
        lays blocks out in order, is the one the source fell out to."""
        # Counted by C loops over the edges, not a line per block: a loop holding N
        # nested ones counted its N * 2 blocks' edges one by one (#332).
        edges = itertools.chain.from_iterable(map(_SUCC, map(blocks.__getitem__, nodes)))
        votes = Counter(itertools.filterfalse(nodes.__contains__, edges))
        if not votes:
            return None
        most = max(votes.values())
        return min(itertools.compress(votes, map(most.__eq__, votes.values())))

    visited = set()
    loop_of = {}   # ctx -> node set, for the out-of-loop escape guard

    follow_memo = {}

    def meet(cur, here, succs):
        """`follow`'s answer read off the dominator tree (#342).

        The block the two-colour search stops at is a child of `cur` in that tree. Say its
        immediate dominator were another block d below `cur`: each arm's way to it goes
        through d, forward all the way, so d carries both bits, `cur` dominates it, and it
        comes first. And every block below one child carries that child's bits and no
        other: a forward way from an arm to it passes the child, and the depth-first walk
        the order comes from goes down from the child to it by forward edges alone. So the
        tags of the children are enough. Each is the bit of the arm it is, and the tags of
        the children its forward edges in come from below, found by where the source's
        number falls among the children's. They are taken in reverse postorder, as the
        search takes them, and the first with both is the answer.

        A child is asked once, by its one parent, and an edge once, so every call of a
        function together costs its blocks and edges, however far the joins are."""
        pre, kids = num[0], num[2].get(cur)
        if not kids:
            return None
        mine = {s: 1 << bit for bit, s in enumerate(succs)
                if rpo.get(s, -1) > here and idom.get(s) == cur}
        if len(mine) < 2:
            return None
        lo, hi = pre[cur], num[1][cur]
        firsts = sorted(map(pre.__getitem__, kids))
        tags = {}
        for c in sorted(kids, key=rpo.__getitem__):
            t, at = mine.get(c, 0), rpo[c]
            for p in preds[c]:
                if lo < pre.get(p, -1) < hi and rpo[p] < at:
                    t |= tags[firsts[bisect.bisect_right(firsts, pre[p]) - 1]]
            if t == 3:
                return c
            tags[pre[c]] = t
        return None

    def follow(cur):
        """Where the two arms of `cur` come back together, when the post-dominator says
        nothing. Cifuentes 1994 ch.6 calls this the follow node.

        The immediate post-dominator is the right answer whenever there IS one, but on
        the corpus binary 36% of conditionals post-dominate at the virtual exit, because
        each arm ends in its own `return` and the only thing they have in common is the
        exit itself. The arms were then walked one after the other with no stopping
        point, so whichever ran second arrived at the block they share, found it already
        emitted, and turned into a `goto`: 7,727 of the 9,916 gotos in the image.

        The search is a two-colour reachability: tag the taken successor with one bit and
        the fall-through with the other, push the tags forward in reverse postorder, and
        take the first block that carries both. Back edges are not followed, so a tag is
        only ever an under-approximation of what reaches a block, which is what makes a
        hit trustworthy: a block carrying both bits really is reachable from both arms.

        The candidate must also be DOMINATED by `cur`. Without that, a block reachable
        from somewhere else entirely could be pulled inside the conditional's region and
        made to look like its continuation.

        Choosing this node is safe whatever it is, which is worth stating plainly: an arm
        walked with `m` as its stop either ends AT m, or ends on a statement that visibly
        does not fall through (return, throw, break, goto). So `if (c) {A} else {B}` then
        m never claims a path that does not exist. What the choice affects is how much
        gets nested, not whether the result is honest."""
        if cur in follow_memo:
            return follow_memo[cur]
        follow_memo[cur] = None
        succs = blocks[cur].succ
        if len(succs) != 2 or succs[0] == succs[1] or cur not in rpo:
            return None
        # The search is not run block by block: `meet` reads its answer off the dominator
        # tree, passing none of the blocks between `cur` and the join. A scan forward in
        # reverse postorder passed every one, so N conditionals whose joins are N blocks
        # on cost N * N (#342).
        m = follow_memo[cur] = meet(cur, rpo[cur], succs)
        return m

    def merge_point(cur, ctx):
        """Post-dominator merge for a conditional, with the follow node as the fallback.
        Clamped to None when it escapes the current loop (so each arm runs to a
        break/back-edge instead of a bogus merge)."""
        m = pidom.get(cur)
        if m == VEXIT or m is None:
            m = follow(cur)
            if m is None:
                return None
        if ctx is not None and m not in loop_of[ctx]:
            return None
        return m

    def emit_cond(cur, stop, ctx, cont):
        blk = blocks[cur]
        if blk.cexit:
            # A conditional return or indirect jump: the `if` holds the exit, and the
            # fallthrough is what follows it.
            a, mn, op, _n = blk.insns[-1]
            leave = (("exit", EXIT_RETURN) if blk.exit == "return"
                     else ("exit", EXIT_INDIRECT, f"{mn} {op}".rstrip()))
            stmts = [("asm", cur), ("if", blk.cond, [leave], [])]
            if blk.cut_next >= 0:
                stmts.append(("cut", blk.cut_next))
            return stmts, blk.succ[0] if blk.succ else None
        if blk.exit_target >= 0:
            # The taken arm leaves the function, so succ holds only the fallthrough. Read
            # positionally that fallthrough looked like the TAKEN arm and the rendered
            # `if` ran its body exactly when the branch was not taken.
            ft = blk.succ[0] if blk.succ else None
            leave = ("cut" if blk.past_cut else "exit", blk.exit_target)
            stmts = [("asm", cur), ("if", blk.cond, [leave], [])]
            if blk.cut_next >= 0:
                stmts.append(("cut", blk.cut_next))
            return stmts, ft
        if blk.cut_next >= 0:
            # At the cut, the not-taken arm runs on past it, and the taken arm is succ[0].
            stmts = [("asm", cur),
                     ("if", negate_cond(blk.cond), [("cut", blk.cut_next)], [])]
            return stmts, blk.succ[0] if blk.succ else None
        taken = blk.succ[0] if len(blk.succ) >= 1 else None
        ft = blk.succ[1] if len(blk.succ) >= 2 else None
        merge = merge_point(cur, ctx)
        # What each arm falls through to. With a merge that is the merge; without one the
        # `if` claims nothing of its own and the arms fall through to whatever the
        # enclosing region falls through to.
        arm_cont = merge if merge is not None else cont
        sub_stop = stop | ({merge} if merge is not None else set())
        then_stmts = region(ft, sub_stop, ctx, arm_cont) if ft is not None else []
        else_stmts = region(taken, sub_stop, ctx, arm_cont) if taken is not None else []
        stmts = [("asm", cur)]
        # then = fallthrough (branch NOT taken). If that arm is empty, keep the branch
        # condition and put the non-empty (taken) arm in the `then`.
        if not then_stmts and else_stmts:
            stmts.append(("if", blk.cond, else_stmts, []))
        else:
            stmts.append(("if", negate_cond(blk.cond), then_stmts, else_stmts))
        return stmts, merge

    def build_loop(header):
        nodes = loop_nodes(header)
        ex = loop_exit(nodes)
        ctx = (header, ex)
        loop_of[ctx] = nodes
        visited.add(header)
        blk = blocks[header]
        # Running off the end of a loop body is the back edge, so that is what the body
        # falls through to. A header that leaves under a condition is a conditional too,
        # or its exit would be dropped and the loop read as having no way out.
        if _is_cond(blk.term) or blk.cexit:
            body, merge = emit_cond(header, set(), ctx, header)
            if merge is not None:
                body = body + region(merge, set(), ctx, header)
        else:
            nxt = blk.succ[0] if blk.succ else None
            body = [("asm", header)] + region(nxt, set(), ctx, header)
        return ("loop", header, body), ex

    def region(start, stop, ctx, cont):
        """Statements for the blocks from `start` up to `stop`.

        `cont` is the block the CALLER will place after this list, and it is what makes
        an empty arm honest. Stopping is not one situation but two: reaching the block
        that is about to be emitted next, where running off the end IS the edge, and
        reaching some outer boundary, where running off the end claims an edge to a block
        that is not there. Without the distinction an `if` whose arms both hit an outer
        boundary rendered as two empty arms, the renderer dropped it as vacuous, and the
        branch to the other successor left the output with nothing saying so.
        """
        out = []
        cur = start
        while cur is not None and cur in blocks:
            if ctx is not None:
                if cur == ctx[0]:           # back edge to loop header
                    # Only running off the END of the loop body is the back edge. Deeper
                    # in, with statements still to come after the enclosing `if`, control
                    # would fall into those instead, so the jump has to be written down.
                    if cont != ctx[0]:
                        out.append(("continue",))
                    break
                if cur == ctx[1]:           # loop exit
                    out.append(("break",))
                    break
            if cur in stop:
                if cur != cont:
                    out.append(("goto", cur))
                break
            if ctx is not None and cur not in loop_of[ctx]:
                out.append(("goto", cur))   # any other escape out of the loop
                break
            if cur in visited:
                out.append(("goto", cur))
                break
            visited.add(cur)
            blk = blocks[cur]
            if loop_header.get(cur) and (ctx is None or cur != ctx[0]):
                loopstmt, ex = build_loop(cur)
                out.append(loopstmt)
                cur = ex
                continue
            if _is_cond(blk.term) or blk.cexit:
                cstmts, merge = emit_cond(cur, stop, ctx, cont)
                out.extend(cstmts)
                cur = merge
                continue
            out.append(("asm", cur))
            if blk.exit_target >= 0 and not blk.succ:
                # A `b` leaving the function. Saying so is the whole point: without it the
                # body just stopped, or the walk continued into an unrelated block.
                out.append(("cut" if blk.past_cut else "exit", blk.exit_target))
                break
            if blk.cut_next >= 0:
                out.append(("cut", blk.cut_next))
                break
            cur = blk.succ[0] if blk.succ else None
        return out

    out = region(entry, set(), None, None)

    # Every block reachable from the entry has to end up somewhere. structure() places
    # blocks as it walks, and a block it arrived at a second time, a join, or an escape
    # out of a loop, turned into a `goto` that nobody ever emitted a body for. The
    # instructions in it left the output silently, and nothing in the text said so, because
    # the goto named a label no tier ever defined. Sweep up whatever is left, as labelled
    # sections, until nothing is.
    #
    # The code after a trap goes in the same way (#57), and so does the code after a call
    # that cannot return (`Block.ends_path`, #234). Nothing runs on past either, yet that
    # code can be a catch entry, which only an exception edge leads to, and the CFG does
    # not model those. Placing only what the entry reaches dropped 182 instructions in 12
    # sections of the clean fixture without a word, 5 of them opening with
    # `sub x15, x29, #imm`, the stack reset a catch entry starts with. So the walk also
    # steps from a reached block that ends a path to the block after it, which is exactly
    # the code the old edge out of it brought in. Ghidra and Hex-Rays drop that code
    # instead, and a stub misidentified as non-returning there hides real source; placing
    # it as its own section cannot.
    #
    # One walk and one pass in address order places blocks in the same order as taking the
    # lowest unplaced one again and again, since placing only ever adds to `visited`, and
    # in linear time: repeating it took 0.88 s on a crafted range of 4,000 `brk`.
    # Which of them a real edge reaches, so a section that only the step past a trap
    # brought in is marked as one nothing leads into.
    edged, stack = set(), [entry]
    while stack:
        n = stack.pop()
        if n in edged or n not in blocks:
            continue
        edged.add(n)
        stack.extend(blocks[n].succ)
    # What the entry or a trap reaches, then, after all of it, what nothing reaches, so
    # that asking for the orphans only ever adds sections at the end.
    tail = []
    if orphans:
        dead = set(blocks) - reachable
        tail = sorted(dead - cut_off(blocks, dead, cut))
        if second:
            # The body of its own goes first, from its first entry, and all of it, as
            # the entry's does. In address order a section below it that reached one
            # of its blocks first would structure that block from there instead.
            tail = ([e for e in entries if e in second]
                    + sorted(second - set(entries))
                    + [a for a in tail if a not in second])
    # The note says no edge leads into the section, so it goes only where none does: a
    # block another unreached section jumps to shows that `goto` in the output itself.
    # Nor over a slow path the step past a trap placed (#157): an edge the caller cut
    # leads into it, and the note would list everything it can be but that.
    targeted = {s for b in blocks.values() for s in b.succ} | set(cut)

    def guard(a):
        """The check at the first of `entries`, where its taken arm goes back into the
        code above and it falls into the next of them, the shape a monomorphic check has
        with its miss handler above it: `if (c) goto X;` with the body after it at the
        same depth, and not nested in the check's other arm. A goto does not fall
        through, so the two forms say the same, and in this one a name the body declares
        is in scope in the sections swept up after it, as it is in a body (#278)."""
        if (len(entries) < 2 or a != entries[0]
                or not checks_into(blocks, a, entries[1], reachable)):
            return None
        blk = blocks[a]
        visited.add(a)
        return ([("asm", a), ("if", blk.cond, [("goto", blk.succ[0])], [])]
                + region(blk.succ[1], set(), None, None))

    for a in sorted(reachable):
        if a not in visited:
            if a not in edged and a not in targeted:
                out.append(("note", UNREACHED))
            out.append(("label", a))
            out.extend(region(a, set(), None, None))
    for a in tail:
        if a in visited:
            continue
        # structure() recurses with the nesting, so a deep enough tangle of conditionals
        # nothing reaches would raise. Main never placed these at all, so rather than
        # turn a hostile binary into a crash here, the rest is counted and left to
        # `disasm`, which lists every instruction.
        before = set(visited)
        try:
            section = ((guard(a) if second else None)
                       or region(a, set(), None, None))
        except RecursionError:
            visited.clear()
            visited.update(before)
            left = [b for b in tail if b not in visited]
            if rest:
                out.append(("rest", tuple(left)))
                break
            n = sum(len(blocks[b].insns) for b in left)
            out.append(("note", f"{n} more instructions no edge in this graph "
                                "reaches are nested too deeply to structure; `disasm` "
                                "lists them"))
            break
        if a not in targeted:
            out.append(("note", UNREACHED))
        out.append(("label", a))
        out.extend(section)
    return out


def label_targets(stmts, acc=None) -> set:
    """Block addresses that need a label defined: every goto target and every swept-up
    section. A goto to a label that is never defined is not pseudo-code, it is a dead end."""
    acc = set() if acc is None else acc
    for s in stmts:
        if s[0] in ("goto", "label"):
            acc.add(s[1])
        elif s[0] == "if":
            label_targets(s[2], acc)
            label_targets(s[3], acc)
        elif s[0] == "loop":
            label_targets(s[2], acc)
    return acc


def _asm_lines(blk, indent, show):
    """Render a block's instructions as pseudo-statements, dropping the terminator
    branch (represented structurally) and rendering ret as `return`. `show` prints an
    operand; see render."""
    lines = []
    for k, (a, mn, op, note) in enumerate(blk.insns):
        last = (k == len(blk.insns) - 1)
        if last and (mn == "b" or _is_cond(mn) or blk.cexit):
            continue                                   # branch is structural
        if mn == "ret" or (mn == "bx" and op.strip() == "lr") or (
                last and blk.exit == "return"):
            lines.append(f"{indent}return;{note}")
        elif mn == "bl" and note:
            lines.append(f"{indent}call{note.replace('  ; -> ', ' ')}();")
        else:
            lines.append(f"{indent}{mn} {show(a, op) if show is not None else op}{note}")
    return lines


#: The note over a function whose control flow nests too deeply to structure (#81).
TOO_DEEP = ("nested too deeply to structure; its instructions follow as they are, in "
            "address order")


def flat_rows(rows, pad, show) -> list:
    """`rows` as they are, each at its address, as `flat` prints them."""
    at = getattr(show, "address", None)
    out = []
    for a, mn, op, note in rows:
        where = at(a) if at is not None else f"0x{a:x}"
        shown = show(a, op) if show is not None else op
        out.append(f"{pad}{where}  {mn} {shown}".rstrip() + note)
    return out


def flat(rows, indent="  ", depth=1, *, show, cut_end=None) -> list:
    """`rows` as they are, each at its address, under a note saying why: what tier 2 and
    tier 3 print for a function `structure` cannot nest (#81). Cut at the instruction
    limit (`cut_end`), they end with the jump to where it goes on, so that the list does
    not read as the whole function."""
    pad = indent * depth
    out = [f"{pad}// {TOO_DEEP}"] + flat_rows(rows, pad, show)
    if cut_end is not None and rows and cut_end > rows[-1][0] + 4:
        out.append(f"{pad}{cut_goto(max(r[0] for r in rows) + 4, show)}")
    return out


def render_function(rows, *, exits=None, cut_end=None, indent="  ", depth=1,
                    show) -> list:
    """Tier 2 for one function: its graph, structured with the code no edge reaches, as
    lines.

    `structure` and `render` recurse once for each level of nesting, so a range of a few
    hundred conditionals nested in each other, which only a crafted binary holds, ran out
    of Python's stack: 500 raised RecursionError, and `export -t 2` and `decompile -t 2`
    exited 3, a bug in jadart (#81). Such a function prints its rows instead (`flat`),
    and the rest of the output goes on."""
    blocks, entry = build_cfg(rows, exits=exits, cut_end=cut_end)
    try:
        return render(blocks, structure(blocks, entry, orphans=True), indent, depth,
                      show=show)
    except RecursionError:
        return flat(rows, indent, depth, show=show, cut_end=cut_end)


def cut_goto(addr: int, show) -> str:
    """The jump to `addr`, in the part of this function the instruction cut left out: an
    address inside it, and not the `sub_0x...` that names another function (#70)."""
    at = getattr(show, "address", None)
    return (f"goto {at(addr) if at is not None else f'0x{addr:x}'};"
            f"  // TRUNCATED: past the instruction cut")


def render(blocks, stmts, indent="  ", depth=1, labels=None, done=None, *, show) -> list:
    """The structured statements as lines. `show` prints an instruction's operand,
    rebaser(image) from disasm so that a code address reads as a virtual address, as in
    `disasm`; it is required, and None prints the operand as capstone did. Only the
    output is rebased: the blocks keep capstone's text, which their targets are read
    from."""
    if labels is None:
        labels, done = label_targets(stmts), set()
    pad = indent * depth
    out = []

    def label(addr):
        """Define the label once, at whichever statement emits that block first."""
        if addr in labels and addr not in done:
            done.add(addr)
            out.append(f"{pad}L_0x{addr:x}:")

    for s in stmts:
        if s[0] == "asm":
            label(s[1])
            out.extend(_asm_lines(blocks[s[1]], pad, show))
        elif s[0] == "label":
            label(s[1])
        elif s[0] == "note":
            out.append(f"{pad}// {s[1]}")
        elif s[0] == "if":
            _, cond, then, els = s
            out.append(f"{pad}if ({cond}) {{")
            out.extend(render(blocks, then, indent, depth + 1, labels, done, show=show))
            if els:
                out.append(f"{pad}}} else {{")
                out.extend(render(blocks, els, indent, depth + 1, labels, done,
                                  show=show))
            out.append(f"{pad}}}")
        elif s[0] == "loop":
            _, header, body = s
            label(header)
            out.append(f"{pad}while (true) {{")
            out.extend(render(blocks, body, indent, depth + 1, labels, done, show=show))
            out.append(f"{pad}}}")
        elif s[0] == "break":
            out.append(f"{pad}break;")
        elif s[0] == "continue":
            out.append(f"{pad}continue;")
        elif s[0] == "goto":
            out.append(f"{pad}goto L_0x{s[1]:x};")
        elif s[0] == "cut":
            out.append(f"{pad}{cut_goto(s[1], show)}")
        elif s[0] == "exit":
            # Outside this function, so not a local label: name it the way the rest of the
            # output names an address it has no name for. A return or an indirect jump
            # names none, and says what it is instead.
            if s[1] == EXIT_RETURN:
                out.append(f"{pad}return;")
            elif s[1] == EXIT_INDIRECT:
                out.append(f"{pad}{s[2]}")
            elif s[1] < 0:
                out.append(f"{pad}goto <unresolved>;")
            else:
                # Not `label`: that is the function above, and rebinding it here made
                # every later `L_0x..:` in this body print nothing while its goto stayed
                # (#66).
                sub = getattr(show, "label", None)
                name = sub(s[1]) if sub is not None else f"sub_0x{s[1]:x}"
                out.append(f"{pad}goto {name};")
    return out
