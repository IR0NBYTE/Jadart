"""Tier 2: control-flow reconstruction (jadart).

Builds a control-flow graph from a function's annotated disassembly and structures
it into if/else and while constructs, so a method body reads as nested pseudo-Dart
instead of a flat labelled listing. This tier stops at the CONTROL-FLOW skeleton,
with best-effort conditions plus the calls and string constants the Tier 1 annotator
already resolved. Expression reconstruction (recovering `balance -= amount` from
sub/stur) is Tier 3 and lives in expr.py. Irreducible regions fall back to `goto Ln`
(honest, never wrong).

CFG terminators: b, b.<cond>, cbz/cbnz/tbz/tbnz, ret, br. Calls (bl/blr) fall through.
Structuring uses forward dominators (loop back edges) + post-dominators (if merge
points), both via the Cooper-Harvey-Kennedy iterative algorithm.
"""
from __future__ import annotations

import bisect
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


_NEG = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", "<=": ">", ">": "<="}


def negate_cond(cond: str) -> str:
    """Negate a `lhs OP rhs` condition (then-branch is the fallthrough = branch not taken)."""
    parts = cond.split(" ")
    for i, tok in enumerate(parts):
        if tok in _NEG:
            parts[i] = _NEG[tok]
            return " ".join(parts)
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


#: Relational spelling for each condition code. `rel` is only meaningful for a flag source
#: that actually sets all four flags; see _Z_N_ONLY below.
_REL = {"eq": "==", "ne": "!=", "lt": "<", "le": "<=", "gt": ">", "ge": ">=",
        "cc": "<", "lo": "<", "cs": ">=", "hs": ">=", "ls": "<=", "hi": ">",
        "mi": "<", "pl": ">="}

#: Flag sources that set C and V to constants rather than computing them: the logical
#: operations. After one of them only Z (eq/ne) and N (mi/pl) carry information, and a
#: carry-based branch means something the operands cannot express, `b.hi` after `tst`
#: is unconditionally FALSE, not `(a & b) > 0`. Measured on the corpus binary, the
#: compiler only ever emits eq/ne there, so this guard costs nothing and closes the hole.
_LOGICAL_FLAGS = ("tst", "ands", "bics")
_Z_N_ONLY = frozenset({"eq", "ne", "mi", "pl"})


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
        if pm in ("cmp", "fcmp", "fcmpe") and len(parts) >= 2:
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
        elif pm == "adds" and len(parts) >= 3:
            b = parts[2] if len(parts) == 3 else _shifted(parts[2:])
            if b is None:
                return "?"
            lhs, rhs = f"({parts[1]} + {b})", "0"
        elif pm in _LOGICAL_FLAGS and cc in _Z_N_ONLY:
            a, b = (parts[0], parts[1]) if pm == "tst" else (
                (parts[1], parts[2]) if len(parts) >= 3 else (parts[0], parts[-1]))
            lhs, rhs = f"({a} & {'~' if pm == 'bics' else ''}{b})", "0"
    return f"{lhs} {rel} {rhs}"


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


def build_cfg(dis) -> tuple[dict, int]:
    """Return ({addr: Block}, entry_addr) for a function's disasm
    (list of (addr, mn, op, note))."""
    if not dis:
        return {}, 0
    addrs = [d[0] for d in dis]
    lo, hi = addrs[0], addrs[-1] + 4
    leaders = {lo}
    for i, (a, mn, op, _n) in enumerate(dis):
        if _is_term(mn):
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
            # `bx` covers both of arm32's uses of it: `bx lr` returns and `bx rN` is
            # an indirect branch. Either way the successor is not in this function.
            if mn in ("ret", "br", "bx"):
                blk.succ = []
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
            elif _is_cond(mn):
                t = _target(op)
                ft = end if end < hi else None
                prev = insns[-2] if len(insns) >= 2 else None
                blk.cond = _cond_text(prev, mn, op)
                blk.succ = []
                if t is not None and lo <= t < hi:
                    blk.succ.append(t)      # taken
                elif ft is not None:
                    # The taken arm leaves the function. succ would then hold only the
                    # fallthrough, and emit_cond reads succ[0] as the TAKEN arm, so the
                    # rendered `if` ran its body exactly when the branch was NOT taken.
                    blk.exit_target = t if t is not None else -1
                if ft is not None:
                    blk.succ.append(ft)     # fallthrough
            else:
                blk.succ = [end] if end < hi else []
        blocks[la] = blk
    return blocks, lo


def _idoms(blocks, entry, succ):
    """Cooper-Harvey-Kennedy iterative dominators over the graph given by `succ`."""
    order = []
    seen = set()
    stack = [entry]
    while stack:
        n = stack.pop()
        if n in seen or n not in blocks:
            continue
        seen.add(n)
        order.append(n)
        for s in succ(n):
            if s in blocks:
                stack.append(s)
    rpo = {n: i for i, n in enumerate(order)}
    preds = {n: [] for n in order}
    for n in order:
        for s in succ(n):
            if s in preds:
                preds[s].append(n)
    idom = {entry: entry}

    def inter(a, b):
        while a != b:
            while rpo[a] > rpo[b]:
                a = idom[a]
            while rpo[b] > rpo[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for n in order:
            if n == entry:
                continue
            new = None
            for p in preds[n]:
                if p in idom:
                    new = p if new is None else inter(p, new)
            if new is not None and idom.get(n) != new:
                idom[n] = new
                changed = True
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


def structure(blocks, entry):
    """Return a list of statements. Each is one of:
      ('asm', block_addr)
      ('if', cond, then_stmts, else_stmts)   (else_stmts may be [])
      ('loop', header_addr, body_stmts)
      ('break',) / ('continue',)
      ('goto', addr)

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
    idom, order = _idoms(blocks, entry, fsucc)
    rank = {n: i for i, n in enumerate(order)}
    rpo = _rpo(blocks, entry, fsucc)

    preds = {a: [] for a in blocks}
    for a, b in blocks.items():
        for s in b.succ:
            if s in preds:
                preds[s].append(a)

    # loop headers: back edge n->h where h dominates n
    def dominates(a, b):
        while b in idom and b != a and b != idom[b]:
            b = idom[b]
        return b == a
    loop_header = {}
    for n in blocks:
        for s in blocks[n].succ:
            if s in rank and rank[s] <= rank.get(n, 1 << 30) and dominates(s, n):
                loop_header[s] = True

    def loop_nodes(header):
        """Natural-loop node set: header plus every block that can reach a latch
        (back-edge source) without passing through the header."""
        latches = [n for n in blocks
                   if header in blocks[n].succ and dominates(header, n)]
        nodes = {header}
        stack = list(latches)
        while stack:
            n = stack.pop()
            if n in nodes:
                continue
            nodes.add(n)
            for p in preds.get(n, ()):
                if p not in nodes:
                    stack.append(p)
        return nodes

    def loop_exit(nodes):
        """Which block the loop is structured to fall out to.

        A loop can leave by several edges and only one target can sit after it; every
        other one becomes a `goto` to a swept-up section. So the choice is the one the
        most edges take, which is what makes the most of them read as `break`. Ties go to
        the lowest address, which keeps the pick deterministic and, on a compiler that
        lays blocks out in order, is the one the source fell out to."""
        votes = {}
        for n in nodes:
            for s in blocks[n].succ:
                if s not in nodes:
                    votes[s] = votes.get(s, 0) + 1
        if not votes:
            return None
        return min(votes, key=lambda s: (-votes[s], s))

    visited = set()
    loop_of = {}   # ctx -> node set, for the out-of-loop escape guard

    by_rpo = sorted(rpo, key=rpo.get)
    follow_memo = {}

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
        tag, pending = {}, 0
        for bit, s in enumerate(succs):
            if s in rpo and s != cur:
                pending += s not in tag
                tag[s] = tag.get(s, 0) | (1 << bit)
        # Only the blocks after this one in reverse postorder can carry a tag, and once
        # none of them still does there is nothing left to find, so the scan is the size
        # of the region between the branch and its join rather than of the function.
        for n in by_rpo[rpo[cur] + 1:]:
            t = tag.get(n)
            if not t:
                continue
            pending -= 1
            if t == 3 and dominates(cur, n):
                follow_memo[cur] = n
                return n
            for s in blocks[n].succ:
                if s in rpo and rpo[s] > rpo[n]:     # forward edges only
                    pending += s not in tag
                    tag[s] = tag.get(s, 0) | t
            if not pending:
                break
        return None

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
        if blk.exit_target >= 0:
            # The taken arm leaves the function, so succ holds only the fallthrough. Read
            # positionally that fallthrough looked like the TAKEN arm and the rendered
            # `if` ran its body exactly when the branch was not taken.
            ft = blk.succ[0] if blk.succ else None
            stmts = [("asm", cur), ("if", blk.cond, [("exit", blk.exit_target)], [])]
            return stmts, ft
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
        # falls through to.
        if _is_cond(blk.term):
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
            if _is_cond(blk.term):
                cstmts, merge = emit_cond(cur, stop, ctx, cont)
                out.extend(cstmts)
                cur = merge
                continue
            out.append(("asm", cur))
            if blk.exit_target >= 0 and not blk.succ:
                # A `b` leaving the function. Saying so is the whole point: without it the
                # body just stopped, or the walk continued into an unrelated block.
                out.append(("exit", blk.exit_target))
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
    reachable, stack = set(), [entry]
    while stack:
        n = stack.pop()
        if n in reachable or n not in blocks:
            continue
        reachable.add(n)
        stack.extend(blocks[n].succ)
    while True:
        left = sorted(a for a in reachable if a not in visited)
        if not left:
            break
        out.append(("label", left[0]))
        out.extend(region(left[0], set(), None, None))
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


def _asm_lines(blk, indent):
    """Render a block's instructions as pseudo-statements, dropping the terminator
    branch (represented structurally) and rendering ret as `return`."""
    lines = []
    for k, (a, mn, op, note) in enumerate(blk.insns):
        last = (k == len(blk.insns) - 1)
        if last and (mn == "b" or _is_cond(mn)):
            continue                                   # branch is structural
        if mn == "ret" or (mn == "bx" and op.strip() == "lr"):
            lines.append(f"{indent}return;{note}")
        elif mn == "bl" and note:
            lines.append(f"{indent}call{note.replace('  ; -> ', ' ')}();")
        else:
            lines.append(f"{indent}{mn} {op}{note}")
    return lines


def render(blocks, stmts, indent="  ", depth=1, labels=None, done=None) -> list:
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
            out.extend(_asm_lines(blocks[s[1]], pad))
        elif s[0] == "label":
            label(s[1])
        elif s[0] == "if":
            _, cond, then, els = s
            out.append(f"{pad}if ({cond}) {{")
            out.extend(render(blocks, then, indent, depth + 1, labels, done))
            if els:
                out.append(f"{pad}}} else {{")
                out.extend(render(blocks, els, indent, depth + 1, labels, done))
            out.append(f"{pad}}}")
        elif s[0] == "loop":
            _, header, body = s
            label(header)
            out.append(f"{pad}while (true) {{")
            out.extend(render(blocks, body, indent, depth + 1, labels, done))
            out.append(f"{pad}}}")
        elif s[0] == "break":
            out.append(f"{pad}break;")
        elif s[0] == "continue":
            out.append(f"{pad}continue;")
        elif s[0] == "goto":
            out.append(f"{pad}goto L_0x{s[1]:x};")
        elif s[0] == "exit":
            # Outside this function, so not a local label: name it the way the rest of the
            # output names an address it has no name for.
            out.append(f"{pad}goto sub_0x{s[1]:x};" if s[1] >= 0
                       else f"{pad}goto <unresolved>;")
    return out
