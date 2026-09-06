"""Tier 3: expression reconstruction (jadart).

Tier 2 recovers the control-flow skeleton but leaves each basic block as annotated
arm64. Tier 3 lifts those instructions into pseudo-Dart *expressions* by abstract
interpretation over the register file. It threads a register -> expression map through
the structured statement tree (from cfg.structure), so a store renders as a field
assignment, `sub`/`mul`/`add` as infix arithmetic, `ret` as `return <expr>`, and a
`bl` as a named call. Compiler boilerplate (frame setup/teardown, the thread
stack-overflow check and its slow path) is stripped so it never reaches the output.

Design (honest, never wrong):
- Everything here is best-effort *display*. The abstraction drops details the source
  didn't have: Smi tag/untag, pointer decompression, 32-bit masks are shown, but
  element addressing collapses `base + index*scale` back to `base[index]`.
- Any instruction the lifter doesn't model is emitted verbatim as its arm64 line, so
  no information is lost and nothing is fabricated.
- Call arguments are reconstructed where it can be done safely, by resolving the callee's
  register arity (see entry_arity). Calls that use the stack convention render as
  `name(...)` rather than a guess.
- Field *names* are not recoverable at all. AOT tree-shakes the metadata: the class
  offset_in_words_to_field table is empty for every class in the corpus and most Field
  objects are gone with it, so fields render by byte offset, `x1.field_0x8`. That's a
  property of the format, not a gap here.

Register roles for this epoch, confirmed against the FluBench 3.12.2 build and
constants_arm64.h: x15=SP, x29=FP, x30=LR, x26=THR, x27=PP, x28=HEAP_BASE,
x22=NULL (true=+0x20, false=+0x30), x21=DISPATCH_TABLE.
"""
from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from sys import intern

from .cfg import (build_cfg, structure, negate_cond, label_targets, _cond_text, _REL,
                  cond_of, _idoms)

# ── operand / register plumbing ─────────────────────────────────────────────

# General-purpose (w/x) and SCALAR floating-point (s/d) registers. Vector registers are
# left out on purpose: `v0.2d` and `v0.4s` are Float64x2 / Float32x4 SIMD values, not
# scalar doubles, and folding them in here would let the lifter print a plain `a + b` for
# a lane-wise add. The pattern can't match them by construction. An arrangement suffix
# puts the digit before the letter (`.2d`, `.16b`), so `\b[ds]\d+\b` never fires on one.
_REG_RE = re.compile(r"\b([wx](?:3[01]|[12]\d|\d)|[ds](?:3[01]|[12]\d|\d))\b")
_FREG_RE = re.compile(r"^[ds](?:3[01]|[12]\d|\d)$")

# ── memoisation of the operand-text parsers ─────────────────────────────────
#
# The IR below the statement tree is TEXT: an instruction is (addr, mnemonic, op_str,
# note), and every pass that wants to know something about an operand re-parses that
# string. There are a lot of passes, strip_boilerplate, build_cfg, detect_dispatch,
# liveness inside _live_in_header, entry_arity on every call target, then the lifter
# itself, so the same handful of characters gets split, stripped and regex-scanned
# over and over. Measured on the clean corpus binary: 457,622 instructions but only
# 72,784 DISTINCT operand strings (6.3x reuse before a single pass repeats), and one
# `export` run made 2.07M _split_ops calls, 3.67M canon calls and 798k _def_use calls.
# That is ~28 calls per distinct string, all returning the same answer. (_split_ops is
# down to 856k calls per export since strip_boilerplate and detect_dispatch learned to
# skip instructions they cannot match; the reuse ratio is what motivates this, and it
# did not move.)
#
# So they are memoised. This is safe for a structural reason rather than a hopeful one:
# every function here is a pure function of its string argument, with no reference to the
# image, the epoch or any lifter state, and each now returns an IMMUTABLE value (tuple /
# frozenset), so a caller that tried to mutate a shared result would raise rather than
# corrupt the next lookup. Nothing about what the tool prints changes; the same answer is
# simply computed once.
#
# The key space of every cache here is the set of distinct operand strings in the images
# this process opens, so it GROWS WITH THE INPUT: 73k strings and 10.1MB of Python heap
# for a 3MB libapp.so, and a shipped app can be twenty times that. _SPLIT_CACHE is the
# one big enough to care about, so it has a ceiling, and it is emptied rather than evicted
# from. Discarding everything is what an O(1) policy buys, and the hot set comes straight
# back because instructions arrive clustered by function and the common idioms recur in
# every one of them: measured on a full export, the ceiling costs 0.5% of wall time and
# returns 3.9MB. LRU bookkeeping on 856k lookups would cost more than that to save the
# same memory.
#
# The VALUES are interned, and that is not tidiness. Memoising _def_use naively cost
# 17.4MB on one export, because 46,884 distinct (mnemonic, operand) pairs produced 46,884
# separate pairs of frozensets holding just 783 distinct values between them: a bare cache
# buys speed with memory, and this project cares about both. Interning gives the space
# back, and the split tokens likewise collapse from 91,656 string objects to the 48,418
# distinct ones they spell.
_CANON_CACHE: dict = {}
_SPLIT_CACHE: dict = {}
#: Ceiling on _SPLIT_CACHE. 16,384 holds ~95% of the call volume on the corpus binary
#: (measured: the 16,384 commonest of its 45,796 operand strings answer 95.3% of the
#: 856,217 lookups a full export makes), and caps the cache at about 2MB whatever the
#: input.
_SPLIT_CACHE_MAX = 16384
_IMM_CACHE: dict = {}
_MEM_CACHE: dict = {}
_DEFUSE_CACHE: dict = {}          # mnemonic -> operand string -> (defs, uses)
_REGSET_INTERN: dict = {}         # frozenset -> the one copy of it
_DEFUSE_INTERN: dict = {}         # (defs, uses) -> the one copy of it
_USE_RE: dict = {}                # register name -> a word-boundary matcher for it


def canon(reg: str) -> str:
    """Canonical register name: w-view -> x-view, s-view -> d-view; zero reg -> 'xzr'."""
    # Only short tokens can be registers, and gating on that keeps the cache to the ~130
    # spellings that exist instead of the 37,874 operand fragments callers also hand in
    # (immediates, shift specifiers, whole memory operands). Purely a size/locality
    # choice: a long token takes the same code path, it just is not remembered.
    if len(reg) > 4:
        return _canon_uncached(reg)
    hit = _CANON_CACHE.get(reg)
    if hit is not None:
        return hit
    _CANON_CACHE[reg] = out = _canon_uncached(reg)
    return out


def _canon_uncached(reg: str) -> str:
    reg = reg.strip()
    # The alias table is the target's, because one spelling means two registers: `sp` is
    # Dart's SP on both machines, but on arm64 that is x15 and on arm32 it is the hardware
    # R13. Everything else the two disassemblers print is unambiguous.
    hit = _T.aliases.get(reg)
    if hit is not None:
        return hit
    if not reg:
        return reg
    if reg[0] == "w":
        return "x" + reg[1:]
    if reg[0] == "s" and reg[1:].isdigit():
        return "d" + reg[1:]                 # s0 is the low half of d0, as w0 is of x0
    return reg


def _is_fp(reg: str) -> bool:
    return bool(_FREG_RE.match(reg))


def _vd(tok: str):
    """`d3` / `v3.2d` -> 'd3'; anything else -> None.

    Use this only for the handful of instructions the SDK proves are scalar despite
    carrying a vector arrangement. Everything else goes through _scalar_fp_ops, which
    rejects any operand with a suffix."""
    t = tok.strip()
    if t.endswith(".2d") and t[:1] == "v" and t[1:-3].isdigit():
        return "d" + t[1:-3]
    c = canon(t)
    return c if _is_fp(c) else None


def _scalar_fp_ops(ops) -> bool:
    """True when every register operand is a BARE scalar s/d register.

    An arrangement suffix (`.2d`, `.4s`, `.8h`, `.16b`) means the instruction works on a
    vector, so `fadd v0.2d, v1.2d, v2.2d` is a Float64x2 add and must not be rendered as
    scalar arithmetic. assembler_arm64 emits the scalar forms with bare registers."""
    for t in ops:
        t = t.strip()
        if "." in t or t.startswith("v"):
            return False
    return True


# machine registers with a fixed role; used both as leaf display names and to keep the
# lifter from mistaking a role register for an object/argument.
#: Architectures this lifter has a register-role model for. Tier 1 decodes more than this
#: (disasm.py), and the difference is deliberate: annotated arm32 is honest without any of
#: the tables below, while lifting arm32 through the arm64 roles is not merely incomplete,
#: it is WRONG in the one direction that matters. `ldr r0, [sl, #0x3c]` reads a canonical
#: object out of the thread, and with no role for r10 it renders as `sl.field_0x3d`, a
#: field access, on an untagged pointer, with the tag bias added anyway. A reader cannot
#: tell that from a real field read.
#:
#: The gate used to be incidental: `disassemble_range` refused arm32, so nothing here was
#: ever reached with it. Tier 1 now decodes arm32, so the invariant has to be stated where
#: it actually holds instead of relying on a refusal three modules away.
@dataclass(frozen=True)
class Target:
    """The per-architecture facts the lifter reads a register file through.

    Everything here is a statement about the Dart AOT calling convention for one machine,
    cited to the VM's own constants header. It is a table rather than a policy: nothing in
    it is inferred from a binary, so a wrong entry is a wrong reading of the SDK and can be
    checked against it directly.
    """
    name: str
    roles: dict          # canonical register -> role name shown in the output
    untagged: frozenset  # roles holding an UNtagged address (no kHeapObjectTag bias)
    arg_regs: tuple      # registers Dart passes arguments in, in order
    zero: str            # the always-zero register, or "" where the machine has none
    aliases: dict        # what the disassembler prints -> canonical name
    ret_int: str
    ret_fp: str
    #: Canonical objects the machine reads out of a fixed base, as {offset: name}. arm64
    #: keeps null in a register and reaches true/false at offsets above it; arm32 has no
    #: register to spare and reads all three out of the thread. Getting these backwards
    #: would invert a boolean quietly, which is the worst thing this file can do, so both
    #: tables are measured rather than assumed.
    consts_base: str
    consts: dict
    #: The incoming stack argument area, as an offset from FP. Reading one is what tells
    #: `entry_arity` the register count is not the signature.
    incoming_from_fp: int
    #: Machine word in bytes. Where it is smaller than a Dart `int`, a 64-bit value lives
    #: in two registers and the lifter has to read the pair as one value; see `State.pair`.
    word: int = 8

    @property
    def pairs(self) -> bool:
        return self.word < 8

    @property
    def special(self) -> frozenset:
        return frozenset(self.roles) | ({self.zero} if self.zero else frozenset())


#: constants_arm64.h. x15 is Dart's SP (the hardware SP is used only in the prologue),
#: x22 is NULL with the Bool singletons just above it, x21 is the dispatch table.
ARM64 = Target(
    name="arm64",
    roles={"x15": "SP", "x29": "FP", "x30": "LR", "x26": "THR", "x27": "PP",
           "x28": "HEAP", "x22": "NULL", "x21": "DISPATCH"},
    untagged=frozenset({"x15", "x21", "x22", "x26", "x27", "x28", "x29", "x30"}),
    arg_regs=("x1", "x2", "x3", "x5", "x6", "x7"),
    zero="xzr",
    aliases={"wzr": "xzr", "xzr": "xzr", "wsp": "x15", "sp": "x15"},
    ret_int="x0", ret_fp="d0",
    # `add xD, x22, #imm`: every one in all fifteen arm64 corpus builds plus the
    # uncompressed iOS build uses 0x20 or 0x30 and nothing else.
    consts_base="NULL", consts={0x20: "true", 0x30: "false", 0x0: "null"},
    incoming_from_fp=0x10, word=8,
)

#: constants_arm.h, Android (non-iOS, so FP=R11 and DISPATCH_TABLE_REG=NOTFP=R7).
#: Two differences from arm64 matter more than the numbering:
#:
#:   * there is NO null register. arm64 keeps null in x22 with true and false at fixed
#:     offsets above it; arm32 has no register to spare, so the canonical objects are read
#:     out of the thread (THR+0x38 is true, THR+0x3c is false, both confirmed against
#:     benchWithdraw's two return paths).
#:   * there is no kCpuRegistersForArgs. arm64 passes up to six Dart arguments in
#:     registers; arm32 passes every one on the stack, which is why `entry_arity` declines
#:     for every arm32 callee and the outgoing-area path does all the work.
ARM32 = Target(
    name="arm",
    roles={"r13": "SP", "r11": "FP", "r14": "LR", "r10": "THR", "r5": "PP",
           "r7": "DISPATCH", "r12": "TMP"},
    untagged=frozenset({"r13", "r11", "r14", "r10", "r7", "r12"}),
    arg_regs=(),
    zero="",
    aliases={"sl": "r10", "fp": "r11", "ip": "r12", "sp": "r13", "lr": "r14",
             "pc": "r15", "sb": "r9"},
    ret_int="r0", ret_fp="d0",
    # `ldr rD, [THR, #imm]`. Thread's CACHED_VM_OBJECTS_LIST is object_null_, bool_true_,
    # bool_false_ in that order, so on a 32-bit build they are three consecutive 4-byte
    # fields. Both ends are pinned against real source, benchWithdraw returns false from
    # 0x3c on the over-balance path and true from 0x38 on the success path, and null
    # sits between the two at 0x34, which is also the most-read offset in the image by a
    # factor of four (14,969 loads, against 3,821 for true).
    consts_base="THR", consts={0x34: "null", 0x38: "true", 0x3c: "false"},
    incoming_from_fp=8, word=4,
)

TARGETS = {t.name: t for t in (ARM64, ARM32)}

#: The targets `lift` will actually run on, which is NOT simply "every target with a
#: table". A table is a claim about the calling convention; being in this set is a claim
#: that the output has been checked against source, which is what semdiff does. A target
#: is added here when its checks pass, not when its roles are written down.
LIFTABLE_ARCHS = frozenset({"arm64"})

#: The target the module-level helpers read. `canon` is called from 49 places and from
#: functions that have no lifter to hand, so the binding is scoped to one lift by
#: `lift_function` rather than threaded through every signature, the same shape the
#: canon cache beside it already has. Single-threaded, and restored in a finally.
_T = ARM64

ROLE = ARM64.roles
_SPECIAL = set(ARM64.roles) | {"xzr"}

# role registers that hold an UNtagged address (no kHeapObjectTag bias on field loads)
_UNTAGGED = ARM64.untagged

# NULL_REG + offset -> Bool singleton. Getting these backwards would invert a boolean,
# which is the worst thing this file could do quietly, so they are measured rather than
# assumed: every `add xD, x22, #imm` in all fifteen arm64 corpus builds (dart 2.19.6
# through 3.12.2) plus the uncompressed-pointer iOS build uses 0x20 or 0x30 and nothing
# else. The order follows the VM heap layout, null then true then false, and semdiff's
# "the success path returns true" check pins the direction against real source.
# arm32 never reaches here, disassemble_range refuses it before the lifter runs.

# Runtime stub classification: a `bl` to a VM stub (named _iso_stub_<Base>[Shared...]Stub) is
# compiler machinery, not a source call. Render the ones with source meaning (throw,
# allocation) and drop the rest (stack check, write barrier, type test, lazy init).
_STUB_RE = re.compile(r"_iso_stub_(.+?)(?:Shared(?:With|Without)FPURegs)?Stub\b")
_ALLOC_TYPE = {"Array": "List", "GrowableArray": "List", "Mint": "int", "Double": "double",
               "Float64Array": "Float64List", "Record2": "Record", "Record3": "Record",
               "Object": "Object", "Context": "Context", "Closure": "Closure"}


def _classify_stub(name: str):
    """(kind, label) for a runtime-stub call target. kind in
    throw|rethrow|throw_err|alloc|suppress|keep."""
    m = _STUB_RE.search(name)
    if not m:
        return ("keep", name)
    base = m.group(1)
    if base == "Throw":
        return ("throw", None)
    if base == "ReThrow":
        return ("rethrow", None)
    if ("WriteBarrier" in base or "TypeTest" in base or base.startswith("StackOverflow")
            or base.startswith("InitLate") or base in ("InitAsync", "Await", "CloneContext")):
        return ("suppress", None)
    if base.endswith("Error"):
        return ("throw_err", base)
    if base.startswith("Allocate"):
        t = base[len("Allocate"):]
        return ("alloc", _ALLOC_TYPE.get(t, t))
    return ("keep", base)


#: cache miss marker, so a memoised None is distinguishable from an absent entry
_MISS = object()


def _split_ops(op: str) -> tuple:
    """Split an operand string on top-level commas (commas inside `[...]` are kept)."""
    hit = _SPLIT_CACHE.get(op)
    if hit is not None:
        return hit
    if len(_SPLIT_CACHE) >= _SPLIT_CACHE_MAX:
        _SPLIT_CACHE.clear()
    _SPLIT_CACHE[op] = out = _split_ops_uncached(op)
    return out


def _split_ops_uncached(op: str) -> tuple:
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(op):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(intern(op[start:i].strip()))
            start = i + 1
    tail = op[start:].strip()
    if tail:
        parts.append(intern(tail))
    return tuple(parts)


def _imm(tok: str):
    """Parse a `#imm` / bare immediate token to int, or None."""
    if tok is None:
        return None
    hit = _IMM_CACHE.get(tok, _MISS)
    if hit is not _MISS:
        return hit
    _IMM_CACHE[tok] = out = _imm_uncached(tok)
    return out


def _imm_uncached(tok: str):
    tok = tok.strip().lstrip("#").rstrip("]!").strip()
    try:
        return int(tok, 16) if tok.lower().startswith(("0x", "-0x")) else int(tok)
    except ValueError:
        return None


def _regs(tokens) -> frozenset:
    """Canonical registers mentioned anywhere in these operand tokens (minus zero reg)."""
    out = set()
    for t in tokens:
        for m in _REG_RE.findall(t):
            r = canon(m)
            if r != "xzr":
                out.add(r)
    fs = frozenset(out)
    return _REGSET_INTERN.setdefault(fs, fs)


def _mem(operand: str):
    """Parse a memory operand `[base(, #disp | , index(, lsl #s))](!)` ->
    (base, disp, index, scale, writeback) or None."""
    hit = _MEM_CACHE.get(operand, _MISS)
    if hit is not _MISS:
        return hit
    _MEM_CACHE[operand] = out = _mem_uncached(operand)
    return out


#: `_addr` saw a writeback operand it could not read. Distinct from "there was none",
#: because a base register that moves by an unknown amount must not be modelled at all.
_BAD_POST = object()


def _addr(ops) -> tuple | None:
    """(memory operand, post-index delta) for a load/store operand list, or None.

    arm64 writes three addressing forms and only two of them keep the whole address
    inside the brackets. `ldr x2, [x4], #8` reads [x4] and THEN advances x4 by 8, so the
    displacement is a SEPARATE operand after the closing bracket. Parsing only the last
    operand found a bare `#8`, decided there was no memory operand at all, and dropped the
    instruction to the raw arm64 fallback: 2,216 lines on the corpus binary, most of them
    the pointer-bumping loops in the core library's copy and hash routines.

    The delta is 0 when the base does not move, and `_BAD_POST` when there is a writeback
    operand this cannot read, which the caller must treat as unmodelled.
    """
    i = None
    for k in range(len(ops) - 1, -1, -1):
        if "[" in ops[k]:
            i = k
            break
    if i is None:
        return None
    m = _mem(ops[i])
    if m is None:
        return None
    post = 0
    if i + 1 < len(ops):
        post = _imm(ops[i + 1])
        if post is None:
            post = _BAD_POST
    return m, post


def _mem_uncached(operand: str):
    s = operand.strip()
    if "[" not in s:
        return None
    wb = s.rstrip().endswith("!")
    inner = s[s.find("[") + 1: s.rfind("]")]
    ps = [p.strip() for p in inner.split(",")]
    base = canon(ps[0])
    disp, index, scale = 0, None, 0
    if len(ps) >= 2:
        if ps[1].startswith("#"):
            disp = _imm(ps[1]) or 0
        else:
            index = canon(ps[1])
            if len(ps) >= 3 and "lsl" in ps[2]:
                scale = _imm(ps[2].split("lsl")[-1]) or 0
    return base, disp, index, scale, wb


# ── value model: (text, precedence) ─────────────────────────────────────────

P_ATOM, P_POST, P_UNARY = 100, 95, 70
P_MUL, P_ADD, P_SHIFT, P_AND, P_XOR, P_OR, P_CMP = 50, 45, 40, 35, 30, 25, 20
#: `?:` binds looser than everything above it, so a conditional select nested anywhere
#: gets brackets. Dart's precedence table, not C's: `&` and `|` bind TIGHTER than `==`
#: there, which is why the bitwise levels sit above P_CMP and no rewrite is needed.
P_TERN = 15

# arm64 lets a data-processing instruction shift or extend its second source operand in
# the same encoding: `add x0, x1, x2, lsl #3` is one instruction meaning x1 + (x2 << 3).
# Reading only the bare register turns that into `x1 + x2`, which is not a gap in the
# output, it is a confident wrong answer, and there are five figures of them in a single
# binary. `ror` has no Dart spelling, so it is named rather than approximated.
#: Dart has both shifts and they are not the same operator: `>>` is arithmetic
#: (sign-propagating) and `>>>` is logical (zero-filling, Dart 2.14+). Rendering
#: `lsr` as `>>` said "arithmetic" about a logical shift, which is a different
#: number for every negative value, a confident wrong answer of exactly the kind
#: the note above refuses for `ror`. 308 `lsr` sites in the 3.12.2 clean build.
_SHIFT_SYM = {"lsl": "<<", "lsr": ">>>", "asr": ">>"}
_EXTENDS = ("sxtw", "uxtw", "sxth", "uxth", "sxtb", "uxtb", "sxtx", "uxtx")

#: `lsl #3`, and every extending form that also takes a shift: `sxtw #2` scales by four
#: just as `lsl #2` does. A5.1.4 spells the amount the same way in both.
_SHIFT_RE = re.compile(r"\b(?:lsl|" + "|".join(_EXTENDS) + r")\s*#?(\d+)")


def _shift_amount(tok: str) -> int:
    """Left-shift an addressing operand applies, or 0 when it applies none."""
    m = _SHIFT_RE.search(tok)
    return int(m.group(1)) if m else 0


#: Every binary operator the renderer prints, with the precedence it prints it at. The
#: renderer puts a space on each side of all of them (`_bin` is `f"{a} {op} {b}"`), so a
#: space-delimited match cannot collide with a unary minus or with `~/` in an identifier.
_BINOP_PREC = {"*": P_MUL, "~/": P_MUL, "+": P_ADD, "-": P_ADD,
               "<<": P_SHIFT, ">>": P_SHIFT, "&": P_AND, "^": P_XOR, "|": P_OR,
               "==": P_CMP, "!=": P_CMP, "<=": P_CMP, ">=": P_CMP, "<": P_CMP,
               ">": P_CMP, "?": P_TERN, ":": P_TERN}
_BINOP_RE = re.compile(r" (" + "|".join(re.escape(o) for o in
                                        sorted(_BINOP_PREC, key=len, reverse=True)) + r") ")
#: `a op (b op c)` is `(a op b) op c` for these and for no others, which is what decides
#: whether a compound assignment may keep a remainder at its own precedence.
_ASSOCIATIVE = frozenset({"*", "+", "&", "|", "^"})


def _top_level_ops(text: str) -> set:
    """The binary operators of `text` that sit outside every bracket."""
    out, depth = set(), 0
    for i, ch in enumerate(text):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == " " and depth == 0:
            m = _BINOP_RE.match(text, i)
            if m:
                out.add(m.group(1))
    return out


def _folds_into(sym: str, rest: str) -> bool:
    """Whether `lhs sym= rest` says the same thing as `lhs = lhs sym rest`.

    It does when everything left at the top of `rest` binds TIGHTER than `sym`, since the
    implied bracket around `rest` then changes nothing, or when the operator is the same
    one and associates, where the bracket moves but the value does not.
    """
    prec = _BINOP_PREC[sym]
    for op in _top_level_ops(rest):
        if _BINOP_PREC[op] > prec:
            continue
        if op == sym and sym in _ASSOCIATIVE:
            continue
        return False
    return True


@dataclass(frozen=True)
class V:
    text: str
    prec: int = P_ATOM


def _wrap(v: V, ctx: int) -> str:
    return v.text if v.prec >= ctx else f"({v.text})"


def _bin(a: V, op: str, b: V, prec: int) -> V:
    # The RIGHT operand is wrapped one level tighter than the left, because every operator
    # here associates to the left and several of them do not commute. `sub x2,x1,#2` then
    # `sub x3,xC,x2` printed `30 - x1 - 2`, which reads as `(30 - x1) - 2` and is four
    # short of the `30 - (x1 - 2)` the CPU computes; `a * (b ~/ c)` printed `a * b ~/ c`,
    # which divides a different numerator. Found by evaluating the printed text against
    # the hardware, not by reading it.
    return V(f"{_wrap(a, prec)} {op} {_wrap(b, prec + 1)}", prec)


def _num(n: int) -> V:
    return V(str(n) if -256 < n < 256 else hex(n), P_ATOM)


_INT_LITERAL = re.compile(r"-?(?:0x[0-9a-fA-F]+|\d+)\Z")
#: A store target that is a field of an object. The third alternative is a field the
#: snapshot still names (fields.py): `this.balance = 8` is the same store as
#: `this.field_0x8 = 8` and wants the same Smi note, so recovering the name must not
#: silently drop it. Dart's private names carry a library id, `_state@5048458`.
_FIELD_LHS = re.compile(
    r"\.(?:field_0x[0-9a-fA-F]+|tags|[A-Za-z_$][A-Za-z0-9_$]*(?:@\d+)?)\Z")

#: The name the receiver alias is bound to (program.receiver_for). A field name is only
#: attached to a base spelled exactly this, so it is worth having one spelling of it.
_RECEIVER = "this"

#: A rendered value that reads the heap somewhere inside it: a field, an object header, or
#: an element. Anything matching is only sound while the memory still holds what it held.
#:
#: The last alternative is why this is not just the byte-offset spelling. Once fields.py
#: recovers a name, the same read prints as `this.balance`, and a pattern that only knew
#: `field_0x` would stop seeing it, so exactly the fields we understand best would be
#: the ones left stale across a call. A name is only ever attached to the receiver alias,
#: which bounds the widening to that one base rather than every dotted expression.
_READS_MEMORY = re.compile(
    r"\.field_0x[0-9a-fA-F]+|\.tags\b|\[|\b" + _RECEIVER + r"\.[A-Za-z_$]")


def _in_cond(v: V) -> str:
    """A value substituted into a condition skeleton built by cfg._cond_text.

    The skeleton is text, so the substitution point carries no precedence with it: a
    register inside `(x1 & x2) == 0` sits in an `&` context, and one either side of a
    relational operator does not. Wrapping only below P_CMP was calibrated for the second
    case and silently reassociated the first, so `tst` against an `orr` result printed
    `(a | b & x2) == 0`, which in Dart means `a | (b & x2)`, a different predicate over
    different values. Anything that is not already a single term gets brackets; that is
    correct at every substitution point rather than at most of them.
    """
    return v.text if v.prec >= P_UNARY else f"({v.text})"


def _smi_note(lhs: V, rhs: V) -> str:
    """Trailing note giving a stored constant's untagged reading, where there is one.

    A Dart Smi is stored shifted left by one, so `field_0xc = 8` is the integer 4 and
    nothing on the line says so. Working that out by hand is exactly the kind of quiet tax
    that costs an hour on a flag that turns out to be `(v >> 1) - 1`.

    It is a note and not a rewrite because the invariant does not hold for every field:
    Dart unboxes int and double fields, and an unboxed slot holds the raw value. Odd
    constants stored into fields are the visible proof, they cannot be Smis at all. So
    this offers the reading rather than asserting it, and stays silent when the arithmetic
    would tell the reader nothing (zero, or a value that is not a plain literal)."""
    if not (_FIELD_LHS.search(lhs.text) and _INT_LITERAL.match(rhs.text)):
        return ""
    n = int(rhs.text, 0)
    if n == 0 or n % 2:
        return ""
    return f"   // {n >> 1} if Smi"


# ── per-function register state (forked at branches, threaded through the tree) ──

# Above this many characters a register's expression stops being inlined into its uses and
# is given a name instead. Substituting a value into every use is what makes the output read
# like source, but the substitution is textual: a value used twice doubles. A chain of pure
# combines (SystemHash.hash20, Matrix4.determinant) doubles per step, so the text grows as
# 2^n, hash10 renders one 774 MB line, and hash20 never finishes. Naming the value bounds
# it at the cost of one extra statement. 99% of lifted lines sit under 153 characters, so
# this only fires where the expression had stopped being readable anyway.
MAX_INLINE_CHARS = 200


class State:
    __slots__ = ("reg", "slot", "elem", "result", "poolbase", "spill", "tmpc", "pair")

    def __init__(self):
        self.reg: dict = {}          # canonical reg -> V
        self.slot: dict = {}         # "(base,disp)" stack slot -> V
        self.elem: dict = {}         # reg -> (base V, index V, scale) for element addrs
        # Temps waiting to be written out. set() can decide a value needs a name, but it is
        # the block walker that owns the line list, so the declaration is parked here and
        # drained at the instruction that produced it.
        self.spill: list = []
        # Boxed so forked states keep numbering from a shared counter; two arms of an if
        # must not both mint a "t3".
        self.tmpc: list = [0]
        # Which return register was written most recently. Dart returns integers and
        # references in R0 and doubles in V0 (constants_arm64.h kReturnReg/kReturnFpuReg),
        # and a function can touch both (a double-returning loop still counts in x0). So
        # the choice has to follow the writes, not which register merely holds a value.
        self.result: str = _T.ret_int
        # reg -> ObjectPool byte offset established by `add xD, x27, #hi(, lsl #sh)`, the
        # base half of a far pool load. Without this the following ldr looks like a field
        # read on the PP register and renders as PP+0x9.field_0x2a1, which is not a thing.
        self.poolbase: dict = {}
        # HIGH register -> the register holding the low half, where the machine carries a
        # Dart `int` in two of them. The VALUE lives under the low register and is the
        # whole 64 bits; this map only records which other register is its top half, so a
        # store of both halves can be read back as one assignment rather than two.
        self.pair: dict = {}

    def copy(self) -> "State":
        s = State()
        s.reg = dict(self.reg)
        s.slot = dict(self.slot)
        s.elem = dict(self.elem)
        s.result = self.result
        s.poolbase = dict(self.poolbase)
        s.pair = dict(self.pair)
        s.tmpc = self.tmpc
        return s

    def _unpair(self, reg: str):
        """Writing either half ends the pairing. Both directions: overwriting the low
        register leaves the high one describing a value that is gone, and overwriting the
        high one means the low register is no longer half of anything."""
        self.pair.pop(reg, None)
        for hi, lo in [(h, l) for h, l in self.pair.items() if l == reg]:
            del self.pair[hi]

    def get(self, reg: str) -> V:
        reg = canon(reg)
        if reg == "xzr":
            return V("0", P_ATOM)
        if reg in self.reg:
            return self.reg[reg]
        return V(ROLE.get(reg, reg), P_ATOM)

    def forget(self, reg: str):
        """Drop what is known about `reg` WITHOUT touching `result`.

        `set` records x0/d0 as the return register the function last wrote, which is how
        `ret` decides between the integer and the double. Invalidating a set of registers
        is not a write and must not vote: a loop containing a call clobbers x0 and d0
        both, and setting them in set order made the rendered `return` depend on Python's
        per-process string hashing. Two runs of the same binary printed different source."""
        self.reg[reg] = V(reg, P_ATOM)
        self.elem.pop(reg, None)
        self.poolbase.pop(reg, None)
        self._unpair(reg)

    def set(self, reg: str, v: V):
        reg = canon(reg)
        if reg == "xzr":
            return
        if len(v.text) > MAX_INLINE_CHARS and v.prec != P_ATOM:
            # An atom is already its own name, so there is nothing to gain from aliasing it;
            # only computed text is worth breaking up.
            name = f"t{self.tmpc[0]}"
            self.tmpc[0] += 1
            self.spill.append(f"var {name} = {v.text};")
            v = V(name, P_ATOM)
        self.reg[reg] = v
        self.elem.pop(reg, None)
        self.poolbase.pop(reg, None)
        self._unpair(reg)
        if reg in (_T.ret_int, _T.ret_fp):
            self.result = reg


#: A name this lifter minted for a value, a phi result or a loop-carried variable,
#: as opposed to a machine register or a source-level name. It is spelled only in the
#: printed body, so dropping it loses the only statement that says what the value is.
_MINTED_RE = re.compile(r"t\d+")


def _use_re(name: str):
    """A word-boundary matcher for one register or temporary name, memoised.

    Same cache `_pin` uses, and for the same reason: these are asked for over and over,
    one per name, and the set of names is tiny."""
    pat = _USE_RE.get(name)
    if pat is None:
        pat = _USE_RE[name] = re.compile(rf"\b{re.escape(name)}\b")
    return pat


def _is_lr_spill(reg: str, st: State) -> bool:
    """True when `reg` is the link register still holding the incoming return address."""
    lr = next((r for r, v in _T.roles.items() if v == "LR"), None)
    return canon(reg) == lr and lr not in st.reg


def _drop_outgoing(st: State):
    """Forget the outgoing-argument area. A call consumes it, and leaving the slots behind
    would let one call's arguments be read back as the next call's."""
    sp = next((r for r, v in _T.roles.items() if v == "SP"), "x15")
    for key in [k for k in st.slot if k.startswith(sp)]:
        del st.slot[key]


def _merge(dst: State, a: State, b: State):
    """Post-if state: keep registers/slots the two arms agree on, else drop to symbolic.

    Dropping a register has to be RECORDED, not just omitted. An omitted register falls
    back to the receiver alias in _leaf, so an instance method whose then-arm overwrote x1
    printed `this` for it after the join, on a path where x1 is provably not this. The
    disagreement is a fact about the register and the map has to hold it."""
    agreed = {r: a.reg[r] for r in a.reg if r in b.reg and b.reg[r] == a.reg[r]}
    # sorted, because this INSERTS into the map that `_pin` later walks in insertion order
    # to hand out temporary names. A set of strings iterates in an order that depends on
    # Python's per-process hash seed, so leaving it unsorted made two runs over the same
    # binary give the same two values the names `t10` and `t11` the other way round,
    # roughly one run in five differed. The same lesson is recorded at the loop header; it
    # applies to every write into `reg`, not only that one.
    for r in sorted(a.reg.keys() | b.reg.keys()):
        if r not in agreed:
            agreed[r] = V(r, P_ATOM)
    dst.reg = agreed
    dst.slot = {k: a.slot[k] for k in a.slot if k in b.slot and b.slot[k] == a.slot[k]}
    dst.elem = {r: a.elem[r] for r in a.elem if b.elem.get(r) == a.elem[r]}
    # Which register the function last wrote a RESULT to is a fact about the arms, exactly
    # as the register map is, and it decided the wrong thing when it was left behind: a
    # function that computes its double in both arms of an `if` and returns at the join
    # wrote d0 twice and printed `return x0;`, naming a register nothing ever set.
    # `_render_loop` already takes the body's answer; this is the same rule for the join.
    if a.result == b.result:
        dst.result = a.result


# ── boilerplate stripping (frame + thread stack-overflow check) ─────────────

#: Every pattern strip_boilerplate recognises starts with one of these. Anything else
#: cannot open any of them, so the operand parsing is skipped for it entirely.
_BOILER_MNEMONICS = frozenset({"stp", "ldp", "mov", "add", "sub", "ldr", "ldur",
                               "tst", "sbfiz", "push", "pop"})


def _regs_in_list(op: str) -> list:
    """The registers of an arm32 `{r4, fp, lr}` register list, canonicalised."""
    return [canon(t) for t in op.strip().strip("{}").split(",") if t.strip()]


def strip_boilerplate(ann: list) -> list:
    """Nop out the compiler-emitted prologue/epilogue and the stack-overflow check.
    They become nops rather than being dropped, so addresses stay stable and branch
    targets still resolve. The stack check's slow-path block is then unreachable and
    structure() skips it."""
    out = list(ann)
    n = len(out)

    def nop(i):
        t = out[i]
        out[i] = (t[0], "nop", "", t[3])          # address and note survive, as before

    for i, (addr, mn, op, note) in enumerate(ann):
        # Every branch below is keyed on the mnemonic, so anything not spelled here
        # cannot match any of them. Checking that first skips the operand work for the
        # ~70% of instructions that were only ever going to fall through.
        if mn not in _BOILER_MNEMONICS:
            continue
        ops = _split_ops(op)
        dst0 = canon(ops[0]) if ops else ""
        # frame chain: any stp/ldp of the FP/LR pair, or SP<->FP moves / SP frame adjust
        if mn in ("stp", "ldp") and {canon(ops[0]) if ops else "",
                                     canon(ops[1]) if len(ops) > 1 else ""} == {"x29", "x30"}:
            nop(i)
        elif (mn in ("mov", "add") and _T.roles.get(dst0) == "FP" and len(ops) > 1
              and _T.roles.get(canon(ops[1])) == "SP"):
            nop(i)                                 # mov FP, SP
        elif (mn in ("mov", "sub") and _T.roles.get(dst0) == "SP" and len(ops) > 1
              and _T.roles.get(canon(ops[1])) == "FP"):
            nop(i)                                 # mov SP, FP
        elif mn in ("add", "sub") and _T.roles.get(dst0) == "SP":
            nop(i)                                 # SP frame alloc / free
        # arm32 frame chain. `push {fp, lr}` / `pop {fp, pc}` are the stp/ldp pair above
        # written as one instruction each, and `add fp, sp, #0` is `mov FP, SP`. The pop
        # is NOT nopped, it is also the return, and dropping it would delete the only
        # statement in the block that says so; _step reads it as one.
        elif mn == "push" and set(_regs_in_list(op)) <= {"r11", "r14"}:
            nop(i)
        # stack-overflow check: ldr TMP,[THR,#imm]; cmp SP,TMP; b.ls/b.lo <slowpath>
        elif (mn in ("ldr", "ldur") and (m := _mem(op))
              and _T.roles.get(m[0]) == "THR"
              and i + 2 < n and ann[i + 1][1] == "cmp"):
            cmp_ops = _split_ops(ann[i + 1][2])
            br = ann[i + 2]
            if (len(cmp_ops) == 2 and _T.roles.get(canon(cmp_ops[0])) == "SP"
                    and canon(cmp_ops[1]) == dst0
                    and br[1] in ("b.ls", "b.lo", "bls", "blo", "blls", "bllo")):
                nop(i)
                nop(i + 1)
                nop(i + 2)                         # b.ls -> nop: slow path unreachable
        # write barrier after a pointer store: tst TMP, x28(, lsr #32); b.cc skip; bl <stub>.
        # x28 is HEAP_BASE (reserved), so a tst against it can only be the barrier. The
        # preceding tags loads and `and` become dead, and the lifter drops them.
        elif (mn == "tst" and len(ops) >= 2 and _T.roles.get(canon(ops[1])) == "HEAP"
              and i + 2 < n and cond_of(ann[i + 1][1])):
            # The stub call does not always sit immediately after the branch, the
            # compiler may spill LR across it first. Requiring adjacency left those
            # barriers in the output, where they read as source-level logic rather than
            # as the bookkeeping they are. Look through the spill for the call, and take
            # the matching restore with it so the block empties out completely.
            j = i + 2
            while j < n and j <= i + 3 and ann[j][1] in _STORES:
                j += 1
            if j < n and ann[j][1] == "bl":
                for k in range(i, j + 1):
                    nop(k)
                if (j + 1 < n and ann[j + 1][1] in _LOADS
                        and (mm := _mem(ann[j + 1][2])) and mm[0] == "x15"):
                    nop(j + 1)
        # Smi box-or-tag: sbfiz XD, XS, #1, #w; cmp XS, XD, asr #1; b.eq skip; <box as Mint>.
        # The value is the same integer either way, so take the fast path unconditionally and
        # let the Mint slow path fall out as unreachable.
        elif (mn == "sbfiz" and i + 2 < n and ann[i + 1][1] == "cmp"
              and ann[i + 2][1] in ("b.eq", "b.ne")):
            so, co = ops, _split_ops(ann[i + 1][2])
            if (len(so) >= 3 and _imm(so[2]) == 1 and len(co) >= 3
                    and canon(co[0]) == canon(so[1]) and canon(co[1]) == dst0
                    and "asr" in co[2] and "#" in ann[i + 2][2]):
                nop(i + 1)
                tgt = ann[i + 2][2].rsplit("#", 1)[-1]
                t = out[i + 2]
                out[i + 2] = (t[0], "b", f"#{tgt}", t[3])
    return out


# ── liveness (for loop-carried materialisation) ─────────────────────────────

_LOADS = {"ldr", "ldur", "ldrb", "ldurb", "ldrh", "ldurh", "ldrsw", "ldursw", "ldrsb",
          "ldursb", "ldrsh", "ldursh", "ldp", "ldpsw"}
_STORES = {"str", "stur", "strb", "sturb", "strh", "sturh", "stp"}

# scalar FP arithmetic -> (source operator, precedence). Vector forms are excluded at the
# call site by _scalar_fp_ops, not here.
_FP_ARITH = {"fadd": ("+", P_ADD), "fsub": ("-", P_ADD),
             "fmul": ("*", P_MUL), "fdiv": ("/", P_MUL)}


def _fimm(tok: str):
    """`#2.00000000` / `#0.0` -> a tidy literal, else None."""
    t = tok.strip()
    if not t.startswith("#"):
        return None
    body = t[1:]
    try:
        val = float(body)
    except ValueError:
        return None
    return str(int(val)) + ".0" if val == int(val) else repr(val)
_CMP = {"cmp", "cmn", "tst", "fcmp", "fcmpe"}
_CONDB = {"cbz", "cbnz", "tbz", "tbnz"}

#: Flag sources cfg._cond_text knows how to spell, and flag WRITERS it does not. The
#: second set matters as much as the first: a conditional select reads flags set by an
#: earlier instruction, so anything that overwrites them in between has to invalidate the
#: recorded source or the select is rendered against a comparison that no longer holds.
_FLAG_SRC = frozenset({"cmp", "cmn", "tst", "fcmp", "fcmpe", "subs", "adds",
                       "ands", "bics"})
_FLAG_KILL = frozenset({"negs", "adcs", "sbcs", "ccmp", "ccmn", "fccmp", "fccmpe",
                        "bl", "blr"})

#: Conditional select and its aliases -> how many operands sit between the destination
#: and the condition code. Each is an exact expression, not an approximation: the
#: architecture defines them as "d = cond ? a : f(b)" with f the identity, +1, ~ or -.
_CSEL = {"csel": 2, "csinc": 2, "csinv": 2, "csneg": 2,
         "cinc": 1, "cinv": 1, "cneg": 1, "cset": 0, "csetm": 0}


#: What a call destroys. `constants_arm64.h:557-561`: kDartVolatileCpuRegs is
#: kDartAvailableCpuRegs minus kAbiPreservedCpuRegs, spelled out as R0 through R14
#: (kDartFirstVolatileCpuReg = R0, kDartLastVolatileCpuReg = R14, count 15). Every V
#: register is volatile too except VTMP, which is V31 (`:127`, `:572`).
#:
#: Saying a call defines only x0 was not conservative, it was wrong in the unsafe
#: direction: a value cannot survive a call in a volatile register, so liveness treated a
#: post-call read of x5 as a read of the value the CALLER passed in. That made registers
#: look live on entry when they are not, and entry_arity turned them into arguments the
#: function never had.
_CALL_CLOBBERS = frozenset({f"x{i}" for i in range(15)} | {f"d{i}" for i in range(31)})


_NO_REGS = frozenset()
_RET_USES = frozenset({"x0", "d0"})
#: The two instructions that leave a value behind for a later statement to read.
_CALLS = frozenset({"bl", "blr", "blx"})
#: Sentinel for "this block has no call, so nothing needs a liveness answer".
_NO_LIVE = object()


def _def_use(mn: str, op: str):
    """(defs, uses) canonical register sets for one instruction (approximate but sound
    enough for loop liveness: a store defines no register, a compare defines none)."""
    by_op = _DEFUSE_CACHE.get(mn)
    if by_op is None:
        _DEFUSE_CACHE[mn] = by_op = {}
    else:
        hit = by_op.get(op)
        if hit is not None:
            return hit
    out = _def_use_uncached(mn, op)
    by_op[op] = out = _DEFUSE_INTERN.setdefault(out, out)
    return out


def _writeback_base(ops) -> str:
    """The base register a load/store's addressing mode WRITES, or "".

    `ldr x16, [x4], #8` and `str x16, [x2, #8]!` both advance their base, so the base is a
    destination as well as a source. `_def_use` reported neither, and every consumer of it
    reads the answer as "nothing was written here": `_written` is what `_render_loop` uses
    to decide which registers a loop carries and what `_join_kill` uses to decide which
    registers a goto join may keep. A missing DEF makes both of them keep a value the
    machine has already moved past, which is a wrong value rather than a missing one.

    An unreadable post-index operand counts as a write. The base moves by an amount this
    cannot read, which is strictly more reason to treat it as written, not less."""
    got = _addr(ops)
    if got is None:
        return ""
    (base, _disp, _index, _scale, wb), post = got
    return base if (wb or post) else ""


def _def_use_uncached(mn: str, op: str):
    ops = _split_ops(op)
    if not ops and mn != "ret":
        return _NO_REGS, _NO_REGS
    if mn in _STORES:
        return _regs((_writeback_base(ops),)), _regs(ops)
    if mn in _LOADS:
        ndst = 2 if mn in ("ldp", "ldpsw") else 1
        return _regs(tuple(ops[:ndst]) + (_writeback_base(ops),)), _regs(ops[ndst:])
    if mn in _CMP:
        return _NO_REGS, _regs(ops)
    if mn == "ret":
        return _NO_REGS, _RET_USES
    if mn in _CONDB:
        return _NO_REGS, _regs(ops[:1])
    if mn in ("blr", "blx"):
        return _CALL_CLOBBERS, _regs(ops[:1])
    if mn in ("bl", "b", "br", "bx") or cond_of(mn):
        return (_CALL_CLOBBERS if mn == "bl" else _NO_REGS), _NO_REGS
    if mn == "nop":
        return _NO_REGS, _NO_REGS
    return _regs(ops[:1]), _regs(ops[1:])       # alu / mov: dst, srcs


#: Canonical register name <-> bit position. Liveness is a separate question per
#: register with no interaction between them, so the dataflow below runs bit-parallel:
#: one int per block instead of a set of strings, and union / difference / equality
#: become single machine instructions instead of hash-table walks. The register file is
#: 62 names, so every mask fits in one CPython digit-pair.
_REG_BIT: dict = {}
_BIT_REG: list = []


def _reg_mask(regs) -> int:
    m = 0
    for r in regs:
        b = _REG_BIT.get(r)
        if b is None:
            b = _REG_BIT[r] = 1 << len(_BIT_REG)
            _BIT_REG.append(r)
        m |= b
    return m


def _mask_regs(m: int) -> frozenset:
    return frozenset(r for i, r in enumerate(_BIT_REG) if m >> i & 1)


#: (defs, uses) -> the same thing as bitmasks. Keyed on the interned _def_use result, so
#: this holds one entry per distinct pair (about 1,500), not one per instruction.
_DEFUSE_MASKS: dict = {}


def _def_use_masks(mn: str, op: str):
    du = _def_use(mn, op)
    hit = _DEFUSE_MASKS.get(du)
    if hit is None:
        _DEFUSE_MASKS[du] = hit = (_reg_mask(du[0]), _reg_mask(du[1]))
    return hit


def _liveness(blocks) -> tuple:
    """(live_in, live_out) masks per block.

    Same backward dataflow as _live_in_header, over the whole function instead of one
    loop. Two questions ride on it, and neither can be answered at the site that asks:
    whether a value a call produced is ever read, `x0` after `bl` is either the result
    or nothing at all, and which of the registers two arms of a branch disagree about is
    still wanted after they rejoin.
    """
    use, dfn = {}, {}
    for b, blk in blocks.items():
        u = d = 0
        for (_a, mn, o, _n) in blk.insns:
            de, us = _def_use_masks(mn, o)
            u |= us & ~d
            d |= de
        use[b], dfn[b] = u, d
    live_in = {b: 0 for b in blocks}
    order = sorted(blocks, reverse=True)     # high addresses first: one sweep carries it
    changed = True
    while changed:
        changed = False
        for b in order:
            lo = 0
            for s in blocks[b].succ:
                lo |= live_in.get(s, 0)
            li = use[b] | (lo & ~dfn[b])
            if li != live_in[b]:
                live_in[b] = li
                changed = True
    return live_in, {b: _or_all(live_in.get(s, 0) for s in blocks[b].succ) for b in blocks}


def _or_all(values) -> int:
    m = 0
    for v in values:
        m |= v
    return m


def _live_in_header(blocks, nodes, header, preds):
    """Registers live on entry to `header` considering only edges inside `nodes`
    (iterative backward dataflow). These are the loop's read-before-write registers."""
    use, dfn = {}, {}
    for b in nodes:
        u = d = 0
        for (_a, mn, o, _n) in blocks[b].insns:
            de, us = _def_use_masks(mn, o)
            u |= us & ~d
            d |= de
        use[b], dfn[b] = u, d
    succ = {b: [s for s in blocks[b].succ if s in nodes] for b in nodes}
    live_in = {b: 0 for b in nodes}
    # Blocks are keyed by address, and this flows information from a block to its
    # PREDECESSORS, so visiting high addresses first carries it most of the way in one
    # sweep. The fixed point of a monotone dataflow is unique, so the order is a speed
    # choice and not a semantic one. Tracking live_out separately is likewise dropped:
    # it is a pure function of the successors' live_in, so it cannot change in a sweep
    # where no live_in did.
    order = sorted(nodes, reverse=True)
    changed = True
    while changed:
        changed = False
        for b in order:
            lo = 0
            for s in succ[b]:
                lo |= live_in[s]
            li = use[b] | (lo & ~dfn[b])
            if li != live_in[b]:
                live_in[b] = li
                changed = True
    return _mask_regs(live_in[header])


# ── the lifter ──────────────────────────────────────────────────────────────

class Lifter:
    def __init__(self, blocks, pool_map=None, receiver=None, arity=None, dispatch=None,
                 selectors=None, entry=None, fields=None):
        self.blocks = blocks
        self.pool_map = pool_map or {}
        # optional register aliases (e.g. {"x1": "this"} for an instance method)
        self.alias = dict(receiver or {})
        # arity: pc -> callee register-argument count (None if unknown); enables call-site
        # argument reconstruction. _args_desc tracks whether R4 (the ArgumentsDescriptor
        # register) was set in the current block, which marks the stack calling convention.
        self.arity = arity
        self._args_desc = False
        #: The low half of a 64-bit add/sub waiting for its high half; see _pair_step.
        self._pend_pair = None
        #: (mnemonic, base, displacement, register) of the previous memory access, so the
        #: second half of a split 64-bit load or store can be recognised as one.
        self._last_mem = None
        # dispatch: blr address -> (receiver_reg, selector_offset) for X21 dispatch-table calls.
        self.dispatch = dispatch or {}
        # selectors: selector_offset -> source name, recovered from the serialized dispatch
        # table (dispatch.py). Missing entries keep the honest `sel_0x<off>` rendering.
        self.selectors = selectors or {}
        # fields: byte offset -> the RECEIVER's field name, recovered from the surviving
        # Field objects (fields.py). Only the receiver, because that is the only value in
        # the register file whose class the snapshot states; every other base keeps its
        # offset. Empty by default, which is exactly the pre-existing rendering.
        self.fields = fields or {}
        # Block addresses a goto refers to; the renderer defines each exactly once.
        self.labels: set = set()
        self._labelled: set = set()
        # precompute loop metadata reused during the walk
        self._preds = {a: [] for a in blocks}
        for a, b in blocks.items():
            for s in b.succ:
                if s in self._preds:
                    self._preds[s].append(a)
        self.carried = {}    # loop header -> set of carried regs
        # (mnemonic, operands, {reg: rendered value}, register set) for the comparison
        # whose result is sitting in the condition flags right now, or None.
        self._flags = None
        # Registers live after the instruction currently being lifted, as a mask.
        self._live_after = 0
        self._livein, self._liveout = _liveness(blocks)
        #: Temporaries minted for a call result. Only these may be folded back into their
        #: use by _inline_single_use; a temp that exists to STOP an expression growing
        #: must not be inlined back into the expression it was cut out of.
        self.results: set = set()
        #: entry block, and the memoised dominator tree / per-join kill sets `_join_kill`
        #: needs. Built on first use, because most functions never reach a goto join.
        self.entry = entry if entry is not None else (min(blocks) if blocks else 0)
        self._idom = None
        self._killcache: dict = {}
        #: Whether a frame address ever reaches a general register; see _frame_escaped.
        self._escaped = None
        #: (header, {reg: name}, copied) for each loop being walked, innermost last. An
        #: exit inside the body has to write the carried names back itself; see _carry_out.
        self._carrying: list = []
        #: Registers `_phi` has written out as a statement. A bare register is normally the
        #: honest spelling for "whatever the machine has there", and for these it is not:
        #: the printed body has assigned that name, so a reader takes it as that value.
        #: block -> the state the walk left it in, for _reenter.
        self._exit: dict = {}

    def _clobber_call(self, st: State):
        """Forget every value a call destroys.

        `_CALL_CLOBBERS` already says what a call takes with it, kDartVolatileCpuRegs,
        R0-R14 plus every V register but VTMP (`constants_arm64.h:557-561`), and liveness
        has read it that way since the entry_arity fix. The VALUE map did not: a call reset
        the return register and nothing else, so anything the state knew about x1-x14 or
        d0-d30 walked straight through the call that destroyed it and was printed on the
        other side as though it had survived.

        That is a wrong value, not a missing one, and it has two spellings. A register the
        state describes renders its pre-call expression (`ldur d0, [x0, #7]; bl f; fmov d1,
        d0` printed the loaded double as the operand of the fmov). A register it does NOT
        describe is worse, because `_leaf` falls back to the receiver alias: x1 after a call
        printed `this` on a path where x1 is provably whatever the callee left there. The
        same reasoning is already written down at `_merge` for the branch join; a call is
        the other place a register stops meaning what it meant, and it was missing.

        Only registers that would render as something other than their own name are
        recorded. `st.get` already falls back to the bare name for a register it has never
        heard of, so writing the other forty-odd in would cost map churn at every call site
        and change no output.
        """
        touched = (set(st.reg) | set(st.elem) | set(st.poolbase) | set(st.pair)
                   | set(st.pair.values()) | set(self.alias))
        for r in sorted(touched & _CALL_CLOBBERS):
            st.forget(r)

    def _pin_call(self, st: State) -> list:
        """Name every live value that READS MEMORY, before a call that may rewrite it.

        `_clobber_call` covers the registers the ABI destroys. The callee-saved ones keep
        their expressions, and correctly so as VALUES, but an expression that reads a
        field is not a value, it is an instruction to read that field, and the callee may
        have written it. `x20` holding `this.field_0x8` across `bl set` prints the field
        the setter just changed.

        No offset test is possible here, unlike `_pin_mem`: a call can write anything, so
        anything memory-derived goes. It is cheap because it is rare, 58 call sites in 47
        of the 8,194 functions in the 3.12.2 clean build keep such a value across a call.

        Call this AFTER the receiver and arguments have been rendered, so the call site
        itself still spells them the way the reader expects.

        Registers only. A stack slot holding a memory read has the same problem and no
        liveness to consult, and dropping those at every call was measured: the outgoing
        area is what `_stack_args` reconstructs a stack-convention call's arguments from,
        so emptying it cost `benchDecodeFlag` the literal semdiff pins it on. That limit
        is recorded in FINDINGS.md rather than traded for a hard check.
        """
        out = []
        for key, v in sorted(st.reg.items()):
            if key in _CALL_CLOBBERS or not _READS_MEMORY.search(v.text):
                continue
            if not (self._live_after & _reg_mask((key,))):
                continue
            tmp = f"t{st.tmpc[0]}"
            st.tmpc[0] += 1
            out.append(f"var {tmp} = {v.text};")
            st.reg[key] = V(tmp, P_ATOM)
        return out

    # leaf rendering
    def _leaf(self, reg: str, st: State) -> V:
        reg = canon(reg)
        if reg in self.alias and reg not in st.reg:
            return V(self.alias[reg], P_ATOM)
        return st.get(reg)

    def _raw(self, st: State, dst: str, mn: str, op: str) -> list:
        """Emit the instruction verbatim and forget what its destination held.

        The same thing the unmodelled-instruction fallthrough does, reached earlier when a
        modelled instruction turns out to carry an operand we cannot render.
        """
        if dst:
            st.set(dst, V(dst, P_ATOM))
        return [f"{mn} {op}".rstrip()]

    def _src(self, ops: list, i: int, st: State) -> V:
        """Source operand `i` with any shift or extend that follows it applied.

        Returns None when the modifier is one we cannot express, so the caller can fall
        through to the raw arm64 line rather than print an expression that is missing a
        term. Silence is recoverable; a wrong operand is not.
        """
        v = self._leaf(ops[i], st)
        if len(ops) <= i + 1:
            return v
        mod = ops[i + 1].strip().lower()
        if not mod:
            return v
        kind = mod.split()[0]
        amt = _imm(mod.split("#")[-1]) if "#" in mod else 0
        if amt is None:
            return None
        if kind in _SHIFT_SYM:
            return _bin(v, _SHIFT_SYM[kind], _num(amt), P_SHIFT) if amt else v
        if kind in _EXTENDS:
            # The extend itself is a width conversion the value model does not track;
            # the optional amount after it is a genuine left shift and does matter.
            return _bin(v, "<<", _num(amt), P_SHIFT) if amt else v
        return None

    def _result(self, st: State, expr: str, reg: str = None) -> list:
        """Emit a call, and give its result a name when anything reads it.

        `bl f` leaves the result in x0, and the lifter used to say so by putting the bare
        string "x0" in the register map. Every later use then printed a machine register:
        `f(this); ... return x0;` never tells the reader that the value being returned is
        the one the call produced. It is not a guess that it is, the ABI says the result
        is in x0 and liveness says x0 is read before it is written again, so it gets a
        name and the reader can follow it.

        Where nothing reads the result the call is emitted exactly as before, so a
        statement whose value is discarded does not grow a variable nobody uses."""
        reg = reg or _T.ret_int
        if self._live_after & _reg_mask((reg,)):
            name = f"t{st.tmpc[0]}"
            st.tmpc[0] += 1
            self.results.add(name)
            st.set(reg, V(name, P_ATOM))
            return [f"var {name} = {expr};"]
        st.set(reg, V(reg, P_ATOM))
        return [f"{expr};"]

    def _note_flags(self, st: State, mn: str, op: str, ops):
        """Track which comparison the condition flags currently hold, and its operands
        AS THEY READ AT THAT POINT. A `csel` three instructions later has to be rendered
        against the values the `cmp` saw, not against whatever those registers hold by
        then, so the rendering is captured with the comparison rather than recovered at
        the use."""
        if mn in _FLAG_SRC:
            regs = _regs(ops)
            self._flags = (mn, op, {r: self._leaf(r, st) for r in regs}, regs)
        elif mn in _FLAG_KILL:
            self._flags = None
        elif self._flags is not None and _def_use(mn, op)[0] & self._flags[3]:
            self._flags = None      # an operand of the live comparison was overwritten

    def _flag_cond(self, cc: str):
        """The live comparison spelled for condition code `cc`, or None.

        None is the whole point: flags set in another block, by an instruction cfg cannot
        spell, or by a floating-point compare whose V flag means "unordered" all reach
        here and all decline. A conditional select is only rendered when the predicate
        behind it is known exactly."""
        if self._flags is None or cc not in _REL:
            return None
        mn, op, vals, _regs_used = self._flags
        text = _cond_text((0, mn, op, ""), "b." + cc, "")
        if "?" in text:
            return None
        return _REG_RE.sub(
            lambda m: _in_cond(vals.get(canon(m.group(1)), V(m.group(1), P_ATOM))), text)

    def _select(self, st: State, mn: str, ops, g) -> list | None:
        """`csel` and friends -> a conditional expression, or None to leave it raw."""
        nsrc = _CSEL[mn]
        if len(ops) < nsrc + 2:
            return None
        cond = self._flag_cond(ops[nsrc + 1].strip().lower())
        if cond is None:
            return None
        if nsrc == 0:                                   # cset / csetm
            yes = V("1" if mn == "cset" else "-1", P_ATOM)
            no = V("0", P_ATOM)
        elif nsrc == 1:                                 # cinc / cinv / cneg
            a = g(canon(ops[1]))
            yes = (_bin(a, "+", V("1", P_ATOM), P_ADD) if mn == "cinc"
                   else V(("~" if mn == "cinv" else "-") + _wrap(a, P_UNARY), P_UNARY))
            no = a
        else:                                           # csel / csinc / csinv / csneg
            yes, b = g(canon(ops[1])), g(canon(ops[2]))
            no = (b if mn == "csel"
                  else _bin(b, "+", V("1", P_ATOM), P_ADD) if mn == "csinc"
                  else V(("~" if mn == "csinv" else "-") + _wrap(b, P_UNARY), P_UNARY))
        st.set(canon(ops[0]),
               V(f"{cond} ? {_wrap(yes, P_TERN + 1)} : {_wrap(no, P_TERN + 1)}", P_TERN))
        return []

    def _frame_moved(self, st: State, base: str, delta: int):
        """SP or FP moved by a writeback, so every slot keyed on it is stale.

        Stack slots are keyed by displacement from the CURRENT base, which is the only
        thing the lifter can name. Once the base itself moves, an old key names a
        different address, and reading it back would hand a call the argument of a frame
        that no longer exists. There is nothing to rename them to, so they go."""
        if not delta:
            return
        for k in [k for k in st.slot if k.startswith(base)]:
            del st.slot[k]

    def _bump(self, st: State, base: str, delta: int) -> list:
        """The base-register update half of a writeback addressing mode.

        Real dataflow, not bookkeeping: `ldr x16, [x4], #8` in a copy loop advances the
        source pointer, and dropping that leaves the loop reading the same element every
        iteration. Frame registers are handled by _frame_moved instead, because SP moving
        is not a source-level statement."""
        if not delta or _T.roles.get(base) in ("SP", "FP"):
            return []
        cur = self._leaf(base, st)
        step = (_bin(cur, "-", _num(-delta), P_ADD) if delta < 0
                else _bin(cur, "+", _num(delta), P_ADD))
        out = self._pin(st, base)
        out.append(self._assign(V(base, P_ATOM), step))
        st.set(base, V(base, P_ATOM))
        return out

    def _pin(self, st: State, name: str) -> list:
        """Give a name to every tracked value that mentions `name`, before `name` changes.

        The register map holds expressions, not results, and they are substituted into
        their uses later. That is what makes the output read like source, and it is only
        sound while the registers inside them still hold what they held. `ldr x16, [x4],
        #8; str x16, [x2], #8` is a copy loop: x16's value is `x4.field_0x1`, and once x4
        has advanced, printing that text at the store describes the WRONG element.

        Writing the value out at the point the base changes is not a heuristic. The load
        already happened, so the value already exists; this only says so out loud."""
        pat = _USE_RE.get(name)
        if pat is None:
            pat = _USE_RE[name] = re.compile(rf"\b{re.escape(name)}\b")
        out = []
        for holder in (st.reg, st.slot):
            # Sorted by key, so the names handed out here depend only on WHICH registers
            # hold a mention of `name`, not on the order they happened to be inserted in
            # somewhere upstream. Relying on insertion order made the numbering a property
            # of every earlier write into the map, which is a global invariant nobody can
            # check locally; one unsorted set in `_merge` was enough to break it.
            for key, v in sorted(holder.items()):
                if key == name or name not in v.text or not pat.search(v.text):
                    continue
                tmp = f"t{st.tmpc[0]}"
                st.tmpc[0] += 1
                out.append(f"var {tmp} = {v.text};")
                holder[key] = V(tmp, P_ATOM)
        for key, (b, i, _s, _f) in list(st.elem.items()):
            if pat.search(b.text) or pat.search(i.text):
                del st.elem[key]
        return out

    def _pin_mem(self, st: State, loc: str) -> list:
        """Give a name to every LIVE tracked value that reads `loc`, before `loc` changes.

        `_pin` is the same argument about a register: the map holds expressions, not
        results, and `x4.field_0x1` only means what it meant while x4 still points where it
        did. The memory is the other half of that and had no rule at all, so a value loaded
        before a store to the same field kept printing as a read of that field, which
        after the store names the value the store put there.

        Real, and not a corner. `_LinkedHashMapMixin._insert` loads `_length` into x9,
        stores `_length + 1` back, and then indexes `_data` with x9; the lifter printed
        `(this.field_0x10 + (this.field_0x14 >> 1 << 2) + 15).field_0x1 = x2`, which is the
        element one PAST the one the machine writes. Across the 3.12.2 clean build that is
        1,146 printed expressions in 377 of 8,194 functions. Found by tools/irfuzz.py
        --mem, which evaluates the printed statements in order against an emulated CPU with
        real memory behind it.

        LIVENESS decides, and it is not an optimisation. A register the function never
        reads again is never printed, so writing it out would only add a dead declaration:
        `balance -= amount` mentions the field in both the loaded register and the computed
        one, and pinning unconditionally puts two of them in front of every such line.
        """
        if not loc:
            return []
        # `loc` ends in hex digits, so a bare substring match would let `field_0x8` fire
        # inside `field_0x80`, a different field, and a value that is not stale at all.
        pat = re.compile(re.escape(loc) + r"(?![0-9a-fA-F])")
        alias = None
        sel = _FIELD_LHS.search(loc)
        if sel:
            # MAY-ALIAS, and the over-approximation is exact rather than nervous. Two reads
            # at DIFFERENT offsets of a heap object are two different addresses and can
            # never be the same slot; two at the SAME offset are the same slot exactly when
            # the two base expressions name the same object, which the lifter cannot know.
            # `setFrom` writes `x1.field_0x8.field_0x18` while `x2.field_0x8.field_0x18` is
            # live, and those are one address whenever the argument is the receiver. 700
            # store sites in 286 of the 8,194 functions in the 3.12.2 clean build, against
            # 1,146 for the exact case, and covering them cost 356 more lines, 0.2%.
            alias = re.compile(re.escape(sel.group(0)) + r"(?![0-9a-fA-F])")
        elif "[" in loc:
            # An element store off a base whose index is not a literal reaches any element
            # of that base, so every read through the same base goes.
            alias = re.compile(re.escape(loc.split("[", 1)[0]) + r"\[")
        out = []

        def reads(text):
            return bool(pat.search(text) or (alias is not None and alias.search(text)))

        # sorted, for the reason _pin and _merge are: this hands out temporary names, and
        # taking them in map order would make the numbering depend on Python's per-process
        # string hash seed. One unsorted iteration was enough to make two runs over the
        # same binary differ.
        for key, v in sorted(st.reg.items()):
            if v.prec == P_ATOM and v.text == key:
                continue                      # already opaque: nothing to preserve
            if not (self._live_after & _reg_mask((key,))):
                continue
            if not reads(v.text):
                continue
            tmp = f"t{st.tmpc[0]}"
            st.tmpc[0] += 1
            out.append(f"var {tmp} = {v.text};")
            st.reg[key] = V(tmp, P_ATOM)
        # A stack slot has no liveness to consult, it is read back by a later load or not
        # at all, so a slot that reads the written location is dropped rather than named.
        # Dropping is honest (the reload renders as the bare destination register) and does
        # not spend a declaration on a spill nothing reloads.
        for key in [k for k, v in st.slot.items() if reads(v.text)]:
            del st.slot[key]
        for key, (b, i, _s, _f) in list(st.elem.items()):
            if reads(b.text) or reads(i.text):
                del st.elem[key]
        return out

    def _byte_off(self, base_reg: str, disp: int) -> int:
        # tagged object pointers carry kHeapObjectTag=1, so a field at object offset F is
        # loaded as [P, #F-1]; untagged role registers (THR/HEAP/...) have no such bias.
        return disp if base_reg in _UNTAGGED else disp + 1

    def _field(self, base_v: V, byte_off: int) -> V:
        # A name is printed only when the base IS the receiver, because that is the one
        # value whose class the snapshot names (Function.owner). `x3.field_0x8` stays an
        # offset even where some class has a field there: attributing it would be a guess
        # about which class x3 holds, and a wrong field name reads as fact where a byte
        # offset reads as "the lifter does not know".
        name = self.fields.get(byte_off) if base_v.text == _RECEIVER else None
        if name:
            tag = "." + name
        else:
            tag = ".tags" if byte_off == 0 else f".field_0x{byte_off:x}"
        return V(f"{_wrap(base_v, P_POST)}{tag}", P_POST)

    def _call_args(self, name, target, st: State) -> str:
        """Reconstruct a direct call's argument list, or `...` when it cannot be done
        safely. Register-convention calls pass args in x1..xk (k = callee arity); the
        stack convention (ArgumentsDescriptor set) and runtime stubs fall back to `...`.
        Every argument rendered is a real incoming arg of the callee (from its live-in
        set); the receiver of an instance call appears as the first argument."""
        # A missing NAME was treated as a missing signature, and the two have nothing to do
        # with each other: the arity comes from the callee's own entry code, read at the
        # target address. 13,923 direct call sites on the corpus binary fell back to `...`
        # for no reason beyond the callee having no recovered name, which is exactly the
        # population (generated closures, and everything in an --obfuscate build) where
        # the argument list is the only thing left to read. Where the target is not a
        # function this can measure, entry_arity still declines and the `...` stands.
        if ((name and "stub" in name) or self._args_desc
                or self.arity is None or target is None):
            return "..."
        k = self.arity(target)
        if k is None:
            return "..."
        if k == 0:
            return ""
        parts = []
        # ARG_REGS, not x1..xk: the fourth register argument is in X5, and X4 is
        # ARGS_DESC_REG. Walking x1..xk rendered the arguments descriptor as an argument.
        for r in ARG_REGS[:k]:
            if r not in st.reg:        # the caller did not establish this arg locally
                return "..."           # not safe to attribute, so fall back
            parts.append(st.reg[r].text)
        return ", ".join(parts)

    def _stack_args(self, st: State, drop_receiver: bool) -> str:
        """Arguments a call takes on the stack, or None when they cannot be read off.

        Dart passes arguments in registers only when the callee's arity is statically
        known. Everything else, every virtual dispatch, and any call whose
        ArgumentsDescriptor is set, pushes them, so the values are sitting in the
        outgoing area at the moment of the call:

            ldr  x16, [x16, #0xfd0]   ; "FLUBENCH{str_literal_compare}"
            stp  x16, x1, [x15]       ; [SP+0] = the string, [SP+8] = the receiver
            blr  x30                  ; through the dispatch table

        SP-relative is what makes this safe to read. A frame-relative slot (x29) is a local
        or a spill and means nothing to the callee, while the outgoing area is only ever
        written to set up a call, so a contiguous run from SP+0 IS the argument list. The
        run has to start at SP+0 and have no hole, or it is something else and we say
        nothing.

        Argument zero sits at the HIGHEST slot, so the run reads back downwards; when the
        receiver is already printed as the call's base, it is dropped from the list."""
        slots = {}
        sp = next((r for r, v in _T.roles.items() if v == "SP"), "x15")
        for key, val in st.slot.items():
            if not key.startswith(sp):
                continue
            off = _imm(key[len(sp):])
            if off is not None and off >= 0:
                slots[off] = val
        if 0 not in slots:
            return None
        n = 0
        while n * 8 in slots:
            n += 1
        args = [slots[i * 8] for i in range(n - 1, -1, -1)]
        if drop_receiver:
            args = args[1:]
        return ", ".join(a.text for a in args)

    # 64-bit values on a 32-bit machine
    def _pair_step(self, st: State, mn, ops, g):
        """Read the register-pair idioms as one 64-bit value, or return None.

        A Dart `int` is 64 bits and a 32-bit machine has to carry it in two registers, so
        the arithmetic a reader is trying to follow arrives split in half. Only four shapes
        do that, and each is unambiguous:

          asr rH, rL, #31         rH is rL's sign, so (rL, rH) is one value
          subs rD, aL, bL         the low half, and the flags carry the borrow
          sbcs rE, aH, bH         ...the high half, IF both sources are known pairs
          umull rLo, rHi, a, b    a 32x32 -> 64 multiply

        The VALUE is kept under the low register and is the whole 64 bits. The high
        register is recorded in `st.pair` as a pointer back to it and carries no value of
        its own, which is what lets `str lo; str hi` collapse into one assignment and
        stops the high half being printed as a second, unrelated number.

        The pairing is only claimed where BOTH sources are already known pairs. An `sbcs`
        whose operands are not is left raw: it is a 64-bit operation whose other half the
        lifter did not see, and guessing which register that was is how a decompiler starts
        inventing arithmetic.
        """
        pend, self._pend_pair = self._pend_pair, None
        if mn == "asr" and len(ops) >= 3 and _imm(ops[2]) == 31:
            lo = canon(ops[1])
            hi = canon(ops[0])
            if hi != lo:
                st.set(hi, V(hi, P_ATOM))
                st.pair[hi] = lo
                return []
            return None
        if mn in ("subs", "adds") and len(ops) >= 3:
            sym, prec = ("-", P_ADD) if mn == "subs" else ("+", P_ADD)
            a, b = canon(ops[1]), canon(ops[2])
            val = _imm(ops[2])
            other = _num(val) if val is not None else g(ops[2])
            st.set(canon(ops[0]), _bin(g(ops[1]), sym, other, prec))
            self._pend_pair = (mn, canon(ops[0]), a, b)
            return []
        if mn in ("sbcs", "adcs", "sbc", "adc") and len(ops) >= 3 and pend:
            want = "subs" if mn in ("sbcs", "sbc") else "adds"
            _m, dlo, alo, blo = pend
            ah, bh = canon(ops[1]), canon(ops[2])
            if _m == want and st.pair.get(ah) == alo and st.pair.get(bh) == blo:
                hi = canon(ops[0])
                st.set(hi, V(hi, P_ATOM))
                st.pair[hi] = dlo
                return []
            return None
        if mn in ("umull", "smull") and len(ops) >= 4:
            lo, hi = canon(ops[0]), canon(ops[1])
            st.set(lo, _bin(g(ops[2]), "*", g(ops[3]), P_MUL))
            st.set(hi, V(hi, P_ATOM))
            st.pair[hi] = lo
            return []
        return None

    # one instruction
    def _step(self, st: State, addr, mn, op, note) -> list:
        """Update `st`; return any emitted statement lines (usually none)."""
        ops = _split_ops(op)
        g = lambda r: self._leaf(r, st)

        if mn in ("nop", "brk", "hlt") or (not ops and mn not in ("ret",)):
            return []                           # brk/hlt: unreachable trap after a noreturn

        self._note_flags(st, mn, op, ops)

        # A machine narrower than a Dart `int` splits one value across two registers.
        if _T.pairs:
            paired = self._pair_step(st, mn, ops, g)
            if paired is not None:
                return paired

        # a write to R4 (ArgumentsDescriptor) marks the stack calling convention for the
        # next call, which does NOT pass its arguments in x1..xN.
        if "x4" in _def_use(mn, op)[0]:
            self._args_desc = True

        # returns. Dart returns ints and references in R0 and doubles in V0/D0
        # (kReturnReg/kReturnFpuReg); st.result is whichever was written last.
        #
        # arm32 spells the return three ways and all three are one thing. `bx lr` is the
        # leaf form; `pop {..., pc}` restores the frame and jumps to the saved return
        # address in the same instruction, which is why a function can end without any
        # branch at all; `mov pc, lr` is the older form. A `bx rN` for any other register
        # is an indirect branch and NOT a return, so the operand is checked rather than
        # the mnemonic alone.
        if (mn == "ret"
                or (mn == "bx" and _T.roles.get(canon(op)) == "LR")
                or (mn == "pop" and "pc" in [t.strip()
                                             for t in op.strip("{} ").split(",")])
                or (mn == "mov" and len(ops) >= 2 and canon(ops[0]) == "r15"
                    and _T.roles.get(canon(ops[1])) == "LR")):
            return [f"return {g(st.result).text};"]

        # calls
        if mn == "bl":
            name = note.split("-> ", 1)[1].strip() if "-> " in note else None
            target = _imm(ops[0]) if ops and ops[0].startswith("#") else None
            exc = g(_T.ret_int)        # captured before the call clobbers it (throw)
            st.set(_T.ret_int, V(_T.ret_int, P_ATOM))
            self._args_desc = False
            # Read the outgoing area BEFORE dropping it, which is the order `blr` below has
            # always used. Doing it after meant `_call_args` was handed an area that had
            # just been emptied, so a direct call could never fall back to its stack
            # arguments: every declining site measured as "no contiguous run from SP+0"
            # because there was nothing there at all.
            #
            # This is not a second guess at the same question. `entry_arity` declines for
            # ONE reason (the callee reads its arguments off the stack) and that is a
            # statement that the caller PUSHED them, so the values are sitting in the
            # outgoing area. The register convention and the stack convention are two
            # conventions, and the lifter knew how to read both; it just asked in an order
            # that guaranteed the second answer was empty.
            pushed = self._stack_args(st, drop_receiver=False)
            # A direct call consumes the outgoing area exactly as an indirect one does.
            # Leaving it behind let a bl's arguments be read back as the arguments of the
            # next blr, a fully fabricated argument list on a call that pushed nothing.
            _drop_outgoing(st)
            if name and "_iso_stub_" in name:   # a VM runtime stub, not a source call
                kind, label = _classify_stub(name)
                if kind == "suppress":
                    # These are the stubs that give the registers back. The shared
                    # stack-overflow and write-barrier entries exist precisely to spill the
                    # volatile set and restore it (`stub_code_compiler_arm64.cc`,
                    # GenerateSharedStub / kWriteBarrierWrappers), and a type-test stub
                    # preserves everything but its own answer. Suppressing the CALL while
                    # clobbering as though it happened would forget the whole loop body a
                    # header stack check sits in front of, for a call that provably keeps it.
                    return []
                self._clobber_call(st)
                if kind == "throw":
                    return [f"throw {exc.text};"]
                if kind == "rethrow":
                    return ["rethrow;"]
                if kind == "throw_err":
                    return [f"throw {label}();"]
                if kind == "alloc":
                    return self._result(st, f"new {label}()")
                terse = label.replace("stub ", "").replace("_iso_stub_", "")
                return self._result(st, f"{terse}(...)")   # terse, without the stub prefix
            call = name or f"sub_0x{target or 0:x}"
            args = self._call_args(name, target, st)
            # after the arguments are read, not before: they live in the very registers the
            # call is about to destroy, and reading them afterwards would print the bare
            # register for every argument of every call. `_pin_call` goes here for the same
            # reason, one step further: it renames what SURVIVES the call, and doing it
            # earlier would rename the arguments too.
            pins = self._pin_call(st)
            self._clobber_call(st)
            if args == "..." and pushed:
                # The receiver is NOT dropped here, unlike the dispatch case. A `blr` prints
                # its receiver as the base of the call (`x.foo(...)`) so listing it again
                # would show it twice; a direct call has no base, so argument zero is the
                # receiver and leaving it out would silently shorten the list.
                args = pushed
            return pins + self._result(st, f"{call}({args})")
        if mn in ("blr", "blx"):
            self._args_desc = False
            tgt = canon(ops[0]) if ops else None
            tgt_val = st.reg.get(tgt) if tgt else None
            st.set(_T.ret_int, V(_T.ret_int, P_ATOM))
            disp = self.dispatch.get(addr)
            stack_args = self._stack_args(st, drop_receiver=bool(disp and disp[0]))
            _drop_outgoing(st)          # consumed by this call; must not reach the next
            if disp is not None:                         # X21 dispatch-table (virtual) call
                recv, off = disp
                named = self.selectors.get(off) if off is not None else None
                base = _wrap(self._leaf(recv, st), P_POST) if recv else None
                pins = self._pin_call(st)   # after the receiver is read, and before it dies
                self._clobber_call(st)   # after the receiver is read; it is x0 as often as not
                if named and base and named.startswith(("get:", "set:")):
                    prop = named.split(":", 1)[1]       # an accessor, not a call, in source
                    return pins + (self._result(st, f"{base}.{prop}")
                                   if named.startswith("get:")
                                   else [f"{base}.{prop} = ...;"])
                sel = (named if named
                       else "dispatch" if off is None
                       else f"sel_0x{off:x}" if off >= 0 else f"sel_m0x{-off:x}")
                shown = stack_args if stack_args is not None else "..."
                if base:
                    return pins + self._result(st, f"{base}.{sel}({shown})")
                return pins + [ln + "   // virtual dispatch"
                               for ln in self._result(st, f"{sel}({shown})")]
            # indirect call through an object field / closure: show what we call through
            shown = stack_args if stack_args is not None else "..."
            # `tgt_val` was read off the state before this point, so the callee register is
            # still spelled as the thing being called and not as its post-call garbage.
            pins = self._pin_call(st)
            self._clobber_call(st)
            if tgt_val and tgt_val.prec >= P_POST and "DISPATCH" not in tgt_val.text:
                return pins + self._result(st, f"{_wrap(tgt_val, P_POST)}({shown})")
            return pins + self._result(st, f"(dynamic call)({shown})")

        # stores: object field (side effect) vs stack slot (tracked, no output)
        if mn in _STORES:
            src = canon(ops[0])
            addr = _addr(ops)
            if addr is None or addr[1] is _BAD_POST:
                return [f"{mn} {op}"]
            (base, disp, index, scale, wb), post = addr
            val = g(src)
            delta = disp if wb else post     # how far the base register moves, if at all
            if post:
                disp = 0                     # post-index: the access is at the OLD base
            if base == "x15" and wb:
                # `stp a, b, [SP, #-0x10]!` moves SP first and stores at the NEW SP, so the
                # values land at SP+0 and SP+8 once the instruction retires. Keying them on
                # the written displacement would file them under an SP that no longer
                # exists, which is how 2.19's argument pushes went unseen.
                disp = 0
            # `stp a, b, [base, #d]` writes TWO registers: a at d and b at d + one slot.
            # Recording only the first silently loses the second, which is how a call's
            # arguments went missing, they are pushed as pairs.
            pair = None
            if mn == "stp" and len(ops) >= 3:
                second = canon(ops[1])
                width = 4 if ops[1].strip().startswith("w") else 8
                pair = (second, disp + width, g(second))
            if _T.roles.get(base) in ("SP", "FP"):           # spill to a stack slot
                self._frame_moved(st, base, delta)
                # Saving the untouched link register is a callee-saved spill, not an
                # argument push. `str x30, [SP, #-8]!` lands at SP+0 exactly like a real
                # push, and _stack_args read it back as argument zero: `f(LR)`. A register
                # the function has since written to is a different matter, x30 doubles as
                # a scratch register, so the test is that x30 still holds the value it
                # came in with.
                if not (base == "x15" and _is_lr_spill(src, st)):
                    st.slot[f"{base}{disp:+d}"] = val
                if pair and not (base == "x15" and _is_lr_spill(pair[0], st)):
                    st.slot[f"{base}{pair[1]:+d}"] = pair[2]
                return []
            # The high half of a split 64-bit field store. The value was already written
            # out by the store of the low half (one 64-bit assignment) so emitting this
            # one would print the same value twice under two different offsets, the second
            # of them wrong. Suppressed only when the register map SAYS these two registers
            # are halves of one value and the slots are adjacent from the same base.
            src0 = canon(ops[0]) if ops else ""
            prev = self._last_mem
            if (_T.pairs and prev and prev[0] == "store" and prev[1] == base
                    and prev[2] + _T.word == disp and st.pair.get(src0) == prev[3]
                    and not index):
                self._last_mem = None
                return self._bump(st, base, delta)
            # Both targets are built BEFORE anything is pinned, because pinning rewrites
            # the register map the base is read through and the second half of an `stp`
            # would then be addressed off a temporary that names the base's old value.
            if index is not None or base in st.elem:          # element store
                tgts = [(self._elem_access(base, index, scale, st, disp), val)]
            else:
                tgts = [(self._field(g(base), self._byte_off(base, disp)), val)]
                if pair:
                    tgts.append((self._field(g(base), self._byte_off(base, pair[1])),
                                 pair[2]))
            out = []
            for tgt, v in tgts:
                # The value being stored was read off the map before this, so `+=` still
                # renders: the rhs keeps the field's own spelling even when a register
                # holding it is pinned on the way past.
                out.extend(self._pin_mem(st, tgt.text))
                out.append(self._assign(tgt, v))
            self._last_mem = ("store", base, disp, src0)
            return out + self._bump(st, base, delta)

        # ── scalar floating point ────────────────────────────────────────────────
        # Scalar forms only. Anything with a vector arrangement falls through to the raw
        # arm64 fallback instead of being flattened into scalar arithmetic.
        if mn in _FP_ARITH and len(ops) >= 3 and _scalar_fp_ops(ops):
            opsym, prec = _FP_ARITH[mn]
            a, b = g(canon(ops[1])), g(canon(ops[2]))
            # Through _bin, so the right operand is wrapped one level tighter. `fsub` and
            # `fdiv` do not commute any more than `sub` and `sdiv` do, and this path was
            # rendering them the way _bin used to: `fsub d0,d1,d2` with d2 holding `d3 - d4`
            # printed `d1 - d3 - d4`. The integer half of that bug was fixed; this half was
            # a separate call site and kept it.
            st.set(canon(ops[0]), _bin(a, opsym, b, prec))
            return []
        if mn in ("fneg", "fabs", "fsqrt") and len(ops) >= 2 and _scalar_fp_ops(ops):
            src = g(canon(ops[1]))
            txt = (f"-{_wrap(src, P_UNARY)}" if mn == "fneg"
                   else f"{_wrap(src, P_POST)}.{'abs' if mn == 'fabs' else 'sqrt'}()")
            st.set(canon(ops[0]), V(txt, P_UNARY if mn == "fneg" else P_POST))
            return []
        if mn in ("fmax", "fmin") and len(ops) >= 3:
            # `.2d` here is NOT a Float64x2 lane-wise op. Dart's assembler builds vmaxd/vmind
            # with EmitSIMDThreeSameOp (assembler_arm64.h:1451,1457), so `math.max(a, b)` on
            # two doubles assembles to the vector encoding. Checked the whole backend:
            # those two helpers have exactly two emitters, MathMinMaxInstr under
            # kUnboxedDouble (il_arm64.cc:4475-4477) and a double clamp (:4156). There is
            # no Float64x2 min/max instruction, so the form is unambiguous.
            v = [_vd(t) for t in ops[:3]]
            if all(v):
                st.set(v[0], V(f"{_wrap(g(v[1]), P_POST)}.{mn[1:]}({g(v[2]).text})", P_POST))
                return []
        if mn == "mov" and len(ops) == 2 and ops[0].strip().endswith(".16b"):
            d, sv = ops[0].strip(), ops[1].strip()
            if sv.endswith(".16b") and d[:1] == "v" and sv[:1] == "v":
                st.set("d" + d[1:-4], g("d" + sv[1:-4]))
                return []
        if mn == "fmov" and len(ops) == 2:
            dst, src = canon(ops[0]), ops[1].strip()
            imm = _fimm(src)
            if imm is not None:
                st.set(dst, V(imm, P_ATOM))
                return []
            if _is_fp(dst) and _is_fp(canon(src)) and _scalar_fp_ops(ops):
                st.set(dst, g(canon(src)))
                return []
            # fmov between an integer and an FP register REINTERPRETS the bits, it does
            # not convert. Modelling it as a move would silently invent a numeric
            # equality, so keep the raw instruction.
            st.set(dst, V(dst, P_ATOM))
            return [f"{mn} {op}"]
        if mn in ("scvtf", "ucvtf") and len(ops) >= 2 and "." not in ops[1]:
            st.set(canon(ops[0]), V(f"{_wrap(g(canon(ops[1])), P_POST)}.toDouble()", P_POST))
            return []
        if mn.startswith("fcvtz") and len(ops) >= 2 and "." not in ops[1]:
            st.set(canon(ops[0]), V(f"{_wrap(g(canon(ops[1])), P_POST)}.toInt()", P_POST))
            return []
        if mn == "fcvt" and len(ops) >= 2 and _scalar_fp_ops(ops):
            st.set(canon(ops[0]), g(canon(ops[1])))     # precision change, same value
            return []

        # loads
        if mn in _LOADS:
            dst = canon(ops[0])
            addr = _addr(ops)
            if addr is None or addr[1] is _BAD_POST:
                st.set(dst, V(dst, P_ATOM))
                return [f"{mn} {op}"]
            (base, disp, index, scale, wb), post = addr
            delta = disp if wb else post
            if delta and base in _regs(ops[:2 if mn in ("ldp", "ldpsw") else 1]):
                st.set(dst, V(dst, P_ATOM))   # writeback into a loaded register: arm64
                return [f"{mn} {op}"]         # calls it unpredictable, so neither do we
            if post:
                disp = 0                     # post-index: the access is at the OLD base
            if note.startswith("  ; = ") or note.startswith("; = "):
                st.set(dst, V(note.split("= ", 1)[1].strip(), P_ATOM))   # resolved pool const
                return []
            # A canonical object read straight out of the base register. arm64 reaches
            # true/false with an `add` off NULL and is handled there; arm32 has no null
            # register and LOADS all three out of the thread, so the same table is
            # consulted on the load path too.
            if (_T.roles.get(base) == _T.consts_base and disp in _T.consts
                    and not index):
                st.set(dst, V(_T.consts[disp], P_ATOM))
                return []
            if _T.roles.get(base) == "PP":                   # unresolved ObjectPool entry
                st.set(dst, V(f"pool_0x{disp:x}", P_ATOM))
                return []
            if base in st.poolbase:                          # far load: add base + ldr off
                off = st.poolbase[base] + disp
                lbl = self.pool_map.get(off)
                st.set(dst, V(lbl if lbl else f"pool_0x{off:x}", P_ATOM))
                return []
            # `ldp a, b, [base, #d]` loads TWO registers, the second one slot further on.
            second = None
            if mn in ("ldp", "ldpsw") and len(ops) >= 3:
                second = (canon(ops[1]), disp + (4 if ops[1].strip()[:1] == "w" else 8))
            if _T.roles.get(base) in ("SP", "FP"):           # reload a stack slot
                # A 64-bit incoming argument or spill occupies two adjacent slots, and the
                # same adjacency rule applies as for a field: the previous access was one
                # word below, off the same base.
                prev = self._last_mem
                if (_T.pairs and prev and prev[0] == "load" and prev[1] == base
                        and prev[2] + _T.word == disp and not index):
                    st.set(dst, V(dst, P_ATOM))
                    st.pair[dst] = prev[3]
                    self._last_mem = None
                    self._frame_moved(st, base, delta)
                    return []
                st.set(dst, st.slot.get(f"{base}{disp:+d}", V(dst, P_ATOM)))
                if second:
                    st.set(second[0], st.slot.get(f"{base}{second[1]:+d}",
                                                  V(second[0], P_ATOM)))
                self._last_mem = ("load", base, disp, dst)
                self._frame_moved(st, base, delta)
                return []
            if index is not None or base in st.elem:          # element load
                st.set(dst, self._elem_access(base, index, scale, st, disp))
                return self._bump(st, base, delta)
            # The high half of a split 64-bit field load, recognised by adjacency: the
            # previous instruction loaded the slot one word below, from the same base.
            # Only then, two loads that merely happen to be four bytes apart in unrelated
            # objects are not a pair, and the base has to be the same register for the
            # question to even make sense.
            prev = self._last_mem
            if (_T.pairs and prev and prev[0] == "load" and prev[1] == base
                    and prev[2] + _T.word == disp and not index):
                st.set(dst, V(dst, P_ATOM))
                st.pair[dst] = prev[3]
                self._last_mem = None
                return self._bump(st, base, delta)
            st.set(dst, self._field(g(base), self._byte_off(base, disp)))
            if second:
                st.set(second[0], self._field(g(base), self._byte_off(base, second[1])))
            self._last_mem = ("load", base, disp, dst)
            return self._bump(st, base, delta)

        # compares set flags only; the condition is rendered from cfg's cond string
        if mn in _CMP:
            return []
        if mn in _CSEL:
            sel = self._select(st, mn, ops, g)
            if sel is not None:
                return sel

        # data processing
        dst = canon(ops[0]) if ops else ""
        if mn == "mov" and len(ops) == 2:
            imm = _imm(ops[1])
            st.set(dst, _num(imm) if imm is not None else g(ops[1]))
            return []
        if mn == "movz" and len(ops) >= 2:
            imm = _imm(ops[1])
            if imm is not None:
                if len(ops) >= 3 and "lsl" in ops[2]:         # movz xD, #1, lsl #16 == 65536
                    imm <<= (_imm(ops[2].split("lsl")[-1]) or 0)
                st.set(dst, _num(imm))
                return []
        if mn == "movk" and len(ops) >= 2:
            # A wide constant is built in 16-bit pieces: `mov x2, #0x1c8; movk x2, #0x3b,
            # lsl #16` is 0x3b01c8. Only the first half was modelled, so the second half
            # printed as raw arm64 and the register it was building went back to being
            # opaque, 1,567 lines, and every constant they spell lost with them.
            # `movk` INSERTS into whatever is already there, so it is only knowable when
            # the current value is a literal; otherwise it stays raw, as before.
            imm = _imm(ops[1])
            cur = st.reg.get(dst)
            known = (cur is not None and cur.prec == P_ATOM
                     and _INT_LITERAL.match(cur.text))
            if imm is not None and known:
                sh = (_imm(ops[2].split("lsl")[-1]) or 0) if (
                    len(ops) >= 3 and "lsl" in ops[2]) else 0
                wide = 0xffffffff if ops[0].strip()[:1] == "w" else (1 << 64) - 1
                val = ((int(cur.text, 0) & wide) & ~((0xffff << sh) & wide)) | (
                    (imm << sh) & wide)
                st.set(dst, _num(val))
                return []
        if mn == "add" and len(ops) >= 3:
            b, c = canon(ops[1]), ops[2]
            imm = _imm(c)
            # `add xD, xN, #9, lsl #12` is a single immediate scaled by the shift. Only the
            # pool-base branch below used to fold it, so every other use was off by 4096x.
            if imm is not None and len(ops) >= 4 and "lsl" in ops[3]:
                imm <<= (_imm(ops[3].split("lsl")[-1]) or 0)
            if _T.roles.get(b) == _T.consts_base and imm in _T.consts:
                st.set(dst, V(_T.consts[imm], P_ATOM))         # base + off -> singleton
                return []
            if _T.roles.get(b) == "PP" and imm is not None:
                # Base half of a far pool load. Record the base so the ldr that follows
                # resolves as a pool constant instead of rendering as a field read on the
                # PP register. A register offset off PP is not this pattern and must not
                # claim a base, or the ldr resolves to an unrelated pool entry.
                st.set(dst, V(f"pool_base_0x{imm:x}", P_ATOM))
                st.poolbase[dst] = imm
                return []
            if imm is not None:
                st.set(dst, _bin(g(b), "+", _num(imm), P_ADD))
                return []
            if _T.roles.get(canon(c)) == "HEAP":               # compressed-pointer decompress
                st.set(dst, g(b))
                return []
            # base + index(*scale): remember as an element address. An extending form
            # carries the shift too, `add xD, x29, w2, sxtw #2` scales by four exactly as
            # `lsl #2` does, and reading only the lsl spelling recorded a stride of one
            # for every frame address in the image, which is the unit the folded
            # displacement in _elem_access is counted in.
            scale = _shift_amount(ops[3]) if len(ops) >= 4 else 0
            val = self._src(ops, 2, st)
            if val is None:
                return self._raw(st, dst, mn, op)
            st.set(dst, _bin(g(b), "+", val, P_ADD))
            # The 4th field records whether the machine's base register held an UNTAGGED
            # address, because that is what decides whether a later displacement off this
            # base is an object header or a real element offset. See _elem_access.
            st.elem[dst] = (g(b), g(c), scale, b in _UNTAGGED)
            return []
        if mn == "sub" and len(ops) >= 3:
            b = g(ops[1])
            imm = _imm(ops[2])
            if imm is not None and len(ops) >= 4 and "lsl" in ops[3]:
                imm <<= (_imm(ops[3].split("lsl")[-1]) or 0)
            other = _num(imm) if imm is not None else self._src(ops, 2, st)
            if other is None:
                return self._raw(st, dst, mn, op)
            st.set(dst, _bin(b, "-", other, P_ADD))
            return []
        if mn == "mul" and len(ops) >= 3:
            st.set(dst, _bin(g(ops[1]), "*", g(ops[2]), P_MUL))
            return []
        if mn in ("and", "orr", "eor", "bic", "orn", "eon") and len(ops) >= 3:
            sym = {"and": "&", "orr": "|", "eor": "^",
                   "bic": "&", "orn": "|", "eon": "^"}[mn]
            prec = {"and": P_AND, "orr": P_OR, "eor": P_XOR,
                    "bic": P_AND, "orn": P_OR, "eon": P_XOR}[mn]
            imm = _imm(ops[2])
            other = _num(imm) if imm is not None else self._src(ops, 2, st)
            if other is None:
                return self._raw(st, dst, mn, op)
            if mn in ("bic", "orn", "eon"):     # the second operand is complemented
                other = V("~" + _wrap(other, P_UNARY), P_UNARY)
            # orr xD, xzr, xS  is a plain move
            if mn == "orr" and canon(ops[1]) == "xzr":
                st.set(dst, other)
            else:
                st.set(dst, _bin(g(ops[1]), sym, other, prec))
            return []
        if mn in ("neg", "mvn") and len(ops) >= 2:
            src = self._src(ops, 1, st)
            if src is None:
                return self._raw(st, dst, mn, op)
            st.set(dst, V(("-" if mn == "neg" else "~") + _wrap(src, P_UNARY), P_UNARY))
            return []
        if mn == "sdiv" and len(ops) >= 3:
            # `~/` is Dart's truncating integer division and arm64 sdiv truncates toward
            # zero, so the two agree exactly. udiv does NOT get the same treatment: it is
            # the same bits read unsigned, and `~/` would be a different answer on any
            # operand with the top bit set.
            st.set(dst, _bin(g(ops[1]), "~/", g(ops[2]), P_MUL))
            return []
        if mn in ("madd", "msub") and len(ops) >= 4:
            prod = _bin(g(ops[1]), "*", g(ops[2]), P_MUL)
            st.set(dst, _bin(g(ops[3]), "+" if mn == "madd" else "-", prod, P_ADD))
            return []
        if mn == "mneg" and len(ops) >= 3:
            st.set(dst, V("-" + _wrap(_bin(g(ops[1]), "*", g(ops[2]), P_MUL), P_UNARY),
                          P_UNARY))
            return []
        if mn in ("lsl", "lsr", "asr") and len(ops) >= 3:
            sym = _SHIFT_SYM[mn]      # one table, so the two spellings cannot drift apart
            amt = _imm(ops[2])
            # A register shift amount is not a shift by zero, which is what `or 0` made it.
            rhs = _num(amt) if amt is not None else g(ops[2])
            st.set(dst, _bin(g(ops[1]), sym, rhs, P_SHIFT))
            return []
        if mn in ("ubfx", "sbfx") and len(ops) >= 4:
            lsb, width = _imm(ops[2]), _imm(ops[3])
            if lsb is None or width is None:
                return self._raw(st, dst, mn, op)
            src = g(ops[1])
            if lsb == 0:
                # `& mask` zero-extends, so it is right for ubfx and wrong for sbfx, whose
                # whole job is to carry the sign. Same bug and same fix as the sxt* forms
                # below: a shift pair, exact because `>>` is arithmetic here.
                if width >= 64:
                    st.set(dst, src)
                elif mn == "ubfx":
                    st.set(dst, _bin(src, "&", V(hex((1 << width) - 1), P_ATOM), P_AND))
                else:
                    pad = 64 - width
                    st.set(dst, _bin(_bin(src, "<<", _num(pad), P_SHIFT), ">>",
                                     _num(pad), P_SHIFT))
            elif lsb == 1 and mn == "sbfx":                   # Smi untag (value = tagged >> 1)
                st.set(dst, _bin(src, ">>", V("1", P_ATOM), P_SHIFT))
            else:
                st.set(dst, V(f"({src.text} >> {lsb}) & 0x{(1 << width) - 1:x}", P_AND))
            return []
        if mn in ("sbfiz", "ubfiz") and len(ops) >= 3:
            lsb = _imm(ops[2])
            if lsb is None:
                return self._raw(st, dst, mn, op)
            src = g(ops[1])                     # lsb 1 = Smi tag (value << 1); show the value
            st.set(dst, src if lsb == 1 else _bin(src, "<<", _num(lsb), P_SHIFT))
            return []
        if mn in ("sxtw", "uxtw", "sxth", "uxth", "sxtb", "uxtb") and len(ops) >= 2:
            # Not the identity. `sxtb` of 0xff is -1, and printing the source register said
            # 255: a confident wrong value, which is the one thing this lifter does not
            # emit. Two lines above, `sbfiz` already declines rather than approximate.
            #
            # The unsigned forms have an exact Dart spelling, so they get it. The signed
            # ones are a shift pair, and it is exact because `>>` here IS arithmetic,
            # the same fact that makes `lsr` above `>>>` rather than `>>`.
            src = g(ops[1])
            width = {"b": 8, "h": 16, "w": 32}[mn[3]]
            if mn.startswith("u"):
                st.set(dst, _bin(src, "&", V(hex((1 << width) - 1), P_ATOM), P_AND))
            else:
                pad = 64 - width
                st.set(dst, _bin(_bin(src, "<<", _num(pad), P_SHIFT), ">>",
                                 _num(pad), P_SHIFT))
            return []

        # not modelled: emit the raw arm64 (never wrong, no information lost)
        if dst:
            st.set(dst, V(dst, P_ATOM))
        return [f"{mn} {op}".rstrip()]

    def _elem_access(self, base_reg, index_reg, scale, st: State, disp: int = 0) -> V:
        """`base[index]` for a computed address, with the displacement folded in where it
        is an element offset rather than an object header.

        The displacement used to be dropped unconditionally, and on a heap object that is
        right: `add xD, xArr, xIdx, lsl #1; ldur wR, [xD, #0xf]` reaches element zero,
        because 0xf is Array's data offset less the heap-object tag. A FRAME address has no
        header to absorb, so dropping it printed different stack slots as the same
        expression. .text+0x1050 in the 3.12.2 clean build loads three separate incoming
        arguments from [xN, #0x18], [xN, #0x10] and [xN, #8] off one base, and all three
        rendered `FP[x4.field_0x14 - 4]`; two of the three stores below them therefore
        claimed a value they never held.

        The fold is only applied where the base register is one the machine holds an
        UNTAGGED address in, and only when the displacement is a whole number of strides.
        Anywhere else the header is unknown, so there is nothing sound to fold and the
        rendering is left as it was."""
        if base_reg in st.elem:
            base_v, idx_v, s, frame = st.elem[base_reg]
        else:
            base_v = self._leaf(base_reg, st)
            idx_v = self._leaf(index_reg, st) if index_reg else V("0", P_ATOM)
            s, frame = scale, base_reg in _UNTAGGED
        idx = idx_v.text
        if frame and disp:
            stride = 1 << s
            k, rem = divmod(disp, stride)
            if rem == 0:
                idx = (_bin(idx_v, "+", _num(k), P_ADD).text if k > 0
                       else _bin(idx_v, "-", _num(-k), P_ADD).text)
        return V(f"{_wrap(base_v, P_POST)}[{idx}]", P_POST)

    def _assign(self, lhs: V, rhs: V) -> str:
        # compound assignment when rhs is `lhs <op> operand`
        for sym, prec in (("*", P_MUL), ("+", P_ADD), ("-", P_ADD),
                          ("&", P_AND), ("|", P_OR), ("^", P_XOR)):
            pre = f"{_wrap(lhs, prec)} {sym} "
            # The text starting `lhs sym ` is not enough. `x = x * a - b` starts `x * `,
            # and `x *= a - b` is `x * (a - b)`; `x = x - a - b` starts `x - `, and
            # `x -= a - b` is `x - a + b`. Both were printed, both are a different value.
            # The rewrite is only an identity when what follows is ONE operand, so it is
            # taken only when nothing binds looser inside the remainder. Found by
            # tools/irfuzz.py --cfg, which evaluated `t0 *= x14 - (x9 - t1)` against the
            # CPU that had run `mul x6, x3, x14; sub x3, x6, x4`.
            if rhs.text.startswith(pre) and _folds_into(sym, rhs.text[len(pre):]):
                return f"{lhs.text} {sym}= {rhs.text[len(pre):]};"
        return f"{lhs.text} = {rhs.text};{_smi_note(lhs, rhs)}"

    # block + tree walk
    def _carry_out(self, st: State, pad: str, leaving: bool) -> list:
        """Write the enclosing loop's carried names back before an edge that skips the tail.

        `_render_loop` binds each loop-carried register to a name, and assigns the name at
        the BOTTOM of the body. That is the copy for the back edge and only for the back
        edge. Every other way out of a `while (true)`, a `break`, a `continue`, a `goto`
        that leaves the loop, jumps over it, so the name kept the value from the previous
        trip while the machine had already done this trip's work.

        Found by tools/irfuzz.py --cfg on a generated bottom-tested loop:

            0x40  orr x5, x3, x5      while (true) {
            0x44  sub x7, x7, #1        if ((t2 - 1) == 0) break;   <- exits here
            0x48  cbnz x7, #0x40        t1 = x3 | t1;               <- never reached
                                        t2 -= 1;                    <- on the last trip
                                      }

        so the code after the loop read a `t1` one iteration behind the register, and a
        `t2` that had not been decremented at all. The CPU and the printed expression
        disagreed on the exit value; they now agree.

        `leaving` is False for a `continue`, which re-enters the body rather than leaving
        the loop, and True otherwise. Both need the copy, a continue skips the tail just
        as a break does, and the flag only says which frame's names to use.
        """
        if not self._carrying:
            return []
        _header, names, copied = self._carrying[-1]
        # Read every value BEFORE any of them is written back: this is the same parallel
        # copy the back edge makes, and one name that another reads has to be captured
        # first. See _parallel_copy.
        here = [(r, st.get(r)) for r in sorted(names)]
        here = [(r, v) for r, v in here if v.text != names[r]]
        out = self._parallel_copy(st, [(names[r], v) for r, v in here], pad)
        for r, _v in here:
            copied.add(r)
            if leaving:
                st.reg[r] = V(names[r], P_ATOM)
        return out

    def _leaves_loop(self, addr) -> bool:
        """True when a goto to `addr` jumps out of the loop currently being walked."""
        if not self._carrying:
            return False
        return addr not in self._loop_nodes(self._carrying[-1][0])

    def _join_kill(self, addr) -> tuple:
        """(registers, slots-too) a block reached by a `goto` may NOT assume it still has.

        `walk` renders a tree, and a goto is the one edge whose source state never reaches
        its target: the walker arrives carrying whatever the path it happened to be on left
        behind, and prints it. `_merge` has meet semantics for the if/else join since the
        `this` bug; this is the same fact about the same kind of join, on the edge the
        structurer could not nest, and it had no meet at all.

        Measured on the 3.12.2 clean build before this existed: 830 of 8194 functions
        (10.1%) printed at least one expression only one predecessor justifies. Two of the
        smaller ones: `createFromCharCodes(x2, x2, x3)` at .text+0xb12c, where argument zero
        is x1 and x2 is what the other path had left in it, and `RangeError.range(...,
        this.field_0x8)` at .text+0xadb0 on a path where the receiver register is x3.

        Every path into `addr` passes through its immediate dominator, so a register that no
        block BETWEEN the two writes carries the same value down all of them and is kept.
        Everything else drops to its own name. `_written` counts a call as writing the whole
        volatile set, the same over-approximation `_render_loop` makes, so a value cannot
        survive a call on one arm and be read after the join.
        """
        hit = self._killcache.get(addr)
        if hit is not None:
            return hit
        if self._idom is None:
            self._idom = _idoms(self.blocks, self.entry,
                                lambda n: self.blocks[n].succ if n in self.blocks else ())[0]
        # backward: every block that can reach addr without going through it again
        back, stack = set(), list(self._preds.get(addr, ()))
        while stack:
            n = stack.pop()
            if n in back or n == addr:
                continue
            back.add(n)
            stack.extend(self._preds.get(n, ()))
        d = self._idom.get(addr)
        if d is not None and d != addr:
            # forward from the dominator, which is where the paths part. The dominator
            # itself is one block with one exit state, so what IT writes is agreed on.
            fwd, stack = set(), [s for s in self.blocks[d].succ if s in self.blocks]
            while stack:
                n = stack.pop()
                if n in fwd or n == addr:
                    continue
                fwd.add(n)
                stack.extend(s for s in self.blocks[n].succ if s in self.blocks)
            back &= fwd
        # A spill slot one of those blocks rewrote says nothing either, which is the rule
        # `_render_loop` already applies to a loop body that stores. Only a store that can
        # REACH a slot counts; see _writes_stack.
        #
        # `- _SPECIAL` is the same subtraction `_render_loop` makes, and the reason only
        # became visible once a writeback counted as a write: `forget` puts the register's
        # own NAME in the map, so forgetting x15 renders it `x15` on the lines after the
        # join where every other line says `SP`. A role is a display constant, not a
        # tracked value, and 4,114 of the corpus's 5,002 writeback sites are the SP of a
        # push or a pop.
        self._killcache[addr] = hit = (frozenset(self._written(back)) - _SPECIAL,
                                       self._writes_stack(back),
                                       self._writes_heap(back))
        return hit

    def _lift_block(self, addr, st: State):
        """Return (lines, falls_through) for one basic block, mutating `st`."""
        blk = self.blocks[addr]
        self._args_desc = False    # ArgumentsDescriptor setup + call live in the same block
        self._flags = None         # flags do not survive into a block from an unknown one
        # Both of these are adjacency claims about consecutive instructions, and adjacency
        # does not survive a branch any more than flag provenance does.
        self._last_mem = None
        self._pend_pair = None
        lines, insns = [], blk.insns
        # Which registers each instruction's result is still needed by. Walked backwards
        # from what is live on the way out of the block, so it covers a value read in a
        # later block as well as one read two instructions on.
        after = _NO_LIVE
        # Stores need it as much as calls do. `_pin_mem` writes a value out before the
        # memory it reads changes, and doing that for a register nothing reads again would
        # put a dead `var tN = this.field_0x8;` in front of every compound assignment,
        # benchWithdraw's `balance -= amount` grows two of them, one for each register that
        # mentions the field.
        if any(t[1] in _CALLS or t[1] in _STORES for t in insns):
            after, m = [0] * len(insns), self._liveout.get(addr, 0)
            for k in range(len(insns) - 1, -1, -1):
                after[k] = m
                de, us = _def_use_masks(insns[k][1], insns[k][2])
                m = us | (m & ~de)
        for k, (a, mn, op, note) in enumerate(insns):
            self._live_after = after[k] if after is not _NO_LIVE else 0
            last = (k == len(insns) - 1)
            if last and (mn == "b" or cond_of(mn) or mn in _CONDB):
                break                                          # branch is structural
            lines.extend(self._step(st, a, mn, op, note))
            if st.spill:
                # After the instruction's own statement, not before: the declaration belongs
                # at the point the value was produced, and only later instructions read it.
                lines.extend(st.spill)
                st.spill.clear()
        falls = blk.term not in ("ret", "br", "bx")
        # Kept for `_reenter`: a block emitted after something that did not fall through
        # needs the state of its own predecessor, not of whatever the tree put above it.
        self._exit[addr] = st.copy()
        return lines, falls

    def _reenter(self, addr, st: State):
        """Give `st` a state that `addr`'s own predecessors justify.

        `structure` emits blocks in an order that is not always a path. A block reachable
        from nothing at all is still emitted, correctly, since dropping it would hide code
        that an exception edge may reach and the CFG does not model, and whatever the
        walker was carrying then flowed straight into the block printed after it. On a
        generated case (tools/irfuzz.py --cfg) an unreachable `orr x0, x13, x11` supplied
        the value for a `return` in a block it has no edge to, and the CPU disagreed. 5,181
        of the 8,194 functions in the 3.12.2 clean build contain a block reachable from
        nothing, so this is not a corner.

        Where the block has exactly one predecessor its exit state IS the edge and is used.
        Anything else drops to symbolic, which is what "no path led here" honestly reads as.
        """
        preds = self._preds.get(addr, ())
        carry = self._exit.get(preds[0]) if len(preds) == 1 else None
        st.elem.clear()
        st.poolbase.clear()
        st.pair.clear()
        if carry is not None:
            st.reg = dict(carry.reg)
            st.slot = dict(carry.slot)
            st.elem.update(carry.elem)
            st.poolbase.update(carry.poolbase)
            st.pair.update(carry.pair)
            st.result = carry.result
        else:
            st.reg = {}
            st.slot = {}
            st.result = _T.ret_int

    def _cond(self, cond: str, st: State) -> str:
        """Render cfg's register-level condition with lifted expressions substituted."""
        return _REG_RE.sub(lambda m: _in_cond(self._leaf(canon(m.group(1)), st)), cond)

    def _entry_block(self, stmts, cont):
        """The block a statement list first transfers control to, or `cont` if it has none
        of its own. Which block a conditional REJOINS at is what says whether the registers
        its arms disagree about are still wanted."""
        for s in stmts:
            k = s[0]
            if k in ("asm", "loop", "goto", "label"):
                return s[1]
            if k == "if":
                return self._entry_block(s[2], cont) if s[2] else cont
            if k in ("break", "continue"):
                return None
        return cont

    def _phi(self, st: State, a: State, b: State, tlines, elines, live, pad, indent):
        """Write out the registers the two arms disagree about, and NAME the result.

        `_merge` keeps what both arms agree on and drops the rest, so a register each arm
        computed differently came out of the join as a bare name with nothing anywhere
        saying what either arm had put in it. That is how a modelled `x5 - x5 ~/ x1 * x1`
        disappeared: both arms had a value for x0, the values differed, and `return x0;`
        was all that was left, strictly less than the raw arm64 it replaced.

        Writing the arms out fixed that half. It left the other half: the assignment went
        to the MACHINE REGISTER, so the join and every line after it still read `x0`, and a
        reader cannot tell that `x0` from one the lifter simply lost. Measured on the
        3.12.2 corpus, 12,710 of the 45,407 bare-register lines (28.0%) name a register the
        printed body assigns to somewhere, a value that is in the output and merely
        spelled as machine state, and the if-join is where most of them are made.

        A disagreement at a join IS a phi, and `_render_loop` already draws the conclusion
        for the loop-carried case: a phi that reaches one join has a name. The same shape
        is used here, which is what makes it a rename and not a claim, bind the value the
        register holds BEFORE the `if`, assign the name in whichever arm changed it, and
        read the name afterwards. An arm that changed nothing needs no assignment, so the
        line cost is bounded by the number of arms that actually computed something, which
        is what the previous version already paid.

        Returns {register: name} for the caller to bind after `_merge`.
        """
        pad2 = pad + indent
        bare, named, decls = {}, {}, []
        for r in sorted(a.reg.keys() | b.reg.keys()):
            # A register only one arm tracks holds, on the other path, whatever it came in
            # with, which is the register itself, since anything the map knew before the
            # `if` is in both copies of it.
            va, vb = a.reg.get(r) or bare.setdefault(r, V(r, P_ATOM)), b.reg.get(r) or bare.setdefault(r, V(r, P_ATOM))
            if va == vb or not (live & _reg_mask((r,))):
                continue
            # Only where an arm COMPUTED something. A name or a field read that reaches
            # the join is a value the reader can still see coming; an expression is not.
            # Writing every disagreement out instead was measured: it turns 11,180
            # register-to-register moves into statements for the 3,874 that carry
            # arithmetic, and costs more lines than the arithmetic is worth.
            #
            # It rests on the bare register meaning "whatever the machine has there",
            # and that stops being true once one of the two values is a name this lifter
            # MINTED. A `t3` from an earlier join or a loop exists only in the printed
            # body; declining the phi drops it to a bare `x3`, and the binding that said
            # what x3 holds is then the one thing the reader cannot see. Measured on the
            # clean build, that is 833 joins in 266 of 8,194 functions. Found by
            # tools/irfuzz.py --cfgmem on `x3 = x14 * x10;` in one join followed by a
            # `ldur x3, [x20, #0xf]` in an arm of the next.
            if (va.prec >= P_POST and vb.prec >= P_POST
                    and not _MINTED_RE.fullmatch(va.text)
                    and not _MINTED_RE.fullmatch(vb.text)):
                continue
            # The value on entry to the `if`. `a` and `b` are copies of `st` taken before
            # either arm walked, so anything they both still agree with is what `st` had;
            # this reads `st` itself so the declaration cannot depend on which arm ran.
            pre = st.reg.get(r) or bare.setdefault(r, V(r, P_ATOM))
            name = self._phi_name(st, r)
            named[r] = name
            arms = [(lines, arm.reg.get(r) or bare[r]) for arm, lines
                    in ((a, tlines), (b, elines))]

            def changed(v, pre=pre):
                """Did this arm leave the register holding something else?

                Textual equality is the obvious test and it is not sufficient, because two
                identical memory reads are two different values when a store separates
                them. The graph that showed it stores to a field inside the arm and reloads
                it: the arm's x0 and the entry x0 both print `x20.field_0x8`, so the arm
                looked like it had changed nothing and the join took the entry value.

                `_pin_mem` does not cover this, and correctly. It writes a value out before
                a store only where LIVENESS says something reads it, and here both arms
                redefine x0 before anything does, so the register is dead at the store and
                skipped. `_phi` then resurrects the text as an initialiser, at a point past
                the store where it no longer means what it meant.

                So a value that reads memory counts as changed whichever way the text
                falls. That is one-directional and cheap: an arm whose value does not read
                memory is decided by text exactly as before, and where it does the arm
                assigns the name itself, after its own store, which is the only place the
                read is sound. Found by tools/irfuzz.py --cfgmem --seed-outputs."""
                return v != pre or bool(_READS_MEMORY.search(v.text))
            # The initialiser exists only for an arm that leaves the value alone. Where
            # both arms assign it, giving one anyway would DUPLICATE the entry expression
            # 506 extra byte-offset field lines on the corpus, paid for a value no path
            # reads. The declaration still dominates every use, so the name is bound.
            decls.append(f"{pad}var {name};" if all(changed(v) for _l, v in arms)
                         else f"{pad}var {name} = {pre.text};")
            for lines, v in arms:
                if changed(v):
                    lines.append(pad2 + self._assign(V(name, P_ATOM), v))
        return named, decls
    def _phi_name(self, st: State, r: str) -> str:
        """The name a phi result is bound to: always a FRESH one, never the register.

        Assigning `r` itself costs nothing to write and is wrong twice over. Every tracked
        value spelled in terms of the old `r` silently rereads it, the machine returns
        (old x1) + x8 + (new x1) where the text says `x1 + x8 + x1`, and a later arm that
        reloads `r` leaves each use after it reading the earlier assignment. Both were real
        (963 and 833 sites on the 3.12.2 clean build, found by tools/irfuzz.py --cfgmem),
        and both are gone the moment the name is fresh, because nothing else can be
        spelled in terms of a name that did not exist yet. Kept as its own method so a test
        can put the register back and watch the oracle catch it."""
        name = f"t{st.tmpc[0]}"
        st.tmpc[0] += 1
        return name

    def _parallel_copy(self, st: State, pairs, pad: str) -> list:
        """Emit a GROUP of assignments that must all read the values from before it.

        A phi group and a loop's carried write-back are both parallel copies: every
        right-hand side describes the state at the point the group starts, and writing
        them out one after another makes each one read whatever the lines above it left.
        Emitted in register order, `x5 = x13 ^ x11; x6 = x5 | x13;` reads the x5 the line
        above it just assigned, where the machine's x6 was computed from the old one. The
        loop tail has the same shape: `t0 += t1 + 1; t1 = t0;` gives t1 this trip's t0
        instead of last trip's.

        Found by tools/irfuzz.py --cfgmem, which interprets the printed statements in
        order and so sees the group as a reader does.

        The fix is the standard lowering, and it is applied only where the order really
        breaks. `pairs` is emitted in the order given, so a right-hand side that names a
        member assigned LATER still reads the old value and needs nothing; only one that
        names a member assigned EARLIER does, and that one is captured in a temporary
        before any assignment runs. On the clean build 1,619 of the 1,728 groups have no
        hazard at all and print exactly as they did.
        """
        if len(pairs) < 2:
            return [pad + self._assign(V(n, P_ATOM), v) for n, v in pairs]
        pre, post, earlier = [], [], []
        for name, v in pairs:
            if not any(_use_re(o).search(v.text) for o in earlier):
                post.append(pad + self._assign(V(name, P_ATOM), v))
            else:
                tmp = f"t{st.tmpc[0]}"
                st.tmpc[0] += 1
                pre.append(f"{pad}var {tmp} = {v.text};")
                post.append(f"{pad}{name} = {tmp};")
            earlier.append(name)
        return pre + post


    def walk(self, stmts, st: State, indent: str, depth: int, cont=None):
        """Render a structured statement list; returns (lines, falls_through)."""
        out, falls = [], True
        pad = indent * depth
        # Where each statement rejoins: the entry of everything after it, or the caller's.
        joins, nxt = [None] * len(stmts), cont
        for i in range(len(stmts) - 1, -1, -1):
            joins[i] = nxt
            nxt = self._entry_block(stmts[i:i + 1], nxt)

        def label(addr):
            """Define a goto target once, wherever its block is first emitted."""
            if addr in self.labels and addr not in self._labelled:
                self._labelled.add(addr)
                out.append(pad + f"L_0x{addr:x}:")

        # Whether the statement just emitted hands control to the next one. `falls` is the
        # answer for the WHOLE list and never goes back up; this is the local question, and
        # a `no` means the state the walk is carrying belongs to some other path.
        alive = True
        for i, s in enumerate(stmts):
            kind = s[0]
            if kind == "asm":
                label(s[1])
                if not alive:
                    self._reenter(s[1], st)
                # The meet a goto join never got. A loop header is excluded because
                # `_render_loop` has already given its carried registers names and bound
                # them in this state; killing them here would put the machine register back
                # into every line of the body.
                if (s[1] in self.labels and len(self._preds.get(s[1], ())) > 1
                        and s[1] not in self.carried):
                    kill, mem, heap = self._join_kill(s[1])
                    for r in sorted(kill):
                        st.forget(r)
                    if mem:
                        st.slot.clear()
                    else:
                        self._stale_slots(st, kill)
                    if heap:
                        # The same meet, for the heap. A register the paths agree on can
                        # still be spelled as a field read, and a store one path made says
                        # that text names a different value coming that way. Dropping the
                        # REGISTER is not enough and dropping every register is far too
                        # much, so what goes is exactly the values that read memory.
                        for r, v in sorted(st.reg.items()):
                            if v.text != r and _READS_MEMORY.search(v.text):
                                st.forget(r)
                        st.elem.clear()
                blines, bfalls = self._lift_block(s[1], st)
                out.extend(pad + ln for ln in blines)
                alive = bfalls
                if not bfalls:
                    falls = False
            elif kind == "label":
                label(s[1])
            elif kind == "if":
                _, cond, then, els = s
                cond_txt = self._cond(cond, st)
                a, b = st.copy(), st.copy()
                tlines, tfalls = self.walk(then, a, indent, depth + 1, joins[i])
                elines, efalls = self.walk(els, b, indent, depth + 1, joins[i])
                named = {}
                if tfalls and efalls:
                    named, decls = self._phi(st, a, b, tlines, elines,
                                             self._livein.get(joins[i], 0), pad, indent)
                    out.extend(decls)
                out.extend(self._render_if(cond_txt, tlines, elines, pad, indent))
                if tfalls and efalls:
                    _merge(st, a, b)
                    # ...and the join value of a named phi is that name, not the register
                    # `_merge` dropped to. Same second half as `_render_loop`: naming the
                    # value and then forgetting it puts the machine register back into
                    # every line that reads the result.
                    for r, name in sorted(named.items()):
                        st.reg[r] = V(name, P_ATOM)
                        st.elem.pop(r, None)
                        st.poolbase.pop(r, None)
                elif tfalls:
                    st.reg, st.slot, st.elem, st.result = a.reg, a.slot, a.elem, a.result
                elif efalls:
                    st.reg, st.slot, st.elem, st.result = b.reg, b.slot, b.elem, b.result
                else:
                    falls = False
                alive = tfalls or efalls
            elif kind == "loop":
                label(s[1])
                out.extend(self._render_loop(s[1], s[2], st, indent, depth))
                alive = True
            elif kind in ("break", "continue"):
                out.extend(self._carry_out(st, pad, kind == "break"))
                out.append(pad + kind + ";")
                falls = alive = False
            elif kind == "goto":
                if self._leaves_loop(s[1]):
                    out.extend(self._carry_out(st, pad, True))
                out.append(pad + f"goto L_0x{s[1]:x};")
                falls = alive = False
        return out, falls

    def _render_if(self, cond, tlines, elines, pad, indent):
        if not tlines and not elines:
            return []                                          # both arms lifted to nothing
        # `if (c) {} else { break; }`  ->  `if (!c) break;`
        if not tlines and elines == [pad + indent + "break;"]:
            return [f"{pad}if ({negate_cond(cond)}) break;"]
        if not tlines and elines == [pad + indent + "continue;"]:
            return [f"{pad}if ({negate_cond(cond)}) continue;"]
        if not tlines:                                         # empty then: flip to the else
            cond, tlines, elines = negate_cond(cond), elines, []
        out = [f"{pad}if ({cond}) {{"]
        out.extend(tlines)
        if elines:
            out.append(f"{pad}}} else {{")
            out.extend(elines)
        out.append(f"{pad}}}")
        return out

    def _render_loop(self, header, body, st: State, indent, depth):
        pad = indent * depth
        nodes = self._loop_nodes(header)
        carried = self.carried.get(header)
        if carried is None:
            carried = (_live_in_header(self.blocks, nodes, header, self._preds)
                       & self._written(nodes)) - _SPECIAL
            self.carried[header] = carried
        # A loop-carried register is the one place the old design gave up a value it still
        # had. Forgetting it made the whole body print the machine register, and MEASURED on
        # the 3.12.2 corpus that single decision is 95.7% of every bare register in the
        # output, an order of magnitude more than merges and call clobbers combined.
        #
        # It is a phi, and a phi that reaches exactly one join has a name in the source: bind
        # it before the loop with the value on entry, read that name in the body, and assign
        # back to it at the bottom. Nothing here is newly claimed. The update at the tail was
        # already emitted; it was assigning to `x5` instead of to something a reader can
        # follow, and the entry value was being discarded rather than written down.
        #
        # sorted, not set order: the map's insertion order decides the order temporaries are
        # minted in, and iterating a set of strings made that depend on Python's per-process
        # hash seed, so two runs over the same binary numbered the same variables differently.
        init = {r: st.get(r) for r in sorted(carried)}
        names = {}
        for r in sorted(carried):
            names[r] = f"t{st.tmpc[0]}"
            st.tmpc[0] += 1
        loop_st = st.copy()
        for r in sorted(carried):
            loop_st.reg[r] = V(names[r], P_ATOM)
            loop_st.elem.pop(r, None)
            loop_st.poolbase.pop(r, None)
        # The names have to be visible to the walk, because the tail below is only ONE of
        # the loop's exits. See _carry_out.
        self._carrying.append((header, names, set()))
        try:
            blines, _f = self.walk(body, loop_st, indent, depth + 1, header)
        finally:
            _h, _n, copied = self._carrying.pop()

        # A phi whose operands are all the same value is not a choice, and Braun's
        # construction collapses it (ir.Phi.trivial). Here that reads as: the loop never
        # assigned this register, so it is not loop-carried at all, it is just a value that
        # was live across the loop, `carried` is a SYNTACTIC over-approximation (live-in
        # AND written somewhere in the loop's blocks) and this is where it is refined by
        # what the walk actually did. Collapsing it back costs nothing when the entry value
        # is an atom, and only then: substituting a compound expression into each use is the
        # duplication this whole exercise exists to stop.
        pairs, drop = [], set()
        for r in sorted(carried):
            v = loop_st.get(r)
            if v.text != names[r]:
                pairs.append((names[r], v))
            elif init[r].prec == P_ATOM and r not in copied:
                # `copied` means an exit inside the body already assigned this name, so the
                # register IS loop-carried even though the back edge leaves it alone, and
                # substituting the entry value back in would rewrite that assignment's
                # left-hand side into an expression.
                drop.add(r)
        # The back edge assigns all of these AT ONCE, so any one that another reads has to
        # be captured before the group runs. See _parallel_copy.
        tail = self._parallel_copy(st, pairs, pad + indent)
        if drop:
            # The name was minted moments ago and is unique, so a word-boundary swap reaches
            # exactly the occurrences this function created and nothing else.
            sub = {names[r]: init[r].text for r in drop}
            pat = re.compile(r"\b(" + "|".join(map(re.escape, sub)) + r")\b")
            blines = [pat.sub(lambda m: sub[m.group(1)], ln) for ln in blines]
            tail = [pat.sub(lambda m: sub[m.group(1)], ln) for ln in tail]
            for r in drop:
                names.pop(r)
                loop_st.reg[r] = init[r]
            # The numbering is NOT compacted afterwards. `State.copy` shares the counter box
            # with the body's walk, so the body has already minted temps above these;
            # rewinding to close a gap would hand out a name the body is using.

        out = [f"{pad}var {names[r]} = {init[r].text};" for r in sorted(names)]
        out.append(f"{pad}while (true) {{")
        out.extend(blines)
        out.extend(tail)
        out.append(f"{pad}}}")
        # Only what the loop never writes survives it. `carried` is the intersection of
        # written with live-on-entry, so restoring just those left every register the loop
        # assigns WITHOUT reading first holding its value from before the loop: set x9 to
        # 5, write 7 to it in the body, and the code after the loop printed 5. The loop
        # body is where the value now comes from, so the name is what the reader gets.
        written = self._written(self._loop_nodes(header)) - _SPECIAL
        for r in sorted(written | carried):
            st.forget(r)
        # ...except the ones that got a name, whose value after the loop is that variable.
        # That is the second half of naming it: forgetting it here would put the machine
        # register back into every line that reads the result of the loop. A register whose
        # phi collapsed keeps its entry value, which the loop did not change.
        for r in sorted(names):
            st.reg[r] = V(names[r], P_ATOM)
        for r in sorted(carried - set(names)):
            st.reg[r] = init[r]
        # Which return register the function last wrote is a fact about the BODY, and the
        # body is what just ran.
        st.result = loop_st.result
        if self._writes_stack(nodes):
            st.slot.clear()          # a spill slot the body rewrote says nothing either
        else:
            self._stale_slots(st, written | carried)
        return out

    def _frame_escaped(self) -> bool:
        """True when this function ever puts a FRAME ADDRESS in a general register.

        `_writes_stack` says a store through an object pointer cannot reach a spill slot.
        That holds because a slot is only addressable off SP or FP, unless the function
        first computes a frame address into some other register, which Dart does do:
        `LeafRuntimeCall` hands a runtime helper a pointer to a stack temporary, built with
        `add xD, SP, #imm`. After that a store through xD is a store to the frame and the
        base register no longer says so, so the whole question has to be given up on.

        Loads are not checked. A frame address that arrives in a register by being loaded
        back had to be computed by one of these instructions first, so the address-taking
        site is caught either way. Measured on the 3.12.2 corpus: 577 of its 8,194
        functions do it, 7.0%.
        """
        if self._escaped is None:
            frame = {r for r, v in _T.roles.items() if v in ("SP", "FP")}
            self._escaped = False
            for blk in self.blocks.values():
                for (_a, mn, op, _n) in blk.insns:
                    if mn in _STORES or mn in _LOADS or mn in _CMP or not op:
                        continue
                    de, us = _def_use(mn, op)
                    if us & frame and de - frame:
                        self._escaped = True
                        return True
        return self._escaped

    def _writes_stack(self, nodes) -> bool:
        """True when a store in `nodes` could land in a tracked stack slot.

        The rule this replaces was "did anything store at all", and both callers used that
        to throw the whole slot map away. It is too strong on its face: the slot map is
        keyed on a displacement from SP or FP, and the store path only ever writes it for a
        base whose role IS SP or FP, so a store through a heap object pointer cannot touch
        one entry in it. Attributing the bare-register lines said the distinction was worth
        2,758 of them, 1,380 at a loop exit and 1,378 at a goto join.

        IT IS WORTH ALMOST NONE OF THEM, and the reason is worth keeping written down so
        nobody re-derives the same estimate: of the 5,414 corpus functions that store at
        all, 4,942 (91.3%) store to a frame slot somewhere too, so the region being asked
        about answers yes either way. What earns this its place is `_stale_slots`, which
        only became safe to write once the two questions were separated.

        A store whose address this cannot parse counts, because "I could not read the base"
        is not evidence about where it points.
        """
        for b in nodes:
            for (_a, mn, op, _n) in self.blocks[b].insns:
                if mn not in _STORES:
                    continue
                got = _addr(_split_ops(op))
                if got is None or got[1] is _BAD_POST:
                    return True
                if _T.roles.get(got[0][0]) in ("SP", "FP"):
                    return True
        return self._frame_escaped()

    def _writes_heap(self, nodes) -> bool:
        """True when a store in `nodes` could land in memory a tracked value READS.

        `_writes_stack` is the same question about the frame, and the two are separate for
        the reason it gives: the slot map is keyed on a displacement from SP or FP, and a
        store through an object pointer cannot reach one. The converse is this. A goto join
        was already given the meet for registers and for slots, and the heap had none, so a
        value spelled `x20.field_0x8` survived a join one of whose paths had just stored
        there, and the reader is looking at that store, a few lines up, next to the goto.

        Found by tools/irfuzz.py --cfgmem --seed-outputs, on a graph where one path stores
        a field and the other does not, and both converge on a block that reads it.

        Over-approximate on purpose, and only in one direction: any store not provably to
        the frame counts, including one whose address does not parse, because "I could not
        read the base" is not evidence about where it points."""
        for b in nodes:
            for (_a, mn, op, _n) in self.blocks[b].insns:
                if mn not in _STORES:
                    continue
                got = _addr(_split_ops(op))
                if got is None or got[1] is _BAD_POST:
                    return True
                if _T.roles.get(got[0][0]) not in ("SP", "FP"):
                    return True
        return False

    def _stale_slots(self, st: State, written) -> None:
        """Drop the slots whose TEXT names a register the region overwrote.

        Keeping a slot across a region that did not store to the frame is only sound for
        the address. The VALUE is an expression in machine registers, and `x1.field_0x8`
        stops describing the slot the moment the region assigns to x1, the same staleness
        `_pin` exists to stop, arriving by a different door. So the address survives the
        region and the text does not have to."""
        if not written:
            return
        for k in [k for k, v in st.slot.items()
                  if any(canon(m) in written for m in _REG_RE.findall(v.text))]:
            del st.slot[k]

    def _loop_nodes(self, header):
        latches = [n for n in self.blocks if header in self.blocks[n].succ]
        nodes, stack = {header}, list(latches)
        while stack:
            n = stack.pop()
            if n in nodes or n not in self.blocks:
                continue
            nodes.add(n)
            for p in self._preds.get(n, ()):
                if p not in nodes:
                    stack.append(p)
        return nodes

    def _written(self, nodes) -> set:
        w = set()
        for b in nodes:
            for (_a, mn, o, _n) in self.blocks[b].insns:
                de, _u = _def_use(mn, o)
                w |= de
        return w


# ── argument-count analysis (for call-site argument reconstruction) ──────────

#: The registers Dart AOT actually passes arguments in, in order.
#: `constants_arm64.h:654`: kCpuRegistersForArgs[] = {R1, R2, R3, R5, R6, R7}.
#: X4 IS NOT IN IT and never can be: `constants_arm64.h:152` reserves it as
#: ARGS_DESC_REG, the arguments descriptor. Verified identical in 3.4.4, 3.8.1 and
#: 3.12.2; the array does not exist before 3.4, where Dart had no register calling
#: convention at all and every call went through the stack (measured: on the 2.19.6 and
#: 3.3.4 corpus binaries 68% of functions read incoming stack arguments and almost all the
#: rest take none, so the sequence below is simply never reached there).
ARG_REGS = ("x1", "x2", "x3", "x5", "x6", "x7")


def entry_arity(ann: list):
    """Number of register arguments a function takes: the count of contiguous ARG_REGS
    live on entry (read before being written) under the Dart AOT register convention
    (receiver in x1 for instance methods). Returns None when the register count is not
    the signature, so a caller must not claim to know the arguments.

    Two things make it return None rather than a number:

    * the function reads incoming STACK arguments (`[FP, #>=0x10]`, which is
      `param_end_from_fp + 1`, the first incoming slot);
    * X4 is live on entry. X4 is ARGS_DESC_REG, so a function reading it is being handed
      an arguments descriptor, which is exactly the case Dart uses when the signature has
      optional or named parameters and therefore does NOT pass in registers.

    That second rule is a correctness fix, not a refinement. Counting a contiguous
    `x1,x2,x3,x4,...` run treated the arguments descriptor as argument four: 55 functions
    on the corpus binary reported an arity of four or more, and every call site to one of
    them rendered ARGS_DESC_REG as a value the caller had passed. A fabricated argument is
    indistinguishable from a real one. Walking the real sequence also stops dropping the
    fourth register argument, which lives in X5: 265 functions have X5 live on entry
    without X4, and each was silently rendered with one argument too few.

    Still never over-counts: float arguments in V registers are simply not seen.
    """
    stripped = strip_boilerplate(ann)
    blocks, entry = build_cfg(stripped)
    if not blocks or entry not in blocks:
        return 0
    for b in blocks.values():
        for (_a, mn, op, _n) in b.insns:
            if mn in _LOADS:
                parts = _split_ops(op)
                m = _mem(parts[-1]) if parts else None
                if m and m[0] == "x29" and m[1] >= 0x10:   # incoming stack argument
                    return None
    live = _live_in_header(blocks, set(blocks), entry, None)
    if "x4" in live:                  # ARGS_DESC_REG: the stack convention, not arity
        return None
    k = 0
    while k < len(ARG_REGS) and ARG_REGS[k] in live:
        k += 1
    return k


def make_arity_resolver(image):
    """Build a cached `pc -> arity` resolver over a whole instruction image, mapping a
    call target to the covering function's register-argument count. A call site uses it
    to render the callee's real arguments. Returns a callable; results are memoised."""
    from .disasm import disassemble_range
    import bisect
    ranges = sorted(image.all_ranges, key=lambda cr: cr.pc_offset)
    starts = [cr.pc_offset for cr in ranges]
    cache: dict = {}

    def of(pc):
        if pc in cache:
            return cache[pc]
        i = bisect.bisect_right(starts, pc) - 1     # covering range (unchecked entries)
        val = None
        if 0 <= i < len(ranges):
            cr = ranges[i]
            if cr.pc_offset <= pc < cr.pc_offset + cr.size:
                dis = disassemble_range(image, cr)
                if dis:
                    val = entry_arity([(a, m, o, "") for (a, m, o) in dis])
        cache[pc] = val
        return val

    return of


# ── dispatch-table (virtual) call attribution ───────────────────────────────

#: What detect_dispatch can know about one register. Exactly one at a time:
#: the tags word of an object, a class id derived from it, a plain immediate, a
#: (cid, selector offset) pair, or a resolved dispatch-table target.
_F_TAGS, _F_CID, _F_IMM, _F_DISP, _F_DTARGET = 0, 1, 2, 3, 4


def detect_dispatch(dis) -> dict:
    """Map each X21 dispatch-table `blr` address -> (receiver_reg | None, selector_offset | None).

    Dart AOT dispatch-table calls resolve a virtual/interface method by class id:
      ldur tags,[recv,#-1]; ubfx cid,tags,#0xc,#0x14; add idx,cid,#off; ldr t,[x21,idx,lsl#3]; blr t
    The offset added to the class id selects the row for one selector. It's stable across
    the whole program (same selector, same offset), so it identifies the selector even
    though the source name lives only in the serialized dispatch table, which this pass
    doesn't read. Recovers the receiver register and that offset; the offset renders
    as `sel_0x<off>`."""
    # ONE fact per register, not five parallel maps. The five kinds are mutually
    # exclusive by construction: every branch below invalidates its destination and then
    # records at most one thing about it, so a register can never be two of them at once.
    # As five dicts, invalidation was five pops on every instruction whether or not
    # anything was known, 2.2M of them on one `functions` run.
    fact = {}
    out = {}
    for t in dis:
        mn = t[1]
        # While nothing is known, there is nothing to propagate and nothing to
        # invalidate, and only a load can put the first fact on the board: the tags word
        # of a tagged object, or the dispatch-table row itself. Every other mnemonic
        # would read five Nones and pop five absent keys.
        if not fact and mn != "ldr" and mn != "ldur":
            continue
        ops = _split_ops(t[2])
        if mn == "blr":
            f = fact.get(canon(ops[0])) if ops else None
            if f is not None and f[0] == _F_DTARGET:
                out[t[0]] = f[1]
            continue
        if not ops:
            continue
        dst = canon(ops[0])
        if (mn == "ldur" or mn == "ldr") and len(ops) >= 2:
            m = _mem(ops[-1])
            if m and m[2] is None and m[1] == -1 and m[0] not in _UNTAGGED:
                fact[dst] = (_F_TAGS, m[0])                     # tags word of a tagged object
            elif (m and _T.roles.get(m[0]) == "DISPATCH"
                  and m[2] is not None):                       # dispatch-table indexed load
                f = fact.get(canon(m[2]))                       # read first: dst may BE the index
                fact[dst] = (_F_DTARGET,
                             f[1] if f is not None and f[0] == _F_DISP else (None, None))
            else:
                fact.pop(dst, None)
            continue
        if mn == "ubfx" and len(ops) >= 4:
            f = fact.get(canon(ops[1]))
            fact.pop(dst, None)
            if (f is not None and f[0] == _F_TAGS
                    and _imm(ops[2]) == 0xc and _imm(ops[3]) == 0x14):
                fact[dst] = (_F_CID, f[1])                      # class id of the receiver
            continue
        if mn == "mov" and len(ops) == 2:
            f = fact.get(canon(ops[1]))
            imm = _imm(ops[1])
            fact.pop(dst, None)
            if imm is not None:
                fact[dst] = (_F_IMM, imm)
            elif f is not None:
                if f[0] == _F_CID:
                    fact[dst] = (_F_DISP, (f[1], 0))
                elif f[0] == _F_DISP or f[0] == _F_DTARGET:
                    fact[dst] = f
            continue
        if (mn == "add" or mn == "sub") and len(ops) >= 3:
            fs = fact.get(canon(ops[1]))
            ft = fact.get(canon(ops[2]))
            off = _imm(ops[2])
            fact.pop(dst, None)
            if fs is not None and fs[0] == _F_CID:
                if off is not None:
                    fact[dst] = (_F_DISP, (fs[1], off if mn == "add" else -off))
                elif mn == "add" and ft is not None and ft[0] == _F_IMM:
                    fact[dst] = (_F_DISP, (fs[1], ft[1]))
            continue
        fact.pop(dst, None)
    return out


# ── public entry point ──────────────────────────────────────────────────────

_DECL_RE = re.compile(r"^(\s*)var (t\d+) = (.+);$")
_TMP_RE = re.compile(r"\bt\d+\b")


def _inline_single_use(lines: list, names: set) -> list:
    """Fold `var t0 = f(x); return t0;` back into `return f(x);`.

    Naming a call's result is what stops a machine register leaking into every later line,
    but where the result has exactly one reader and that reader is the VERY NEXT
    statement, the name buys nothing and costs a line.

    Folding it there is safe for a reason that does not generalise, so the conditions are
    both checked rather than assumed: the value crosses no statement, so nothing it is
    spelled in terms of can have changed and no side effect is reordered; and it has one
    use in the whole body, so the call is not duplicated. Only temporaries minted for a
    call RESULT are eligible, a temporary that exists to stop an expression doubling in
    size must not be folded back into the expression it was cut out of."""
    if not names:
        return lines
    counts: dict = {}
    for ln in lines:
        for m in _TMP_RE.finditer(ln):
            counts[m.group(0)] = counts.get(m.group(0), 0) + 1
    out, skip = [], -1
    for i, ln in enumerate(lines):
        if i == skip:
            continue
        m = _DECL_RE.match(ln)
        if m and m.group(2) in names and counts.get(m.group(2)) == 2 and i + 1 < len(lines):
            nxt = lines[i + 1]
            # A WORD-boundary match, not a substring one. `"t1" in "... = t10;"` is true,
            # and with `t1` used exactly twice and its real use further down, the fold
            # fired on a line that does not mention it: the substitution below matched
            # nothing, the declaration was dropped anyway, and the surviving use of `t1`
            # had nothing defining it. Latent rather than live, 0 of the corpus's 4,642
            # folds collide, but the numbering reaches t10 in 1,600 functions, so it is
            # a coincidence away.
            use = _TMP_RE.findall(nxt)
            if len(use) == 1 and use[0] == m.group(2):
                out.append(re.sub(rf"\b{m.group(2)}\b", m.group(3).replace("\\", "\\\\"),
                                  nxt))
                skip = i + 1
                continue
        out.append(ln)
    return out


def lift_function(ann: list, pool_map=None, receiver=None, arity=None,
                  indent="  ", depth=1, selectors=None, arch=None, fields=None) -> list:
    """Annotated disasm -> pseudo-Dart body lines (Tier 3). `receiver` is an optional
    register-alias map, e.g. {"x1": "this"} for an instance method; `arity` is an optional
    `pc -> int` resolver (see make_arity_resolver) enabling call-argument reconstruction;
    `selectors` maps a dispatch-call immediate to its source name (see dispatch.py);
    `fields` maps a byte offset to the receiver's field name at that offset (see
    fields.py), and only the receiver's, so an unresolved base still prints its offset.

    `arch` is the resolved target. Passing one whose roles are not modelled refuses; see
    LIFTABLE_ARCHS. Omitting it keeps the arm64 assumption every caller had before the
    parameter existed, so a caller that has no target to hand is not silently gated.
    """
    name = getattr(arch, "name", arch)
    if name is not None and name not in LIFTABLE_ARCHS:
        from .disasm import UnsupportedArch
        raise UnsupportedArch(
            f"Tier 3 expression lifting models the register roles of "
            f"{' and '.join(sorted(LIFTABLE_ARCHS))}, and this snapshot is {name}. "
            f"Tier 1 (`disasm`) does decode it, and the snapshot layer is unaffected.")
    with use_target(TARGETS[name] if name else ARM64):
        return _lift_function(ann, pool_map, receiver, arity, indent, depth, selectors,
                              fields)


@contextlib.contextmanager
def use_target(tgt: Target):
    """Bind the per-architecture tables for the duration of one lift.

    These are read by module-level helpers (`canon` is called from 49 places, several of
    them with no lifter in scope) so they are rebound rather than threaded. Rebinding the
    NAMES keeps every existing reader working unchanged, which is what makes it possible to
    add a second architecture without touching sixty call sites and hoping the first one
    still renders identically, and `export` on arm64 is byte-for-byte what it was.

    The caches have to go with them: `sp` canonicalises to x15 on one target and r13 on
    the other, so an entry made under one is wrong under the other. That is true of all
    three, not just `_CANON_CACHE`, `_MEM_CACHE` and `_DEFUSE_CACHE` store `canon()`
    results keyed on the operand STRING alone, so whichever target parsed a given string
    first would answer for both. Nothing catches it today because `LIFTABLE_ARCHS` admits
    only arm64, but a test already drives the lifter under ARM32 directly, and the day the
    gate opens the wrong register file is a silently wrong body.
    """
    global _T, ROLE, _SPECIAL, _UNTAGGED, ARG_REGS, _CALL_CLOBBERS, _RET_USES
    prev = (_T, ROLE, _SPECIAL, _UNTAGGED, ARG_REGS, _CALL_CLOBBERS, _RET_USES,
            dict(_CANON_CACHE), dict(_MEM_CACHE), dict(_DEFUSE_CACHE))
    _T = tgt
    ROLE, _SPECIAL, _UNTAGGED = tgt.roles, set(tgt.special), tgt.untagged
    ARG_REGS = tgt.arg_regs
    _RET_USES = frozenset({tgt.ret_int, tgt.ret_fp})
    _CALL_CLOBBERS = (frozenset({f"x{i}" for i in range(15)}
                                | {f"d{i}" for i in range(31)}) if tgt is ARM64 else
                      # arm32: R0-R3 and R12 are AAPCS volatile, and Dart adds R9. The FPU
                      # side is D0-D7 (constants_arm.h kAbiVolatileFpuRegs).
                      frozenset({f"r{i}" for i in (0, 1, 2, 3, 9, 12)}
                                | {f"d{i}" for i in range(8)}))
    _CANON_CACHE.clear()
    _MEM_CACHE.clear()
    _DEFUSE_CACHE.clear()
    try:
        yield
    finally:
        (_T, ROLE, _SPECIAL, _UNTAGGED, ARG_REGS, _CALL_CLOBBERS,
         _RET_USES, cache, mem, defuse) = prev
        _CANON_CACHE.clear()
        _CANON_CACHE.update(cache)
        _MEM_CACHE.clear()
        _MEM_CACHE.update(mem)
        _DEFUSE_CACHE.clear()
        _DEFUSE_CACHE.update(defuse)


def _lift_function(ann, pool_map, receiver, arity, indent, depth, selectors,
                   fields=None) -> list:
    stripped = strip_boilerplate(ann)
    blocks, entry = build_cfg(stripped)
    if not blocks:
        return []
    stmts = structure(blocks, entry)
    dispatch = detect_dispatch(stripped)
    lifter = Lifter(blocks, pool_map=pool_map, receiver=receiver, arity=arity,
                    dispatch=dispatch, selectors=selectors, entry=entry, fields=fields)
    lifter.labels = label_targets(stmts)
    lines, _falls = lifter.walk(stmts, State(), indent, depth)
    return _inline_single_use(lines, lifter.results)
