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
  register arity (see entry_arity). A callee that takes its arguments on the stack gets
  what the caller pushed, one that takes registers and the stack gets both, and a call
  whose list cannot be read renders as `name(...)` rather than a guess.
- Field *names* are not recoverable at all. AOT tree-shakes the metadata: the class
  offset_in_words_to_field table is empty for every class in the corpus and most Field
  objects are gone with it, so fields render by byte offset, `x1.field_0x8`. That's a
  property of the format, not a gap here.

Register roles for this epoch, confirmed against the FluBench 3.12.2 build and
constants_arm64.h: x15=SP, x29=FP, x30=LR, x26=THR, x27=PP, x28=HEAP_BASE,
x22=NULL (true=+0x20, false=+0x30), x21=DISPATCH_TABLE.
"""
from __future__ import annotations

import bisect
import collections
import contextlib
import heapq
import re
from dataclasses import dataclass, field, replace
from sys import intern
from typing import NamedTuple

from .keep import kept
from .cfg import (build_cfg, structure, negate_cond, label_targets, _cond_text, _REL,
                  cond_of, cut_goto, flat, flat_rows, TOO_DEEP, TRAPS, _target,
                  entry_reach, UNREACHED, cut_off, dominator_forest, dom_numbers,
                  second_reach, strong_components, past_trap, _cond_for, checks_into,
                  _conditions_from_the_block_before, LoopNest)

# ── operand / register plumbing ─────────────────────────────────────────────

# General-purpose (w/x) and SCALAR floating-point (s/d) registers. Vector registers are
# left out on purpose: `v0.2d` and `v0.4s` are Float64x2 / Float32x4 SIMD values, not
# scalar doubles, and folding them in here would let the lifter print a plain `a + b` for
# a lane-wise add. The pattern can't match them by construction. An arrangement suffix
# puts the digit before the letter (`.2d`, `.16b`), so `\b[ds]\d+\b` never fires on one.
_REG_RE = re.compile(r"\b([wx](?:3[01]|[12]\d|\d)|[ds](?:3[01]|[12]\d|\d))\b")
_FREG_RE = re.compile(r"^[ds](?:3[01]|[12]\d|\d)$")

# The IR below the statement tree is text, so every pass re-parses the same operand
# strings: about 6x reuse across an image. These parsers are therefore memoised.
# Safe because each is a pure function of its string argument, touching no image,
# epoch or lifter state, and each returns an immutable value. _SPLIT_CACHE is the
# only one large enough to bound; it is cleared wholesale rather than evicted from,
# and the values are interned so the cache does not buy speed with memory.
_CANON_CACHE: dict = {}
_SPLIT_CACHE: dict = {}
#: Ceiling on _SPLIT_CACHE: the commonest 16k operand strings answer ~95% of lookups,
#: which caps it near 2MB whatever the input.
_SPLIT_CACHE_MAX = 16384
_IMM_CACHE: dict = {}
_MEM_CACHE: dict = {}
_DEFUSE_CACHE: dict = {}          # mnemonic -> operand string -> (defs, uses)
_AF_ROW_CACHE: dict = {}          # mnemonic -> operand string -> `_af_row`'s answer
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
    # The low doubleword lane IS what dN names, so `mov x0, v0.d[0]` reads d0. Keyed
    # apart, the read found nothing under its own spelling and fell back to the bare
    # operand, which the printed body never assigns and so reads as the value the
    # function came in with: 31 lines on each fixture read the double a call had just
    # returned as the entry v0 (#209). Folded here rather than at the read, so an insert
    # into the lane lands on dN too, which is what it overwrites (#134): `mov v0.d[0],
    # x3` used to write a key nothing reads and leave dN reading as the entry value with
    # no printed assignment at all. `ins` and `fmov` of a lane print raw instead, and a
    # raw line is itself a printed assignment, so those were already consistent. Neither
    # fixture holds a lane write; all 62 lane operands in them are reads.
    if reg[0] == "v" and reg.endswith(".d[0]") and reg[1:-5].isdigit():
        return "d" + reg[1:-5]
    return reg


def _is_fp(reg: str) -> bool:
    return bool(_FREG_RE.match(reg))


#: Any spelling of an arm64 FP/SIMD register: d3, v3.16b, v3.d[0], q3, h3, b3 (s3 is
#: already d3 by canon). All of them are one register, v3.
_FP_VIEW_RE = re.compile(r"^[dvqhb](3[01]|[12]\d|\d)(?:\.\w+(?:\[\d+\])?|\[\d+\])?$")


#: What `eor` of a register with itself, or `movi #0`, zeroes the whole double in.
_ZEROED = re.compile(r"(v(3[01]|[12]\d|\d)\.(16b|8b|2d))|d(3[01]|[12]\d|\d)")

#: A lane insert's destination lane: `v0.d[1]`, `v0.s[2]`, `v0.b[9]`.
_LANE_RE = re.compile(r"\.([dshb])\[(\d+)\]\s*$")


def _upper_lane(opspec: str) -> bool:
    """Whether `opspec` is an insert into a lane entirely in the upper 64 bits of a V
    register, so the low 64, which dN names, is untouched: `.d[1]`, `.s[2]`/`.s[3]`,
    `.h[4]` and up, `.b[8]` and up. The low lane (`.d[0]`, `.s[0..1]`, ...) is not one,
    as an insert there changes what dN holds (#134)."""
    m = _LANE_RE.search(opspec.strip())
    if m is None:
        return False
    return int(m.group(2)) * {"d": 8, "s": 4, "h": 2, "b": 1}[m.group(1)] >= 8


_FP_N_CACHE: dict = {}


def _fp_n(reg: str):
    """The number of the FP/SIMD register `reg` spells, or None. arm64 only: on arm32 q1
    is d2:d3, and tier 3 lifts arm64 alone (LIFTABLE_ARCHS)."""
    hit = _FP_N_CACHE.get(reg, _FP_N_CACHE)
    if hit is not _FP_N_CACHE:
        return hit
    m = _FP_VIEW_RE.match(reg)
    out = m.group(1) if m else None
    if len(reg) <= 12:
        _FP_N_CACHE[reg] = out
    return out


#: A vector spelling of an FP/SIMD register in an operand, for liveness (#114).
_VREG_RE = re.compile(r"\b[vqhb](3[01]|[12]\d|\d)\b")


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
#: Architectures this lifter has a register-role model for. Tier 1 (disasm.py) decodes
#: more than this on purpose: annotated arm32 is honest without these tables, while lifting
#: it through arm64's roles is wrong in the direction that matters. `ldr r0, [sl, #0x3c]`
#: reads a canonical object out of the thread, and with no role for r10 it renders as
#: `sl.field_0x3d`: a field access, on an untagged pointer, with the tag bias added anyway,
#: which a reader cannot tell from a real field read.
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
    #: Roles holding an UNtagged address (no kHeapObjectTag bias) whatever the code does.
    #: Not LR: Dart also loads a Code object into it and calls through its entry point,
    #: so what it holds is the code's to say and not the table's (`Lifter._holds_ra`).
    untagged: frozenset
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
    #: The displacements off an element address, `add xD, xArr, xIdx, lsl #s`, at which
    #: an indexed load or store reaches element xIdx, by whether pointers are compressed:
    #: `Instance::DataOffsetFor(cid)` less the heap-object tag for each class it names,
    #: and 0, which it gives external typed data (runtime_api.cc), as (every Dart
    #: release cited has it, some release cited has it). An element is printed only at
    #: a member of the first, and a member of the second is one more offset the class
    #: could have (`_elem_offsets`). Empty where nothing is read as an element.
    data_offsets: dict = field(default_factory=dict)

    @property
    def pairs(self) -> bool:
        return self.word < 8

    @property
    def special(self) -> frozenset:
        return frozenset(self.roles) | ({self.zero} if self.zero else frozenset())


#: constants_arm64.h. x15 is Dart's SP (the hardware SP is used only in the prologue),
#: x22 is NULL with the Bool singletons just above it, x21 is the dispatch table.
#:
#: Untagged, each from the VM's assembler_arm64.cc: SP and FP are stack addresses, THR is
#: the Thread*, PP has the tag taken off (`sub(PP, PP, Operand(kHeapObjectTag)); // Pool
#: in PP is untagged!`), x21 is `Thread::dispatch_table_array()`, a `const uword*`, and
#: x28 is HEAP_BITS, mask and heap base bits, not an object (`RestorePinnedRegisters`).
#: NOT x22: it is loaded from `Thread::object_null_offset()`, an ObjectPtr, so null is
#: a tagged pointer like any other and a field off it carries the bias (#330). true and
#: false are `NULL_REG + kTrueOffsetFromNull` and `+ kFalseOffsetFromNull`, offsets
#: between two tagged pointers, which the `add` reads from `consts` and not from here.
ARM64 = Target(
    name="arm64",
    roles={"x15": "SP", "x29": "FP", "x30": "LR", "x26": "THR", "x27": "PP",
           "x28": "HEAP", "x22": "NULL", "x21": "DISPATCH"},
    untagged=frozenset({"x15", "x21", "x26", "x27", "x28", "x29"}),
    arg_regs=("x1", "x2", "x3", "x5", "x6", "x7"),
    zero="xzr",
    aliases={"wzr": "xzr", "xzr": "xzr", "wsp": "x15", "sp": "x15"},
    ret_int="x0", ret_fp="d0",
    # `add xD, x22, #imm`: every one in all fifteen arm64 corpus builds plus the
    # uncompressed iOS build uses 0x20 or 0x30 and nothing else.
    consts_base="NULL", consts={0x20: "true", 0x30: "false", 0x0: "null"},
    incoming_from_fp=0x10, word=8,
    # The AOT_ offsets of the PRODUCT ARM64 blocks of runtime_offsets_extracted.h at
    # 2.19.6, 3.12.2 and 3.13.0, for the classes DataOffsetFor names there. Compressed,
    # all three: Array, OneByteString, TwoByteString and Record at 0x10, TypeArguments
    # and TypedData at 0x18; 3.13.0 adds Closure, at 0x20. Uncompressed: Array and
    # TypedData at 0x18, the strings at 0x10, TypeArguments at 0x28, Record at 0x18 in
    # 2.19.6 and 0x10 after, Closure at 0x28 in 3.13.0. Of the 44,291 element accesses
    # off a base of unknown tag on the nine compressed binaries, 2.19 to 3.13, 42,275 are
    # at 0xf or 0x17 and 1,375 at 0.
    data_offsets={True: (frozenset({0x0, 0xf, 0x17}), frozenset({0x0, 0xf, 0x17, 0x1f})),
                  False: (frozenset({0x0, 0xf, 0x17, 0x27}),) * 2},
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
    untagged=frozenset({"r13", "r11", "r10", "r7", "r12"}),
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
    # The PRODUCT ARM block of the same three headers: Array, the strings and
    # TypedData at 0xc, TypeArguments at 0x14, Record at 0xc in 2.19.6 and 8 after,
    # Closure at 0x14 in 3.13.0.
    data_offsets={False: (frozenset({0x0, 0xb, 0x13}), frozenset({0x0, 0x7, 0xb, 0x13}))},
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

#: What the thread pointer reads as, on both targets. The walk keeps a register's VALUE,
#: so a copy of it, `mov x25, x26` or a spill and reload of one, holds this same text for
#: as long as the walk can show it holds the thread, and no longer (#273).
_THR = "THR"

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
               "Object": "Object", "Context": "Context", "Closure": "Closure",
               # Dart 3.13 sizes a closure by its captured slots and has one stub per
               # size, GenerateAllocateClosureStub(1) to (4) (stub_code_compiler.cc).
               # The class allocated is Closure whichever it is.
               "Closure1": "Closure", "Closure2": "Closure", "Closure3": "Closure",
               "Closure4": "Closure"}


def _returns_x0(base: str) -> bool:
    """The stubs that hand a value back in x0: `InitLate*` the field's, `Await` the
    awaited one, `InitAsync` and `CloneContext` an object.

    They are not register-preserving machinery like the stack-check, write-barrier and
    type-test stubs, so they are rendered as the calls they are rather than dropped.
    Dropping them left the STALE x0 standing in for the value, which collapsed thirteen
    lazy-init getters on the clean fixture to `return x0;` the moment stub naming started
    working (#234): a whole body replaced by a bare register, where the unnamed call at
    least printed the branch it came from."""
    return base.startswith("InitLate") or base in ("InitAsync", "Await", "CloneContext")


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
    if "WriteBarrier" in base or "TypeTest" in base or base.startswith("StackOverflow"):
        return ("suppress", None)
    if _returns_x0(base):
        return ("keep", base)        # hands a value back: a call, not machinery to drop
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
        # v0.16b, q0, h0 and b0 are d0 too: `mov v0.16b, v1.16b` in a loop writes d0, and
        # liveness that did not say so let a 0.0 from before the loop stand after it.
        for n in _VREG_RE.findall(t):
            out.add("d" + n)
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

#: The mnemonics that COMPUTE a value, so that writing their w form truncates a result the
#: text would otherwise keep whole (`_narrow`, #235). A load is not here: it moves as many
#: bytes as its own form says and nothing above them. Nor is a store or a compare: their
#: first operand is a source, and narrowing one would rewrite a value the machine kept.
#: `uxtb`, `uxth` and `movz` are not here either, because what they write already fits.
#: Only mnemonics this file MODELS: one it does not reaches `_verbatim`, which forgets the
#: destination, so there is no value left to truncate and listing it would claim a
#: coverage that is not there.
_NARROW32 = frozenset({
    "add", "adds", "sub", "subs", "neg", "negs", "mul", "madd", "msub", "mneg", "sdiv",
    "and", "ands", "orr", "eor", "bic", "bics", "orn", "eon", "mvn", "lsl", "lsr", "asr",
    "mov", "movk", "csel", "csinc", "csinv", "csneg", "cinc", "cinv", "cneg", "csetm",
    "sbfx", "sxtb", "sxth", "sbfiz", "ubfiz", "adc", "sbc",
})
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


#: How a frozen dataclass stores a field (`V.__init__`).
_SETATTR = object.__setattr__


@dataclass(frozen=True)
class V:
    text: str
    prec: int = P_ATOM
    #: The same value before a 32-bit destination truncated it, where one did (`_narrow`,
    #: #235). A consumer that reads the w view of the register takes the low 32 bits
    #: itself, so it reads THIS and truncates its own result instead, which leaves one
    #: `.toUnsigned(32)` at the end of a chain of 32-bit operations rather than one on
    #: every step of it. Compares structurally like the other two fields, so two arms of a
    #: join agree exactly when their texts and their untruncated values do.
    wide: "V | None" = None
    #: An upper bound on the value: it is in [0, 2**bits). 64 is "nothing is known", which
    #: is also what a value that may be NEGATIVE gets, since a negative Dart int is
    #: exactly what a 32-bit destination cannot hold. Carried because the text does not
    #: say it: `(x1 & 0xffffffff) >>> 3` fits in 32 bits and `x1 >>> 3` does not, and
    #: their tails read the same. `_fits32` reads it to leave a truncation off a value
    #: that needs none (#235), and `_sext32` to leave the sign extension off an untag
    #: whose source is under 2**31 (#285); it is the smallest useful piece of the
    #: representation lattice DESIGN section 13 describes, not that lattice.
    bits: int = 64
    #: The signed counterpart of `bits`: bits `sext - 1` to 63 of the value agree, so it
    #: is in [-2**(sext-1), 2**(sext-1)). 64 is "nothing is known". Set where the text
    #: prints a sign extension, `.toSigned(k)`, and carried through an arithmetic shift
    #: right by a literal, so a Smi untag, `x1.toSigned(32) >> 1`, has 31. `_sext32` reads
    #: it to leave the sign extension off an operand of a 32-bit signed division that
    #: already has it (#291).
    sext: int = 64
    #: How the register holds the value the text names, where not as itself (#290). A
    #: Smi tag, `sbfiz xD, xN, #1, #0x1f`, prints the Dart value it tags, which is how a
    #: store, a call or a return reads it, and the register holds bits 0 to 30 of it
    #: shifted up one: `_SMI_TAG`, whose untag gives back `xN.toSigned(31)`. `_SMI_BOX`
    #: once the box-or-tag check tier 3 follows has compared exactly that against xN, so
    #: the register holds xN boxed: its untag gives back xN, and so does the Mint's value
    #: field, the other half of an unbox. 0 is the value itself. A name given to one
    #: value carries it; two paths that disagree on it keep the value and drop it.
    smi: int = 0
    #: The value is an address or a number the lifter COMPUTED, arithmetic on something,
    #: and so not known to be an object pointer (#329). `.tags` is the header word of the
    #: object a base points at, and off `t0 + 1 + (x5 << 2)` no object is known to start
    #: there: an access at offset 0 off a computed base prints as the read at its
    #: address (`Lifter._rebase`). Every operator sets it; an inline allocation the rows
    #: prove clears it again (`_addr_facts`). It is the value's and not the text's, so a
    #: name given to the value carries it, as a frame slot and a 32-bit view do, and two
    #: paths that disagree on it keep it. Left out of the comparison: two values that
    #: print the same are the same value, and what is known of them is merged
    #: (`_joined`).
    calc: bool = field(default=False, compare=False)
    #: `(base, k, untagged, row)` where the value is `base + k` for a constant k: what
    #: an `add` or `sub` of an immediate made, and a sum that has one inside. An access
    #: off it is one off `base` at the displacement plus k, so the constants of the
    #: address are made one, and a chain that cancels gives `base` back with what is
    #: known of it. `untagged` is whether `base` was read from a register that holds an
    #: untagged address (`Lifter._untagged`), whose offsets carry no tag bias. `row` is
    #: the address of the first add of the chain, where `_addr_facts` says whether the
    #: register `base` was read from may have held a computed address on some way in.
    #: Dropped where the value is given a name, since `base` is text and means what it
    #: meant only until a register in it is written.
    at: "tuple | None" = field(default=None, compare=False)

    def __init__(self, text, prec=P_ATOM, wide=None, bits=64, sext=64, smi=0,
                 calc=False, at=None):
        # Written out, and not the one the dataclass makes, which stores every field
        # through `object.__setattr__` whatever it holds. A lift builds about two
        # million of these and nearly all of them are a text and a precedence, so a
        # field left at its default is not stored: it reads off the class, where the
        # dataclass keeps each default, and compares, hashes and prints as before.
        # `V("x0", 0)` took 288 ns with five fields, 377 with seven, and takes 142
        # (#346).
        put = _SETATTR
        put(self, "text", text)
        put(self, "prec", prec)
        if wide is not None:
            put(self, "wide", wide)
        if bits != 64:
            put(self, "bits", bits)
        if sext != 64:
            put(self, "sext", sext)
        if smi != 0:
            put(self, "smi", smi)
        if calc is not False:
            put(self, "calc", calc)
        if at is not None:
            put(self, "at", at)


def _wrap(v: V, ctx: int) -> str:
    # A negative literal is an atom here and a unary minus to Dart, so a postfix operator
    # binds tighter than its sign: `-128.field_0x8` is `-(128.field_0x8)` (#130).
    if v.prec >= ctx and not (ctx > P_UNARY and v.text[:1] == "-"):
        return v.text
    return f"({v.text})"


_TAIL_MASK = re.compile(r"& (0x[0-9a-fA-F]+|\d+)\Z")


def _fits(v: V, bits: int) -> bool:
    """Whether `v` is `... & m` with a mask m under 2**bits."""
    m = _TAIL_MASK.search(v.text) if v.prec == P_AND else None
    return bool(m) and int(m.group(1), 0) < 1 << bits


#: What `_narrow` writes, and what reading a 32-bit operand takes back off.
_U32 = ".toUnsigned(32)"


def _fits32(v: V) -> bool:
    """Whether `v`'s value provably has no bit above 31, so a 32-bit destination holding
    it needs no truncation in the text: a mask that small, a literal that small, a value
    this already truncated, or one whose bound says so (`V.bits`)."""
    if v.bits <= 32 or _fits(v, 32) or v.text.endswith(_U32):
        return True
    return bool(_INT_LITERAL.match(v.text)) and 0 <= int(v.text, 0) < (1 << 32)


def _sext32(v: V) -> bool:
    """Whether bits 31 to 63 of `v` provably agree, so `v.toSigned(32)` is `v` itself: a
    bound under 2**31, which makes every one of them zero, or an int literal in the int32
    range. `V.bits` is unsigned and a value that may be negative has 64, so a bound of 32
    says nothing about bit 31 (#285). A value the text already sign-extends from bit 31 or
    lower, `V.sext`, needs no second extension."""
    if v.bits <= 31 or v.sext <= 32:
        return True
    return bool(_INT_LITERAL.match(v.text)) and -(1 << 31) <= int(v.text, 0) < (1 << 31)


def _to_signed(v: V, k: int) -> V:
    """`v.toSigned(k)`, the low `k` bits of `v` sign-extended, and the bound it proves."""
    return V(f"{_wrap(v, P_POST)}.toSigned({k})", P_POST, sext=k, calc=True)


def _signed32(v: V) -> V:
    """`v` as a 32-bit signed operand reads it: its low 32 bits, sign-extended. `v` itself
    where `_sext32` proves the two the same."""
    return v if _sext32(v) else _to_signed(v, 32)


#: `V.smi`.
_SMI_TAG, _SMI_BOX = 1, 2


def _fits31(v: V) -> bool:
    """Whether `v` is provably a 31-bit signed value, so `v.toSigned(31)` is `v`: a bound
    under 2**30 or an int literal in that range."""
    if v.bits <= 30:
        return True
    return bool(_INT_LITERAL.match(v.text)) and -(1 << 30) <= int(v.text, 0) < (1 << 30)


def _smi_value(v: V) -> V:
    """What an untag of a register holding `v` Smi-tagged reads: the bits of the value a
    tag keeps, `.toSigned(31)`, or the value itself where it provably fits, by its bound
    or by the box-or-tag check. Only the low 31 bits are read, so a value a 32-bit write
    truncated is read whole (`V.wide`)."""
    val = replace(v, smi=0)
    if v.smi == _SMI_BOX or _fits31(val):
        return val
    low = val.wide if val.wide is not None else val
    return _to_signed(low, 31)


def _to_s64(n: int) -> int:
    """`n` as the signed 64-bit integer a register holding it reads as."""
    n &= (1 << 64) - 1
    return n - (1 << 64) if n >> 63 else n


def _whole(ops) -> bool:
    """Whether no operand of `ops` is the 32-bit view of a register."""
    return not any(o.strip()[:1] == "w" for o in ops)


def _role_address(v: V) -> bool:
    """Whether `v` is an untagged role register's own address in some other register:
    `mov x0, x28` holds HEAP, which is no object pointer and has no header. The thread
    is left out, since a copy of it is read as the thread is (`Lifter._untagged`)."""
    if v.prec != P_ATOM:
        return False
    got = _UNTAGGED_ROLES.get(id(_T))
    if got is None:
        got = _UNTAGGED_ROLES[id(_T)] = (frozenset(
            ROLE[r] for r in _UNTAGGED if r in ROLE) - {_THR}, _T)
    return v.text in got[0]


#: Per target, the role names `_role_address` answers yes to, made once, and the
#: target, kept so that its id stays its own.
_UNTAGGED_ROLES: dict = {}


#: Role name -> a matcher for it standing as a value in a text (_names_role).
_ROLE_RE: dict = {}
_QUOTED_RE = re.compile(r'"(?:[^"\\]|\\.)*"')


def _names_role(v: V, role: str) -> bool:
    """Whether the text of `v` names the frame register `role`, `SP` or `FP`.

    `SP` in a text is SP at the line it is printed on, and `FP` the frame pointer of the
    frame in force there, so a value that names one says something else once that
    register moves (#340). A name given to the value does not, and a 32-bit view prints
    the value it narrows. Not a field or a member called the same, nor the word in a
    string constant."""
    text = v.text
    if role not in text:
        return False
    if '"' in text:
        text = _QUOTED_RE.sub('""', text)
    pat = _ROLE_RE.get(role)
    if pat is None:
        pat = _ROLE_RE[role] = re.compile(rf"(?<![\w$.]){role}(?![\w$@])")
    return pat.search(text) is not None


def _names_frame(v: V, role: str) -> bool:
    """`_names_role`, or the register of `role` by its machine name: one the step forgot
    is printed bare, and a text spelled with that says something else past a move of
    the register as surely as one spelled with the role (#340)."""
    text, reg = v.text, _frame_regs()[role == "FP"]
    if role not in text and reg not in text:
        return False
    return _names_role(v, role) or _names_role(v, reg)


def _role_sum(v: V, role: str):
    """`(base, k, untagged, row)` where `v` is the frame register `role` plus a constant
    by its own record, `V.at` off the register's address or that address itself; None
    for any other value, whatever its text."""
    if v.smi or v.wide is not None:
        return None
    if v.at is None:
        return (v, 0, False, None) if _role_address(v) and v.text == role else None
    base = v.at[0]
    return v.at if _role_address(base) and base.text == role else None


def _off_role(base: V, k: int, untagged: bool, row) -> V:
    """The value `base + k` with its record, as `Lifter._offset` leaves one."""
    if k == 0:
        return replace(base, at=None if row is None else (base, 0, untagged, row))
    total = (_bin(base, "+", _num(k), P_ADD) if k > 0
             else _bin(base, "-", _num(-k), P_ADD))
    return replace(total, at=(base, k, untagged, row))


def _smi_word(v: V) -> V:
    """The machine word of a register holding `v`: `v` itself, or for a tagged value the
    Smi it is, shifted up one."""
    return v if not v.smi else _bin(_smi_value(v), "<<", _num(1), P_SHIFT)


def _narrow(v: V) -> V:
    """`v` as a 32-bit destination holds it: the low 32 bits, zero-extended.

    arm64 writes the w view of a register by clearing the top half, and `canon` folds the
    two views onto one name, so without this the text of a 32-bit result is the text of a
    64-bit one and the top half it keeps is a value the machine does not have. Measured
    against the CPU over the fixtures' own code, with the `w` exclusion dropped from
    `tools/irfuzz.py`'s operand filter: 32 printed expressions in 2,001 runs on clean and
    30 on obf disagree, every one of them a 32-bit shift of a 64-bit shift's result (#235).

    `.toUnsigned(32)` rather than `& 0xffffffff` on purpose: a mask is what an `and`
    instruction does, this is what the register width does, and a reader who cannot tell
    them apart cannot tell which the program asked for. It pairs with the `.toSigned(32)`
    an `asr` on a w register already prints. Hex-Rays and Ghidra carry the same fact in a
    TYPE (`unsigned int`, `uint`) and Binary Ninja in the register name; this file has
    neither, so it goes in the expression."""
    return (v if _fits32(v)
            else V(f"{_wrap(v, P_POST)}{_U32}", P_POST, wide=v, bits=32, smi=v.smi,
                   calc=True))


def _prefix(sym: str, v: V) -> V:
    """`sym`, `-` or `~`, applied to `v`. A minus before a value that starts with a minus
    would read as Dart's decrement, `--128`, so that one is bracketed (#130)."""
    inner = _wrap(v, P_UNARY)
    if sym == "-" and inner[:1] == "-":
        inner = f"({inner})"
    return V(sym + inner, P_UNARY, calc=True)


def _bits_of(a: V, op: str, b: V) -> int:
    """An upper bound on `a op b`, as `V.bits` means it: the value is in [0, 2**bits).

    64 wherever nothing follows, which is most places, and in particular wherever the
    result can be NEGATIVE: `a - b` and `~a` can be, and a negative Dart int is what a
    32-bit destination does not hold, so claiming a width for one would lose the
    truncation that makes the text right. A shift amount that is not a literal is
    unknown, and so is the result.

    `_fits32` and `_sext32` read this. An estimate that is too LARGE costs a truncation
    or a sign extension that changes no value; one that is too small would print a value
    the machine does not have, a top half kept by `_fits32` (#235) or, by `_sext32`, a
    negative Smi untagged as a large positive one (#285). Every rule here is therefore
    the loose side of the real bound."""
    x, y = a.bits, b.bits
    if op in ("+", "|", "^"):
        return min(64, (max(x, y) + 1) if op == "+" else max(x, y))
    if op == "*":
        return min(64, x + y)
    if op == "&":
        return min(x, y)
    if op in ("<<", ">>>", ">>"):
        k = int(b.text, 0) if _INT_LITERAL.match(b.text) else None
        if k is None or k < 0 or k >= 64:
            return 64
        if op == "<<":
            return min(64, x + k)
        # `>>` is arithmetic and `>>>` logical, but the text says `>>` for both and only
        # the arithmetic one can carry a sign in. A value already bounded below 2**63 is
        # non-negative either way, so the bound holds for both.
        return max(0, x - k) if x < 64 else 64
    return 64


def _bin(a: V, op: str, b: V, prec: int) -> V:
    # The RIGHT operand is wrapped one level tighter than the left, because every operator
    # here associates to the left and several of them do not commute. `sub x2,x1,#2` then
    # `sub x3,xC,x2` printed `30 - x1 - 2`, which reads as `(30 - x1) - 2` and is four
    # short of the `30 - (x1 - 2)` the CPU computes; `a * (b ~/ c)` printed `a * b ~/ c`,
    # which divides a different numerator. Found by evaluating the printed text against
    # the hardware, not by reading it.
    # An arithmetic shift right by k keeps a sign extension, k bits narrower (`V.sext`).
    k = int(b.text, 0) if op == ">>" and _INT_LITERAL.match(b.text) else -1
    sext = max(1, a.sext - k) if 0 <= k < 64 and a.sext < 64 else 64
    return V(f"{_wrap(a, prec)} {op} {_wrap(b, prec + 1)}", prec, bits=_bits_of(a, op, b),
             sext=sext, calc=True)


def _num(n: int) -> V:
    return V(str(n) if -256 < n < 256 else hex(n), P_ATOM,
             bits=n.bit_length() if n >= 0 else 64, calc=True)


#: The root of an address off the frame, `FP`, `SP`, `(FP - 8)` (#341).
_FRAME_ROOT = re.compile(r"\(*(?:FP|SP)(?: [-+] [^.()\[\]]+)*\)*\Z")
#: A read of the frame inside a value's text, which a store to the heap does not write:
#: `FP.field_0x21`, `(FP - 0x340).field_0x1`, and the `FP[` of a slot at an index, whose
#: index may itself read the heap and stays (#341).
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _spelled(texts: tuple, text: str, whole=False) -> bool:
    """Whether `text` has one of `texts` in it with no hex digit after it, which is
    what `(?:a|b)(?![0-9a-fA-F])` of them finds: a spelling ends in hex digits, so
    `field_0x8` must not be found inside `field_0x80`. With `whole`, and nothing a
    name is made of before it either, the lookbehind for a word character, `$` or
    `@` that an element's pattern had. An empty one is found at the end of any text,
    as the pattern finds it."""
    n = len(text)
    for x in texts:
        i = text.find(x)
        while i >= 0:
            j = i + len(x)
            if (j == n or text[j] not in _HEX_DIGITS) and not (
                    whole and i and ((c := text[i - 1]) in "_$@" or c.isalnum())):
                return True
            i = text.find(x, i + 1)
    return False


_FRAME_READ = re.compile(r"\((?:FP|SP)(?: [-+] (?:0x[0-9a-fA-F]+|\d+))?\)\.field\d*_0x"
                         r"[0-9a-fA-F]+|\b(?:FP|SP)\.field\d*_0x[0-9a-fA-F]+|\b(?:FP|SP)\[")


#: The most spellings a store looks for one by one to say whether a field and an
#: element may be one word (`Lifter._pin_mem`, #375). Past it the store names every
#: live read of the kind, which is more names and the same cost per row.
_EDGE_CAP = 64
#: `Lifter._elems_under`: every element read, where there are more than `_EDGE_CAP`.
_EVERY = object()
#: `Lifter._pin_mem`: the element reads a field store may write, not asked for yet.
_LATER = object()
#: How many slots `Lifter._pin_mem` walks, per row of the function, before it keeps
#: the texts a store was found not to write. Ordinary code stays far under it: a store
#: walks the slots the frame holds, and the walks of a whole body come to a few times
#: its rows. A body made to hold thousands of slots across thousands of stores passes
#: it at once, and from there a store like the one before it asks about a slot's text
#: once and not once a store.
_PIN_WALK = 16
#: How many kinds of store `_pin_mem` keeps those texts for, the oldest dropped first.
_PIN_KEPT = 8

#: A field read spelled by its offset, with the width its spelling states.
_FIELD_AT = re.compile(r"(?<!\bTHR)(?<!\bPP)\.field(\d*)_0x([0-9a-fA-F]+)")
#: The same off any base, to count the `.` of a text that are one.
_FIELD_ANY = re.compile(r"\.field\d*_0x[0-9a-fA-F]+")
#: The bases a store goes INTO that hold no Dart object, so no element of one: the
#: thread and the object pool. A store through a pointer read out of one is a store
#: into whatever object that pointer is (`Lifter._pin_mem`, #375).
_NO_OBJECT = frozenset((_THR, "PP"))


def _fields_in(text: str) -> tuple:
    """Where the fields `text` reads off a heap object end, which an element store
    asks of every live value (`Lifter._pin_mem`, #375), so it is made once a text.
    The furthest byte a spelling states, with a word taken for four bytes; the
    offsets of the words that end past that if they are eight; and whether a `.` in
    it is anything but a field spelled by its offset, which is where a named field
    would be. Not a read off the frame, which no heap store reaches, nor off THR or
    PP, which are no Dart objects."""
    named = text.count(".") != len(_FIELD_ANY.findall(text))
    if "P" in text:
        text = _FRAME_READ.sub("", text)
    end, words = 0, set()
    for m in _FIELD_AT.finditer(text):
        off, w = int(m.group(2), 16), m.group(1)
        if w:
            end = max(end, off + int(w))
        else:
            end = max(end, off + 4)
            words.add(off)
    return end, tuple(o for o in words if o + 8 > end), named


def _fresh_v(v) -> bool:
    """Whether `v` is the pointer an inline allocation made (`Lifter._offset`, #329): a
    store off it cannot reach memory older than the object (#341)."""
    return not v.calc and v.at is not None and v.at[3] is None


_INT_LITERAL = re.compile(r"-?(?:0x[0-9a-fA-F]+|\d+)\Z")
#: A store target that is a field of an object. The third alternative is a field the
#: snapshot still names (fields.py): `this.balance = 8` is the same store as
#: `this.field_0x8 = 8` and wants the same Smi note, so recovering the name must not
#: silently drop it. Dart's private names carry a library id, `_state@5048458`.
_FIELD_LHS = re.compile(
    r"\.(?:field_0x[0-9a-fA-F]+|tags|[A-Za-z_$][A-Za-z0-9_$]*(?:@\d+)?)\Z")

#: A selector that says its access is WIDER than one word, `.field16_0x8`; see
#: Lifter._field. `_FIELD_LHS` matches it as though it were a recovered field name, which
#: is what the may-alias rule wants, and is wrong for anything that reads it as one word.
_WIDE_FIELD = re.compile(r"\.field\d+_0x[0-9a-fA-F]+\Z")

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
#: A text spelled off the frame itself, `(FP - 64).field_0x1`. It reads memory the
#: lifter tracks as slots rather than as fields, so a frame store writes it without
#: anything marking a value that reads it stale; such a text is never recorded (#199).
_FRAME_TEXT_RE = re.compile(r"\((?:FP|SP)\s*[-+]")
#: `this.toSigned(32)` and `this.toUnsigned(32)` are width conversions of the receiver
#: register, not fields of it, and read nothing. Taken for a named field, an untag of
#: `this` was assigned in each arm of an `if` rather than declared before it (#285).
_READS_MEMORY = re.compile(
    r"\.field(?:\d+)?_0x[0-9a-fA-F]+|\.tags\b|\[|\b" + _RECEIVER
    + r"\.(?!to(?:Signed|Unsigned)\(\d+\))[A-Za-z_$]")


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
    if _WIDE_FIELD.search(lhs.text):
        return ""            # a Smi is one word, and this write is wider than a field
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


#: Text -> the canonical registers it names, memoised. A slot's text is asked for its
#: registers when the slot is filed and again when one of them is written, and the texts
#: repeat (a bare `x6`, a field read), so the parse is worth keeping (#173).
_SLOT_REGS_CACHE: dict = {}


def _slot_regs(text: str) -> frozenset:
    hit = _SLOT_REGS_CACHE.get(text)
    if hit is None:
        hit = _SLOT_REGS_CACHE[text] = frozenset(canon(m) for m in _REG_RE.findall(text))
    return hit


class State:
    __slots__ = ("reg", "slot", "elem", "result", "poolbase", "spill", "tmpc", "pair",
                 "src", "views", "lost", "lost_slot", "slot_by_reg", "dropped",
                 "opaque", "spilled", "hoist", "hoisted")

    def __init__(self):
        self.reg: dict = {}          # canonical reg -> V
        self.slot: dict = {}         # "(base,disp)" stack slot -> V
        #: {slot key: (value, memory still fresh)} for the slots `stale_on_write` dropped,
        #: so `_reload` can spell the value rather than the load's own register (#196).
        #:
        #: THE INVARIANT. A record is valid at a reload on a path iff, on THAT path,
        #: between the drop that made it and the reload: nothing FILLED the slot, the key
        #: still names the same address, no write touched memory the text reads, and the
        #: printed body assigned none of the registers the text names. It lives on the
        #: State so it forks with the arms and is intersected by `_merge`; it is killed by
        #: a fill (`note_slot`) rather than by the slot leaving the map, because a store
        #: to a key that is already absent removes nothing and would be missed (#199).
        self.dropped: dict = {}
        self.elem: dict = {}         # reg -> (base V, index V, scale) for element addrs
        # Temps waiting to be written out. set() can decide a value needs a name, but it is
        # the block walker that owns the line list, so the declaration is parked here and
        # drained at the instruction that produced it.
        self.spill: list = []
        # Boxed so forked states keep numbering from a shared counter; two arms of an if
        # must not both mint a "t3".
        self.tmpc: list = [0]
        #: `set` below is the one site that mints a name without going through
        #: `Lifter._mint`, and #204 moved the other thirteen there so every name could be
        #: HOISTED: declared at the top of the body, assigned where the value is. Without
        #: that a spill declared inside an `if` arm and read after it closed had no way to
        #: be fixed, which is a read of something undeclared. These three are shared with
        #: the Lifter by reference, like `tmpc`, so a fork cannot lose them.
        self.spilled: set = set()
        self.hoist: frozenset = frozenset()
        self.hoisted: set = set()
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
        # The block this state last came out of, or right after a loop the blocks that
        # broke out of it. `Lifter._arrive` reads it to tell a goto straight from its
        # block from one that follows a `break`.
        self.src = None
        # FP/SIMD register number -> the spellings other than dN it is held under (q0,
        # v0.16b), so a write under one need not search the whole map for the others.
        self.views: dict = {}
        # Registers holding a value a join lost: the bare name a `_merge` dropped them to,
        # which reads like the entry value and like a raw line's result. A slot must not
        # store one, as the register will mean something else when the slot is read back
        # (#140). Cleared when the register is set to a real value.
        self.lost: set = set()
        # Registers the MACHINE has moved on from where the walk has not: the ones a loop
        # exit drops because the loop writes them. `lost` is the join's own set and the
        # narrower question a slot asks (#140); this is kept apart and read in one place,
        # a store's BASE, where a bare name claims the object the function came in with
        # (#208).
        self.opaque: set = set()
        # frame slot key -> the lost register whose value it holds, so the slot can be
        # dropped when that register is reassigned and its spelling means something else
        # (#140). Only lost values are tracked; a stable value in a slot stays.
        self.lost_slot: dict = {}
        # register -> the slot keys whose text names it, the reverse of what each slot's
        # text mentions. A slot's text stops describing the slot once a register it names
        # is reassigned on a straight-line path, so a reload reads the register afresh
        # rather than the value stored (#173). This indexes the drop so a write costs a
        # lookup, not a scan of every slot (the loop cost #154 removed). A superset is
        # safe: a key read back is re-checked against the slot it still holds, and a key
        # left out only misses a drop, never invents one.
        self.slot_by_reg: dict = {}

    def copy(self) -> "State":
        s = State()
        s.reg = dict(self.reg)
        s.slot = dict(self.slot)
        s.elem = dict(self.elem)
        s.result = self.result
        s.poolbase = dict(self.poolbase)
        s.pair = dict(self.pair)
        s.views = {n: set(v) for n, v in self.views.items()}
        s.lost = set(self.lost)
        s.opaque = set(self.opaque)
        s.lost_slot = dict(self.lost_slot)
        s.slot_by_reg = {r: set(ks) for r, ks in self.slot_by_reg.items()}
        s.dropped = dict(self.dropped)
        s.tmpc = self.tmpc
        s.spilled, s.hoist, s.hoisted = self.spilled, self.hoist, self.hoisted
        s.src = self.src
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
            return V("0", P_ATOM, calc=True)
        if reg in self.reg:
            return self.reg[reg]
        return V(ROLE.get(reg, reg), P_ATOM)

    def restore(self, reg: str):
        """`reg` holds what it held on entry again: the frame chain put it back, so it
        reads as its role (FP, LR) and not as the last value a row wrote there (#331)."""
        self.reg.pop(reg, None)
        self.elem.pop(reg, None)
        self.poolbase.pop(reg, None)
        self._unpair(reg)
        self._other_views(reg)
        self._stale_lost(reg)
        self.lost.discard(reg)
        self.opaque.discard(reg)

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
        self._other_views(reg)
        self._stale_lost(reg)
        self.lost.discard(reg)

    def _stale_lost(self, reg: str):
        """Drop the slots holding `reg` as a lost value, now `reg` is reassigned and its
        bare name names something else (#140)."""
        for k in [k for k, r in self.lost_slot.items() if r == reg]:
            self.slot.pop(k, None)
            del self.lost_slot[k]

    def note_slot(self, key: str, v: V):
        """Record that slot `key` holds `v`, whose text names registers it goes stale
        with (#173). Called wherever an FP-relative slot is filed with a value; the
        caller gates on that, as the outgoing area off SP is a call's arguments, read
        before any reassign and cleared by `_drop_outgoing` (#140)."""
        # A FILL supersedes any record, and is the only event that can: a store to a
        # key already absent from the map removes nothing, so keying the kill off removals
        # misses it (#199).
        self.dropped.pop(key, None)
        for r in _slot_regs(v.text):
            self.slot_by_reg.setdefault(r, set()).add(key)

    def reindex_slots(self):
        """Rebuild the register -> slot index from the slot map, where the keys or texts
        changed outside `note_slot`: a join builds a fresh slot map, a frame move renames
        the keys, and a reenter carries another block's. Only FP-relative slots, as
        `note_slot` indexes."""
        fp = next((r for r, v in _T.roles.items() if v == "FP"), None)
        idx: dict = {}
        if fp is not None:
            for key, v in self.slot.items():
                if key.startswith(fp):
                    for r in _slot_regs(v.text):
                        idx.setdefault(r, set()).add(key)
        self.slot_by_reg = idx

    def forget_slot(self, key: str):
        """Remove slot `key` and forget what it held.

        Every way a slot leaves the map except `stale_on_write` means its value is no
        longer the one the machine has there, so the record goes with it (#199)."""
        self.slot.pop(key, None)
        self.dropped.pop(key, None)

    def record_drop(self, key: str, v: V):
        """Remember `v` for a slot dropped because a register its text names was
        reassigned, which is the one drop whose value stays worth spelling: the
        instruction was FOLDED, so it printed no assignment and the text still reads what
        it read at the spill (#196).

        A text spelled off the frame itself is refused. `(FP - 64).field_0x1` reads memory
        the lifter does not model as a slot, so nothing marks it stale when a frame store
        writes it (#199)."""
        if not _FRAME_TEXT_RE.search(v.text):
            self.dropped[key] = (v, True)

    def stale_mem(self):
        """A write to memory has happened, so no record that READS memory is fresh.

        A flag and not a counter: `_merge` has to combine two arms, and the obvious
        arithmetic is unsound. With generations, an arm that wrote memory raises the
        merged counter, and a record the other arm kept then compares equal to it and
        reads as fresh. "Has memory been written since" is a predicate, so it ANDs."""
        if self.dropped:
            self.dropped = {k: (v, False) for k, (v, _f) in self.dropped.items()}

    def stale_on_write(self, written, keep=()):
        """Drop the slots whose text names a register in `written`, reassigned here on a
        straight-line path (#173). The index gives the candidate keys without a scan; each
        is re-checked against the slot it still holds, so a key left by an overwrite or a
        drop cannot take a slot that no longer names the register with it.

        `keep` is the slot a frame reload reads back: dropping it would collide the reload
        with the one that spilled, so it stays (and stays indexed), while the other slots
        the reload's register names still go (#173)."""
        for reg in written:
            survivors = set()
            for k in self.slot_by_reg.pop(reg, ()):
                v = self.slot.get(k)
                if v is None or reg not in _slot_regs(v.text):
                    continue
                if k in keep:
                    survivors.add(k)
                else:
                    self.record_drop(k, v)
                    del self.slot[k]
            if survivors:
                self.slot_by_reg[reg] = survivors

    def forget_hi(self, n):
        """Forget the wider spellings of FP register `n` (v*.16b, q*, v*.2d, lane
        inserts), keeping its low 64 bits d*. An upper-lane insert changes those wider
        values but not d* (#134). `views[n]` holds only the non-d spellings."""
        for k in list(self.views.get(n, ())):
            self.reg.pop(k, None)
            self.elem.pop(k, None)
            self.poolbase.pop(k, None)
        self.views.pop(n, None)

    def _other_views(self, reg: str):
        """Forget what the other spellings of `reg`'s FP/SIMD register hold.

        d0, v0.16b and q0 are one register, and a value is tracked under the spelling it
        was written with. A write under one left the others describing what was there
        before: `eor v0.16b, v0.16b, v0.16b` (the VM's 0.0), `ldr q0`, `ins v0.d[0], x3`
        and `movi v0.2d, #0` all left d0 holding the double loaded before them, and the
        store after printed that (#114)."""
        n = _fp_n(reg)
        if n is None:
            return
        d = "d" + n
        if reg != d and d in self.reg:
            self.reg[d] = V(d, P_ATOM)
            self.elem.pop(d, None)
            self.poolbase.pop(d, None)
        others = self.views.get(n)
        if others:
            for k in [k for k in others if k != reg]:
                # Gone rather than reset: an unknown register reads as its own name either
                # way, and a key left behind would be searched at every later write.
                self.reg.pop(k, None)
                self.elem.pop(k, None)
                self.poolbase.pop(k, None)
                others.discard(k)
        if reg != d:
            self.views.setdefault(n, set()).add(reg)

    def set(self, reg: str, v: V):
        reg = canon(reg)
        if reg == "xzr":
            return
        if len(v.text) > MAX_INLINE_CHARS and v.prec != P_ATOM:
            # An atom is already its own name, so there is nothing to gain from aliasing it;
            # only computed text is worth breaking up.
            name = f"t{self.tmpc[0]}"
            self.tmpc[0] += 1
            self.spilled.add(name)
            if name in self.hoist:
                self.hoisted.add(name)
                self.spill.append(f"{name} = {v.text};")
            else:
                self.spill.append(f"var {name} = {v.text};")
            v = V(name, P_ATOM, smi=v.smi, calc=v.calc)
        self.reg[reg] = v
        self.elem.pop(reg, None)
        self.poolbase.pop(reg, None)
        self._unpair(reg)
        self._other_views(reg)
        self._stale_lost(reg)
        self.lost.discard(reg)
        self.opaque.discard(reg)
        if reg in (_T.ret_int, _T.ret_fp):
            self.result = reg


#: A name this lifter minted for a value, a phi result or a loop-carried variable,
#: as opposed to a machine register or a source-level name. It is spelled only in the
#: printed body, so dropping it loses the only statement that says what the value is.
_MINTED_RE = re.compile(r"t\d+")
#: A double literal. The instruction that made it (`fmov #`, the `eor` zeroing idiom)
#: prints nothing, so a join one arm of which holds it is no more visible than one
#: holding a computed value, and has to be named (#114).
_FLIT_RE = re.compile(r"-?\d+\.\d+")


def _use_re(name: str):
    """A word-boundary matcher for one register or temporary name, memoised.

    Same cache `_pin` uses, and for the same reason: these are asked for over and over,
    one per name, and the set of names is tiny."""
    pat = _USE_RE.get(name)
    if pat is None:
        pat = _USE_RE[name] = re.compile(rf"\b{re.escape(name)}\b")
    return pat


def _base_re(name: str):
    """A matcher for `name` used as the BASE of a dotted access, `t7.`.

    Same cache as `_use_re`, keyed on the spelling it compiles, so the two cannot
    collide."""
    key = name + "."
    pat = _USE_RE.get(key)
    if pat is None:
        pat = _USE_RE[key] = re.compile(rf"\b{re.escape(name)}\.")
    return pat


def _mentions(names):
    """A test for whether a text mentions any of `names`, word-bounded."""
    pats = [_use_re(n) for n in sorted(names)]
    return lambda text: any(p.search(text) for p in pats)


def _lr() -> str:
    """The link register's machine name on the current target. Looked up once for a
    target, which is kept beside the answer so its id stays its own: about 700,000
    rows of a lift ask (#346)."""
    got = _LR_REG.get(id(_T))
    if got is None:
        got = _LR_REG[id(_T)] = (next(r for r, v in _T.roles.items() if v == "LR"), _T)
    return got[0]


_LR_REG: dict = {}


def _is_lr_spill(reg: str, st: State) -> bool:
    """True when `reg` is the link register still holding the incoming return address.
    A call writes it, so after one it is not (#162)."""
    lr = _lr()
    return canon(reg) == lr and lr not in st.reg


_WORD_RE = re.compile(r"\b[a-z][a-z0-9]*\b")


def _lr_write(mn: str, op: str, lr: str):
    """What the row leaves in the link register `lr`: True for a call, which puts its own
    return address there, False for any other row that may write it, None for a row that
    leaves it alone. `_def_use` names arm64 registers only, so on another target any row
    that names LR at all counts as a write: it can only say less (#280)."""
    if mn in _CALLS:
        return True
    if lr in _def_use(mn, op)[0]:
        return False
    if _T is not ARM64 and any(canon(w) == lr for w in _WORD_RE.findall(op)):
        return False
    return None


def _lr_row(a, mn: str, op: str, lr: str, raw):
    """`_lr_write` for the row at `a`, a blanked frame-chain pop of the pair read as it
    was: it puts the return address the prologue pushed back in LR (#331)."""
    if mn == "nop" and raw is not None and a in raw:
        pmn, pop = raw[a]
        if pmn == "ldp" and lr in _def_use(pmn, pop)[0]:
            return True
    return _lr_write(mn, op, lr)


def _lr_return_address(blocks, preds, entries, raw=None) -> dict:
    """{block: whether LR holds a return address on entry to it, on every way in} (#280).

    LR holds the caller's return address at each of `entries`, where the function is
    entered, and a call inside the body leaves its own. Any other write leaves something
    else: the assembler loads a Code object into LR and calls through its entry point, a
    tagged pointer. `Assembler::BranchLink` takes `code_reg = FLAG_precompiled_mode ? LR
    : CODE_REG` in assembler_arm64.cc at every tag from 3.3.0-174.2.beta to 3.13.0
    (2.19.6 to 3.2.6 load CODE_REG), and in assembler_arm.cc at 3.12.2 and 3.13.0. A
    must-analysis, the meet the lifter's joins make: a block holds it only where every
    predecessor's exit does. A block the entries reach by no path holds it nowhere, and
    counts as a way in that does not hold it, so a join such code falls into knows
    nothing.

    One bit per block, set to start with and only ever cleared, so each block changes at
    most once and the work is linear in blocks plus edges."""
    lr = _lr()
    last = {}
    for b, blk in blocks.items():
        got = None
        for (a, mn, op, _n) in blk.insns:
            w = _lr_row(a, mn, op, lr, raw)
            if w is not None:
                got = w
        last[b] = got
    reach, stack = set(), [e for e in entries if e in blocks]
    while stack:
        n = stack.pop()
        if n not in reach:
            reach.add(n)
            stack.extend(s for s in blocks[n].succ if s in blocks)
    out = {b: True if last[b] is None else last[b] for b in blocks}

    def into(b):
        return b in reach and all(p in reach and out[p] for p in preds.get(b, ()))
    work = [b for b in blocks if last[b] is None]
    while work:
        b = work.pop()
        if out[b] and not into(b):
            out[b] = False
            work.extend(s for s in blocks[b].succ if s in blocks and last[s] is None)
    return {b: into(b) for b in blocks}


def _fp_write(a, mn: str, op: str, raw: dict, prev=None):
    """What the row at `a` leaves in FP: False for the frame pointer, which is what the
    frame chain puts there, True for anything else, None where FP keeps what it held,
    as it does where the row leaves it alone or moves it by an immediate.

    The frame chain is what strip_boilerplate blanked, read as it was (`raw`): the
    prologue's move of SP and the epilogue's pop off SP. And the pop that ends an FFI
    call's frame, `mov x15, x29; ldr x29, [x15], #8`, which is the chain only with that
    move just before it (`prev`, the row before in the block), as blutter's leave-frame
    matcher takes it (CodeAnalyzer_arm64.cpp, tryConsumeLeaveFrameRestore): without it,
    a pop off SP puts whatever was pushed in FP. All 2,550 such pops in the clean
    fixture and the seven app-sweep libraries have the move. A write-back through FP
    moves it, which `_frame_plan` follows where FP holds the frame and `_bump` where it
    does not, so it is None too. `_def_use` names arm64 registers only, so on another
    target no row writes FP."""
    blank = mn == "nop"
    if blank:
        got = raw.get(a)
        if got is None:
            return None
        mn, op = got
    sp, fp = _frame_regs()
    if fp not in _def_use(mn, op)[0]:
        return None
    ops = _split_ops(op)
    if mn in _LOADS or mn in _STORES:
        if mn in _STORES or fp not in _regs(ops[:2 if mn in ("ldp", "ldpsw") else 1]):
            return None
        got = _addr(ops)
        if got is None or got[0][0] != sp:
            return True
        if blank:
            return False
        if prev is None:
            return True
        pmn, pop = raw.get(prev[0], prev[1:3]) if prev[1] == "nop" else prev[1:3]
        pops = _split_ops(pop)
        return not (pmn == "mov" and len(pops) == 2 and canon(pops[0]) == sp
                    and canon(pops[1]) == fp)
    src = canon(ops[1]) if len(ops) >= 2 else ""
    if mn in ("mov", "add", "sub") and src == sp:
        return False
    # FP moved by an amount the row spells keeps what FP held: in its frame, where
    # `_frame_moves` and `_frame_plan` follow it (#165), and off the value a write put
    # there, where it reads as that value moved.
    if mn in ("add", "sub") and src == fp and len(ops) == 3 and _imm(ops[2]) is not None:
        return None
    return True


def _fp_lost_at(blocks, raw) -> frozenset:
    """The addresses of the rows before which FP may hold something other than the frame
    pointer: a row that is not the frame chain wrote it on some path there (#307).

    The lifter reads an access off FP as a frame slot by the register's role, so after
    `ldr x29, [x0, #8]` a read off x29 named a stack slot the machine does not touch.
    Compiled Dart writes FP only in the frame chain, so on compiled code this is empty. A
    may-analysis, the other way round from `_lr_return_address`: what no such write
    reaches keeps the role, the entry and every section no edge reaches included, so a
    function that never writes FP lifts as it did. One bit per block, set at most once,
    so the work is linear in rows plus edges."""
    effect, touched = {}, set()
    for b, blk in blocks.items():
        got = None
        for k, (a, mn, op, _n) in enumerate(blk.insns):
            # Every spelling of FP has these two characters, and a blanked row is
            # read as it was.
            if mn != "nop" and "29" not in op:
                continue
            w = _fp_write(a, mn, op, raw, blk.insns[k - 1] if k else None)
            if w is not None:
                got = w
                touched.add(b)
        effect[b] = got
    lost_in = set()
    work = [b for b in blocks if effect[b]]
    while work:
        b = work.pop()
        for t in blocks[b].succ:
            if t in blocks and t not in lost_in:
                lost_in.add(t)
                if effect[t] is None:
                    work.append(t)
    out = set()
    for b in lost_in | touched:
        cur = b in lost_in
        insns = blocks[b].insns
        for k, (a, mn, op, _n) in enumerate(insns):
            if cur:
                out.add(a)
            if mn == "nop" or "29" in op:
                w = _fp_write(a, mn, op, raw, insns[k - 1] if k else None)
                if w is not None:
                    cur = w
    return frozenset(out)


#: The pair forms, each of which reaches a second word one register's width past the
#: first. The exclusive store's first operand is its status register, not data.
_PAIR_MEM = frozenset({"ldp", "ldpsw", "stp", "ldnp", "stnp", "ldxp", "ldaxp",
                       "stxp", "stlxp"})


def _data_offsets(compressed) -> tuple:
    """The bound target's element data offsets for one pointer width, as
    `Target.data_offsets` pairs them; None is the compressed arm64 every caller without
    a target to hand has always meant."""
    tab = _T.data_offsets
    got = tab.get(True if compressed is None else bool(compressed))
    return got if got is not None else next(iter(tab.values()), (frozenset(),) * 2)


def _stub_of(note: str):
    """(kind, label) of the VM runtime stub a `bl` row's note names, or None for any
    other call. The walk's `bl` decides by it what a call leaves standing, and
    `_elem_offsets` by `_call_forgets`, which reads it, so the two cannot disagree."""
    name = note.split("-> ", 1)[1].strip() if "-> " in note else None
    return _classify_stub(name) if name and "_iso_stub_" in name else None


def _call_forgets(mn: str, note: str) -> frozenset:
    """The registers a call row leaves the walk knowing nothing about, on every path:
    the result register, which `bl` and `blr` both set, and the volatile set
    `_clobber_call` forgets, except at a stub `_classify_stub` says gives the file back,
    where it is LR alone. A type-testing stub loses more, but only some of the time."""
    stub = _stub_of(note) if mn == "bl" else None
    if stub is not None and stub[0] == "suppress":
        return frozenset({_T.ret_int, _lr()})
    return _CALL_CLOBBERS | {_T.ret_int}


#: `_addr_facts`' fact for a register that may hold a value arithmetic made.
_AF_CALC = ("c",)


def _af_plain(f) -> bool:
    """Whether fact `f` is of a value read as it is: nothing known, a thread field as
    it was loaded, or the tagged pointer to a new object."""
    return f is None or (f[0] == "t" and f[2] == 0) or (f[0] == "n" and f[1] == 1)


def _af_add(f, k):
    """Fact `f` once the constant `k` is added; a `k` of None is an amount not read."""
    if k is None or f == _AF_CALC:
        return _AF_CALC
    if f is None:
        return ("o", k) if k else None
    if f[0] == "o":
        return ("o", f[1] + k) if f[1] + k else None
    if f[0] == "t":
        return ("t", f[1], f[2] + k)
    if f[0] == "n":
        return ("n", f[1] + k)
    return f                          # ("x", field): top plus an amount not known


def _af_stale(f):
    """Fact `f` once the thread field it stands off may hold something else."""
    if f[0] == "t":
        return ("o", f[2]) if f[2] else None
    return _AF_CALC if f[0] == "x" else f


def _af_meet(a: dict, b: dict) -> dict:
    """What two ways in agree on: a fact both hold, nothing where both hold a plain
    value, and `_AF_CALC` where either may hold a computed one."""
    out = {}
    for r in a.keys() | b.keys():
        x, y = a.get(r), b.get(r)
        j = x if x == y else None if _af_plain(x) and _af_plain(y) else _AF_CALC
        if j is not None:
            out[r] = j
    return out


def _af_target() -> tuple:
    """(the thread register, the zero register, the registers `_addr_facts` keeps no
    fact for, the first letter of a full-width register, the word size): the same for
    every body of one target, so made once for it (`use_target`)."""
    got = _AF_ROW_CACHE.get(None)
    if got is None:
        zero = _T.zero or "xzr"
        got = _AF_ROW_CACHE[None] = (
            next((r for r, v in _T.roles.items() if v == _THR), None), zero,
            frozenset(r for r in _T.roles if r != _lr()) | {zero},
            "x" if _T.word == 8 else "r", _T.word)
    return got


def _af_row(mn: str, op: str, note: str):
    """What the row `mn op` does to `_addr_facts`' facts, as `(kind, ...)`, or None
    where it does nothing to them. A row's text says all of it but for a call, whose
    note names the stub, so the answer is kept by text, as `_def_use`'s is: the lift
    reads the same few thousand rows over and over, and compiling each one again for
    every body that asked was half of what the analysis cost (#346)."""
    if mn in _CALLS:
        roles = _af_target()[2]
        return ("call", tuple(r for r in _call_forgets(mn, note) if r not in roles))
    by_op = _AF_ROW_CACHE.get(mn)
    if by_op is None:
        by_op = _AF_ROW_CACHE[mn] = {}
    else:
        hit = by_op.get(op, _MISS)
        if hit is not _MISS:
            return hit
    thr, zero, roles, wch, word = _af_target()

    def full(tok):
        return tok.strip()[:1] == wch

    def row():
        ops = _split_ops(op)
        if not ops:
            return None
        if any("[" in o for o in ops):
            got = _addr(ops)
            defs = tuple(r for r in _def_use(mn, op)[0] if r not in roles)
            if got is None:
                return ("mem", defs)
            (base, disp, index, _s, wb), post = got
            delta = None if post is _BAD_POST else post if post else disp if wb else 0
            defs = tuple(d for d in defs if d != base or delta == 0)
            if mn in _LOADS or (mn[:2] == "ld" and not _ATOMIC_OP_RE.match(mn)):
                gen = ()
                if base == thr and index is None and delta == 0 and full(ops[0]):
                    if mn in ("ldr", "ldur"):
                        gen = ((canon(ops[0]), ("t", disp, 0)),)
                    elif mn == "ldp" and full(ops[1]):
                        gen = ((canon(ops[0]), ("t", disp, 0)),
                               (canon(ops[1]), ("t", disp + word, 0)))
                return ("load", base, defs, gen, delta)
            if (base == thr and index is None and delta == 0 and mn in ("str", "stur")
                    and full(ops[0])):
                return ("back", base, disp, canon(ops[0]))
            return ("store", base, defs, delta)
        defs = _def_use(mn, op)[0]
        if not defs:
            return None
        dst = canon(ops[0])
        if dst in roles:
            return ("mem", ()) if dst == thr else None
        m = _FLAG_VALUE.get(mn, mn)
        if full(ops[0]):
            src = canon(ops[1]) if len(ops) >= 2 and full(ops[1]) else None
            if src == zero:
                src = None
            if m == "mov" and len(ops) == 2 and src and _imm(ops[1]) is None:
                return ("mov", dst, src)
            if m in ("add", "sub") and len(ops) >= 3 and src:
                k = _imm(ops[2])
                if k is not None:
                    if len(ops) >= 4 and "lsl" in ops[3]:
                        k <<= (_imm(ops[3].split("lsl")[-1]) or 0)
                    role = _T.roles.get(src)
                    if m == "add" and (role == "PP" or role == _T.consts_base
                                       and k in _T.consts):
                        return ("plain", dst)         # a pool base, true or false
                    return ("addi", dst, src, k if m == "add" else -k)
                if m == "add" and _T.roles.get(canon(ops[2])) == "HEAP":
                    return ("mov", dst, src)          # the decompression
                if m == "add" and len(ops) == 3 and full(ops[2]):
                    return ("addr", dst, src, canon(ops[2]))
            if (m == "csel" and len(ops) >= 4 and src and full(ops[2])
                    and canon(ops[2]) != zero):
                return ("csel", dst, src, canon(ops[2]))
            if (m == "orr" and len(ops) == 3 and canon(ops[1]) == zero
                    and _imm(ops[2]) is None and full(ops[2]) and canon(ops[2]) != zero):
                return ("mov", dst, canon(ops[2]))
        return ("def", tuple(d for d in defs if d not in roles
                             and _reg_file(d) == "x"))

    by_op[op] = out = row()
    return out


def _addr_facts(blocks, preds, entries, raw=None) -> tuple:
    """(computed, fresh): the addresses of the rows that read a register which may hold
    a computed address, and of the adds and subs that make a new object's pointer (#329).

    `computed` has a load or a store whose BASE, and an `add` or `sub` of an immediate
    whose SOURCE, may on some path hold a value an arithmetic row made. The walk's own
    record (`V.calc`) follows a value it tracks; a register it has lost, at a join, a
    loop header or a label, reads as its bare name or as the name the join gave it,
    and this says what every way in left there. A may-analysis over the rows: a load
    and a call's result are plain, a move copies, the decompression `add xD, xN, HEAP,
    lsl #32` and a `csel` of two plain values are plain, an immediate added and taken
    off again is plain, and every other write of a general register is computed.

    `fresh` is the inline allocation, which is arithmetic and makes an object pointer.
    `Assembler::TryAllocateObject` and `TryAllocateArray` (assembler_arm64.cc) and the
    allocation stubs (stub_code_compiler_arm64.cc: AllocateArray, AllocateContext,
    AllocateObject, the typed-data and suspend-state ones) all do

        ldr  xS, [THR, #top]        or  ldp xS, xEnd, [THR, #top]
        add  xE, xS, #size          or  add xE, xS, xSize, either operand order
        ...                         the comparison with end, and the branch away
        str  xE, [THR, #top]
        add  xD, xS, #1             or  sub xD, xE, #(size - 1)

    so a value loaded from a thread field, bumped and stored back to the same field
    has reserved the bytes between, and the loaded value plus the heap-object tag is
    the pointer to the object being made there. Read off the rows, with no table of
    thread offsets: the field is whichever one the store goes back to. A must-analysis
    in the same pass: the add is fresh only where every way into it loaded, bumped and
    stored, with no call and no other store between the load and the store back, which
    could have moved the field; a store back of anything else, a register written on
    the way, or one path that did not, and it is arithmetic like any other.

    One fact per register and block, raised at most twice (a fact, then plain, then
    computed), so a block is taken again a bounded number of times and the work is
    linear in rows plus edges."""
    thr, _zero, roles, _wch, word = _af_target()

    def compiled(a, mn, op, note):
        if mn == "nop" and raw is not None and a in raw:
            (mn, op), note = raw[a], ""           # a blanked row, as the CPU runs it
        row = _af_row(mn, op, note)
        return None if row is None else (a, *row)

    def put(f, r, v):
        if v is None:
            f.pop(r, None)
        else:
            f[r] = v

    def stale(f, keep=None):
        for r, v in list(f.items()):
            if v[0] in "tx" and not (keep is not None and abs(v[1] - keep) >= word):
                put(f, r, _af_stale(v))

    def step(f, row):
        kind = row[1]
        if kind == "mov":
            put(f, row[2], f.get(row[3]))
        elif kind == "addi":
            put(f, row[2], _af_add(f.get(row[3]), row[4]))
        elif kind == "def":
            for d in row[2]:
                f[d] = _AF_CALC
        elif kind == "load":
            for d in row[3]:
                f.pop(d, None)
            for r, fact in row[4]:
                f[r] = fact
            if row[5] != 0:
                bump(f, row[2], row[5])
        elif kind == "back":
            # The store back. Everything read off the field's old value is now an
            # offset into the bytes reserved; off one of unknown size it is unknown.
            field, got = row[3], f.get(row[4])
            if got is not None and got[1:2] == (field,) and (
                    got[0] == "x" or got[0] == "t" and got[2] > 0):
                for r, v in list(f.items()):
                    if v[0] in "tx" and v[1] == field:
                        f[r] = ("n", v[2]) if v[0] == "t" else _AF_CALC
                stale(f, field)
            else:
                stale(f)
        elif kind == "store":
            stale(f)
            for d in row[3]:
                f.pop(d, None)
            if row[4] != 0:
                bump(f, row[2], row[4])
        elif kind == "call":
            # It may allocate, and move what was reserved before it.
            for r, v in list(f.items()):
                if v[0] == "n" and v[1] != 1:
                    f[r] = _AF_CALC
            stale(f)
            for d in row[2]:
                f.pop(d, None)
        elif kind == "mem":
            stale(f)
            for d in row[2]:
                f.pop(d, None)
        elif kind == "plain":
            f.pop(row[2], None)
        elif kind == "addr":
            x, y = f.get(row[3]), f.get(row[4])
            tx, ty = x is not None and x[0] == "t", y is not None and y[0] == "t"
            f[row[2]] = ("x", (x if tx else y)[1]) if tx != ty else _AF_CALC
        elif kind == "csel":
            put(f, row[2], None if _af_plain(f.get(row[3])) and _af_plain(f.get(row[4]))
                else _AF_CALC)

    def bump(f, base, delta):
        if base == thr:
            stale(f)
        elif base not in roles:
            put(f, base, _af_add(f.get(base), delta))

    def checked(blk):
        # (registers, successor) of a Smi check: `tbz xN, #0` falls through, and `tbnz`
        # branches, only where bit 0 of xN is set. The compiler tests the tag bit of
        # a Dart value and of nothing else, so what a join left as possibly computed
        # is on that edge the object the value is boxed in: `sbfiz x0, x1, #1, #31`
        # on one arm and AllocateMint's result on the other, then `tbz w0, #0` and the
        # class id out of `[x0, #-1]`. A constant offset is still one (`_af_add`).
        # `and w16, w5, w0; tbz w16, #0` tests two values at once, the Mint arm of an
        # integer equality: the bit is set in the AND only where it is set in both.
        if not blk.insns or blk.insns[-1][1] not in ("tbz", "tbnz"):
            return None
        ops = _split_ops(blk.insns[-1][2])
        if len(ops) != 3 or _imm(ops[1]) != 0 or len(set(blk.succ)) != 2:
            return None
        target = _imm(ops[2])
        if target not in blk.succ:
            return None
        hit = target if blk.insns[-1][1] == "tbnz" else next(
            s for s in blk.succ if s != target)
        regs = (canon(ops[0]),)
        if len(blk.insns) >= 2 and blk.insns[-2][1] == "and":
            both = _split_ops(blk.insns[-2][2])
            if (len(both) == 3 and canon(both[0]) == regs[0]
                    and _imm(both[1]) is None and _imm(both[2]) is None):
                regs += tuple(r for r in map(canon, both[1:]) if r != regs[0])
        return regs, hit

    rows = {b: [r for r in (compiled(*t) for t in blk.insns) if r is not None]
            for b, blk in blocks.items()}
    checks = {b: c for b, blk in blocks.items() if (c := checked(blk)) is not None}
    # Reverse postorder from the entries, then from every block nothing leads into,
    # then from whatever is left, a cycle no entry reaches: each starts knowing
    # nothing, which is what a section no edge leads into is entered with.
    order, seen, starts = [], set(), []
    for root in ([e for e in entries if e in blocks]
                 + [b for b in blocks if not preds.get(b)] + list(blocks)):
        if root in seen:
            continue
        seen.add(root)
        starts.append(root)
        stack = [(root, iter(blocks[root].succ))]
        while stack:
            b, it = stack[-1]
            t = next((t for t in it if t in blocks and t not in seen), None)
            if t is None:
                order.append(b)
                stack.pop()
            else:
                seen.add(t)
                stack.append((t, iter(blocks[t].succ)))
    order.reverse()
    rank = {b: i for i, b in enumerate(order)}
    inn = {b: {} for b in starts}
    heap = sorted(rank[b] for b in inn)
    queued = set(heap)
    while heap:
        i = heapq.heappop(heap)
        queued.discard(i)
        b = order[i]
        f = dict(inn[b])
        for row in rows[b]:
            step(f, row)
        check = checks.get(b)
        for s in blocks[b].succ:
            if s not in blocks:
                continue
            out = f
            if check is not None and check[1] == s and any(
                    f.get(r) == _AF_CALC for r in check[0]):
                out = {r: v for r, v in f.items()
                       if v != _AF_CALC or r not in check[0]}
            old = inn.get(s)
            new = out if old is None else _af_meet(old, out)
            if old is not None and new == old:
                continue
            inn[s] = new
            if rank[s] not in queued:
                queued.add(rank[s])
                heapq.heappush(heap, rank[s])
    computed, fresh = set(), set()
    for b in blocks:
        f = dict(inn.get(b, ()))
        for row in rows[b]:
            kind = row[1]
            if kind in ("load", "store", "back"):
                if not _af_plain(f.get(row[2])):
                    computed.add(row[0])
            elif kind == "addi" and not _af_plain(f.get(row[3])):
                computed.add(row[0])
            step(f, row)
            if kind == "addi" and f.get(row[2]) == ("n", 1):
                fresh.add(row[0])
    return frozenset(computed), frozenset(fresh)


def _elem_offsets(blocks, data) -> dict:
    """{address of each `add xD, xB, xI{, shift}`: the members of `data` that some access
    off xD that the add can reach is made at} (#308).

    `data` holds the displacements at which an indexed access reaches its element, one
    per class (`Target.data_offsets`). Which class xB holds is not known, so the offset
    is read from the accesses: where they reach exactly one member of `data`, that one is
    the element's and the rest are whole strides on from it or are not elements; where
    they reach none, or two, no access off xD is an element. The compiler computes an
    element address for each indexed access it emits: scanning each block of the nine
    arm64 binaries, 7 of the 65,836 it reads through are read at two displacements.

    A backward may-analysis over the CFG: an access counts for every add whose value can
    reach it along a path that does not write xD, and a write is one the walk forgets
    the entry at too, a call's being `_call_forgets`, so the set never misses an access
    the entry can reach. Each block's map only ever grows, by a member of `data` for a
    register some such add writes, and blocks are taken successors first, in postorder,
    so a pass over them carries every fact it can and the work is linear in rows times
    that bound."""
    if not data:
        return {}
    rows, regs = {}, set()
    for b, blk in blocks.items():
        out = []
        for (a, mn, op, note) in blk.insns:
            ops = _split_ops(op)
            edef = None
            if (mn in ("add", "adds") and len(ops) >= 3 and _imm(ops[2]) is None
                    and _T.roles.get(canon(ops[2])) != "HEAP"):
                edef = canon(ops[0])
                regs.add(edef)
            gen = ()
            if any("[" in o for o in ops):
                got = _addr(ops)
                if got is not None:
                    (base, disp, index, _s, _wb), post = got
                    if index is None:
                        d = 0 if post else disp
                        gen = [d]
                        if mn in _PAIR_MEM and len(ops) >= 3:
                            reg = ops[1] if mn in ("stxp", "stlxp") else ops[0]
                            gen.append(d + _access_width(mn, reg))
                        gen = (base, tuple(x for x in gen if x in data))
            defs = (_call_forgets(mn, note) if mn in ("bl", "blr", "blx")
                    else _def_use(mn, op)[0])
            out.append((a, edef, defs, gen))
        rows[b] = out

    def through(b, live):
        """`live` at the end of block `b` carried to its start, recording each add's set
        into `seen` where that is asked for."""
        live = dict(live)
        for (a, edef, defs, gen) in reversed(rows[b]):
            if edef is not None and seen is not None:
                seen[a] = frozenset(live.get(edef, ()))
            for r in defs:
                live.pop(r, None)
            if gen and gen[0] in regs and gen[1]:
                live[gen[0]] = live.get(gen[0], frozenset()) | frozenset(gen[1])
        return live

    seen = None
    preds = {b: [] for b in blocks}
    for b, blk in blocks.items():
        for t in blk.succ:
            if t in preds:
                preds[t].append(b)
    # Postorder over the whole graph, every block a root in address order, iteratively.
    # A LIFO worklist took a chain laid out from high addresses to low against its flow
    # once per fact: 6,028 rows, 1.69 s of CPU where the lift took 0.12 s before this.
    rank, done = {}, set()
    for root in blocks:
        if root in done:
            continue
        done.add(root)
        stack = [(root, iter(blocks[root].succ))]
        while stack:
            b, it = stack[-1]
            t = next((t for t in it if t in blocks and t not in done), None)
            if t is None:
                rank[b] = len(rank)
                stack.pop()
            else:
                done.add(t)
                stack.append((t, iter(blocks[t].succ)))
    live_in = {b: {} for b in blocks}
    work = [(rank[b], b) for b in blocks]
    heapq.heapify(work)
    queued = set(blocks)
    while work:
        _r, b = heapq.heappop(work)
        queued.discard(b)
        out = {}
        for t in blocks[b].succ:
            for r, v in live_in.get(t, {}).items():
                out[r] = out.get(r, frozenset()) | v
        got = through(b, out)
        if got != live_in[b]:
            live_in[b] = got
            for p in preds[b]:
                if p not in queued:
                    queued.add(p)
                    heapq.heappush(work, (rank[p], p))
    seen = {}
    for b in blocks:
        out = {}
        for t in blocks[b].succ:
            for r, v in live_in.get(t, {}).items():
                out[r] = out.get(r, frozenset()) | v
        through(b, out)
    return seen


#: The slot-map key that says a push dropped part of the outgoing area; see
#: Lifter._frame_moved. It starts with SP's name, so whatever forgets the area forgets it.
_LOST = "x15?"
#: What the slot 8 bytes into a q register's 16 holds: its top half, no value the walk
#: can name (#162).
_UPPER = V("", P_ATOM)


def _drop_outgoing(st: State):
    """Forget the outgoing-argument area. A call consumes it, and leaving the slots behind
    would let one call's arguments be read back as the next call's."""
    sp = next((r for r, v in _T.roles.items() if v == "SP"), "x15")
    for key in [k for k in st.slot if k.startswith(sp)]:
        st.forget_slot(key)


def _forget_frame(st: State):
    """Forget every slot, for a store that may have written any of them. Where the
    outgoing area held a value, it is marked short, so no call takes what is pushed after
    for its whole argument list (_stack_args)."""
    sp = next((r for r, v in _T.roles.items() if v == "SP"), "x15")
    lost = any(k.startswith(sp) for k in st.slot)
    st.slot.clear()
    st.dropped.clear()          # the frame is not trustworthy, so neither is a record
    if lost:
        st.slot[_LOST] = V("", P_ATOM)


def _joined(a: V, b: V):
    """The value two paths agree a register holds, or None where they do not. A value
    held Smi-tagged on one path and not on the other is still the value, which is what a
    store, a call or a return reads, so the paths agree on it without the record: an
    untag past the join cannot tell which word it reads (`V.smi`, #290)."""
    if a == b:
        # One value by two paths, and what each knew of it: computed on either is
        # computed, and the constant it stands off its base by holds where both have
        # the same one (`V.calc`, #329).
        if a.calc == b.calc and a.at == b.at:
            return a
        return replace(a, calc=a.calc or b.calc, at=a.at if a.at == b.at else None)
    if a.smi != b.smi and replace(a, smi=0) == replace(b, smi=0):
        # Where one of them holds the tagged word, the register holds arithmetic.
        return replace(a, smi=0, at=None,
                       calc=a.calc or b.calc or _SMI_TAG in (a.smi, b.smi))
    return None


def _merge(dst: State, a: State, b: State):
    """Post-if state: keep registers/slots the two arms agree on, else drop to symbolic.
    A register the arms disagree about is LOST: its bare name reads like the entry value
    and like a raw line's result, so a slot that holds it is tied to it and dropped once
    it is reassigned, when that name means something else (#140, State.lost).

    Dropping a register has to be RECORDED, not just omitted. An omitted register falls
    back to the receiver alias in _leaf, so an instance method whose then-arm overwrote x1
    printed `this` for it after the join, on a path where x1 is provably not this. The
    disagreement is a fact about the register and the map has to hold it."""
    agreed = {r: j for r in a.reg if r in b.reg
              and (j := _joined(a.reg[r], b.reg[r])) is not None}
    # sorted, because this INSERTS into the map that `_pin` later walks in insertion order
    # to hand out temporary names. A set of strings iterates in an order that depends on
    # Python's per-process hash seed, so leaving it unsorted made two runs over the same
    # binary give the same two values the names `t10` and `t11` the other way round,
    # roughly one run in five differed. The same lesson is recorded at the loop header; it
    # applies to every write into `reg`, not only that one.
    dropped = set()
    for r in sorted(a.reg.keys() | b.reg.keys()):
        if r not in agreed:
            agreed[r] = V(r, P_ATOM)
            dropped.add(r)
    dst.reg = agreed
    dst.slot = {k: j for k in a.slot if k in b.slot
                and (j := _joined(a.slot[k], b.slot[k])) is not None}
    # ...and the same rule for the records, with the freshness ANDed: a record only one
    # path justifies would be spelled on the path that never made it, and one arm having
    # written memory makes it unfresh for both (#199).
    dst.dropped = {k: (va, fa and b.dropped[k][1])
                   for k, (va, fa) in a.dropped.items()
                   if k in b.dropped and b.dropped[k][0] == va and k not in dst.slot}
    # A slot's lost tie survives only where both arms agree on it and the register is not
    # itself dropped. A slot either arm held as a lost value whose tie does not survive is
    # unstable on that path, so it goes rather than lingering untied (#140).
    dst.lost_slot = {k: r for k, r in a.lost_slot.items()
                     if k in dst.slot and b.lost_slot.get(k) == r and r not in dropped}
    for k in [k for k in dst.slot
              if (k in a.lost_slot or k in b.lost_slot) and k not in dst.lost_slot]:
        dst.slot.pop(k, None)
    dst.reindex_slots()         # the agreed slots are a fresh map (#173)
    dst.elem = {r: a.elem[r] for r in a.elem if b.elem.get(r) == a.elem[r]}
    # Which register the function last wrote a RESULT to is a fact about the arms, exactly
    # as the register map is, and it decided the wrong thing when it was left behind: a
    # function that computes its double in both arms of an `if` and returns at the join
    # wrote d0 twice and printed `return x0;`, naming a register nothing ever set.
    # `_render_loop` already takes the body's answer; this is the same rule for the join.
    if a.result == b.result:
        dst.result = a.result
    dst.lost = dropped | (a.lost & b.lost)
    dst.opaque = a.opaque | b.opaque


# ── boilerplate stripping (frame + thread stack-overflow check) ─────────────

#: Every pattern strip_boilerplate recognises starts with one of these. Anything else
#: cannot open any of them, so the operand parsing is skipped for it entirely.
_BOILER_MNEMONICS = frozenset({"stp", "ldp", "mov", "add", "sub", "ldr", "ldur",
                               "tst", "sbfiz", "push", "pop"})


def _regs_in_list(op: str) -> list:
    """The registers of an arm32 `{r4, fp, lr}` register list, canonicalised."""
    return [canon(t) for t in op.strip().strip("{}").split(",") if t.strip()]


def strip_boilerplate(ann: list, slow: set = None) -> list:
    """Nop out the compiler-emitted prologue/epilogue and the stack-overflow check.
    They become nops rather than being dropped, so addresses stay stable and branch
    targets still resolve. The stack check's slow-path block is then unreachable and
    structure() skips it. `slow`, where given, gets the address of each such slow path:
    one laid out after a throw still looks reached from it (#157)."""
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
        # frame chain: an stp/ldp of the FP/LR pair off SP, or SP<->FP moves / SP frame
        # adjust. Off another base the pair stores FP and LR to an object or loads both
        # from one, and dropping it hid that write (#294). Nor is FP taken as a base:
        # every such pair on both fixtures and FluffyChat is off x15, the push
        # pre-indexed and the pop post-indexed.
        if (mn in ("stp", "ldp") and len(ops) >= 3
                and {canon(ops[0]), canon(ops[1])} == {"x29", "x30"}
                and (m := _mem(ops[2])) and _T.roles.get(m[0]) == "SP"):
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
                if slow is not None:
                    slow.add(_target(br[2]))
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

#: A flag-setting ALU op, and the plain twin that computes the same VALUE.
#:
#: The flags and the value are two definitions of one instruction, and only the flags
#: were modelled here, so `subs x0, x1, x2` printed as arm64 where `sub x0, x1, x2`
#: prints `x1 - x2`, and the register it wrote read as nothing: 262 raw lines on the
#: clean fixture, the only difference being the flag suffix (#239). Every other tool
#: splits the two. Ghidra translates one instruction to a sequence of p-code operations
#: each of which writes at most one varnode, so the register result is its own operation
#: and the flag bits are theirs. Binary Ninja lifts the value as the ordinary definition
#: and emits the flag IL beside it, only where a consumer reads it. LLVM's AArch64
#: `SUBSWrr` writes its GPR and carries `implicit-def $nzcv`, and the selector emits
#: `$wzr = SUBSWrr` where the value is unused, which is what `cmp` is.
#:
#: So the value is taken from the twin and the flags stay with `_note_flags`. `State.set`
#: drops a write to xzr, which is that same `cmp` form written out, so it needs no case
#: of its own here.
_FLAG_VALUE = {"subs": "sub", "adds": "add", "ands": "and", "bics": "bic",
               "negs": "neg"}

#: Conditional select and its aliases -> how many operands sit between the destination
#: and the condition code. Each is an exact expression, not an approximation: the
#: architecture defines them as "d = cond ? a : f(b)" with f the identity, +1, ~ or -.
_CSEL = {"csel": 2, "csinc": 2, "csinv": 2, "csneg": 2,
         "cinc": 1, "cinv": 1, "cneg": 1, "cset": 0, "csetm": 0}


def _flags_read(insns) -> frozenset:
    """The addresses of the flag-setting instructions in one block whose flags are read
    before anything replaces them: by a conditional select, or by the branch that ends
    the block. Only those need the old value of a register they overwrite named (#116);
    the rest would print a declaration nothing reads."""
    out, live = set(), None
    for a, mn, op, _note in insns:
        if live and (mn in _CSEL or cond_of(mn)):
            out.add(live[0])
        if mn in _FLAG_SRC:
            live = (a, _regs(_split_ops(op)))
        elif mn in _FLAG_KILL or (live and _def_use(mn, op)[0] & live[1]):
            live = None
    return frozenset(out)


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
#:
#: x16 and x17 too. They are not in that list because Dart never allocates them, they are
#: TMP and TMP2, and a stub or a veneer between the call and its target may use them: a
#: value set in x17 before a call printed as still there after it (#137).
#:
#: And x30, LR, which the call itself writes with its own return address. Kept, it read
#: `LR` after a call as before it, two values under one name in one loop (#162).
_A64_CLOBBERS = frozenset({f"x{i}" for i in range(15)} | {"x16", "x17", "x30"}
                          | {f"d{i}" for i in range(31)})
_CALL_CLOBBERS = _A64_CLOBBERS
#: What a type-testing stub does not hand back: every volatile general register but the
#: four TypeTestABI::kPreservedAbiRegisters names (constants_arm64.h, 3.12.2). Wider than
#: kNonPreservedAbiRegisters on purpose, which lists the registers one release's stubs
#: happen to use; the four it keeps are the claim.
_TTS_LOSES = frozenset(r for r in _A64_CLOBBERS
                       if r[0] == "x" and r not in ("x0", "x1", "x2", "x8", "x30"))


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
    if mn in ("br", "bx"):
        return _NO_REGS, _regs(ops[:1])            # the target is read (#118)
    if mn in ("bl", "b") or cond_of(mn):
        return (_CALL_CLOBBERS if mn == "bl" else _NO_REGS), _NO_REGS
    if mn == "nop":
        return _NO_REGS, _NO_REGS
    if any(o.lstrip().startswith("[") for o in ops):
        # The other memory instructions, by the registers they write (#118). An atomic
        # load-op or swap writes its second register, the old memory value, and a
        # compare-and-swap its first; a store-release, an atomic store or a prefetch
        # none; an exclusive or non-temporal pair load two. Every one also writes a
        # base it moves, `st1 {v0.16b}, [x1], x2` included.
        at = next(i for i, o in enumerate(ops) if o.lstrip().startswith("["))
        wb = (_writeback_base(ops),)
        if _ATOMIC_OP_RE.match(mn):
            return _regs(ops[1:2] + wb), _regs(ops[:1] + ops[at:])
        if _CAS_RE.match(mn):
            n = 2 if mn.startswith("casp") else 1
            return _regs(ops[:n] + wb), _regs(ops)
        if _NO_DEF_RE.match(mn):
            return _regs(wb), _regs(ops)
        n = 2 if mn in ("ldxp", "ldaxp", "ldnp") else 1
        if ops[0].lstrip().startswith("{"):
            # A register list loads every register in it: `ld1 {v0.16b, v1.16b}` writes
            # d1 too, and a store of d1 after it printed what d1 held before (#134). A
            # lane of each, `ld2 {v4.s, v5.s}[1]`, keeps the rest, and so reads it.
            n = next((i for i, o in enumerate(ops) if "}" in o), 0) + 1
            if "[" in ops[n - 1]:
                return _regs(ops[:n] + wb), _regs(ops)
        return _regs(ops[:min(n, at)] + wb), _regs(ops[n:])
    defs, uses = _regs(ops[:1]), _regs(ops[1:])     # alu / mov: dst, srcs
    # movk, bfi, a lane insert: the rest is kept, and so read (#125). An insert into the
    # low doubleword overwrites the whole of dN; what it keeps is the other lane.
    lane = "[" in ops[0]                  # `mov v0.s[1], w1`: capstone's lane insert
    low = lane and ops[0].replace(" ", "").endswith(".d[0]")
    if (mn in _KEEPS_DST or (mn == "mov" and lane)) and not low:
        uses = uses | defs
    return defs, uses


_ATOMIC_OP_RE = re.compile(r"(ld(add|clr|eor|set|smax|smin|umax|umin)|swp)"
                           r"(a|al|l)?[bh]?$")
_CAS_RE = re.compile(r"casp?(a|al|l)?[bh]?$")
_NO_DEF_RE = re.compile(r"(stl(l)?u?r[bh]?|st(add|clr|eor|set|smax|smin|umax|umin)l?[bh]?"
                        r"|st[1-4]|stnp|prfu?m)$")


#: Canonical register name <-> bit position. Liveness is a separate question per
#: register with no interaction between them, so the dataflow below runs bit-parallel:
#: one int per block instead of a set of strings, and union / difference / equality
#: become single machine instructions instead of hash-table walks. The register file is
#: 62 names, so every mask fits in one CPython digit-pair.
_REG_BIT: dict = {}
_BIT_REG: list = []


def _reg_mask(regs) -> int:
    """These registers as a bitmask, under the LIVENESS identity.

    Every liveness set is built by `_regs`, which calls d0, s0, v0, q0, h0, b0 and v0.16b
    all `d0`: they are one machine register and a write under any spelling reaches the
    others. The STATE is keyed by `canon` instead, which keeps those spellings apart on
    purpose, so a value written under one is not read back under another (#114,
    `_other_views`).

    The two are therefore different names for one register, and a caller holding a state
    key asks about liveness with the wrong one. The lookup cannot say so: an unknown name
    MINTS a bit, and no liveness set holds it, so the answer is a confident "not live".
    That is how 1,169 frame reloads off FP came to be passed over, every one of them read
    again (#198 review). Mapping here, with the identity the sets were built with, makes
    every caller right rather than leaving fifteen of them to remember which name to use.
    """
    m = 0
    for r in regs:
        # What `_regs` does, in the same order: `canon` first, which already folds w into
        # x and s into d, then the view spellings `canon` keeps apart on purpose.
        r = canon(r)
        n = _fp_n(r)
        if n is not None:
            r = "d" + n
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


def _live_in_header(blocks, nodes, header, preds, reads=None):
    """Registers live on entry to `header` considering only edges inside `nodes`
    (iterative backward dataflow). These are the loop's read-before-write registers.
    `reads` adds what each call prints as its arguments (Lifter._call_reads): a value a
    loop passes to a call on the next trip is carried as much as one it adds to (#142)."""
    use, dfn = {}, {}
    for b in nodes:
        u = d = 0
        more = reads.get(b, {}) if reads else {}
        for i, (_a, mn, o, _n) in enumerate(blocks[b].insns):
            de, us = _def_use_masks(mn, o)
            u |= (us | more.get(i, 0)) & ~d
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


# ── which register a `ret` hands back (#115) ────────────────────────────────

#: R0 under both widths, and V0 under every name capstone gives it: d0, s0, h0, b0, q0,
#: v0.16b, v0.d[1]. Dart returns references and integers in R0 and an unboxed double in
#: V0 (constants_arm64.h kReturnReg, kReturnFpuReg), so these are all a `ret` can mean.
_RX0 = re.compile(r"(?<![\w.#])[xw]0(?!\w)")
_RD0 = re.compile(r"(?<![\w.#])[vqdshb]0(?!\w)")
_RX0_OR_D0 = re.compile(r"(?<![\w.#])[xwvqdshb]0(?!\w)")
#: Writes that keep part of what the destination held, and so read it too.
_KEEPS_DST = frozenset({"movk", "ins", "fmla", "fmls", "mla", "mls", "bfi", "bfxil",
                        "bfm", "sli", "sri", "tbx"})
#: Atomics whose FIRST operand is the value sent and whose second is the one loaded.
_RMW = ("ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin", "swp")
_RX0_SET, _RD0_SET = frozenset({"x0"}), frozenset({"d0"})
_RV_BOTH = _RX0_SET | _RD0_SET
_RV_CACHE: dict = {}


def _rv(tokens) -> frozenset:
    x = any(_RX0.search(t) for t in tokens)
    d = any(_RD0.search(t) for t in tokens)
    return _RV_BOTH if x and d else _RX0_SET if x else _RD0_SET if d else _NO_REGS


def _rv_def_use(mn: str, op: str) -> tuple:
    """(defs, uses) of x0 and d0 alone, for one instruction, any spelling of V0 being d0.

    Separate from _def_use because the question is narrower and has to be answered
    exactly: _def_use sees no `v0.16b`, and `mov v0.16b, v2.16b` is how a double reaches
    the return register at a join. A call reads only the register it goes through, and
    what it writes is the caller's business, as a `ret` is."""
    key = (mn, op)
    hit = _RV_CACHE.get(key)
    if hit is None:
        if len(_RV_CACHE) >= _SPLIT_CACHE_MAX:
            _RV_CACHE.clear()
        hit = _RV_CACHE[key] = _rv_def_use_uncached(mn, op)
    return hit


def _rv_def_use_uncached(mn: str, op: str) -> tuple:
    if not _RX0_OR_D0.search(op):
        return _NO_REGS, _NO_REGS
    ops = _split_ops(op)
    if mn.startswith(("ld", "st", "swp")):
        wb = _rv((_writeback_base(ops),))                # `[x0], #8` moves x0 itself
        if mn in ("stxr", "stlxr", "stxp", "stlxp"):    # the status register is written
            return _rv(ops[:1]) | wb, _rv(ops[1:])
        if mn.startswith(_RMW):
            return _rv(ops[1:2]) | wb, _rv(ops[:1] + ops[2:])
        if mn.startswith("st"):
            return wb, _rv(ops)
        mem = next((k for k, t in enumerate(ops) if t.startswith("[")), len(ops))
        uses = _rv(ops[mem:])
        if any("[" in t for t in ops[:mem]):            # one lane: the rest is kept
            uses |= _rv(ops[:mem])
        return _rv(ops[:mem]) | wb, uses
    if mn in _CMP or mn in ("ccmp", "ccmn", "fccmp", "fccmpe", "br", "blr", "blx"):
        return _NO_REGS, _rv(ops)
    if mn in _CONDB:
        return _NO_REGS, _rv(ops[:1])
    if mn == "eor" and len(ops) == 3 and ops[1] == ops[2]:
        return _rv(ops[:1]), _NO_REGS                   # the zero idiom reads nothing
    defs, uses = _rv(ops[:1]), _rv(ops[1:])
    if mn in _KEEPS_DST or mn.startswith("cas") or "[" in ops[0]:
        uses |= defs
    return defs, uses


def _rv_pop(mn: str, op: str) -> bool:
    """A load that pops the Dart stack: `ldr q0, [x15], #0x10`. A slow path saves the
    live registers around its call and restores them after, so what this writes is what
    the register held before the save, not a value the function just made."""
    ops = _split_ops(op)
    return mn.startswith("ld") and len(ops) >= 3 and ops[-2] == "[x15]"


def _rv_push(mn: str, op: str) -> bool:
    """A store that pushes a whole V register on the Dart stack, `str q0, [x15,
    #-0x10]!`: the save that a slow path's _rv_pop restores. It keeps the register; it
    does not use it. A push of an x or d register, `stp x0, x16, [x15, #-0x10]!`, is a
    call's argument, and reads it."""
    ops = _split_ops(op)
    return (mn.startswith("st") and len(ops) >= 2 and ops[0].startswith("q")
            and ops[-1].endswith("]!") and ops[-1].replace(" ", "").startswith("[x15,"))


def _rv_call(mn: str, note: str):
    """False for what is not a call, None for a stub that gives every register back,
    True for any other call.

    The stubs that hand a value back in x0 (_returns_x0) are not in that middle case: to
    the question of which register a `ret` hands back they are calls, and a write to d0
    before one is not the last write a `ret` after it sees (#127). `_phi` asks the same
    question of an arm, and there one of them writes what a call does where it wrote x0
    alone, which can move a name's assignment into the arm."""
    if mn not in ("bl", "blr", "blx"):
        return False
    name = note.split("-> ", 1)[1].strip() if "-> " in note else ""
    if "_iso_stub_" in name and _classify_stub(name)[0] == "suppress":
        return None
    return True


def returns_in_d0(ann) -> bool:
    """Whether the function `ann` hands back a double in d0 on every `ret`, by its own
    code (_return_registers without callers' evidence). For dispatch.recover_selectors."""
    with use_target(ARM64):
        # Honour traps so a `ret` only a trap's false fall-through reaches is not
        # counted as a return (#178), as the lift and entry_arity do, and a call that
        # cannot return for the same reason (#234).
        stripped = strip_boilerplate(ann)
        blocks, entry = build_cfg(stripped, traps=TRAPS, ends=_path_ends(stripped))
        if not blocks:
            return False
        got = _return_registers(blocks, entry)
    return bool(got) and set(got.values()) == {"d0"}


def _return_registers(blocks, entry, evidence=None, named=None, table=None) -> dict:
    """{ret address: "x0" or "d0"}, the register each `ret` hands back, or {} for a
    function that never writes d0, where nothing below applies and `State.result` stands,
    unless a `ret` no call or write to x0 comes before hands back its argument
    (_argument_returns). That `ret` returns d0 where its callers read d0, or, where no
    caller speaks, the other implementations of its selector hand back d0 (`table()`,
    make_return_resolver's by_table): `_Linear.transformInternal` is only called through
    the dispatch table.

    `ret` used to print whichever of x0 and d0 the path wrote LAST. A function that
    allocates an object and fills its double fields writes x0 (the allocation) and then
    d0 (each field value on its way into the object), so it printed its last field value
    as what it returns. Which of the two was written last says nothing about which comes
    back.

    The snapshot cannot settle it: whether a function returns an unboxed double is
    `Function::has_unboxed_double_return`, read off `unboxed_parameters_info_`, and that
    field is compiled out of the AOT runtime and never serialized. raw_object.h keeps it
    under `!defined(DART_PRECOMPILED_RUNTIME)` and the Function cluster writes only
    `kind_tag_` for kFullAOT, whose bits are kind, recognizer and modifiers, on all 19
    registered releases, 2.19.0-444.2.beta to 3.13.0. So the answer comes from the code,
    and d0 needs proof:

      * the callers. `evidence()` says which of x0 and d0 the code after a `bl` to this
        function reads; see make_return_resolver. That is the ABI as the compiler used
        it, and when it speaks it decides.
      * a path to a `ret` on which this function never writes x0 and does write d0.
        x0 still holds what it held on entry there, and no Dart function returns that.
      * a write to d0 that reaches a `ret` and that nothing else reads. The optimizing
        compiler does not emit a write nothing reads, so the `ret` is its reader. A slow
        path's restore (_rv_pop) is the exception, and does not count.

    Without any of those, x0 when what d0 holds at a `ret` was only ever stored, a value
    on its way into memory. When something else reads it too (a double summed in a loop
    that leaves x0 as scratch), nothing here says which register comes back, and the
    `ret` keeps what `State.result` says: changing it would be a guess as well.

    The lifter names a call's result in x0, so a `ret` returning d0 whose last write on
    every path was a call prints x0: both registers hold that result. Where only SOME
    paths reach it from a call, the `ret` returns d0 where each such call is one the
    lifter names the double of (`named`, _d0_callee): `getOffsetX` returns its own sum
    on one path and `_rightOffsetX`'s result on the other (#127). Through a register or
    a stub, the lifter's d0 after the call reads as the d0 the function was handed, and
    a join would print that as what the call's path returns, so it is left to
    `State.result`."""
    facts = _return_facts(blocks, entry)
    if facts is None:
        # It never writes d0 itself, so where d0 comes back, a `ret` no call or write to
        # x0 can come before hands back the d0 it was given (#127).
        if _T is not ARM64 or evidence is None:
            return {}
        out = _argument_returns(blocks, entry)
        if not out:
            return {}
        said = evidence()
        if said is None and table is not None:
            said = table()
        return out if said == "d0" else {}
    at_ret, proven, read, calls = facts
    said = evidence() if evidence is not None else None
    reg = said or ("d0" if proven else None if read else "x0")
    if reg is None:
        return {}
    out = {}
    for a, (_xw, _down, dcall, last_call, made) in at_ret.items():
        if reg == "x0" or last_call:
            out[a] = "x0"
        elif not dcall or named and all(named(*calls[c]) for c in made):
            out[a] = "d0"
    return out


def _argument_returns(blocks, entry) -> dict:
    """{ret address: "d0"} for each `ret` that neither a call nor a write to x0 can come
    before on a path from `entry`, in a function that never writes d0: what it holds
    there is its argument. A stub that gives every register back is not a call. Code the
    decoded graph does not hold could be either, so a function cut short gets none."""
    if any(b.past_cut or b.cut_next >= 0 for b in blocks.values()):
        return {}

    def spends(mn, op, note):
        return bool(_rv_call(mn, note)) or "x0" in _rv_def_use(mn, op)[0]
    spent = {entry: False}                 # block -> whether one may come before it
    work = [entry]
    while work:
        b = work.pop()
        state = spent[b] or any(spends(mn, op, note) for (_a, mn, op, note)
                                in blocks[b].insns)
        for s in blocks[b].succ:
            if s in blocks and (s not in spent or (state and not spent[s])):
                spent[s] = state
                work.append(s)
    out = {}
    for b, state in spent.items():
        for (a, mn, op, note) in blocks[b].insns:
            if mn == "ret" and not state:
                out[a] = "d0"
            state = state or spends(mn, op, note)
    return out


#: What one instruction does to the return registers, for _return_facts: a `ret`, a
#: call, a stub that gives every register back, or anything else.
_RV_RET, _RV_CALL, _RV_KEEP, _RV_PLAIN = range(4)


def _d0_callee(callees):
    """`(mn, op, note) -> bool`: whether a call is one whose double `_result` names past
    the next instruction, a direct one to a function that returns d0: its callers read
    d0 after it (`callees`, make_return_resolver), or, where they say nothing, its own
    code hands back d0 at every `ret` (returns_in_d0). A named stub is not. An unnamed
    one reads as a function: the stack-overflow check's gives every register back and
    a throw's never returns, so their callers read neither register after them
    (_read_after_call) and neither hands back d0."""
    own = getattr(callees, "code_d0", None)

    def named(mn, op, note):
        if callees is None or mn != "bl" or "_iso_stub_" in note:
            return False
        target = _imm(op.strip()) if op.strip().startswith("#") else None
        if target is None:
            return False
        said = callees(target)
        return said == "d0" or said is None and own is not None and own(target)
    return named


def _d0_result_reads(blocks, entry, returned, named, roots=()) -> frozenset:
    """The calls whose result in d0 the code goes on to read, of those `named` says are
    calls to a function that returns d0 (_d0_callee): what one leaves in d0 reaches an
    instruction that reads it, or a `ret` that hands d0 back (`returned`,
    _return_registers), with nothing writing d0 on the way. Any other call writes it. A
    stub that gives every register back keeps it, and so does a slow path's save and
    restore around one (_rv_push, _rv_pop). A d0 read past the next instruction, after
    a reload of x0 or a join, was left as d0, the d0 the function was handed (#152,
    #127). arm64 only, as _rv_def_use is. `roots` are the proven entries no edge
    reaches (Lifter.roots), each entered, as the entry is, with no call's result in d0
    (#278)."""
    if _T is not ARM64:
        return frozenset()
    read_, call_, write_ = range(3)
    rows, insn = {}, {}
    for b, blk in blocks.items():
        row = rows[b] = []
        for (a, mn, op, note) in blk.insns:
            if mn == "ret":
                if returned.get(a) == "d0":
                    row.append((a, read_))
                continue
            c = _rv_call(mn, note)
            if c is not False:
                if c:
                    direct = mn == "bl" and "_iso_stub_" not in note
                    row.append((a, call_ if direct else write_))
                    insn[a] = (mn, op, note)
                continue
            if _rv_push(mn, op) or _rv_pop(mn, op) and op.lstrip().startswith("q"):
                continue                    # a slow path's save, and its restore
            defs, uses = _rv_def_use(mn, op)
            if "d0" in uses:
                row.append((a, read_))
            if "d0" in defs:
                row.append((a, write_))
    # A call's d0 is read where d0 is live right after it, on a path from a block the
    # entry or a root reaches; every block on that path is reached too. So one bit per
    # block, backward: d0 is live into a block that reads it before any write, or into
    # one with no row at all whose successor has it live. This was the forward set of
    # calls whose d0 may still be there, rebuilt at every join and walked again each
    # time it grew: N if/else diamonds with a call in one arm walked 3,001 blocks
    # 1,502,501 times at 1,000. A bit is set once, so each block is handled once (#296).
    preds, live_in = {}, set()
    for b, row in rows.items():
        for s in blocks[b].succ:
            if s in blocks:
                preds.setdefault(s, []).append(b)
        if row and row[0][1] == read_:
            live_in.add(b)
    live_out, work = set(), list(live_in)
    while work:
        for p in preds.get(work.pop(), ()):
            live_out.add(p)
            if not rows[p] and p not in live_in:
                live_in.add(p)
                work.append(p)
    reach = {r for r in (entry, *roots) if r in blocks}
    work = list(reach)
    while work:
        for s in blocks[work.pop()].succ:
            if s in blocks and s not in reach:
                reach.add(s)
                work.append(s)
    read = set()
    for b in reach:
        live = b in live_out
        for a, kind in reversed(rows[b]):
            if kind == read_:
                live = True
                continue
            if kind == call_ and live:
                read.add(a)
            live = False
    return frozenset(a for a in read if named(*insn[a]))       # asked only of these


def _return_facts(blocks, entry):
    """What the function's own code says about its return register, or None when it
    never writes V0 (or is not arm64): ({ret address: (x0 may be written, the last write
    to d0 may be its own, it may be a call, the last write to either is a call on every
    path, the calls that may have made the last write to d0)}, whether the code proves a
    d0 return, whether a d0 of its own that reaches a `ret` is read by something other
    than a store, {call address: (mnemonic, operands, note)}). See _return_registers."""
    if _T is not ARM64:
        return None
    # Most functions never name V0 at all, and one search over all their operands says
    # so without a call per instruction.
    if not _RD0.search("\n".join([i[2] for blk in blocks.values() for i in blk.insns])):
        return None
    # Each instruction once: (address, kind, writes x0, writes d0, reads d0, is a store,
    # is a pop of the Dart stack).
    rows = {}
    calls = {}
    for b, blk in blocks.items():
        row = rows[b] = []
        for (a, mn, op, note) in blk.insns:
            if mn == "ret":
                row.append((a, _RV_RET, False, False, False, False, False))
                continue
            c = _rv_call(mn, note)
            if c is not False:
                row.append((a, _RV_CALL if c else _RV_KEEP, False, False, False, False,
                            False))
                calls[a] = (mn, op, note)
                continue
            defs, uses = _rv_def_use(mn, op)
            wd = "d0" in defs
            row.append((a, _RV_PLAIN, "x0" in defs, wd, "d0" in uses, mn.startswith("st"),
                        wd and _rv_pop(mn, op)))
    # The d0 writes that count are the ones the CPU can reach, the basis #182 gave the
    # rest of the proof (at_ret, only_ret, read). A block only a trap's false fall-through
    # reaches is not the function's own code, so a d0 write there does not make it return
    # a double (#184). Without a reachable one, a `ret` that hands back its d0 argument is
    # left to _argument_returns, as it is for a function that never writes d0 at all.
    reach = {entry}
    stack = [entry]
    while stack:
        for s in blocks[stack.pop()].succ:
            if s in blocks and s not in reach:
                reach.add(s)
                stack.append(s)
    if not any(r[3] for b in reach for r in rows[b]):
        return None

    # Forward, per point: x0 may have been written, the last write to d0 may be this
    # function's own, it may be a call, on every path the last write to either was a
    # call, and which calls may have made the last write to d0. Joined by or, or, or,
    # and, union.
    def step_fwd(state, r):
        kind = r[1]
        if kind == _RV_CALL:
            return True, False, True, True, frozenset((r[0],))
        if kind != _RV_PLAIN:
            return state
        if r[3]:
            return state[0], True, False, False, frozenset()
        if r[2]:
            return True, state[1], state[2], False, state[4]
        return state

    ins = {entry: (False, False, False, False, frozenset())}
    work = [entry]
    while work:
        b = work.pop()
        state = ins[b]
        for r in rows[b]:
            state = step_fwd(state, r)
        for s in blocks[b].succ:
            if s not in blocks:
                continue
            old = ins.get(s)
            new = state if old is None else (old[0] or state[0], old[1] or state[1],
                                              old[2] or state[2], old[3] and state[3],
                                              old[4] | state[4])
            if new != old:
                ins[s] = new
                work.append(s)
    at_ret = {}
    for b, state in ins.items():
        for r in rows[b]:
            if r[1] == _RV_RET:
                at_ret[r[0]] = state
            state = step_fwd(state, r)

    # Backward, d0 alone: whether what it holds is read by a `ret` (reach), by a store
    # (stored) or by anything else (read) before it is written again. A call writes it,
    # and may read it as an argument; a stub that gives every register back does
    # neither, it puts back what it saved.
    def step_bwd(live, r):
        kind = r[1]
        if kind == _RV_RET:
            return True, live[1], live[2]
        if kind == _RV_CALL:
            return False, False, True
        if kind == _RV_KEEP:
            return live
        if r[3]:
            live = (False, False, False)
        if not r[4]:
            return live
        if r[5]:
            return live[0], True, live[2]
        return live[0], live[1], True

    # A worklist, as the forward pass: each block's three flags only ever turn on, so
    # it is requeued at most three times, where sweeping every block until nothing
    # changed was quadratic on a chain of blocks that runs backwards.
    preds: dict = {b: [] for b in blocks}
    for b, blk in blocks.items():
        for s in blk.succ:
            if s in preds:
                preds[s].append(b)
    outs = {}
    live_in = {}
    work = sorted(blocks)                  # popped from the end, highest address first
    queued = set(work)
    while work:
        b = work.pop()
        queued.discard(b)
        live = (False, False, False)
        for s in blocks[b].succ:
            li = live_in.get(s)
            if li:
                live = (live[0] or li[0], live[1] or li[1], live[2] or li[2])
        outs[b] = live
        for r in reversed(rows[b]):
            live = step_bwd(live, r)
        if live_in.get(b) != live:
            live_in[b] = live
            for p in preds[b]:
                if p not in queued:
                    queued.add(p)
                    work.append(p)
    only_ret = read = False
    # Forward-reachable blocks only, the basis at_ret uses above. A block a CPU never
    # enters (its one in-edge was a trap's false fall-through, gone once the trap is
    # honoured) can write d0 and ret, which would prove a d0 return the live code never
    # makes (#182).
    for b in ins:
        live = outs[b]
        for r in reversed(rows[b]):
            if live[0] and r[3]:
                if live[2]:
                    read = True
                elif not live[1] and not r[6]:
                    only_ret = True
            live = step_bwd(live, r)
    proven = only_ret or any(not st[0] and st[1] for st in at_ret.values())
    return at_ret, proven, read, calls
def _raw_store(mn: str) -> bool:
    """Whether `mn` writes memory and is not one of `_STORES`, which `_step` models: a
    non-temporal pair, a store-release, an exclusive store, `st1` to `st4`, an atomic. It
    is printed raw, and its address counts as a store all the same (#162)."""
    got = _RAW_STORE.get(mn)
    if got is None:
        got = _RAW_STORE[mn] = mn not in _STORES and (
            mn.startswith("st") or bool(_ATOMIC_OP_RE.match(mn) or _CAS_RE.match(mn)))
    return got


_RAW_STORE: dict = {}

#: `Lifter._kill_bits`: a block's stores that `_writes_stack` and `_writes_heap` count,
#: and a bit per register it writes, given out as registers turn up.
_KILL_STACK, _KILL_HEAP = 1, 2
#: How many blocks `Lifter._join_kill` walks, per block of the function, before it
#: builds `_kill_fold`. The fold costs a pass over the function, and a function whose
#: joins sit close under their dominators never earns it back: with every function
#: folded, the clean fixture lifted 1.4% slower. Walked first, a function pays for the
#: fold only once its walks have cost this many passes, so the walks stay linear too.
_KILL_WALK = 8
_KILL_BIT: dict = {}
_KILL_REG: list = []


def _kill_regs(mask) -> frozenset:
    """The registers of a `Lifter._kill_bits` mask."""
    mask >>= 2
    return frozenset(r for i, r in enumerate(_KILL_REG) if mask >> i & 1)


def _off_frame(ops) -> bool:
    """Whether the memory operand in `ops` may be off SP or FP: it is, or it does not
    parse, which is no evidence about where it points."""
    got = _addr(ops)
    return got is None or _T.roles.get(got[0][0]) in ("SP", "FP")


def _frame_access(mn: str, op: str, apart: bool = True):
    """(slot keys, how far FP moves, operands) for a load or store `_step` keeps in the
    slot map, else None. The keys are the ones `_step` files the access under, so an
    analysis over them agrees with what the walk reads back. A store these cannot place
    has no keys and moves the frame by 1, which every analysis takes as the frame moving:
    one through an offset in a register, one `_step` leaves raw, and one through SP where
    `apart` is False, that it may write a slot off FP (_frame_meets)."""
    if mn not in _STORES and mn not in _LOADS:
        if _raw_store(mn) and _off_frame(_split_ops(op)):
            return [], 1, _split_ops(op)
        return None
    fp = next((r for r, v in _T.roles.items() if v == "FP"), None)
    ops = _split_ops(op)
    got = _addr(ops)
    if got is None or got[1] is _BAD_POST:
        return None
    (base, disp, index, _scale, wb), post = got
    if index is not None and _T.roles.get(base) in ("SP", "FP"):
        # An offset in a register _fold_frame_offsets could not read: a load from it
        # fills no slot, and a store may have written any of them, off SP as off FP,
        # which these analyses take as they take the frame moving.
        return ([], 1, ops) if mn in _STORES else None
    if base != fp:
        if not apart and mn in _STORES and _T.roles.get(base) == "SP":
            return [], 1, ops
        return None
    delta = disp if wb else post
    if mn in _LOADS and delta and fp in _regs(ops[:2 if mn in ("ldp", "ldpsw") else 1]):
        return None                                   # left raw by _step, see there
    if post:
        disp = 0
    if mn in _STORES:
        disp -= delta           # keyed off FP where the move leaves it, as _step files it
    if mn in ("stp", "ldp", "ldpsw") and len(ops) >= 3:
        second = disp + _access_width(mn, ops[0])
        return [f"{fp}{disp:+d}", f"{fp}{second:+d}"], delta, ops
    return [f"{fp}{disp:+d}"], delta, ops


def _frame_at(mn: str, op: str):
    """(base, the offset `_step` keys the access at) for a frame LOAD or store, else None.

    `_frame_slots` answers this for a store alone, because its caller files slots; the
    addressing arithmetic is the same for a load (#207).
    """
    if mn not in _STORES and mn not in _LOADS:
        return None
    ops = _split_ops(op)
    got = _addr(ops)
    if got is None or got[1] is _BAD_POST:
        return None
    (base, disp, index, _scale, wb), post = got
    if index is not None or _T.roles.get(base) not in ("SP", "FP"):
        return None
    return base, (0 if post else disp) - (disp if wb else post)


def _frame_slots(mn: str, op: str):
    """(base, [(key, bytes)]) for a store `_step` files in the slot map, one entry per
    register, keyed as `_step` keys it: off the base where a write-back has left it. None
    for any other instruction."""
    if mn not in _STORES:
        return None
    got = _frame_at(mn, op)
    if got is None:
        return None
    base, at = got
    ops = _split_ops(op)
    width = _access_width(mn, ops[0])
    n = 2 if mn == "stp" and len(ops) >= 3 else 1
    return base, [(f"{base}{at + i * width:+d}", width) for i in range(n)]


def _frame_roles(regs) -> tuple:
    """The frame roles, `SP` and `FP`, whose registers are among `regs`."""
    sp, fp = _frame_regs()
    return (("SP",) if sp in regs else ()) + (("FP",) if fp in regs else ())


def _frame_regs() -> tuple:
    """(SP, FP) on the current target, by machine name."""
    got = _FRAME_REGS.get(id(_T))
    if got is None:
        got = _FRAME_REGS[id(_T)] = (next(r for r, v in _T.roles.items() if v == "SP"),
                                     next(r for r, v in _T.roles.items() if v == "FP"))
    return got


_FRAME_REGS: dict = {}


def _sp_mem(op: str):
    """Split a memory operand into (registers, mem) where mem starts at '['.

    `str x0, [x15, #-8]!` -> (["x0"], "[x15, #-8]!"). None where there is no memory
    operand. The registers are everything before the first bracket."""
    i = op.find("[")
    if i < 0:
        return None, None
    regs = [r.strip() for r in op[:i].rstrip(", ").split(",") if r.strip()]
    return regs, op[i:]


def _sp_base(mem: str):
    """The base register of a `[reg...]` memory operand, else None."""
    j = mem.find("]")
    if j < 0:
        return None
    return mem[1:j].split(",", 1)[0].strip()


def _push_regs(mn: str, op: str):
    """Registers a pre-index SP store write-back pushes (`str/stp R, [sp,#-k]!`), or None.

    A push moves SP down and leaves the registers in the outgoing area; see
    _save_wrapped_calls."""
    if mn not in ("str", "stp", "stur"):
        return None
    regs, mem = _sp_mem(op)
    if not regs or mem is None or not mem.rstrip().endswith("]!"):
        return None
    base = _sp_base(mem)
    if base is None or _T.roles.get(canon(base)) != "SP":
        return None
    return [canon(r) for r in regs]


def _pop_regs(mn: str, op: str):
    """Registers a post-index SP load write-back pops (`ldr/ldp R, [sp], #k`), or None."""
    if mn not in ("ldr", "ldp", "ldur"):
        return None
    regs, mem = _sp_mem(op)
    if not regs or mem is None:
        return None
    j = mem.find("]")
    if j < 0 or "#" not in mem[j:]:     # post-index: the imm is OUTSIDE the bracket
        return None
    base = _sp_base(mem)
    if base is None or _T.roles.get(canon(base)) != "SP":
        return None
    return [canon(r) for r in regs]


def _call_setup(mn: str, op: str) -> bool:
    """A register-defining row that is call set-up or result capture, so it may sit
    between a save and the call it guards (`mov x0, #1`, `ldr x30, [x27, #..]`, the
    `mov x1, x0` that takes the result). Anything that stores, branches, returns, or
    moves SP ends the straight run and is not skipped (_save_wrapped_calls)."""
    if mn in _CALLS or mn in _STORES or mn == "ret":
        return False
    if mn[:1] == "b" or mn[:2] in ("cb", "tb"):
        return False
    regs, _mem = _sp_mem(op)
    dst = canon(op.split(",", 1)[0].strip()) if regs is None and op else None
    if dst is not None and _T.roles.get(dst) == "SP":
        return False                    # a frame move, not set-up
    return True


def _save_wrapped_calls(rows) -> set:
    """PCs of calls whose stack pushes are registers saved round the call, not arguments.

    `_stack_args` reads a contiguous run of SP slots as a call's pushed argument list.
    A slow path that spills volatile registers before a runtime call and reloads them
    after leaves that same run in the outgoing area, and the call printed them as its
    arguments: `pool_0x2650.field_0x7(t4, t3)` for a saved `stp x0, x1` (#147). A save
    is told from an argument by what the code does after the call: a save is reloaded
    into the registers it came from; arguments are dropped with the outgoing area. So a
    run of pre-index pushes right before a call whose registers a run of post-index pops
    right after the call reloads is a save, and the call reads no stack arguments."""
    out: set = set()
    n = len(rows)
    for i in range(n):
        if rows[i][1] not in _CALLS:
            continue
        pushed: list = []               # closest-to-call first
        j = i - 1
        while j >= 0:
            pr = _push_regs(rows[j][1], rows[j][2])
            if pr is not None:
                pushed.extend(pr)
                j -= 1
                continue
            if pushed or not _call_setup(rows[j][1], rows[j][2]):
                break                   # pushes are contiguous; set-up only precedes them
            j -= 1
        if not pushed:
            continue
        popped: list = []
        k = i + 1
        while k < n:
            qr = _pop_regs(rows[k][1], rows[k][2])
            if qr is not None:
                popped.extend(qr)
                k += 1
                continue
            if popped or not _call_setup(rows[k][1], rows[k][2]):
                break
            k += 1
        if popped and set(pushed) == set(popped):
            out.add(rows[i][0])
    return out


def _frame_moves(blocks, raw, wrote=None) -> dict:
    """{address: (whether FP moves, how far SP moves)} for each instruction that moves
    a frame register where `_step` does not see it move (#165). `_step` follows the
    write-back of a load or store through SP or FP and nothing else. strip_boilerplate
    blanks every `mov x29, x15` and every `add` or `sub` of SP, not only the prologue's,
    and `raw` (address -> mnemonic and operands) gives them back. An FFI call's frame
    ends with `ldr x29, [x15], #8` and aligns SP with `and`, which `_step` reads as a
    register like any other. How far SP moves is None where it is not known.

    `wrote`, a dict, is given every row that writes SP or FP, seen by `_step` or not,
    as (whether it writes FP, how far it moves SP): the rows a value naming one has to
    be looked at before (`Lifter._frame_shift`), a visible write-back among them."""
    sp, fp = _frame_regs()
    out = {}
    for blk in blocks.values():
        for (a, mn, op, _n) in blk.insns:
            if mn == "nop":
                if a not in raw:
                    continue
                mn, op = raw[a]
                seen = False
            else:
                seen = True
            if mn in ("push", "pop"):
                regs = _regs_in_list(op)
                if regs:
                    out[a] = (mn == "pop" and fp in regs,
                              _T.word * len(regs) * (1 if mn == "pop" else -1))
                if wrote is not None:
                    wrote[a] = out.get(a, (False, None))
                continue
            moved = _def_use(mn, op)[0] & {sp, fp}
            if not moved:
                continue
            wrote_fp, wrote_sp = fp in moved, sp in moved
            ops = _split_ops(op)
            delta = None
            got = _addr(ops) if any(o.lstrip().startswith("[") for o in ops) else None
            if got is not None and got[1] is not _BAD_POST:
                (base, disp, _index, _scale, wb), post = got
                n = 2 if mn in ("ldp", "ldpsw") else 1
                loaded = _regs(ops[:n]) if mn in _LOADS else ()
                if base == sp and sp not in loaded:
                    delta = disp if wb else post
                if seen and (mn in _STORES or mn in _LOADS and base not in loaded):
                    moved = moved - {base}
            elif mn in ("add", "sub") and len(ops) == 3 and {canon(ops[0]),
                                                            canon(ops[1])} == {sp}:
                imm = _imm(ops[2])
                delta = None if imm is None else imm if mn == "add" else -imm
            if wrote is not None:
                wrote[a] = (wrote_fp, delta if wrote_sp else 0)
            if moved:
                out[a] = (fp in moved, (delta if sp in moved else 0))
    return out


def _sp_neutral(mn: str, op: str) -> bool:
    """Whether an instruction leaves _sp_step's state as it is, whatever it is: it writes
    neither SP nor FP and stores nothing through either, as most instructions do."""
    key = (id(_T), mn, op)
    got = _SP_NEUTRAL.get(key)
    if got is None:
        if len(_SP_NEUTRAL) >= _SPLIT_CACHE_MAX:
            _SP_NEUTRAL.clear()
        sp, fp = _frame_regs()
        got = _SP_NEUTRAL[key] = not (
            (mn in _STORES or _raw_store(mn)) and _off_frame(_split_ops(op))
            or set(_def_use(mn, op)[0]) & {sp, fp})
    return got


#: _sp_neutral's answer per instruction text.
_SP_NEUTRAL: dict = {}


#: How many FP values saved on the stack _sp_step follows at once, and how far below
#: where it was an alignment may have put SP.
_MAX_SAVED_FP = 4
_MAX_SLACK = 63


def _sp_step(state, here, mn: str, op: str):
    """The frame state after one instruction at address `here`, from `state` before it;
    see _frame_meets. It is (SP - FP, how much lower SP may be, the FP values saved on
    the stack, which frame FP points into, and where in it).

    SP - FP is None where it is not known. It is the most it can be, and an alignment,
    `and x15, x15, #-16` before an FFI call's stack arguments, puts SP up to 15 below.
    A saved value is (where it is, what it was), both from FP as it is now, so that an
    FFI call's `str x29, [x15, #-8]!; mov x29, x15; ...; mov x15, x29; ldr x29, [x15],
    #8`, which gives the C call a frame of its own, ends where it began. The frame is
    the address where FP last moved by an amount not known, and where in it is how far
    FP has moved since by amounts that are."""
    if _sp_neutral(mn, op):
        return state
    d, slack, saved, frame, f = state
    sp, fp = _frame_regs()
    ops = _split_ops(op)

    def moved(d, slack, saved, k):
        """FP moved by k: SP - FP and every saved place and value with it."""
        if k is None:
            return None, 0, (), here, 0
        return ((None if d is None else d - k), slack,
                tuple((p - k, v - k) for p, v in saved), frame, f + k)

    if mn in ("mov", "add", "sub", "and") and 2 <= len(ops) <= 3:
        dst, src = canon(ops[0]), canon(ops[1])
        imm = 0 if len(ops) == 2 else _imm(ops[2])
        if mn == "and" and dst == src == sp and imm is not None and d is not None:
            align = (1 << 64) - imm         # `#0xff..f0` keeps SP 16-aligned
            if 0 < align and align & (align - 1) == 0 and slack + align - 1 <= _MAX_SLACK:
                return d, slack + align - 1, saved, frame, f
            return None, 0, saved, frame, f
        if mn != "and" and dst in (sp, fp) and src in (sp, fp):
            if imm is None or (mn == "mov") != (len(ops) == 2):
                return ((None, 0, saved, frame, f) if dst == sp
                        else moved(None, 0, (), None))
            imm = -imm if mn == "sub" else imm
            if dst == sp:
                if src == fp:
                    return imm, 0, saved, frame, f
                return (None if d is None else d + imm), slack, saved, frame, f
            if src == fp:
                return moved(d, slack, saved, imm)
            exact = d is not None and not slack
            return (-imm, 0) + moved(d, slack, saved, d + imm if exact else None)[2:]
    defs = set(_def_use(mn, op)[0])
    got = _addr(ops) if any(o.lstrip().startswith("[") for o in ops) else None
    if got is None or got[1] is _BAD_POST:
        if fp in defs:
            return moved(None, 0, (), None)
        return (None, 0, saved, frame, f) if sp in defs else state
    (base, disp, index, _scale, wb), post = got
    at = None if index is not None else 0 if post else disp
    low = 0                                  # how much lower the address may be
    if base == sp:
        at, low = (None, 0) if d is None or at is None else (d + at, slack)
    elif base != fp:
        at = None
    width = _access_width(mn, ops[0])
    n = 2 if mn in ("stp", "ldp", "ldpsw") and len(ops) >= 3 else 1
    if (mn in _STORES or _raw_store(mn)) and base in (sp, fp):
        if at is None or mn not in _STORES:
            saved = ()
        elif saved or fp in {canon(o) for o in ops[:n]}:
            saved = tuple((p, v) for p, v in saved
                          if not at - low - 7 <= p < at + width * n)
            if not low:
                saved += tuple((at + i * width, 0) for i in range(n)
                               if canon(ops[i]) == fp)
            saved = tuple(sorted(saved))[-_MAX_SAVED_FP:]
    if low:
        at = None                            # no saved value is read from there
    state = d, slack, saved, frame, f
    delta = disp if wb else post
    if delta and base == sp:
        state = (None if d is None else d + delta,) + state[1:]
    elif delta and base == fp:
        state = moved(d, slack, saved, delta)
    d, slack, saved, frame, f = state
    loaded = {canon(o) for o in ops[:n]} if mn in _LOADS else set()
    if fp in loaded:
        k = None
        for i in range(n):
            if canon(ops[i]) == fp and at is not None:
                k = dict(saved).get(at + i * width)
        state = moved(d, slack, saved, k)
    elif fp in defs - {base}:
        state = moved(None, 0, (), None)     # an atomic's or a raw line's destination
    if sp in loaded or sp in defs - {base} or (
            sp in defs and mn not in _LOADS and mn not in _STORES):
        state = (None, 0) + state[2:]       # `ldr x15, [x15]` loads SP through itself
    return state


def _cut_edges(blocks, raw) -> dict:
    """{block: where each edge strip_boilerplate took out of it led}: the target of a
    conditional branch it made a nop, which is a stack check's slow path, and the
    fallthrough of one it made unconditional, which is the slow path that boxes a Mint.
    `raw` is what it changed: the mnemonic and operands it had, by address."""
    cut = {}
    for b, blk in blocks.items():
        for t in blk.insns:
            if cond_of(raw.get(t[0], ("",))[0]):
                to = _target(raw[t[0]][1]) if t[1] == "nop" else t[0] + 4
                cut.setdefault(b, []).append(to)
    return cut


def _frame_pass(blocks, entry, raw):
    """Where SP and FP are at the entry of each block, from _sp_step (#162): ({block: the
    state at its entry}, {block: the instructions that may change it or end a path, in
    order, as (instruction, mnemonic, operands, whether it ends one)}, the blocks the
    entry reaches, and the blocks where paths meet with FP in different places).

    What strip_boilerplate changed is read back from `raw` (address -> mnemonic and
    operands), and the edges it cut are put back: to a stack check's slow path, which
    runs with SP where the check found it and goes back with it there, and on past a
    box-or-tag check it made unconditional, into the slow path that boxes a Mint. No
    state is carried past a trap or a throw, over the edge tier 3 keeps there and no
    path runs (#64).

    The entry is walked first, then each block it does not reach, in address order: the
    body behind a second entry point, or a catch handler, which sets SP from FP itself.
    What the entry reaches is not changed from one of those: the walk takes no edge from
    them, and a stack check's slow path, cut off from the check by strip_boilerplate,
    runs back into the body with SP where the check left it.

    A block is walked again only when what reaches it changes: SP - FP goes unknown at
    most once, the frame changes once, and the saved FP values only shrink, at most
    _MAX_SAVED_FP of them, so each block is walked a few times at most."""
    def insn(t):
        return raw.get(t[0], t[1:3]) if t[1] == "nop" else t[1:3]

    # Per block, only what can change the state or ends a path, in order.
    steps = {}
    for b, blk in blocks.items():
        steps[b] = [(t, *insn(t), _ends_path(t[1], t[3])) for t in blk.insns
                    if not _sp_neutral(*insn(t)) or _ends_path(t[1], t[3])]
    cut = _cut_edges(blocks, raw)
    seen = object()                     # not reached yet
    into = {b: seen for b in blocks}
    clash = set()

    def meet(a, b, at):
        # A frame of its own where FP differs, named apart from one a move starts at.
        if a[3:] != b[3:]:
            clash.add(at)
            return None, 0, (), ("join", at), 0
        return (a[:2] if a[:2] == b[:2] else (None, 0)) + (
            tuple(e for e in a[2] if e in b[2]),) + a[3:]
    fixed = set()
    for root in [entry] + sorted(blocks):
        if into[root] is not seen:
            continue
        into[root] = (None, 0, (), ("root", root), 0)
        work, queued = [root], {root}
        while work:
            b = work.pop()
            queued.discard(b)
            d, ends = into[b], False
            for t, mn, op, ends in steps[b]:
                d = _sp_step(d, t[0], mn, op)
                if ends:
                    break           # the edge past a throw, which tier 3 keeps (#64)
            for s in list(blocks[b].succ) + cut.get(b, []):
                if s not in into or s in fixed or ends:
                    continue
                got = d if into[s] is seen else meet(into[s], d, s)
                if got == into[s]:
                    continue
                into[s] = got
                if s not in queued:
                    queued.add(s)
                    work.append(s)
        if root == entry:
            fixed = {b for b in blocks if into[b] is not seen}
    return into, steps, fixed, frozenset(clash)


def _frame_meets(blocks, entry, raw, passed=None) -> frozenset:
    """The addresses of the frame stores the walk sees that may write a slot it keys off
    the other frame register (#162).

    The walk keeps the slots off SP and off FP apart: a store through one was not
    checked against the other's. Dart's frame is why that holds. The prologue reserves
    the spill slots and the outgoing area with one `sub`, and the arguments are stored
    below the spill slots. Where SP sits higher, a store through SP changed a slot the
    walk went on reading through FP as before, and a store through FP one a call takes
    its arguments from. So this follows SP - FP through the graph (_frame_pass, or
    `passed`, what it gave), and compares the bytes each store through SP writes with
    those each store through FP writes, in the frame FP was in then, from where FP is
    where it does not move by an amount not known: an FFI call's frame has an FP of its
    own, and _frame_plan keys a slot off FP in its frame. Loads take no part, as the
    walk keeps a slot only where a store filled it.

    A store through SP that may reach a store through FP is one, and so is a store
    through FP that may reach a store through SP the entry reaches. A store through SP
    where SP - FP is not known is one, and one the entry reaches makes every store
    through FP one: it is somewhere the walk cannot place. A store adds its width and
    at most _MAX_SLACK bytes to compare."""
    sp = next((r for r, v in _T.roles.items() if v == "SP"), None)
    fp = next((r for r, v in _T.roles.items() if v == "FP"), None)
    if sp is None or fp is None or entry not in blocks:
        return frozenset()
    if not any(mn in _STORES and (sp in op or "sp" in op)      # `sp` canonicalises to SP
               and (_frame_slots(mn, op) or ("",))[0] == sp
               for blk in blocks.values() for (_a, mn, op, _n) in blk.insns):
        return frozenset()
    into, steps, fixed, _clash = passed or _frame_pass(blocks, entry, raw)
    # Each store through FP as (first byte, end, its address) in its frame, keyed as
    # _frame_access keys it; each store through SP as (its frame, first byte it may
    # write, end, its address, whether the entry reaches it). Both from where FP is at
    # the frame's start. The instructions are the ones the pass stepped, from before
    # _frame_plan rewrote any.
    reached: dict = {}
    pushed, out, lost = [], set(), False
    for b in blocks:
        d = into[b]
        for t, rmn, rop, _ends in steps[b]:
            d = _sp_step(d, t[0], rmn, rop)
            mn, op = t[1], t[2]
            if mn not in _STORES:
                continue
            got = _frame_access(mn, op)
            if got is not None and got[0]:
                for k, o in zip(got[0], got[2]):
                    lo = int(k[len(fp):]) + d[4]
                    reached.setdefault(d[3], []).append(
                        (lo, lo + _access_width(mn, o), t[0]))
            slots = _frame_slots(mn, op)
            if slots is not None and slots[0] == sp:
                if d[0] is None:
                    out.add(t[0])
                    lost = lost or b in fixed
                    continue
                for key, width in slots[1]:
                    lo = d[0] + int(key[len(sp):]) + d[4]
                    pushed.append((d[3], lo - d[1], lo + width, t[0], b in fixed))
    if not reached:
        return frozenset()              # no slot off FP for a store through SP to meet
    # An access is at most 16 bytes, so one that a store's bytes meet starts at most 15
    # before them: sorted by where they start, the candidates are a slice.
    starts = {}
    for k, accs in reached.items():
        accs.sort(key=lambda a: a[0])
        starts[k] = [a[0] for a in accs]
    for where, lo, hi, at, walked in pushed:
        accs = reached.get(where)
        if not accs:
            continue
        i = bisect.bisect_left(starts[where], lo - 15)
        j = bisect.bisect_left(starts[where], hi)
        for k in range(i, j):
            a_lo, a_hi, store = accs[k]
            if a_hi > lo:
                out.add(at)
                if walked:
                    out.add(store)
    if lost:
        out.update(a for blk in blocks.values() for (a, mn, op, _n) in blk.insns
                   if (_frame_slots(mn, op) or ("",))[0] == fp)
    return frozenset(out)


def _frame_plan(blocks, entry, raw, lost=frozenset()):
    """(_frame_meets, the frame moves `_step` does not see, the blocks to forget the frame
    at the entry of, and where each store through SP or FP sits against the other) for
    _lift_function, with the accesses through FP rewritten in place into the
    coordinates of the frame FP is in (#165).

    FP moves inside a function. An FFI call gives the C call a frame of its own, `str
    x29, [x15, #-8]!; mov x29, x15; ...; mov x15, x29; ldr x29, [x15], #8`, and a leaf
    runtime call the same with `stp x29, x30`, and both put FP back where it was. A slot
    keyed off FP where it was before reads, through the moved FP, bytes 0x30 lower, and
    forgetting the frame there made `__constructor$Method$FfiNative` lose its spills to
    the first FFI call. So where _frame_pass knows how far FP has moved in its frame, an
    access through it is rewritten to that offset from where FP started, and a write-back
    through FP becomes the access alone, as FP then moves where nothing reads it. Every
    analysis over the slots reads the rewritten offsets. Where FP moves by an amount not
    known it starts a frame of its own, and the walk forgets the frame there
    (_frame_moves), and at a block where paths meet from different frames.

    A store through SP or FP gets (SP less where its frame starts, how much lower SP may
    be), or None where SP is not known against it: the walk drops the other register's
    slots the store's bytes may cover (Lifter._cross_write). _frame_meets answers the same
    question for the whole function at once, for the analyses that need it without the
    walk's state, and over a function it pairs two stores that use one cell at different
    times, the push that starts an FFI call's frame and a leaf call's store into its own.

    Only FP's accesses move: a raw store through FP is printed as it is, and keeps its
    text. Where nothing stores through SP and the moves are only the prologue's and the
    epilogue's, FP is in one place between, and the pass is not run. Nor is an access
    at one of `lost`, the rows where FP may hold something other than the frame pointer
    (`_fp_lost_at`), rewritten or counted: it is off the value FP holds there (#307)."""
    sp, fp = _frame_regs()
    wrote = {}
    moves = _frame_moves(blocks, raw, wrote)
    inner, pushes = 0, False    # FP moves but an epilogue's restore before a return
    for blk in blocks.values():
        insns = blk.insns
        for k, (a, mn, op, _n) in enumerate(insns):
            if a in moves and moves[a][0]:
                if not any(insns[j][1] in ("ret", "b", "br") for j in
                           range(k + 1, min(len(insns), k + 3))):
                    inner += 1
            elif a in lost:
                continue
            elif mn in _STORES or mn in _LOADS:
                got = _addr(_split_ops(op))
                if got is None:
                    continue
                if got[0][0] == fp and (got[0][4] or got[1]):
                    inner += 1
                elif got[0][0] == sp and mn in _STORES:
                    pushes = True
    if inner < 2 and not pushes:
        return frozenset(), moves, frozenset(), {}, {}, None, wrote
    passed = _frame_pass(blocks, entry, raw)
    into, _steps, _fixed, clash = passed
    cross, spat, fpat = {}, {}, {}
    for b, blk in blocks.items():
        d = into[b]
        for k, t in enumerate(blk.insns):
            mn, op = raw.get(t[0], t[1:3]) if t[1] == "nop" else t[1:3]
            where = d[3]
            if d[4] and t[1] != "nop":
                fpat[t[0]] = d[4]       # where a row that reads FP finds it (#340)
            # Not where FP may hold something other than the frame pointer: the access
            # is off the value there, and keeps its operands and its write-back (#307).
            if t[1] != "nop" and t[0] not in lost and (mn in _STORES or mn in _LOADS):
                got = _rekeyed(mn, op, d[4])
                if got is not None:
                    blk.insns[k] = (t[0], t[1], got, t[3])
            # SP as the instruction's own addressing mode sees it, which is BEFORE any
            # write-back it does: `_name_blind` is handed the displacement off that base,
            # so a post-indexed `ldp` off SP reads 16 bytes below where it leaves SP
            # (#207). `cross` below wants the other one, because `_frame_slots` keys a
            # store's slots off the base the write-back has already moved.
            acc = _frame_at(mn, op)
            off_sp = acc is not None and acc[0] == sp
            before = (d[0] + d[4], d[1]) if off_sp and d[0] is not None else None
            if not _sp_neutral(mn, op):
                d = _sp_step(d, t[0], mn, op)
            if t[1] in _STORES and (_frame_slots(t[1], t[2]) or ("",))[0] in (sp, fp):
                cross[t[0]] = None if d[0] is None else (d[0] + d[4], d[1])
            if off_sp:
                spat[t[0]] = before
            if d[3] != where:
                moves[t[0]] = (True, moves.get(t[0], (False, 0))[1])
            elif moves.get(t[0], (False,))[0]:
                if moves[t[0]][1] == 0:
                    del moves[t[0]]
                else:
                    moves[t[0]] = (False, moves[t[0]][1])
    for b in clash:
        if blocks[b].insns:
            a = blocks[b].insns[0][0]
            moves[a] = (True, moves.get(a, (False, 0))[1])
    return (_frame_meets(blocks, entry, raw, passed), moves, clash, cross, spat, fpat,
            wrote)


def _rekeyed(mn: str, op: str, f: int):
    """The operands of the load or store `mn op` through FP with its offset taken `f` on,
    FP's place in its frame, and its write-back left out; None where nothing changes or
    `_step` does not file it in the slot map (_frame_plan)."""
    ops = _split_ops(op)
    got = _addr(ops)
    if got is None or got[1] is _BAD_POST:
        return None
    (base, disp, index, _scale, wb), post = got
    if _T.roles.get(base) != "FP" or index is not None:
        return None
    n = 2 if mn in ("ldp", "ldpsw") else 1
    if mn in _LOADS and base in _regs(ops[:n]):
        return None
    at = (0 if post else disp) + f
    if at == disp and not wb and not post:
        return None
    mem = next((i for i, o in enumerate(ops) if o.lstrip().startswith("[")), None)
    if mem is None:
        return None
    name = ops[mem].strip()[1:].split(",")[0].split("]")[0].strip()
    regs = ", ".join(o.strip() for o in ops[:mem])
    return f"{regs}, [{name}, #{at:#x}]" if at else f"{regs}, [{name}]"


_FRAME_INDEX_RE = re.compile(r"\[(\w+), (x\d+)\]")
#: A 64-bit general or FP register and nothing else: the source of a plain move; and a
#: machine register under any spelling, anywhere in a text.
_REG_ONLY = re.compile(r"[xd](?:3[01]|[12]\d|\d)\Z")
_ANY_REG = re.compile(r"\b[xwdsqhbv](?:3[01]|[12]\d|\d)\b")


def _fold_frame_offsets(blocks, entry=None, raw=None) -> None:
    """Write a frame offset held in a register into the access, in place.

    A frame slot past the 9-bit displacement is reached as `mov x17, #-0x158; str d0,
    [x29, x17]`, 622 accesses on the clean fixture, every one with the `mov` just before.
    Read as `[x29]`, every such slot was one slot, x29+0, and a load got whatever was
    stored at another offset last (#137). Folded to `[x29, #-0x158]` where the `mov` is
    the instruction before it in the same block, so the walk and every analysis over the
    slots read the same address. No further: x16 and x17 are scratch registers a callee
    or a stub may change, and a call need not say so. The `mov` stays."""
    frame = {r for r, v in _T.roles.items() if v in ("SP", "FP")}
    for blk in blocks.values():
        prev = None
        for k, (a, mn, op, note) in enumerate(blk.insns):
            m = _FRAME_INDEX_RE.search(op) if mn in _LOADS or mn in _STORES else None
            if m and prev and canon(m.group(1)) in frame and m.group(2) == prev[0]:
                op = f"{op[:m.start()]}[{m.group(1)}, #{prev[1]:#x}]{op[m.end():]}"
                blk.insns[k] = (a, mn, op, note)
            ops = _split_ops(op) if mn == "mov" else ()
            val = _imm(ops[1]) if len(ops) == 2 and ops[0].strip()[:1] == "x" else None
            prev = None if val is None else (
                canon(ops[0]), val - (1 << 64 if val >= 1 << 63 else 0))
    _fold_held_frame_addresses(blocks, frame, entry, raw or {})


_MEM_PLAIN_RE = re.compile(r"\[(\w+)(?:, #(-?(?:0x[0-9a-f]+|\d+)))?\]\Z")


def _held_step(const, held, k, insn, frame, out=None, raw=None):
    """One instruction of `_fold_held_frame_addresses`: what it leaves in `const` (a
    register's constant) and `held` (a register's frame register and offset), and, where
    `out` is given, the instruction rewritten into it at index `k`. A row
    strip_boilerplate blanked is read as it was (`raw`) for what it writes: a `nop` that
    was `sub x15, x15, #0x20` or `mov x29, x15` still moves the frame register."""
    a, mn, op, note = insn
    if raw and a in raw:
        rmn, rop = raw[a]
        rdefs = set(_def_use(rmn, rop)[0])
        if rmn in _LOADS or rmn in _STORES:
            rdefs.add(_writeback_base(_split_ops(rop)))
        if rmn in _CALLS or rdefs & frame:
            const.clear()
            held.clear()
        for r in rdefs:
            const.pop(r, None)
            held.pop(r, None)
    ops = _split_ops(op)
    if out is not None and (mn in _LOADS or mn in _STORES) and held and ops:
        m = _MEM_PLAIN_RE.match(ops[-1].strip())
        if m and canon(m.group(1)) in held:
            fr, off = held[canon(m.group(1))]
            at = off + (_imm(m.group(2)) if m.group(2) else 0)
            regs = ", ".join(o.strip() for o in ops[:-1])
            out[k] = (a, mn, f"{regs}, [{fr}, #{at:#x}]" if at
                      else f"{regs}, [{fr}]", note)
    if mn in _CALLS:
        const.clear()
        held.clear()
        return
    defs = set(_def_use(mn, op)[0])
    if mn in _LOADS or mn in _STORES:
        defs.add(_writeback_base(ops))
    was, was_held = dict(const), dict(held)           # what the operands read
    if defs & frame:
        held.clear()
    for r in defs:
        const.pop(r, None)
        held.pop(r, None)
    if len(ops) < 2 or ops[0].strip()[:1] != "x" or canon(ops[0]) in frame:
        return
    d = canon(ops[0])
    if mn in ("mov", "movz", "movk") and len(ops) in (2, 3):
        v = _imm(ops[1])
        if len(ops) == 3 and "lsl" not in ops[2]:
            return
        sh = _imm(ops[2].split("lsl")[-1]) if len(ops) == 3 else 0
        if v is None or sh is None:
            return
        if mn == "movk":
            if d in was:
                v = (was[d] & ~(0xffff << sh) & ((1 << 64) - 1)) | ((v & 0xffff) << sh)
                const[d] = v - (1 << 64) if v >= 1 << 63 else v
            return
        v = v - (1 << 64) if v >= 1 << 63 else v
        const[d] = (v << sh) if mn == "movz" else v
        return
    if mn not in ("add", "sub") or len(ops) not in (3, 4):
        return
    a_, b_ = canon(ops[1]), canon(ops[2])
    sh = 0
    if len(ops) == 4:
        t = ops[3].strip()
        sh = _imm(t.split("lsl")[-1]) if t.startswith("lsl") else None
        if sh is None:
            return
    if ops[2].strip().startswith("#"):
        v = _imm(ops[2])
        if v is None or a_ not in was_held or (sh and sh != 12):
            return
        fr, off = was_held[a_]
        held[d] = (fr, off + (v << sh if mn == "add" else -(v << sh)))
        return
    if ops[1].strip()[:1] not in ("x", "s") or ops[2].strip()[:1] not in ("x", "s"):
        return
    if a_ in frame and b_ in was:
        at, fr = was[b_] << sh, a_
    elif mn == "add" and b_ in frame and a_ in was and not sh:
        at, fr = was[a_], b_
    else:
        return
    at = at if mn == "add" else -at
    at = (at + (1 << 63)) % (1 << 64) - (1 << 63)
    held[d] = (fr, at)
    if out is not None:
        rw = "add" if at >= 0 else "sub"
        out[k] = (a, rw, f"{ops[0].strip()}, {fr}, #{abs(at):#x}", note)


def _fold_held_frame_addresses(blocks, frame, entry=None, raw=None) -> None:
    """Read SP or FP plus a constant held in a register as the frame slot it is (#328).

    A slot past the displacement is also reached by building the address, `mov x17,
    #0x238; add x17, x17, x15; str x1, [x17]`. `_step_rest` took the `add` for an element
    address with the constant as its base and SP as its index, so the store printed
    `0x238[SP] = x1;`, and a load of `[x15, #0x238]` was never told the slot had been
    written. The `add` is now `add x17, x15, #0x238` and each plain access through x17
    after it, `[x17]` or `[x17, #8]`, is `[x15, #0x238]` or `[x15, #0x240]`: the one text
    every analysis over the slots reads (_frame_plan, _rekeyed, _frame_moved,
    _writes_outgoing). The constant is a `mov`, a `movz` or a `movk`, in either operand
    order, scaled by `lsl`, or taken off the frame register with `sub`.

    Held along every path to the access and no further: a block starts with what all its
    predecessors leave, a call or a write of the register empties it, and a write of the
    frame register it was taken off, as SP or FP may have moved, does too, read off the
    row as it was where strip_boilerplate blanked it (`raw`); x16 and x17 are scratch
    registers a callee may change. An access with a write-back keeps its text."""
    # A loop and not a generator: every row of every body is asked this (#346).
    for blk in blocks.values():
        for (_a, mn, op, _n) in blk.insns:
            if ((mn == "add" or mn == "sub") and "#" not in op
                    and ("x15" in op or "x29" in op or "sp" in op)):
                break
        else:
            continue
        break
    else:
        return
    preds = {b: [] for b in blocks}
    for b, blk in blocks.items():
        for t in blk.succ:
            if t in preds:
                preds[t].append(b)
    into = {}                       # block -> (const, held) at its start; absent = unseen
    done = {}                       # block -> (const, held) at its end
    work = collections.deque(blocks)
    queued = set(work)
    while work:
        b = work.popleft()
        queued.discard(b)
        seen = [done[p] for p in preds[b] if p in done]
        if b == entry or not preds[b]:
            seen.append(({}, {}))           # the function's own start holds nothing
        if not seen:
            continue                        # nothing has reached it yet
        c = {r: v for r, v in seen[0][0].items() if all(o[0].get(r) == v for o in seen)}
        h = {r: v for r, v in seen[0][1].items() if all(o[1].get(r) == v for o in seen)}
        if into.get(b) == (c, h):
            continue
        into[b] = (c, h)
        c, h = dict(c), dict(h)
        for k, insn in enumerate(blocks[b].insns):
            _held_step(c, h, k, insn, frame, raw=raw)
        if done.get(b) != (c, h):
            done[b] = (c, h)
            for t in blocks[b].succ:
                if t in blocks and t not in queued:
                    queued.add(t)
                    work.append(t)
    for b, (c, h) in into.items():
        if not (c or h) and not any(mn in ("add", "sub") for (_a, mn, _o, _n)
                                    in blocks[b].insns):
            continue
        c, h = dict(c), dict(h)
        out = {}
        for k, insn in enumerate(blocks[b].insns):
            _held_step(c, h, k, insn, frame, out, raw)
        for k, insn in out.items():
            blocks[b].insns[k] = insn


#: The stub kinds that never return; see Lifter._loop_rewrites.
_NORETURN = frozenset({"throw", "rethrow", "throw_err"})


def _ends_path(mn: str, note: str) -> bool:
    """True for an instruction no path runs past: a trap, or a call to a stub that throws.

    Tier 3 builds its graph with neither ending a block (#64), so the instructions after
    one, and the block they fall into, look reachable from it."""
    if mn in TRAPS:
        return True
    if mn == "bl" and "-> " in note and "_iso_stub_" in note:
        return _classify_stub(note.split("-> ", 1)[1].strip())[0] in _NORETURN
    return False


def _path_ends(rows) -> frozenset:
    """The addresses in `rows` that no path runs past, for `build_cfg`'s `ends`.

    A trap says so in its mnemonic and build_cfg knows them; a `bl` to a stub that throws
    does not, and the callee's name is the only evidence there is, so the lift has to hand
    the addresses over (_ends_path, #234)."""
    return frozenset(t[0] for t in rows if _ends_path(t[1], t[3]))


def _frame_accesses(insns, stop=False, meets=frozenset(), moves=frozenset()):
    """(index, slot keys, how far FP moves, operands, write-backs) for each load and store
    of one block that `_step` keeps in the slot map, in order. `write-backs` is None for a
    load, and for a store says per key whether the register stored was reloaded from that
    slot in this block with nothing written to either since: the value already there.
    `stop` ends the block at the first instruction no path runs past (_ends_path),
    `meets` holds the stores that may write a slot off the other frame register
    (_frame_meets), and `moves` the instructions that move FP where `_step` does not see
    it (_frame_moves), which move it by an amount not known."""
    fresh = {}                             # {register: the slot it was reloaded from}
    for i, (_a, mn, op, note) in enumerate(insns):
        if stop and _ends_path(mn, note):
            return
        got = _frame_access(mn, op, _a not in meets)
        if _a in moves:
            got = ([], 1, ()) if got is None else (got[0], 1, got[2])
        if got is None:
            for r in _def_use(mn, op)[0]:
                fresh.pop(r, None)
            continue
        keys, delta, ops = got
        if mn not in _STORES and not _raw_store(mn):
            for k, dst in zip(keys, ops):
                fresh[canon(dst)] = k
            backs = None
        else:
            backs = []
            for k, src in zip(keys, ops):
                r = canon(src)
                backs.append(not delta and fresh.get(r) == k)
                for other in [o for o, at in fresh.items() if at == k and o != r]:
                    del fresh[other]
        if delta:
            fresh.clear()
        yield i, keys, delta, ops, backs


# ── the lifter ──────────────────────────────────────────────────────────────

class Lifter:
    #: Whether the last `_reload` fell back to the load's own register; see `_reload`.
    _reload_blind = False

    def __init__(self, blocks, pool_map=None, receiver=None, arity=None, dispatch=None,
                 selectors=None, entry=None, fields=None, allocs=None, casts=None):
        self.blocks = blocks
        self.pool_map = pool_map or {}
        #: The displacements an element access is read at, `Target.data_offsets`'s pair
        #: for compressed pointers unless `lift_function` is told otherwise, and per
        #: element address the ones its accesses reach (`_elem_offsets`), made when
        #: first asked.
        self.data_offsets = _data_offsets(None)
        self._elem_box = {}
        #: The lowest field offset the element `_elem_access` last named can be at.
        self._elem_lo = 0
        #: Prints an operand kept as is, and names a range with no name; see
        #: lift_function.
        self.show = None
        # optional register aliases (e.g. {"x1": "this"} for an instance method)
        self.alias = dict(receiver or {})
        #: A value spelled with one of those names, for what a stub that loses the
        #: register has to forget (the type-testing stub below).
        self._entry_word = (re.compile(r"\b(?:" + "|".join(
            map(re.escape, sorted(set(self.alias.values())))) + r")\b")
            if self.alias else None)
        # arity: pc -> callee register-argument count (None if unknown); enables call-site
        # argument reconstruction. The callee's arity is None where it takes an
        # arguments descriptor or reads only stack arguments (entry_arity), and the call
        # then prints `...` or what was pushed; a StackArity where it takes both. A flag
        # for "x4 set in this block" did the job here once and never fired for a `bl`: the
        # call's own clobber of x4 set it, and the call cleared it before reading it.
        # Where it could have fired it would have been wrong, as a descriptor comes with
        # fixed arguments still in x1..xN (#144).
        self.arity = arity
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
        # Field objects (fields.py). Empty by default, which is exactly the pre-existing
        # rendering.
        self.fields = fields or {}
        # allocs: the per-class allocation stubs, pc -> AllocSite
        # (fields.recover_allocations). A `bl` to one of these allocates an instance of a
        # class the snapshot names, so the result is the SECOND base in the register file
        # whose class is read rather than guessed; every other one keeps its offset.
        self.allocs = {} if allocs is None else allocs.by_pc
        #: The names this body minted for such a result, name -> AllocSite. Keyed by TEXT,
        #: which is sound because `_mint` hands each name out once per lift and the only
        #: line that assigns one is the `new` that produced it, so `t7` means that object
        #: wherever it is read. Dropped for a base an access contradicts; see
        #: `_alloc_field`.
        self.alloc_of: dict = {}
        #: Every name that has EVER been one, which `_reads_mem` asks. It only grows,
        #: because a name dropped from the map above is still a name whose dotted reads
        #: were printed, and a value holding one of those still has to go stale with the
        #: memory it reads.
        self._alloc_bases: set = set()
        #: Every recovered name `_field` has printed at each byte offset in this walk,
        #: off any base. `_covers` asks it, because a store and a live read of one slot
        #: can be spelled one by name and one by offset, and the may-alias rule compares
        #: spellings.
        self._named_at: dict = {}
        #: How many names it holds, so what was made of them is made again when one
        #: is added and not at every store (`_pin_mem`).
        self._named_n = 0
        #: The CastClass a cast proves the base of an access an instance of, on every
        #: path to that access, keyed by (instruction address, base register)
        #: (fields.cast_accesses). The THIRD base whose class is read rather than
        #: guessed, and the only one that holds on some edges of a body and not others,
        #: which is why it is keyed by address.
        self.cast_at = casts or {}
        #: The names printed off such a base, which `_reads_mem` asks for the reason it
        #: asks `_alloc_bases`; and the matcher for them, rebuilt when the set grows.
        self._cast_names: set = set()
        self._cast_re = None
        # Block addresses a goto refers to; the renderer defines each exactly once.
        self.labels: set = set()
        self._labelled: set = set()
        #: The labels a way in the entry takes leads to, and the sections no edge leads
        #: into, which `structure` places after the body (#266). None takes every label.
        #: A goto out of such a section into the body is a way in no path from the entry
        #: takes, and what it carries justifies nothing about the others (#237), so it
        #: does not make its target a join the walk meets and names a phi for, nor an
        #: arm it enters one the walk declares phis around: the body prints as it did
        #: with the section left out, and gains the label the goto names.
        self.joinable = None
        self.orphans: frozenset = frozenset()
        #: The blocks before those sections that a goto out of one of them jumps to, and
        #: whether the walk is in them yet. The code past such a label was worked out for
        #: the body's own ways in, so the goto says so (REJOIN); a block that leads
        #: nowhere is printed again under the section instead (`_ends_again`). Meeting
        #: that way in at the label, dropping the body to bare registers there, changed
        #: 641 lines in 49 functions of the clean fixture and is the static meet #237
        #: measured and set aside (#266).
        self.rejoined: frozenset = frozenset()
        self._in_tail = False
        #: The proven entries no edge reaches whose body is lifted as one (#278): the
        #: monomorphic entry and the normal entry its check falls into, each the root of
        #: a dominator tree of its own (`_dom_tree`), and each starting from bare
        #: registers whatever falls into it, since the callers enter it too and the
        #: graph has no edge for them. `placed` is what the first instruction reaches,
        #: `second` what those entries reach that it does not, and `rejoined_second`
        #: the blocks of `placed` a goto out of `second` jumps to, which take the
        #: REJOIN note there as the ones above do from a section. `_in_second`: whether
        #: the walk is in that body now.
        self.roots: tuple = ()
        self.placed: frozenset = frozenset()
        self.second: frozenset = frozenset()
        self.rejoined_second: frozenset = frozenset()
        self._in_second = False
        #: The blocks of the body a goto out of a section `structure` placed past a trap
        #: jumps to, and whether the walk is in one: a section no edge leads into all
        #: the same, which takes the REJOIN note there too (#283). The body goes on after
        #: it, so `_in_tail` says only whether the walk is in a section now.
        self.rejoined_trap: frozenset = frozenset()
        self._in_trap = False
        self._root_of: dict = {}
        # precompute loop metadata reused during the walk
        self._preds = {a: [] for a in blocks}
        for a, b in blocks.items():
            for s in b.succ:
                if s in self._preds:
                    self._preds[s].append(a)
        self.carried = {}    # loop header -> set of carried regs
        #: block -> the comparison it left live, for `_flags_in`.
        self._flags_out: dict = {}
        # (mnemonic, operands, {reg: rendered value}, register set) for the comparison
        # whose result is sitting in the condition flags right now, or None.
        self._flags = None
        # The addresses of the flag-setting instructions whose flags something reads.
        self._flag_reads = frozenset()
        # Registers live after the instruction currently being lifted, as a mask.
        self._live_after = 0
        #: (call reads, live in, live out) per block; see _printed_liveness.
        self._printed = None
        #: The block being lifted and the index of the instruction in it; see _reads_next.
        self._insns, self._at = (), 0
        #: Temporaries minted for a call result. Only these may be folded back into their
        #: use by _inline_single_use; a temp that exists to STOP an expression growing
        #: must not be inlined back into the expression it was cut out of.
        self.results: set = set()
        #: Names _verbatim gave, which _drop_unread leaves out where nothing reads them.
        self.raw_names: set = set()
        #: Registers the printed body has assigned SO FAR in this walk.
        self._printed_regs: set = set()
        #: Registers the printed body assigns ANYWHERE in the function, handed in by the
        #: walk before this one. The growing set above answers "assigned before the walk
        #: reached here", which is the wrong question: a loop body's write happens
        #: before a reload inside the same loop on every trip after the first, and
        #: `_render_loop` RENAMES a carried register rather than writing it, so the
        #: growing set never sees that at all (#199).
        self.printed_prior: frozenset = frozenset()
        #: Phi names whose declaration this walk lifts to the top of the body, because the
        #: walk before it found them read outside the scope `_phi` declared them in (#198).
        self.hoist: frozenset = frozenset()
        #: The ones it actually hoisted, for `_lift_function` to declare.
        self.hoisted: set = set()
        #: The names `State.set` minted for a value too long to inline, shared with the
        #: state so `wants_hoist` can ask for one (#234).
        self.spilled: set = set()
        #: The names `_phi` MINTED. `phi_names` is wider: `_render_loop` and `_join_write`
        #: add to it, and only `_phi` reads `self.hoist`, so deciding off `phi_names` put
        #: names in the set that nothing could act on (#198 review).
        self.phi_minted: set = set()
        #: The names `_name_blind` minted. Hoisted by the same rule as a phi name and for
        #: the same reason: the declaration sits where the load is, which can be inside a
        #: block a later reader is outside of (#198).
        self.blind_named: set = set()
        #: EVERY name `_mint` hands out. `wants_hoist` asks this, so a name is hoistable
        #: whichever site minted it. Before, only `_phi`'s and `_name_blind`'s were
        #: hoistable, and a name any other site minted was not (#204).
        self.minted: set = set()
        #: How many names `_mint` had made before each, for a store into an object
        #: this body allocated to tell the reads made since (`_pin_mem`, #375).
        self._mint_at: dict = {}
        self._mints = 0
        #: Each element this walk read, as (text, lowest offset), and beside it how
        #: many names had been made by then (`_elem_read`). This walk's and not the
        #: body's (`_elem_box`): the count starts again with each walk.
        self._elem_reads: list = []
        self._elem_when: list = []
        #: The registers each spelled record named, so `_lift_function` can tell whether
        #: the prior above would change an answer and pay for the extra walk only then.
        self.spelled_regs: set = set()
        #: entry block, and the memoised dominator tree / per-join kill sets `_join_kill`
        #: needs. Built on first use, because most functions never reach a goto join.
        self.entry = entry if entry is not None else (min(blocks) if blocks else 0)
        self._idom = None
        #: Its numbering (cfg.dom_numbers), which answers `_dominates` in O(1).
        self._dnum = None
        self._killcache: dict = {}
        #: {block: LR holds a return address on entry}, `_lr_return_address`, and {block:
        #: whether it does before each of its rows}, built the first time an access goes
        #: through LR, for the function and for that block (`_holds_ra`); most make none.
        self._lr_in = None
        self._lr_at: dict = {}
        #: The rows before which FP may not hold the frame pointer (`_fp_lost_at`), built
        #: the first time an access goes through FP, and the row being stepped.
        self._fp_lost_set = None
        self._here = None
        #: {temp number: the block its declaration stands in}, and the block lifted last,
        #: for the goto join in `walk`.
        self._anchor: dict = {}
        self._last_block = None
        self._loop_before = None
        #: Whether a frame address ever reaches a general register; see _frame_escaped.
        self._escaped = None
        #: {store: registers that may hold a frame address there}; see _frame_taint.
        self._taint = None
        #: (address, slot) of the frame stores that name their value; see _slot_crossings.
        self._crossings = None
        #: The names those stores gave; see _lift_function.
        self.slot_names: set = set()
        #: Names `_phi` and `_render_loop` bind at a join or loop header (#169).
        self.phi_names: set = set()
        #: ({slot: bit}, {block: (live, crossing) masks}) from _slot_crossings, and the
        #: block order its worklist runs in; see _backward.
        self._slot_live = ({}, {})
        self._rank = None
        #: Blocks no path runs to the end of (_ends_path), the dominators of the graph
        #: where they end and their numbering, and each block's frame stores; see
        #: _loop_rewrites and _trip_nodes.
        self._ended = self._ridom = self._rnum = self._spills = self._wide = None
        #: The stack checks' slow paths strip_boilerplate took the branch to; see
        #: _quiet.
        self.slow_paths: frozenset = frozenset()
        #: The frame stores that may write a slot off the other frame register
        #: (_frame_meets). _lift_function works them out; the graph alone does not show
        #: where SP is.
        self.frame_meets: frozenset = frozenset()
        #: The frame moves `_step` does not see, and the addresses of those of FP
        #: (_frame_moves). _lift_function works them out.
        self.frame_moves: dict = {}
        self.fp_moves: frozenset = frozenset()
        #: Calls whose stack pushes are saved registers, not arguments (#147); see
        #: _save_wrapped_calls. _lift_function works them out.
        self.save_wrapped: frozenset = frozenset()
        self.frame_joins: frozenset = frozenset()
        #: {store through SP or FP: (SP less where its frame starts, slack) or None};
        #: see _frame_plan and _cross_write.
        self.frame_cross: dict = {}
        #: address -> where SP sits there against the frame the function was entered
        #: with, exact only (None where unknown or merely bounded by an alignment) (#207).
        self.sp_at: dict = {}
        #: address -> how far FP is from where its frame started, where that is not 0;
        #: None where `_frame_plan` did not follow FP through the function (#340).
        self.fp_at = None
        #: (join, whether as a loop's entry) -> the frame roles moved on a way into it
        #: (_join_kill).
        self._killroles: dict = {}
        #: The rows that write a frame register or are one of `frame_moves`, each with
        #: (whether it writes FP, how far it moves SP, None for not known): a value
        #: naming the register is seen to before each (`_frame_shift`).
        self.shift_rows: dict = {}
        #: FP's machine name where `fp_at` is kept, for `_leaf`.
        self._fp_leaf = None
        self._sp_reg, self._fp_reg = _frame_regs()
        #: The instructions strip_boilerplate changed, as they were (_lift_function).
        self.raw: dict = {}
        self._trips: dict = {}
        self._bodies: dict = {}
        #: Per header and per block, what nested loops ask again for each loop around
        #: them; see _loop_nodes, _written, _accesses and _reload_step (#162).
        self._loops: dict = {}
        #: per block, what `_exit_slots` asks of every block that can reach it; see
        #: _near_written. And per block, which strongly connected piece of the graph it
        #: is in; see _pieces.
        self._near: dict = {}
        self._piece: dict = {}
        self._piece_order: list = []
        #: loop header -> its natural body; see _back_loop. The LoopNest that builds
        #: them, the one `_trip_nodes` builds its own with, and what each rooted body's
        #: blocks read and leave written; see _loop_live_in.
        self._backloops: dict = {}
        self._bnest = self._tnest = None
        #: Whether the loops asked for so far were walked through more than _NEST_AFTER
        #: times the function's blocks, which takes loops nested deeper than that: only
        #: then are bodies built as a nest and folded, and the dicts for it made, as a
        #: loop by itself or a few deep is cheaper walked (_go_nested). Before that,
        #: how many blocks the bodies and the trips walked.
        self._nested = False
        self._looped = self._tripped = 0
        #: loop header -> the blocks it can reach while it runs; see _loop_region. And
        #: per block, what its subtree of `_idom` writes; see _region_written.
        self._regions: dict = {}
        self._own_sub: dict = {}
        #: what `_join_kill` asks of the blocks between a join and its dominator, folded
        #: over the dominator tree once; see _kill_fold.
        self._kfold = None
        self._kwalked = 0
        #: the slots `_pin_mem` has walked, and how many it walks before it keeps what
        #: a store did not write (`_PIN_WALK`), made at the first store with a slot.
        self._pin_walked, self._pin_budget = 0, None
        #: what `_pin_mem` keeps of this walk: per edge, the selectors of the named
        #: fields past it, and per kind of store, the slot texts it does not write.
        self._past_at: dict = {}
        self._unread: dict = {}
        self._defs: dict = {}
        #: per block, whether it stores where `_writes_stack`, `_writes_heap` and
        #: `_writes_outgoing` ask, calls (`_CALLS`, or `bl`/`blr`), or what `_exit_slots`
        #: makes of its stores; see _any_block.
        self._stack_blocks = self._heap_blocks = self._out_blocks = None
        self._call_blocks = self._bl_blocks = self._thru_blocks = None
        self._slot_stores = self._folds = self._livesum = self._usedef = None
        self._quiet_set = None
        self._frame_list: dict = {}
        self._reload_ops: dict = {}
        #: (header, {reg: name}, copied) for each loop being walked, innermost last. An
        #: exit inside the body has to write the carried names back itself; see _carry_out.
        self._carrying: list = []
        #: Registers `_phi` has written out as a statement. A bare register is normally the
        #: honest spelling for "whatever the machine has there", and for these it is not:
        #: the printed body has assigned that name, so a reader takes it as that value.
        #: block -> the state the walk left it in, for _reenter.
        self._exit: dict = {}
        #: block -> the state the goto to it left, after its write-back; see _arrive.
        self._came: dict = {}
        #: For `_arrive`: block -> the names written back by the `break` it left a loop
        #: by, and loop header -> the blocks that broke out of it.
        self._broke: dict = {}
        self._breakers: dict = {}
        #: The values `_arrive` wrote out before a write-back, name -> (target, "reg" or
        #: "slot", key), and which of them to write out, None for all; see _lift_function.
        self.pins: dict = {}
        self.keep = None
        #: loop header -> registers to carry beyond what liveness says, the ones this
        #: walk found a break holding something else in, and the names the carried ones
        #: got; see _render_loop and _lift_function.
        self.carry_more: dict = {}
        self.exit_hazards: dict = {}
        #: loop header -> {register: the value _render_loop forgot it to at the header},
        #: for each register the loop writes and does not carry; see _note_goto.
        self._unset: dict = {}
        self.carry_names: dict = {}
        #: A goto-reached join (addr with >1 predecessors) is the one join `_merge`/`_phi`
        #: never saw, and `_join_kill` drops its disagreed registers to bare, which reads
        #: as the last printed line put them: a raw line's or a value a loop lost (#123).
        #: A first walk records {join addr -> registers it may need a phi for}; the second
        #: builds one, a name written on every edge in and read at the join, like `_phi`
        #: does for the if/else join. See _join_write and the `join` branch of walk.
        self._join_phi_set: dict = {}
        #: Input to the second walk, as `carry_more` is: join addr -> registers to phi.
        self.join_phi: dict = {}
        #: (join addr, register) -> the name its phi is bound to, minted once and written
        #: by every edge into the join; and which edges have written it, so the join binds
        #: the register to the name only where every way in set it.
        self._join_name: dict = {}
        self._join_wrote: dict = {}
        self._loads = None
        #: () -> "x0" | "d0" | None, what this function's callers read its result from;
        #: and, built at the first `ret`, the register each `ret` hands back (#115).
        self.returns = None
        self._ret_regs = None
        #: () -> "x0" | "d0" | None, what the other implementations of its selector
        #: return in, asked only where no caller speaks (_return_registers).
        self.table = None
        #: the same resolver for any address, for the calls this function makes; and
        #: which of them have their double read (_d0_result_reads).
        self.callees = None
        self._d0_calls = None

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
        and change no output. LR is one that would: untouched, it renders as `LR`, the
        function's return address, and the call has just put its own there (#162).
        """
        touched = (set(st.reg) | set(st.elem) | set(st.poolbase) | set(st.pair)
                   | set(st.pair.values()) | set(self.alias) | {_lr()})
        # A V register is clobbered under every spelling: `ldr q0; bl f; str q0` printed
        # the load as what was stored (#114).
        # `_call_forgets` is the one list, read by `_elem_offsets` too (#308).
        gone = _call_forgets("blr", "")
        for r in sorted(r for r in touched if r in gone
                        or (_fp_n(r) is not None and f"d{_fp_n(r)}" in gone)):
            st.forget(r)
        # ...and the call DEFINES each one it destroyed that is read again, with a name
        # for a value nobody knows. `forget` leaves the register holding its own bare
        # name, and the printed body never assigns that, so it reads as the value the
        # function came in with: `f(this); x1.field_0x8 = x2;` says the entry x2 where the
        # machine has whatever `f` left. A fresh name says the one true thing instead,
        # that the value is not known, and it cannot be confused with an argument.
        #
        # This is what every decompiler does rather than reuse the register's name.
        # Ghidra emits an INDIRECT at the call, "a placeholder for possible indirect
        # effects... used for SSA construction", whose output carries nothing through from
        # before it; GCC's RTL SSA makes a clobber a definition in its own right, marking
        # the register as holding an unknown value. It is also `_phi_name`'s own rule,
        # "always a FRESH one, never the register", at a third site (#176, #198, #206).
        #
        # Only the ones liveness says are read again, which is what keeps it to a handful
        # per call site rather than forty.
        # Not the return registers: the call's own result is `_result`'s to name, and
        # minting here would hand out a name it overwrites one line later.
        rets = {_T.ret_int, _T.ret_fp} - {None}
        out = []
        for r in sorted(_CALL_CLOBBERS - rets):
            if not (self._live_after & _reg_mask((r,))):
                continue
            name, decl = self._mint(st)
            if decl:
                out.append(decl)
            # So the pass that drops what nothing reads can take it: liveness says the
            # register is read again, and a later pass can still take that reader away.
            self.raw_names.add(name)
            st.reg[r] = V(name, P_ATOM)
            st.lost.discard(r)
        return out

    def _pin_call(self, st: State, dying=None) -> list:
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

        Registers only. A frame slot holding a memory read has the same problem, and is
        named where it is stored rather than here; see `_slot_crossings` (#64). Dropping
        every slot at a call was tried first: the outgoing area is what `_stack_args`
        reconstructs a stack-convention call's arguments from, so emptying it cost
        `benchDecodeFlag` the literal semdiff pins it on.

        A store `_step` prints raw asks the same question, with `dying` the registers it
        writes in place of the call's (_raw_write).
        """
        dying = _CALL_CLOBBERS if dying is None else dying
        out = []
        for key, v in sorted(st.reg.items()):
            if key in dying or not self._reads_mem(v.text):
                continue
            if not (self._live_after & _reg_mask((key,))):
                continue
            tmp, decl = self._mint(st, v.text)
            out.append(decl)
            st.reg[key] = V(tmp, P_ATOM, smi=v.smi, calc=v.calc)
        return out

    def _call_reads(self, insns) -> dict:
        """{index: the registers the call there prints, as a mask} for one block.

        `_def_use` says a direct call reads no register, which is what the machine needs
        and not what the printed body does: `_call_args` spells the callee's register
        arguments when its arity is known, and a throw prints x0. A value reloaded from a
        slot only to be passed to a call is read by the reader, and `_slot_crossings` has
        to count it (#64): `handleMessage` reloads a spilled field to pass it on, and the
        argument printed as a fresh read of the field after the calls in between. The
        tests `_call_args` makes that the block shows: a stub, an arity it cannot read, a
        StackArity short of six registers, handed a double or whose reach is not known.
        The other ones, an argument register the walk holds no value for and fewer values
        pushed than a StackArity reads, are decided by the walk, and a call that prints
        `...` for them counts its reads all the same; the cost is a name nothing reads. An
        indirect call needs nothing here: liveness already sees it read its target, and a
        dispatch call's receiver is read by the class id load in front of it."""
        out = {}
        for i, (_a, mn, op, note) in enumerate(insns):
            if mn != "bl":
                continue
            name = note.split("-> ", 1)[1].strip() if "-> " in note else None
            ops = _split_ops(op)
            target = _imm(ops[0]) if ops and ops[0].startswith("#") else None
            if name and "_iso_stub_" in name:
                if _classify_stub(name)[0] == "throw":
                    out[i] = _reg_mask((_T.ret_int,))
            elif not (name and "stub" in name) and self.arity is not None and (
                    target is not None):
                k = self.arity(target)
                if k and not (isinstance(k, StackArity) and (  # `...`; _call_args
                        k < len(ARG_REGS) or k.fpu or k.need is None)):
                    out[i] = _reg_mask(ARG_REGS[:k])
        return out

    def _slot_crossings(self) -> frozenset:
        """(address, slot) for each frame store whose slot is read back after a call.

        The frame-slot half of `_pin_call`. A slot keeps the TEXT of what was stored in
        it, and when that text reads memory a reload on the far side of a call prints a
        field the callee may have rewritten. `_CompactLinkedHashBase.forEach` saves
        `_data`'s length in a slot, calls the user's callback, and throws if the length
        changed; with the slot spelled as the field the guard reads `this.field_0xc !=
        this.field_0xc` (#64).

        Slots have no register liveness, so this is the same backward dataflow done over
        slot keys: a slot is LIVE where a load of it is reachable with no store to it in
        between, and CROSSING where such a load is reachable through a call. A store into
        a crossing slot is where the value gets its name. At the store, and not at the
        call, for two reasons measured on the clean build. Naming at the call put a
        declaration in front of every call a spilled value outlives (14,294 of them) where
        one per store does. And a store before a loop or an `if` is outside it, so the
        name is bound once on a path every use is on; naming at a call inside one arm
        made the arms disagree at the join, and inside a loop body it would re-read the
        field on each trip, which the machine does not do.

        Only the calls `_pin_call` runs for count: a runtime stub keeps or does not touch
        the heap a spilled read came from. Keys and frame moves are worked out exactly as
        `_step` does, so a slot this misses is one the walk would not have kept either.
        """
        if self._crossings is not None:
            return self._crossings
        bit: dict = {}
        events = {}
        reads = live_out = None
        for b, blk in self.blocks.items():
            ev, after = [], None
            frame = {t[0]: t[1:]
                     for t in _frame_accesses(blk.insns, moves=self.fp_moves)}
            for i, (a, mn, op, note) in enumerate(blk.insns):
                if mn in _CALLS:
                    name = note.split("-> ", 1)[1].strip() if "-> " in note else None
                    if not (mn == "bl" and name and "_iso_stub_" in name):
                        ev.append(("call", a, 0))
                    continue
                got = frame.get(i)
                if got is None:
                    continue
                keys, delta, ops, backs = got
                for k in keys:
                    bit.setdefault(k, 1 << len(bit))
                if backs is not None:
                    # `_step` drops the slots the move made stale, THEN stores. A store
                    # that writes back what was reloaded from the slot is no store here:
                    # the value the next reload sees is still the one stored before, and
                    # that is the store the name belongs to. `ldur x24, [k]; bl; stur x24,
                    # [k]` round a loop otherwise hid the store in front of it, and the
                    # field it spilled was read again inside the loop.
                    if delta:
                        ev.append(("kill", a, 0))
                    for k, back in zip(keys, backs):
                        if not back:
                            ev.append(("store", a, bit[k], k))
                    continue
                # A reload counts only where the register it fills is read, the rule
                # `_pin_call` applies to a register: a name for a spill nothing reads
                # would be a declaration for nothing. Read as the printed body reads,
                # with a call's printed arguments counted (`_call_reads`).
                if after is None:
                    if live_out is None:
                        reads, _li, live_out = self._printed_liveness()
                    more = reads[b]
                    after, m = [0] * len(blk.insns), live_out.get(b, 0)
                    for k in range(len(blk.insns) - 1, -1, -1):
                        after[k] = m
                        de, us = _def_use_masks(blk.insns[k][1], blk.insns[k][2])
                        m = us | more.get(k, 0) | (m & ~de)
                for k, dst in zip(keys, ops):
                    if after[i] & _reg_mask((canon(dst),)):
                        ev.append(("load", a, bit[k]))
                if delta:
                    ev.append(("kill", a, 0))
            if ev:
                events[b] = ev

        def back(b, live, cross, hits=None):
            for e in reversed(events.get(b, ())):
                kind, m = e[0], e[2]
                if kind == "load":
                    live |= m
                elif kind == "call":
                    cross |= live
                elif kind == "store":
                    if hits is not None and cross & m:
                        hits.add((e[1], e[3]))
                    live &= ~m
                    cross &= ~m
                else:
                    live = cross = 0
            return live, cross

        def out_of(b):
            lo = co = 0
            for s in self.blocks[b].succ:
                sl, sc = live_in.get(s, (0, 0))
                lo |= sl
                co |= sc
            return lo, co

        found: set = set()
        live_in: dict = {}
        if bit:
            self._backward(lambda b: back(b, *out_of(b)), live_in, (0, 0))
            for b in events:
                back(b, *out_of(b), found)
        self._crossings = frozenset(found)
        self._slot_live = (bit, live_in)
        return self._crossings

    def _backward(self, step, live_in: dict, empty) -> None:
        """Run a backward dataflow to its fixed point: `step(b)` is block b's answer from
        what `live_in` says of its successors, and `live_in` is filled in place.

        A worklist in postorder, not the repeated sweeps of `_liveness`. A fact crosses
        one block per sweep along a chain of backward branches, so sweeping costs blocks
        times chain length: on a crafted 3,903-instruction chain the register half of
        `_slot_crossings` took 0.19 s that way, as long as the whole lift takes on main,
        and takes 0.002 s this way. Successors first, and a block again only when a
        successor's answer changed."""
        if self._rank is None:
            self._rank = self._postorder()
        rank = self._rank
        work = [(rank[b], b) for b in self.blocks]
        heapq.heapify(work)
        queued = set(self.blocks)
        while work:
            _r, b = heapq.heappop(work)
            queued.discard(b)
            got = step(b)
            if got != live_in.get(b, empty):
                live_in[b] = got
                for p in self._preds.get(b, ()):
                    if p not in queued:
                        queued.add(p)
                        heapq.heappush(work, (rank[p], p))

    def _returned(self) -> dict:
        """{ret address: "x0" or "d0"}, which register each `ret` hands back; see
        _return_registers and make_return_resolver."""
        if self._ret_regs is None:
            self._ret_regs = _return_registers(self.blocks, self.entry, self.returns,
                                               _d0_callee(self.callees), self.table)
        return self._ret_regs

    def _d0_read(self, addr) -> bool:
        """Whether what the call at `addr` leaves in d0 is read, where it is a call to a
        function that returns d0; see _d0_result_reads."""
        if self._d0_calls is None:
            self._d0_calls = _d0_result_reads(self.blocks, self.entry, self._returned(),
                                              _d0_callee(self.callees), self.roots)
        return addr in self._d0_calls

    def _ret_use(self, addr, us: int) -> int:
        """What the `ret` at `addr` reads as the printed body reads it: the register it
        hands back, where that is decided, and not the other one too. A `ret` read both,
        so d0 looked live up to it in a function that returns `NULL`, and every join on
        the way took a phi for it that nothing reads."""
        got = self._returned()
        if not got:
            # d0 is never written, or nothing decides it and a `ret` on d0 prints the
            # bare register, which reads no value: x0 is the one it prints a value of.
            return _reg_mask((_T.ret_int,))
        reg = got.get(addr)
        return _reg_mask((reg,)) if reg else us

    def _printed_liveness(self) -> tuple:
        """({block: _call_reads}, live in, live out): each block's live registers as
        `_liveness` has them, with a call's printed arguments counted as its reads. That
        is what the printed body reads. A value read only as a call's argument was dead
        to `_liveness`, so a raw line overwriting a register it is spelled with did not
        name it first: `foo(x1, x1 + 1)` printed the new x1 in the second argument (#122).
        """
        if self._printed is None:
            reads = {b: self._call_reads(blk.insns) for b, blk in self.blocks.items()}
            use, dfn = {}, {}
            for b, blk in self.blocks.items():
                u = d = 0
                more = reads[b]
                for i, (a, mn, o, _n) in enumerate(blk.insns):
                    de, us = _def_use_masks(mn, o)
                    if mn == "ret":
                        us = self._ret_use(a, us)
                    u |= (us | more.get(i, 0)) & ~d
                    d |= de
                use[b], dfn[b] = u, d
            live_in: dict = {}

            def step(b):
                lo = 0
                for s in self.blocks[b].succ:
                    lo |= live_in.get(s, 0)
                return use[b] | (lo & ~dfn[b])
            self._backward(step, live_in, 0)
            self._printed = (reads, live_in, {
                b: _or_all(live_in.get(s, 0) for s in self.blocks[b].succ)
                for b in self.blocks})
        return self._printed

    @property
    def _livein(self) -> dict:
        return self._printed_liveness()[1]

    @property
    def _liveout(self) -> dict:
        return self._printed_liveness()[2]

    def _loop_rewrites(self, header, st: State) -> list:
        """The slots the loop at `header` may come round to holding something new (#109).

        A loop's walk starts from the state before it, so a slot keeps its pre-loop text
        at the top of the body. That is right for a slot the loop only reads, and for one
        it writes back unchanged, the invariant spill: `this` saved before a loop and
        saved again around a call inside it. It is wrong for a slot the loop stores a new
        value to and reads at the top of the next trip, where every trip then printed the
        first trip's value: a counter kept in a slot read `(1 + 1) >= 0xa` and never
        ended. These are forgotten at the header, so the reload prints its register.

        Forgetting every slot a loop stores to was measured first: 6,383 changed lines on
        the clean fixture, and the sample was mostly invariant spills that printed right
        before and a bare register after. So a store counts only where its value cannot
        be shown to be the one already there: its register was reloaded from that slot in
        the same block and not changed since, or the loop never writes the register and
        it held the slot's value on the way in.

        And only a store that comes round to the header. Tier 3 keeps the edge past a
        trap, and a throw stub with nothing after it falls into the next block, often a
        stack-overflow slow path that jumps back to a check (#64): loops the machine never
        runs again, whose stores set up a throw. With `_ends_path` saying no to every
        instruction, this rule changes 105 functions on the clean fixture, a sample of
        them printing a register where `this` was right. So the loop here is the natural
        loop of the graph where a block holding a trap or a throw ends: the latches are
        the predecessors the header dominates there, and the body is what reaches one
        without passing the header. That changes no line of the two fixtures or of the
        2.19.6, 3.4.4 and 3.10.9 corpus builds, and still forgets the counter.

        Only slots live at the header count, from `_slot_crossings`' dataflow; the others
        are stored before the loop reads them, and the walk sees the store."""
        self._slot_crossings()
        bit, live_in = self._slot_live
        live = live_in.get(header, (0, 0))[0]
        keys = [k for k in st.slot if bit.get(k, 0) & live]
        if not keys:
            return []
        nodes = self._trip_nodes(header)
        if not nodes:
            return []
        if self._any_block(self._thru_blocks, self._thru_block, nodes):
            return keys
        written, new = None, set()
        held, wide = set(keys), self._wide_slots()
        fp = next((r for r, v in _T.roles.items() if v == "FP"), None)
        for b in nodes:
            got = self._spills.get(b)
            if got is None:
                got = self._spills[b] = self._block_spills(b)
            if got is False:
                return keys               # the frame moves inside a loop: claim nothing
            for k, r, back, width in got:
                # A store over part of another slot changes it, whatever it stores (#162).
                lo = int(k[len(fp):])
                for off in range(lo - 15, lo + width):
                    o = f"{fp}{off:+d}"
                    if o != k and o in held and (off > lo - 8 or o in wide):
                        new.add(o)
                if back or k not in st.slot:
                    continue
                if written is None:
                    written = self._written(nodes)
                if r in written or self._leaf(r, st) != st.slot[k]:
                    new.add(k)
        return [k for k in keys if k in new]

    def _trip_nodes(self, header) -> frozenset:
        """The blocks a second trip round the loop at `header` runs, or none.

        The natural loop of the graph where a block holding a trap or a throw ends: the
        latches are the predecessors the header dominates there, and the body is what
        reaches one without passing the header. Empty where no latch comes round, a loop
        that only the edge past a trap makes, which the machine never runs twice; see
        _loop_rewrites."""
        got = self._trips.get(header)
        if got is not None:
            return got
        if self._ridom is None:
            ended = self._ended_blocks()
            self._ridom = dominator_forest(
                self.blocks, self.entry, lambda n: () if n in ended
                else self.blocks[n].succ if n in self.blocks else (), self.roots,
                self.placed)[0]
            self._rnum = dom_numbers(self._ridom)
            self._spills = {}
        idom, ended, num = self._ridom, self._ended, self._rnum

        def dominated(n):
            # The header, or a block it is above in its tree: its idom chain reaches the
            # header before a root. In O(1) from the numbering (#282).
            if num is not None:
                pre, end = num[0], num[1]
                return n == header or (header in pre and n in pre
                                       and pre[header] <= pre[n] < end[header])
            while n != header:
                up = idom.get(n)
                if up is None or up == n:
                    return False
                n = up
            return True
        latches = [p for p in self._preds.get(header, ())
                   if p not in ended and dominated(p)]
        if not latches:
            got = self._trips[header] = frozenset()
            return got
        if not self._nested:
            nodes, stack = {header}, latches[:]
            while stack:
                n = stack.pop()
                if n not in nodes and n not in ended:
                    nodes.add(n)
                    stack.extend(self._preds.get(n, ()))
            self._tripped += len(nodes)
            if self._tripped <= _NEST_AFTER * len(self.blocks):
                got = self._trips[header] = frozenset(nodes)
                return got
            self._go_nested()
        nest = self._tnest
        if nest is None:
            # As `_back_loop` builds its bodies (#332), over `_ridom`.
            nest = self._tnest = LoopNest(self._preds, lambda _h, n: n not in ended, num)
            nest.prepare([h for h, ps in self._preds.items()
                          if any(p != h and nest.above(h, p) for p in ps)],
                         self._trip_nodes)
            got = self._trips.get(header)
            if got is not None:
                return got
        got = self._trips[header] = nest.closure(header, latches)
        return got

    def _ended_blocks(self) -> set:
        """The blocks holding a trap or a throw, which no path runs to the end of."""
        if self._ended is None:
            self._ended = {b for b, blk in self.blocks.items()
                           if any(_ends_path(t[1], t[3]) for t in blk.insns)}
        return self._ended

    def _trip_body(self, header) -> frozenset:
        """Those of `_trip_nodes` the header reaches. A stack check's slow path that
        strip_boilerplate cut off still jumps back into the loop, and its call would
        count as writing every register the stub gives back."""
        got = self._bodies.get(header)
        if got is not None:
            return got
        trip = self._trip_nodes(header)
        nest = self._tnest
        if trip and nest is not None and header in nest.good and (
                nest.body[header] is trip):
            # Rooted: the header reaches every block of it inside it (LoopNest), so the
            # walk below would gather it all, one block at a time per loop (#332).
            self._bodies[header] = trip
            return trip
        seen, stack = set(), [header] if trip else []
        while stack:
            n = stack.pop()
            if n not in seen:
                seen.add(n)
                stack.extend(s for s in self.blocks[n].succ if s in trip)
        got = self._bodies[header] = frozenset(seen)
        return got

    def _reloads(self, header, trip, st: State, regs) -> set:
        """Those of `regs` that every trip round the loop at `header` puts back the value
        they had before it into, reloaded from a frame slot that held it then (#154).

        `_render_loop` forgets at the header each register the loop writes. One the trip
        writes only with what it had is the exception: a call takes x6 in `compareTo`
        and the trip reloads it from the slot the comparison was saved in, so the value
        from before the loop was right at a goto out of it, and forgotten it printed a
        bare `x6`. So a must-analysis over the trip of which value each register holds,
        where a value is what an FP slot held before the loop, and a register gets one by
        a 64-bit load of the slot or a move from a register that holds one. A register
        keeps its value where it held it before the loop, and the way in and every latch
        hand it the same one.

        A slot counts where the trip stores no byte of it, and only while the frame stays
        put: nothing in the trip writes FP, loads or stores with a write-back to it, or
        stores through an index off it, and no frame address reaches a register anywhere
        in the function. No store narrower than 8 bytes may fill it (_reload). And only a
        value whose text names no register and reads no
        memory: one spelled the same can be a different value where a register or the heap
        changed in between. Slots of one text hold one value, so a register holds at most
        one, a block costs its length, and with the header dominating the trip, reverse
        postorder settles in a few rounds."""
        fp = next((r for r, v in _T.roles.items() if v == "FP"), None)
        if fp is None or self._frame_escaped() or fp in self._written(trip):
            return set()
        held = {}                       # FP slot -> the text of its value
        narrow, files = self._narrow_slots(), self._slot_widths()[4]
        for k, v in st.slot.items():
            if (k.startswith(fp) and k[len(fp):][:1] in "+-" and k not in narrow
                    and len(files.get(k, ())) == 1
                    and not _ANY_REG.search(v.text) and not self._reads_mem(v.text)):
                held[k] = v.text
        # A trip only drops what is held, so where no register holds one of these
        # already there is nothing to ask of the trip's blocks (#332).
        values = set(held.values())
        if not any(st.get(r).text in values for r in regs):
            return set()
        for b in trip:
            insns = self.blocks[b].insns
            for i, keys, delta, ops, backs in self._accesses(b):
                if delta:
                    return set()
                if backs is not None and held:
                    lo = int(keys[0][len(fp):])
                    _drop_stored(held, fp, lo,
                                 lo + _access_width(insns[i][1], ops[0]) * len(keys))
        values = set(held.values())
        start = {}
        for r in regs:
            v = st.get(r)
            if v.text in values:
                start[r] = v.text
        if not start:
            return set()
        post, seen, stack = [], {header}, [(header, iter(self.blocks[header].succ))]
        while stack:
            n, it = stack[-1]
            for s in it:
                if s in trip and s not in seen:
                    seen.add(s)
                    stack.append((s, iter(self.blocks[s].succ)))
                    break
            else:
                post.append(n)
                stack.pop()
        out: dict = {}
        changed = True
        while changed:
            changed = False
            for b in reversed(post):
                ins = [out[p] for p in self._preds.get(b, ()) if p in trip and p in out]
                if b == header:
                    ins.append(start)
                got = self._reload_step(b, _agree(ins), held)
                if out.get(b) != got:
                    out[b] = got
                    changed = True
        return set(_agree([start] + [out[p] for p in self._preds.get(header, ())
                                     if p in trip]))

    def _reload_step(self, b, facts: dict, held: dict) -> dict:
        """`facts`, {register: the slot value it holds}, after block `b`; see _reloads.
        A 64-bit load or move copies all 64 bits, from a general register or an FP one
        alike, and any other write, a wider load's included, ends what it held."""
        facts = dict(facts)
        steps = self._reload_ops.get(b)
        if steps is None:
            steps = self._reload_ops[b] = []
            for (_a, mn, op, _n) in self.blocks[b].insns:
                ops = _split_ops(op) if mn in ("mov", "fmov") else ()
                if len(ops) == 2 and _REG_ONLY.match(ops[1].strip()):
                    steps.append((canon(ops[0]), canon(ops[1]), ()))
                    continue
                got = _frame_access(mn, op) if mn in ("ldr", "ldur", "ldp") else None
                steps.append((None, _def_use(mn, op)[0], [
                    (k, canon(o)) for k, o in zip(got[0], got[2])
                    if o.strip()[:1] in ("x", "d")] if got is not None else ()))
        for dst, src, loads in steps:
            if dst is not None:                 # a move from a register
                v = facts.get(src)
                facts.pop(dst, None)
                if v is not None:
                    facts[dst] = v
                continue
            for r in src:                       # what the instruction writes
                facts.pop(r, None)
            for k, r in loads:
                if k in held and self._slot_widths()[4][k] == {_reg_file(r)}:
                    facts[r] = held[k]
        return facts

    def _block_spills(self, b):
        """(slot, register, written back, bytes) for each frame store in block `b`
        before anything ends its path, or False when the block moves the frame. Written
        back means the value already there; see _frame_accesses and _loop_rewrites."""
        out = []
        insns = self.blocks[b].insns
        for i, slots, delta, ops, backs in _frame_accesses(insns, True, self.frame_meets,
                                                           self.fp_moves):
            if delta:
                return False
            if backs is not None:
                out.extend((k, canon(r), back, _access_width(insns[i][1], r))
                           for k, r, back in zip(slots, ops, backs))
        return out

    def _postorder(self) -> dict:
        """Each block's rank in a depth-first postorder from the entry, successors first.
        Blocks the entry does not reach rank after every block it does."""
        rank, seen = {}, set()
        for root in [self.entry] + sorted(self.blocks):
            if root in seen or root not in self.blocks:
                continue
            seen.add(root)
            stack = [(root, iter(self.blocks[root].succ))]
            while stack:
                n, it = stack[-1]
                for s in it:
                    if s in self.blocks and s not in seen:
                        seen.add(s)
                        stack.append((s, iter(self.blocks[s].succ)))
                        break
                else:
                    rank[n] = len(rank)
                    stack.pop()
        return rank

    def _name_slot(self, st: State, at, key: str, reg: str, v: V, named: dict) -> list:
        """Store `v` into frame slot `key`, giving it a name first if it has to have one.

        A name is given where the value reads memory and `_slot_crossings` says the slot
        is reloaded after a call. The register stored from holds the same value, so it
        takes the name too: it is what `_pin_call` would otherwise name a second time if
        it survives the call. `named` carries a name across the two halves of an `stp`
        that spill one value twice."""
        fp = next((r for r, vv in _T.roles.items() if vv == "FP"), None)
        if reg in st.lost and fp is not None and key.startswith(fp):
            # A value a join lost, spilled to a frame slot: its bare name will mean
            # something else once the register is reassigned, so the slot is tied to that
            # register and dropped then, and a reload reads the register afresh (#140).
            # While the register still holds it, the slot reads right. Only an FP spill,
            # not the outgoing area (SP), whose arguments a call reads before any reassign
            # and `_drop_outgoing` clears.
            st.slot[key] = v
            st.lost_slot[key] = reg
            st.note_slot(key, v)
            return []
        st.lost_slot.pop(key, None)
        # A value that names SP is given a name where it is spilled: the slot outlives
        # the next move of SP, and the text would then read as SP there (#340).
        off_sp = _names_frame(v, "SP")
        if not off_sp and (
                (at, key) not in self._slot_crossings() or not self._reads_mem(v.text)):
            st.slot[key] = v
            if fp is not None and key.startswith(fp):
                st.note_slot(key, v)
            return []
        out = []
        tmp = named.get(v.text)
        if tmp is None:
            tmp, decl = self._mint(st, v.text)
            named[v.text] = tmp
            # Not a slot name where it names SP: one is folded back into the statement
            # after it, and SP may move between the two.
            (self.raw_names if off_sp else self.slot_names).add(tmp)
            out.append(decl)
        if st.reg.get(reg) == v:
            st.reg[reg] = V(tmp, P_ATOM, smi=v.smi, calc=v.calc)
        st.slot[key] = V(tmp, P_ATOM, smi=v.smi, calc=v.calc)
        return out

    # leaf rendering
    def _leaf(self, reg: str, st: State) -> V:
        # A `w` operand reads the low 32 bits, so a value a 32-bit destination truncated
        # is read back untruncated: this consumer drops the same bits anyway, and if it
        # writes a w register of its own `_step` truncates the result once at the end
        # (#235). Nothing else looks at `V.wide`, so a 64-bit read sees the truncation.
        narrow = reg.strip()[:1] == "w"
        reg = canon(reg)
        if reg in self.alias and reg not in st.reg:
            return V(self.alias[reg], P_ATOM)
        v = st.get(reg)
        if reg == self._fp_leaf:
            # FP where an FFI or a leaf call's frame has moved it: an address off `FP`
            # is one off where the frame started, as an access through it is, and
            # `_frame_plan` knows how far FP is from there at this row whatever the
            # walk holds for the register (#340). Not where FP holds another value.
            got = _role_sum(v, "FP")
            if got is not None:
                v = _off_role(got[0], self.fp_at.get(self._here, 0), False, None)
        return v.wide if narrow and v.wide is not None else v

    def _sub(self, pc_offset: int) -> str:
        """A range with no name, as every other surface names it (disasm.sub_label)."""
        label = getattr(self.show, "label", None)
        return label(pc_offset) if label is not None else f"sub_0x{pc_offset:x}"

    def _raw(self, st: State, dst: str, mn: str, op: str) -> list:
        """Emit the instruction verbatim and forget what its destination held.

        The same thing the unmodelled-instruction fallthrough does, reached earlier when a
        modelled instruction turns out to carry an operand we cannot render.
        """
        return self._verbatim(st, mn, op, op, dst)

    def _verbatim(self, st: State, mn: str, op: str, shown: str, dst: str = "",
                  keep=frozenset()) -> list:
        """The instruction printed as it is, and every register it writes forgotten.

        The printed body reads the line as having run, so from there on a register it
        writes means what the machine put in it. A value the lifter still holds that is
        spelled with one of them would read as the new value: `add x5, x1, #1; subs x1,
        x1, #8; str x5` printed `x1 + 1` for the old x1 (#118). Each such value still read
        later is named first, `var t0 = x1 + 1;`, as _pin does before a base moves.

        It reads the machine registers it names, and a register the lifter holds as an
        expression was never assigned in the printed body: `add x1, x1, #8; adcs x1, x1,
        x3` printed the `adcs` alone, which reads as working on the entry x1 (#120). The
        line says what each register it reads holds, `adcs x1, x1, x3   // x1 holds x1 +
        8`. A comment and not an assignment, so the printed body still assigns a register
        only where the machine's own instruction does."""
        def_regs, use_regs = _def_use(mn, op)
        # The role registers stay as they are, all but LR: its role name says it holds the
        # return address, and after this line it does not (#162). `keep` holds a register
        # the line leaves alone, the low lane of a V register an upper-lane insert does
        # not touch (#134).
        defs = set(def_regs) - (_SPECIAL - {_lr()}) - keep
        if dst in def_regs:               # a role register it loads, as before; not
            defs.add(dst)                 # the source of `stlr x0, [x17]`
        out = []
        live = self._live_after & ~_reg_mask(defs)
        for r in sorted(defs):
            out += self._pin(st, r, live)
        # Not every line `_pin` returns declares. A name the hoist took declares at the
        # top of the body and assigns here, `tN = ...;`, which `_DECL_RE` does not match
        # because it requires `var`. Matching unconditionally raises AttributeError, and
        # an exception that escapes is exit 3, a bug in Jadart rather than bad input.
        # Reached only by a walk that hoists a name `_pin` writes out, which is why #212
        # shipped it green: nothing on either fixture hoists one today, and the first
        # change that makes `_verbatim` fire more often finds it (#212).
        self.raw_names.update(m.group(2) for m in map(_DECL_RE.match, out) if m)
        held = [f"{r} holds {v.text}" for r, v in sorted(st.reg.items())
                if r in use_regs and v.text != r]
        for r in sorted(defs):
            st.set(r, V(r, P_ATOM))
            self._printed_regs.add(r)
        line = f"{mn} {shown}".rstrip()
        return out + [f"{line}   // {', '.join(held)}" if held else line]

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

    def _reads_next(self, reg: str) -> bool:
        """Whether, of x0 and d0, the first one an instruction after the current one in
        its block touches is `reg`, and it reads it: the register a call's result is
        taken from. A `ret` or another call is no evidence. On arm64 every spelling of V0
        is d0, and `eor v0.16b, v0.16b, v0.16b` zeroes it rather than reading it
        (_rv_def_use): read as a use, a call whose result nothing reads got a name."""
        regs = (_T.ret_int, _T.ret_fp)
        exact = _rv_def_use if _T is ARM64 else _def_use
        for (_a, mn, op, _n) in self._insns[self._at + 1:]:
            if mn == "ret" or mn in _CALLS:
                return False
            de, us = exact(mn, op)
            for r in regs:
                if r in us:
                    return r == reg
            if any(r in de for r in regs):
                return False
        return False

    def _result(self, st: State, expr: str, reg: str = None, alloc=None) -> list:
        """Emit a call, and give its result a name when anything reads it.

        `bl f` leaves the result in x0, and the lifter used to say so by putting the bare
        string "x0" in the register map. Every later use then printed a machine register:
        `f(this); ... return x0;` never tells the reader that the value being returned is
        the one the call produced. It is not a guess that it is, the ABI says the result
        is in x0 and liveness says x0 is read before it is written again, so it gets a
        name and the reader can follow it.

        Where nothing reads the result the call is emitted exactly as before, so a
        statement whose value is discarded does not grow a variable nobody uses.

        A double comes back in d0, and the call destroys d0 as it does x0, so a read of d0
        before anything writes it again is a read of the result. Where the next
        instruction of the block to touch x0 or d0 reads d0, and x0 is not read, the
        double is the result and gets the name. It was left as d0, which is also how the
        d0 the function was handed reads, and two calls' results compared printed
        `if (d0 > d0)` (#134, #127). Liveness alone does not say it: a `ret` reads both
        registers, so a call followed by `return NULL;` looked like it returned d0.

        `alloc` is the AllocSite of a per-class allocation stub, recorded against the name
        so a field loaded off the new object can be named (#240). Against a NAME only:
        where nothing reads the result the register keeps its own spelling, and
        attributing a class to a bare `x0` would outlive the one value it is true of."""
        if reg is None:
            fp = self._d0_read(self._insns[self._at][0]) or self._reads_next(_T.ret_fp)
            reg = (_T.ret_fp if fp and not self._live_after & _reg_mask((_T.ret_int,))
                   else _T.ret_int)
        if self._live_after & _reg_mask((reg,)):
            name, decl = self._mint(st, expr)
            self.results.add(name)
            if alloc is not None:
                self.alloc_of[name] = alloc
                self._alloc_bases.add(name)
            st.set(reg, V(name, P_ATOM))
            return [decl]
        st.set(reg, V(reg, P_ATOM))
        return [f"{expr};"]

    def _note_flags(self, st: State, mn: str, op: str, ops, read=True) -> list:
        """Track which comparison the condition flags currently hold, and its operands
        AS THEY READ AT THAT POINT. A `csel` three instructions later has to be rendered
        against the values the `cmp` saw, not against whatever those registers hold by
        then, so the rendering is captured with the comparison rather than recovered at
        the use. The branch that ends the block is rendered from it too (#116).

        `subs x1, x1, #8` sets the flags from the x1 it is about to overwrite. Where the
        value captured for x1 is spelled with x1 itself, that spelling means the new
        value once the instruction has run, so the old one is named first, where
        something reads the flags (`read`, see _flags_read); the line that names it is
        returned."""
        out = []
        if mn in _FLAG_SRC:
            regs = _regs(ops)
            dst = canon(ops[0]) if mn not in _CMP else None
            # The comparison is of the sources; `subs x1, x0, x2` sets the flags from x0
            # and x2, and naming the x1 it overwrites would be a line nothing reads.
            srcs = regs if dst is None else _regs(ops[1:])
            vals = {r: self._leaf(r, st) for r in srcs}
            if read and dst in vals:
                pat = re.compile(rf"\b{re.escape(dst)}\b")
                for r, v in sorted(vals.items()):
                    if pat.search(v.text):
                        name, decl = self._mint(st, v.text)
                        out.append(decl)
                        vals[r] = V(name, P_ATOM)
            self._flags = (mn, op, vals, regs)
        elif mn in _FLAG_KILL:
            self._flags = None
        elif self._flags is not None and _def_use(mn, op)[0] & self._flags[3]:
            self._flags = None      # an operand of the live comparison was overwritten
        return out

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
                   else _prefix("~" if mn == "cinv" else "-", a))
            no = a
        else:                                           # csel / csinc / csinv / csneg
            yes, b = g(canon(ops[1])), g(canon(ops[2]))
            no = (b if mn == "csel"
                  else _bin(b, "+", V("1", P_ATOM), P_ADD) if mn == "csinc"
                  else _prefix("~" if mn == "csinv" else "-", b))
        # One of two object pointers is an object pointer; anything else the select
        # made or chose from is computed (`V.calc`, #329).
        calc = mn != "csel" or yes.calc or no.calc or bool(yes.smi or no.smi)
        st.set(canon(ops[0]),
               V(f"{cond} ? {_wrap(yes, P_TERN + 1)} : {_wrap(no, P_TERN + 1)}", P_TERN,
                 calc=calc))
        return []

    def _raw_write(self, st: State, mn: str, op: str, at=None) -> list:
        """What a store `_step` prints raw does to the state, ahead of its line (#162).

        One off SP or FP may have written any slot, as may one whose address does not
        parse, so the slot map goes. One anywhere else may have written any memory a
        value reads, as a call may, so each live register value that reads memory is
        named first (_pin_call), and each slot whose text reads memory goes. Before
        this, `stnp x0, x1, [x29, #-0x10]` left the slot reading what was there before
        it, and a raw store to a field left a value loaded from it reading the new one."""
        ops = _split_ops(op)
        if _off_frame(ops):
            _forget_frame(st)
            if _addr(ops) is not None:
                return []
        elif self._through_frame(at, mn, op):
            _forget_frame(st)       # and it may write the heap all the same
        st.stale_mem()
        out = self._pin_call(st, _def_use(mn, op)[0])
        for k in [k for k, v in st.slot.items() if self._reads_mem(v.text)]:
            st.forget_slot(k)
        return out

    def _reload(self, st: State, key: str, mn: str, reg: str) -> V:
        """What a load of `reg` with `mn` from slot `key` reads: the slot's value, else
        the register's own name. A load of 8 bytes or more reads it where no narrower
        store fills the slot anywhere in the function, and a narrower load where every
        store that fills it is as wide as the load. Otherwise a load reads part of the
        value, or bytes the store left alone, and either read as the whole of it (#162).
        A 16-byte slot reads as before: its low 8 bytes are the value's.

        A load into the other register file reads the bits as another kind of value, as
        `fmov d3, x0` does, which is kept raw for that reason: a slot reads only where
        every store that fills it is from the load's own file. And a load that extends
        what it reads is spelled as `sxtw` and `uxth` are: `stur w0; ldursw x3` printed
        x0 for x3, and `strh w0; ldrh w3` x0 for its low 16 bits (#165). A 4-byte load
        into a w register reads as every w value does, as its value's 64 bits and exact
        in the low 32, as `mov w3, w0` prints x0."""
        width, held = _access_width(mn, reg), self._slot_widths()[0].get(key, ())
        got = st.slot.get(key, _UPPER)
        if (held and min(held) < 8) if width >= 8 else held != {width}:
            got = _UPPER
        kind = _reg_file(reg)
        if self._slot_widths()[4].get(key) != {kind}:
            got = _UPPER
        signed = mn in _SIGNED_LOADS
        if got.text and kind == "x" and (width < 4 or width < 8 and signed):
            got = _extended(got, 8 * width, signed)
        if not got.text:
            # The fallback spells the LOAD'S OWN register, right only where the slot held
            # that very register, whose entry value the printed body still reads so the
            # reload round-trips. Where it held anything else the fallback names a
            # different value, 6,623 reads in 1,967 of 8,194 functions (#196). Spell what
            # the slot held instead, under `State.dropped`'s invariant.
            held = st.dropped.get(key)
            if held is not None:
                v, fresh = held
                if ((fresh or not self._reads_mem(v.text))
                        and not any(r in self._printed_regs or r in self.printed_prior
                                    for r in _slot_regs(v.text))):
                    self.spelled_regs.update(_slot_regs(v.text))
                    self._reload_blind = False
                    return v
        # Whether the fallback ran, which the caller cannot tell from the value: a slot
        # that held this very register reads back the same text as the fallback spells.
        self._reload_blind = not got.text
        return got if got.text else V(canon(reg), P_ATOM)

    def _frame_read(self, base: str, disp: int, at=None, width: int = 8) -> V:
        """A frame slot spelled as the read it is, `(FP - 8).field_0x1`.

        Spelled the way the lifter already spells the SAME address when it is held in a
        register: `sub x0, x29, #0x40; ldur x3, [x0, #8]` prints `(FP - 64).field_0x9`,
        and `mov x0, x15; ldur x3, [x0, #0x10]` prints `SP.field_0x11`. So the negative
        part of the displacement goes into the base expression and the field offset
        carries the tag bias, which is what `record_drop` and `_FRAME_TEXT_RE` both
        document.

        Not `_byte_off`: the frame registers are untagged, and taking its answer here
        would print `.tags`, the object header, for a read at the base itself, and a
        negative field offset for the frame slots that matter, which are all below FP.
        """
        # Off SP, spelled against the frame the function was ENTERED with wherever SP's
        # place there is known exactly. `SP` means SP at this line, so two reads of
        # addresses a push apart printed one text and neither said SP had moved (#207).
        # The accesses through FP are already rewritten into the coordinates of the frame
        # FP started in, so this is the half that was left (`_frame_plan`, #165).
        #
        # `at` is the instruction's own address, which is what `_frame_plan` keys `sp_at`
        # by; `isinstance`, so that anything that cannot be one of those keys declines
        # rather than asking the dict about it, which an unhashable value would raise on.
        role = _T.roles.get(base) or base
        got = self.sp_at.get(at) if role == "SP" and isinstance(at, int) else None
        sits = got[0] if got and not got[1] else None
        if sits is not None:
            role, disp = "FP", sits + disp
        addr, off = V(role, P_ATOM), disp
        if disp < 0:
            addr, off = _bin(addr, "-", _num(-disp), P_ADD), 0
        return self._field(addr, off + 1, width)

    def _name_blind(self, st: State, base: str, mn: str, blind: list, at=None) -> list:
        """Name what a DECLINED frame reload read, rather than keep the load's register.

        The fallback in `_reload` spells the load's own register, and the printed body
        reads a register it never assigns as the value the function came in with, so the
        output said the destination still held its entry argument. It does not: the load
        happened. Every cause of a decline gives the same silent wrong read, and most of
        them cannot be fixed by remembering a spelling, because once a path may have
        written the slot neither the register nor a name for it is what the load reads
        (#198). What the lifter does know is the read, so it says that and names it, which
        is `_phi_name`'s rule at the other end: always a fresh one, never the register.

        A register nothing reads again is left alone; naming it would print a line for a
        value the reader never meets. Liveness is asked with `_regs`, which is how the
        liveness sets are keyed: `canon` leaves `q0`, `v0`, `h0` and `b0` alone where
        `_regs` calls them all `d0`, so testing the state key minted an unknown bit that
        is never live and 1,169 reads off FP that ARE read again were passed over.

        And only where the text can say what was read. A field read is eight bytes. The
        general file has a convention for saying less, which `_reload` uses for a slot's
        value too: `_extended` below for a byte or a halfword, and a w register left as it
        is because a w value reads as its low 32 bits anyway. The other file has no such
        convention, so a read through it declines unless it is exactly eight bytes: a
        16-byte `q` or `v`, and a 4, 2 or 1-byte `s`, `h` or `b`. A decline is
        recoverable; a width that is not what the machine read is not.
        """
        out = []
        for reg, op, disp in blind:
            if not (self._live_after & _reg_mask(tuple(_regs((op,))))):
                continue
            width, signed = _access_width(mn, op), mn in _SIGNED_LOADS
            # Sixteen bytes has a spelling of its own now, so a `q` or `v` reload says
            # the read instead of keeping the register (#209). Still not a 4, 2 or 1-byte
            # read through that file: `_extended`'s mask is the general file's convention
            # and a masked double is not what the machine loaded.
            if _reg_file(op) != "x" and width not in (8, 16):
                continue
            v = self._frame_read(base, disp, at, width)
            # The spelling says how many bytes were read now, so the unsigned mask said it
            # twice: `(FP - 8).field2_0x1` and not `((FP - 8).field_0x1 & 0xffff)`. The
            # SIGN is a separate fact about the destination's 64 bits, and the shift pair
            # is still the only thing that says it (#221).
            if _reg_file(op) == "x" and signed and width < 8:
                v = _extended(v, 8 * width, signed)
            tmp, decl = self._mint(st, v.text)
            self.blind_named.add(tmp)
            out.append(decl)
            st.set(reg, V(tmp, P_ATOM))
        return out

    def _overwrite(self, st: State, at, base: str, lo: int, width: int, second):
        """Forget the slots off `base` that the store at `at` of `width` bytes to `lo`,
        and of as many again to `second` for a pair, writes any of, ahead of the store
        filling its own (#162).

        A slot holds 8 bytes from its key, or 16 where a q register fills it
        (_wide_slots), and fewer where a narrower store does. Only the store's own keys
        were replaced, so `stur x0, [x29, #-0xc]; stur x1, [x29, #-8]` left the first
        slot reading x0 with its top half x1's. Each key a store can touch is looked
        up, not each slot held (#154). A slot off SP that goes marks the outgoing area
        short, as a push does (_frame_moved).

        So do the other frame register's slots the store's bytes may cover
        (_cross_write).
        """
        if at in self.frame_cross:
            self._cross_write(st, base, lo, width * (1 if second is None else 2),
                              self.frame_cross[at])
        if self._slot_widths()[3]:
            return          # Dart's spills: 8 bytes at a multiple of 8, so only its own
        own = {f"{base}{lo:+d}"} | (set() if second is None else {f"{base}{second:+d}"})
        hi = lo + width * (1 if second is None else 2)
        sp = next((r for r, v in _T.roles.items() if v == "SP"), None)
        wide = self._wide_slots()
        gone = False
        for off in range(lo - 15 if wide else lo - 7, hi):
            key = f"{base}{off:+d}"
            if key in st.slot and (off >= lo - 7 or key in wide):
                st.forget_slot(key)
                gone = gone or key not in own
        if gone and base == sp:
            st.slot[_LOST] = V("", P_ATOM)

    def _cross_write(self, st: State, base: str, lo: int, n: int, cross):
        """Drop the slots off the other frame register that a store of `n` bytes to
        `lo` off `base` may write, from `cross`, (SP less where the frame starts, how
        much lower SP may be) where the store is, or None where SP is not known against
        FP (_frame_plan).

        The walk keys slots off SP and off FP apart, and Dart's frame keeps them apart
        but where SP sits higher than the prologue put it, or an FFI call's frame lies
        below it (#162). This drops only the slots the store may write, and only where it
        stores, so a cell an FFI call's push and a leaf call use at different times costs
        nothing (#165). Where SP is not known, a store through SP may write any slot off
        FP, and one through FP any slot off SP."""
        sp, fp = _frame_regs()
        if cross is None:
            other = fp if base == sp else sp
            gone = [k for k in st.slot if k != _LOST and k.startswith(other)]
        else:
            at, slack = cross
            if base == sp:
                gone = self._covered(st, fp, at + lo - slack, at + lo + n)
            else:
                gone = self._covered(st, sp, lo - at, lo - at + slack + n)
        for k in gone:
            st.forget_slot(k)
        if base == fp and any(k != _LOST for k in gone):
            st.slot[_LOST] = V("", P_ATOM)

    def _covered(self, st: State, base: str, lo: int, hi: int) -> list:
        """The slots off `base` with a byte in [lo, hi): 8 bytes from a key, 16 where a
        q register fills it (_wide_slots)."""
        wide = self._wide_slots()
        out = []
        for off in range(lo - 15 if wide else lo - 7, hi):
            key = f"{base}{off:+d}"
            if key in st.slot and key != _LOST and (off >= lo - 7 or key in wide):
                out.append(key)
        return out

    def _frame_moved(self, st: State, base: str, delta: int):
        """SP or FP moved by a writeback, so every slot keyed on it is stale.

        Stack slots are keyed by displacement from the CURRENT base, which is the only
        thing the lifter can name. Once the base itself moves, an old key names a
        different address, and reading it back would hand a call the argument of a frame
        that no longer exists. There is nothing to rename them to, so they go.

        A push that drops arguments already stored leaves the outgoing area short, and a
        call that read the rest as its argument list printed part of it, `_setFlag(true)`
        for three values pushed (#144, #147): that is recorded, see _stack_args."""
        if not delta:
            return
        if _T.roles.get(base) == "FP":
            # SP's slots too: _frame_meets compares them with FP's only while FP stays
            # where it is (#162). The records go with them, through `_forget_frame`: their
            # keys are displacements from the base that just moved, so each now names a
            # different address and there is nothing to rename it to (#199).
            _forget_frame(st)
            return
        # An SP move leaves the records alone, because every one of them is FP-keyed.
        # `record_drop` is reached only from `stale_on_write`, whose candidates come from
        # `slot_by_reg`, which `note_slot` and `reindex_slots` fill for FP slots only; and
        # the loop-exit recorder runs after `_exit_slots` deleted the SP keys. Measured
        # over the 3.12.2 clean build, all 3,640 recorded keys are FP's, and clearing
        # here threw away 2,553 of them on SP moves alone (#199 review).
        if delta % 8 == 0:
            # SP moved by a push or a pop of a known amount: a slot keyed off it is still
            # there, now at a different displacement. Rename them by the move rather than
            # drop, so a second push does not lose what the first stored and a call then
            # read short, `_setFlag` for three values pushed as two pushes (#144, #147). A
            # slot the move takes below SP (a pop past it) is gone.
            renamed = {}
            for k, v in st.slot.items():
                if k == _LOST or not k.startswith(base):
                    renamed[k] = v
                    continue
                off = int(k[len(base):]) - delta
                if off >= 0:
                    renamed[f"{base}{off:+d}"] = v
            st.slot = renamed
            st.reindex_slots()      # keys moved, so the register index has to (#173)
            return
        gone = [k for k in st.slot if k != _LOST and k.startswith(base)]
        for k in gone:
            del st.slot[k]
        if delta < 0 and gone:
            st.slot[_LOST] = V("", P_ATOM)

    def _moved_unseen(self, st: State, fp: bool, delta):
        """A frame register moved where `_step` did not see it (_frame_moves), as a
        write-back moves it: FP by an amount not known, SP by `delta`, None where that
        is not known either. Kept, a slot read back through the moved register printed
        what was stored where it pointed before (#165)."""
        if fp:
            _forget_frame(st)
        elif delta != 0:
            self._frame_moved(st, _frame_regs()[0], -1 if delta is None else delta)

    def _moved_regs(self, a) -> set:
        """The frame registers the instruction at `a` moves out of `_step`'s sight."""
        fp, delta = self.frame_moves[a]
        sp, fpr = _frame_regs()
        return ({fpr} if fp else set()) | ({sp} if delta != 0 else set())

    def _role_stale(self, st: State, role: str, live: int, shift=None, row=None,
                    keep=()) -> list:
        """Before the frame register `role` moves: every value in the register map
        whose text names it is made right for the lines after (#340).

        `SP` is SP at the line and `FP` the frame in force there, so a text naming one
        means another address past the move. A value that is the register plus a
        constant by its record (`_role_sum`) has the constant taken on by `shift`, how
        far the register moves, where that is known: `add x0, x15, #0x238; sub x15, x15,
        #0x20` holds `SP + 0x258`. Any other is given a name while its text is still
        right, where a later line reads it (`live`, a register mask) or the moving row
        itself does (`row`, as written), and a register nothing reads again drops to its
        own name.
        `live` of None names nothing: at a join the ways in moved the register apart,
        and no one text is right on all of them. A text spelled with the bare register,
        which a row printed raw leaves, is named or dropped the same way. `keep` are
        registers a loop carries, which it names itself. The slot map holds no such
        value (`_name_slot`)."""
        if self._flags is not None and any(_names_frame(v, role)
                                           for v in self._flags[2].values()):
            self._flags = None
        out, reg = [], self._fp_reg if role == "FP" else self._sp_reg
        # The two words looked for here and not in a call: this runs at every row that
        # moves a frame register, over every register, and few of them hold either.
        held = [(r, v) for r, v in st.reg.items() if role in v.text or reg in v.text]
        held.sort()         # by register: no two are the same, so no V is compared
        uses = _def_use(*row)[1] if held and row is not None else ()
        for r, v in held:
            if ROLE.get(r) == role or r in keep or not _names_frame(v, role):
                continue
            got = _role_sum(v, role) if shift is not None and r not in uses else None
            if got is not None:
                st.reg[r] = _off_role(got[0], got[1] - shift, got[2], got[3])
            elif live is not None and (r in uses or live & _reg_mask((r,))):
                tmp, decl = self._mint(st, v.text)
                self.raw_names.add(tmp)     # one only the moving row read goes unread
                out.append(decl)
                st.reg[r] = V(tmp, P_ATOM, smi=v.smi, calc=v.calc)
                st.elem.pop(r, None)
                st.poolbase.pop(r, None)
            else:
                st.forget(r)
        if st.elem:
            for key, (b, i, _s, _f) in list(st.elem.items()):
                if _names_frame(b, role) or _names_frame(i, role):
                    del st.elem[key]
        return out

    def _frame_shift(self, st: State, a, mn: str, op: str) -> list:
        """`_role_stale` for the row at `a`, which writes a frame register or is one of
        `frame_moves`, before it is stepped. SP moves by what a write-back through it
        or `_frame_moves` says, not known where neither does. FP starts a frame of its
        own where `_frame_plan` says so, or, where it did not follow FP, at any write
        of it; a move inside its frame changes no text, as `FP` is where the frame
        started (`_leaf`)."""
        wrote_fp, delta = self.shift_rows[a]
        got = self.frame_moves.get(a)
        out = []
        if delta != 0:
            out = self._role_stale(st, "SP", self._live_after, delta, (mn, op))
        if got[0] if got is not None else (
                wrote_fp and mn != "nop" and self.fp_at is None):
            out += self._role_stale(st, "FP", self._live_after, None, (mn, op))
        return out

    def _frame_reads(self, st: State, a, mn: str) -> None:
        """After the row at `a` wrote a frame register: the register reads as its
        role again. `and x15, x15, #-16` left the walk holding `SP & 0xfffffffffffffff0`
        for x15, the SP of the row before, on every line after; SP at a line is the
        register there, whatever wrote it. Not where the step forgot it, a row
        printed raw or a load with a write-back into it: that stays the bare register,
        which says no more than the row does. FP likewise where the row starts a frame
        of its own and left it a value that names the frame before, and past a `mov
        x29, x15` strip_boilerplate blanked, which the walk did not step (#340)."""
        sp, fp = self._sp_reg, self._fp_reg
        if sp in st.reg and st.reg[sp].text != sp:
            st.restore(sp)
        if fp not in st.reg:
            return
        if mn == "nop" and self.shift_rows[a][0]:
            st.restore(fp)
        elif self.frame_moves.get(a, (False,))[0] and _names_role(st.reg[fp], "FP"):
            st.restore(fp)

    def _bump(self, st: State, base: str, delta: int) -> list:
        """The base-register update half of a writeback addressing mode.

        Real dataflow, not bookkeeping: `ldr x16, [x4], #8` in a copy loop advances the
        source pointer, and dropping that leaves the loop reading the same element every
        iteration. Frame registers are handled by _frame_moved instead, because SP moving
        is not a source-level statement."""
        if not delta or self._frame_base(base):
            return []
        cur = self._leaf(base, st)
        step = (_bin(cur, "-", _num(-delta), P_ADD) if delta < 0
                else _bin(cur, "+", _num(delta), P_ADD))
        out = self._pin(st, base)
        out.append(self._assign(V(base, P_ATOM), step))
        st.set(base, V(base, P_ATOM))
        self._printed_regs.add(base)
        return out

    def _mint(self, st: State, text=None, pad: str = "") -> tuple:
        """Allocate a name for `text` and return it with the line that declares it.

        `text` of None is a name for a value the lifter does NOT know, declared and never
        assigned: what a call leaves in a register it clobbered. See `_clobber_call`.

        One place for it, because thirteen sites allocated `t{tmpc}` themselves and then
        each decided for itself whether the name could be hoisted. Only `_phi` and
        `_name_blind` could, so a name any other site minted and a later line read outside
        the block it was declared in was a read of something undeclared: 164 of them in
        115 of 8,194 ranges, which is #204. Minting here puts every name in `self.minted`,
        which is what `_lift_function.wants_hoist` asks.

        Hoisted, the DECLARATION moves to the top of the body and the assignment stays
        where the value is, because the text means what it means at this line and not at
        the top. That split is `_phi`'s, and the reason it is not just a `var` at the top
        is in its comment (#198).

        Which pass may DROP the name is still the caller's to say, by adding it to
        `results`, `slot_names`, `phi_names` or `raw_names`: those three passes keep
        different things (a slot name's initialiser chain, a phi's block, a one-occurrence
        test) and folding them together is not this change.
        """
        name = f"t{st.tmpc[0]}"
        st.tmpc[0] += 1
        self.minted.add(name)
        self._mint_at[name] = self._mints
        self._mints += 1
        if name in self.hoist:
            self.hoisted.add(name)
            # Already declared at the top, so an initialiser-less one needs no line at all.
            return name, ("" if text is None else f"{pad}{name} = {text};")
        if text is None:
            return name, f"{pad}var {name};"
        return name, f"{pad}var {name} = {text};"

    def _pin(self, st: State, name: str, live=None, regs: bool = False) -> list:
        """Give a name to every tracked value that mentions `name`, before `name` changes.

        The register map holds expressions, not results, and they are substituted into
        their uses later. That is what makes the output read like source, and it is only
        sound while the registers inside them still hold what they held. `ldr x16, [x4],
        #8; str x16, [x2], #8` is a copy loop: x16's value is `x4.field_0x1`, and once x4
        has advanced, printing that text at the store describes the WRONG element.

        Writing the value out at the point the base changes is not a heuristic. The load
        already happened, so the value already exists; this only says so out loud.

        `live`, a register mask, leaves out a register nothing reads again. `regs` asks
        the register map alone, which is what a REGION wants: a slot is dropped across one
        by `_stale_slots` instead, for the reason it gives (#228)."""
        pat = _USE_RE.get(name)
        if pat is None:
            pat = _USE_RE[name] = re.compile(rf"\b{re.escape(name)}\b")
        # An operand the live comparison was captured from reads as the new value from
        # here on, so the comparison can no longer be spelled (#118).
        if self._flags is not None and any(pat.search(v.text)
                                           for v in self._flags[2].values()):
            self._flags = None
        out = []
        for holder in ((st.reg,) if regs else (st.reg, st.slot)):
            # Sorted by key, so the names handed out here depend only on WHICH registers
            # hold a mention of `name`, not on the order they happened to be inserted in
            # somewhere upstream. Relying on insertion order made the numbering a property
            # of every earlier write into the map, which is a global invariant nobody can
            # check locally; one unsorted set in `_merge` was enough to break it.
            for key, v in sorted(holder.items()):
                if key == name or name not in v.text or not pat.search(v.text):
                    continue
                if live is not None and holder is st.reg and not live & _reg_mask((key,)):
                    continue
                tmp, decl = self._mint(st, v.text)
                out.append(decl)
                holder[key] = V(tmp, P_ATOM, smi=v.smi, calc=v.calc)
        for key, (b, i, _s, _f) in list(st.elem.items()):
            if pat.search(b.text) or pat.search(i.text):
                del st.elem[key]
        return out

    def _feeds_selfref(self, key: str, text: str, start: int) -> bool:
        """True if a later instruction in this block reads `key` and renders a
        self-referential result: its destination is one of its own source registers, or is
        a register `text` already names. Freezing `key` would then change how that
        self-referential store spells (or remove the self-reference), and such a store is
        right on main only by the stale read it keeps, so #187 leaves the pin out (the
        still-open self-referential case). A call ends the straight-line reasoning."""
        for (_a, mn, op, _n) in self._insns[start:]:
            if mn in _CALLS:
                break
            defs, uses = _def_use(mn, op)
            if key not in uses:
                continue
            for d in defs:
                if d in uses or _use_re(d).search(text):
                    return True
        return False

    def _name_stale_reg(self, st: State, name: str, live, guard_feed=False) -> list:
        """Name-first a register-held EXPRESSION that mentions `name`, before `name` is
        reassigned (#187). The register analog of `_pin` before a base moves, but
        narrowed: register map only (a slot is `stale_on_write`'s job, #173), and only a
        compound expression (a bare-register copy stays bare for the argument / phi /
        read-afresh rules that want the register name). The expression must still be
        VALID: every register it names holds its own bare value, so the text means what it
        says. An expression already stale from an earlier untracked reassignment (a named
        register no longer holding its bare value) is left alone; freezing it into a temp
        would preserve the wrong value and defeat the slot reload that still read it right
        (#173). `live` leaves out a register nothing reads again, so a dropped value is
        not written out dead. The caller leaves out a reassignment of a register live out
        of the block: one carried into a join is the phi machinery's to name (it renames
        arm write so the register keeps its pre-branch meaning), so a value naming it does
        not go stale there, and a pin would only force a redundant phi temp. `guard_feed`
        (set for a move or a computed result, not a load) also leaves out a value a later
        self-referential store in the block reads (`_feeds_selfref`)."""
        pat = _USE_RE.get(name)
        if pat is None:
            pat = _USE_RE[name] = re.compile(rf"\b{re.escape(name)}\b")
        if self._flags is not None and any(pat.search(v.text)
                                           for v in self._flags[2].values()):
            self._flags = None
        out = []
        for key, v in sorted(st.reg.items()):
            if key == name or name not in v.text or not pat.search(v.text):
                continue
            if _REG_RE.fullmatch(v.text) or not live & _reg_mask((key,)):
                continue                      # a bare-register copy, or a dead register
            if any(st.get(q).text != q for q in _slot_regs(v.text)):
                continue                      # already names a reassigned register: stale
            if guard_feed and self._feeds_selfref(key, v.text, self._at + 1):
                continue                      # feeds a later self-referential store
            tmp, decl = self._mint(st, v.text)
            out.append(decl)
            st.reg[key] = V(tmp, P_ATOM, smi=v.smi, calc=v.calc)
            st.elem.pop(key, None)
            st.poolbase.pop(key, None)
        return out

    def _pin_mem(self, st: State, loc: str, also=(), anywhere=False, elems=False,
                 edge=None, keep=None, since=None) -> list:
        """Give a name to every LIVE tracked value that reads `loc`, before `loc` changes.

        Two more ways a store reaches a read, both because an access at a COMPUTED
        address is spelled by its address and not by a field of an object (#341). A
        store to the heap names each read this body made at such an address
        (`_at_reads`), whatever its spelling: `(x1 + x5 - 1).field_0x1` is
        `x1.field_0x8` when x5 is 8. And `anywhere`, a store AT such an address, may
        write any field of any object, so it names every live value that reads the heap
        (`_reads_mem`), as a store the lifter prints raw does (`_raw_write`).

        And `elems`, an element store, names every element read this body made
        (`_at_reads("elem")`), whatever its base and index: `x6[x7]` is `x3[x4]` when x6
        holds x3 and x7 holds x4, as two registers may hold one object for a field
        (#343).

        And `edge`, a field against an element (#375). The elements of an object are
        the words from its data offset up, and a field read at a fixed offset that
        reaches that far is one of them: `ldur x4, [x13, #0x17]` is element 0 of the
        array `add x16, x13, x8, lsl #3; stur x1, [x16, #0x17]` stores into, whenever
        x8 is 0, and through any two bases that hold one object. So an element store
        names each live field read with a byte at `edge`, the lowest offset the
        element can be at, or past it (`_field_past`), and a field store names each
        live element read that can be below `edge`, the end of the bytes it writes
        (`_elems_under`). A field that ends below the data offset is the header and no
        element. An element with no data offset shown is spelled by its address and
        nothing else, and both ways it is the access at a computed address above.
        Past `_EDGE_CAP` spellings to look for, a store names every live heap read, or
        every live element read: more names, and the work stays linear in the rows.
        The caller gives no `edge` for a store into the thread, the pool or the frame,
        which hold no Dart object. `since` is for a store into an object this body
        allocated: the order of the name its address was given, so that only the
        elements read after it are named, as nothing read before the object was made
        is a word of it (#341).

        That an element is at its data offset or above is an ASSUMPTION about the
        compiler and not something the rows prove: compiled Dart checks every index
        against the length before it is used, so an index is never negative, and the
        lifter does not look for the check. Rows that index with a negative number,
        `asr x8, x7, #63` for one, reach below the data offset, and a header field
        read stays inline across that store (`_elem_access`).

        `keep` is the element address the second word of an `stp` is still to be
        stored through. Its base and index take names where every other record that
        reads the write is dropped, so the second word prints as the element it is.

        `also` is the OTHER spellings of bytes this write covers, which a 16-byte access
        needs because the spelling says the width: a write of `x2.field16_0x8` lands on
        the bytes a live `x2.field_0x8` and `x2.field_0x10` read, and neither text
        contains the other, so matching one text would miss them (#209). A text that
        is a bare selector, `.tags`, is one the write may land on under ANY base
        (`_header_selectors`).

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

        Liveness can still be right and the READER unable to use the name: `ldr q0` leaves
        d0 holding the low half of a 16-byte read, which the field spelling cannot say, so
        the `ret` that reads d0 declines and the name goes unread. The names are recorded
        in `raw_names` for that, so `_drop_unread` takes the ones nothing reads.
        """
        if not loc:
            return []
        st.stale_mem()
        # `loc` ends in hex digits, so a bare substring match would let `field_0x8` fire
        # inside `field_0x80`, a different field, and a value that is not stale at all.
        # Each text once: `_covers` spells a slot off a nonzero offset twice over.
        # Looked for as text (`_spelled`), where a pattern was compiled at every
        # store: nearly every store has its own, so the 512 that `re` keeps were no
        # help, and compiling them was 4% of the time tier 3 takes (#346).
        texts = tuple(dict.fromkeys(x for x in (loc, *also) if x[:1] != ".")) or ("",)
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
            # Every covered spelling's selector too, for the same reason as `texts`, and
            # `_covers` gives both kinds of spelling a slot has, its name and its offset.
            # Not off THR or PP: the same offset is the same slot only where the two bases
            # may be one object, and the thread and the object pool are not Dart objects
            # at all, so no store through a base the lifter tracks can write them.
            sels = dict.fromkeys((sel.group(0), *(
                m.group(0) for m in map(_FIELD_LHS.search, also) if m)))
            alias = re.compile(r"(?<!\bTHR)(?<!\bPP)(?:"
                               + "|".join(re.escape(x) for x in sels)
                               + r")(?![0-9a-fA-F])")
        elif "[" in loc:
            # An element store off a base whose index is not a literal reaches any element
            # of that base, so every read through the same base goes.
            alias = re.compile(re.escape(loc.split("[", 1)[0]) + r"\[")
        out = []
        # Asked for only where the body has made such a read: most have none (#346).
        box = self._elem_box
        at = self._at_reads() if "at" in box else None
        maybe = self._at_reads("maybe_sel") if "maybe_sel" in box else None
        el = self._at_reads("elem") if elems and "elem" in box else None
        past = under = None
        wide, risky = (), False
        if edge is not None:
            if elems:
                # The named fields that reach the elements, by their selectors: made
                # again when a name or a wide word is added, not at every store.
                wide = box.get("wide", ())
                if self._named_at:
                    made = self._past_at
                    got, now = made.get(edge), (self._named_n, len(wide))
                    if got is None or got[0] != now:
                        past = tuple("." + n for off, ns in self._named_at.items()
                                     if off + (8 if off in wide else 4) > edge
                                     for n in ns)
                        # A name that starts as `.field_0x10` does is found inside
                        # one, so a text is asked whatever its `.` are.
                        got = made[edge] = (now, past,
                                            any(n.startswith(".f") for n in past))
                    past, risky = got[1], got[2]
                else:
                    past = ()
                if len(past) > _EDGE_CAP:
                    past, anywhere = None, True
                else:
                    fields = box.get("fields")
                    if fields is None:
                        fields = box["fields"] = {}
            elif "elem_at" in box:
                under = _LATER                # made where a live value has an element
        # A field's spellings each have a `.` in them (`_covers`) and an element's a
        # `[`, so a text with neither is not asked for them. Over thousands of slots
        # that is most of what a store asks.
        dotted, indexed = sel is not None, sel is None and "[" in loc and not also

        def reads(text):
            # The two tests that need `_addr_facts` (`_at_computed`) ask only once a
            # text depends on them, so a body pays for the analysis only where a live
            # value could be named by it. The one put off comes before the tests of
            # #375, which would name most of what it asks about and leave every later
            # access to read the rows back for itself (`_row_plain`).
            nonlocal at, maybe, anywhere, under
            dot, bracket = "." in text, "[" in text
            if ((dot if dotted else bracket or not indexed)
                    and (_spelled(texts, text)
                         or (alias is not None and alias.search(text)))
                    or (at is not None and _spelled(at, text))
                    or (el is not None and bracket and _spelled(el, text, True))):
                return True
            if (maybe is not None and _spelled(maybe, text)
                    and any(x in text for x in self._elem_box["maybe"])):
                self._settle_reads()
                at, maybe = self._at_reads(), None
                if at is not None and _spelled(at, text):
                    return True
            if past is not None and dot:
                got = fields.get(text)
                if got is None:
                    got = fields[text] = _fields_in(text)
                if (got[0] > edge
                        or got[1] and any(o + 8 > edge and o in wide for o in got[1])
                        or past and (got[2] or risky) and _spelled(past, text)):
                    return True
            if under is not None and bracket:
                if under is _LATER:
                    under = self._elems_under(edge, since)
                if under and (under is _EVERY
                              or self._elem_below(text, since, under)):
                    return True
            if not anywhere or not (dot or bracket):
                return False                  # every read of the heap has one of them
            if self._reads_mem(_FRAME_READ.sub("", text)):
                if anywhere is not True:
                    anywhere = self._settle(anywhere)
                return anywhere
            return False

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
            tmp, decl = self._mint(st, v.text)
            out.append(decl)
            self.raw_names.add(tmp)
            st.reg[key] = V(tmp, P_ATOM, smi=v.smi, calc=v.calc)
        # A stack slot has no liveness to consult, it is read back by a later load or not
        # at all, so a slot that reads the written location is dropped rather than named.
        # Dropping is honest (the reload renders as the bare destination register) and does
        # not spend a declaration on a spill nothing reloads.
        slots = st.slot
        if slots:
            self._pin_walked += len(slots)
            budget = self._pin_budget
            if budget is None:
                budget = self._pin_budget = _PIN_WALK * sum(
                    len(b.insns) for b in self.blocks.values())
            if self._pin_walked <= budget or maybe is not None or anywhere:
                for key in [k for k, v in slots.items() if reads(v.text)]:
                    st.forget_slot(key)
            else:
                # Past `_PIN_WALK` the walks have cost more than the body is long, which
                # is a frame of thousands of slots under thousands of stores. A slot's
                # text that this store does not write is kept, under everything the
                # answer is made of, and a store that asks the same thing again asks
                # only about the texts it has not seen. Not where the analysis of the
                # body may still be asked (`maybe`, `anywhere`), which is no text's
                # alone to answer.
                kept = self._unread
                what = (texts, alias and alias.pattern, at and len(at), el and len(el),
                        edge, past, len(wide))
                if under is not None:
                    what += (since, len(box["elem_at"][1]),
                             since is not None and len(self._elem_when))
                unread = kept.get(what)
                if unread is None:
                    if len(kept) >= _PIN_KEPT:
                        del kept[next(iter(kept))]
                    unread = kept[what] = set()
                for key, text in [(k, v.text) for k, v in slots.items()
                                  if v.text not in unread]:
                    if reads(text):
                        st.forget_slot(key)
                    else:
                        unread.add(text)
        for key, (b, i, _s, _f) in list(st.elem.items()):
            rb, ri = reads(b.text), reads(i.text)
            if not (rb or ri):
                continue
            if key != keep:
                del st.elem[key]
                continue
            got = []
            for v, hit in ((b, rb), (i, ri)):
                if hit:
                    tmp, decl = self._mint(st, v.text)
                    out.append(decl)
                    self.raw_names.add(tmp)
                    v = V(tmp, P_ATOM, smi=v.smi, calc=v.calc)
                got.append(v)
            st.elem[key] = (got[0], got[1], _s, _f)
        return out

    def _at_reads(self, kind="at"):
        """The text of every read this body made at a computed address, or None where
        it made none (#341), with `kind` "elem" of every element read (#343), or with
        `kind` "maybe_sel" the selector of every read put off by `_at_computed`. Each
        such read is recorded where it is made, by its text, and they are looked for
        as text (`_spelled`): a pattern of them was compiled again in every body, and
        again whenever a read was added, 0.6% of the time tier 3 takes (#346). An
        element's text starts with its base's name, so it is looked for as a whole
        name, `t3[x4]` and not the end of `at3[x4]`."""
        box = self._elem_box
        got = box.get(kind)
        if not got:
            return None
        made = box.get(kind + "_re")
        if made is None or made[0] != len(got):
            made = box[kind + "_re"] = (len(got), tuple(got))
        return made[1]

    def _elems_under(self, edge: int, since):
        """The element reads this body made that can be at a field offset below
        `edge`, the end of the bytes a field store writes (#375): `x3[x4]`, read at a
        data offset of 0x18, for a store to `.field_0x18` or past it of any base, and
        for none to `.field_0x10`. As the data offsets under `edge` that an element
        was read at, for `_elem_below`, or `_EVERY` where more than `_EDGE_CAP` texts
        were read at them, counted from the lowest offset up and no further, so a
        store's share of the work does not grow with the body.

        With `since`, for a store into an object this body allocated (`_pin_mem`):
        the texts of the ones read after the name of that order was made, which is
        after the allocation, and `_EVERY` past `_EDGE_CAP` reads since."""
        by_lo, _pairs, los = self._elem_box["elem_at"]
        if since is not None:
            read = self._elem_reads
            i = bisect.bisect_right(self._elem_when, since)
            if len(read) - i > _EDGE_CAP:
                return _EVERY
            return tuple(dict.fromkeys(r[0] for r in read[i:] if r[1] < edge))
        n = 0
        for k, lo in enumerate(los):
            if lo >= edge:
                return los[:k]
            n += len(by_lo[lo])
            if n > _EDGE_CAP:
                return _EVERY
        return tuple(los)

    def _elem_below(self, text: str, since, under) -> bool:
        """Whether `text` has in it, as a whole name (`_spelled`), an element read
        that `_elems_under` gave `under` for. Asked of every live value at every
        field store, so what a text has in it is kept by data offset: each element
        read is looked for in a text once, and a text asked again is asked only
        about the reads made since. The few read since an allocation are looked for
        as they are."""
        if since is not None:
            return _spelled(under, text, True)
        box = self._elem_box
        seen = box.get("elem_in")
        if seen is None:
            seen = box["elem_in"] = {}
        got = seen.get(text)
        if got is None:
            got = seen[text] = {}
        by_lo = box["elem_at"][0]
        for lo in under:
            had = got.get(lo)
            if had is True:
                return True
            texts = by_lo[lo]
            n = len(texts)
            if had != n:
                for x in texts[had or 0:]:
                    if x in text and _spelled((x,), text, True):
                        got[lo] = True
                        return True
                got[lo] = n
        return False

    def _at_read(self, text: str, got) -> None:
        """Record `text`, a read `_at_computed` gave `got` for: one at a computed
        address, or one that is where `_addr_facts` says so."""
        if got is True:
            self._elem_box.setdefault("at", {})[text] = None
        elif got:
            # By its selector too, few enough to look for at every store, and all most
            # stores need to see that none of these is live. A text that holds one
            # only may hold the read, which is enough to decide whether to ask.
            box = self._elem_box
            box.setdefault("maybe", {}).setdefault(text, set()).update(got)
            box.setdefault("maybe_sel", {})[text[text.rfind("."):]] = None

    def _settle(self, rows) -> bool:
        """`_computed`'s last test, put off by `_at_computed`: whether `_addr_facts`
        has any of `rows` reading a register that may hold a computed address."""
        return any(self._row_computed(r) for r in rows)

    def _settle_reads(self) -> None:
        """The reads put off by `_at_computed`, now decided."""
        box = self._elem_box
        box.pop("maybe_sel", None), box.pop("maybe_sel_re", None)
        for text, rows in box.pop("maybe", {}).items():
            if self._settle(rows):
                box.setdefault("at", {})[text] = None

    def _elem_read(self, v: V) -> V:
        """`v`, an element this body read, recorded for the element stores after it to
        name (#343). An element of the frame, `FP[x4]`, is no heap store's to write."""
        if not _FRAME_ROOT.match(v.text.split("[", 1)[0]):
            box = self._elem_box
            box.setdefault("elem", {})[v.text] = None
            # And by the lowest offset it can be at, for the field stores (#375): each
            # text at each offset once, in the order they were first read, and every
            # read of this walk with how many names had been made by then
            # (`_elems_under`).
            made = box.get("elem_at")
            if made is None:
                made = box["elem_at"] = ({}, set(), [])
            by_lo, pairs, los = made
            r = (v.text, self._elem_lo)
            if r not in pairs:
                pairs.add(r)
                texts = by_lo.get(r[1])
                if texts is None:
                    texts = by_lo[r[1]] = []
                    bisect.insort(los, r[1])
                texts.append(r[0])
            self._elem_when.append(self._mints)
            self._elem_reads.append(r)
        return v

    def _at_computed(self, base_reg: str, base_v: V, spelled: V):
        """Whether an access off `base_reg`, holding `base_v`, and spelled off `spelled`
        (`_rebase`), is made at an address the lifter computed, which may be any field
        of any object (#341): a displacement folded into the base, or a base that may
        hold a computed address (`_computed`). Not off an untagged role's own address,
        DISPATCH or HEAP, which is no Dart object, as THR and PP are not (`_pin_mem`),
        and not off the frame: SP, FP or a sum of one, `(FP - 8).field_0x1`, which no
        heap store reaches. Or the rows to ask `_settle` about, where only the analysis
        of the whole body can say and it has not been made."""
        if self._frame_base(base_reg) or _FRAME_ROOT.match(spelled.text):
            return False
        if spelled is not base_v:
            return True
        if _role_address(base_v):
            return False
        if base_v.smi or base_v.calc:
            return self._computed(base_reg, base_v)
        # Only `_addr_facts` can say, which is an analysis of the whole body, so the
        # rows it would be asked about are given back, and asked about once a live
        # value depends on the answer (`_pin_mem`). Where it was made, it is asked.
        rows = (self._here,) if base_v.at is None else (self._here, base_v.at[3])
        if "facts" in self._elem_box:
            return self._settle(rows)
        return False if all(map(self._row_plain, rows)) else rows

    def _byte_off(self, base_reg: str, base_v: V, disp: int) -> int:
        # tagged object pointers carry kHeapObjectTag=1, so a field at object offset F is
        # loaded as [P, #F-1]; untagged role registers (THR/HEAP/...) have no such bias.
        #
        # The thread is untagged in whichever register holds it, so its VALUE decides too.
        # Keyed on the name alone, `mov x25, x26; ldr x9, [x25, #0x7d0]` printed
        # `THR.field_0x7d1` beside `THR.field_0x6c8` for x26 itself: one Thread spelled
        # two ways, the odd one no slot at all (#273). The value is the walk's must-fact:
        # a write, a call that clobbers the copy, a join that disagrees and a section no
        # edge leads into each leave the register something else, and an interior
        # pointer, `add x25, x26, #0x10`, reads `THR + 16`, which is not the thread. Only
        # THR follows its value: the null in x22 is a tagged object, and a copy of FP or
        # SP is spelled with the bias, as the frame read itself is (`_frame_read`).
        #
        # LR is untagged only while it holds a return address (`_holds_ra`). Keyed on the
        # name, `ldr x30, [x27, #0x13e0]; ldur x30, [x30, #7]` printed `.field_0x7` for
        # the Code entry point that `ldr x8, ..; ldur x9, [x8, #7]` spells `.field_0x8`
        # (#280). Where the graph cannot show which, LR takes the bias as any register
        # of unknown value does: a Dart register holds a tagged object unless its role
        # says otherwise. FP the same, past a write that is not the frame chain (#307).
        return disp if self._untagged(base_reg, base_v) else disp + 1

    def _holds_ra(self) -> bool:
        """Whether LR holds a return address before the instruction being stepped, on
        every path to it: the last write to it in this block is a call, or there is none
        and `_lr_return_address` says every way into the block holds one (#280)."""
        rows = self._lr_at.get(self._last_block)
        if rows is None:
            if self._lr_in is None:
                self._lr_in = _lr_return_address(self.blocks, self._preds,
                                                  (self.entry, *self.roots), self.raw)
            lr, cur, rows = _lr(), self._lr_in.get(self._last_block, False), []
            # Once per block, so a block of N reads through LR costs N and not N squared.
            for (a, mn, op, _n) in self._insns:
                rows.append(cur)
                w = _lr_row(a, mn, op, lr, self.raw)
                if w is not None:
                    cur = w
            self._lr_at[self._last_block] = rows
        return rows[self._at]

    def _fp_lost(self) -> bool:
        """Whether FP may hold something other than the frame pointer before the row
        being stepped (`_fp_lost_at`, #307)."""
        if self._fp_lost_set is None:
            self._fp_lost_set = _fp_lost_at(self.blocks, self.raw)
        return self._here in self._fp_lost_set

    def _frame_base(self, base: str) -> bool:
        """Whether an access off `base` is one off the frame: SP, and FP while it holds
        the frame pointer. Past a write that put anything else there, FP is a register
        like any other and the access reads the value it holds (#307)."""
        role = _T.roles.get(base)
        return role == "SP" or role == "FP" and not self._fp_lost()

    def _untagged(self, reg: str, v: V) -> bool:
        """Whether `reg`, holding `v`, holds an untagged address before the row being
        stepped: a role register that does (`_UNTAGGED`), FP only while it holds the frame
        pointer (#307), a copy of the thread (#273), and LR where it holds a return
        address and nowhere else (#280)."""
        if reg in _UNTAGGED and not (ROLE.get(reg) == "FP" and self._fp_lost()):
            return True
        return v.text == _THR or (ROLE.get(reg) == "LR" and self._holds_ra())

    def _rebase(self, base_reg: str, base_v: V, disp: int) -> tuple:
        """The (base expression, NON-NEGATIVE field offset, whether offset 0 there is an
        object's header) that `[base_reg, #disp]` names.

        Offset 0 is the header word, `.tags`, only off an object pointer (#329). Off an
        untagged base it is offset 0 of that address, `THR.field_0x0`. Off a value the
        lifter computed, or a register some way in left one in (`_computed`), it is the
        access at its address, spelled as the one below a base is (`_at_address`).

        `_frame_read`'s rule, for every base. A displacement that reaches BELOW the base
        goes into the base expression and the offset stays a field offset, so a read at
        an address is spelled as the read at that address: `(t4 - 8).field_0x1`, which is
        what the lifter already prints when the same address arrives in a register first.

        Without it the biased offset came out negative and printed as one, `t4.field_0x-7`
        for `ldr x16, [x1, #-8]!`. There is no field at -7 of anything: `.field_0xN` says
        offset N of the object the base points at, and a reader who takes that at face
        value is reading a claim the snapshot never made. `_frame_read` was written to
        avoid exactly this ("a negative field offset for the frame slots that matter") and
        nothing applied the same rule to a base that is not a frame register, so a
        pre-indexed copy loop printed the case it refuses: 236 lines of the clean export
        and 2 of the obf one, 511 accesses over 60 of the clean image's ranges, at
        displacements -2, -4, -8, -16 and a run of -64 down to -176 off one saved pointer.

        Ghidra prints the same default name, and guards it. `PrintC::opPtrsub` composes
        `field_0x` + hex only after `if (ct->getSize() <= suboff || suboff < 0) throw
        LowlevelError("PTRSUB out of bounds into struct")`, so a negative sub-offset is an
        error there rather than a field; upstream of that, `TypeStruct::isOffsetValid`
        rejects a negative offset and `RulePtrsubUndo` turns the PTRSUB back into an
        INT_ADD, which prints as plain pointer arithmetic. Hex-Rays moves the negative
        part into the base instead: applying a structure offset to a negative number
        "usually converts the whole (var-num) expression into the CONTAINING_RECORD
        macro", which is this rewrite with a name. Binary Ninja cannot spell one at all,
        a structure member's offset being unsigned. None of the three prints a negative
        member, and this does not either.

        The fold is exact for both representations BECAUSE it uses the displacement and
        not the biased offset: the address is `base + disp` either way, and offset 1 is
        the read at the base expression (a field offset carries the tag bias, which is
        the convention `_frame_read`, `_FRAME_TEXT_RE` and docs/usage.md all state). Only
        a displacement below the base can bias negative, so the two cases do not overlap:
        `ldur x0, [x1, #-1]` on a tagged pointer is offset 0, the object header, and still
        prints `.tags`. 11,184 of the clean image's 11,695 negative displacements are that
        header read and are untouched.
        """
        off = self._byte_off(base_reg, base_v, disp)
        if off > 0:
            return base_v, off, True
        if off < 0:
            return _bin(base_v, "-", _num(-disp), P_ADD), 1, True
        if disp == 0:
            return base_v, 0, False             # an untagged base: no header at 0
        if not self._computed(base_reg, base_v):
            return base_v, 0, True              # the header of the object it points at
        return self._at_address(base_v, disp)

    def _header_selectors(self, width: int) -> tuple:
        """The selector of every spelling a `width`-byte access at an object's header
        has. A store that may write a header names each live read of one, whatever its
        base, and `_pin_mem` matches these for it. Selectors and not whole spellings,
        made once a body: the text is matched against every live value at every
        store, and off the address itself a run of add and store pairs took 2.3
        times as long as it does on main."""
        got = self._elem_box.get(("header", width))
        if got is None:
            base = V("_", P_ATOM)
            texts = (self._field(base, 0, width).text,) + self._covers(base, 0, width)
            got = self._elem_box["header", width] = tuple(dict.fromkeys(
                m.group(0) for m in map(_FIELD_LHS.search, texts) if m))
        return got

    def _facts(self) -> tuple:
        """`_addr_facts` of this body, made the first time a row asks."""
        box = self._elem_box
        if "facts" not in box:
            box["facts"] = _addr_facts(self.blocks, self._preds,
                                       (self.entry, *self.roots), self.raw)
        return box["facts"]

    #: How many rows `_row_plain` reads back for one row, and how many ways into the
    #: blocks it passes it follows, before `_addr_facts` is made.
    _PLAIN_ROWS = 64

    def _row_computed(self, a) -> bool:
        """Whether `_addr_facts` has the row at `a` reading a register that may hold a
        computed address. Asked of the rows before it first (`_row_plain`), and of the
        analysis where they do not say or it is already made."""
        box = self._elem_box
        if "facts" not in box and self._row_plain(a):
            return False
        return a in self._facts()[0]

    def _row_plain(self, a) -> bool:
        """True where the rows on every way into the row at `a` show `_addr_facts`
        holds no fact for the register it reads, which is a plain value, without the
        analysis being made (#346).

        Nearly every body reads a class id, `ldur x2, [x1, #-1]`, and each asked for
        the analysis of the whole body to learn that x1 was loaded two rows up. A fact
        is put on a register only by a row that writes it: the rows that go on to
        change a fact change one that is there. So the rows are read back from `a` to
        the nearest write of the register on each way in, through a move to its
        source, and where each is a load, a call or another write that leaves no fact,
        there is none at `a` on any path, which is what the fixpoint holds. Anything
        else, arithmetic, a thread field loaded, a base that moves, a role register or
        more than `_PLAIN_ROWS` rows to read or ways in to follow, is the analysis's to
        say: a join has as many ways in as the body has branches to it, and reading
        each for every row under it would be quadratic. A way in with no write on it
        comes from a block nothing leads into, which the analysis starts with no fact
        at all. What a walk proved of a block's end is kept for the body, and the rows
        read and the ways in followed per asking row are bounded, so the cost stays
        linear."""
        box = self._elem_box
        at = box.get("rowat", _MISS)
        if at is _MISS:
            at = {}
            for b, blk in self.blocks.items():
                for i, t in enumerate(blk.insns):
                    at[t[0]] = None if t[0] in at else (b, i)
            box["rowat"] = at
        pos = at.get(a, _MISS)
        if pos is _MISS:
            return True                     # no row of the body: the analysis has none
        if pos is None:
            return False                    # in two blocks, and the analysis reads both
        blocks, raw = self.blocks, self.raw
        b, i = pos
        _a, mn, op, note = blocks[b].insns[i]
        if mn == "nop" and a in raw:
            (mn, op), note = raw[a], ""       # a blanked row, as the CPU runs it
        got = _af_row(mn, op, note)
        kind = got[0] if got is not None else None
        if kind in ("load", "store", "back"):
            r = got[1]
        elif kind == "addi":
            r = got[2]
        else:
            return True                     # not a row `computed` can hold
        roles = _af_target()[2]
        if r in ROLE or r in roles:
            return False
        proven = box.setdefault("plain", set())
        left, seen, work = self._PLAIN_ROWS, set(), [(b, i, r)]
        ways = left
        while work:
            b, i, r = work.pop()
            insns = blocks[b].insns
            while i:
                i -= 1
                left -= 1
                if left < 0:
                    return False
                at, mn, op, note = insns[i]
                if mn == "nop" and at in raw:
                    (mn, op), note = raw[at], ""
                if mn in _CALLS:
                    # `r` is no role register, so the call's row has it where the
                    # call forgets it, and the row is not made for the asking.
                    if r in _call_forgets(mn, note):
                        break
                    continue
                got = _af_row(mn, op, note)
                if got is None:
                    continue
                kind = got[0]
                if kind == "mov":
                    if got[1] == r:
                        r = got[2]
                        if r in ROLE or r in roles:
                            return False
                elif kind == "load":
                    if got[1] == r and got[4] != 0:
                        return False
                    for g in got[3]:
                        if g[0] == r:
                            return False
                    if r in got[2]:
                        break
                elif kind == "store":
                    if got[1] == r and got[3] != 0:
                        return False
                    if r in got[2]:
                        break
                elif kind == "mem":
                    if r in got[1]:
                        break
                elif kind == "plain":
                    if got[1] == r:
                        break
                elif kind == "def":
                    if r in got[1]:
                        return False
                elif kind != "back" and got[1] == r:
                    return False            # addi, addr, csel: arithmetic
            else:
                into = self._preds.get(b, ())
                ways -= len(into)
                if ways < 0:
                    return False
                for p in into:
                    if (p, r) not in seen and (p, r) not in proven:
                        seen.add((p, r))
                        work.append((p, len(blocks[p].insns), r))
        proven |= seen
        return True

    def _fresh(self, here) -> bool:
        """Whether the add or sub at `here` makes the pointer to an object the rows
        before it allocated (`_addr_facts`). An allocation stores back to a field of
        the thread, so a body with no such store is not asked."""
        box = self._elem_box
        if "back" not in box:
            thr = next((r for r, v in _T.roles.items() if v == _THR), None)
            rows = [(mn, op) for blk in self.blocks.values()
                    for (_a, mn, op, _n) in blk.insns if mn in ("str", "stur")]
            rows += [r for r in self.raw.values() if r[0] in ("str", "stur")]
            box["back"] = any((got := _addr(_split_ops(op))) is not None
                              and got[0][0] == thr for _mn, op in rows)
        return box["back"] and here in self._facts()[1]

    def _offset(self, total: V, src: V, reg: str, k: int, here, ops) -> V:
        """`total`, the printed `src + k` that the add or sub of an immediate at `here`
        made from register `reg`, with what is known of it (`V.at`, #329).

        The sum is `base + k` for the base `src` stands off, so a later access adds its
        displacement to one constant, and a chain that comes back to the base IS the
        base: `add x0, x1, #8; sub x0, x0, #8` holds x1, an object pointer if x1 is one,
        and a store through it is a store through x1. An untagged base other than the
        thread is not given back bare, because a copy of it is spelled with the tag
        bias and the register is not (`_byte_off`); the sum keeps its text and its
        base, and the access is made off that. Where the rows prove an inline
        allocation the sum is the new object's pointer and not a computed address."""
        if src.smi or not _whole(ops[:2]):
            return total                    # a tagged Smi's word, or 32-bit arithmetic
        base, k0, untagged, at = src.at if src.at is not None else (
            src, 0, _role_address(src) and src.text not in ("SP", "FP")
            or self._untagged(reg, src) and not self._frame_base(reg), here)
        k += k0
        if self._fresh(here):
            return replace(total, calc=False, at=(base, k, untagged, None))
        if k == 0 and (not untagged or base.text == _THR):
            return replace(base, at=None if at is None else (base, 0, untagged, at))
        if src.at is not None and _role_address(base) and base.text in ("SP", "FP"):
            # Off a frame register the constants are printed as one, the text a move
            # of the register leaves (`_role_stale`), so two ways in agree on it (#340).
            return _off_role(base, k, untagged, at)
        return replace(total, at=(base, k, untagged, at))

    def _computed(self, reg: str, v: V) -> bool:
        """Whether `reg`, holding `v`, may hold an address the lifter computed and not
        an object pointer, before the row being stepped: the value's own record, a
        Smi's tagged word, an untagged role's address in a copy, the register its base
        was read from, and, since the walk's map holds only what every path agrees on,
        the rows on every way in (`_addr_facts`). A value a Smi check left boxed is the
        object (`V.smi`)."""
        if v.smi:
            return v.smi == _SMI_TAG
        if v.calc or _role_address(v):
            return True
        return self._row_computed(self._here) or (
            v.at is not None and self._row_computed(v.at[3]))

    def _at_address(self, base_v: V, disp: int) -> tuple:
        """`_rebase` for a computed base at offset 0: the access at its address.

        The displacement goes into the base, as a negative one does, and the constants
        are made one off the base the sum stands on (`V.at`), read as that base reads:
        `add x0, x0, #1; add x5, x0, x5, lsl #2; stur w1, [x5, #-1]` is `(x0 + (x5 <<
        2)).field_0x1`, `sub x0, x2, #15; stur x1, [x0, #-1]` is `(x2 - 16).field_0x1` as
        `stur x1, [x2, #-16]` is, and `add x0, x26, #8; ldr x3, [x0, #-8]` is
        `THR.field_0x0`, with no tag bias off the thread. Only a chain that lands on
        the header of an object pointer it started from is `.tags`."""
        v = _smi_word(base_v) if base_v.smi else base_v
        base, k, untagged, at = v.at if v.at is not None else (v, 0, False, None)
        k += disp
        if untagged and k >= 0:
            return base, k, False
        if not untagged and k >= 0:
            return base, k + 1, True
        if (k == -1 and not untagged and v.at is not None and not base.calc
                and not base.smi and not _role_address(base)
                and not self._row_computed(at)):
            return base, 0, True
        if _INT_LITERAL.match(base.text):
            return _num(_to_s64(int(base.text, 0) + k)), 1, True
        return _bin(base, "-", _num(-k), P_ADD), 1, True

    def _covers(self, base_v: V, byte_off: int, width: int, cast=None,
                header: bool = True) -> tuple:
        """The other spellings of the bytes a `width`-byte write at `byte_off` covers.

        The width is in the spelling, so one write's bytes have more than one text and no
        two of them contain each other: a 16-byte write lands on what the two eight-byte
        reads inside it say, and an eight-byte write lands inside what a 16-byte read says
        at its own offset and at eight below it. `_pin_mem` matches all of them (#209).
        """
        # Four is not in the list: it prints the same text as eight (see `_field`), so
        # the eight-byte spelling already covers a four-byte access at this offset.
        out = [self._field(base_v, byte_off, w, cast, header).text
               for w in (1, 2, 8, 16) if w != width]
        if width == 16:
            out.append(self._field(base_v, byte_off + 8, 8, cast).text)   # its top half
        elif width == 8 and byte_off >= 8:
            # Not below the object: `byte_off` carries the tag bias, so 8 is the first
            # offset with a whole word under it.
            out.append(self._field(base_v, byte_off - 8, 16).text)
        # And the slot under its OTHER kind of spelling. A name and a byte offset are two
        # texts for one slot, and which one a read prints depends on what was known about
        # its base, not on where it reads: `this.balance` and `x2.field_0x8` are the same
        # address whenever x2 is the receiver, and a store through either left a live
        # read through the other standing. So every one-word slot the write lands on is
        # spelled both ways, by offset and by every name this walk has printed there.
        base = _wrap(base_v, P_POST)
        if byte_off:
            out += [f"{base}.field{w}_0x{byte_off:x}" for w in ("", "1", "2")]
        for off in (byte_off, byte_off + 8) if width == 16 else (byte_off,):
            out += [f"{base}.{n}" for n in sorted(self._named_at.get(off, ()))]
        return tuple(out)

    def _field(self, base_v: V, byte_off: int, width: int = 8, cast=None,
               header: bool = True) -> V:
        """The read or write of `width` bytes at `byte_off` off `base_v`, as text.

        `.field_0x8` is eight bytes, the word this machine spills and loads, and every
        narrower access in the general file is that read masked or extended (`_extended`).
        A SIXTEEN byte access says so: `.field16_0x8`. It had no spelling at all, so a
        `ldr q0` printed the eight-byte read of its low half and a `str q0` printed an
        eight-byte write, which makes a 16-byte copy character for character identical to
        an 8-byte one and names half the bytes it moves. 195 printed assignments on each
        fixture move sixteen bytes (#209).

        The width goes in the spelling because this output has no types to put it in.
        Ghidra gives a 128-bit register the type `undefined1 [16]` and slices it
        `._0_8_`, offset then size; Hex-Rays gives it `_OWORD`, a type whose only known
        property is that it is sixteen bytes, and casts for the halves. Neither leaves the
        width unsaid, and with no declarations here the statement is the only place left.

        A recovered field name is not taken for a 16-byte access, nor is `.tags`: a named
        field and the object header are each one word, and a read spanning two of them is
        not either of them.
        """
        # A name is printed for three bases and no others: the RECEIVER, whose class the
        # snapshot names through Function.owner, the result of an ALLOCATION this body
        # made, whose class it names through Code.owner, and a value on the edges after
        # a CAST to a class nothing implements (#240). `x3.field_0x8` stays an
        # offset even where some class has a field there: attributing it would be a guess
        # about which class x3 holds, and a wrong field name reads as fact where a byte
        # offset reads as "the lifter does not know".
        # A byte-offset spelling says nothing about how many bytes moved, so a byte store
        # and a word store printed the same text and a reader could not tell them apart.
        # Marked for every width but FOUR and eight (#221).
        #
        # Four is left alone because this target compresses pointers: 17,789 of the 20,941
        # four-byte loads on the clean build are followed by `add xN, xN, x28, lsl #32`,
        # the decompression, so a four-byte read is what a reference field read looks like
        # and the lifter prints the pointer it becomes. Marking those would decorate the
        # most common read in the output with the width of a representation, and say
        # "four bytes" where the value is an object reference. The genuinely unsaid widths
        # are one and two, 5,662 accesses, and sixteen, which has no other spelling at all.
        #
        # A RECOVERED name is still taken for a narrower access, because the name is the
        # field the access is in and a narrower read of it is that field's low part. The
        # width goes unsaid there, and saying it would need the name and the width both;
        # the byte-offset spelling is where it was unsaid with nothing else to go on.
        name = None
        if width <= 8:
            name = (self.fields.get(byte_off) if base_v.text == _RECEIVER
                    else self._alloc_field(base_v.text, byte_off, width))
            # The third base: a value a cast let through, whose class is one every
            # subtype of which extends it, so its map names the slot whatever the value
            # is (`cast`, from fields.cast_accesses). Taken only where the two above say
            # nothing, since they state the class exactly and a cast states a bound.
            if not name and cast is not None:
                name = cast.fields.get(byte_off)
                if name and name not in self._cast_names:
                    self._cast_names.add(name)
                    self._cast_re = None
        if name:
            tag = "." + name
            names = self._named_at.get(byte_off)
            if names is None:
                self._named_at[byte_off] = {name}
                self._named_n += 1
            elif name not in names:
                names.add(name)
                self._named_n += 1
        elif width not in (4, 8):
            tag = f".field{width}_0x{byte_off:x}"
        else:
            # `.tags` only where `_rebase` says offset 0 is an object's header (#329).
            tag = ".tags" if byte_off == 0 and header else f".field_0x{byte_off:x}"
        return V(f"{_wrap(base_v, P_POST)}{tag}", P_POST)

    def _reads_mem(self, text: str) -> bool:
        """True when this rendered value reads the heap somewhere inside it.

        `_READS_MEMORY` is the pattern, and this adds the one case a pattern cannot see.
        Its own comment gives the argument: once a field has a name the read no longer
        spells `field_0x`, so a pattern that only knew the byte offset would leave
        exactly the fields we understand best stale across a call. That was handled for
        the receiver by matching `this.<name>`, which is a fixed spelling. An allocation's
        result is a MINTED name, `t7`, so there is no spelling to match, and `t7.<name>`
        and `t7.someGetter` are the same shape; which names are allocation bases is a
        fact about this body rather than about the text (#240).

        Free where nothing was allocated, which is most functions: the set is empty and
        this is the pattern and nothing else."""
        if _READS_MEMORY.search(text):
            return True
        if self._cast_names:
            # A name printed off a cast's base, whatever spells that base: the base can
            # be any value at all, so the selector is the one thing to match.
            if self._cast_re is None:
                self._cast_re = re.compile(
                    r"\.(?:" + "|".join(re.escape(n) for n in sorted(self._cast_names))
                    + r")(?![\w$@])")
            if self._cast_re.search(text):
                return True
        return any(_base_re(n).search(text) for n in self._alloc_bases)

    def _alloc_field(self, base: str, byte_off: int, width: int):
        """The field name at `byte_off` of an object this body ALLOCATED, or None.

        `base` is the name `_result` minted for an allocation stub's result, so the class
        is the one the stub's owner Class states (fields.recover_allocations) and the map
        is that class's own. Not an inference about which class a register holds: it is
        the one object in the register file besides the receiver whose class was read.

        AND THE REFUSAL, which is the point. `instance_size` bounds the object, so an
        offset outside it cannot be a field of this class, and one that happens says
        either the attribution or the base tracking is wrong. Either way nothing off this
        base may be named again, so the whole attribution goes rather than the one access;
        the same argument `recover_fields` makes for refusing the whole map when one
        offset places outside its owner. Measured: all 7,504 accesses this attributes on
        the clean fixture and all 7,515 on the obfuscated one land inside, so the drop is
        a guard against being wrong and not a path the fixtures exercise.

        The WIDTH is deliberately not added to the bound, and `width` is here only to say
        why. The question is whether this offset can be a field of this class, and a field
        starts inside the object; a `ldr x` over the last two compressed slots is a read
        the compiler does emit, and its eight bytes overhang an instance_size that ends
        four bytes in. So does the eight-byte spelling `_covers` asks for to cover a
        four-byte write there. Neither is evidence that the class is wrong, and treating
        them as such cost 19 names on the clean fixture and 2 on the obf one.

        An offset INSIDE the object with no entry keeps its byte offset, which is 6,812 of
        the 7,504: the slot is real, its `Field` object was tree-shaken, and there is
        nothing to call it."""
        site = self.alloc_of.get(base)
        if site is None:
            return None
        if not 0 <= byte_off < site.instance_size:
            del self.alloc_of[base]
            return None
        return site.fields.get(byte_off)

    def _call_args(self, name, target, st: State, pushed=None) -> str:
        """Reconstruct a direct call's argument list, or `...` when it cannot be done
        safely. Register-convention calls pass args in x1..xk (k = callee arity); the
        stack convention (ArgumentsDescriptor set) and runtime stubs fall back to `...`.
        Every argument rendered is a real incoming arg of the callee (from its live-in
        set); the receiver of an instance call appears as the first argument.

        `pushed` is what the caller left in the outgoing area (_stack_args), the list a
        callee that reads only stack arguments takes. One that takes registers too, a
        StackArity, takes all six and then all of that, so long as it reaches every slot
        the callee reads; otherwise the list is not known (#148). One that takes only
        registers does not read it, so where they are not known the list is not either:
        3.4.4's `contains` printed a pushed 0 as the whole list of a callee that reads
        x1 and x2."""
        # A missing NAME was treated as a missing signature, and the two have nothing to do
        # with each other: the arity comes from the callee's own entry code, read at the
        # target address. 13,923 direct call sites on the corpus binary fell back to `...`
        # for no reason beyond the callee having no recovered name, which is exactly the
        # population (generated closures, and everything in an --obfuscate build) where
        # the argument list is the only thing left to read. Where the target is not a
        # function this can measure, entry_arity still declines and the `...` stands.
        listed = ", ".join(v.text for v in pushed) if pushed else "..."
        if (name and "stub" in name) or self.arity is None or target is None:
            return listed
        k = self.arity(target)
        if k is None:
            return listed
        # One whose register count falls short of six leaves a register argument it does
        # not read, or passes some in the V registers, and which is not said; and one
        # handed a double in a V register passes it beside the six, in no order said.
        # And where its loads do not say how far up it reads, nor how many were pushed.
        stack = isinstance(k, StackArity)
        if stack and (k < len(ARG_REGS) or k.fpu or not pushed or k.need is None
                      or len(pushed) < k.need):
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
        return ", ".join(parts + ([listed] if stack else []))

    def _stack_args(self, st: State, drop_receiver: bool, whole: bool = False,
                    values: bool = False):
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
        receiver is already printed as the call's base, it is dropped from the list.
        `values` asks for the values themselves rather than the list printed. A run that
        reaches the top half of a q register (_UPPER) is registers saved round the call,
        not its arguments, and says nothing (#162)."""
        if whole and _LOST in st.slot:
            return None                 # a push dropped part of it; see _frame_moved
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
            if not slots[n * 8].text:        # the top half of a q register (_UPPER)
                return None
            n += 1
        args = [slots[i * 8] for i in range(n - 1, -1, -1)]
        if drop_receiver:
            args = args[1:]
        return args if values else ", ".join(a.text for a in args)

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
        # Reading the `w` view of a register takes the low 32 bits, so a consumer that
        # reads one needs no truncation of its own and `_leaf` hands it the value
        # untruncated; the result is then truncated again here. The mask lands at the end
        # of a chain of 32-bit operations rather than on every step of it, which is where
        # a type-carrying decompiler puts its cast too (#235).
        self._here = addr
        gave = self._chain_gives(addr, mn, op)
        out = self._step_row(st, addr, mn, op, note)
        for r in gave:
            st.restore(r)
        return out

    def _chain_gives(self, addr, mn: str, op: str) -> tuple:
        """The registers the frame chain row being stepped gives back their role: FP
        where it is a write of the chain (`_fp_write` False) past one that was not, and
        LR where the pop is of the pair, and the register holds a value some row put
        there. The row is blanked or spelled off SP, so the register map still holds
        what the other write put there and would read it as the frame (#331)."""
        if mn != "nop" and "29" not in op and "30" not in op:
            return ()
        raw = self.raw.get(addr) if mn == "nop" else None
        if mn == "nop" and raw is None:
            return ()
        out = []
        # An FFI frame's pop is a load the walk steps, and x29 holds what it loads.
        if self._fp_lost() and not (mn in _LOADS):
            prev = self._insns[self._at - 1] if self._at else None
            if _fp_write(addr, mn, op, self.raw, prev) is False:
                out.append(_frame_regs()[1])
        if raw is not None and raw[0] == "ldp" and _lr() in _def_use(*raw)[0]:
            out.append(_lr())
        return tuple(out)

    def _step_row(self, st: State, addr, mn, op, note) -> list:
        ops = _split_ops(op)
        g = lambda r: self._leaf(r, st)

        # A trap renders nothing, like a nop: the machine never runs past brk, hlt, udf,
        # bkpt or trap, so none leaves text. Only brk and hlt were named here, so udf and
        # bkpt (an all-zero word read as code decodes to udf) leaked through as verbatim.
        if mn in TRAPS or mn == "nop" or (not ops and mn not in ("ret",)):
            return []

        flagged = self._note_flags(st, mn, op, ops, addr in self._flag_reads)
        # The flags are noted above and the value comes from the plain twin
        # (`_FLAG_VALUE`, #239). `mn` itself is kept for the width rule below, which is
        # the machine's and knows both spellings.
        out = self._step_rest(st, addr, _FLAG_VALUE.get(mn, mn), op, note, ops, g)
        # One place, after the branch that modelled the instruction, because the rule is
        # the machine's and not any one mnemonic's: a 32-bit destination clears the top
        # half of its register (#235).
        if mn in _NARROW32 and ops and ops[0].strip()[:1] == "w":
            dst = canon(ops[0])
            v = st.reg.get(dst)
            if v is not None and not _fits32(v):
                st.set(dst, _narrow(v))
        return flagged + out if flagged else out

    def _box_cut(self, st: State, addr, insns):
        """The box-or-tag check strip_boilerplate made unconditional at `addr`: the one
        rewrite there that leaves an unconditional `b` where a `b.eq`/`b.ne` was. The path
        it cut boxes the value as a Mint through AllocateMintShared*, whose fast path uses
        R1 as its temporary (AllocateMintABI::kTempReg, constants_arm64.h, 3.12.2), so
        past the join x1 holds what it held before on one path only. The compiler keeps
        nothing live in R1 across a box, so on compiled code this records a register
        nothing reads; on a crafted body it keeps an entry name, `this` or `a0`, from
        reading as a register the stub overwrote (#255). The register being boxed into is
        the value either way and is left alone."""
        k = next((j for j, t in enumerate(insns) if t[0] == addr - 8), None)
        if k is None or insns[k][1] != "sbfiz":
            return
        ops = _split_ops(insns[k][2])
        if ops and canon(ops[0]) != "x1":
            st.forget("x1")
        # The Smi path is taken only where `cmp xS, xD, asr #1` found the tag's own untag
        # equal to xS, so past it the register holds xS boxed (`_SMI_BOX`, #290).
        d = canon(ops[0]) if len(ops) >= 4 and _imm(ops[3]) == 31 else None
        if d is not None and st.reg.get(d, V("")).smi == _SMI_TAG:
            st.reg[d] = replace(st.reg[d], smi=_SMI_BOX)

    def _step_rest(self, st: State, addr, mn, op, note, ops, g) -> list:
        """_step past the flags: what the instruction does to `st`, and its lines."""
        # The instruction's own address, under a name of its own because `addr` is
        # reassigned to `_addr(ops)`, the parsed addressing mode, further down.
        here = addr

        # A machine narrower than a Dart `int` splits one value across two registers.
        if _T.pairs:
            paired = self._pair_step(st, mn, ops, g)
            if paired is not None:
                return paired

        # returns. Dart returns ints and references in R0 and doubles in V0/D0
        # (kReturnReg/kReturnFpuReg). Which one is _return_registers' question, and
        # st.result, whichever was written last, only answers where it has nothing to say.
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
            reg = self._returned().get(addr)
            if reg is None and st.result == _T.ret_fp:
                # Nothing decided this `ret`, and it falls back to the double only because
                # d0 was written last. That says nothing about which register comes back,
                # and naming what d0 holds would claim it: an allocate-and-fill that keeps
                # a spilled double named returned the field (#64). The register it would
                # be is all this says.
                return [f"return {_T.ret_fp};"]
            return [f"return {g(reg or st.result).text};"]

        # calls
        if mn == "bl":
            name = note.split("-> ", 1)[1].strip() if "-> " in note else None
            target = _imm(ops[0]) if ops and ops[0].startswith("#") else None
            exc = g(_T.ret_int)        # captured before the call clobbers it (throw)
            st.set(_T.ret_int, V(_T.ret_int, P_ATOM))
            # Read the outgoing area BEFORE dropping it, the order `blr` uses. `entry_arity`
            # declines for one reason, that the callee reads its arguments off the stack,
            # which is itself a statement that the caller pushed them. So the values are in
            # the outgoing area, and reading it after the drop always found it empty.
            pushed = (None if addr in self.save_wrapped
                      else self._stack_args(st, drop_receiver=False, whole=True,
                                            values=True))
            # A direct call consumes the outgoing area exactly as an indirect one does.
            # Leaving it behind let a bl's arguments be read back as the arguments of the
            # next blr, a fully fabricated argument list on a call that pushed nothing.
            _drop_outgoing(st)
            stub = _stub_of(note)
            if stub is not None:                # a VM runtime stub, not a source call
                kind, label = stub
                if kind == "suppress":
                    # These are the stubs that give the registers back. The shared
                    # stack-overflow and write-barrier entries exist precisely to spill the
                    # volatile set and restore it (`stub_code_compiler_arm64.cc`,
                    # GenerateSharedStub / kWriteBarrierWrappers), and a type-test stub
                    # preserves everything but its own answer. Suppressing the CALL while
                    # clobbering as though it happened would forget the whole loop body a
                    # header stack check sits in front of, for a call that provably keeps it.
                    # All but LR, which the `bl` itself writes (#162).
                    st.forget(_lr())
                    if "TypeTest" in name:
                        # ...and a type-testing stub gives back four registers, not
                        # the file: the instance, the type and the two type-argument
                        # vectors, x0, x8, x2 and x1 (constants_arm64.h, TypeTestABI::
                        # kPreservedAbiRegisters). x3, x5, x6 and x7 are its cache and its
                        # internals (kNonPreservedAbiRegisters), and all four are
                        # argument registers. One still spelled by its entry name would
                        # go on reading as the argument past a stub that overwrote it, and
                        # so would one the body copied an entry name into, `mov x5, x2`,
                        # or reloaded one into from a frame slot, so all of those are
                        # recorded. The compiler reloads what it needs after one, so no
                        # body on either fixture reads such a register there; a crafted
                        # body can (#255). What the walk holds in the other registers the
                        # stub loses is left as it was: forgetting all of it changes 637
                        # lines on the two fixtures, none of them a read past the stub.
                        ent = self._entry_word
                        for r in sorted((set(self.alias) | set(st.reg)) & _TTS_LOSES):
                            if r not in st.reg or (ent is not None
                                                   and ent.search(st.reg[r].text)):
                                st.forget(r)
                    return []
                pre = self._clobber_call(st)
                if kind == "throw":
                    return pre + [f"throw {exc.text};"]
                if kind == "rethrow":
                    return pre + ["rethrow;"]
                if kind == "throw_err":
                    return pre + [f"throw {label}();"]
                if kind == "alloc":
                    return pre + self._result(st, f"new {label}()", _T.ret_int)
                terse = label.replace("stub ", "").replace("_iso_stub_", "")
                # terse, without the stub prefix; a stub's result is an object
                return pre + self._result(st, f"{terse}(...)", _T.ret_int)
            # A per-class allocation stub, which the snapshot names through the Code's
            # owner Class rather than through any symbol (#240). Taken ahead of the name
            # because the owner is the stronger statement: a dwarf_stack_traces build's
            # symbol for one of these is a mangled stub label, and `new Color()` says the
            # same thing in the spelling the object-store allocation stubs already use.
            site = self.allocs.get(target) if target is not None else None
            call = name or self._sub(target or 0)
            args = "" if site is not None else self._call_args(name, target, st, pushed)
            # after the arguments are read, not before: they live in the very registers the
            # call is about to destroy, and reading them afterwards would print the bare
            # register for every argument of every call. `_pin_call` goes here for the same
            # reason, one step further: it renames what SURVIVES the call, and doing it
            # earlier would rename the arguments too.
            pins = self._pin_call(st)
            pins += self._clobber_call(st)
            # An allocation enters the runtime on its slow path, so it keeps the ordinary
            # call's invalidation rather than the register-preserving treatment a named
            # stub gets: the only thing that changes here is what the line says.
            if site is not None:
                return pins + self._result(st, f"new {site.name}()", _T.ret_int,
                                           alloc=site)
            # The receiver is NOT dropped from `pushed`, unlike the dispatch case. A `blr`
            # prints its receiver as the base of the call (`x.foo(...)`) so listing it
            # again would show it twice; a direct call has no base, so argument zero is
            # the receiver and leaving it out would silently shorten the list.
            return pins + self._result(st, f"{call}({args})")
        if mn in ("blr", "blx"):
            tgt = canon(ops[0]) if ops else None
            tgt_val = st.reg.get(tgt) if tgt else None
            st.set(_T.ret_int, V(_T.ret_int, P_ATOM))
            disp = self.dispatch.get(addr)
            recv, off = disp if disp is not None else (None, None)
            pushed = None
            if isinstance(recv, int):
                # The receiver is in no register by now, only in the slot it was pushed
                # to (_receiver_at). It is the call's base where that slot is argument
                # zero of the list read off the stack, and the call has none otherwise.
                vals = (None if addr in self.save_wrapped
                        else self._stack_args(st, False, values=True))
                if vals and (len(vals) - 1) * 8 == recv:
                    pushed = vals[0]
                recv = None
            stack_args = (None if addr in self.save_wrapped else self._stack_args(
                st, drop_receiver=recv is not None or pushed is not None))
            _drop_outgoing(st)          # consumed by this call; must not reach the next
            if disp is not None:                         # X21 dispatch-table (virtual) call
                named = self.selectors.get(off) if off is not None else None
                if named and off in getattr(self.selectors, "doubles", ()) and (
                        self._reads_next(_T.ret_int)):
                    # The selector returns a double and this call's result is read from
                    # x0: two selectors share the offset, and this is the other one. The
                    # clean build's `._widget.textScaleFactor` was a bool getter (#128).
                    named = None
                base = (_wrap(pushed, P_POST) if pushed is not None
                        else _wrap(self._leaf(recv, st), P_POST) if recv else None)
                pins = self._pin_call(st)   # after the receiver is read, and before it dies
                # after the receiver is read; it is x0 as often as not
                pins += self._clobber_call(st)
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
            pins += self._clobber_call(st)
            if tgt_val and tgt_val.prec >= P_POST and "DISPATCH" not in tgt_val.text:
                return pins + self._result(st, f"{_wrap(tgt_val, P_POST)}({shown})")
            return pins + self._result(st, f"(dynamic call)({shown})")

        # stores: object field (side effect) vs stack slot (tracked, no output)
        if _raw_store(mn):
            return self._raw_write(st, mn, op, addr) + self._verbatim(st, mn, op, op)
        if mn in _STORES:
            at = addr
            src = canon(ops[0])
            addr = _addr(ops)
            if addr is None or addr[1] is _BAD_POST:
                return self._raw_write(st, mn, op, at) + self._verbatim(st, mn, op, op)
            (base, disp, index, scale, wb), post = addr
            val = g(src)
            delta = disp if wb else post     # how far the base register moves, if at all
            if post:
                disp = 0                     # post-index: the access is at the OLD base
            frame = self._frame_base(base)
            if frame and delta:
                # Slots are keyed off where the frame register is once the store retires.
                # `stp a, b, [SP, #-0x10]!` moves SP first and stores at the NEW SP, so the
                # values land at SP+0 and SP+8. Keying them on the written displacement
                # would file them under an SP that no longer exists, which is how 2.19's
                # argument pushes went unseen. A post-index store lands where the register
                # was, one move below where it is now, off FP as off SP (#162).
                disp -= delta
            # `stp a, b, [base, #d]` writes TWO registers: a at d and b at d + one slot.
            # Recording only the first silently loses the second, which is how a call's
            # arguments went missing, they are pushed as pairs. One slot is as wide as
            # the register: `stp q0, q1` puts q1 16 bytes on (#162).
            pair = None
            if mn == "stp" and len(ops) >= 3:
                second = canon(ops[1])
                pair = (second, disp + _access_width(mn, ops[1]), g(second))
            # A base a JOIN lost is not the register's own name, whatever the map says.
            # The two arms disagreed about it, so `x2.field_0x10 = ...` claims the object
            # the function came in with while the machine has one of two others. That is
            # #206's rule at the other map, and #216's at the other end of the same
            # argument: a fallback must not borrow a name that already means something.
            # Named with no initialiser, `var tN;`, which says the lifter does not know
            # what this points at, so the store writes a field of something unknown
            # rather than of the wrong object. 17 stores in 11 ranges of the clean
            # fixture (#208).
            #
            # `lost` and not every register the walk drops to its bare name: a loop exit
            # drops the ones the loop writes, which takes this to 147 stores, and naming
            # those costs 152 more blocks holding nothing but a declaration nothing reads
            # and contradicts the thirteen loop-reload expectations in
            # `test_a_slot_or_lr_a_write_changed_out_of_sight_reads_as_changed`. Measured
            # and written up on the issue rather than shipped.
            #
            # Only an ordinary object register: SP, FP, THR and PP are roles whose value
            # is the same all the way through, and the frame path below has its own rules.
            basedecl = []
            if ((base in st.lost or base in st.opaque) and _T.roles.get(base) is None
                    and base not in self.alias):
                tmp, decl = self._mint(st)
                if decl:
                    basedecl.append(decl)
                self.raw_names.add(tmp)
                st.set(base, V(tmp, P_ATOM))
            if frame and index is not None:
                st.slot.clear()              # an offset _fold_frame_offsets left
                st.dropped.clear()
                return self._verbatim(st, mn, op, op)
            if frame:                                        # spill to a stack slot
                self._frame_moved(st, base, delta)
                width = _access_width(mn, ops[0])
                self._overwrite(st, at, base, disp, width, pair[1] if pair else None)
                # Saving the untouched link register is a callee-saved spill, not an
                # argument push. `str x30, [SP, #-8]!` lands at SP+0 exactly like a real
                # push, and _stack_args read it back as argument zero: `f(LR)`. A register
                # the function has since written to is a different matter, x30 doubles as
                # a scratch register, so the test is that x30 still holds the value it
                # came in with.
                out, named = [], {}
                if not (base == "x15" and _is_lr_spill(src, st)):
                    out += self._name_slot(st, at, f"{base}{disp:+d}", src, val, named)
                if pair and not (base == "x15" and _is_lr_spill(pair[0], st)):
                    out += self._name_slot(st, at, f"{base}{pair[1]:+d}", pair[0],
                                           pair[2], named)
                if width == 16:
                    # The top half of a q register, which no 8-byte argument is: a run
                    # from SP+0 that reaches one is saves, `stp q1, q3; blr; ldp q1, q3`,
                    # and _stack_args says nothing (#147, #162). A reload reads nothing.
                    for k in [disp] + ([pair[1]] if pair else []):
                        st.slot[f"{base}{k + 8:+d}"] = _UPPER
                return out
            if self._through_frame(at, mn, op):
                _forget_frame(st)        # it may be a slot: `sub x16, x29, #8` (#165)
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
            # An element access carries no width: the index is already scaled by the
            # element size, so a 16-byte element is `t3[t4]` either way (#209). One
            # `_elem_access` declines is the store to the address it computes (#308).
            # Each word of an `stp` is its own store, the second one register's width on:
            # off an element address only the first was printed (#316).
            # `ops[1]` and not `pair[0]` for the second, which `canon` has folded: s1 is
            # d1 there and would read as eight bytes where the store writes four. The
            # offset step has the same reason.
            #
            # The machine reads both registers of an `stp`, and its address, before it
            # writes either word, and the two lines print one after the other. So the
            # second line is built from the map as the first store's names left it,
            # with the registers it reads live for that store whatever comes after:
            # `ldur x1, [x13, #8]; stp x2, x1, [x13, #8]` printed `x13.field_0x11 =
            # x13.field_0x9` under the line that had just changed that field, which
            # stores x2 twice, and a base or an index that reads the first word was
            # read again the same way (#372).
            words = [(disp, ops[0], val)] + ([(pair[1], ops[1], pair[2])] if pair else [])
            out, cast = list(basedecl), self.cast_at.get((at, base))
            second_elem = (pair is not None and base in st.elem and self._elem_access(
                base, index, scale, st, pair[1]) is not None)
            for k, (d, reg, v) in enumerate(words):
                if k:
                    v = g(pair[0])
                elem = (self._elem_access(base, index, scale, st, d)
                        if index is not None or base in st.elem else None)
                if elem is not None:                          # element store
                    # Every element read is named, through any base (#343), and every
                    # field read that reaches the elements (#375). An element with no
                    # header shown is the store at its address, which may be to any
                    # field of any object (#341).
                    elems = not _FRAME_ROOT.match(elem.text.split("[", 1)[0])
                    edge = (self._elem_lo or None) if elems else None
                    tgt, also, anywhere = elem, (), elems and edge is None
                    since = None
                else:
                    w = _access_width(mn, reg)
                    # `_rebase` and not `_byte_off`: a displacement below the base goes
                    # into the base expression, so the offset is a field offset, never
                    # negative.
                    held = g(base)
                    bv, off, hdr = self._rebase(base, held, d)
                    cast = cast if off == d + 1 and bv is held else None
                    also = self._covers(bv, off, w, cast, hdr)
                    if self._byte_off(base, held, d) == 0 and not (bv is held and hdr):
                        # Offset 0 spelled as the access at its address. It may write
                        # any header word a live value read, as the `.tags` it was
                        # spelled as did: pinned as that spelling pins (#329).
                        also += self._header_selectors(w)
                    # A store at a computed address, at any offset, may be to any field
                    # of any object, so every live read of the heap is named first
                    # (#341).
                    tgt = self._field(bv, off, w, cast, hdr)
                    fresh = _fresh_v(held)
                    anywhere = not fresh and self._at_computed(base, held, bv)
                    # The bytes end here: an element read that can be below it is
                    # named (#375). Not for a store into the thread, the pool or the
                    # frame, which hold no Dart object: a store through a pointer
                    # read out of one of them is to whatever object that is. And for
                    # a store into an object these rows allocated, only an element
                    # read since the allocation, which is since its address was named
                    # at the store back to the thread: nothing read before the object
                    # was made is a word of it (#341).
                    elems = False
                    edge = (None if bv.text in _NO_OBJECT or _FRAME_ROOT.match(bv.text)
                            else off + w)
                    since = self._mint_at.get(held.at[0].text) if fresh else None
                # The value being stored was read off the map before this, so `+=` still
                # renders: the rhs keeps the field's own spelling even when a register
                # holding it is pinned on the way past.
                live, keep = self._live_after, None
                if pair and not k:
                    # Where the second word is an element, the address keeps its
                    # record, with names (`_pin_mem`); anywhere else the word is
                    # addressed off the base register.
                    keep = base if second_elem else None
                    self._live_after = live | _reg_mask(
                        (pair[0],) if keep else (pair[0], base))
                try:
                    out.extend(self._pin_mem(st, tgt.text, also, anywhere, elems, edge,
                                             keep, since))
                finally:
                    self._live_after = live
                out.append(self._assign(tgt, v))
            self._last_mem = ("store", base, disp, src0)
            return out + self._bump(st, base, delta)

        # A lane insert into the upper 64 bits of a V register (`ins v0.d[1], x5`, `mov
        # v0.d[1], v3.d[0]`, `fmov v0.d[1], x5`, a lane above the low doubleword of any
        # element size) leaves the low 64 bits, which dN names, unchanged. #114 forgot
        # dN on any write to a wider spelling, which declined a double the machine still
        # holds; here dN is kept, the wider spellings change and are forgotten, and the
        # insert prints raw, its upper lane not being modelled (#134).
        if ops and _upper_lane(ops[0]) and _fp_n(canon(ops[0])) is not None:
            n = _fp_n(canon(ops[0]))
            st.forget_hi(n)
            shown = self.show(addr, op) if self.show is not None else op
            return self._verbatim(st, mn, op, shown, keep=frozenset(("d" + n,)))

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
            st.set(canon(ops[0]), _prefix("-", src) if mn == "fneg" else V(
                f"{_wrap(src, P_POST)}.{'abs' if mn == 'fabs' else 'sqrt'}()", P_POST))
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
        # The two ways the VM zeroes a double register (#114): LoadDImmediate(0.0) emits
        # `eor vN.16b, vN.16b, vN.16b`, and `movi` with #0 does the same.
        zero = None
        if mn == "eor" and len(ops) == 3 and len({o.strip() for o in ops}) == 1:
            zero = ops[0].strip()
        elif mn == "movi" and len(ops) == 2 and _imm(ops[1]) == 0:
            zero = ops[0].strip()
        if zero and _ZEROED.fullmatch(zero):
            # Not a vote on which register the function returns: the VM zeroes a double
            # for a comparison as often as for a result, and counting it printed `return
            # 0.0;` in functions returning the object in x0 (lerp, clamp; see #115).
            result = st.result
            st.set("d" + _fp_n(zero), V("0.0", P_ATOM))
            st.result = result
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
            return self._verbatim(st, mn, op, op, dst)
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
                return self._verbatim(st, mn, op, op, dst)
            (base, disp, index, scale, wb), post = addr
            delta = disp if wb else post
            # The two shapes the ARM ARM leaves CONSTRAINED UNPREDICTABLE, where no one
            # outcome is the machine's, so the row stays as it is. A writeback into a
            # loaded register is one whatever the immediate: `[x8, #0]!` and `[x8], #0`
            # write back too, and were read as plain loads. An `ldp` into one register
            # twice is the other (LDPOVERLAP). capstone decodes neither, so only a row
            # that did not come from it reaches here (#293).
            moves = wb or "[" not in ops[-1]
            if ((moves and base in _regs(ops[:2 if mn in ("ldp", "ldpsw") else 1]))
                    or (mn in ("ldp", "ldpsw") and len(ops) >= 3
                        and canon(ops[0]) == canon(ops[1]))):
                return self._verbatim(st, mn, op, op, dst)
            if post:
                disp = 0                     # post-index: the access is at the OLD base
            if note.startswith("  ; = ") or note.startswith("; = "):
                st.set(dst, V(note.split("= ", 1)[1].strip(), P_ATOM))   # resolved pool const
                return []
            # A canonical object read straight out of the base register. arm64 reaches
            # true/false with an `add` off NULL and is handled there; arm32 has no null
            # register and LOADS all three out of the thread, so the same table is
            # consulted on the load path too, and through a copy of the thread as through
            # r10 itself, since the role is the value's (`_byte_off`, #273). Asked only
            # where the table is the thread's: arm64's is of addresses, null + 0x20 IS
            # true, and a load there reads the word inside the object, which `ldr x0,
            # [x22, #0x20]` printed as `true` (#317). The VM's own decoder names the two
            # off an `add` alone (instructions_arm64.cc, `IsAddSubImmOp` with Rn NULL_REG,
            # kTrueOffsetFromNull and kFalseOffsetFromNull in pointer_tagging.h), and so
            # do aotopsy and blutter.
            role = _T.roles.get(base)
            if _T.consts_base == _THR and g(base).text == _THR:
                role = _THR
            if (_T.consts_base == _THR and role == _T.consts_base and disp in _T.consts
                    and not index):
                st.set(dst, V(_T.consts[disp], P_ATOM))
                return []
            # `ldp a, b, [base, #d]` loads TWO registers, the second one slot further on.
            # Every base below reads both: the pool and an element address took the first
            # and returned, so the second register kept what it held (#306).
            second = None
            if mn in ("ldp", "ldpsw") and len(ops) >= 3:
                second = (canon(ops[1]), disp + _access_width(mn, ops[1]))
            words = [(dst, disp)] + ([second] if second else [])
            if _T.roles.get(base) == "PP":                   # unresolved ObjectPool entry
                for r, d in words:
                    st.set(r, V(f"pool_0x{d:x}", P_ATOM))
                return []
            if base in st.poolbase:              # far load: add base, then ldr off it
                # Both offsets before either register is written, which can be the base.
                offs = [(r, st.poolbase[base] + d) for r, d in words]
                for r, off in offs:
                    lbl = self.pool_map.get(off)
                    st.set(r, V(lbl if lbl else f"pool_0x{off:x}", P_ATOM))
                return []
            frame = self._frame_base(base)
            if frame and index is not None:
                return self._verbatim(st, mn, op, op, dst)       # as for a store
            if frame:                                        # reload a stack slot
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
                got = self._reload(st, f"{base}{disp:+d}", mn, ops[0])
                blind = [(canon(ops[0]), ops[0], disp)] if self._reload_blind else []
                st.set(dst, got)
                if second:
                    g2 = self._reload(st, f"{base}{second[1]:+d}", mn, ops[1])
                    if self._reload_blind:
                        blind.append((canon(ops[1]), ops[1], second[1]))
                    st.set(second[0], g2)
                out = self._name_blind(st, base, mn, blind, here)
                self._last_mem = ("load", base, disp, dst)
                self._frame_moved(st, base, delta)
                return out
            # The Mint half of an unbox, `ldur xD, [xB, #7]` past a `tbz wB, #0`: a boxed
            # value's Mint holds it at Mint::value_offset, 8, less the heap-object tag
            # (#290). The Smi half is the untag.
            boxed = g(base)
            if (boxed.smi == _SMI_BOX and disp == 7 and index is None and not delta
                    and mn in ("ldr", "ldur") and ops[0].strip()[:1] == "x"):
                st.set(dst, replace(boxed, smi=0))
                return []
            if index is not None or (base in st.elem and not second):   # element load
                elem = self._elem_access(base, index, scale, st, disp)
                if elem is not None:
                    st.set(dst, self._elem_read(elem))
                    return self._bump(st, base, delta)
                # Not one the lifter can show is an element: the load from the address
                # it computes, as off any other base (#308). An `ldp` reads each of its
                # words that way or as an element, below (#306).
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
            # A sign-extending load's destination holds the read widened to 64 bits, which
            # the field spelling's width does not say: `ldrsw x0` is the four bytes at that
            # address with the top bit copied up, and the shift pair is how `_extended`
            # spells that. Unsigned needs nothing, the width is in the spelling (#221).
            sign = mn in _SIGNED_LOADS
            # `_rebase` folds a displacement below the base into the base expression, so a
            # pre-indexed `ldr x16, [x1, #-8]!` reads `(t4 - 8).field_0x1` and not a
            # field at -7, which is not a field (see `_rebase`).
            # A cast names the base only where the access is at the offset it reads,
            # which a folded displacement is not.
            cast = self.cast_at.get((here, base))
            # Both words are read off the base as it was before the instruction: an `ldp`
            # whose first register is its base wrote it, and the second word was then read
            # off the value just loaded, `x8.field_0x9.field_0x11` for `ldp x8, x0, [x8,
            # #8]` (#293).
            at_base = g(base)
            got = []
            for k, (r, d) in enumerate(words):
                # A word of an `ldp` off an element address is an element where
                # `_elem_access` shows it is one, and otherwise the read at its address.
                v = (self._elem_access(base, None, scale, st, d) if base in st.elem
                     else None)
                if v is not None:
                    self._elem_read(v)
                else:
                    wk = _access_width(mn, ops[k])
                    bv, off, hdr = self._rebase(base, at_base, d)
                    if wk == 8:
                        # The spelling of a word does not say four bytes or eight,
                        # and an element store asks which (`_field_past`).
                        wide = self._elem_box.get("wide")
                        if wide is None:
                            wide = self._elem_box["wide"] = set()
                        wide.add(off)
                    v = self._field(bv, off, wk,
                                    cast if off == d + 1 and bv is at_base else None, hdr)
                    # A read at its address, at any offset: a store through any base
                    # may write it, and its spelling is no field of that base (#329,
                    # #341).
                    self._at_read(v.text, self._at_computed(base, at_base, bv))
                    if sign and wk < 8 and _reg_file(ops[k]) == "x":
                        v = _extended(v, 8 * wk, True)
                got.append((r, v))
            for r, v in got:
                st.set(r, v)
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
            # `b` is canonical because the role tables and `_UNTAGGED` are keyed that way;
            # the VALUE comes from the operand as written, so that reading the w view of a
            # register takes the low 32 bits (`_leaf`, #235).
            raw_b, b, c = ops[1], canon(ops[1]), ops[2]
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
                src = g(raw_b)
                st.set(dst, self._offset(_bin(src, "+", _num(imm), P_ADD), src, b, imm,
                                         here, ops))
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
            # The 4th field records whether the machine's base register held an UNTAGGED
            # address, because that is what decides whether a later displacement off this
            # base is an object header or a real element offset. See _elem_access. A copy
            # of the thread holds one as x26 does (`_byte_off`, #273), read before `dst`,
            # which can be the base, is written, and so does LR where it holds a return
            # address and nowhere else (#280).
            # A constant is not an address to take an element of (#328). Where the base
            # holds a number and the other register does not, and no shift scales it, the
            # sum is the same either way round, so it is recorded the way `add xD, xN,
            # xM` with the number in xM already was: element 0x238 of x3, not element x3
            # of 0x238. A shifted index off a number, or two numbers, is no element
            # address at all: the sum is the value and nothing is recorded.
            numeric = _imm(g(b).text) is not None
            swap = numeric and len(ops) < 4 and _imm(g(c).text) is None
            if swap:
                b = canon(c)
            untagged = self._untagged(b, g(b))
            # The 4th field is what `_elem_access` reads the displacement against: None
            # off an untagged base, where there is no header and an element is at 0,
            # else the data offsets the accesses this add reaches are made at (#308).
            if untagged:
                offs = None
            else:
                box = self._elem_box
                if "offs" not in box:          # once per body, whichever walk asks first
                    box["offs"] = _elem_offsets(self.blocks, self.data_offsets[1])
                offs = box["offs"].get(here, frozenset())
            # The base and index are read before `dst` is written, since it can be either
            # of them: `add x3, x3, x4, lsl #3` read x3 back as the address it had just
            # made and printed `(x3 + (x4 << 3))[x4]` for element x4 of x3 (#314).
            base_v, idx_v = (g(canon(c)), g(canon(raw_b))) if swap else (g(b), g(c))
            # A right shift scales by no power of two, so the index is the shifted value
            # itself, one byte a step: `add x2, x3, x4, asr #1` printed `x3[x4]`, the
            # element `lsl #0` names (#315). The VM shifts right by one only to untag a
            # Smi index (`ElementAddressForRegIndex`), but a register is read as holding
            # one only where the walk saw it tagged (#290); anywhere else its word is
            # shifted as the machine shifts it, `x4 >> 1`, and says no more than that.
            sh = (ops[3].strip().split()[0].lower()
                  if len(ops) >= 4 and ops[3].strip() else "")
            if sh in ("asr", "lsr"):
                amt = _imm(ops[3].split("#")[-1]) if "#" in ops[3] else 0
                if idx_v.smi and sh == "asr" and amt == 1:
                    val = _smi_value(idx_v)
                elif idx_v.smi:
                    val = _bin(_smi_word(idx_v), _SHIFT_SYM[sh], _num(amt), P_SHIFT)
                idx_v, scale = val, 0
            src, total = g(raw_b), _bin(g(raw_b), "+", val, P_ADD)
            if src.at is not None and src.at[1] and not src.smi and _whole(ops[:2]):
                # The constant the base stands off its own base by stays one: `add x0,
                # x0, #1; add x5, x0, x5, lsl #2` is `x0 + (x5 << 2)` and 1 (`V.at`).
                total = replace(total, at=(_bin(src.at[0], "+", val, P_ADD), src.at[1],
                                           False, None))
            st.set(dst, total)
            if not numeric or swap:
                st.elem[dst] = (base_v, idx_v, scale, offs)
            return []
        if mn == "sub" and len(ops) >= 3:
            b = g(ops[1])
            imm = _imm(ops[2])
            if imm is not None and len(ops) >= 4 and "lsl" in ops[3]:
                imm <<= (_imm(ops[3].split("lsl")[-1]) or 0)
            other = _num(imm) if imm is not None else self._src(ops, 2, st)
            if other is None:
                return self._raw(st, dst, mn, op)
            total = _bin(b, "-", other, P_ADD)
            if imm is not None:
                total = self._offset(total, b, canon(ops[1]), -imm, here, ops)
            st.set(dst, total)
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
                other = _prefix("~", other)
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
            st.set(dst, _prefix("-" if mn == "neg" else "~", src))
            return []
        if mn == "sdiv" and len(ops) >= 3:
            # `~/` is Dart's truncating integer division and arm64 sdiv truncates toward
            # zero, so the two agree exactly. udiv does NOT get the same treatment: it is
            # the same bits read unsigned, and `~/` would be a different answer on any
            # operand with the top bit set.
            #
            # The 32-bit form divides the LOW halves, read as signed: `sdiv w0, w1, w2`
            # printed `(x1 ~/ x2).toUnsigned(32)`, the whole registers divided, which is
            # 0x92b1d3f3 where the CPU has 0x35fdeca2 for x1 = 0x92b1d3f2ca02135e and
            # x2 = 0xffffffff (#291). Each operand is sign-extended from bit 31 unless
            # `_sext32` proves it already is, as a Smi untag is. The 64-bit quotient then
            # agrees with the CPU's in the low half for every input but a zero divisor,
            # INT32_MIN ~/ -1 included: 0x80000000 either way once truncated. A zero
            # divisor gives 0 on the CPU and a throw in Dart; the compiler tests the
            # divisor before it divides, so compiled code never reaches one.
            a, b = g(ops[1]), g(ops[2])
            if ops[0].strip()[:1] == "w":
                a, b = _signed32(a), _signed32(b)
            st.set(dst, _bin(a, "~/", b, P_MUL))
            return []
        if mn in ("madd", "msub") and len(ops) >= 4:
            prod = _bin(g(ops[1]), "*", g(ops[2]), P_MUL)
            st.set(dst, _bin(g(ops[3]), "+" if mn == "madd" else "-", prod, P_ADD))
            return []
        if mn == "mneg" and len(ops) >= 3:
            st.set(dst, _prefix("-", _bin(g(ops[1]), "*", g(ops[2]), P_MUL)))
            return []
        if mn in ("lsl", "lsr", "asr") and len(ops) >= 3:
            sym = _SHIFT_SYM[mn]      # one table, so the two spellings cannot drift apart
            amt = _imm(ops[2])
            # A register shift amount is not a shift by zero, which is what `or 0` made it.
            rhs = _num(amt) if amt is not None else g(ops[2])
            src = g(ops[1])
            narrow = ops[0].strip()[:1] == "w"
            fits = _fits(src, 32 if mn == "lsr" else 31)
            if mn != "lsl" and narrow and not fits:
                # A 32-bit shift right reads only the low half: the 64-bit register's top
                # half would shift into it (#130). Shown as a 64-bit value like every w
                # register, so exact in the low 32 bits for an amount under 32. A value
                # already masked to fit, as w values and hash mixing mostly are, needs
                # neither.
                src = (_bin(src, "&", V("0xffffffff", P_ATOM, bits=32), P_AND) if mn == "lsr"
                       else _to_signed(src, 32))
            st.set(dst, _bin(src, sym, rhs, P_SHIFT))
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
                    st.set(dst, _bin(src, "&", V(hex((1 << width) - 1), P_ATOM, bits=width), P_AND))
                else:
                    pad = 64 - width
                    st.set(dst, _bin(_bin(src, "<<", _num(pad), P_SHIFT), ">>",
                                     _num(pad), P_SHIFT))
            elif lsb == 1 and width == 31 and mn == "sbfx":
                # The Smi untag under compressed pointers: SmiUntag is sbfm with immr 1
                # and imms kSmiBits + 1 = 31. It takes bits 1 to 31 and sign-extends from
                # bit 31, so it is `src.toSigned(32) >> 1` for every 64-bit source. The
                # bare `src >> 1` is that only where bits 31 to 63 already agree, and the
                # VM leaves them zero after a 32-bit Smi add or LoadCompressedSmi and the
                # heap base after LoadCompressed: a negative Smi read as a large positive
                # one (#285). Only the low half is read, so a value a 32-bit write
                # truncated is read whole, as `_leaf` reads a w operand.
                u = src.wide if src.wide is not None else src
                if u.smi:
                    # A Smi tag read back. The tag prints the value it tags, so the
                    # arithmetic below would divide it a second time: `sbfiz x1, x2, #1,
                    # #0x1f; sbfx x0, x1, #1, #0x1f` printed `x2.toSigned(32) >> 1`, where
                    # the CPU has bits 0 to 30 of x2 sign-extended (#290).
                    st.set(dst, _smi_value(u))
                    return []
                st.set(dst, _bin(_signed32(u), ">>", _num(1), P_SHIFT))
            elif lsb + width >= 64:
                # The field runs to the top bit: a plain shift, arithmetic for sbfx.
                sym = ">>>" if mn == "ubfx" else ">>"
                st.set(dst, _bin(src, sym, _num(lsb), P_SHIFT))
            elif mn == "ubfx":
                field = f"0x{(1 << width) - 1:x}"
                st.set(dst, V(f"({_wrap(src, P_SHIFT)} >> {lsb}) & {field}", P_AND,
                              calc=True))
            else:
                # sbfx carries the field's top bit up, which `& mask` would clear (#124).
                inner = _bin(src, ">>", _num(lsb), P_SHIFT)
                st.set(dst, _to_signed(inner, width))
            return []
        if mn in ("sbfiz", "ubfiz") and len(ops) >= 4:
            lsb, width = _imm(ops[2]), _imm(ops[3])
            if lsb is None or width is None:
                return self._raw(st, dst, mn, op)
            src = g(ops[1])
            if lsb == 1 and width == 31 and mn == "sbfiz":
                # Smi tag (value << 1) under compressed pointers: show the value, and
                # record that the register holds it tagged, which the untag reads (#290).
                # A tag of a tagged register tags the word that register holds.
                st.set(dst, replace(_smi_word(src), smi=_SMI_TAG, wide=None))
            elif lsb == 1 and width == 63 and mn == "sbfiz":
                st.set(dst, src)                # Smi tag (value << 1): show the value
            else:
                # The low `width` bits of the source, sign- or zero-extended, then moved
                # up; `src << lsb` alone kept the bits above the field (#124).
                if lsb + width >= 64:
                    field = src
                elif mn == "ubfiz":
                    field = _bin(src, "&", V(hex((1 << width) - 1), P_ATOM, bits=width), P_AND)
                else:
                    field = _to_signed(src, width)
                st.set(dst, _bin(field, "<<", _num(lsb), P_SHIFT))
            return []
        if mn in ("sxtw", "uxtw", "sxth", "uxth", "sxtb", "uxtb") and len(ops) >= 2:
            # Not the identity. `sxtb` of 0xff is -1, and printing the source register said
            # 255: a confident wrong value, which is the one thing this lifter does not
            # emit.
            #
            # The unsigned forms have an exact Dart spelling, so they get it. The signed
            # ones are a shift pair, and it is exact because `>>` here IS arithmetic,
            # the same fact that makes `lsr` above `>>>` rather than `>>`.
            src = g(ops[1])
            width = {"b": 8, "h": 16, "w": 32}[mn[3]]
            if mn.startswith("u"):
                st.set(dst, _bin(src, "&", V(hex((1 << width) - 1), P_ATOM, bits=width), P_AND))
            else:
                pad = 64 - width
                st.set(dst, _bin(_bin(src, "<<", _num(pad), P_SHIFT), ">>",
                                 _num(pad), P_SHIFT))
            return []

        # not modelled: emit the raw arm64 (never wrong, no information lost). Of what
        # reaches here only `adr` names a code address, and `show` writes it as a virtual
        # address; the loads, stores and arithmetic kept raw above name none.
        shown = self.show(addr, op) if self.show is not None else op
        return self._verbatim(st, mn, op, shown, dst)

    def _elem_access(self, base_reg, index_reg, scale, st: State, disp: int = 0):
        """`base[index]` for a computed address, or None where the access is not one the
        lifter can show is an element; the caller then reads it as the address it is.

        An element address on a heap object is read at the data offset less the tag, so
        `add xD, xArr, xIdx, lsl #1; ldur wR, [xD, #0xf]` reaches element zero of an
        Array, and the displacement is absorbed. Every displacement used to be dropped,
        so two accesses at different ones printed as one element: `str x5, [x2, #0x17];
        str x6, [x2, #0x1f]` printed `x3[x4] = x5;` and then `x3[x4] = x6;`, which reads
        as the second overwriting the first where the machine writes two elements
        (#308). Which displacement is the data offset depends on the class, and that is
        not known; `_elem_offsets` gives the data offsets the address's accesses are
        made at, and only where there is one is it taken as the element's. The access
        there prints `base[index]`, one k strides on prints `base[index + k]`, and every
        other one, and every one off an address with none or two, returns None.

        A FRAME address has no header to absorb, so its offset is 0: .text+0x1050 in the
        3.12.2 clean build loads incoming arguments from [xN, #0x18] and [xN, #0x10] off
        one base, `FP[x4.field_0x14 - 4 + 6]` and `... + 4]`. The register-offset form,
        `[xB, xI]`, has no displacement at all."""
        if base_reg in st.elem:
            if index_reg is not None:
                # `[xD, xJ]` off an element address: the address plus a second index,
                # which the entry's own index does not say.
                self._elem_lo = 0
                return V(f"{_wrap(self._leaf(base_reg, st), P_POST)}"
                         f"[{self._leaf(index_reg, st).text}]", P_POST)
            base_v, idx_v, s, offs = st.elem[base_reg]
            claim, reach = self.data_offsets
            if offs is None:
                at = 0
            elif disp in reach and disp not in offs:
                return None              # an access `_elem_offsets` did not count
            elif len(offs) == 1 and next(iter(offs)) in claim:
                at = next(iter(offs))
            else:
                return None
            k, rem = divmod(disp - at, 1 << s)
            if rem:
                return None
            idx = (idx_v.text if k == 0 else _bin(idx_v, "+", _num(k), P_ADD).text
                   if k > 0 else _bin(idx_v, "-", _num(-k), P_ADD).text)
            # The lowest field offset the access reaches with an index of zero or more:
            # the data offset with the tag bias, less the strides below the index. 0
            # where no header was shown, which says nothing about where it is.
            # That the index is zero or more is assumed, not proven: compiled Dart
            # checks an index against the length before it uses it, and the rows are
            # not searched for the check. `asr x8, x7, #63` as the index is -1 or 0,
            # and its element is the word below the data offset (`_pin_mem`, #375).
            self._elem_lo = max(at + 1 + (k << s if k < 0 else 0), 0) if at else 0
            return V(f"{_wrap(base_v, P_POST)}[{idx}]", P_POST)
        self._elem_lo = 0
        base_v = self._leaf(base_reg, st)
        idx_v = self._leaf(index_reg, st) if index_reg else V("0", P_ATOM)
        return V(f"{_wrap(base_v, P_POST)}[{idx_v.text}]", P_POST)

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
    def _carry_out(self, st: State, pad: str, leaving: bool, target=None) -> list:
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
        as a break does, and the flag only says which frame's names to use. `target` is
        the block a goto goes to, which `_arrive` hands the state it is entered with.
        """
        if not self._carrying:
            return []
        header, names, copied = self._carrying[-1]
        # Read every value BEFORE any of them is written back: this is the same parallel
        # copy the back edge makes, and one name that another reads has to be captured
        # first. See _parallel_copy.
        here = [(r, st.get(r)) for r in sorted(names)]
        here = [(r, v) for r, v in here if v.text != names[r]]
        pins = ([] if target is None else
                self._arrive(target, st, {names[r]: r for r, _v in here}, pad))
        out = pins + self._parallel_copy(st, [(names[r], v) for r, v in here], pad)
        for r, _v in here:
            copied.add(r)
            if leaving:
                st.reg[r] = V(names[r], P_ATOM)
        # A register this edge does NOT write back still holds the NAME in the state the
        # target is handed, so the target may print it. `_render_loop` collapses a name
        # the body never assigned and substitutes the entry value back into the body and
        # the tail, which does not reach a block outside the loop: six reads of a name no
        # line declares, in `parsePartialNumber` on both fixtures (#205). Counted as
        # escaped for the same reason a written-back one is: the name is out in the
        # output, so the loop cannot take it back.
        #
        # Only where `_arrive` hands over that state at all, which is where the target has
        # exactly ONE predecessor: a join starts from what every way in agrees on and
        # reads the register bare, so the name never reaches it and keeping one would be a
        # tautology, `var t1 = x7;`, with the note on a raw line then reporting `x7 holds
        # t1`, which tells a reader nothing.
        if target is not None and len(self._preds.get(target, ())) == 1:
            live = _mask_regs(self._livein.get(target, 0))
            copied.update(r for r in names if r in live)
        return out

    def _arrive(self, addr, st: State, moved: dict, pad: str = "") -> list:
        """Record the state a goto hands `addr`; return what to write out first (#106).

        `_reenter` gave a block only a jump reaches the exit state of its one predecessor,
        and that state was recorded BEFORE the printed program writes names back on the
        way there: in the goto's own write-back, and in a `break`'s when the goto comes
        right after a loop. A write-back changes what a NAME means, and the target went on
        reading the old meaning. 3.4.4's parsePartialString printed `t0` for a register
        that holds the `t0` from before `t0 = x0;`, and 2.19.6's parsePartialKeyword
        returned `t4 + 1` after `t4 += 1;`, one more than the CPU does.

        Straight from its block, the walk's own state at the goto is that exit state.
        Right after a loop it is the state past the loop, which holds for every way out of
        it and so knows less, so there the exit state is kept and only what mentions a
        name the breaks on this path wrote back is taken from the walk. Then, for the
        names this goto writes back (`moved`, name -> register), a value spelled exactly
        as one of those registers IS that name once the copy has run, and anything else
        that mentions one is written out first, once per value, while it still means what
        it says. Most of those nothing reads; `_lift_function` keeps the ones read."""
        preds = self._preds.get(addr, ())
        if len(preds) != 1:
            return []                       # _reenter starts from nothing here anyway
        left = self._exit.get(preds[0])
        if isinstance(st.src, frozenset) and preds[0] in st.src and left is not None:
            got = left.copy()
            stale = _mentions(self._broke.get(preds[0], ()))
            # The record comes from the same predecessor the slot map does, and takes the
            # same text test: these two do not invalidate anything, they describe another
            # path, so forgetting here would throw away a record still true on it. Whether
            # the arriving path has PRINTED to a register the text names is asked at the
            # reload instead, by `_printed_regs` and `printed_prior`, which are
            # function-wide.
            got.dropped = {k: (v, f) for k, (v, f) in got.dropped.items()
                           if not stale(v.text)}
            for r, v in sorted(got.reg.items()):
                if stale(v.text):
                    got.reg[r] = st.get(r)
                    got.elem.pop(r, None)
                    got.poolbase.pop(r, None)
            for k, v in sorted(got.slot.items()):
                if stale(v.text):
                    del got.slot[k]
            for k, (b, i, *_r) in list(got.elem.items()):
                if stale(b.text) or stale(i.text):
                    del got.elem[k]
        else:
            got = st.copy()
        moves = _mentions(moved)
        now = {}
        for n in sorted(moved, reverse=True):
            now[got.get(moved[n]).text] = n
        out, pinned = [], {}
        live = self._livein.get(addr, 0)
        for side, held in (("reg", got.reg), ("slot", got.slot)):
            for k, v in sorted(held.items()):
                if not moves(v.text):
                    continue
                n = now.get(v.text) or pinned.get(v.text)
                if n is None:
                    # The first walk writes out what can be read at all: a register live
                    # at the target or one a call can take, which liveness counts only
                    # where the callee's arity is known, and a slot the function loads
                    # somewhere. Which of those is read decides what the second walk
                    # writes out.
                    if self.keep is not None:
                        want = (addr, side, k) in self.keep
                    elif side == "reg":
                        want = (k in ARG_REGS or k == _T.ret_int
                                or live & _reg_mask((k,)))
                    else:
                        want = k in self._slot_loads()
                    if want and self.keep is None and len(self.pins) >= _MAX_PINS:
                        want = False            # a crafted function: forget, a decline
                    if not want:
                        if side == "reg":
                            got.forget(k)
                        else:
                            del held[k]
                        continue
                    n, decl = self._mint(st, v.text, pad)
                    pinned[v.text] = n
                    out.append(decl)
                    self.pins[n] = (addr, side, k)
                    # Set on the goto's path, and that is every path into its one-way
                    # target; see the join in `walk`.
                    self._anchor[int(n[1:])] = addr
                held[k] = V(n, P_ATOM)
                if side == "reg":
                    got.elem.pop(k, None)
                    got.poolbase.pop(k, None)
        for k, (b, i, *_r) in list(got.elem.items()):
            if moves(b.text) or moves(i.text):
                del got.elem[k]
        self._came[addr] = got
        return out

    def _slot_loads(self) -> set:
        """The frame slots this function loads anywhere, keyed as `State.slot` is."""
        if self._loads is None:
            self._loads = set()
            for blk in self.blocks.values():
                for (_a, mn, op, _n) in blk.insns:
                    if mn not in _LOADS:
                        continue
                    ops = _split_ops(op)
                    got = _addr(ops)
                    if got is None or got[1] is _BAD_POST:
                        continue
                    (base, disp, index, _s, _wb), post = got
                    if _T.roles.get(base) not in ("SP", "FP") or index is not None:
                        continue
                    disp = 0 if post else disp
                    self._loads.add(f"{base}{disp:+d}")
                    if mn in ("ldp", "ldpsw") and len(ops) >= 3:
                        w = 4 if ops[1].strip()[:1] == "w" else 8
                        self._loads.add(f"{base}{disp + w:+d}")
        return self._loads

    def _note_break(self, st: State):
        """Record the names this `break` writes back, against the block it leaves."""
        header, names, _c = self._carrying[-1]
        if isinstance(st.src, int):
            self._broke[st.src] = frozenset(n for r, n in names.items()
                                            if st.get(r).text != n)
            self._breakers.setdefault(header, set()).add(st.src)

    def _note_goto(self, addr):
        """Record the registers a goto out of a loop may hand its target unknown (#154).

        `_render_loop` forgets at the header each register the loop writes and does not
        carry, and one the trip has not written by the goto reaches it as itself, or as
        a name a join bound to it. Where the target reads it, that reads as the last value
        a printed line put there, which can be a raw line's from an earlier trip, the
        hazard a `break` has (#123). So it is an exit hazard of each loop the goto leaves,
        and _lift_function carries it there where a printed line writes it. Not of a loop
        the goto stays in: its target reads the register only where every way there from
        the header writes it, or the loop would carry it already, so a name there would
        say nothing a reader needs. Nor where the target is a join: it starts from what
        every way in agrees on (_reenter, _join_kill), not from the goto's state, so it
        reads the register bare whatever the loop names. Where the target IS a join, the
        loop still has to carry the register: a join-phi (see _join_write) reads a name
        written on each edge in, and the goto's write-back gives it the loop-carried value
        rather than the bare register the loop forgot at its header (#123)."""
        live = _mask_regs(self._livein.get(addr, 0))
        for header, _names, _copied in self._carrying:
            hit = live & self._unset.get(header, {}).keys()
            if hit and addr not in self._trip_body(header):
                self.exit_hazards.setdefault(header, set()).update(hit)

    def _leaves_loop(self, addr) -> bool:
        """True when a goto to `addr` jumps out of the loop currently being walked."""
        if not self._carrying:
            return False
        # `_back_loop`, the natural body, and not `_loop_nodes`: the latter closes
        # backward over every predecessor, so it holds the blocks BEFORE the loop too,
        # all 6,131 loops on the clean fixture and 70,789 such blocks, and a goto back to
        # one of those then read as staying inside the loop and wrote nothing back (#129).
        # `_loop_nodes` is right where it is asked what the loop may WRITE, which is an
        # over-approximation, and where the blocks before the loop stand for the ones
        # between a store and the loop (#140); this question is not that one.
        return addr not in self._back_loop(self._carrying[-1][0])

    def _dominators(self, addr) -> frozenset:
        """The blocks every path from the entry to `addr` passes through before it."""
        out, n = set(), self._idom.get(addr)
        while n is not None and n not in out:
            out.add(n)
            n = self._idom.get(n)
        return frozenset(out)

    def _dominates(self, a, b) -> bool:
        """Whether `a` is one of `_dominators(b)`, in O(1) from the numbering of the
        forest (cfg.dom_numbers) and not by walking `_idom` up from `b`, which asked once
        per block a loop dominates took 42 million steps for 500 loops in a row (#282).
        The meaning is the walk's: a block above `b` in its tree, and `b` itself only
        where it roots one, as a root is its own idom; nothing for a block in no tree,
        nor across two trees."""
        if self._idom is None:
            self._dom_tree()
        num = self._dnum
        if num is None:
            return a in self._dominators(b)
        pre, end = num[0], num[1]
        if a not in pre or b not in pre:
            return False
        if a == b:
            return self._idom[b] == b
        return pre[a] <= pre[b] < end[a]

    def _dom_tree(self):
        """The dominator tree, `_idom`, from the entry and from each proven entry no edge
        reaches (`roots`, dominator_forest), and which root each block's tree hangs off,
        `_root_of`. Without `roots` it is the entry's tree alone, as it always was."""
        self._idom, _order, trees = dominator_forest(
            self.blocks, self.entry,
            lambda n: self.blocks[n].succ if n in self.blocks else (), self.roots,
            self.placed)
        self._dnum = dom_numbers(self._idom)
        self._root_of = {n: r for r, nodes in trees for n in nodes}

    def _join_kill(self, addr, entry=False) -> tuple:
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
        hit = self._killcache.get((addr, entry))
        if hit is not None:
            return hit
        if self._idom is None:
            self._dom_tree()
        # backward: every block that can reach addr without going through it again
        # `entry`: the ways into a loop's head only, not the latches it dominates, whose
        # values the loop's own names carry (#125).
        preds = self._preds.get(addr, ())
        if entry:
            preds = [p for p in preds if not self._dominates(addr, p)]
        d = self._idom.get(addr)
        mask = (self._kill_mask(addr)
                if self._kwalked >= _KILL_WALK * len(self.blocks) else None)
        if mask is not None:
            # The same three answers, off the dominator tree and no walk (#333).
            regs = _kill_regs(mask)
            self._killroles[(addr, entry)] = _frame_roles(regs)
            self._killcache[(addr, entry)] = hit = (
                regs - _SPECIAL,
                bool(mask & _KILL_STACK) or self._frame_escaped(),
                bool(mask & _KILL_HEAP))
            return hit
        if d is not None and d != addr and addr not in self._root_of:
            back = self._between(d, addr, preds)
        else:
            back, stack = set(), list(preds)
            while stack:
                n = stack.pop()
                if n in back or n == addr:
                    continue
                back.add(n)
                stack.extend(self._preds.get(n, ()))
        self._kwalked += len(back) + 1
        if d is not None and d != addr and addr in self._root_of:
            # forward from the dominator, which is where the paths part. The dominator
            # itself is one block with one exit state, so what IT writes is agreed on.
            fwd, stack = set(), [s for s in self.blocks[d].succ if s in self.blocks]
            while stack:
                n = stack.pop()
                if n in fwd or n == addr:
                    continue
                fwd.add(n)
                stack.extend(s for s in self.blocks[n].succ if s in self.blocks)
            self._kwalked += len(fwd)
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
        regs = frozenset(self._written(back))
        self._killroles[(addr, entry)] = _frame_roles(regs)
        self._killcache[(addr, entry)] = hit = (regs - _SPECIAL,
                                       self._writes_stack(back),
                                       self._writes_heap(back))
        return hit

    def _between(self, d, addr, preds) -> set:
        """The blocks `_join_kill` asks about, for an `addr` in the entry's tree with `d`
        its immediate dominator: those that reach one of `preds` without passing `addr`,
        and that `d` reaches the same way. Walked back from `preds`, and on only from a
        block that is one of them, as every block on such a path from one of them is one
        too. The walk back over every block that reaches `addr` and the walk on over every
        block `d` reaches, each nearly the function, made N loops leaving by a goto into
        the next one's head cost about N * N (#289).

        The entry's tree holds every block the entry reaches and no other, so a path
        from `d` stays in it. A block below `d` in the tree is one: the entry reaches it
        by a path that passes `d` and, unless `addr` is above it too, one that avoids
        `addr` after that. Any other block on a path from `d` into `addr` reaches `d`
        again, as `d` is on every path from the entry to `addr`: it is in `d`'s strongly
        connected piece (_pieces), and is one where `d` reaches it within that piece."""
        piece = self._pieces()[0]
        home, near = piece.get(d), None

        def one(m):
            nonlocal near
            if m != d and self._dominates(d, m):
                return not self._dominates(addr, m)
            if piece.get(m) != home:
                return False
            if near is None:
                near, stack = set(), list(self.blocks[d].succ)
                while stack:
                    n = stack.pop()
                    if n in near or n == addr or piece.get(n) != home:
                        continue
                    near.add(n)
                    stack.extend(self.blocks[n].succ)
            return m in near
        back, seen, stack = set(), set(), list(preds)
        while stack:
            n = stack.pop()
            if n in seen or n == addr:
                continue
            seen.add(n)
            if one(n):
                back.add(n)
                stack.extend(self._preds.get(n, ()))
        return back

    def _kill_mask(self, addr):
        """What `_join_kill` asks of the blocks between `addr` and its immediate
        dominator `d`, as one mask (_kill_bits), or None where it has to walk them.

        Walked once per join, those blocks made N conditionals that each jump over the
        next cost about N * N, as each one's join hangs off the first conditional and the
        blocks between are most of the function (#333). They are the ones on a path from
        `d` into `addr` that passes neither again, and in the entry's tree, where every
        such block is below `d` or in `d`'s strongly connected piece (_between), that is:

          T1, the blocks below `d` and not below `addr` that reach `addr`, and
          T2, where `d` is on a cycle that `addr` is not on, all of `d`'s piece, which
              reaches `d`, as `d` reaches it, without passing `addr`.

        Where `addr` is on no cycle, T1 is what each way in reaches from below `d`:
        `chain` up the tree from that way in, each block's `kin` saying what reaches it
        from below its own dominator (_kill_fold). Where `addr` is on one and
        `d` is not, `addr` is a way into its piece and T1 is the rest of the piece and
        what reaches the piece from below `d`. Where both are on the same cycle, T1 is
        the piece below `d` and not below `addr`, and T2 what `d` reaches of the rest
        without `addr`, which is `escape`'s. Another root's tree is the entry's case where
        no path leaves it and comes back, as a mono entry's body is. A block in no tree,
        in a tree a path comes back into, or in one that is no forest (cfg.dom_numbers),
        is walked as it was."""
        fold = self._kill_fold()
        if fold is None:
            return None
        depth, kin, chain, span, outside, live, escape = fold
        pre, end, _kids = self._dnum
        if addr not in kin:
            return None
        d = self._idom[addr]
        piece, order = self._pieces()
        home, there = piece[addr], piece[d]
        if home == there:
            return (span(home, pre[d] + 1, pre[addr]) | span(home, end[addr], end[d])
                    | escape(d, pre[addr], end[addr]))
        if live(addr):
            mask = (span(home, pre[d] + 1, pre[addr]) | span(home, end[addr], end[d])
                    | outside(home, d))
        else:
            mask = 0
            for p in self._preds.get(addr, ()):
                if p in pre and pre[d] < pre[p] < end[d]:
                    mask |= chain(p, d)
        if live(d):
            mask |= span(there, -1, len(pre))
        return mask

    def _kill_fold(self):
        """(depth, kin, chain, span, outside, live, escape) for `_kill_mask`, once:

        `kin[v]` says what the blocks below `e`, the immediate dominator of `v`, that
        reach `v` or are `v` write. A block `m` below `e` that reaches a way into `v`,
        `p`, is either below `p`'s own dominator `q`, and so in `kin[p]`, or reaches `q`,
        as the path from the entry to `m` passes `q` by and the one on to `p` cannot. So
        what `m`s there are is `kin` of each block from `p` up the tree to just below `e`,
        and `chain(p, e)` folds that, in jumps of a power of two up the tree. On a cycle,
        `v`'s piece is in it, or the part of it below `e` where `e` is on the cycle too;
        `e` is above every block of the piece where it is not, and what reaches the
        piece from outside is `outside`. The pieces come in order, each after every piece
        with an edge into it, and a block's dominators are in its piece or earlier ones,
        so each `kin` is done before a `chain` asks for it. Where `e` is on a cycle `v` is
        not on, the part of `e`'s piece below it reaches `v` through `e`, and those are
        the only ones that reach it only that way.

        `span(piece, lo, hi)` is what that piece's blocks numbered in [lo, hi) write
        (cfg.dom_numbers), and `live(n)` whether `n` is on a cycle. Each block and edge
        is seen once, and each `chain` takes a jump per bit of a depth. None where the
        tree is no forest.

        `escape(d, lo, hi)`, for a `d` on a cycle, is what the blocks of its piece that
        are not below it, `d` among them, write where `d` reaches them by a path that
        leaves its subtree by an edge from a block not numbered in [lo, hi). From such a
        block, `rest`, the path can only come back below `d` through `d`, which leaves by
        the same edges, so it is what each edge's target reaches within `rest`. Worked
        out once per `d`, over its piece."""
        if self._kfold is not None:
            return self._kfold or None
        if self._idom is None:
            self._dom_tree()
        num = self._dnum
        if num is None:
            self._kfold = ()
            return None
        pre, end, kids = num
        idom, root_of, preds = self._idom, self._root_of, self._preds
        piece, order = self._pieces()
        # Nothing below holds the lifter, which would keep it past its walk in a cycle.
        blocks, own = self.blocks, {b: self._kill_bits(b) for b in pre}.__getitem__
        depth: dict = {}
        for n in sorted(pre, key=pre.get):
            d = idom[n]
            depth[n] = 0 if d == n else depth[d] + 1

        def live(n):
            return len(order[piece[n]]) > 1 or n in blocks[n].succ

        tables: dict = {}

        def span(i, lo, hi):
            got = tables.get(i)
            if got is None:
                members = sorted((m for m in order[i] if m in pre), key=pre.get)
                keys = [pre[m] for m in members]
                rows = [[own(m) for m in members]]
                w = 1
                while 2 * w <= len(members):
                    last = rows[-1]
                    rows.append([last[j] | last[j + w] for j in range(len(last) - w)])
                    w *= 2
                got = tables[i] = (keys, rows)
            keys, rows = got
            a, b = bisect.bisect_right(keys, lo - 1), bisect.bisect_left(keys, hi)
            if a >= b:
                return 0
            k = (b - a).bit_length() - 1
            return rows[k][a] | rows[k][b - (1 << k)]

        kin: dict = {}
        up, acc = [idom], [kin]

        def jump(v, j):
            while len(acc) <= j:
                up.append({})
                acc.append({})
            got = acc[j].get(v)
            if got is None:
                u, w = jump(v, j - 1)
                w2, m2 = jump(u, j - 1)
                up[j][v], acc[j][v] = w2, (got := w | m2)
                return w2, got
            return up[j][v], got

        def step(v, j):
            if j == 0:
                return idom[v], kin[v]
            return jump(v, j)

        def chain(p, e):
            steps, j, mask = depth[p] - depth[e], 0, 0
            while steps:
                if steps & 1:
                    p, got = step(p, j)
                    mask |= got
                steps >>= 1
                j += 1
            return mask

        outs: dict = {}

        def outside(i, e):
            got = outs.get((i, e))
            if got is None:
                got = 0
                for w in order[i]:
                    for p in preds.get(w, ()):
                        if piece[p] == i or p not in pre:
                            continue
                        if pre[e] < pre[p] < end[e]:
                            got |= chain(p, e)
                outs[(i, e)] = got
            return got

        # Another root's tree is one as the entry's is only where no path leaves it and
        # comes back, which would pass its dominators by: no edge comes in from outside
        # but to its root, and none of its blocks is on a cycle with one outside.
        trees: dict = {}
        for n, r in root_of.items():
            trees.setdefault(r, []).append(n)
        shut = {r for r, ns in trees.items()
                if all((n == r or all(root_of.get(p) == r for p in preds.get(n, ())))
                       and all(root_of.get(m) == r for m in order[piece[n]])
                       for n in ns)}
        for i, members in enumerate(order):
            for v in members:
                if (v not in pre or idom[v] == v
                        or (v in root_of and root_of[v] not in shut)):
                    continue
                e = idom[v]
                if not live(v):
                    mask = own(v)
                    for p in preds.get(v, ()):
                        if p in pre and pre[e] < pre[p] < end[e]:
                            mask |= chain(p, e)
                elif piece[e] == i:
                    mask = span(i, pre[e] + 1, end[e])
                else:
                    mask = span(i, pre[e], end[e]) | outside(i, e)
                if piece[e] != i and live(e):
                    mask |= span(piece[e], pre[e] + 1, end[e])
                kin[v] = mask
        exits: dict = {}

        def escape(d, lo, hi):
            got = exits.get(d)
            if got is None:
                i = piece[d]
                rest = {m for m in order[i] if not pre[d] < pre[m] < end[d]}
                parts = strong_components(
                    rest, lambda n: [s for s in blocks[n].succ if s in rest])
                at = {m: j for j, ms in enumerate(parts) for m in ms}
                reach = [0] * len(parts)
                for j in range(len(parts) - 1, -1, -1):
                    mask = 0
                    for m in parts[j]:
                        mask |= own(m)
                        for s in blocks[m].succ:
                            if s in at and at[s] != j:
                                mask |= reach[at[s]]
                    reach[j] = mask
                edges = sorted((pre[u], reach[at[s]]) for u in order[i]
                               if pre[d] <= pre[u] < end[d]
                               for s in blocks[u].succ if s in at)
                keys = [k for k, _m in edges]
                rows = [[m for _k, m in edges]]
                w = 1
                while 2 * w <= len(edges):
                    last = rows[-1]
                    rows.append([last[j] | last[j + w] for j in range(len(last) - w)])
                    w *= 2
                got = exits[d] = (keys, rows)
            keys, rows = got

            def run(a, b):
                a, b = bisect.bisect_left(keys, a), bisect.bisect_left(keys, b)
                if a >= b:
                    return 0
                k = (b - a).bit_length() - 1
                return rows[k][a] | rows[k][b - (1 << k)]
            return run(pre[d], lo) | run(hi, end[d])

        self._kfold = (depth, kin, chain, span, outside, live, escape)
        return self._kfold

    def _kill_bits(self, b) -> int:
        """What block `b` writes as `_join_kill` counts it, as a mask: a bit per register
        `_written` gives it (_KILL_BIT), and _KILL_STACK and _KILL_HEAP where one of its
        stores is one `_writes_stack` or `_writes_heap` counts."""
        mask = 0
        for r in self._written((b,)):
            bit = _KILL_BIT.get(r)
            if bit is None:
                bit = _KILL_BIT[r] = 1 << (len(_KILL_REG) + 2)
                _KILL_REG.append(r)
            mask |= bit
        if self._stores_frame(b):
            mask |= _KILL_STACK
        if self._writes_heap((b,)):
            mask |= _KILL_HEAP
        return mask

    def _join_write(self, addr, st: State, pad: str, src=None) -> list:
        """Write each phi register of goto-join `addr` to its shared name, from `st`.

        The second walk calls this on every edge into the join, a goto's source (after
        its loop write-back) and the block that falls through to it, so the name holds the
        value that way in has. `_merge`/`_phi` do the same for the if/else join by writing
        each arm; a goto-reached join is the one the structurer could not nest, and
        `_join_kill` dropped its registers to bare (#123). The name is minted once, kept
        in `_join_name`, declared above the function body by `_lift_function`, and read at
        the join. `_join_wrote` records which predecessor set it, so the join binds the
        register to the name only where every way in did; anywhere else it stays a bare
        register, the honest spelling of a value this walk cannot name.

        `src` is the edge the walk arrives by, for callers where the state no longer says:
        the arrival guard replaces the state of a block a section nothing reaches falls
        into (#237), and the record is about the EDGE and not about the values, so losing
        it there left `_join_wrote` short of a predecessor, the join's name unbound on
        every path, and the register bare at the join: #123 again, by another road."""
        regs = self.join_phi.get(addr)
        if not regs:
            return []
        src = st.src if src is None else src
        pairs = []
        for r in sorted(regs):
            key = (addr, r)
            name = self._join_name.get(key)
            if name is None:
                name = self._join_name[key] = f"t{st.tmpc[0]}"
                st.tmpc[0] += 1
                # Declared above the body, so in scope wherever the join's own entry is:
                # the entry's, or a proven entry's for a join in its body (#278).
                if self._idom is None:
                    self._dom_tree()
                self._anchor[int(name[1:])] = self._root_of.get(addr, self.entry)
                self.phi_names.add(name)
            pairs.append((name, st.get(r)))
            w = self._join_wrote.setdefault(key, set())
            if isinstance(src, int):
                w.add(src)
            elif isinstance(src, frozenset):
                w.update(src)
        return self._parallel_copy(st, pairs, pad)

    def _lift_block(self, addr, st: State):
        """Return (lines, falls_through) for one basic block, mutating `st`."""
        blk = self.blocks[addr]
        self._flags = self._flags_in(addr, st)
        # Both of these are adjacency claims about consecutive instructions, and adjacency
        # does not survive a branch any more than flag provenance does.
        self._last_mem = None
        self._pend_pair = None
        lines, insns = [], blk.insns
        self._flag_reads = _flags_read(insns)
        self._last_block, first = addr, st.tmpc[0]
        # Which registers each instruction's result is still needed by. Walked backwards
        # from what is live on the way out of the block, so it covers a value read in a
        # later block as well as one read two instructions on.
        after = _NO_LIVE
        # Stores need it as much as calls do. `_pin_mem` writes a value out before the
        # memory it reads changes, and doing that for a register nothing reads again would
        # put a dead `var tN = this.field_0x8;` in front of every compound assignment,
        # benchWithdraw's `balance -= amount` grows two of them, one for each register that
        # mentions the field. And an instruction printed raw can be anywhere (_verbatim).
        # The rows that move a frame register, by a write of it or out of `_step`'s
        # sight: a value whose text names it is seen to before each (`_frame_shift`).
        shifts = self.shift_rows
        if self._fp_lost_set is None:
            self._fp_lost_set = _fp_lost_at(self.blocks, self.raw)
        fp_lost, raw = self._fp_lost_set, self.raw
        if insns:
            after, m = [0] * len(insns), self._liveout.get(addr, 0)
            more = self._printed_liveness()[0].get(addr, {})
            for k in range(len(insns) - 1, -1, -1):
                after[k] = m
                de, us = _def_use_masks(insns[k][1], insns[k][2])
                if insns[k][1] == "ret":
                    us = self._ret_use(insns[k][0], us)
                m = us | more.get(k, 0) | (m & ~de)
        self._insns = insns
        # Registers live into a JOIN this block feeds (a successor more than one block
        # reaches). A move or a computed result that reassigns one of these is the phi
        # machinery's to name, not #187's (see the hook below).
        join_live = _or_all(self._livein.get(s, 0) for s in blk.succ
                            if len(self._preds.get(s, ())) > 1)
        if addr in self.frame_joins:
            _forget_frame(st)       # paths meet here from frames apart (_frame_plan)
            self._role_stale(st, "FP", None)
        for k, (a, mn, op, note) in enumerate(insns):
            self._at = k
            self._live_after = after[k] if after is not _NO_LIVE else 0
            last = (k == len(insns) - 1)
            if last and (mn == "b" or cond_of(mn) or mn in _CONDB):
                if mn == "b" and a in self.raw:
                    self._box_cut(st, a, insns)
                break                                          # branch is structural
            shift = a in shifts
            if shift:
                lines.extend(self._frame_shift(st, a, mn, op))
            # Name-first (#187): a reassignment of a register (a load's unrelated value, a
            # move, or a computed result) leaves a computed expression that still names it
            # stale. Write such a value out first, so a later read gets what it held, not
            # the reassigned register: `add x3,x2,#173; <x2 reassigned>; stur x3,[..]`
            # printed `= x2 + 173`, reading the reassigned x2. Only an expression (a
            # bare-register copy stays bare for arg/phi/afresh rules), only st.reg (a slot
            # is #173's, via stale_on_write below). The pin goes before the write.
            if mn not in _CALLS and mn not in _CSEL:
                # Not a conditional select either (`csel`, `cset`, ..): it reads the flags
                # to render, and pinning before it would clear a comparison that names the
                # register it sets, leaving the select itself with no flags and raw.
                defs, uses = _def_use(mn, op)
                wq = set(defs) - (_SPECIAL - {_lr()})
                plive = self._live_after & ~_reg_mask(wq)
                # A load reassigns to an unrelated value, pinned wherever the stale
                # expression is still live. A move or a computed result is pinned too, but
                # not where it would disturb a self-referential store, which is right on
                # main only by a stale read it keeps (the still-open #187 case). Two such
                # cases are caught here, a third in `_name_stale_reg` via `guard_feed`.
                # One: a register live into a join is the phi's to name (it renames the
                # arm write, so the register keeps its pre-branch meaning), and a pin only
                # forces a redundant phi temp. Two: a write whose own result already names
                # the register it sets, because a source holds a value that does (`sub x4,
                # x7, x4`, or `eor x2, x6, x1` with x6 as `x2 << 4`); it names the
                # register and is right only by that stale read cancelling the one in the
                # expressions naming it (`x4 + 214 - x4`), which a pin breaks. A load's
                # result is a fresh value, not a text of its operands, so none applies.
                carried = 0 if mn in _LOADS else join_live
                for q in sorted(wq):
                    if _reg_mask((q,)) & carried:
                        continue
                    if mn not in _LOADS and any(_use_re(q).search(st.get(s).text)
                                                for s in uses):
                        continue
                    lines.extend(self._name_stale_reg(st, q, plive, mn not in _LOADS))
            if (a not in raw) if mn == "nop" else (
                    a not in fp_lost or "29" not in op and "30" not in op):
                # No row that gives a role back (`_chain_gives`): not one that was
                # blanked, and FP not lost before it or neither frame chain register
                # in it. Stepped as it is, without two more calls on every row (#346).
                self._here = a
                lines.extend(self._step_row(st, a, mn, op, note))
            else:
                lines.extend(self._step(st, a, mn, op, note))
            if shift:
                if a in self.frame_moves:
                    self._moved_unseen(st, *self.frame_moves[a])
                self._frame_reads(st, a, mn)
            if st.slot_by_reg and mn not in _CALLS:
                # A slot whose text names a register this instruction reassigns now reads
                # the new register, not the value stored: `stur x6; mov x6, x1; ldur x3`
                # read the new x6 (#173). A goto join and a loop drop such a slot already;
                # here it is dropped on the straight-line write too, in program order. Not
                # at a call: its clobbers are named across it (#64) and dropping the
                # outgoing area would lose a call's arguments. A frame reload drops the
                # other slots its register names but keeps the one it reads, whose drop
                # would collide two reloads onto one name; a reload keying to no slot is
                # skipped (#173 review).
                written = _def_use(mn, op)[0]
                if mn in _LOADS and _off_frame(_split_ops(op)):
                    got = _frame_access(mn, op)
                    if got is not None:
                        st.stale_on_write(written, got[0])
                else:
                    st.stale_on_write(written)
            if st.spill:
                # After the instruction's own statement, not before: the declaration belongs
                # at the point the value was produced, and only later instructions read it.
                lines.extend(st.spill)
                st.spill.clear()
        if insns and insns[-1][1] in _CONDB:
            self._flags = None              # cbz and tbz test a register, not the flags
        self._anchor.update(dict.fromkeys(range(first, st.tmpc[0]), addr))
        # A block nothing runs past hands nothing to what the tree put after it, trap or
        # throw (`Block.ends_path`). Saying it falls through made an `if` arm that throws
        # contribute to the join: 212 arms on the clean fixture printed the join's
        # write-back under their own `throw`, a line no path reaches, and the join met a
        # value from a path that never arrives (#234).
        falls = not blk.ends_path and blk.term not in ("ret", "br", "bx")
        # Kept for `_reenter`: a block emitted after something that did not fall through
        # needs the state of its own predecessor, not of whatever the tree put above it.
        self._exit[addr] = st.copy()
        # The comparison the block leaves live, for the one successor that can justify
        # taking it (`_flags_in`).
        self._flags_out[addr] = self._flags
        st.src = addr
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

        Where the block has exactly one predecessor its exit state IS the edge and is
        used, or, where a goto takes that edge, the state the goto left, since the printed
        program can write names back on the way (`_arrive`). Anything else drops to
        symbolic, which is what "no path led here" honestly reads as.
        """
        preds = self._preds.get(addr, ())
        carry = None
        if len(preds) == 1 and addr not in self.roots:
            carry = self._came.get(addr) or self._exit.get(preds[0])
        st.elem.clear()
        st.poolbase.clear()
        st.pair.clear()
        if carry is not None:
            st.reg = dict(carry.reg)
            st.slot = dict(carry.slot)
            st.dropped = dict(carry.dropped)     # with the slot map, from its source
            st.slot_by_reg = {r: set(ks) for r, ks in carry.slot_by_reg.items()}
            st.elem.update(carry.elem)
            st.poolbase.update(carry.poolbase)
            st.pair.update(carry.pair)
            st.result = carry.result
        else:
            # Dropping to symbolic has to be RECORDED for a register with an entry name,
            # the rule `_merge` states for a join: one left out of the map falls back to
            # that name in `_leaf`, and no path here says it still holds the value the
            # function came in with. A catch block is entered with the exception in x0
            # and the stack trace in x1 (constants_arm64.h, kStackTraceObjectReg), and
            # `_run`'s on the clean fixture printed `_list2(x0, this)` for the two of
            # them. So is the Mint slow path the box-or-tag strip cuts off, where the
            # register being boxed is one the body has long since rewritten (#255).
            st.reg = {r: V(r, P_ATOM) for r in sorted(self.alias)}
            st.slot = {}
            st.dropped = {}
            st.slot_by_reg = {}
            st.result = _T.ret_int
        # Where the state came from NOW, which is the predecessor it was taken from, or
        # nowhere when no single way in justified one. `_lift_block` sets this at its end,
        # which was enough while this only ran where nothing fell through and the block
        # was lifted straight after it; `_unjustified` reads it on a live arrival, and the
        # disowned block left in it fired the guard a second time inside `_render_loop`,
        # resetting the registers the loop had just bound its carried names to (#237).
        #
        # Not `addr`: the state did not come out of the block it is being handed to, and
        # the one caller that needs the ARRIVING edge is handed it directly, because that
        # edge is what a goto-join's phi record is about (`_join_write`).
        st.src = preds[0] if carry is not None else None

    def _flags_in(self, addr, st: State):
        """The comparison `addr` may read on arrival, or None.

        Flags do not survive into a block from an unknown one, and that is what this used
        to say for EVERY block: the thunk was dropped at each entry. `_flag_cond` then
        declined for want of a live comparison, which is what 101 of its 106 declines on
        the clean fixture were, and 78 `csel` lines printed as arm64 while the same select
        in the same block as its `cmp` rendered exactly (#239).

        The other tools keep this fact in state rather than per block. VEX holds a thunk
        of the last flag-setting op and its operands in GUEST STATE (`CC_OP`, `CC_DEP1`,
        `CC_DEP2`) and computes the condition where it is READ, so it crosses an edge like
        any value; Hex-Rays makes the condition its own microinstruction over the two
        comparands, so it is an operand; Binary Ninja resolves a flag use when the flags
        were set by one instruction that reaches it, which is a unique reaching
        definition and not same-block adjacency. `self._flags` already IS such a thunk,
        mnemonic and operands and their rendered values, so what was missing is the edge.

        Taken only where the block has ONE predecessor in the graph: then the comparison
        it reads is the one that edge left and there is nothing to meet. A branch does not
        write the flags, so a thunk still live at the predecessor's exit is live on the
        edge out of it. Of the 99 that still decline on the clean fixture, 48 are joins,
        whose two ways in would have to AGREE before anything could be spelled, 13 had
        their comparison dropped before the edge and 4 are blocks nothing reaches.

        The VALUES are re-read from the arriving state rather than taken from the text the
        predecessor captured, which is what VEX does with `CC_DEP1`/`CC_DEP2`: keep the
        operands and compute the condition where it is READ. The captured text would be
        the wrong thing to carry twice over. It can name a temp the predecessor declared,
        and `structure` prints blocks in an order that is not a path (#237), so that name
        need not be in scope here. And the state this block is entered with IS the
        predecessor's exit state, since one way in is all it has, so re-reading spells the
        same values in names that are in scope.

        That holds because of what the thunk's own invalidation guarantees: no instruction
        after the comparison wrote an operand of it, or the predecessor would have dropped
        the thunk (`_note_flags`). The one case it does not cover is a comparison that
        overwrote an operand it compared, `subs x1, x1, #8`, where the arriving state has
        the NEW x1 and only the predecessor's captured text has the old one (#116). That
        one is declined rather than re-read.

        Nor into a proven entry (`roots`): the callers enter the normal entry too, with
        flags no edge brings, so the monomorphic check's comparison is not its (#278).
        """
        preds = self._preds.get(addr, ())
        if len(preds) != 1 or addr in self.roots:
            return None
        got = self._flags_out.get(preds[0])
        if got is None:
            return None
        mn, op, vals, regs = got
        ops = _split_ops(op)
        if mn not in _CMP and ops and canon(ops[0]) in vals:
            return None                 # it overwrote an operand it compared (#116)
        return (mn, op, {r: self._leaf(r, st) for r in vals}, regs)

    def _unjustified(self, addr, st: State) -> bool:
        """Whether `addr` is being handed a state out of a section the entry cannot reach
        while it also has a way in that the entry does reach.

        `structure` places a block no edge leads into, and the code after a trap or a call
        that cannot return, as its own labelled section (#57, #234), because an exception
        edge the CFG does not model may reach it. The section FALLS THROUGH into whatever
        the tree put below it, and that is a way in no path from the entry takes, so what
        it carries justifies nothing about the OTHER ways in: on a generated graph
        (`tools/irfuzz.py --cfg --nested`) the join below one read `x9 + 27` from an `add
        x2, x9, #0x1b` the CPU never executes (#237).

        Both halves of the question are needed. A block whose only predecessor is the
        section takes its state from that edge, which is the one it has. And INSIDE such a
        section the same is true of every join it contains: a region nothing reaches is
        still a region, its own flow is the only flow there is, and wiping a value both of
        its paths agree on would put a bare register where the output had the value. So
        this asks for a predecessor the entry reaches, the one the arriving state cannot
        speak for; `_join_kill` is what meets the ways in that it can.

        `st.src` is the last block lifted into this state, which after an `if` is the
        block that decided it rather than the arm that ran. That is enough: a block the
        entry cannot reach has only predecessors it cannot reach either, so a state whose
        last block is unreachable came through unreachable blocks the whole way.

        The body a proven entry roots (`_dom_tree`) counts as reached here, as the
        entry's does: a section falling into it is a way in its walk did not take (#278).
        """
        preds = self._preds.get(addr, ())
        if len(preds) < 2 or not isinstance(st.src, int):
            return False
        if self._idom is None:
            self._dom_tree()
        return (st.src not in self._idom
                and any(p in self._idom for p in preds))

    def _cond(self, cond: str, st: State) -> str:
        """Render cfg's register-level condition with lifted expressions substituted.

        From the operands the live comparison captured where it has them: the flags
        were set from those values, and a register the flag-setting instruction
        overwrote no longer holds them: `subs x1, x1, #8; b.ne` printed `x1 == 8` after
        the `subs`, where it reads as the new x1 (#116). A `cbz` or `tbz` reads its
        register as it is, and _lift_block drops the comparison before one."""
        vals = self._flags[2] if self._flags is not None else {}

        def sub(m):
            r = canon(m.group(1))
            v = vals.get(r)
            return _in_cond(v if v is not None else self._leaf(r, st))
        return _REG_RE.sub(sub, cond)

    def _entered(self, lines) -> bool:
        """Whether `lines` define a label a goto the walk meets jumps to: one out of a
        section no edge leads into does not count (`joinable`)."""
        for ln in lines:
            m = _LABEL_LINE_RE.match(ln)
            if m and (self.joinable is None or int(m.group(1), 16) in self.joinable):
                return True
        return False

    def _entry_block(self, stmts, cont):
        """The block a statement list first transfers control to, or `cont` if it has none
        of its own. Which block a conditional REJOINS at is what says whether the registers
        its arms disagree about are still wanted."""
        for s in stmts:
            k = s[0]
            if k in ("note", "rest") or (k == "label" and s[1] in self.orphans):
                return None             # a section nothing before it runs on into
            if k in ("asm", "loop", "goto", "label", "again"):
                return s[1]
            if k in ("exit", "cut"):
                return None
            if k == "if":
                return self._entry_block(s[2], cont) if s[2] else cont
            if k in ("break", "continue"):
                return None
        return cont

    def _phi(self, st: State, a: State, b: State, tlines, elines, live, pad, indent,
             stmts):
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
        # An arm a `goto` jumps into is entered below the declaration, so it cannot leave
        # the name holding what the declaration gave it (#121); it assigns it itself.
        entered = {id(lines): self._entered(lines) for lines in (tlines, elines)}
        # ...and one that prints a write to a register has changed it, even where it
        # ends up spelled as the register again, which is also how the entry value reads.
        printed = {id(lines): _printed_writes(lines) for lines in (tlines, elines)}
        # ...and so has one whose own instructions write it and that leaves it spelled as
        # it was before the `if`: a value lost at a join inside the arm is spelled as the
        # register, as the entry value is, and `x1 + 1` recomputed after x1 was lost there
        # is spelled as the `x1 + 1` from before. `lerp` loads x1 in both arms of an inner
        # `if` whose join keeps neither, and the name took x1 from before the outer one
        # (#122). Such an arm assigns the register itself, which is the machine's value
        # at its end. A stub that gives every register back writes none, and a part of
        # the arm that leaves the function does not reach its end.
        wrote = {}

        def writes(k):
            if k not in wrote:
                w = wrote[k] = set()
                for blk in sorted(_stmt_blocks(stmts[k], self.blocks)):
                    for (_a, mn, o, note) in self.blocks[blk].insns:
                        if _rv_call(mn, note) is None:
                            w.add(_T.ret_int)       # as `_step` takes any `bl`
                        else:
                            w |= _def_use(mn, o)[0]
            return wrote[k]

        def lost(k, v, r, pre):
            if v.text != pre.text or r not in writes(k):
                return False
            return v.text == r or any(canon(m) in writes(k)
                                      for m in _REG_RE.findall(v.text))
        for r in sorted(a.reg.keys() | b.reg.keys()):
            # A register only one arm tracks holds, on the other path, whatever it came in
            # with, which is the register itself, since anything the map knew before the
            # `if` is in both copies of it.
            va, vb = a.reg.get(r) or bare.setdefault(r, V(r, P_ATOM)), b.reg.get(r) or bare.setdefault(r, V(r, P_ATOM))
            if _joined(va, vb) is not None or not (live & _reg_mask((r,))):
                continue
            # Only where an arm COMPUTED something: a name or a field read reaching the
            # join is still visible to the reader, an expression is not. Writing out every
            # disagreement costs more lines than the arithmetic is worth.
            #
            # The exception is a name this lifter MINTED. A `t3` exists only in the printed
            # body, so declining the phi drops it to a bare `x3` and the binding that said
            # what x3 holds becomes the one thing the reader cannot see.
            #
            # So is a double literal against something other than the register's bare
            # name. An arm that overwrote it and then lost the value at a join inside
            # leaves that same bare name, which is also how the value on entry reads, and
            # the phi would carry the entry value down an arm that never kept it (#114).
            lit = ((_FLIT_RE.fullmatch(va.text) and vb.text != r)
                   or (_FLIT_RE.fullmatch(vb.text) and va.text != r))
            if (va.prec >= P_POST and vb.prec >= P_POST
                    and not _MINTED_RE.fullmatch(va.text)
                    and not _MINTED_RE.fullmatch(vb.text)
                    and not lit):
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
                return _joined(v, pre) is None or bool(self._reads_mem(v.text))
            # The initialiser exists only for an arm that leaves the value alone. Where
            # both arms assign it, giving one anyway would DUPLICATE the entry expression
            # 506 extra byte-offset field lines on the corpus, paid for a value no path
            # reads. The declaration still dominates every use, so the name is bound.
            gone = [lost(k, v, r, pre) for k, (_lines, v) in enumerate(arms)]
            sets = [changed(v) or entered[id(lines)] or r in printed[id(lines)] or gone[k]
                    for k, (lines, v) in enumerate(arms)]
            if name in self.hoist:
                # Declared at the top instead, because a reader outside this `if`'s scope
                # needs it. The INITIALISER stays here: it is the value from before this
                # `if`, and evaluating it at the top of the body would read a different
                # state. So the declaration splits into a bare one up there and an
                # assignment down here (#198).
                self.hoisted.add(name)
                if not all(sets):
                    decls.append(f"{pad}{name} = {pre.text};")
            else:
                decls.append(f"{pad}var {name};" if all(sets)
                             else f"{pad}var {name} = {pre.text};")
            for (lines, v), assign, g in zip(arms, sets, gone):
                if assign:
                    lines.append(pad2 + self._assign(V(name, P_ATOM),
                                                     V(r, P_ATOM) if g else v))
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
                tmp, decl = self._mint(st, v.text, pad)
                pre.append(decl)
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
        # The note over the section being walked: where it is in `out`, and whether the
        # section's own label has been passed. A section that printed nothing but labels,
        # a trap tier 3 does not print, loses its note at the next one: a note over
        # nothing says nothing, and it read as being about the section after it (#266).
        note = None
        for i, s in enumerate(stmts):
            kind = s[0]
            if note is not None and (kind in ("note", "rest")
                                     or (kind == "label" and note[1])):
                _drop_empty_note(out, note[0])
                note = None
            if kind == "asm":
                joins_at = self.labels if self.joinable is None else self.joinable
                join = (s[1] in joins_at and len(self._preds.get(s[1], ())) > 1
                        and s[1] not in self.carried)
                # Before the phi write below, which spells the arriving value: a section
                # the entry cannot reach falling into a block with other ways in hands it
                # a state none of them justifies (`_unjustified`, #237). A loop header is
                # excluded for the reason the meet below excludes it: `_render_loop` has
                # already bound its carried registers in this state.
                came = st.src
                # A proven entry the walk falls into starts from bare registers all the
                # same: the normal entry is where the callers come in too (#278).
                if (alive and s[1] not in self.carried
                        and (s[1] in self.roots or self._unjustified(s[1], st))):
                    self._reenter(s[1], st)
                # The fall-through edge into a goto-join writes its phi names BEFORE the
                # label, so a goto that jumps to the label does not re-run them (#123).
                if join and alive and s[1] in self.join_phi:
                    out.extend(pad + ln
                               for ln in self._join_write(s[1], st, "", src=came))
                label(s[1])
                if not alive:
                    self._reenter(s[1], st)
                    # A block with no successor (a trap, a return, or an indirect jump
                    # out of the function), reached out of normal flow (a goto, not a
                    # fall-through), hands its state to no later line. That state can
                    # spell a value with a temp no `var` on the way here declared (the
                    # live path's declaration dropped or never printed), so the block
                    # reads a name nothing binds: nextInt's throw read t0 and t1, and a
                    # loop that collapsed the receiver's name left toUpperCase reading an
                    # undeclared t1 at `return t1`. A register's temp name holds only
                    # until it is reassigned, so the bare register is the same value;
                    # drop the undeclared temps, keep the declared (#179, #129). Only
                    # where the state spells a temp at all: scanning `out` at every
                    # section a range places past its body made 4,000 `ret` take 6.8 s
                    # (#266), and right after a bare `_reenter` there is none to drop.
                    if not self.blocks[s[1]].succ and _spells_a_temp(st):
                        bound = _declared_temps(out)
                        bound |= {int(n[1:]) for n in self.pins}
                        bound |= {int(n[1:]) for n in self.phi_names}
                        _forget_temps(st, lambda n: n not in bound)
                # The meet a goto join never got. A loop header is excluded because
                # `_render_loop` has already given its carried registers names and bound
                # them in this state; killing them here would put the machine register back
                # into every line of the body.
                if join:
                    kill, mem, heap = self._join_kill(s[1])
                    # A frame register a way in moved: no text naming it is right on
                    # every one of them (#340).
                    for role in self._killroles[(s[1], False)]:
                        self._role_stale(st, role, None)
                    # Each register the join disagrees about and the code after it
                    # reads is one the first walk recorded for a phi; the second walk
                    # wrote a name on every edge in (above and at each goto), so the join
                    # reads the name, not the bare register a printed line would misname.
                    live = _mask_regs(self._livein.get(s[1], 0))
                    self._join_phi_set.setdefault(s[1], set()).update(
                        r for r in kill if r in live)
                    phis = self.join_phi.get(s[1], frozenset())
                    preds = set(self._preds.get(s[1], ()))
                    for r in sorted(kill):
                        key = (s[1], r)
                        if (r in phis and key in self._join_name
                                and self._join_wrote.get(key, set()) >= preds):
                            st.reg[r] = V(self._join_name[key], P_ATOM)
                            st.elem.pop(r, None)
                            st.poolbase.pop(r, None)
                            st._unpair(r)
                            st.lost.discard(r)
                            continue
                        st.forget(r)
                    # A name is declared on the paths through the block its declaration
                    # stands in, and only those. Naming a value writes no register, so the
                    # rule above kept a register a pin in a block between had renamed, and
                    # it read a name the other paths never declared (#121). What a block
                    # that dominates the join declares is on every path into it.
                    _forget_temps(st, lambda k: not self._dominates(
                        self._anchor.get(k), s[1]))
                    if mem:
                        st.slot.clear()
                        st.dropped.clear()
                    else:
                        self._stale_slots(st, kill)
                    if heap:
                        # The same meet, for the heap. A register the paths agree on can
                        # still be spelled as a field read, and a store one path made says
                        # that text names a different value coming that way. Dropping the
                        # REGISTER is not enough and dropping every register is far too
                        # much, so what goes is exactly the values that read memory.
                        for r, v in sorted(st.reg.items()):
                            if v.text != r and self._reads_mem(v.text):
                                st.forget(r)
                        st.elem.clear()
                blines, bfalls = self._lift_block(s[1], st)
                out.extend(pad + ln for ln in blines)
                alive = bfalls
                if not bfalls:
                    falls = False
            elif kind == "label":
                label(s[1])
                # A section, after the body or past a trap, or the body going on after
                # one past a trap: a block a goto of the body left to be placed (#283).
                self._in_tail = s[1] in self.orphans
                if self._in_tail:
                    alive = False       # a section; nothing runs on into it
                    self._in_second = s[1] in self.second
                    self._in_trap = s[1] in self.placed
                if note is not None:
                    note = (note[0], True)
            elif kind == "note":
                # Over a section no edge leads into, which says what it can be. Nothing
                # above it runs on into it, so its first block starts from what `_reenter`
                # justifies and not from the state the walk was carrying (#266).
                note = (len(out), False)
                out.append(pad + "// " + s[1])
                alive = False
            elif kind == "if":
                _, cond, then, els = s
                cond_txt = self._cond(cond, st)
                a, b = st.copy(), st.copy()
                head = self._last_block if self._last_block is not None else self.entry
                tlines, tfalls = self.walk(then, a, indent, depth + 1, joins[i])
                elines, efalls = self.walk(els, b, indent, depth + 1, joins[i])
                named = {}
                if tfalls and efalls:
                    first = st.tmpc[0]
                    named, decls = self._phi(st, a, b, tlines, elines,
                                             self._livein.get(joins[i], 0), pad, indent,
                                             (then, els))
                    self.phi_names.update(named.values())
                    self.phi_minted.update(named.values())
                    out.extend(decls)
                    # Declared above the `if`, at the end of the block that decides it,
                    # and set on every path through it. Where a goto enters an arm, that
                    # arm sets it too, and it is set on every path into the join instead.
                    entered = self._entered(tlines + elines)
                    at = joins[i] if entered and joins[i] is not None else head
                    self._anchor.update(dict.fromkeys(range(first, st.tmpc[0]), at))
                out.extend(self._render_if(cond_txt, tlines, elines, pad, indent))
                if tfalls and efalls:
                    _merge(st, a, b)
                    # ...and the join value of a named phi is that name, not the register
                    # `_merge` dropped to. Same second half as `_render_loop`: naming the
                    # value and then forgetting it puts the machine register back into
                    # every line that reads the result.
                    for r, name in sorted(named.items()):
                        st._stale_lost(r)       # the register's old lost value is gone
                        st.reg[r] = V(name, P_ATOM)
                        st.elem.pop(r, None)
                        st.poolbase.pop(r, None)
                        st.lost.discard(r)      # a named phi is a stable name, not lost
                elif tfalls:
                    st.reg, st.slot, st.elem, st.result = a.reg, a.slot, a.elem, a.result
                    st.lost, st.lost_slot = a.lost, a.lost_slot
                    st.slot_by_reg = a.slot_by_reg
                elif efalls:
                    st.reg, st.slot, st.elem, st.result = b.reg, b.slot, b.elem, b.result
                    st.lost, st.lost_slot = b.lost, b.lost_slot
                    st.slot_by_reg = b.slot_by_reg
                else:
                    falls = False
                alive = tfalls or efalls
            elif kind == "loop":
                # Its names are declared right after the statement before it, and only a
                # block falls straight into them; anything else anchors them nowhere.
                prev = stmts[i - 1] if i and alive else None
                self._loop_before = prev[1] if prev and prev[0] == "asm" else None
                if alive and (s[1] in self.roots or self._unjustified(s[1], st)):
                    self._reenter(s[1], st)      # the same way in, into a loop head
                label(s[1])
                if s[1] in (self.labels if self.joinable is None else self.joinable):
                    # A goto into the loop's head brings a state the walk never saw: the
                    # goto join's meet, over the ways in and not the latches, before the
                    # loop binds its names from it (#125).
                    kill, mem, heap = self._join_kill(s[1], entry=True)
                    for role in self._killroles[(s[1], True)]:
                        self._role_stale(st, role, None)
                    for r in sorted(kill):
                        st.forget(r)
                    if mem:
                        st.slot.clear()
                        st.dropped.clear()
                    else:
                        self._stale_slots(st, kill)
                    if heap:
                        for r, v in sorted(st.reg.items()):
                            if v.text != r and self._reads_mem(v.text):
                                st.forget(r)
                        st.elem.clear()
                    _forget_temps(st, lambda k: not self._dominates(
                        self._anchor.get(k), s[1]))
                out.extend(self._render_loop(s[1], s[2], st, indent, depth))
                st.src = frozenset(self._breakers.get(s[1], ()))
                alive = True
            elif kind in ("break", "continue"):
                if kind == "break" and self._carrying:
                    self._note_break(st)
                out.extend(self._carry_out(st, pad, kind == "break"))
                out.append(pad + kind + ";")
                falls = alive = False
            elif kind == "rest":
                # The sections `structure` could not nest, from the first one nested too
                # deeply for it on (_rest_sections): each under its note, the first also
                # under the one `flat` prints over a whole function, and every row as it
                # is, with a label where a goto names one. They were a count in a note
                # this loop took for a section's over nothing and dropped, so the body
                # behind a monomorphic entry 1,000 ifs deep printed `br x16` (#284).
                for k, (text, rows_of) in enumerate(s[1]):
                    if text:
                        out.append(pad + "// " + text)
                    if not k:
                        out.append(pad + "// " + TOO_DEEP)
                    for b, rows, past in rows_of:
                        label(b)
                        out.extend(flat_rows(rows, pad, self.show))
                        if past >= 0:
                            out.append(pad + cut_goto(past, self.show))
                falls = alive = False
            elif kind == "again":
                # A block of the body that leads nowhere, printed again under a section
                # no edge leads into and lifted from its state (`_ends_again`). No label:
                # nothing jumps to this copy, and the body's own is where its gotos go.
                blines, _bfalls = self._lift_block(s[1], st)
                out.extend(pad + ln for ln in blines)
                falls = alive = False
            elif kind == "goto":
                if self._carrying:
                    self._note_goto(s[1])
                if self._leaves_loop(s[1]):
                    out.extend(self._carry_out(st, pad, True, s[1]))
                # This edge into the join writes its phi names, after the loop write-back
                # so they hold the carried value, not the register the loop forgot (#123).
                if s[1] in self.join_phi:
                    out.extend(self._join_write(s[1], st, pad))
                rejoins = (self.rejoined_second if self._in_second
                           else self.rejoined_trap if self._in_trap else self.rejoined)
                out.append(pad + f"goto L_0x{s[1]:x};"
                           + (f"   // {REJOIN}" if self._in_tail and s[1] in rejoins
                              else ""))
                falls = alive = False
            elif kind in ("exit", "cut"):
                # Out of the loop as surely as a break, so its names are written back
                # first, as a break's are, or they say nothing of what the registers
                # hold where control leaves (#86). The innermost loop's only, as for a
                # goto: writing back the loops around it too reads names the inner one
                # has just reassigned.
                out.extend(self._carry_out(st, pad, True))
                if kind == "exit":
                    # A branch out of this function. It is not a local label, and it does
                    # not fall through: leaving it unsaid ended the body with no
                    # explanation, or let the carried state run on into a block control
                    # never reaches from here. 997 sites on the clean fixture did exactly
                    # that.
                    out.append(pad + (f"goto {self._sub(s[1])};" if s[1] >= 0
                                      else "goto <unresolved>;"))
                else:
                    out.append(pad + cut_goto(s[1], self.show))  # inside this function
                falls = alive = False
        if note is not None:
            _drop_empty_note(out, note[0])
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

    def _pin_loop(self, st: State, header, carried) -> list:
        """Write out, above the loop at `header`, every live value a trip can make stale.

        Two arguments, both of them ones already made at a single instruction:

        `_pin`'s, that the register map holds EXPRESSIONS, and `x9 - 34` stops describing
        anything the moment x9 is reassigned. A loop reassigns every register it writes,
        so a value live across it whose text names one has to be named above it.

        `_pin_mem`'s, that a value which READS MEMORY means what it meant while that
        memory held what it did. A trip storing through an object pointer is the write,
        and so is a call. The load already happened, so naming the value only says so.

        Main needed neither here, by accident. `_loop_nodes` counted the blocks before
        the loop as the loop's own, so a register assigned there came out loop-carried and
        the carried name materialised its value above the loop, which is this. Asking the
        body instead (#228) stops that, and without these `tools/irfuzz.py --cfgmem`
        disagrees at seed 9, where a value loaded before the loop is printed after a trip
        has stored to the field it reads.

        This is the one place SSA hands a decompiler for nothing: a store makes a new
        memory version rather than changing what an earlier load meant, and a register
        write makes a new value rather than reaching into an expression that read the old
        one. This map holds text, so where SSA would have a second version, this writes
        the first one out.

        The REGISTER map alone, at both. A slot whose text names a register the region
        wrote is dropped by `_stale_slots`, and one that reads memory a trip may store to
        by `_exit_slots`, both of which still ask `_loop_nodes`: this changes what the
        loop's writes are read off, not what the slot map is kept across.

        A carried register is left out of both, as the holder: the value it has before the
        loop is what `init` binds to its name, above the loop, which is this same
        materialisation. A carried register NAMED in another value's text is not left out,
        because that text reads the machine register and the carried name does not change
        what the machine does to it.

        What a TRIP runs decides, `_trip_body`, and not the whole body: a stack check's
        slow path that strip_boilerplate cut off still jumps back into the loop, and its
        call would count as writing every register the stub gives back (#157), which put a
        declaration above every loop that has one. The loop-exit `forget` keeps asking the
        whole body, where over-approximating only forgets more.
        """
        trip = self._trip_body(header)
        live = self._livein.get(header, 0) & ~_reg_mask(tuple(carried))
        out = []
        for r in sorted(self._written(trip) - (_SPECIAL - {_lr()})):
            out += self._pin(st, r, live, regs=True)
        # A frame register the loop moves: a value naming it is right before the loop
        # and on no trip after the first, so it is named here as well (#340). Over the
        # whole body, where a slow path may move one too.
        moved = _frame_roles(self._written(trip) | self._written(self._back_loop(header)))
        for role in moved:
            out += self._role_stale(st, role, live, keep=carried)
        # A call stores wherever its callee does, which is `_writes_heap`'s own
        # over-approximation reached by the other door.
        if self._writes_heap(trip) or self._any_block(
                self._call_blocks, self._calls_in, trip):
            for key in sorted(st.reg):
                v = st.reg[key]
                if v.text == key or not live & _reg_mask((key,)):
                    continue                  # its own name, or nothing reads it again
                if not self._reads_mem(v.text):
                    continue
                tmp, decl = self._mint(st, v.text)
                out.append(decl)
                st.reg[key] = V(tmp, P_ATOM, smi=v.smi, calc=v.calc)
                st.elem.pop(key, None)
                st.poolbase.pop(key, None)
        # Anchored above the loop, as a carried name is. A goto out of the loop hands its
        # target a state holding these names, and the declaration has to be visible there
        # too (#204, #205).
        for m in map(_DECL_RE.match, out):
            if m:
                self._anchor[int(m.group(2)[1:])] = self._loop_before
        return out

    def _render_loop(self, header, body, st: State, indent, depth):
        pad = indent * depth
        # The loop's OWN blocks, the natural body read off the back edges, and not
        # `_loop_nodes`, which closes backward over the header's predecessors without
        # stopping at the header and so returns every ANCESTOR of it. On the clean
        # fixture that is 20,211 blocks across the 833 loops this is asked about where
        # the body is 8,975, and 9,781 of the extra ones run BEFORE the loop. The three
        # questions asked of this set are what the loop WRITES, what it carries, and
        # whether a break leaves it, and a block that ran before the loop answers none of
        # them (#228). It is also the body the field means: LLVM's loop is the maximal
        # strongly connected set whose every entering edge reaches the header, and
        # Ghidra's `LoopBody` marks the same one off the back edges.
        nodes = self._back_loop(header)
        carried = self.carried.get(header)
        if carried is None:
            carried = (self._loop_live_in(header, nodes)
                       & self._written(nodes)) - (_SPECIAL - {_lr()})
            carried |= self.carry_more.get(header, frozenset())     # see below
            self.carried[header] = carried
        written = self._written(nodes) - (_SPECIAL - {_lr()})
        pre = self._pin_loop(st, header, carried)
        # A loop-carried register is a phi, and a phi reaching exactly one join has a name
        # in the source: bind it before the loop with the entry value, read that name in
        # the body, assign back at the bottom. Nothing new is claimed; the tail update was
        # already emitted, it just assigned to `x5` instead of to something followable.
        # Left as a bare register this is 95.7% of every machine register in the output.
        #
        # sorted, not set order: insertion order decides how temporaries are numbered, and
        # iterating a set made that depend on the per-process hash seed.
        # Through `_leaf`, not `st.get`: a carried register the function was entered
        # with reads as its entry name here, `var t0 = a1;`, as it does at any other
        # use of it before the loop. The state is the one the loop is entered in, so the
        # rule is the one every use has: the name holds only where no path to here
        # recorded the register (#255).
        init = {r: self._leaf(r, st) for r in sorted(carried)}
        names = {}
        before = self._loop_before
        for r in sorted(carried):
            self._anchor[st.tmpc[0]] = before       # declared above the loop
            names[r] = f"t{st.tmpc[0]}"
            st.tmpc[0] += 1
        loop_st = st.copy()
        # A slot the body stores a new value to holds that value at the top of the next
        # trip, not the one it came in with (#109). `_loop_rewrites` reads `st`, as it
        # compares a slot's text with what a register held on the way in, so its keys are
        # `st`'s and are dropped here, while the copy still has every one. Below, a
        # register the loop carries or writes takes with it a slot that held its lost
        # value (#140), and a key both name was gone before a later `del`: a KeyError out
        # of the lifter on a crafted range (#287).
        for k in self._loop_rewrites(header, st):
            del loop_st.slot[k]
        # A record does not cross into the loop. The body's own fills happen in this copy
        # and are never reconciled back, so a record carried in would survive a store the
        # body makes on every trip (#199). What the loop itself drops is re-recorded on
        # the way out, by `_stale_slots` through `_exit_slots`.
        loop_st.dropped.clear()
        for r in sorted(carried):
            loop_st._stale_lost(r)      # its lost value is gone, carried as a name (#140)
            loop_st.reg[r] = V(names[r], P_ATOM)
            loop_st.elem.pop(r, None)
            loop_st.poolbase.pop(r, None)
            loop_st.lost.discard(r)
        # A register the loop writes and does not carry is one no trip reads before
        # writing it, and on every trip after the first it holds what the last trip left
        # there, not its value from before the loop. Kept, that value went to the target
        # of a goto out of the loop: `x2.field_0x60 = x5 + x1;` where the CPU leaves on
        # the second trip with x6 + x1 (#154). Forgotten, the target reads the register;
        # see _note_goto for where that is not enough, and _reloads for one every trip
        # puts its value from before the loop back into.
        trip = self._trip_body(header)
        writes = self._written(trip) - (_SPECIAL - {_lr()}) - carried
        marks = self._unset[header] = {}
        for r in sorted(writes - self._reloads(header, trip, st, writes)):
            loop_st.forget(r)
            marks[r] = loop_st.reg[r]
        # The outgoing area too, where a trip may write it or a call in it takes it: the
        # next trip starts with what the last one left there, which _loop_rewrites, over
        # FP's slots alone, did not see (#162).
        if self._writes_outgoing(trip):
            sp = next((r for r, v in _T.roles.items() if v == "SP"), None)
            gone = [k for k in loop_st.slot if sp and k.startswith(sp)]
            for k in gone:
                del loop_st.slot[k]
            if any(k != _LOST for k in gone):
                loop_st.slot[_LOST] = V("", P_ATOM)
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
            blines = [_no_self_holds(pat.sub(lambda m: sub[m.group(1)], ln))
                      for ln in blines]
            tail = [pat.sub(lambda m: sub[m.group(1)], ln) for ln in tail]
            for r in drop:
                names.pop(r)
                loop_st.reg[r] = init[r]
            # The numbering is NOT compacted afterwards. `State.copy` shares the counter box
            # with the body's walk, so the body has already minted temps above these;
            # rewinding to close a gap would hand out a name the body is using.

        # One carried past a printed write starts from its value before the loop as any
        # other does: a break the walk reaches before the body writes it reads that.
        fresh = self.carry_more.get(header, frozenset())
        self.carry_names[header] = {names[r]: r for r in fresh if r in names}
        self.phi_names.update(names.values())
        # Hoistable, like every other name a join binds. A loop-carried name is declared
        # at the loop, and a goto out of the loop can hand it to a target whose scope that
        # declaration has closed before: 164 reads of a name declared elsewhere were fixed
        # for `_mint` in #204 and this site was left out, so its reads were counted and
        # not fixed. `wants_hoist` asks `phi_minted` (#205).
        self.phi_minted.update(names.values())
        out = [pad + ln for ln in pre]
        for r in sorted(names):
            if names[r] in self.hoist:
                # Declared at the top; the INITIALISER stays here, because it is the value
                # from before the loop and reads a different state at the top (`_phi`).
                self.hoisted.add(names[r])
                out.append(f"{pad}{names[r]} = {init[r].text};")
            else:
                out.append(f"{pad}var {names[r]} = {init[r].text};")
        out.append(f"{pad}while (true) {{")
        out.extend(blines)
        out.extend(tail)
        out.append(f"{pad}}}")
        # Only what the loop never writes survives it. `carried` is the intersection of
        # written with live-on-entry, so restoring just those left every register the loop
        # assigns WITHOUT reading first holding its value from before the loop: set x9 to
        # 5, write 7 to it in the body, and the code after the loop printed 5. The loop
        # body is where the value now comes from, so the name is what the reader gets.
        # What the loop's OWN instructions write, a call's clobbers left out. After the
        # loop the machine holds what the last trip put in one of these, while the
        # register's own name says the value the function came in with, so a store
        # through one as its base writes a field of the wrong object (#208).
        #
        # Not the registers only a CALL inside the loop clobbered. Those are #216's
        # class, which names them where a straight-line read follows the call, and
        # treating them here as well renames the base of every store after a loop that
        # calls, which is most of them: the shapes in three loop tests are exactly that,
        # and those tests are about the value rather than the base. That half wants its
        # own measurement.
        own = self._region_written(header) - (_SPECIAL - {_lr()})
        for r in sorted(written | carried):
            st.forget(r)
            if r in own:
                st.opaque.add(r)
        # Forgotten, a register prints as itself, which reads as the last value a printed
        # line put in it. Where a break holds something else in it and the code after the
        # loop reads it, that is the wrong value: `umulh x7, ...` printed, `add x7, x5,
        # x1` not, and the store after the loop read the `umulh` (#123). The walk is run
        # again with such a register carried, so the breaks name what it holds; see
        # _lift_function. So too where a break leaves before the trip writes it: it holds
        # what the header forgot, and that was the last trip's (#154). A goto out of the
        # loop hands its target its own state (_arrive, _note_goto).
        for n in sorted(self._breakers.get(header, ())):
            left = self._exit.get(n)
            for s in self.blocks[n].succ:
                if s in nodes or left is None:
                    continue
                for r in (written - carried) & _mask_regs(self._livein.get(s, 0)):
                    v = left.get(r)
                    if v.text != r or (r in marks and v is marks[r]):
                        self.exit_hazards.setdefault(header, set()).add(r)
                        # A break that leaves MORE THAN ONE loop leaves this register in
                        # the same state at each of them, so each has to carry it. Named
                        # at the inner loop alone, the name was written back there and the
                        # outer loop had still forgotten the register, so the code after
                        # both read it bare; the name then had no reader and the walk gave
                        # it up, which is how the second walk's fix came undone. The
                        # enclosing loops are the frames still on `_carrying`: this runs
                        # after the body walk has popped this loop's own (#176).
                        for out_h, _names, _copied in self._carrying:
                            if s not in self._back_loop(out_h):
                                self.exit_hazards.setdefault(out_h, set()).add(r)
        # ...except the ones that got a name, whose value after the loop is that variable.
        # That is the second half of naming it: forgetting it here would put the machine
        # register back into every line that reads the result of the loop. A register whose
        # phi collapsed keeps its entry value, which the loop did not change.
        for r in sorted(names):
            st.reg[r] = V(names[r], P_ATOM)
            st.opaque.discard(r)      # it holds the carried name, not an unknown (#208)
        for r in sorted(carried - set(names)):
            st.reg[r] = init[r]
            st.opaque.discard(r)      # its phi collapsed: it holds its entry value
        # Which return register the function last wrote is a fact about the BODY, and the
        # body is what just ran.
        st.result = loop_st.result
        # ...and no record survives the loop either: `_exit_slots` subtracts statically
        # from the pre-loop state, so a key the loop FILLED is simply absent here and no
        # removal fires for it (#199).
        st.dropped.clear()
        self._exit_slots(st, header)
        return out

    def _back_loop(self, header) -> frozenset:
        """The natural loop at `header`: the predecessors it dominates are its latches,
        and the body is what reaches one without passing it. `_loop_nodes` takes the
        edge in from before the loop for a latch too, and with it every block before the
        loop (#129). A predecessor no path from the entry reaches counts as a latch, as
        it may be a handler the graph has no edge into, and so does one under another
        root of the forest (`_dom_tree`): that is the edge in from a second entry's body,
        which reaches no tree but its own (#278)."""
        if self._idom is None:
            self._dom_tree()
        got = self._backloops.get(header)
        if got is not None:
            return got
        tree = self._root_of.get(header)
        latches = [p for p in self._preds.get(header, ())
                   if p not in self._idom or self._root_of.get(p) != tree
                   or self._dominates(header, p)]
        if not self._nested:
            # Walked by itself, as every loop was, while the bodies walked come to no
            # more than _NEST_AFTER times the function: loops side by side or a few deep
            # cost a few walks of it, and a nest has more to keep than it saves there.
            # Past that the loops are nested deep, and the nest is turned on (#332).
            nodes, stack = {header}, latches[:]
            while stack:
                n = stack.pop()
                if n not in nodes and n in self.blocks:
                    nodes.add(n)
                    stack.extend(self._preds.get(n, ()))
            self._looped += len(nodes)
            if self._looped <= _NEST_AFTER * len(self.blocks):
                got = self._backloops[header] = frozenset(nodes)
                return got
            self._go_nested()
        nest = self._bnest
        if nest is None:
            # Inner loops first, each taken in whole by the loops around it (LoopNest):
            # walked one by one, N nested loops walked N * N / 2 blocks (#332).
            blocks = self.blocks
            nest = self._bnest = LoopNest(self._preds, lambda _h, n: n in blocks,
                                          self._dnum)
            nest.prepare([h for h, ps in self._preds.items()
                          if any(p != h and nest.above(h, p) for p in ps)],
                         self._back_loop)
            got = self._backloops.get(header)
            if got is not None:
                return got
        # Remembered, as `_loop_nodes` is: `_leaves_loop` asks this once per goto inside
        # a loop now, not once per loop (#129).
        got = self._backloops[header] = nest.closure(header, latches)
        return got

    def _go_nested(self) -> None:
        """Turn on the nest of loops for this function: from here `_back_loop` and
        `_trip_nodes` build bodies inner loops first, and what a body holds is folded
        from the bodies inside it. The bodies walked so far are asked again, to be part
        of it; they come out the same sets."""
        self._nested = True
        self._backloops.clear()
        self._trips.clear()
        self._bodies.clear()
        self._stack_blocks, self._heap_blocks, self._out_blocks = {}, {}, {}
        self._call_blocks, self._bl_blocks, self._thru_blocks = {}, {}, {}
        self._slot_stores, self._folds, self._livesum, self._usedef = {}, {}, {}, {}

    def _loop_live_in(self, header, nodes) -> frozenset:
        """`_live_in_header` of the loop at `header` over its body `nodes`, the registers
        a trip may read before it writes them, folded up the nest of loops (#332).

        Asked of each body, N nested loops ran the dataflow over N * N / 2 blocks between
        them. A rooted body (LoopNest) is entered at its header alone, so to the loop
        around it the body is one node: what it reads from its header on, `live`, and
        for each block outside it an edge leaves to, the registers some path from the
        header to that edge does not write, `through`. The loop around it reads through
        it what the block past the edge reads and the path leaves alone. Both are unions
        over paths of a write-kills-a-read transfer, so each is exact where the blocks
        are, and the dataflow of the outer loop over its own blocks and these nodes has
        the fixed point the one over every block had (Kildall; Tarjan's path expressions
        fold a reducible graph the same way). A body that is not rooted, or whose parts
        overlap, is asked as it was."""
        reads = self._printed_liveness()[0]
        nest = self._bnest
        if nest is None or header not in nest.clean or nest.body.get(header) is not nodes:
            return _live_in_header(self.blocks, nodes, header, self._preds, reads)
        memo, todo, stack = self._livesum, [], [header]
        while stack:                       # the nest below `header`, outer bodies first
            h = stack.pop()
            if h not in memo:
                todo.append(h)
                stack.extend(nest.kids[h])
        for h in reversed(todo):
            if h not in memo:
                memo[h] = self._live_fold(h, reads)
        got = memo[header]
        if got is None:
            return _live_in_header(self.blocks, nodes, header, self._preds, reads)
        return _mask_regs(got[0])

    def _live_fold(self, h, reads):
        """(live, through) of the rooted body at `h`, from its own blocks and the
        (live, through) of the bodies it took in whole; see _loop_live_in. None where
        a part is not one (#332)."""
        nest, memo, blocks, usedef = self._bnest, self._livesum, self.blocks, self._usedef
        if h not in nest.clean:
            return None
        body, kids = nest.body[h], nest.kids[h]
        parts = {}
        for k in kids:
            got = memo.get(k)
            if got is None:
                return None
            parts[k] = got
        own = nest.own[h]
        for b in own:
            if b not in usedef:
                u = d = 0
                more = reads.get(b, {}) if reads else {}
                for i, (_a, mn, o, _n) in enumerate(blocks[b].insns):
                    de, us = _def_use_masks(mn, o)
                    u |= (us | more.get(i, 0)) & ~d
                    d |= de
                usedef[b] = (u, d)
        # Each edge, from a block of this body or a body inside it, to a node of this
        # level, a block or the header of a body taken in, or out of the body.
        node = set(own) | set(kids)
        edges, out = {}, []
        for b in own:
            mine = edges[b] = []
            for s in blocks[b].succ:
                if s in node:
                    mine.append(s)
                elif s not in body:
                    out.append((b, s, -1))
                else:
                    return None            # into a body other than at its header
        for k in kids:
            mine = edges[k] = []
            for s, m in parts[k][1].items():
                if s in node:
                    mine.append((s, m))
                elif s not in body:
                    out.append((k, s, m))
                else:
                    return None
        order = sorted(node, reverse=True)
        live = dict.fromkeys(node, 0)
        changed = True
        while changed:
            changed = False
            for b in order:
                if b in parts:
                    v = parts[b][0]
                    for s, m in edges[b]:
                        v |= live[s] & m
                else:
                    lo = 0
                    for s in edges[b]:
                        lo |= live[s]
                    u, d = usedef[b]
                    v = u | (lo & ~d)
                if v != live[b]:
                    live[b] = v
                    changed = True
        # Forward: what some path from the header to the end of each node leaves alone.
        clear = dict.fromkeys(node, 0)
        clear[h] = -1
        order.reverse()
        changed = True
        while changed:
            changed = False
            for b in order:
                if b in parts:
                    for s, m in edges[b]:
                        v = clear[s] | (clear[b] & m)
                        if v != clear[s]:
                            clear[s] = v
                            changed = True
                else:
                    left = clear[b] & ~usedef[b][1]
                    for s in edges[b]:
                        v = clear[s] | left
                        if v != clear[s]:
                            clear[s] = v
                            changed = True
        # Only an edge to a block of a rooted body around this one is asked again.
        top = nest._find(h)
        around = nest.body[top] if top is not None and top != h else ()
        through: dict = {}
        for b, s, m in out:
            if s in around:
                left = clear[b] & m if b in parts else clear[b] & ~usedef[b][1]
                through[s] = through.get(s, 0) | left
        return live[h], through

    def _call_written(self, nodes) -> frozenset:
        """The registers a call inside `nodes` may leave holding something the reader
        cannot read off the entry state: what the calling blocks write, plus the call's
        own clobbers.

        A region-level drop is recordable for a key whose text names none of these. Asking
        instead whether the region calls AT ALL is too coarse, because the region reaches
        back past the loop header on purpose (`_exit_slots`: the pre-loop blocks stand for
        the ones between the store and the loop), so a call before the loop turned the
        record off for keys its clobbers never touch: 260 of 991 loop exits on the 3.12.2
        clean build, against 95 where the gate was on at all (#199 review).

        A tail call through `br` is not counted, the convention `_exit_slots` uses for
        its own memory question: a `br` block does not fall through, so it cannot reach
        the latch and the region's text cannot be read after it."""
        out: set = set()
        for b in nodes:
            if b not in self.blocks:
                continue
            if any(mn in _CALLS for (_a, mn, _o, _n) in self.blocks[b].insns):
                out |= self._written({b}) | _CALL_CLOBBERS
        return frozenset(out)

    def _quiet(self, b) -> bool:
        """True for a stack check's slow path, `bl` to the stub and `b` back: the stub
        gives back every register it is handed live and stores to no slot (#157)."""
        return (b in self.slow_paths
                and [t[1] for t in self.blocks[b].insns] == ["bl", "b"])

    def _exit_slots(self, st: State, header) -> None:
        """Drop from `st` the slots the loop at `header` may leave holding something else.

        The loop is its own blocks, `_back_loop`, less a stack check's slow path. Main
        dropped every slot where any block of `_loop_nodes` stored to the frame, and
        those take in the blocks before the loop, which store to it as a rule: a double
        `_contentWidthFor` saved at entry then read back after the loop as the register
        it was reloaded into, `d1`, which reads as its second argument (#157).

        A store drops the slots it overlaps, 16 bytes of one a q register filled
        (_wide_slots) and 8 of any other. The outgoing area goes whatever the loop does: a
        call in it takes what was pushed before it, and a call after it would print that
        for its arguments. A store whose place in the frame is not known, a frame that
        moves or whose address reaches a register, drops them all. A slot whose text
        reads memory goes where the loop stores to memory or makes a call. One whose text
        names a register goes where `_loop_nodes` writes it: the walk keeps a slot's text
        past a write to a register it names (#140), and the blocks before the loop stand
        for the ones between the store and the loop, where `_lShiftDigits` overwrites the
        x2 and x3 its slot was computed from. A block with a trap or a throw is left out
        there, as no path runs on from it, but its stores and calls count, for a handler
        the graph does not show may run after them."""
        fp = next((r for r, v in _T.roles.items() if v == "FP"), None)
        sp = next((r for r, v in _T.roles.items() if v == "SP"), None)
        body = self._back_loop(header)
        if not self._nested:
            if not self._exit_walk(st, body, fp, sp):
                written, unsafe = self._near_written(header)
                self._stale_slots(st, written, unsafe=unsafe)
            return
        # In a nest of loops, what each block writes and what its stores do are the same
        # for every loop holding it, and a drop is a drop in any order, so each block is
        # read once and the loop's answer folded up the nest (#332). A block that clears
        # the map clears it whatever the others drop.
        quiet, stores = self._quiet_blocks(), self._slot_stores

        def one(b):
            if b in quiet:
                return _NO_EXIT
            got = stores.get(b, False)
            if got is False:
                got = stores[b] = self._slot_store(b, fp) if fp is not None else None
            return (self._block_defs(b), got,
                    self._flag(self._heap_blocks, self._heap_block, b),
                    self._flag(self._bl_blocks, self._bl_in, b))
        got = self._fold(body, "exit", one, _exit_join)
        if got is None:
            got = _exit_join([one(b) for b in sorted(body)])
        if fp is None or self._frame_escaped() or fp in got[0]:
            st.slot.clear()
            return
        if sp is not None:
            for k in [k for k in st.slot if k.startswith(sp)]:
                del st.slot[k]
        if got[1] is None:
            st.slot.clear()
            return
        for k in [k for k in st.slot if k in got[1]]:
            del st.slot[k]
        if got[2] or got[3]:
            for k in [k for k, v in st.slot.items() if self._reads_mem(v.text)]:
                del st.slot[k]
        written, unsafe = self._near_written(header)
        self._stale_slots(st, written, unsafe=unsafe)

    def _exit_walk(self, st: State, body, fp, sp) -> bool:
        """`_exit_slots` up to `_near_written` for a loop by itself, block by block, as
        it was for every loop; True where it cleared the map. A loop with none inside
        it is asked once, and stops at the first block that clears."""
        loop = {b for b in body if not self._quiet(b)}
        if fp is None or self._frame_escaped() or fp in self._written(loop):
            st.slot.clear()
            return True
        if sp is not None:
            for k in [k for k in st.slot if k.startswith(sp)]:
                del st.slot[k]
        wide = self._wide_slots()
        for b in sorted(loop):
            insns = self.blocks[b].insns
            for (_a, mn, op, _n) in insns:
                if mn in _STORES:
                    got = _addr(_split_ops(op))
                    if got is None or got[1] is _BAD_POST:
                        st.slot.clear()
                        return True
            for i, keys, delta, ops, backs in self._accesses(b):
                if delta:
                    st.slot.clear()
                    return True
                if backs is not None:
                    lo = int(keys[0][len(fp):])
                    _drop_stored(st.slot, fp, lo,
                                 lo + _access_width(insns[i][1], ops[0]) * len(keys))
                    for off in range(lo - 15, lo - 7):
                        if f"{fp}{off:+d}" in wide:
                            st.slot.pop(f"{fp}{off:+d}", None)
        if self._writes_heap(loop) or any(mn in ("bl", "blr") for b in loop
                                          for (_a, mn, _o, _n) in self.blocks[b].insns):
            for k in [k for k, v in st.slot.items() if self._reads_mem(v.text)]:
                del st.slot[k]
        return False

    def _slot_store(self, b, fp):
        """The frame slots block `b`'s stores drop in `_exit_slots`, or None where one
        of them clears the map: a store whose address does not parse or moves the frame
        after it, or one at a displacement the frame moved by."""
        insns = self.blocks[b].insns
        for (_a, mn, op, _n) in insns:
            if mn in _STORES:
                got = _addr(_split_ops(op))
                if got is None or got[1] is _BAD_POST:
                    return None
        gone, wide = set(), self._wide_slots()
        for i, keys, delta, ops, backs in self._accesses(b):
            if delta:
                return None
            if backs is not None:
                lo = int(keys[0][len(fp):])
                hi = lo + _access_width(insns[i][1], ops[0]) * len(keys)
                gone.update(f"{fp}{off:+d}" for off in range(lo - 7, hi))
                gone.update(k for k in (f"{fp}{off:+d}" for off in range(lo - 15, lo - 7))
                            if k in wide)
        return frozenset(gone)

    def _quiet_blocks(self) -> frozenset:
        """The blocks `_quiet` says yes to, once."""
        if self._quiet_set is None:
            self._quiet_set = frozenset(b for b in self.slow_paths
                                        if b in self.blocks and self._quiet(b))
        return self._quiet_set

    def _thru_block(self, b) -> bool:
        return any(self._through_frame(a, mn, op)
                   for (a, mn, op, _n) in self.blocks[b].insns)

    def _calls_in(self, b) -> bool:
        """Whether `b` calls; False for a block the graph does not have, as `_pin_loop`
        asks of a trip, which may hold one."""
        return b in self.blocks and any(t[1] in _CALLS for t in self.blocks[b].insns)

    def _bl_in(self, b) -> bool:
        return any(t[1] in ("bl", "blr") for t in self.blocks[b].insns)

    def _near_written(self, header) -> tuple:
        """(`_written` less _SPECIAL, `_call_written`) of the blocks `_exit_slots` calls
        near: `_loop_nodes(header)` less a block with a trap or a throw and a stack
        check's slow path.

        `_loop_nodes` is the header and every block that reaches it: the same set for
        each block of one strongly connected piece of the graph, that piece and each
        piece with a path into it. So a piece's answer is its own blocks' joined with the
        answers of the pieces with an edge into it, worked out once for every block in a
        topological order of the pieces (_pieces). A set per loop, N loops in a row
        walked about N * N / 2 blocks between them, and the lift grew with N * N (#289).
        """
        if not self._near:
            piece, order = self._pieces()
            ended, got = self._ended_blocks(), []
            for i, members in enumerate(order):
                w, c = set(), set()
                for x in members:
                    if x not in ended and not self._quiet(x):
                        own = self._written({x})
                        w |= own
                        if any(mn in _CALLS for (_a, mn, _o, _n) in self.blocks[x].insns):
                            c |= own | _CALL_CLOBBERS
                    for p in self._preds.get(x, ()):
                        j = piece.get(p)
                        if j is not None and j != i:
                            w |= got[j][0]
                            c |= got[j][1]
                got.append((frozenset(w - _SPECIAL), frozenset(c)))
            self._near = {x: got[i] for x, i in piece.items()}
        return self._near[header]

    def _pieces(self) -> tuple:
        """({block: its piece}, [blocks of each piece]): the strongly connected pieces
        of the graph, each before every piece it has an edge into (cfg.strong_components),
        numbered in that order."""
        if not self._piece:
            order = strong_components(
                self.blocks, lambda n: self.blocks[n].succ if n in self.blocks else ())
            self._piece = {x: i for i, members in enumerate(order) for x in members}
            self._piece_order = order
        return self._piece, self._piece_order

    def _wide_slots(self) -> set:
        """The frame slots a store of a q register fills anywhere in the function, which
        hold 16 bytes from their key and not 8; see _exit_slots and _overwrite."""
        return self._slot_widths()[1]

    def _narrow_slots(self) -> set:
        """The frame slots a store of fewer than 8 bytes fills anywhere in the function;
        see _reload and _reloads."""
        return self._slot_widths()[2]

    def _slot_widths(self) -> tuple:
        """({frame slot: the widths of the stores that fill it}, the slots one of 16
        fills, the slots one of fewer than 8 fills, whether every one is 8 bytes at a
        multiple of 8, and {frame slot: the register files they store from, `x` or
        `v`}), over the function, once."""
        if self._wide is None:
            widths: dict = {}
            files: dict = {}
            plain = True
            for blk in self.blocks.values():
                for (_a, mn, op, _n) in blk.insns:
                    got = _frame_slots(mn, op)
                    if not got:
                        continue
                    for (key, width), reg in zip(got[1], _split_ops(op)):
                        widths.setdefault(key, set()).add(width)
                        files.setdefault(key, set()).add(_reg_file(reg))
                        plain = plain and width == 8 and not int(key[len(got[0]):]) % 8
            self._wide = (widths, {k for k, w in widths.items() if 16 in w},
                          {k for k, w in widths.items() if min(w) < 8}, plain, files)
        return self._wide

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

    def _frame_taint(self) -> dict:
        """{address of a store: the mask of the registers that may hold a frame address
        before it}, in a function where one reaches a register (_frame_escaped) (#165).

        A store through such a register may write a slot: `sub x16, x29, #8; str x1,
        [x16]` wrote FP-8 and the slot read as before. A forward analysis: a register
        holds a frame address where an ALU instruction computes it from SP, FP or a
        register that may hold one, and any other write, a load or a call among them,
        gives it a value of its own. A frame address kept in a register, not one spilled
        and read back: that is rarer, and taking every value loaded back after any spill
        as a frame address flags the heap pointers a whole function stores through."""
        if self._taint is not None:
            return self._taint
        self._taint = {}
        if not self._frame_escaped():
            return self._taint
        sp, fp = _frame_regs()
        frame, clob = _reg_mask((sp, fp)), _reg_mask(_CALL_CLOBBERS)
        rank = self._rank if self._rank is not None else self._postorder()
        self._rank = rank
        order = sorted(self.blocks, key=lambda b: -rank.get(b, -1))
        raw = self.raw
        seen = {}
        out: dict = {}
        changed = True
        while changed:
            changed = False
            for b in order:
                m = 0
                for p in self._preds.get(b, ()):
                    m |= out.get(p, 0)
                for (a, mn, op, _n) in self.blocks[b].insns:
                    if mn == "nop" and a in raw:
                        mn, op = raw[a]
                    if mn in _STORES or _raw_store(mn):
                        seen[a] = m
                    m = self._taint_step(m, mn, op, frame, clob)
                if out.get(b) != m:
                    out[b] = m
                    changed = True
        self._taint = seen
        return seen

    @staticmethod
    def _taint_step(m: int, mn: str, op: str, frame: int, clob: int) -> int:
        """_frame_taint's mask after one instruction: a frame address survives in the
        register it is in, and an ALU instruction spreads it to what it computes from
        one; every other write clears its destination."""
        if mn == "nop" or not op:
            return m
        if mn in _CALLS:
            return m & ~clob
        de, us = _def_use_masks(mn, op)
        ops = _split_ops(op)
        if any(o.lstrip().startswith("[") for o in ops):
            return m & ~(de & ~_reg_mask((_writeback_base(ops),)) & ~frame)
        if us & (m | frame):
            return m | de & ~frame
        return m & ~de

    def _through_frame(self, a, mn: str, op: str) -> bool:
        """Whether the store at `a` is through a register that may hold a frame address
        (_frame_taint), off neither SP nor FP."""
        m = self._frame_taint().get(a)
        if not m:
            return False
        got = _addr(_split_ops(op))
        if got is None:
            return False
        (base, _disp, index, _scale, _wb), _post = got
        return bool(m & _reg_mask((base,) + ((index,) if index else ())))

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
        return self._any_block(self._stack_blocks, self._stores_frame, nodes) or (
            self._frame_escaped())

    def _stores_frame(self, b) -> bool:
        """`_writes_stack` of block `b` before it asks `_frame_escaped`."""
        for (_a, mn, op, _n) in self.blocks[b].insns:
            if mn not in _STORES and not _raw_store(mn):
                continue
            got = _addr(_split_ops(op))
            if got is None or got[1] is _BAD_POST:
                return True
            if _T.roles.get(got[0][0]) in ("SP", "FP"):
                return True
        return False

    def _any_block(self, memo: dict, test, nodes) -> bool:
        """Whether `test` holds of a block of `nodes`, each block's answer worked out once
        and remembered in `memo`. Over a loop's body it is folded up the nest (_fold),
        and over any other set asked by C loops and not a line per block: N nested loops
        asked it of N * N / 2 blocks (#332). A block that is not one raises KeyError, as
        the walk over its instructions did."""
        if not self._nested:
            return any(map(test, nodes))       # a loop by itself: stop at the first
        got = self._fold(nodes, id(memo), lambda b: self._flag(memo, test, b), any)
        if got is not None:
            return got
        for b in nodes - memo.keys():
            memo[b] = test(b)
        return any(map(memo.__getitem__, nodes))

    @staticmethod
    def _flag(memo: dict, test, b) -> bool:
        got = memo.get(b)
        if got is None:
            got = memo[b] = test(b)
        return got

    def _fold(self, nodes, name, leaf, join):
        """`join` of `leaf` of each block of `nodes` where `nodes` is a rooted body a
        LoopNest built (`_back_loop`, `_trip_nodes`, `_trip_body`), else None. A rooted
        body is its own blocks and the bodies it took in whole, so its answer is joined
        from theirs, each body's worked out once under `name`: N nested loops asked each
        body's every block (#332). `join` is a union or an `any`, which a block in two
        of the parts does not change."""
        for nest in (self._bnest, self._tnest):
            h = nest.by_id.get(id(nodes)) if nest is not None else None
            if h is not None and nest.body[h] is nodes and h in nest.good:
                break
        else:
            return None
        memo = self._folds.setdefault((name, id(nest)), {})
        if h not in memo:
            todo, stack = [], [h]
            while stack:                   # the nest below `h`, outer bodies first
                n = stack.pop()
                if n not in memo:
                    todo.append(n)
                    stack.extend(nest.kids[n])
            for n in reversed(todo):
                if n not in memo:
                    memo[n] = join([*map(leaf, nest.own[n]),
                                    *(memo[k] for k in nest.kids[n])])
        return memo[h]

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
        read the base" is not evidence about where it points. Nor is FP's role, past a
        write that put something else there (#307)."""
        return self._any_block(self._heap_blocks, self._heap_block, nodes)

    def _heap_block(self, b) -> bool:
        """_writes_heap of block `b` alone."""
        for (a, mn, op, _n) in self.blocks[b].insns:
            if mn not in _STORES and not _raw_store(mn):
                continue
            got = _addr(_split_ops(op))
            if got is None or got[1] is _BAD_POST:
                return True
            role = _T.roles.get(got[0][0])
            if role not in ("SP", "FP"):
                return True
            if role == "FP":
                if self._fp_lost_set is None:
                    self._fp_lost_set = _fp_lost_at(self.blocks, self.raw)
                if a in self._fp_lost_set:
                    return True
        return False

    def _stale_slots(self, st: State, written, unsafe=None) -> None:
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
            # Recordable where the text names no register a call in the region may have
            # left holding something else: then the drop has `stale_on_write`'s reason and
            # the value stays worth spelling (#196). `unsafe` is None where the caller
            # does not vouch for the region at all (#199).
            if unsafe is not None and not (set(_slot_regs(st.slot[k].text)) & unsafe):
                st.record_drop(k, st.slot[k])
            del st.slot[k]

    def _loop_nodes(self, header) -> frozenset:
        """Every ANCESTOR of `header`: the backward closure over its predecessors, which
        does not stop at the header and so takes the edge in from before the loop too.

        What `_exit_slots`'s `near` wants, which `_near_written` folds once over the
        graph's strongly connected pieces rather than walk per loop (#289), and is held
        to this walk by a test. The slot map is carried into the loop from before it,
        and the staleness it asks about is a register reassigned anywhere between the
        store that filled a slot and the read after the loop, so the blocks before the
        loop stand for the ones between the two (#199). The three questions about what
        the loop itself does ask `_back_loop`, the natural body: a block that ran before
        the loop is no part of what a trip does (#228).
        """
        got = self._loops.get(header)
        if got is not None:
            return got
        nodes, stack = {header}, list(self._preds.get(header, ()))
        while stack:
            n = stack.pop()
            if n in nodes or n not in self.blocks:
                continue
            nodes.add(n)
            for p in self._preds.get(n, ()):
                if p not in nodes:
                    stack.append(p)
        got = self._loops[header] = frozenset(nodes)
        return got

    def _loop_region(self, header) -> frozenset:
        """The blocks the loop at `header` can reach while it runs: the ones the header
        DOMINATES, so control cannot be in them without having entered the loop.

        Asked for ONE caller, the opaque marking at the loop exit, through
        `_region_written`, which folds what it writes up the dominator tree instead and
        walks it only where that has no numbers; and deliberately not by the three that
        ask `_loop_nodes` what the loop may write. `_loop_nodes` returns
        every ANCESTOR of the header, blocks that run BEFORE the loop among them, and a
        register written there is not one the loop assigned: a store based on it after the
        loop reads the value the pre-loop block put there, which its own name says
        correctly. Tightening what `written` and `carried` are computed over is a separate
        question with its own measurement (#228); this adds a set rather than changing
        one (#208).
        """
        got = self._regions.get(header)
        if got is not None:
            return got
        if self._idom is None:
            self._dom_tree()
        nodes, stack = set(), [header]
        while stack:
            n = stack.pop()
            if n in nodes or n not in self.blocks:
                continue
            if n != header and not self._dominates(header, n):
                continue
            nodes.add(n)
            stack.extend(self.blocks[n].succ)
        got = self._regions[header] = frozenset(nodes)
        return got

    def _region_written(self, header) -> frozenset:
        """`_own_written` of `_loop_region(header)`, folded up the dominator tree once.

        The region is the header's subtree of `_idom`, a run of its numbering: a block the
        header is above is reached from it through blocks it is above, or a path from the
        entry would pass it by. So what the region writes is what the header writes and
        what each child's subtree does, worked out once per block for every loop that
        asks. Walked as a set per loop, the regions asked 125,250 dominance questions
        between them for 500 loops in a row and 179,700 for 300 nested ones (#282). Where
        the header is in no tree, or `_idom` is no forest (cfg.dom_numbers), the region is
        walked as it was."""
        if self._idom is None:
            self._dom_tree()
        num = self._dnum
        if num is None or header not in num[0]:
            return frozenset(self._own_written(self._loop_region(header)))
        kids, memo = num[2], self._own_sub
        stack = [header]
        while stack:
            n = stack[-1]
            if n in memo:
                stack.pop()
                continue
            todo = [c for c in kids.get(n, ()) if c not in memo]
            if todo:
                stack.extend(todo)
                continue
            stack.pop()
            memo[n] = frozenset(self._own_written((n,))).union(
                *(memo[c] for c in kids.get(n, ())))
        return memo[header]

    def _own_written(self, nodes) -> set:
        """What the instructions in `nodes` write, NOT counting a call's clobbers.

        `_written` folds `_def_use`, which gives a call every volatile register, so it
        cannot tell "the loop assigned this" from "a callee may have changed it". A store
        base wants the first (#208).
        """
        w = set()
        for b in nodes:
            for (_a, mn, op, _n) in self.blocks[b].insns:
                if mn not in _CALLS:
                    w |= _def_use(mn, op)[0]
        return w

    def _written(self, nodes) -> set:
        """What the instructions in `nodes` write, a call's clobbers and a frame move's
        registers counted. Each block's worked out once, and joined by C loops and not a
        line per block (#332)."""
        defs = self._defs
        if not self._nested:
            w = set()
            for b in nodes:
                got = defs.get(b)
                w |= got if got is not None else self._block_defs(b)
            return w
        got = self._fold(nodes, "written", self._block_defs, _union)
        if got is not None:
            return set(got)
        for b in nodes - defs.keys():
            self._block_defs(b)
        return set().union(*map(defs.__getitem__, nodes))

    def _block_defs(self, b) -> frozenset:
        got = self._defs.get(b)
        if got is None:
            got = self._defs[b] = frozenset().union(
                *(_def_use(mn, o)[0] for (_a, mn, o, _n) in self.blocks[b].insns),
                *(self._moved_regs(a) for (a, _m, _o, _n) in self.blocks[b].insns
                  if a in self.frame_moves))
        return got

    def _writes_outgoing(self, nodes) -> bool:
        """Whether `nodes` hold a call, or a store that may write a slot off SP: one
        through SP, one `_step` prints raw, one through a frame register at an offset
        held in a register, or one _frame_meets found; or a frame move `_step` does not
        see (_frame_moves)."""
        return self._any_block(self._out_blocks, self._out_block, nodes)

    def _out_block(self, b) -> bool:
        """_writes_outgoing of block `b` alone."""
        sp = next((r for r, v in _T.roles.items() if v == "SP"), None)
        for (a, mn, op, _n) in self.blocks[b].insns:
            if mn in _CALLS or a in self.frame_meets or a in self.frame_moves:
                return True
            if mn in _STORES or _raw_store(mn):
                if self._through_frame(a, mn, op):
                    return True
                got = _addr(_split_ops(op))
                if got is None or got[0][0] == sp or (
                        _T.roles.get(got[0][0]) == "FP" and got[0][2] is not None):
                    return True
                if _raw_store(mn) and _T.roles.get(got[0][0]) in ("SP", "FP"):
                    return True
        return False

    def _accesses(self, b) -> list:
        """_frame_accesses of block `b`, worked out once."""
        got = self._frame_list.get(b)
        if got is None:
            got = self._frame_list[b] = list(_frame_accesses(
                self.blocks[b].insns, meets=self.frame_meets, moves=self.fp_moves))
        return got


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


#: The V registers Dart passes double arguments in, apart from the CPU ones:
#: `constants_arm64.h`, kFpuRegistersForArgs[] = {V0, V1, V2, V3, V4, V5}.
FPU_ARG_REGS = ("d0", "d1", "d2", "d3", "d4", "d5")


class StackArity(int):
    """entry_arity's register count for a function that takes the rest of its arguments
    on the stack, the last one at the lowest slot: `need` is how many slots of them its
    own loads reach, None where it reads them through an index computed from FP, and
    `fpu` whether it reads a V register it was handed (#148)."""

    def __new__(cls, k: int, need: int, fpu: bool = False):
        self = super().__new__(cls, k)
        self.need, self.fpu = need, fpu
        return self

    def __getnewargs__(self):
        return int(self), self.need, self.fpu


def _fpu_args_live(blocks, entry, with_ret: bool = True) -> bool:
    """Whether one of FPU_ARG_REGS is read before it is written, from `entry`: the
    function is handed a double in it. The zero idiom reads nothing. A `ret` reads d0
    only where no call and no write to x0 can come before it (_argument_returns): what
    it hands back there is d0, the argument, as #127's `Curve.transform` hands back its
    own; elsewhere it returns in x0, or d0 a call or the function itself wrote. A call
    is not taken to read them: one with more than six arguments that passes a double on
    untouched would be missed, where taking every call for a read left almost every
    such callee unprinted.

    `with_ret` is False where the `ret` must not count: a function that reads x1 and
    returns the object in x0 writes neither d0 nor x0 and makes no call, so
    _argument_returns marks its `ret` as handing back d0 all the same, which is a read
    only a caller's own reading could confirm. For counting a double ARGUMENT that
    decides a call's argument list (#155), that bare `ret` is not evidence, where a real
    read of d0 in the body is."""
    want = frozenset(FPU_ARG_REGS)
    back = _argument_returns(blocks, entry) if with_ret else {}
    use, dfn = {}, {}
    for b, blk in blocks.items():
        u, d = set(), set()
        for (a, mn, op, _n) in blk.insns:
            if mn == "ret":
                if a not in back:
                    continue
                de, us = (), ("d0",)
            else:
                de, us = _def_use(mn, op)
            ops = _split_ops(op)
            if mn == "eor" and len(ops) == 3 and ops[1] == ops[2]:
                us = ()
            u |= (want & set(us)) - d
            d |= want & set(de)
        use[b], dfn[b] = u, d
    live = {b: set() for b in blocks}
    changed = True
    while changed:
        changed = False
        for b in sorted(blocks, reverse=True):
            out = set()
            for s in blocks[b].succ:
                out |= live.get(s, set())
            li = use[b] | (out - dfn[b])
            if li != live[b]:
                live[b], changed = li, True
    return bool(live.get(entry))


def entry_arity(ann: list, cut: bool = False):
    """Number of register arguments a function takes: the count of contiguous ARG_REGS
    live on entry (read before being written) under the Dart AOT register convention
    (receiver in x1 for instance methods). Returns None when the register count is not
    the signature, so a caller must not claim to know the arguments.

    These make it return None rather than a number:

    * the function reads incoming STACK arguments (`[FP, #>=0x10]`, which is
      `param_end_from_fp + 1`, the first incoming slot, or off SP without a frame, or
      through an index computed from FP) and no argument register (#144);
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

    A function that reads both is handed its first arguments in registers and the rest
    on the stack, as `hash6` to `hash20` are, and gets a StackArity (#148). `cut` says
    the instruction cut stopped `ann` short of the function's end (disasm.truncated_by):
    the part left out could read a higher stack slot or a V register, so a StackArity's
    reach is then not known.
    """
    return _entry_read(ann, cut)[0]


def entry_args(ann: list, cut: bool = False) -> tuple:
    """The argument registers a function reads before it writes them, in ARG_REGS order:
    the ones it was handed a value in. Empty where `entry_arity` declines, so every
    reason it has for not knowing the arguments holds here too.

    The count `entry_arity` returns is the LEADING run of these, because a call site
    prints a list and a list cannot skip a slot. A name can. `classify(int score)` on an
    instance never touches `this`, so it reads x2 and not x1, the run is empty and its
    count is 0, while x2 is as much an argument as it would be had the body read x1
    first: 208 of the clean fixture's 6,037 counted ranges read no x1 and some later
    register, and 45 more read one past a gap. Checked against the snapshot where it
    says: on the 428 functions that keep their FunctionType and are counted, the highest
    register read is never past `num_fixed_parameters`, and in the 11 of them that read
    past a gap it is exactly the last one (#255)."""
    return _entry_read(ann, cut)[1]


def _entry_read(ann: list, cut: bool) -> tuple:
    """(entry_arity's answer, entry_args's), from one pass over the function."""
    stripped = strip_boilerplate(ann)
    # honours traps and calls that cannot return, like the lift
    blocks, entry = build_cfg(stripped, traps=TRAPS, ends=_path_ends(stripped))
    if not blocks or entry not in blocks:
        return 0, ()
    # A function that never moves SP reads its incoming stack arguments off SP itself,
    # `ldr x0, [x15]`, and one that indexes them computes the address from FP, `add x1,
    # x29, w0, sxtw #2; ldr x1, [x1, #0x28]`. Where it reads no register as well, it was
    # taken for a function of no arguments and a call to one printed `f()` over what it
    # pushed (#144). One that takes some in registers and the rest on the stack printed
    # either its registers or what was pushed, as the whole list (#148).
    frameless = not any("x15" in _def_use(row[1], row[2])[0] for row in ann)
    off_stack, indexed, need, reach = False, set(), 0, True
    for b in blocks.values():
        for (_a, mn, op, _n) in b.insns:
            parts = _split_ops(op)
            if mn in _LOADS:
                m = _mem(parts[-1]) if parts else None
                first = None                           # an incoming stack argument's slot
                if m and m[0] == "x29" and m[1] >= 0x10:
                    first = m[1] - 0x10
                elif m and frameless and m[0] == "x15" and m[1] >= 0:
                    first = m[1]
                if first is not None:
                    off_stack = True
                    width = {"w": 4, "s": 4, "q": 16}.get(parts[0].strip()[:1], 8)
                    size = width * (2 if mn.startswith("ldp") and mn != "ldpsw" else 1)
                    need = max(need, (first + size + 7) // 8)
                if m and m[0] in indexed and m[1] >= 0x10:
                    off_stack, reach = True, False     # how far up, the index says
            if (mn == "add" and len(parts) >= 3 and canon(parts[1]) in ("x29", "x15")
                    and not parts[2].strip().startswith("#")):
                indexed.add(canon(parts[0]))          # a local below FP is read below 0
            elif indexed:
                indexed -= _def_use(mn, op)[0]        # it holds something else now
    live = _live_in_header(blocks, set(blocks), entry, None)
    if "x4" in live:                  # ARGS_DESC_REG: the stack convention, not arity
        return None, ()
    k = 0
    while k < len(ARG_REGS) and ARG_REGS[k] in live:
        k += 1
    args = tuple(r for r in ARG_REGS if r in live)
    if not off_stack:
        # A function handed a double in a V register (`_fpu_args_live`) passes it beside
        # the x registers, in an order the registers alone do not give: `f(Object a,
        # double b)` reads x1 and d0 and printed `f(x1)`, and where the double comes
        # first the list did not even start at the first argument. So the list is not
        # known, the same decline a mixed register-and-stack callee handed a double
        # already makes (#148, #155). A `ret` that hands d0 back is not counted here: a
        # function reading only x registers and returning its object in x0 has one too.
        return (None, ()) if _fpu_args_live(blocks, entry, with_ret=False) else (k, args)
    if not args:
        return None, ()
    return StackArity(k, need if reach and not cut else None,
                      _fpu_args_live(blocks, entry)), args


@kept
def make_arity_resolver(image):
    """Build a cached `pc -> arity` resolver over a whole instruction image, mapping a
    call target to the covering function's register-argument count. A call site uses it
    to render the callee's real arguments. Returns a callable; results are memoised.

    Its `args(pc)` is `entry_args` for the same function, from the same pass and the
    same cache: the registers a body reads its arguments from (program.EntryNames)."""
    from .disasm import disassemble_range, truncated_by
    import bisect
    ranges = sorted(image.all_ranges, key=lambda cr: cr.pc_offset)
    starts = [cr.pc_offset for cr in ranges]
    cache: dict = {}

    def read(pc):
        if pc in cache:
            return cache[pc]
        i = bisect.bisect_right(starts, pc) - 1     # covering range (unchecked entries)
        val = (None, ())
        if 0 <= i < len(ranges):
            cr = ranges[i]
            if cr.pc_offset <= pc < cr.pc_offset + cr.size:
                dis = disassemble_range(image, cr)
                if dis:
                    val = _entry_read([(a, m, o, "") for (a, m, o) in dis],
                                      cut=bool(truncated_by(cr, dis)))
        cache[pc] = val
        return val

    def of(pc):
        return read(pc)[0]

    of.args = lambda pc: read(pc)[1]
    return of


#: How far past a `bl` its caller is read for the first touch of x0 or d0, and how many
#: call sites a function may have and still be asked about. The first touch is the next
#: instruction or two in compiled Dart. A function called from more places than that is
#: not read at all, rather than read in part: the sites left out could disagree. A call
#: is only seen where `disassemble_range` reads, so a site past MAX_INSNS of a range
#: longer than that is not counted either: 119 on 3.4.4, 355 in immich.
_AFTER_CALL = 16
_MAX_SITES = 256


def _read_after_call(rows):
    """"x0" or "d0", whichever the code after a call reads first, or None when it reads
    neither before writing both, branching, calling again or returning. A push of a
    whole V register says nothing either (_rv_push): it saves it for a slow path, and
    follows a call only where the call does not return, a throw laid out before the
    next slow path, whose `str q0, [x15, #-0x10]!` read as the throw's d0 result."""
    from .disasm import UNDECODABLE
    gone = set()
    for (_a, mn, op) in rows:
        if mn == "ret" or _rv_push(mn, op):
            return None              # handed straight back: says nothing about which
        defs, uses = _rv_def_use(mn, op)
        uses = uses - gone
        if uses:
            return next(iter(uses)) if len(uses) == 1 else None
        if (mn in ("bl", "blr", "b", "br", "brk", "hlt", UNDECODABLE) or cond_of(mn)
                or mn in _CONDB):
            return None
        gone |= defs
    return None


@kept
def make_return_resolver(image):
    """Build a cached `pc -> "x0" | "d0" | None` resolver over a whole instruction image:
    which register the code after a direct `bl` to the function covering `pc` reads the
    result from (#115). A value has to be read from where the callee left it, and a call
    clobbers both registers, so the first of the two a caller touches after the call,
    reading it, is the one the callee returns in. Callers that disagree, none that read
    either, or more than _MAX_SITES of them, give None. Its `code_d0` says whether a
    function's own code hands back d0, and `by_table` what the other implementations of
    its selector return in.

    The index of call sites is built on the first question, one pass over the raw words
    as callgraph reads them, and a function's sites are decoded only when it is asked
    about, each site once. arm64 only, as tier 3 is."""
    from array import array
    from .disasm import A64Words, A64_BL, CodeRange, MAX_INSNS, disassemble_range
    import bisect
    arch = getattr(image, "arch", None)
    if (arch.name if arch is not None else "arm64") != "arm64":
        return lambda pc: None
    ranges = sorted(image.all_ranges, key=lambda cr: cr.pc_offset)
    starts = [cr.pc_offset for cr in ranges]
    cache: dict = {}
    sites: list = []

    def covering(pc):
        i = bisect.bisect_right(starts, pc) - 1
        if 0 <= i < len(ranges) and starts[i] <= pc < starts[i] + (ranges[i].size or 0):
            return i
        return None

    def end_of(i):
        """Where the window disassemble_range reads for range i stops."""
        cr = ranges[i]
        end = min(len(image.text), cr.pc_offset + (cr.size or 512))
        return cr.pc_offset + min(max(0, end - cr.pc_offset) // 4, MAX_INSNS) * 4

    def index():
        words = A64Words(image.text)
        out: dict = {}                     # callee range -> word index of each `bl`
        for i, cr in enumerate(ranges):
            for w_at, w in words.window(cr.pc_offset, (end_of(i) - cr.pc_offset) // 4):
                if (w & 0xFC000000) != A64_BL:
                    continue
                imm = w & 0x03FFFFFF
                if imm & 0x02000000:
                    imm -= 0x04000000
                k = covering(w_at * 4 + imm * 4)
                if k is None:
                    continue
                got = out.get(k)
                if got is None:
                    got = out[k] = array("I")
                if len(got) <= _MAX_SITES:       # one past the bound marks it as over
                    got.append(w_at)
        return out

    def of(pc):
        k = covering(pc)
        if k is None:
            return None
        if k in cache:
            return cache[k]
        if not sites:
            sites.append(index())
        at = sites[0].get(k, ())
        votes = set()
        for w_at in (at if len(at) <= _MAX_SITES else ()):
            site = w_at * 4
            caller = covering(site)       # None only where crafted ranges overlap
            if caller is None:
                continue
            n = min(_AFTER_CALL, (end_of(caller) - site - 4) // 4)
            if n <= 0:
                continue
            got = _read_after_call(disassemble_range(
                image, CodeRange(site + 4, n * 4, -1), max_insns=n))
            if got:
                votes.add(got)
                if len(votes) > 1:
                    break
        cache[k] = val = next(iter(votes)) if len(votes) == 1 else None
        if votes or len(at) > _MAX_SITES:
            spoke.add(k)
        return val

    own: dict = {}
    spoke: set = set()          # ranges whose callers read a register, or are too many

    def code_d0(pc):
        """Whether the function covering `pc` hands back d0 at every `ret` by its own
        code (returns_in_d0), for a call to it that no caller's reading decides."""
        k = covering(pc)
        if k is None:
            return False
        if k not in own:
            dis = disassemble_range(image, ranges[k])
            own[k] = bool(dis) and returns_in_d0([(a, m, o, "") for (a, m, o) in dis])
        return own[k]

    def by_table(pc, selectors):
        """Which register the other implementations of the selector the dispatch table
        places the function at `pc` under hand back their result in (Selectors.peers),
        for a function whose direct callers, where it has any, read neither register
        after the call (#127): each one's callers' reading, or, where those say
        nothing, d0 where its own code hands back d0 (code_d0). A call through the
        table reads one register whatever function it lands on, so every
        implementation of a selector returns in the same one. Callers that disagree, or
        more than _MAX_SITES of them, have spoken, and the table is not asked over
        them. Those asked have to agree, and at most _MAX_SITES of them are."""
        peers = getattr(selectors, "peers", None)
        k = covering(pc)
        if peers is None or k is None:
            return None
        of(pc)
        if k in spoke:
            return None
        votes = set()
        for p in peers(pc, _MAX_SITES):
            got = of(p) or ("d0" if code_d0(p) else None)
            if got:
                votes.add(got)
                if len(votes) > 1:
                    return None
        return next(iter(votes)) if votes else None

    of.code_d0 = code_d0
    of.by_table = by_table
    return of


# ── dispatch-table (virtual) call attribution ───────────────────────────────

#: What detect_dispatch can know about one register. Exactly one at a time:
#: the tags word of an object, a class id derived from it, a plain immediate, a
#: (cid, selector offset) pair, or a resolved dispatch-table target.
_F_TAGS, _F_CID, _F_IMM, _F_DISP, _F_DTARGET = 0, 1, 2, 3, 4


#: How many rows back from a dispatch call its class id read may be for the receiver to
#: be followed from one to the other. The clean build's furthest is 11; past the bound
#: the call prints no receiver, and a call costs no more than the bound to answer.
_RECV_WINDOW = 64


def _branch_map(dis):
    """(into, out, indirect) for the rows of one body: the rows that branch to each row a
    direct branch names, the row each direct branch names (None where it leaves the
    body), and whether any row jumps through a register."""
    row = {t[0]: i for i, t in enumerate(dis)}
    into, out, indirect = {}, {}, False
    for i, t in enumerate(dis):
        mn = t[1]
        if mn[:1] != "b" and mn not in _CONDB:
            continue
        if mn == "br" or mn == "bx":
            indirect = True
        elif mn == "b" or mn in _CONDB or cond_of(mn):
            out[i] = j = row.get(_target(t[2]))
            if j is not None:
                into.setdefault(j, []).append(i)
    return into, out, indirect


def _receiver_at(dis, read, call, flow):
    """Where the object whose tags word row `read[1]` loaded off register `read[0]` is at
    the `blr` in row `call`: a register that holds it, or the offset of the outgoing
    slot it was pushed to (an int) where no register does, or None. `flow` is the
    body's `_branch_map`.

    The class id is read before the arguments are moved into place, so the register it
    was read from is as often as not something else by the call: `mov x1, x2` and then
    `ldr x2, [x27, #0x2a00]` printed the pool entry as the receiver, and a class id
    copied over its own object, which had gone to the stack, printed the register the
    class id is in (#377). A whole-register `mov` out of a holder makes another holder
    and any other write of one ends it; a whole holder stored off SP is in that slot
    until a store reaches the slot or SP moves, other than by a push, which moves the
    slot up by as much.

    The answer is what every way from the read to the call leaves, not what the rows
    between them leave when read top to bottom. A row a branch names is reached with
    what each of its ways in carries, and keeps what they agree on: the row before it
    unless that row cannot fall through, and each branch to it. A branch inside the
    stretch carries what was known at it. The Smi check, `tbz w0, #0` on the row before
    the read and over it to the row after the `ubfx`, carries the register of the read
    and nothing else: it tests the low bit of that register, so the object is in it on
    the way that skips the read as well. A branch from anywhere else, any other branch
    on the row before the read and a loop back into the stretch included, carries
    nothing this has followed, and the call has no receiver; so has a call in a body
    that jumps through a register, since that may land on any row. A row after `b`,
    `ret` or a trap that no branch names is not reached at all.

    The first argument register is preferred where it holds the object, since that is
    the receiver the callee is handed, then the register the read was off."""
    reg, at = read
    into, out, indirect = flow
    if call - at > _RECV_WINDOW or indirect:
        return None
    sp = _sp_reg()
    held, slot, live = {reg}, None, True
    ahead = {}                                  # row -> what branches before it carry
    for k in range(at, call + 1):
        if k > at and (not live or k in into):
            ways = ahead.pop(k, [])
            if live:
                ways.append((held, slot))
            for src in into.get(k, ()):
                if src == at - 1:
                    ops = _split_ops(dis[src][2])
                    if dis[src][1] != "tbz" or canon(ops[0]) != reg or ops[1] != "#0":
                        return None             # not the Smi check on that register
                    ways.append(({reg}, None))
                elif not at <= src < k:
                    return None                 # from outside the stretch, or a loop
            if not ways:
                if k == call:
                    return None
                continue                        # a row nothing reaches
            held = set(ways[0][0]).intersection(*(w[0] for w in ways[1:]))
            slot = ways[0][1] if all(w[1] == ways[0][1] for w in ways) else None
            live = True
        if k == call:
            break
        mn, op = dis[k][1], dis[k][2]
        pushed = False
        if mn == "mov":
            ops = _split_ops(op)
            # whole registers only: `mov w1, w2` keeps half of it
            if len(ops) == 2 and ops[1] in held and canon(ops[0]) == ops[0]:
                held.add(ops[0])
                if ops[0] == sp:
                    slot = None
                continue
        elif mn in _STORES:
            ops = _split_ops(op)
            m = _mem(ops[-1])
            if m is None or m[0] != sp or m[2] is not None:
                if m is None or m[0] == sp:
                    slot = None             # a store off SP this cannot place
            elif mn == "str" or mn == "stur" or mn == "stp":
                low = m[1] or 0
                if m[4]:
                    # a push, as Dart 2.19 writes one: SP moves by the displacement and
                    # the store is at the new SP, so a slot already held is that much up
                    if slot is not None:
                        slot = slot - low if slot >= low else None
                    low, pushed = 0, True
                for n, src in enumerate(ops[:-1]):
                    at_off = low + 8 * n
                    if src in held:
                        slot = at_off
                    elif src[:1] != "x" or (slot is not None and abs(at_off - slot) < 8):
                        slot = None         # the slot, or a width this does not place
            else:
                slot = None
        elif slot is not None and (mn == "dc" or "[" in op and mn not in _LOADS):
            slot = None                     # any other instruction that may write memory
        elif k in out:
            j = out[k]
            if j is not None and k < j <= call:
                ahead.setdefault(j, []).append((frozenset(held), slot))
            live = mn != "b"
        elif mn == "ret" or mn in TRAPS:
            live = False
        defs = _def_use(mn, op)[0]
        if defs:
            held -= defs
            if sp in defs and not pushed:
                slot = None
        if not held and slot is None and not ahead:
            return None
    first = _T.arg_regs[0] if _T.arg_regs else None
    if not held:
        return slot
    return first if first in held else reg if reg in held else min(held)


def _sp_reg() -> str:
    """The register Dart keeps its stack pointer in."""
    return next((r for r, v in _T.roles.items() if v == "SP"), "x15")


def detect_dispatch(dis) -> dict:
    """Map each X21 dispatch-table `blr` address -> (receiver | None, offset | None).

    Dart AOT dispatch-table calls resolve a virtual/interface method by class id:
      ldur tags,[recv,#-1]; ubfx cid,tags,#0xc,#0x14; add idx,cid,#off; ldr t,[x21,idx,lsl#3]; blr t
    The offset added to the class id selects the row for one selector. It's stable across
    the whole program (same selector, same offset), so it identifies the selector even
    though the source name lives only in the serialized dispatch table, which this pass
    doesn't read. Recovers that offset, which renders as `sel_0x<off>`, and where the
    receiver is AT THE CALL: a register, or an outgoing slot's offset (_receiver_at)."""
    # ONE fact per register, not five parallel maps. The five kinds are mutually
    # exclusive by construction: every branch below invalidates its destination and then
    # records at most one thing about it, so a register can never be two of them at once.
    # A fact is about the value in a register, so every register a row writes loses its
    # own: the second register of an `ldp`, a base that a load or a store moves, what a
    # call may write. `mov x17, #5; ldp x3, x17, [x9]; add x30, x0, x17` named the
    # selector at offset 5, and a call through the pool after a table call,
    # `ldp x5, x30, [x16]; blr x30`, named the table call's selector again.
    # As five dicts, invalidation was five pops on every instruction whether or not
    # anything was known, 2.2M of them on one `functions` run.
    fact = {}
    out = {}
    flow = None                                 # the body's branches, once a call asks
    for i, t in enumerate(dis):
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
            for r in [r for r in fact if r in _CALL_CLOBBERS]:
                del fact[r]
            if f is not None and f[0] == _F_DTARGET:
                read, off = f[1]
                if read and flow is None:
                    flow = _branch_map(dis)
                out[t[0]] = (_receiver_at(dis, read, i, flow) if read else None, off)
            continue
        if not ops:
            continue
        dst = canon(ops[0])
        if (mn == "ldur" or mn == "ldr") and len(ops) >= 2:
            m = _mem(ops[-1])
            if m is None or m[4]:
                # the base moves: `ldr x3, [x17], #8` writes x17 as well
                for r in _def_use(mn, t[2])[0]:
                    fact.pop(r, None)
            elif m[2] is None and m[1] == -1 and m[0] not in _UNTAGGED:
                fact[dst] = (_F_TAGS, (m[0], i))            # tags word of a tagged object
            elif (_T.roles.get(m[0]) == "DISPATCH"
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
                # A 32-bit move clears the top half: `mov w17, #-5` leaves 0xfffffffb.
                fact[dst] = (_F_IMM, imm if ops[0][:1] != "w" else imm & 0xffffffff)
            elif f is not None:
                if f[0] == _F_CID:
                    fact[dst] = (_F_DISP, (f[1], 0))
                elif f[0] == _F_DISP or f[0] == _F_DTARGET:
                    fact[dst] = f
            continue
        if (mn == "add" or mn == "sub") and len(ops) >= 3:
            fs = fact.get(canon(ops[1]))
            ft = fact.get(canon(ops[2]))
            fact.pop(dst, None)
            # The row is the class id plus what the machine adds, in 64 bits. An
            # immediate is twelve bits, as written or shifted left by twelve, and
            # `sub x30, x0, #1, lsl #12` is the row 0x1000 below, not the one below
            # (#376). A register is added whole only when nothing shifts or extends it.
            # Any other form, and a 32-bit add, which wraps where this one does not,
            # is left with no offset, and the call prints without a selector.
            if (fs is not None and fs[0] == _F_CID
                    and ops[0][:1] == "x" and ops[1][:1] == "x"):
                off = _imm(ops[2])
                if off is not None:
                    if len(ops) == 4 and ops[3] == "lsl #12":
                        off <<= 12
                    elif len(ops) != 3:
                        off = None
                elif (len(ops) == 3 and ops[2][:1] == "x"
                      and ft is not None and ft[0] == _F_IMM):
                    off = ft[1]
                if off is not None:
                    fact[dst] = (_F_DISP, (fs[1], off if mn == "add" else -off))
            continue
        fact.pop(dst, None)
        defs = _def_use(mn, t[2])[0]
        if defs:
            for r in [r for r in fact if r in defs]:
                del fact[r]
    return out


# ── public entry point ──────────────────────────────────────────────────────

_DECL_RE = re.compile(r"^(\s*)var (t\d+) = (.+);$")
#: A declaration with NO initialiser, `var t5;`, which is what names a value the lifter
#: does not know: what a call left in a register it clobbered (`_clobber_call`). It has no
#: initialiser to evaluate, so one nothing reads can always go (#176).
_BARE_DECL_RE = re.compile(r"^(\s*)var (t\d+);$")
_TMP_RE = re.compile(r"\bt\d+\b")


def _inline_single_use(lines: list, names: set, wrap=frozenset()) -> list:
    """Fold `var t0 = f(x); return t0;` back into `return f(x);`.

    Naming a call's result is what stops a machine register leaking into every later line,
    but where the result has exactly one reader and that reader is the VERY NEXT
    statement, the name buys nothing and costs a line.

    Folding it there is safe for a reason that does not generalise, so the conditions are
    both checked rather than assumed: the value crosses no statement, so nothing it is
    spelled in terms of can have changed and no side effect is reordered; and it has one
    use in the whole body, so the call is not duplicated. Only temporaries minted for a
    call RESULT are eligible, a temporary that exists to stop an expression doubling in
    size must not be folded back into the expression it was cut out of.

    A slot name (#64) is eligible too, and is passed in `wrap` as well. It is given for a
    reload after a call, and where the only use the body prints is the statement right
    after the store, that reload is not printed and the name says no more than the field
    read did: about 60 a build, like a class id saved across calls that only the next
    `if` reads. Unlike a call, its value can be any expression, so it goes back in
    brackets unless it is one term: `t0 * 2` with `t0 = a + b` is `(a + b) * 2`."""
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
            # A use in the line's comment (`// x0 holds t4`, _verbatim) is no use to fold
            # into: the call would leave the code for the comment.
            use = _TMP_RE.findall(nxt)
            if (len(use) == 1 and use[0] == m.group(2)
                    and m.group(2) in _TMP_RE.findall(nxt.split("   // ", 1)[0])):
                text = m.group(3)
                if m.group(2) in wrap and not _one_term(text):
                    text = f"({text})"
                out.append(re.sub(rf"\b{m.group(2)}\b", text.replace("\\", "\\\\"),
                                  nxt))
                skip = i + 1
                continue
        out.append(ln)
    return out


def _no_self_holds(ln: str) -> str:
    """`ln` without the `x7 holds x7` a raw line's note says once a loop name it held
    is put back to the register it stood for (_render_loop)."""
    if " holds " not in ln or "   // " not in ln:
        return ln
    code, note = ln.split("   // ", 1)
    keep = [p for p in re.split(r", (?=\w+ holds )", note)
            if not re.fullmatch(r"(\w+) holds \1", p)]
    return f"{code}   // {', '.join(keep)}" if keep else code


_VAR_DECL_RE = re.compile(r"\bvar (t\d+)\b")


def _declared_temps(lines) -> set:
    """The numbers of the temps a `var` line in `lines` declares, so a block reached out
    of flow can tell a name the way to it bound from one nothing here does (`walk`)."""
    return {int(m[1:]) for ln in lines for m in _VAR_DECL_RE.findall(ln)}


def _forget_temps(st: State, gone) -> None:
    """Drop every value in `st` spelled with a temp whose number `gone` is true of."""
    def late(text):
        return "t" in text and any(gone(int(m)) for m in _TMP_NUM_RE.findall(text))
    for r, v in sorted(st.reg.items()):
        if late(v.text):
            st.forget(r)
    for k in [k for k, v in st.slot.items() if late(v.text)]:
        st.forget_slot(k)
    # ...and a record naming a name declared only on another path goes too: the text
    # would read a `tN` whose declaration does not dominate the reload (#199).
    for k, (v, _f) in list(st.dropped.items()):
        if late(v.text):
            st.dropped.pop(k, None)
    for k, (b, i, _s, _f) in list(st.elem.items()):
        if late(b.text) or late(i.text):
            del st.elem[k]


_TMP_NUM_RE = re.compile(r"\bt(\d+)\b")


def _spells_a_temp(st: State) -> bool:
    """Whether anything `_forget_temps` looks at in `st` spells a temp."""
    texts = [v.text for v in st.reg.values()] + [v.text for v in st.slot.values()]
    texts += [v.text for v, _f in st.dropped.values()]
    texts += [t.text for b, i, _s, _f in st.elem.values() for t in (b, i)]
    return any("t" in t and _TMP_NUM_RE.search(t) for t in texts)

#: How many values one function's first walk writes out before a goto (_arrive). A real
#: function needs a handful; a crafted one with thousands of slots and hundreds of gotos
#: asked for millions, a gigabyte of declarations. Past the bound a value is forgotten,
#: which the target reads as its bare register.
_MAX_PINS = 2048
_RAW_LINE_RE = re.compile(r"\s*([a-z][a-z0-9.]*)(?:\s+(.*?))?(?:\s+//.*)?$")
_ASSIGN_LINE_RE = re.compile(r"\s*([a-z]\d+) ([-+*&|^]?=) ")
_NOT_RAW = frozenset({"return", "throw", "rethrow", "break", "continue", "goto", "var"})


def _stmt_blocks(stmts, blocks) -> set:
    """The blocks a structured statement list walks, nested ones included, leaving out
    an arm of a nested `if` that leaves the function: no path through it reaches the
    end of the list."""
    def leaves(arm):
        last = arm[-1] if arm else ("",)
        return last[0] in ("exit", "cut") or (
            last[0] == "asm" and last[1] in blocks and not blocks[last[1]].succ)
    out, todo = set(), [stmts]
    while todo:
        for s in todo.pop():
            if s[0] == "asm":
                out.add(s[1])
            elif s[0] == "if":
                todo += [arm for arm in (s[2], s[3]) if not leaves(arm)]
            elif s[0] == "loop":
                out.add(s[1])
                todo.append(s[2])
    return out


def _agree(maps: list) -> dict:
    """The entries all of `maps` hold alike."""
    return {k: v for k, v in maps[0].items() if all(m.get(k) == v for m in maps)}


#: How many times over the bodies of a function's loops may walk its blocks, one loop
#: at a time, before they are built as a nest; see Lifter._back_loop. Of the 721
#: functions with a loop in the clean fixture, 21 walk theirs more than once over, 2
#: more than one and a half times and none twice.
_NEST_AFTER = 2


def _union(parts) -> frozenset:
    return frozenset().union(*parts)


#: What a block `_exit_slots` leaves out adds to its answer: nothing.
_NO_EXIT = (frozenset(), frozenset(), False, False)


def _exit_join(parts) -> tuple:
    """(written, the frame slots dropped or None for all of them, stores to the heap,
    calls) of a loop, from those of its parts; see Lifter._exit_slots."""
    gone = [p[1] for p in parts]
    return (frozenset().union(*(p[0] for p in parts)),
            None if None in gone else frozenset().union(*gone),
            any(p[2] for p in parts), any(p[3] for p in parts))


def _drop_stored(held: dict, fp: str, lo: int, hi: int):
    """Drop from `held`, FP slots of 8 bytes keyed as `State.slot` is, each one a store to
    bytes `lo` to `hi` of the frame writes any of. A slot starts at most 7 below `lo`, so
    this looks up a fixed number of keys, not every slot held (#154)."""
    for off in range(lo - 7, hi):
        held.pop(f"{fp}{off:+d}", None)


#: The loads that sign-extend what they read.
_SIGNED_LOADS = frozenset({"ldrsw", "ldursw", "ldrsh", "ldursh", "ldrsb", "ldursb",
                           "ldpsw"})


def _reg_file(reg: str) -> str:
    """`v` for a floating-point or vector register, `x` for a general one."""
    r = reg.strip()
    return "v" if r[:1] in "bhsdqv" and r[1:2].isdigit() else "x"


def _extended(v: V, bits: int, signed: bool) -> V:
    """`v` read as a load of its low `bits` bits does: sign-extended as `sxtw` prints
    it, or zero-extended as `uxtw` does, and as it is where it already fits."""
    if _fits(v, bits - 1 if signed else bits):
        return v
    if signed:
        pad = 64 - bits
        return _bin(_bin(v, "<<", _num(pad), P_SHIFT), ">>", _num(pad), P_SHIFT)
    return _bin(v, "&", V(hex((1 << bits) - 1), P_ATOM, bits=bits), P_AND)


def _access_width(mn: str, reg: str) -> int:
    """The bytes a load or store of `reg` with `mn` moves, per register: a q register's
    16 where the spelling says nothing narrower."""
    if mn in ("strb", "sturb", "ldrb", "ldurb", "ldrsb", "ldursb"):
        return 1
    if mn in ("strh", "sturh", "ldrh", "ldurh", "ldrsh", "ldursh"):
        return 2
    if mn in ("ldrsw", "ldursw", "ldpsw"):
        return 4
    return {"x": 8, "d": 8, "w": 4, "s": 4, "h": 2, "b": 1}.get(reg.strip()[:1], 16)


def _printed_writes(lines: list) -> set:
    """The machine registers `lines` assign: a raw line's destinations, and the
    left-hand side of `x4 = x4 + 8;` (_bump)."""
    out = set()
    for ln in lines:
        m = _ASSIGN_LINE_RE.match(ln)
        if m:
            out.add(canon(m.group(1)))
            continue
        if ln.rstrip().endswith((";", "{", "}", ":")):
            continue
        m = _RAW_LINE_RE.match(ln)
        if m and m.group(1) not in _NOT_RAW:
            out |= _def_use(m.group(1), m.group(2) or "")[0]
    return out


_LABEL_LINE_RE = re.compile(r"\s*L_0x([0-9a-f]+):$")


def _drop_empty_note(out: list, at: int) -> None:
    """Drop the note at `out[at]` when nothing but labels follows it."""
    if all(_LABEL_LINE_RE.match(ln) for ln in out[at + 1:]):
        del out[at]
#: A declaration of a minted name, with or without an initialiser.
_PHI_DECL_RE = re.compile(r"\s*var (t\d+)\s*(?:=|;)")


_SET_RE = re.compile(r"\s*(?:var\s+)?(t\d+)\s*(?:;|=(?!=))")


def _never_read(lines: list, names) -> set:
    """Those of `names` that `lines` only declare or assign to."""
    read = set()
    for ln in lines:
        m = _SET_RE.match(ln)
        read.update(n for n in _TMP_RE.findall(ln[m.end():] if m else ln) if n in names)
    return set(names) - read


def _drop_unread(lines: list, names: set) -> list:
    """Leave out the declaration of each of `names` that nothing else in `lines` reads.

    _verbatim names a value where liveness says a register holding it is read again,
    and a raw line reads the machine register, not the name. A value whose only reader
    is another raw line, or `d0` at a `ret` that returns x0, gets a name nothing prints
    (#118). Reading a field or a register has no side effect to keep."""
    if not names:
        return lines
    counts: dict = {}
    for ln in lines:
        for m in _TMP_RE.finditer(ln):
            counts[m.group(0)] = counts.get(m.group(0), 0) + 1
    drop = {}                              # {line index: the name it declares}
    for i, ln in enumerate(lines):
        m = _DECL_RE.match(ln) or _BARE_DECL_RE.match(ln)
        if m and m.group(2) in names and counts[m.group(2)] == 1:
            drop[i] = m.group(2)
    if not drop:
        return lines
    # ...except where one is all its block holds. `_drop_unread_slots` and
    # `_drop_dead_phis` both carry this guard and say why: an `if` arm is the walk's to
    # render, and taking its only line prints `if (c) {` with `}` under it. Costing
    # nothing while this ran over `_verbatim`'s names alone, which are pinned beside the
    # line that needed them and so never stand alone in an arm, and costing 112 empty
    # blocks in 47 ranges of the clean build once it also runs over `_name_blind`'s,
    # where a declined reload can be the only thing an arm does (#198).
    #
    # Without `_drop_unread_slots`'s closure over what a kept initialiser reads, which it
    # needs because `_unread` is transitive and can mark a name whose only reader is
    # another name that also goes. The test here is `counts == 1`, so a name that goes
    # appears nowhere else in the body at all and no kept line can name it.
    keep, inside = set(), []               # the lines of each block still open
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("}") and inside:
            body = inside.pop()
            if body and all(j in drop for j in body):
                keep.update(drop[j] for j in body)
        elif inside:
            inside[-1].append(i)
        if s.endswith("{"):
            inside.append([])
    return [ln for i, ln in enumerate(lines) if i not in drop or drop[i] in keep]


def _one_term(text: str) -> bool:
    """True when `text` is one term and postfix: a name, a literal, `a.b`, `a[i]`, `f(x)`.

    Asked of what is there rather than of a list of operators, so an operator the
    precedence table does not hold still counts: `_BINOP_PREC` has no `/`, `>>>` or `%`,
    and a check against it folded `t0 = b / c` into `a / t0` as `a / b / c` (#64). Any
    space outside brackets, a sign or a bracket left open is more than one term."""
    depth = 0
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
            if depth < 0:
                return False
        elif ch == " " and depth == 0:
            return False
    return depth == 0 and bool(text) and text[0] not in "-~!"


def _unread(lines: list, names: set) -> set:
    """The slot names (#64) that nothing in `lines` reads but their own declaration.

    `_slot_crossings` decides from the instructions that a reload after a call is read,
    and the walk can still print that reload as something else: a loop exit or a join
    that forgets the slots, or a call that falls back to `(...)` for its arguments. The
    name is then declared and never used, a line that says nothing.

    Last line first, so a name read only by a declaration that goes is seen to go too:
    one pass, where a pass per name would cost lines times names."""
    if not names:
        return set()
    counts: dict = {}
    for ln in lines:
        for m in _TMP_RE.finditer(ln):
            counts[m.group(0)] = counts.get(m.group(0), 0) + 1
    out = set()
    for ln in reversed(lines):
        m = _DECL_RE.match(ln)
        if m and m.group(2) in names and counts.get(m.group(2)) == 1:
            out.add(m.group(2))
            for u in _TMP_RE.findall(m.group(3)):
                counts[u] -= 1
    return out


#: A call in a line: `name(`, `)(`, or a virtual/indirect call. Anything else a phi arm
#: binds, a field read or arithmetic, has no side effect to keep (#169). A width
#: conversion the lifter prints, `.toSigned(n)` or `.toUnsigned(n)` with a literal n, is
#: arithmetic too: read as a call, it kept a dead phi whose arm binds an untag or a
#: 32-bit result (#285). Anything else after those names is a call, `Foo.toSigned(x1)`.
_CALL_IN_LINE = re.compile(
    r"(?<=[\w\])])(?:(?<!\.toSigned)(?<!\.toUnsigned)\(|\((?!\d+\)))|\(dynamic call\)")


def _out_of_scope(lines: list, hits=None) -> set:
    """The minted names `lines` READ outside the scope their declaration is in.

    `_phi` declares its name at the level of the `if` it belongs to, which dominates the
    arms but not necessarily the reader: where that `if` is itself nested in an arm, the
    arm closes and the name is gone while a later line still reads it. Over the 3.12.2
    clean build that is 1,554 reads in 544 of 8,194 functions, each one a reference to
    something no longer declared (#198).

    Three things it deliberately does not count.

    A use inside the `   //` note a raw line carries is not a read: `_inline_single_use`
    refuses to fold into one for the same reason, and hoisting a declaration on the
    strength of a comment moved one name on the clean build for no reader at all.

    And `var t1;` at the top with the arms assigning it is the `_join_name` shape, which
    is already correct; only a declaration that has closed is reported.

    `hits`, a list if given, collects one (line index, name) per offending READ. The
    lifter wants the set; a census wants the count, and counting occurrences of the set
    afterwards is NOT the same thing, because a name can be in scope on one line and out
    on another. Both come from this one walk so neither can drift from the other, which
    four separate scripts of mine did, each reporting a number I had to withdraw (#198).

    Linear in the lines, not in lines times live names: the live set is a count per name,
    decremented when its scope pops, because both the line count and the nesting come
    from the input (CLAUDE.md puts resource exhaustion on hostile input first).
    """
    live: dict = {}
    scopes: list = [[]]
    bad = set()

    def pop():
        for n in scopes.pop():
            if live.get(n):
                live[n] -= 1
                if not live[n]:
                    del live[n]

    for i, ln in enumerate(lines):
        cut = ln.find("   //")
        t = (ln[:cut] if cut >= 0 else ln).strip()
        if t.startswith("}"):
            if len(scopes) > 1:
                pop()
            if t.endswith("{"):                       # `} else {`
                scopes.append([])
            continue
        m = _PHI_DECL_RE.match(t)
        if m:
            scopes[-1].append(m.group(1))
            live[m.group(1)] = live.get(m.group(1), 0) + 1
        for name in _TMP_RE.findall(t):
            if not (m and name == m.group(1)) and name not in live:
                bad.add(name)
                if hits is not None:
                    hits.append((i, name))
        if t.endswith("{"):
            scopes.append([])
    return bad


def _unbound(lines: list) -> set:
    """The `tN` names `lines` read where NO line of `lines` binds them, at any depth.

    Worse than `_out_of_scope`'s set, which at least leaves the reader a declaration to
    look at: this is not valid Dart at all, and it is what `tools/pbfuzz.py`'s `undecl`
    counts and requires to be zero (#205). Bound is read the same way the census reads it,
    `_SET_RE`, a declaration or an assignment, so the two cannot drift apart."""
    bound = {m.group(1) for m in (_SET_RE.match(ln) for ln in lines) if m}
    read = {n for ln in lines for n in _TMP_RE.findall(ln.split("   //")[0])}
    return read - bound


def _drop_dead_phis(lines: list, names: set) -> list:
    """Drop the declaration and assignments of each phi name in `names` nothing reads.

    `_phi` and `_render_loop` bind a name at a join or a loop header whenever the paths
    disagree about a register, before the body is printed and so before it is known
    whether anything goes on to read the result. Where nothing does, the declaration and
    the writes to it on each arm say nothing: a value computed into a name no reader
    wants, `var t10 = t1;` on an allocation slow path among them (#169).

    A phi's lines go together, declaration and every assignment, or the output would
    assign a name it never declares. They stay, whole, where dropping them would leave an
    if-arm or a loop body holding nothing else: the one line that an arm ran, which is the
    walk's to render, as `_drop_unread_slots` keeps a slot name. An assignment whose value
    makes a call is a side effect and is never dropped; a phi arm binds no call, so this
    only guards against one reaching here by another path."""
    if not names:
        return lines
    read, lhs_of = set(), {}
    for i, ln in enumerate(lines):
        m = _SET_RE.match(ln)
        read.update(_TMP_RE.findall(ln[m.end():] if m else ln))
        if m and m.group(1) in names:
            lhs_of[i] = m.group(1)
    dead = {n for n in names if n not in read}
    if not dead:
        return lines
    # A phi's lines go together: group them, and never drop a name any of whose lines
    # makes a call, or the kept call would reference a name no line declares.
    by_name = {}
    for i, n in lhs_of.items():
        if n in dead:
            by_name.setdefault(n, []).append(i)
    by_name = {n: idxs for n, idxs in by_name.items()
               if not any(_CALL_IN_LINE.search(lines[i]) for i in idxs)}
    drop_line = {i: n for n, idxs in by_name.items() for i in idxs}
    # Keep whole a phi any of whose lines is in a block that would otherwise empty. A
    # block holding a NESTED one would not empty, whatever happens to its own lines, and
    # counting it as empty kept a dead phi alive for nothing: the lines it collects are a
    # block's direct ones, so a parent whose body is one dead declaration plus an `if`
    # looked bare. That is invisible while a live declaration sits beside the dead one and
    # shows the moment anything moves the live one away (#198).
    keep, stack = set(), []
    for i, ln in enumerate(lines):
        s = ln.strip()
        opens, closes = s.endswith("{"), s.startswith("}")
        if closes and stack:
            body, nested = stack.pop()
            if body and not nested and all(j in drop_line for j in body):
                keep.update(drop_line[j] for j in body)
        if not opens and not closes and stack:
            stack[-1][0].append(i)
        if opens:
            if stack:
                stack[-1][1] = True
            stack.append([[], False])
    drop = {i for i, n in drop_line.items() if n not in keep}
    return [ln for i, ln in enumerate(lines) if i not in drop]


def _drop_unread_slots(lines: list, names: set) -> list:
    """`lines` without the declarations of the slot names nothing reads (#64; _unread).

    The `elif` below is deliberate and load-bearing: it appends a block-OPENING line to
    the parent's body, so a parent holding one unread declaration plus a nested `if` fails
    the all-dropped test on that `if` line and the declaration is dropped. Writing it as
    `_drop_dead_phis` does, skipping opens and closes, is what made that function call such
    a parent empty and keep a dead phi alive (#198).

    Except where an arm of an `if` holds nothing else: dropping those left the arm empty,
    `if (c) {} else {}` 21 times over the two fixtures and three corpus builds, and the
    arm is the walk's to render. So they stay, a line saying the arm read the field, and
    so does whatever they read. Lifting again with those stores unnamed was tried
    instead, and is wrong: both arms then hold the same field text, agree at the join,
    and a reload after a call prints the field again, the defect being fixed."""
    unread = _unread(lines, names)
    if not unread:
        return lines
    decl = {}                              # {line index: the name it declares}
    for i, ln in enumerate(lines):
        m = _DECL_RE.match(ln)
        if m and m.group(2) in unread:
            decl[i] = m.group(2)
    keep, inside = set(), []               # the lines of each block still open
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("}") and inside:
            body = inside.pop()
            if body and all(j in decl for j in body):
                keep.update(decl[j] for j in body)
        elif inside:
            inside[-1].append(i)
        if s.endswith("{"):
            inside.append([])
    init = {decl[i]: _DECL_RE.match(lines[i]).group(3) for i in decl}
    todo = list(keep)
    while todo:
        for used in _TMP_RE.findall(init[todo.pop()]):
            if used in init and used not in keep:
                keep.add(used)
                todo.append(used)
    return [ln for i, ln in enumerate(lines) if i not in decl or decl[i] in keep]


#: The note over the section at a Code's monomorphic entry, in place of cfg.UNREACHED,
#: where the snapshot says the code has one (#266). That is the low bit of the Code's
#: payload_info (app_snapshot.cc:8488-8489 at 3.12.2), and the deserializer puts the
#: entry a monomorphic call takes at the payload start plus kMonomorphicEntryOffsetAOT,
#: 8 on arm64, and `entry_point`, the normal entry, at kPolymorphicEntryOffsetAOT, 24
#: (app_snapshot.cc:9625-9644, object.h:5922-5923). MonomorphicCheckedEntryAOT
#: (assembler_arm64.cc:1941-1965) emits the miss handler at +0 and the class check at +8,
#: and falls through into +24. That function and both offsets read the same in all 19
#: releases jadart registers, 2.19.0-444.2.beta to 3.13.0.
#:
#: The section is lifted as the body it is (#278): the check and the normal entry each
#: root a dominator tree (Lifter.roots), so its loops and joins read as the same rows do
#: lifted from +8, and it starts from bare registers, at +8 and again at +24. A
#: switchable call enters +8 with the receiver in x0 and the class id it expects in x5
#: (flow_graph_compiler_arm64.cc:556-575), but +24 on is the normal entry's code too,
#: which MegamorphicCallStub enters with the target Function in x0, the entry address in
#: x1 and its cache in x5 (stub_code_compiler_arm64.cc:3643-3660, constants_arm64.h:148
#: and 151). Neither name, nor the entry's own `this` and `aN`, holds on every way in,
#: and none is printed.
MONOMORPHIC_ENTRY = ("reached by no edge in this graph: the monomorphic entry, which the "
                     "snapshot says this code has, 8 bytes in; its normal entry is 24 "
                     "bytes in")

#: The note on a goto out of a section no edge leads into back into the body above it
#: (Lifter.rejoined), where the block it lands on leads on: one that leads nowhere is
#: printed again under the section instead (`_ends_again`). The code past the label was
#: worked out for the body's ways in, and nothing says whether it holds for this one. A
#: monomorphic entry's body is such a body to the sections after it, and its own gotos
#: into the body above it take the note too (Lifter.rejoined_second, #278).
REJOIN = ("the names past that label were worked out for the ways in above it, not "
          "checked for this one")


def lift_function(ann: list, pool_map=None, receiver=None, arity=None,
                  indent="  ", depth=1, selectors=None, arch=None, fields=None,
                  show=None, cut_end=None, returns=None, allocs=None,
                  mono=None, casts=None) -> list:
    """Annotated disasm -> pseudo-Dart body lines (Tier 3). `receiver` is an optional
    register-alias map, e.g. {"x1": "this"} for an instance method; `arity` is an optional
    `pc -> int` resolver (see make_arity_resolver) enabling call-argument reconstruction;
    `selectors` maps a dispatch-call immediate to its source name (see dispatch.py);
    `fields` maps a byte offset to the receiver's field name at that offset (see
    fields.py); `allocs` is the AllocLayout of per-class allocation stubs from the same
    module, which names the class of an object this body allocates; `casts` is its
    CastLayout, which names the class of a value on the edges after a cast to a class
    every subtype of which extends it. Those are the bases a field name is printed off,
    and an unresolved base still prints its offset.
    `show` prints the operand of an instruction kept as it is, rebaser(image) from disasm
    so that an `adr` target reads as a virtual address; without it the operand is
    capstone's. `cut_end` is where the range ends when the instruction cut stopped `ann`
    short of it (disasm.cut_end); see build_cfg. `returns` is a `pc -> "x0" | "d0" |
    None` resolver (make_return_resolver) saying which register the function's callers
    read its result from, and, where none does, its `by_table` asks the other functions
    `selectors` places under the same selector; without it a `ret` is decided by the
    function's own code. `mono` is the address of the code's monomorphic entry where
    the snapshot says it has one (disasm.monomorphic_entry): the section placed there
    says so, and is lifted as a body from that entry; see MONOMORPHIC_ENTRY.

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
        try:
            return _lift_function(ann, pool_map, receiver, arity, indent, depth,
                                  selectors, fields, show, cut_end, returns, allocs,
                                  mono, casts, getattr(arch, "compressed", None))
        except RecursionError:
            # The structurer and the walk recurse once per level of nesting (#81); see
            # cfg.render_function. The caches hold parses only, and each lift builds its
            # own Lifter, so nothing a half-finished lift touched outlives it.
            return flat(ann, indent, depth, show=show, cut_end=cut_end)


@contextlib.contextmanager
def use_target(tgt: Target):
    """Bind the per-architecture tables for the duration of one lift.

    These are read by module-level helpers (`canon` is called from 49 places, several of
    them with no lifter in scope) so they are rebound rather than threaded. Rebinding the
    NAMES keeps every existing reader working unchanged, which is what makes it possible to
    add a second architecture without touching sixty call sites and hoping the first one
    still renders identically, and `export` on arm64 is byte-for-byte what it was.

    When the target actually changes, the caches have to go with it: `sp` canonicalises
    to x15 on one target and r13 on the other, so an entry made under one is wrong under
    the other. That is true of all
    three, not just `_CANON_CACHE`, `_MEM_CACHE` and `_DEFUSE_CACHE` store `canon()`
    results keyed on the operand STRING alone, so whichever target parsed a given string
    first would answer for both. Nothing catches it today because `LIFTABLE_ARCHS` admits
    only arm64, but a test already drives the lifter under ARM32 directly, and the day the
    gate opens the wrong register file is a silently wrong body.
    """
    global _T, ROLE, _SPECIAL, _UNTAGGED, ARG_REGS, _CALL_CLOBBERS, _RET_USES
    if tgt is _T:
        # Already bound. The caches are keyed on operand text and every entry in them was
        # made under this same target, so they are valid as they stand. Clearing them here
        # anyway is what made every lift start cold: measured over 400 functions the cache
        # was empty when the lifting was done, and the module had spent its memoisation
        # paying an O(cache) snapshot and restore per function for nothing. Only a change
        # of target invalidates anything, and that path is below.
        yield
        return
    prev = (_T, ROLE, _SPECIAL, _UNTAGGED, ARG_REGS, _CALL_CLOBBERS, _RET_USES,
            dict(_CANON_CACHE), dict(_MEM_CACHE), dict(_DEFUSE_CACHE),
            dict(_AF_ROW_CACHE))
    _T = tgt
    ROLE, _SPECIAL, _UNTAGGED = tgt.roles, set(tgt.special), tgt.untagged
    ARG_REGS = tgt.arg_regs
    _RET_USES = frozenset({tgt.ret_int, tgt.ret_fp})
    _CALL_CLOBBERS = (_A64_CLOBBERS if tgt is ARM64 else
                      # arm32: R0-R3 and R12 are AAPCS volatile, and Dart adds R9. The FPU
                      # side is D0-D7 (constants_arm.h kAbiVolatileFpuRegs). And LR.
                      frozenset({f"r{i}" for i in (0, 1, 2, 3, 9, 12, 14)}
                                | {f"d{i}" for i in range(8)}))
    _CANON_CACHE.clear()
    _MEM_CACHE.clear()
    _DEFUSE_CACHE.clear()
    _AF_ROW_CACHE.clear()
    try:
        yield
    finally:
        (_T, ROLE, _SPECIAL, _UNTAGGED, ARG_REGS, _CALL_CLOBBERS,
         _RET_USES, cache, mem, defuse, af_rows) = prev
        _CANON_CACHE.clear()
        _CANON_CACHE.update(cache)
        _MEM_CACHE.clear()
        _MEM_CACHE.update(mem)
        _DEFUSE_CACHE.clear()
        _DEFUSE_CACHE.update(defuse)
        _AF_ROW_CACHE.clear()
        _AF_ROW_CACHE.update(af_rows)


class Tier3Graph(NamedTuple):
    """One function's graph as tier 3 lifts it, and how `structure` places it."""
    stripped: list          # the rows after strip_boilerplate
    slow: frozenset         # the stack checks' slow paths it took the branch to
    blocks: dict
    entry: int
    raw: dict               # what it changed: the mnemonic and operands, by address
    cut: frozenset          # where the edges it took out led (_cut_edges)
    stmts: list             # structure(), with every block no edge reaches after the body
    roots: tuple = ()       # the proven entries no edge reaches (_proven_entries)
    second: frozenset = frozenset()     # what they reach and the entry does not
    trapped: frozenset = frozenset()    # the sections placed past a trap (cfg.past_trap)


#: How far past the monomorphic entry the normal entry is, on arm64:
#: kPolymorphicEntryOffsetAOT less kMonomorphicEntryOffsetAOT, 24 less 8
#: (object.h:5922-5923 at 3.12.2, and the same in every release from 2.19.0-444.2.beta
#: to 3.13.0). MonomorphicCheckedEntryAOT emits the class check between them and falls
#: through into the normal entry (assembler_arm64.cc:1953-1962 at 3.12.2).
_NORMAL_PAST_MONO = 16


def _proven_entries(blocks, mono, placed) -> tuple:
    """(the monomorphic entry, the normal entry) where the snapshot says the code has one
    and the graph has the shape MonomorphicCheckedEntryAOT emits (cfg.checks_into): a
    check at `mono` that branches back to the miss handler in `placed` and falls into a
    block 16 bytes on. Anything else gets none, and its section is lifted as one nothing
    reaches, from bare registers, as before #278. A looser test let a check that also
    branched into the body dominate code the callers enter at +24 without it, and the
    meet there kept a value only the check had set."""
    if mono is None or not checks_into(blocks, mono, mono + _NORMAL_PAST_MONO, placed):
        return ()
    return mono, mono + _NORMAL_PAST_MONO


def tier3_graph(ann, cut_end=None, mono=None):
    """The Tier3Graph of the annotated rows `ann`, or None where they make no block.
    `_lift_function` lifts it and tools/cfgcheck.py checks it, so both see one graph.
    `mono` is the code's monomorphic entry, as lift_function takes it."""
    slow = set()
    stripped = strip_boilerplate(ann, slow)
    # Tier 3 honours traps, the rule tier 2 took in #57: a block ends at a `brk`/`udf`
    # with no edge past it. The false edge used to drop a join that, by accident, kept a
    # frame slot from reading as the field it was loaded from; naming frame slots across
    # a call (`Lifter._slot_crossings`) now covers that, so `forEach`'s concurrent
    # modification guard no longer prints `this.field_0xc != this.field_0xc` (#64).
    # A call to a stub that throws ends its block the same way, and nothing in a `bl`
    # says so, which is why the addresses are handed over (#234).
    blocks, entry = build_cfg(stripped, traps=TRAPS, cut_end=cut_end,
                              ends=_path_ends(stripped))
    if not blocks:
        return None
    raw = {t[0]: t[1:3] for t, s in zip(ann, stripped) if s[1:3] != t[1:3]}
    _fold_frame_offsets(blocks, entry, raw)
    # Every block, as tier 2 places them (#67): what no edge reaches goes after the body,
    # each section under a note. Placing only what the entry reaches dropped the body
    # behind a monomorphic entry and the catch entries after a `ret` or a `b` without a
    # word (#266). What strip_boilerplate cut off on purpose stays out, since an edge
    # does reach it in the machine: a stack check's slow path, and the slow path that
    # boxes a Mint.
    cut = frozenset(to for tos in _cut_edges(blocks, raw).values() for to in tos)
    # A monomorphic entry is placed and structured as the body it is, from its own
    # entry (#278); see structure's `entries`.
    placed = entry_reach(blocks, entry)
    roots = _proven_entries(blocks, mono, placed)
    second = second_reach(blocks, placed, roots)
    if not second:
        roots = ()
    if roots:
        # Nor does a branch alone at one, or in a chain of lone branches it falls into,
        # read the flags the check left: the callers come in there too. Each lone branch
        # gets back its own condition, as build_cfg gave it, and the chains are followed
        # again, stopping at the entries.
        for blk in blocks.values():
            if len(blk.insns) == 1 and blk.cond and not blk.cexit:
                blk.cond = _cond_for([], blk.insns[0][1], blk.insns[0][2])
        _conditions_from_the_block_before(blocks, stop=frozenset(roots))
    stmts = structure(blocks, entry, orphans=True, cut=cut, entries=roots, rest=True)
    if stmts and stmts[-1][0] == "rest":
        stmts[-1] = ("rest", _rest_sections(blocks, stmts[-1][1], ann, cut, mono))
    trapped = past_trap(blocks, entry, placed, cut)
    return Tier3Graph(stripped, frozenset(slow), blocks, entry, raw, cut,
                      _ends_again(blocks, stmts, placed, second, trapped), roots, second,
                      trapped)


def _rest_sections(blocks, left, ann, cut, mono) -> tuple:
    """The blocks `structure` left when a section no edge reaches was nested too deeply
    for it, `left` in the order it would have placed them (#284), as the sections it
    would have placed them in: each block no earlier one took starts one, with what it
    reaches among the rest, under the note `structure` gives it (MONOMORPHIC_ENTRY at the
    monomorphic entry `mono`), and with its rows as they are in `ann`, by address:
    ((note or None, ((block, rows, cut_next), ...)), ...). Each block is taken once, so
    this is linear in the rows."""
    rest = set(left)
    targeted = {s for b in blocks.values() for s in b.succ} | set(cut)
    row = {r[0]: r for r in ann}
    out, taken = [], set()
    for a in left:
        if a in taken:
            continue
        group, stack = [], [a]
        while stack:
            n = stack.pop()
            if n in taken or n not in rest:
                continue
            taken.add(n)
            group.append(n)
            stack.extend(blocks[n].succ)
        note = None if a in targeted else MONOMORPHIC_ENTRY if a == mono else UNREACHED
        out.append((note, tuple((b, tuple(row[i[0]] for i in blocks[b].insns),
                                 blocks[b].cut_next) for b in sorted(group))))
    return tuple(out)


def _ends_again(blocks, stmts, placed, second=frozenset(), trapped=frozenset()) -> list:
    """`stmts` with each goto out of a section no edge leads into, to a block of the body
    that leads nowhere, a return, a throw or a jump out, made `("again", block)`: that
    block printed once more under the section, and lifted from the section's own state,
    with the exit or cut the body prints after it.

    Read on from a goto, the block's lines are worked out for the body's ways in, and
    the section's way in had nothing to do with them: `invokeCallback` on the clean
    fixture went on to `return t2;`, the callback's result, from a catch entry that
    leaves null in x0, and every monomorphic entry ended in a goto to the miss handler
    (#266). Printed again, the block says what this way in does there, and nothing
    follows it to read on into. A block with a successor is left a goto: copying it
    would copy what it leads to as well.

    `second` is the body a proven entry has (Tier3Graph.second), placed first among the
    sections and lifted as a body. A goto inside it to a block of its own is a goto of
    that body; one out of it to a block of `placed`, the miss handler a monomorphic
    check branches back to, is copied as from any section; and a section after it
    treats its blocks as it treats `placed`'s (#278).

    `trapped` are the sections `structure` places past a trap, among the body's
    (cfg.past_trap). Each is one no edge leads into, as one after the body is, and a goto
    out of it to a block of the body is copied the same way. Left a goto, a catch entry
    past a `brk` read on into the body's `return this.field_0x8 + 1;` where its own way in
    returns 10 (#283). One to another such section is a goto between sections, as one
    between the sections after the body is."""
    above, body = placed | second, placed - trapped

    def copy(ss, into):
        out = []
        for s in ss:
            if s[0] == "goto" and s[1] in into and not blocks[s[1]].succ:
                blk = blocks[s[1]]
                out.append(("again", s[1]))
                if blk.exit_target >= 0:
                    out.append(("cut" if blk.past_cut else "exit", blk.exit_target))
                elif blk.cut_next >= 0:
                    out.append(("cut", blk.cut_next))
            elif s[0] == "if":
                out.append(("if", s[1], copy(s[2], into), copy(s[3], into)))
            elif s[0] == "loop":
                out.append(("loop", s[1], copy(s[2], into)))
            else:
                out.append(s)
        return out
    out, into = [], None
    for s in stmts:
        if s[0] == "label":
            into = (body if s[1] in trapped else None if s[1] in placed
                    else placed if s[1] in second else above)
        out.extend(copy([s], into) if into is not None else (s,))
    return out


def _lift_function(ann, pool_map, receiver, arity, indent, depth, selectors,
                   fields=None, show=None, cut_end=None, returns=None,
                   allocs=None, mono=None, casts=None, compressed=None) -> list:
    g = tier3_graph(ann, cut_end, mono)
    if g is None:
        return []
    stripped, slow, blocks, entry, raw, stmts = (g.stripped, g.slow, g.blocks, g.entry,
                                                 g.raw, g.stmts)
    second, trapped = g.second, g.trapped
    # The sections no edge leads into start at the first label `structure` placed past
    # what the entry reaches, under its note, and those past a trap are among the body's.
    placed = entry_reach(blocks, entry)
    tail = next((i for i, s in enumerate(stmts)
                 if s[0] == "label" and s[1] not in placed), len(stmts))
    if tail and stmts[tail - 1][0] == "note":
        tail -= 1
    for i in range(len(stmts) - 1):
        if stmts[i] == ("note", UNREACHED) and stmts[i + 1] == ("label", mono):
            stmts[i] = ("note", MONOMORPHIC_ENTRY)
    labels = label_targets(stmts)
    # The body a proven entry has comes first among the sections (#278), and a goto in
    # it is one of its own ways in, as one in the body is. A goto into it from a section
    # after it is not, as one from a section into the body is not.
    end = next((i for i in range(tail, len(stmts)) if stmts[i][0] == "label"
                and stmts[i][1] not in placed and stmts[i][1] not in second), len(stmts))
    if end > tail and stmts[end - 1][0] == "note":
        end -= 1
    # A section past a trap is placed among the body's, and a goto out of it into the
    # body is no more a way in the walk meets than one from after the body is; one to
    # another such section is, as one between the sections after the body is (#283).
    ours, past = [], []
    into = ours
    for s in stmts[:tail]:
        if s[0] == "label":
            into = past if s[1] in trapped else ours
        into.append(s)
    joinable = frozenset(label_targets(ours) | (label_targets(past) & trapped)
                         | (label_targets(stmts[tail:end]) & second)
                         | {a for a in labels if a not in placed and a not in second})
    orphans = frozenset(s[1] for s in stmts[tail:] if s[0] == "label")
    if trapped:
        orphans |= {s[1] for s in stmts[:tail] if s[0] == "label" and s[1] in trapped}
    # The blocks before the sections that a block of one jumps to, and those of the body
    # a goto out of the proven entry's body jumps to.
    unreached = set(blocks) - placed
    dead = unreached - second
    rejoined = frozenset(t for b in dead - cut_off(blocks, unreached, g.cut)
                         for t in blocks[b].succ if t in placed or t in second)
    rejoined_second = frozenset(t for b in second for t in blocks[b].succ if t in placed)
    rejoined_trap = frozenset(t for b in trapped for t in blocks[b].succ
                              if t in placed and t not in trapped)
    dispatch = detect_dispatch(stripped)
    fp_lost = _fp_lost_at(blocks, raw)
    meets, moves, joins, cross, spat, fpat, wrote = _frame_plan(blocks, entry, raw,
                                                                fp_lost)
    # Every row a value naming a frame register is looked at before: the ones that
    # write one, and the ones `_frame_plan` starts a frame at.
    shift_rows = {a: (False, 0) for a in moves.keys() - wrote.keys()}
    shift_rows.update(wrote)
    save_wrapped = _save_wrapped_calls(stripped)
    cast_at = {}
    if casts is not None and casts.pool:
        from .fields import cast_accesses
        cast_at = cast_accesses(blocks, entry, casts, cross, moves, joins,
                                slow=slow, raw=raw)

    data, elem_box = _data_offsets(compressed), {}

    def walk(keep, carry=None, join_phi=None, printed_prior=None, hoist=None):
        lifter = Lifter(blocks, pool_map=pool_map, receiver=receiver, arity=arity,
                        dispatch=dispatch, selectors=selectors, entry=entry,
                        fields=fields, allocs=allocs, casts=cast_at)
        lifter.data_offsets, lifter._elem_box = data, elem_box
        lifter.show = show
        lifter.slow_paths = frozenset(slow)
        lifter.frame_meets = meets
        lifter.frame_moves = moves
        lifter.save_wrapped = save_wrapped
        lifter.frame_joins = joins
        lifter.frame_cross = cross
        lifter.sp_at = spat
        lifter.fp_at = fpat
        lifter.shift_rows = shift_rows
        lifter._fp_leaf = None if fpat is None else lifter._fp_reg
        lifter.raw = raw
        lifter._fp_lost_set = fp_lost
        lifter.fp_moves = frozenset(a for a, (fp, _d) in moves.items() if fp)
        if returns is not None:
            lifter.returns = lambda: returns(ann[0][0])
            lifter.callees = returns
            by_table = getattr(returns, "by_table", None)
            if by_table is not None and selectors:
                lifter.table = lambda: by_table(ann[0][0], selectors)
        lifter.labels = labels
        lifter.joinable, lifter.orphans, lifter.rejoined = joinable, orphans, rejoined
        lifter.roots, lifter.placed, lifter.second = g.roots, frozenset(placed), second
        lifter.rejoined_second, lifter.rejoined_trap = rejoined_second, rejoined_trap
        lifter.keep = keep
        lifter.carry_more = carry or {}
        lifter.join_phi = join_phi or {}
        lifter.printed_prior = printed_prior or frozenset()
        lifter.hoist = hoist or frozenset()
        st = State()
        # `State.set` mints a name for a value too long to inline, and it is the one such
        # site outside `_mint`. Sharing these makes those names hoistable too.
        st.hoist, st.spilled, st.hoisted = lifter.hoist, lifter.spilled, lifter.hoisted
        lines, _falls = lifter.walk(stmts, st, indent, depth)
        return lifter, lines

    lifter, lines = walk(None)
    keep = None
    if lifter.pins:
        # Which of the values `_arrive` wrote out the body goes on to read is only known
        # once the body is printed. One nothing read still took a temporary's number, so
        # the walk runs again writing out only those that were read, and every other name
        # is numbered as it would have been without them.
        counts: dict = {}
        for ln in lines:
            for m in _TMP_RE.finditer(ln):
                counts[m.group(0)] = counts.get(m.group(0), 0) + 1
        read = frozenset(at for n, at in lifter.pins.items() if counts.get(n, 0) > 1)
        if len(read) < len(lifter.pins):
            keep = read
    # ...and which registers a loop has to carry out past a printed write (#123). One the
    # body never prints a write to reads as its value from before, which is a decline.
    printed = _printed_writes(lines)
    # ...and whether a slot value `_reload` spelled names a register the printed body
    # assigns somewhere the growing set could not have seen yet (#199). Only then is the
    # extra walk worth it, so this reuses the set the carry already needs. One walk is
    # enough: both walks print the same raw lines and the same write-backs, since those
    # come from the instructions, and every statement a later walk adds assigns a `tN`.
    printed_prior = frozenset(lifter.spelled_regs & printed) or None
    # ...and which phi names are read outside the scope `_phi` declared them in, which
    # only the printed body can say (#198). Their declaration moves to the top, where it
    # dominates every read, and the initialiser stays where the value was.
    # ...and which phi names are read outside the scope `_phi` declared them in (#198).
    # Decided on the lines as they will SHIP, after the passes that drop what nothing
    # reads: deciding on the raw walk hoisted declarations whose only reader was a line
    # about to be dropped, and left 11 functions with a top-of-body `var tN;` nothing
    # reads. Only names `_phi` minted, because only `_phi` acts on the set.
    def wants_hoist(lf, body):
        """The names `_phi` minted that `body` reads out of scope, judged on the lines as
        they will SHIP: deciding on the raw walk hoists for readers a later pass drops.
        The view it judges has no top declarations yet, so every already-hoisted name
        reads as undeclared in it and this always re-reports the whole current set. The
        caller's loop therefore has to test for GROWTH rather than for emptiness.

        EVERY name `_mint` handed out, not just the two kinds that used to be hoistable:
        a name any other site minted and a later line read outside its block was a read of
        something undeclared, 164 of them in 115 ranges (#204). `phi_minted` stays in the
        union because `_phi` mints its own, outside `_mint`."""
        shipped_body = _inline_single_use(
            _drop_dead_phis(_drop_unread_slots(
                _drop_unread(body, lf.raw_names | lf.blind_named), lf.slot_names),
                lf.phi_names),
            lf.results | lf.slot_names, lf.slot_names)
        return frozenset(_out_of_scope(shipped_body)
                         & (lf.minted | lf.phi_minted | lf.spilled))

    hoist = wants_hoist(lifter, lines) or None
    carry = {h: frozenset(r & printed) for h, r in lifter.exit_hazards.items()
             if r & printed}
    # ...and which registers a goto-reached join needs a phi for (#123). Only ones a loop
    # carries past it: a killed register nothing carried is genuinely lost, and naming it
    # would claim a value no path has. See _join_write.
    carried_regs = frozenset().union(*carry.values()) if carry else frozenset()
    join_phi = {j: frozenset(rs & carried_regs)
                for j, rs in lifter._join_phi_set.items() if rs & carried_regs}
    if keep is not None or carry or join_phi or printed_prior or hoist:
        lifter = lines = None               # not held while the second walk runs
        lifter, lines = walk(keep, carry, join_phi, printed_prior, hoist)
        # A name the code after the loop does not print, its only reader a call that
        # prints `(...)`, says nothing, and the walk goes back to the bare register.
        unread = {h: frozenset(names[n] for n in _never_read(lines, names))
                  for h, names in lifter.carry_names.items()}
        if any(unread.values()):
            carry = {h: r - unread.get(h, frozenset()) for h, r in carry.items()}
            carry = {h: r for h, r in carry.items() if r}
            lifter = lines = None
            lifter, lines = walk(keep, carry, join_phi, printed_prior, hoist)
        # A goto-join phi nothing reads says nothing, and minting its name shifted every
        # later temp for a line then dropped. The walk runs once more without the joins
        # whose names went unread, so those numbers go back and only a join a reader
        # wants changes the output.
        if join_phi:
            dead = _never_read(lines, set(lifter._join_name.values()))
            if dead:
                drop = {k for k, n in lifter._join_name.items() if n in dead}
                join_phi = {j: frozenset(r for r in rs if (j, r) not in drop)
                            for j, rs in join_phi.items()}
                join_phi = {j: rs for j, rs in join_phi.items() if rs}
                lifter = lines = None
                lifter, lines = walk(keep, carry, join_phi, printed_prior, hoist)
    # A goto-join phi is declared once, above the body, since no single edge into the
    # join dominates it; `_drop_dead_phis` drops the ones nothing read.
    # Hoisting changes the lines, so a name that was in scope may now not be. Measured on
    # both fixtures this settles in ONE more round: of the functions that reach here, all
    # but about thirty want nothing further and none wants a third pass. Bounded anyway,
    # because the bound is the only thing standing between a pathological body and a loop.
    for _ in range(4):
        more = wants_hoist(lifter, lines)
        if not more or more <= (hoist or frozenset()):
            break
        hoist = frozenset((hoist or frozenset()) | more)
        lifter = lines = None
        lifter, lines = walk(keep, carry, join_phi, printed_prior, hoist)
    top = set(lifter._join_name.values()) | lifter.hoisted
    if top:
        pad = indent * depth
        decls = [f"{pad}var {n};" for n in sorted(top, key=lambda n: int(n[1:]))]
        lines = decls + lines
    # `blind_named` too: a declined reload is named where liveness says the register is
    # read again, and 2,192 such reads shipped as a declaration nothing reads over the
    # clean build without this (#198).
    lines = _drop_unread_slots(
        _drop_unread(lines, lifter.raw_names | lifter.blind_named), lifter.slot_names)
    lines = _drop_dead_phis(lines, lifter.phi_names)
    lines = _inline_single_use(lines, lifter.results | lifter.slot_names,
                               lifter.slot_names)
    # And once more, for those names only. Each pass above can delete the last READER of
    # a name, which leaves the declaration behind: 417 frame reads shipped unread for
    # that reason, every one of them a line the first call would have taken had it run
    # after. Restricted to `blind_named` on purpose. The other emitters' names have the
    # same pass-order limit, 3,878 of them on the clean build, and taking those too is a
    # far wider changed answer than this one concern.
    out = _drop_unread(lines, lifter.blind_named)
    # Last resort, and for the invariant rather than for the shape. A name the shipped
    # body READS and binds nowhere is not Dart and leaves the reader nothing to look at,
    # which is why `undecl` has to be 0 (#205). `wants_hoist` fixes the ones it can: a
    # name `_mint`, `_phi` or `State.set` handed out in the walk that ships gets its
    # declaration moved to the top. One range of each fixture reaches here instead,
    # holding a name a trial walk minted and the walk that shipped did not, so there is no
    # assignment left to hoist to. Declaring it says `a value this lifter does not know`,
    # which is what an initialiser-less declaration means everywhere else in this file.
    missing = _unbound(out)
    if missing:
        pad = indent * depth
        out = [f"{pad}var {n};" for n in sorted(missing, key=lambda n: int(n[1:]))] + out
    return out
