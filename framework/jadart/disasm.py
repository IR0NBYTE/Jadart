"""Tier 1 foundation: Instructions image + per-function ARM64 disassembly (jadart).

Maps a recovered Function to its Code object's byte range in the instructions image
(via the InstructionsTable rodata) and disassembles it with capstone, annotating
ObjectPool loads (PP/X27-relative) and direct BL call targets with recovered names.
This is the first Tier 1 step. The result is annotated disassembly, which no current
tool produces (unflutter et al. stop at raw BL offsets).

InstructionsTable layout (unflutter instrtable.go, app_snapshot.cc image_snapshot):
the table is a OneByteString object in the isolate DATA image at
roundUp(header.length, 64) + instr_table_rodata_offset; skip its 16-byte header to
reach {canon u32, length u32, first_entry_with_code u32, pad u32} then `length`
DataEntry {pc_offset u32, stackmap_offset u32}. Code cluster-index i maps to entry
first_entry_with_code + i; pc_offset is the byte offset into the instructions image.
"""
from __future__ import annotations

from .errors import JadartError

import bisect
import re
import struct
from dataclasses import dataclass

try:
    from capstone import (Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM,
                          CS_MODE_LITTLE_ENDIAN)
    _HAVE_CAPSTONE = True
    _CAPSTONE_IMPORT_ERROR = None
except Exception as exc:                       # noqa: BLE001 - reported, not swallowed
    # Kept, and reported by MissingDisassembler. Discarding it told a user who HAD
    # installed capstone to install capstone, when the real cause was an ABI mismatch in
    # the bundled libcapstone, ten minutes to find something the exception already said.
    _HAVE_CAPSTONE = False
    _CAPSTONE_IMPORT_ERROR = exc

from .macho import open_container
from .fill import printable
from .stream import ReadStream
from . import versions


SNAPSHOT_MAGIC_SIZE = 4      # Snapshot::kMagicSize; excluded from the stored length

#: One decoder for the process. Opening a capstone handle is a cs_open/cs_close pair and
#: `export` disassembles 8,194 ranges, so it was paying for 8,194 of them. The handle is
#: stateless for our purposes: every decode call allocates its own instruction array, and
#: nothing here is threaded.
_MD: dict = {}
#: Whether this capstone build exposes disasm_lite. A diet build does not (it has no
#: mnemonic or operand strings to hand back), and there the object-building path is the
#: only one, so the fast path is probed once rather than assumed.
_HAVE_LITE = False

#: Instruction sets this file can decode, by the architecture name in the features string.
#: `arm` is ARM mode, not Thumb: Dart's arm32 AOT backend emits A32 throughout
#: (assembler_arm.cc), and asking capstone for Thumb turns that into plausible nonsense
#: rather than failing, 13 decoded instructions where 18 exist, none of them the code
#: that is there. Probe rather than assume was cheap: the same 72 bytes decode as coherent
#: Dart in ARM mode and as unrelated branches in Thumb.
_DECODERS = {
    "arm64": (lambda: CS_ARCH_ARM64, lambda: CS_MODE_LITTLE_ENDIAN,
              b"\x00\x00\x80\xd2"),                            # mov x0, #0
    "arm":   (lambda: CS_ARCH_ARM, lambda: CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN,
              b"\x00\x00\xa0\xe3"),                            # mov r0, #0
}


def _decoder(arch_name: str = "arm64"):
    """The decoder for one instruction set, opened on first use.

    One handle per architecture rather than per call: opening a capstone handle is a
    cs_open/cs_close pair and `export` disassembles thousands of ranges.
    """
    global _HAVE_LITE
    md = _MD.get(arch_name)
    if md is None:
        arch, mode, probe = _DECODERS[arch_name]
        md = _MD[arch_name] = Cs(arch(), mode())
        try:
            next(md.disasm_lite(probe, 0), None)
            _HAVE_LITE = True
        except Exception:
            _HAVE_LITE = False
    return md


def _round_up(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


@dataclass
class CodeRange:
    pc_offset: int
    size: int
    owner_ref: int


def _string_header_size(word: int, slot: int) -> int:
    """Bytes from a heap String's start to its character data, for one target.

    tags_ is one machine word. The hash is a field of its own only when
    HASH_IN_OBJECT_HEADER is undefined, which globals.h ties to 32-bit; on 64-bit it lives
    in the spare upper half of the tags word. Then a Smi length, one pointer slot wide.
    The whole thing is rounded up to a word because that is where the object's data starts,
    and it is that rounding (not the field widths) that makes a 64-bit compressed
    header 16 bytes rather than the 12 its fields occupy."""
    fields = word + (0 if word == 8 else slot) + slot
    return (fields + word - 1) & ~(word - 1)


def parse_instructions_table(data: bytes, header_length: int, itro: int,
                            arch=None) -> tuple[list[int], int]:
    """Return (pc_offsets, first_entry_with_code). pc_offsets[i] is the instruction
    offset for instructions-table entry i (image-base relative).

    The table rides inside a OneByteString in the data image, so the offset to its payload
    is that object's header, which is target-shaped: `[tags+hash 8][length 8]` on 64-bit,
    where HASH_IN_OBJECT_HEADER puts the hash in the spare half of the tags word, against
    `[tags 4][hash 4][length 4]` on 32-bit. Everything after the header is identical,
    the same four-word preamble and the same eight-byte entries, so only this offset
    varies, and getting it wrong reads a length of zero rather than failing."""
    word = arch.word_size if arch else 8
    slot = arch.compressed_word_size if arch else 8
    str_header = _string_header_size(word, slot)
    di_start = _round_up(header_length, 64)          # data image alignment (>= 2.19)
    payload = di_start + itro + str_header
    _canon, length, first_code, _pad = struct.unpack_from("<IIII", data, payload)
    off = payload + 16
    pcs = [struct.unpack_from("<I", data, off + i * 8)[0] for i in range(length)]
    return pcs, first_code


class MissingDisassembler(JadartError):
    """capstone is not installed. It is an optional extra because the snapshot layer does
    not need it, so this is a normal thing for a user to hit rather than a broken install."""


class UnsupportedArch(JadartError):
    """The snapshot parsed, but its instructions are for an architecture the decoder does
    not model. Separate from a parse failure: everything that does not come from machine
    code is still available."""


@dataclass
class InstrImage:
    text: bytes             # the instructions image bytes
    pcs: list               # pc_offsets by table index
    first_code: int
    code_ranges: dict       # owner_ref -> CodeRange (named function -> its code)
    all_ranges: list        # CodeRange per table entry, pc-sorted (full-image coverage,
                            # incl. --obfuscate-discarded codes with no recovered owner)
    symbol_names: dict = None  # pc_offset -> qualified name from the ELF .symtab, when the
                               # .so still carries one (dwarf_stack_traces_mode builds)
    data: bytes = b""          # the isolate snapshot DATA blob (the serialized stream),
                               # kept so later passes (dispatch.py) need not re-read the ELF
    data_length: int = 0       # header.length: where the serialized stream ends
    arch: object = None        # the resolved target; the decoder below is arm64-only and
                               # has to know when it is not looking at arm64


def load_instructions(path: str):
    """Parse the isolate instructions image + table and build owner_ref -> CodeRange.
    Returns (image, fr, hdr): the InstrImage, the FillResult from walk_fill, and the
    parsed snapshot header."""
    from .snapshot import parse_blob
    from .clusters import walk_alloc
    from .fillwalk import walk_fill

    raw = open(path, "rb").read()
    elf = open_container(raw)
    data = elf.symbol_bytes("_kDartIsolateSnapshotData")
    text = elf.symbol_bytes("_kDartIsolateSnapshotInstructions")
    hdr = parse_blob(data, "isolate", strict=True)
    # Snapshot::length() is the STORED int64 plus kMagicSize: the magic is excluded from the
    # written size (snapshot.h "Excluding the magic value from the size written in the buffer").
    # Rounding the raw stored value instead lands the data image 64 bytes early whenever
    # stored % 64 is 0 or 61..63, which is ~6.25% of builds, including the x86_64 corpus.
    header_length = struct.unpack_from("<q", data, 4)[0] + SNAPSHOT_MAGIC_SIZE

    st = ReadStream(data, 52)
    st.read_cstring()
    for _ in range(5):
        st.read_unsigned()
    clusters = walk_alloc(st, hdr.num_base_objects, hdr.num_objects, hdr.num_clusters,
                          epoch=hdr.epoch, is_root_unit=True, arch=hdr.arch)
    fr = walk_fill(st, clusters, hdr.epoch, arch=hdr.arch)

    pcs, first_code = parse_instructions_table(data, header_length,
                                               hdr.instr_table_rodata_offset, hdr.arch)

    # Function sizes are the gap to the NEXT table entry, across ALL entries, not just
    # the ones whose Code object we recovered. Using only retained entries made each
    # size overrun through the intervening (e.g. --obfuscate-discarded) functions.
    img_end = len(text)
    boundaries = sorted(set(pcs))

    def next_boundary(pc: int) -> int:
        i = bisect.bisect_right(boundaries, pc)
        return boundaries[i] if i < len(boundaries) else img_end

    # named ranges: owner_ref -> CodeRange (for disassemble-by-function)
    owner_by_slot = {}
    ranges = {}
    for ref, owner_ref, ci in fr.codes:
        slot = first_code + ci
        if 0 <= slot < len(pcs):
            owner_by_slot[slot] = owner_ref
            pc = pcs[slot]
            ranges[owner_ref] = CodeRange(pc_offset=pc, size=next_boundary(pc) - pc,
                                          owner_ref=owner_ref)

    # full-image coverage: one range per table entry across the WHOLE table, not just
    # the [first_code, length) slots that still own a Code object. On obfuscated builds
    # the leading entries [0, first_code) are the discarded functions. Their names are
    # gone but their instructions remain, and they hold the bulk of the image. Skipping
    # them (as disassembling only recovered owners does) collapsed coverage to ~4%.
    all_ranges = []
    for slot in range(len(pcs)):
        pc = pcs[slot]
        size = next_boundary(pc) - pc
        if size > 0:
            all_ranges.append(CodeRange(pc_offset=pc, size=size,
                                        owner_ref=owner_by_slot.get(slot, -1)))
    all_ranges.sort(key=lambda cr: cr.pc_offset)

    # backfill real names from the ELF symbol table, if present (dwarf_stack_traces_mode)
    from .symbols import pc_name_map
    symbol_names = pc_name_map(elf, len(text))

    return InstrImage(text=text, pcs=pcs, first_code=first_code, code_ranges=ranges,
                      all_ranges=all_ranges, symbol_names=symbol_names,
                      data=data, data_length=header_length, arch=hdr.arch), fr, hdr


# One cap for every path into the disassembler. `decompile` and `export` used to pass a
# separate, much smaller one, so the same function came back whole from `lift` and cut off
# at 200 instructions from the other two, with nothing in the output saying so.
MAX_INSNS = 4000


def truncated_by(cr: CodeRange, dis, max_insns: int = MAX_INSNS) -> int:
    """How many instructions of `cr` the cap left out, or 0 when nothing was cut.

    Only reports a cut when the cap was actually reached: a range can also come back short
    because capstone stopped on bytes it could not decode, which is a different thing and
    not something to announce as truncation.
    """
    if len(dis) < max_insns:
        return 0
    return max(0, (cr.size or 0) // 4 - len(dis))


def disassemble_range(image: InstrImage, cr: CodeRange, max_insns: int = MAX_INSNS):
    """Disassemble one CodeRange (used for full-image coverage, incl. anonymous
    obfuscation-discarded functions where owner_ref is -1)."""
    if not _HAVE_CAPSTONE:
        # The import error, when there was one. "install capstone" is the wrong advice for
        # a user who installed it and hit an ABI mismatch, and the exception already knew.
        why = (f"\n  the import failed with: {_CAPSTONE_IMPORT_ERROR!r}"
               if _CAPSTONE_IMPORT_ERROR is not None else "")
        raise MissingDisassembler(
            "reading instructions needs capstone, which is an optional extra because "
            "the snapshot layer does not use it.\n"
            "  install it with:  pip install 'jadart[disasm]'   (or: pip install capstone)\n"
            "  without it:       info, classes, libraries, strings and verify all work"
            + why)
    arch = getattr(image, "arch", None)
    arch_name = arch.name if arch is not None else "arm64"
    if arch_name not in _DECODERS:
        # Decoding one instruction set as another does not fail, it produces confident
        # nonsense, and expressions lifted from it. The snapshot layer is
        # target-independent and works here; the machine-code layer is not.
        raise UnsupportedArch(
            f"instruction decoding is implemented for "
            f"{' and '.join(sorted(_DECODERS))}, and this snapshot is "
            f"{arch_name}. Its structure still reads: classes, libraries, strings and "
            f"selectors come from the snapshot rather than from the code.")
    size = cr.size or 512
    code = image.text[cr.pc_offset:cr.pc_offset + size]
    md = _decoder(arch_name)
    if _HAVE_LITE:
        # disasm_lite yields (address, size, mnemonic, op_str) straight out of the C
        # array. `disasm` builds a full CsInsn per instruction instead, and this walks
        # the whole image: 457,622 instructions on the clean corpus binary, of which the
        # lifter reads exactly the three fields below and never the operand detail. Same
        # tuples, measured identical over all 457,622; 1.93x faster to produce them.
        return [(a, mn, op)
                for (a, _sz, mn, op) in md.disasm_lite(code, cr.pc_offset, max_insns)]
    out = []
    for insn in md.disasm(code, cr.pc_offset):
        out.append((insn.address, insn.mnemonic, insn.op_str))
        if len(out) >= max_insns:
            break
    return out


def disassemble_function(image: InstrImage, func_ref: int, max_insns: int = MAX_INSNS):
    """Disassemble the code owned by func_ref. Returns a list of (addr, mnemonic, op_str).

    The cap matters more than it looks: the CFG is built from whatever comes back, so a
    truncated list does not merely lose the tail, branches into the missing part fall out
    of range and the recovered structure is different too. Callers that render should ask
    `truncated_by` and say so.
    """
    cr = image.code_ranges.get(func_ref)
    if cr is None:
        return None
    return disassemble_range(image, cr, max_insns=max_insns)


def named_ranges(image: InstrImage, fr, name: str) -> list:
    """Resolve a function name, or an address, to its (name, CodeRange) pairs.

    Three things a user actually types, in order of how exactly they mean it:

    An address (`0xe0428` or `.text+0xe0428`) names a range that has no symbol at all.
    AOT emits closures anonymously, so the lambda passed to `map` cannot be reached by name
    from anywhere, and it is regularly the function that holds the answer.

    An exact name.

    Otherwise, a bare name against private ones. Dart mangles library-private identifiers
    with a per-library suffix, so the button handler is `_onButtonPressed@19445826` and
    nobody can guess that number. Matching `_onButtonPressed` on the stem is what a person
    means, and the printed name still shows the full mangling.

    Returns [] if unresolved."""
    out = []
    seen_pc = set()
    by_pc = {cr.pc_offset: cr for cr in image.all_ranges}

    addr = _parse_addr(name)
    if addr is not None:
        cr = by_pc.get(addr)
        if cr is None:                     # inside a range rather than at its start
            cr = next((c for c in image.all_ranges
                       if c.pc_offset <= addr < c.pc_offset + (c.size or 1)), None)
        # same spelling the lifter already uses for an unnamed call target
        return [(f"sub_0x{cr.pc_offset:x}", cr)] if cr else []

    def collect(pred):
        for ref, nr, ow, kt in fr.functions:
            nm = fr.strings.get(nr)
            if nm and pred(nm):
                cr = image.code_ranges.get(ref)
                if cr and cr.pc_offset not in seen_pc:
                    seen_pc.add(cr.pc_offset)
                    out.append((nm, cr))
        for pc, nm in (image.symbol_names or {}).items():
            if pred(nm) and pc not in seen_pc and pc in by_pc:
                seen_pc.add(pc)
                out.append((nm, by_pc[pc]))

    collect(lambda nm: nm == name)
    if not out:
        # `foo` should find `foo@12345`, but must not find `foobar`: only the mangling
        # suffix may follow, never more identifier.
        collect(lambda nm: nm.startswith(name + "@"))
    return out


def _parse_addr(text: str):
    """`0x1234`, `.text+0x1234` or a bare hex/decimal offset -> int, else None."""
    t = text.strip()
    if t.startswith(".text+"):
        t = t[len(".text+"):]
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        if t.isdigit():
            return int(t)
    except ValueError:
        pass
    return None


def function_name_by_pc(image: InstrImage, fr) -> dict:
    """Map each code's start pc_offset -> owning function name, for call-target naming.
    Snapshot names win; ELF .symtab names (image.symbol_names) backfill the gaps. That
    backfill is what recovers real names on dwarf_stack_traces_mode builds, where the
    snapshot itself no longer carries them."""
    fname = {}
    for ref, name_ref, owner_ref, kind_tag in fr.functions:
        fname[ref] = fr.strings.get(name_ref, "")
    pc_to_name = dict(image.symbol_names or {})
    for owner_ref, cr in image.code_ranges.items():
        nm = fname.get(owner_ref)
        if nm:
            pc_to_name[cr.pc_offset] = nm      # snapshot name wins over ELF backfill
    return pc_to_name


def _imm_from(op: str, reg: str):
    """Extract the immediate from an `[reg, #imm]` operand, or None."""
    if reg not in op or "#" not in op:
        return None
    t = op.split("#", 1)[1].rstrip("]!").split(",")[0].strip()
    try:
        return int(t, 16) if t.startswith("0x") else int(t)
    except ValueError:
        return None


# ObjectPool object layout (runtime_offsets_extracted.h, PRODUCT+ARM64+COMPRESSED):
# elements_start_offset = 0x10, element_size = 0x8. PP (X27) is UNTAGGED on arm64
# (assembler_arm64.cc LoadWordFromPoolIndex), so a load `[x27, #off]` reads pool entry
# index (off - 0x10) / 8, i.e. entry idx sits at byte offset 0x10 + idx*8.
POOL_ELEMENTS_START = 0x10
POOL_ELEMENT_SIZE = 8

#: The same three facts for arm32 (PRODUCT+ARM, uncompressed). Derived from the binary
#: rather than read off a header, and uniquely: of the twelve plausible combinations of
#: (start, element size, tag bias), exactly one makes the offset that benchCheckSecret
#: loads name the literal its source compares against. PP is TAGGED here, unlike arm64,
#: so a `[PP, #off]` load reads entry (off + 1 - 8) / 4.
POOL32_ELEMENTS_START = 8
POOL32_ELEMENT_SIZE = 4
POOL32_TAG = 1


def _pool_shape(arch):
    if arch is not None and getattr(arch, "word_size", 8) == 4:
        return POOL32_ELEMENTS_START, POOL32_ELEMENT_SIZE, POOL32_TAG
    return POOL_ELEMENTS_START, POOL_ELEMENT_SIZE, 0


def pool_byte_offset(idx: int, arch=None) -> int:
    """The offset a `[PP, #off]` load uses to reach pool entry `idx`."""
    start, size, tag = _pool_shape(arch)
    return start + idx * size - tag


def build_pool_map(fr, arch=None) -> dict:
    """ObjectPool byte-offset -> annotation string. The pool is loaded into PP (X27,
    untagged); a `ldr xN, [x27, #off]` reads pool entry (off - 0x10)//8. Entries keyed
    here by their true byte offset 0x10 + idx*8. Refs to a String or Function get a
    readable label; other object kinds are left unlabelled."""
    fname = {ref: fr.strings.get(nr, "") for ref, nr, ow, kt in fr.functions}
    m = {}
    for idx, (kind, val) in enumerate(fr.pool):
        if kind != "ref":
            continue
        off = pool_byte_offset(idx, arch)
        s = fr.strings.get(val)
        if s is not None:
            # Escaped, for the same reason strings.txt is: a literal holding a newline
            # would otherwise split one lifted line into several. And kept long, because a
            # decompiler exists to show you the literal, truncating at forty characters
            # hid the second half of an asset path that was the answer to a challenge.
            e = printable(s)
            m[off] = f'"{e}"' if len(e) <= 200 else f'"{e[:197]}..."'
        elif val in fname and fname[val]:
            m[off] = f"&{fname[val]}"
        else:
            lit = _const_list(fr, val, off)
            if lit is not None:
                m[off] = lit
    return m


#: How many elements to spell inline before the label becomes a reference. A short list is
#: the whole answer and belongs in the line; a long one is a data table, and inlining it at
#: every use site buried the loop that read it under three copies of a 47-byte keystream.
#: Past this, the label carries the length and the pool offset, and `jadart.constants()`
#: hands back the elements.
_LIST_INLINE = 6


def const_lists(fr, arch=None) -> dict:
    """pool byte offset -> the const list's elements, fully.

    The decompiled body names a long table rather than spelling it, so this is where the
    bytes come back. Keyed the same way the body labels them, so `const[47] @0xb9b0` in a
    lifted line and `0xb9b0` here are the same slot.
    """
    out = {}
    for idx, (kind, val) in enumerate(fr.pool):
        if kind != "ref":
            continue
        vals = _const_elems(fr, val)
        if vals is not None:
            out[pool_byte_offset(idx, arch)] = vals
    return out


def _const_elems(fr, ref: int):
    """A const list's elements as ints and strings, or None.

    The fill pass reads every element of every Array to stay in step with the stream, and
    used to drop them on the floor. That left a decompiled table lookup showing the
    arithmetic over `pool_0xb970[i]` with nothing anywhere saying what was in it, which for
    const DATA (a keystream, an S-box, a table of magic constants) is the half that
    matters. Dart puts all of it in Arrays, so this covers the general case.

    Ints and strings only, and all-or-nothing per list. An element that resolves to neither
    is an object this cannot name, and a list printed with holes invites the reader to
    assume the holes are zeroes.
    """
    elems = fr.arrays.get(ref)
    if not elems:
        return None
    out = []
    for e in elems:
        v = fr.smi_values.get(e)
        if v is not None:
            out.append(v)
            continue
        t = fr.strings.get(e)
        if t is None:
            return None
        out.append(t)
    return out


def _fmt_elem(v):
    return (hex(v) if abs(v) > 9 else str(v)) if isinstance(v, int) else f'"{printable(v)}"'


def _const_list(fr, ref: int, off: int):
    vals = _const_elems(fr, ref)
    if vals is None:
        return None
    if len(vals) <= _LIST_INLINE:
        return "const[" + str(len(vals)) + "]{" + ", ".join(_fmt_elem(v) for v in vals) + "}"
    head = ", ".join(_fmt_elem(v) for v in vals[:3])
    return f"const[{len(vals)}] @0x{off:x}{{{head}, ...}}"



_BRANCH = ("b", "cbz", "cbnz", "tbz", "tbnz")


def _branch_target(mn: str, op: str, lo: int, hi: int):
    """Return the intra-function target address of a conditional/uncond branch, or None.
    Excludes calls (bl) and out-of-range targets."""
    if not (mn == "b" or mn.startswith("b.") or mn in ("cbz", "cbnz", "tbz", "tbnz")):
        return None
    if "#" not in op:
        return None
    t = op.rsplit("#", 1)[1].strip().rstrip("]!")
    try:
        target = int(t, 16) if t.startswith("0x") else int(t)
    except ValueError:
        return None
    return target if lo <= target < hi else None


def label_blocks(dis) -> dict:
    """Assign L0, L1, ... labels to intra-function branch targets, in address order."""
    if not dis:
        return {}
    lo = dis[0][0]
    hi = dis[-1][0] + 4
    targets = set()
    for addr, mn, op in dis:
        t = _branch_target(mn, op, lo, hi)
        if t is not None:
            targets.add(t)
    return {addr: f"L{i}" for i, addr in enumerate(sorted(targets))}


def _add_imm_from_pp(op: str):
    """For `add xD, x27, #imm (, lsl #sh)` return (dst_reg, byte_offset), else None.
    This is the base-computing half of a far pool load (offset >= ~0x8000)."""
    parts = [p.strip() for p in op.split(",")]
    if len(parts) < 3 or parts[1] != "x27" or not parts[2].startswith("#"):
        return None
    hi = _parse_imm(parts[2].lstrip("#"))
    if hi is None:
        return None
    if len(parts) >= 4 and "lsl" in parts[3]:
        sh = _parse_imm(parts[3].split("lsl")[-1])
        if sh is not None:
            hi <<= sh
    return parts[0], hi


def _parse_imm(tok):
    if tok is None:
        return None
    tok = tok.strip().rstrip("]!").lstrip("#").split(",")[0].strip()
    try:
        return int(tok, 16) if tok.startswith(("0x", "-0x")) else int(tok)
    except ValueError:
        return None


def _mem_base_disp(op: str):
    """For a `[reg, #disp]` / `[reg]` operand return (base_reg, disp), else None.
    A bare `[reg]` (no displacement) has disp 0."""
    m = re.search(r"\[(\w+)(?:,\s*#(-?0x[0-9a-fA-F]+|-?\d+))?\]", op)
    if not m:
        return None
    return m.group(1), (_parse_imm(m.group(2)) or 0)


def annotate(dis, pc_to_name: dict, pool_map: dict | None = None) -> list:
    """Annotate direct BL/B call targets with the callee name, and PP-relative pool
    loads with the referenced string/function. Handles both direct loads
    (`ldr xN, [x27, #off]`) and far loads (`add xD, x27, #hi; ldr xN, [xD, #lo]`,
    used when the pool offset exceeds the 12-bit scaled ldr range ~0x7ff8)."""
    ann = []
    far_base = {}   # reg -> pp-relative byte offset established by `add reg, x27, #hi`
    for addr, mn, op in dis:
        note = ""
        if mn in ("bl", "b") and op.startswith("#"):
            try:
                nm = pc_to_name.get(int(op[1:], 16))
                if nm:
                    note = f"  ; -> {nm}"
            except ValueError:
                pass
        elif pool_map and mn in ("ldr", "ldur"):
            off = None
            if "x27" in op:                          # direct PP load
                off = _imm_from(op, "x27")
            else:                                    # possible far load via tracked base
                md = _mem_base_disp(op)
                if md and md[0] in far_base:
                    off = far_base[md[0]] + md[1]
            if off is not None and off in pool_map:
                note = f"  ; = {pool_map[off]}"

        # maintain far-load base registers: `add xD, x27, #hi` establishes xD; any
        # later instruction that overwrites a tracked reg invalidates it (the far load
        # above is resolved before this, so a `ldr xD, [xD, #lo]` still works).
        fb = _add_imm_from_pp(op) if mn == "add" else None
        if fb is not None:
            far_base[fb[0]] = fb[1]
        elif far_base:
            dst = op.split(",", 1)[0].strip()
            far_base.pop(dst, None)

        ann.append((addr, mn, op, note))
    return ann


def render_body(dis, pc_to_name: dict, pool_map: dict | None = None, indent: str = "    ") -> list:
    """Render a function body as annotated, block-labelled arm64 lines. Branch operands to
    intra-function targets are rewritten to the block label; calls and pool loads are named."""
    labels = label_blocks(dis)
    lines = []
    for addr, mn, op, note in annotate(dis, pc_to_name, pool_map):
        if addr in labels:
            lines.append(f"  {labels[addr]}:")
        # rewrite an intra-function branch operand to its label
        t = _branch_target(mn, op, dis[0][0], dis[-1][0] + 4)
        shown = op
        if t is not None and t in labels:
            shown = op.rsplit("#", 1)[0] + labels[t]
        lines.append(f"{indent}{mn:<7} {shown}{note}")
    return lines


def pool_xrefs(image: InstrImage, offsets) -> dict:
    """Which functions load these ObjectPool entries: `{pool offset: [CodeRange, ...]}`.

    The question "what uses this string?" is the first one anyone asks of a binary, and on
    an obfuscated build it is often the only one that still has an answer, names are gone,
    but a literal is a literal and whatever loads it is the code that cares about it.
    r2 spells this `axt`.

    Two addressing forms reach the pool. A near entry is `ldr xN, [x27, #off]`; a far one is
    `add xM, x27, #hi, lsl #12` followed by `ldr xN, [xM, #lo]`, and missing the second form
    would silently lose every reference past ~0x7ff8, which is most of them in a real app.

    A far base is only a pool base until something overwrites that register. Tracking the
    `add` without tracking the clobber attributes the string to whatever function happens to
    reload that register later, a spill restore ~250 bytes on, and the answer to "what uses
    this string" comes back three-quarters wrong. `annotate` already does this correctly, so
    the two share `_add_imm_from_pp`/`_mem_base_disp` rather than keeping second copies that
    can drift apart again.
    """
    want = set(offsets)
    out = {off: [] for off in want}
    for cr in image.all_ranges:
        dis = disassemble_range(image, cr)
        if not dis:
            continue
        far_base, seen = {}, set()
        for _addr, mn, op in dis:
            op = op or ""
            if mn in ("ldr", "ldur"):
                # Resolve off the memory operand, never off "is x27 anywhere in the text":
                # that also matches `ldr x27, [x0, #8]`, where x27 is the destination.
                md = _mem_base_disp(op)
                off = None
                if md and md[0] == "x27":
                    off = md[1]
                elif md and md[0] in far_base:
                    off = far_base[md[0]] + md[1]
                if off is not None and off in want and off not in seen:
                    seen.add(off)
                    out[off].append(cr)
            fb = _add_imm_from_pp(op) if mn == "add" else None
            if fb is not None:
                far_base[fb[0]] = fb[1]
            elif far_base:
                far_base.pop(op.split(",", 1)[0].strip(), None)
    return out
