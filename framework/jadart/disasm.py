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

from .errors import InputError, JadartError

import bisect
import re
import struct
import sys
from array import array
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
from .branches import code_target, printed_number
from .fill import quoted
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


#: Re-exported so `from .disasm import ISOLATE_INSTRUCTIONS` keeps working. It is defined
#: in snapshot.py because `info` reads it and must not import capstone to do so.
from .snapshot import ISOLATE_INSTRUCTIONS  # noqa: E402,F401

#: Instructions::kPolymorphicEntryOffsetAOT (object.h), identical in 2.19.6 and 3.12.2: how
#: far into the payload a Code object with a monomorphic entry has its normal entry point.
#: Such a payload opens on the switchable-call miss handler, then the monomorphic entry,
#: then the entry every static and dispatch-table call targets. ia32 has none in AOT, and
#: is absent here, so a lookup on it returns None and the entry reads as unknown.
#:
#: arm64 and arm are measured: every range the snapshot flags carries the miss handler's
#: `ldr x16, [x26, #off]; br x16` at +0 on arm64 across 2.19.6, 3.0.6, 3.2.6 and 3.12.2,
#: and the prologue sits at +0x10 on arm32-3.4.4. x64 and riscv are read from the SDK and
#: not measured: no corpus binary targets them, so `entry_va` on those is the SDK's number
#: rather than something this code has seen.
AOT_ENTRY_OFFSET = {"arm64": 24, "arm": 16, "x64": 22, "riscv32": 18, "riscv64": 18}



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
    # Where the image sits in the binary. pc_offset is relative to the exported symbol
    # below, not to .text: .text also holds the VM instructions image in front of it, so a
    # `.text+pc_offset` label names code that far into the WRONG image. `anchor_va +
    # pc_offset` is the virtual address a disassembler shows. Checked on 58 ELF builds and
    # an iOS dylib, 546,037 ranges, against the container's own section headers.
    anchor_symbol: str = ISOLATE_INSTRUCTIONS
    anchor_va: int = None
    anchor_file_offset: int = None
    container: str = ""        # "elf" or "macho"
    # pc_offset -> bytes from the range start to the entry calls actually land on, for the
    # Code objects with a monomorphic entry only. See AOT_ENTRY_OFFSET.
    entry_offsets: dict = None


def load_instructions(path):
    """Parse the isolate instructions image + table and build owner_ref -> CodeRange.
    Returns (image, fr, hdr): the InstrImage, the FillResult from walk_fill, and the
    parsed snapshot header.

    `path` is anything source.open_source accepts: a binary, a directory, an APK or IPA,
    or a Source already read out of one."""
    from .snapshot import parse_blob
    from .clusters import walk_alloc
    from .fillwalk import walk_fill
    from .source import read_binary

    src = read_binary(path)
    raw = src.data
    elf = open_container(raw)
    data = elf.symbol_bytes("_kDartIsolateSnapshotData")
    text = elf.symbol_bytes(ISOLATE_INSTRUCTIONS)
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

    anchor = elf.symbols.get(ISOLATE_INSTRUCTIONS)
    anchor_va = anchor.value if anchor is not None else None
    anchor_off = elf.va_to_offset(anchor_va) if anchor_va is not None else None

    # A Code object's payload_info says whether it has a monomorphic entry; if so, calls
    # land AOT_ENTRY_OFFSET bytes in. An arch missing from the table records None, which
    # the consumers must treat as "entry unknown" rather than as the range start.
    # A range with no Code object (discarded under --dwarf-stack-traces, before
    # first_entry_with_code) has no payload_info, and its entry is the range start: every
    # function that needs a monomorphic entry is put in functions_called_dynamically_,
    # whose Code DiscardCodeObjects keeps (precompiler.cc, 2.19.6 and 3.12.2). The obf
    # fixture agrees: none of its 6421 such ranges has the miss handler's br x16 at +4.
    entry_offsets = {}
    step = AOT_ENTRY_OFFSET.get(hdr.arch.name) if hdr.arch is not None else None
    for ci, info in fr.code_payload_info.items():
        slot = first_code + ci
        if info & 1 and 0 <= slot < len(pcs):
            entry_offsets[pcs[slot]] = step

    return InstrImage(text=text, pcs=pcs, first_code=first_code, code_ranges=ranges,
                      all_ranges=all_ranges, symbol_names=symbol_names,
                      data=data, data_length=header_length, arch=hdr.arch,
                      anchor_va=anchor_va, anchor_file_offset=anchor_off,
                      container="macho" if type(elf).__name__ == "MachO64" else "elf",
                      entry_offsets=entry_offsets), fr, hdr


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


def cut_end(cr: CodeRange, dis, max_insns: int = MAX_INSNS):
    """Where `cr` ends when the cap stopped `dis` short of it, else None: what build_cfg
    and lift_function take, to tell a branch into the part left out from one to another
    function (#70)."""
    return cr.pc_offset + cr.size if truncated_by(cr, dis, max_insns) else None


def require_decoder(image: InstrImage) -> str:
    """The architecture name, or the error that says why this image cannot be decoded.

    Split out of disassemble_range so a caller that decodes only some ranges still fails
    the way it did when it decoded all of them: up front, with the same message, rather
    than succeeding on an image where it happened not to need the decoder this time."""
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
    return arch_name


#: Both instruction sets here are fixed width, so a word capstone rejects can be stepped
#: over and decoding picked up at the next one. Anything variable width would need a real
#: resynchronisation strategy instead, and would have to be added to `_DECODERS` first.
_WORD = 4

#: What an undecodable word is rendered as, the spelling objdump uses. It is a mnemonic no
#: instruction set has, so nothing downstream mistakes it for one it should model.
UNDECODABLE = ".word"


def disassemble_range(image: InstrImage, cr: CodeRange, max_insns: int = MAX_INSNS):
    """Disassemble one CodeRange (used for full-image coverage, incl. anonymous
    obfuscation-discarded functions where owner_ref is -1).

    A word capstone cannot decode is emitted as `.word 0x...` and decoding continues after
    it. capstone stops at such a word, so this used to return the instructions before it
    and nothing else: every command dropped the rest of the function silently, and a range
    whose second word was junk read as a complete one-instruction function. No compiler
    output does that (capstone decodes every word of every range on all sixteen arm64
    corpus binaries), which is exactly why a crafted one must not be able to hide code
    behind it."""
    arch_name = require_decoder(image)
    size = cr.size or 512
    code = image.text[cr.pc_offset:cr.pc_offset + size]
    md = _decoder(arch_name)

    def decode(buf, addr, limit):
        """(instructions, bytes consumed) from one capstone pass."""
        if _HAVE_LITE:
            # disasm_lite yields (address, size, mnemonic, op_str) straight out of the C
            # array. `disasm` builds a full CsInsn per instruction instead, and this walks
            # the whole image: 457,622 instructions on the clean corpus binary, of which
            # the lifter reads exactly the three fields below and never the operand
            # detail. Same tuples, measured identical over all 457,622; 1.93x faster.
            got = [(a, mn, op) for (a, _sz, mn, op) in md.disasm_lite(buf, addr, limit)]
        else:
            got = [(i.address, i.mnemonic, i.op_str) for i in md.disasm(buf, addr)][:limit]
        return got, len(got) * _WORD

    out, used = decode(code, cr.pc_offset, max_insns)
    # The common case decodes the whole range in that one pass and never enters the loop.
    while used < len(code) and len(out) < max_insns:
        left = len(code) - used
        if left < _WORD:
            break                      # a tail shorter than one word is not an instruction
        word = int.from_bytes(code[used:used + _WORD], "little")
        out.append((cr.pc_offset + used, UNDECODABLE, f"0x{word:08x}"))
        used += _WORD
        if len(out) >= max_insns:
            break
        more, consumed = decode(code[used:], cr.pc_offset + used, max_insns - len(out))
        out.extend(more)
        used += consumed
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

    An address (`0x1eebac`, the virtual address Jadart prints, or the older
    `.text+0xb812c` spelling) names a range that has no symbol at all.
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

    addr = _parse_addr(name, image)
    if addr is not None:
        cr = by_pc.get(addr)
        if cr is None:                     # inside a range rather than at its start
            cr = next((c for c in image.all_ranges
                       if c.pc_offset <= addr < c.pc_offset + (c.size or 1)), None)
        # the spelling every surface uses for a range with no name
        return [(sub_label(image, cr.pc_offset), cr)] if cr else []

    # Matched as printed: a name holding a control character is escaped everywhere it
    # appears (#74), so the escaped spelling is the one that reads back.
    from .fill import visible

    def collect(pred):
        for ref, nr, ow, kt in fr.functions:
            nm = fr.names.get(nr)
            if nm and pred(nm):
                cr = image.code_ranges.get(ref)
                if cr and cr.pc_offset not in seen_pc:
                    seen_pc.add(cr.pc_offset)
                    out.append((nm, cr))
        for pc, nm in (image.symbol_names or {}).items():
            nm = visible(nm)
            if pred(nm) and pc not in seen_pc and pc in by_pc:
                seen_pc.add(pc)
                out.append((nm, by_pc[pc]))

    collect(lambda nm: nm == name)
    if not out:
        # `foo` should find `foo@12345`, but must not find `foobar`: only the mangling
        # suffix may follow, never more identifier.
        collect(lambda nm: nm.startswith(name + "@"))
    return out


def va_of(image: InstrImage, pc_offset: int):
    """The virtual address of a pc_offset, or None when the anchor symbol is absent."""
    return None if image.anchor_va is None else image.anchor_va + pc_offset


def addr_label(image: InstrImage, pc_offset: int) -> str:
    """The address to print for a code range.

    The virtual address, which is what every other tool shows and what can be pasted into
    one. Jadart used to print `.text+<pc_offset>`, but the number was never an offset into
    `.text`: that section also holds the VM instructions image in front of the isolate one,
    so the label named code that far into the wrong image, out by 0x16a80 on the clean
    fixture and by a different amount per build. Without the anchor symbol there is no
    virtual address to give, and the offset is named for what it actually is."""
    va = va_of(image, pc_offset)
    return f"0x{va:x}" if va is not None else f"isolate+0x{pc_offset:x}"


def target_va(image: InstrImage, pc_offset: int, op: str):
    """The virtual address the operand of the instruction at `pc_offset` names as code, or
    None when it names none.

    Decided from the instruction word, not the mnemonic (see branches.py): a text rule
    named arm64's `b.eq` and missed arm32's `beq` and `blls`. The text listing shows this
    in place of the operand; `-j` keeps `operands` exactly as capstone rendered it and
    carries this beside it, so a consumer that already parsed that string is not silently
    handed a different one."""
    if image.anchor_va is None:
        return None
    t = code_target(image, pc_offset, op)
    return None if t is None else image.anchor_va + t


def rebase_operand(image: InstrImage, pc_offset: int, op: str) -> str:
    """The operand of the instruction at `pc_offset`, with a code address it names written
    as a virtual address.

    capstone is handed the range at its pc_offset, so it renders `bl #0xb8334`, a number
    that is an offset into the instructions image. Printed next to virtual addresses that
    would read as one, and pasting it into another tool lands in the wrong place. Only the
    print layer rewrites it: every address inside the pipeline stays a pc_offset, which is
    what the pool, the call graph and the lifter are keyed on."""
    if image.anchor_va is None:
        return op
    t = code_target(image, pc_offset, op)
    if t is None:
        return op
    # the text before capstone's number, which is decimal below 10 (`w0, #0, #4`)
    return f"{printed_number(op)[0]}0x{image.anchor_va + t:x}"


def sub_label(image: InstrImage, pc_offset: int) -> str:
    """The name of a range that has none: `sub_` and the address the rest of the output
    prints for it, the virtual address when there is an anchor and the pc_offset when
    there is not. It used to carry the pc_offset either way, and 799 of the clean
    fixture's 2,254 such labels named a number inside the image window, which, pasted
    back, reached a different function (#40). _parse_addr reads the label back."""
    va = va_of(image, pc_offset)
    return f"sub_0x{pc_offset if va is None else va:x}"


class Printer:
    """How the decompiler writes a code address. Called as (pc_offset, operand), it gives
    the operand as `disasm` prints it, a code address it names written as a virtual
    address (#43); `.label(pc_offset)` names a range with no name (sub_label). Every tier
    prints through one, so no surface keeps capstone's pc_offset."""

    def __init__(self, image: InstrImage):
        self.image = image

    def __call__(self, pc_offset: int, op: str) -> str:
        return rebase_operand(self.image, pc_offset, op)

    def label(self, pc_offset: int) -> str:
        return sub_label(self.image, pc_offset)

    def address(self, pc_offset: int) -> str:
        """A code address inside a range: the virtual address, or the pc_offset when
        there is no anchor, as sub_label spells it, so it reads back the same way."""
        va = va_of(self.image, pc_offset)
        return f"0x{pc_offset if va is None else va:x}"


def rebaser(image: InstrImage) -> Printer:
    """The Printer for this image; see Printer."""
    return Printer(image)


def _parse_addr(text: str, image: "InstrImage | None" = None):
    """An address a person typed -> a pc_offset into the instructions image, else None.

    Accepted forms, and why:
    - `.text+0x1234`, the label Jadart used to print. It was never a `.text` offset; the
      number after it is a pc_offset, so it is still read as one and old scripts keep
      working.
    - `isolate+0x1234`, the same number said correctly, and `va+0x1234` for the other
      reading, so both are always expressible.
    - `0x1234` or `1234`. Read as a virtual address when it lands inside the image, which
      is the form every command prints now, so anything Jadart printed can be pasted back
      and reach what it named. Outside that window it can only be a pc_offset, and is read
      as one.
    - `sub_0x1234`, the name of a range with no name (sub_label), read as its number. It
      carries the virtual address, or the pc_offset when there is no anchor, so it reaches
      the range it names.

    The two readings overlap, because the image is longer than the address it starts at.
    Preferring the pc_offset there meant an address Jadart had just printed came back as a
    different function: `disasm` prints `0x13ef44` inside `FormatException.`, and pasting
    it returned `sub_0x13ee74`. 2506 of the clean fixture's addresses sit in that window.
    Refusing them was not an option either, since they are the output's own spelling. So
    the address reading wins, and `isolate+`/`.text+`/`+` keep meaning the pc_offset for
    anything written against the older output.
    """
    t = text.strip()
    if t[:6].lower() == "sub_0x":
        t = t[len("sub_"):]
    forced_va = False
    for prefix in ("va+", "va:"):
        if t.startswith(prefix):
            t, forced_va = t[len(prefix):], True
            break
    else:
        for prefix in (".text+", "isolate+", "+"):
            if t.startswith(prefix):
                t = t[len(prefix):]
                image = None      # an explicit prefix means a pc_offset, not an address
                break
    try:
        if t.lower().startswith("0x"):
            n = int(t, 16)
        elif t.isdigit():
            n = int(t)
        else:
            return None
    except ValueError:
        return None
    if image is None or image.anchor_va is None:
        if forced_va:
            raise InputError(
                "this binary has no anchor symbol, so there is no virtual address to "
                "resolve `va+` against; give the pc_offset instead")
        return n
    as_va = n - image.anchor_va
    if 0 <= as_va < len(image.text):
        return as_va
    if forced_va:
        raise InputError(
            f"0x{n:x} is not inside the instructions image, which runs from "
            f"0x{image.anchor_va:x} to 0x{image.anchor_va + len(image.text):x}")
    return n


def function_name_by_pc(image: InstrImage, fr, raw: bool = False) -> dict:
    """Map each code's start pc_offset -> owning function name, for call-target naming.
    Snapshot names win; ELF .symtab names (image.symbol_names) backfill the gaps. That
    backfill is what recovers real names on dwarf_stack_traces_mode builds, where the
    snapshot itself no longer carries them.

    Both come from the binary, so they are escaped as names (fill.visible, #74) unless
    `raw` asks for them as written, which only interop does: it escapes each name where
    it prints it and carries the original in base64."""
    from .fill import visible
    S = fr.strings if raw else fr.names
    fname = {}
    for ref, name_ref, owner_ref, kind_tag in fr.functions:
        fname[ref] = S.get(name_ref, "")
    pc_to_name = {pc: (nm if raw else visible(nm))
                  for pc, nm in (image.symbol_names or {}).items()}
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
    fname = {ref: fr.names.get(nr, "") for ref, nr, ow, kt in fr.functions}
    m = {}
    for idx, (kind, val) in enumerate(fr.pool):
        if kind != "ref":
            continue
        off = pool_byte_offset(idx, arch)
        s = fr.strings.get(val)
        if s is not None:
            # Escaped, for the same reason strings.txt is: a literal holding a newline
            # would otherwise split one lifted line into several, and one holding a quote
            # would end early (#83). And kept long, because a decompiler exists to show
            # you the literal, truncating at forty characters hid the second half of an
            # asset path that was the answer to a challenge.
            m[off] = quoted(s, 200)
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
    return (hex(v) if abs(v) > 9 else str(v)) if isinstance(v, int) else quoted(v)


def const_listing(vals) -> str:
    """A const list's elements as `constants` and constants.txt print them.

    Strings are quoted, as the `const[N]{...}` label quotes them. Printed bare, an element
    holding `, ` read as two elements, one spelling `0x10` read as that int, and an empty
    one left a gap that looked like a missing element.
    """
    return ", ".join(quoted(v) if isinstance(v, str) else hex(v) for v in vals)


def _const_list(fr, ref: int, off: int):
    vals = _const_elems(fr, ref)
    if vals is None:
        return None
    if len(vals) <= _LIST_INLINE:
        return "const[" + str(len(vals)) + "]{" + ", ".join(_fmt_elem(v) for v in vals) + "}"
    head = ", ".join(_fmt_elem(v) for v in vals[:3])
    return f"const[{len(vals)}] @0x{off:x}{{{head}, ...}}"



#: Branch kinds whose target is a place in the same function, so it gets a block label.
_LABELLED = ("jump", "cjump")

#: Branch kinds whose target is named after the function it lands on. A conditional jump
#: is left out: it stays inside its function, where it gets a block label instead.
_NAMED = ("jump", "call", "ccall")


def _block_target(kind_row, lo: int, hi: int):
    """A (kind, target) row's target when it is a branch into [lo, hi), else None."""
    kind, t = kind_row
    return t if kind in _LABELLED and t is not None and lo <= t < hi else None


def label_blocks(dis, kinds) -> dict:
    """Assign L0, L1, ... labels to intra-function branch targets, in address order.

    `kinds` is branches.row_kinds for the same rows, which reads each branch off its word.
    It is required: the mnemonic test it replaces knew arm64's `b.eq` but not arm32's
    `beq`, and over every range of arm32-2.19.6 labelled 7,583 targets where the word
    gives 35,458."""
    if not dis:
        return {}
    lo = dis[0][0]
    hi = dis[-1][0] + 4
    targets = set()
    for row in kinds:
        t = _block_target(row, lo, hi)
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


def annotate(dis, pc_to_name: dict, pool_map: dict | None = None, *, kinds) -> list:
    """Annotate direct BL/B call targets with the callee name, and PP-relative pool
    loads with the referenced string/function. Handles both direct loads
    (`ldr xN, [x27, #off]`) and far loads (`add xD, x27, #hi; ldr xN, [xD, #lo]`,
    used when the pool offset exceeds the 12-bit scaled ldr range ~0x7ff8).

    `kinds` is branches.row_kinds for the same rows, and is required. A callee is found
    from the word, so arm32's conditional calls are named too: `blls` to the
    stack-overflow stub and `bleq` to the null-error stubs, 9,554 of them over every range
    of arm32-2.19.6 that the mnemonic test it replaced (`bl` and `b` only) passed over.
    That test stayed as a fallback for a caller that left `kinds` out, and tier 2 did, so
    `export -t 2` named none of them (#42)."""
    ann = []
    far_base = {}   # reg -> pp-relative byte offset established by `add reg, x27, #hi`
    for i, (addr, mn, op) in enumerate(dis):
        note = ""
        kind, target = kinds[i]
        if kind in _NAMED and target is not None:
            nm = pc_to_name.get(target)
            if nm:
                note = f"  ; -> {nm}"
        # A branch is never a load, so this and the callee name above cannot both apply.
        if pool_map and mn in ("ldr", "ldur"):
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


def render_body(dis, pc_to_name: dict, pool_map: dict | None = None, indent: str = "    ",
                *, kinds, show) -> list:
    """Render a function body as annotated, block-labelled lines. Branch operands to
    intra-function targets are rewritten to the block label; calls and pool loads are
    named. `kinds` is branches.row_kinds for the same rows, and is required; see
    label_blocks. `show` prints any other operand, rebaser(image) so that a code address
    reads as a virtual address, as in `disasm`; it is required too, and None prints the
    operand as capstone did."""
    if not dis:
        return []
    labels = label_blocks(dis, kinds)
    lo, hi = dis[0][0], dis[-1][0] + 4
    lines = []
    ann = annotate(dis, pc_to_name, pool_map, kinds=kinds)
    for i, (addr, mn, op, note) in enumerate(ann):
        if addr in labels:
            lines.append(f"  {labels[addr]}:")
        # rewrite an intra-function branch operand to its label
        t = _block_target(kinds[i], lo, hi)
        if t is not None and t in labels:
            shown = op.rsplit("#", 1)[0] + labels[t]
        else:
            shown = show(addr, op) if show is not None else op
        lines.append(f"{indent}{mn:<7} {shown}{note}")
    return lines


_PP = 27

_PP_WORD = re.compile(
    b"(?=[\x60-\x7f]["
    + b"".join(re.escape(bytes([b])) for b in range(256) if b & 3 == 3)
    + b"].["
    + b"".join(re.escape(bytes([b])) for b in
               (0x38, 0x39, 0x3c, 0x3d, 0x78, 0x79, 0x7c, 0x7d,
                0xb8, 0xb9, 0xbc, 0xbd, 0xf8, 0xf9, 0xfc, 0xfd, 0x91))
    + b"])", re.S)


def _word_load(w: int):
    size, v, opc = w >> 30, (w >> 26) & 1, (w >> 22) & 3
    if not v:
        if opc != 1 or size < 2:
            return None
        scale = size
    elif opc == 1:
        scale = size
    elif opc == 3 and size == 0:
        scale = 4
    else:
        return None
    rn = (w >> 5) & 31
    if (w & 0x3B000000) == 0x39000000:
        return rn, ((w >> 10) & 0xFFF) << scale
    if (w & 0x3B200000) == 0x38000000:
        mode = (w >> 10) & 3
        if mode == 2:
            return None
        if mode == 1:
            return rn, 0
        imm9 = (w >> 12) & 0x1FF
        return rn, imm9 - 0x200 if imm9 & 0x100 else imm9
    return None


def _word_add_pp(w: int):
    if (w & 0xFF8003E0) != 0x91000000 | _PP << 5:
        return None
    imm = (w >> 10) & 0xFFF
    return w & 31, imm << 12 if w & (1 << 22) else imm


def _word_dest(w: int):
    if (w >> 25) & 7 in (4, 5) or (w >> 26) & 7 == 4:
        return w & 31
    return None


# ---------------------------------------------------------------------------
# Reading arm64 without a decoder
# ---------------------------------------------------------------------------

#: Byte tables for the candidate filter in A64Words. An arm64 word is little endian, so its
#: top byte (the opcode class) is every fourth byte from offset 3, and Rn (bits 5-9) is
#: split across bytes 0 and 1: its low three bits are byte 0's top three, its high two are
#: byte 1's bottom two.
_TOP_CALL = bytes(1 if (0x94 <= b <= 0x97 or b == 0xD6) else 0 for b in range(256))


def _rn_tables(reg: int):
    lo, hi = (reg & 7) << 5, reg >> 3
    return (bytes(1 if (b & 0xE0) == lo else 0 for b in range(256)),
            bytes(1 if (b & 0x03) == hi else 0 for b in range(256)))


A64_DISPATCH = 21                      # the dispatch table; the object pool is _PP
_RN_TABLES = (_rn_tables(_PP), _rn_tables(A64_DISPATCH))

A64_BL = 0x94000000            # bl #imm26                  (w & 0xFC000000)
A64_BLR = 0xD63F0000           # blr xN                      (w & 0xFFFFFC1F)


def _word_loadstore(w: int) -> bool:
    """Whether `w` sits in the arm64 load/store encoding group (op0 = x1x0)."""
    return (w & 0x0A000000) == 0x08000000


def _word_loads_x(w: int) -> bool:
    """Whether `w` is a load _word_load reads that writes a 64-bit general register, the
    only kind whose first operand capstone spells `xN`."""
    return _word_load(w) is not None and not (w >> 26) & 1 and w >> 30 == 3


class A64Words:
    """The instruction image as 32-bit words, with the few that name a call or the object
    pool found without decoding any of them.

    Capstone turns every word into text so that a caller can parse the text back into
    numbers. For a question like "which `bl`s are in this range" that is the whole cost and
    none of the value: a `bl` is one fixed opcode with its target in the low 26 bits. So
    the candidates are found with byte slicing and a regex, which run in C, and only those
    words are looked at in Python, about one word in six on a real image.

    A candidate is a `bl`, a `blr`, or any word whose Rn field is x27, the object pool
    register, or x21, the dispatch table. That is deliberately broad: it catches every
    load and add off either, plus words where those five bits mean something else. Callers
    classify pool words with _word_load and _word_add_pp, the decoders pool_xrefs uses.
    Those two agree with capstone's own text, in both directions, on every one of the
    7,755,621 instructions in the sixteen arm64 binaries of the corpus.
    """

    def __init__(self, text: bytes):
        n = len(text) // 4
        body = memoryview(text)[:n * 4]
        if sys.byteorder == "little":
            # A view, not a copy: the image is already in memory once.
            self.words = body.cast("I")
        else:
            self.words = array("I", body.tobytes())
            self.words.byteswap()
        b0, b1 = bytes(body[0::4]), bytes(body[1::4])
        marks = int.from_bytes(bytes(body[3::4]).translate(_TOP_CALL), "little")
        for lo, hi in _RN_TABLES:
            marks |= (int.from_bytes(b0.translate(lo), "little")
                      & int.from_bytes(b1.translate(hi), "little"))
        marks = marks.to_bytes(n, "little") if n else b""
        # An array rather than a list: 70,000 indexes as Python ints are 2.5 MB of peak
        # memory that `jadart functions` never used to pay; as 32-bit slots, 0.3 MB.
        self.candidates = array("I", (m.start() for m in re.finditer(b"\x01", marks)))

    def window(self, pc_offset: int, nwords: int):
        """(word index, word) for every candidate in `nwords` words from `pc_offset`."""
        first = pc_offset // 4
        lo = bisect.bisect_left(self.candidates, first)
        hi = bisect.bisect_left(self.candidates, first + nwords)
        words = self.words
        return [(i, words[i]) for i in self.candidates[lo:hi]]


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
    this string" comes back three-quarters wrong.
    """
    want = set(offsets)
    out = {off: [] for off in want}
    arch = getattr(image, "arch", None)
    arch_name = arch.name if arch is not None else "arm64"
    if arch_name != "arm64":
        raise UnsupportedArch(
            f"finding pool loads is implemented for arm64, and this snapshot is "
            f"{arch_name}. Its strings still read: `jadart strings` comes from the "
            f"snapshot rather than from the code.")
    ranges = image.all_ranges
    if not want or not ranges:
        return out
    text = image.text
    starts = [cr.pc_offset for cr in ranges]
    word = struct.Struct("<I").unpack_from
    hits = {}

    for m in _PP_WORD.finditer(text):
        pos = m.start()
        if pos & 3:
            continue
        i = bisect.bisect_right(starts, pos) - 1
        if i < 0 or pos >= starts[i] + ranges[i].size:
            continue
        w = word(text, pos)[0]
        ld = _word_load(w)
        if ld is not None:
            if ld[0] == _PP and ld[1] in want:
                hits.setdefault(ld[1], set()).add(i)
            continue
        fb = _word_add_pp(w)
        if fb is None or fb[0] == _PP:
            continue
        reg, hi = fb
        end = min(starts[i] + ranges[i].size, len(text) - 3)
        q = pos + 4
        while q < end:
            v = word(text, q)[0]
            ld = _word_load(v)
            if ld is not None and ld[0] == reg and hi + ld[1] in want:
                hits.setdefault(hi + ld[1], set()).add(i)
            fb = _word_add_pp(v)
            if fb is not None:
                if fb[0] == reg:
                    break
            elif _word_dest(v) == reg:
                break
            q += 4

    for off, idx in hits.items():
        out[off] = [ranges[i] for i in sorted(idx)]
    return out
