"""Which instructions carry a PC-relative code address, read from the instruction word.

capstone is handed each range at its pc_offset, so a branch prints its target as a
pc_offset (`bl #0xb8334`). Only the print layer turns that into a virtual address, and it
used to decide which operands to turn from the mnemonic text: a list that named arm64's
spelling (`b.eq`) and missed arm32's (`beq`, `blls`), so in `disasm` over every range of
arm32-2.19.6, 48,839 of the 85,944 PC-relative branches stayed pc_offsets beside virtual
addresses. darter, the one other Flutter tool that disassembles arm32, has the same bug
for calls. The Dart VM's own disassembler decides from the encoding, and so does this: on
both instruction sets the class of a PC-relative branch or address is fixed by the top
byte of the word (bits 31:24), and its target by the immediate field.

No capstone here, so this works in an install without it. The tables were checked against
capstone over all 2^32 words of each instruction set, each decoded at two bases: every
decodable word of a byte the table names prints an address that moves with the base, and
no word of any other byte does (536,870,912 such words on each set, no exception). That
proves it for one capstone build, the 5.0.9 wheel. For any other, each target is also
checked per row against the last number capstone printed, and a disagreement leaves the
operand exactly as printed rather than trusting either side.
"""
from __future__ import annotations

import re
import struct

NONE, JUMP, CJUMP, CALL, CCALL, B54, ADR, ADRP, LIT = range(9)


def _a32_table() -> bytes:
    t = bytearray(256)
    for tb in range(256):
        cond, op = tb >> 4, tb & 0xF
        if op == 0xA:        # B<c>; cond 1111 is BLX(imm) with H=0
            t[tb] = JUMP if cond == 0xE else CALL if cond == 0xF else CJUMP
        elif op == 0xB:      # BL<c>; cond 1111 is BLX(imm) with H=1
            t[tb] = CALL if cond >= 0xE else CCALL
    return bytes(t)


def _a64_table() -> bytes:
    t = bytearray(256)
    for tb in range(256):
        if tb & 0x7C == 0x14:
            t[tb] = CALL if tb & 0x80 else JUMP                # BL / B
        elif tb == 0x54:
            t[tb] = B54                                        # B.cond / BC.cond
        elif tb & 0x7C == 0x34:
            t[tb] = CJUMP                                      # CBZ CBNZ TBZ TBNZ
        elif tb & 0x9F == 0x10:
            t[tb] = ADR
        elif tb & 0x9F == 0x90:
            t[tb] = ADRP
        elif tb & 0x3B == 0x18 and tb != 0xDC:
            t[tb] = LIT                                        # LDR/LDRSW/PRFM literal
    return bytes(t)


#: For each instruction set, 256 bytes: the class of every top byte.
CLASS = {"arm": _a32_table(), "arm64": _a64_table()}

#: Classes whose operand is a code address in this image, and so is printed as one. ADRP
#: (a page) and the literal loads (data) are PC-relative too and stay as capstone printed
#: them, which is what the text rule did.
CODE_ADDRESS = {"arm": frozenset({JUMP, CJUMP, CALL, CCALL}),
                "arm64": frozenset({JUMP, CJUMP, CALL, B54, ADR})}
_MASK = {"arm": 0xFFFFFFFF, "arm64": 0xFFFFFFFFFFFFFFFF}
_U32 = struct.Struct("<I").unpack_from

#: Per instruction set, a top byte's class when that class names a code address, else 0.
#: One lookup rejects the rows that carry none, which is most of them.
_CODE = {a: bytes(c if c in CODE_ADDRESS[a] else 0 for c in t) for a, t in CLASS.items()}

#: What a branch is, for the readers that need more than its address: block labels take
#: jump and cjump targets, callee names take jump, call and ccall.
KINDS = {JUMP: "jump", CJUMP: "cjump", CALL: "call", CCALL: "ccall"}


def arch_name(image) -> str:
    """The instruction set this image's rows were decoded as.

    An image with no resolved target decodes as arm64 (disasm.require_decoder), so its
    words are read that way here too: the rows and the words have to be read alike."""
    a = getattr(image, "arch", None)
    return a.name if a is not None else "arm64"


def indirect_call(image, pc: int) -> bool:
    """Whether the word at `pc` calls through a register: `blr xN` on arm64, `blx rN` on
    arm32 under any condition. Read off the word, as row_kinds reads a direct call, so
    arm32 is not left out by a mnemonic test that knew only arm64's name (#54). Agrees
    with capstone on every such word of both fixtures and the 13 arm32 corpus builds."""
    try:
        w = _U32(image.text, pc)[0]
    except struct.error:
        return False
    if arch_name(image) == "arm":
        return w & 0x0FFFFFF0 == 0x012FFF30 and w >> 28 != 0xF     # BLX (register), A1
    return w & 0xFFFFFC1F == 0xD63F0000                               # BLR


def _sx(v: int, bits: int) -> int:
    return (v ^ (1 << (bits - 1))) - (1 << (bits - 1))


def word_target(arch: str, w: int, pc: int, cls: int) -> int:
    """The pc_offset a PC-relative word at `pc` points at, from its immediate field."""
    if arch == "arm":
        t = pc + 8 + (_sx(w & 0xFFFFFF, 24) << 2)
        return t + ((w >> 23) & 2) if w >> 28 == 0xF else t     # BLX(imm): H is bit 1
    if cls == JUMP or cls == CALL:
        return pc + (_sx(w & 0x3FFFFFF, 26) << 2)
    if cls == ADR:
        return pc + _sx((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3), 21)
    if cls == CJUMP and w & 0x02000000:                        # TBZ / TBNZ
        return pc + (_sx((w >> 5) & 0x3FFF, 14) << 2)
    return pc + (_sx((w >> 5) & 0x7FFFF, 19) << 2)              # B.cond, CBZ, literal


#: The last `#` number of an operand, in hex or in decimal. A code target is decimal only
#: below 10 (`bl #8` for 8, `bl #0xc` for 12, on arm64 and arm alike). A shift amount is
#: decimal at any size (`lsl #12`); only the word's class keeps it out of code_target and
#: row_kinds.
_NUMBER = re.compile(r"0x([0-9a-f]+)|([0-9]+)")


def printed_number(op: str):
    """(the operand before it, the value) of the last `#` number capstone printed in `op`,
    or None when it ends in anything else."""
    head, sep, tail = op.rpartition("#")
    m = _NUMBER.fullmatch(tail) if sep else None
    if m is None:
        return None
    return head, int(m.group(1), 16) if m.group(1) is not None else int(m.group(2))


def _agrees(op: str, t: int, arch: str, size: int) -> bool:
    """Whether the last number capstone printed is `t`, and `t` is in the image."""
    printed = printed_number(op)
    return printed is not None and printed[1] == t & _MASK[arch] and 0 <= t < size


def code_target(image, pc_offset: int, op: str):
    """The pc_offset the operand of the instruction at `pc_offset` names as a code address,
    or None. None unless all three agree: the word is a PC-relative branch (or `adr`), the
    target its immediate field gives is the last number capstone printed, and it lies
    inside the image."""
    arch = arch_name(image)
    tab = _CODE.get(arch)
    if tab is None or pc_offset < 0:
        return None
    text = image.text
    try:
        cls = tab[text[pc_offset + 3]]
    except IndexError:
        return None
    if not cls:
        return None
    t = word_target(arch, _U32(text, pc_offset)[0], pc_offset, cls)
    return t if _agrees(op, t, arch, len(text)) else None


def row_kinds(image, rows) -> list:
    """(kind, target pc_offset) for each (pc_offset, mnemonic, op) row of one range.

    kind is "jump", "cjump", "call", "ccall" or None. The target is given only when the
    word and capstone's printed number agree and it lies in the image, as in code_target;
    a branch whose target cannot be confirmed keeps its kind and gets None. arm64's `b.al`
    and `b.nv` branch always, so they are jumps; `bc.cond` is read like `b.cond`."""
    arch = arch_name(image)
    tab = CLASS.get(arch)
    if tab is None:
        return [(None, None)] * len(rows)
    text, size = image.text, len(image.text)
    out = []
    for pc, _mn, op in rows:
        try:
            cls = tab[text[pc + 3]] if pc >= 0 else NONE
        except IndexError:
            cls = NONE
        if cls == B54:
            # The target is read from the B.cond layout (imm19) before the kind is decided:
            # b.al is a jump, but its word is not B's, and decoding it as one gives imm26.
            kind = "jump" if text[pc] & 0xF >= 0xE else "cjump"
        else:
            kind = KINDS.get(cls)
        if kind is None:
            out.append((None, None))
            continue
        t = word_target(arch, _U32(text, pc)[0], pc, cls)
        out.append((kind, t if _agrees(op, t, arch, size) else None))
    return out


#: arm32 condition codes, by the value of bits 31:28. 14 is "always"; 15 is the
#: unconditional instruction space, which holds no exit a function body uses.
_A32_CC = ("eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt",
           "le")


def a32_exit(w: int):
    """(condition, is_return) when the A32 word `w` writes PC and is not a call or a
    PC-relative branch, else None. condition is "" for one that always does.

    These end a block with no successor in the function: a return (`pop {fp, pc}`,
    `bx lr`, `mov pc, lr`, `ldr pc, [sp], #4`) or an indirect jump (`ldr pc, [r4, #3]`,
    `bx r2`). Read off the word, because the mnemonic test this replaced knew `bx` and
    not `pop {fp, pc}`, arm32's usual return, nor any conditional form (#45).

    - BX: 0x012FFF1m. A return when m is lr. (BLX rm, 0x012FFF3m, is a call.)
    - LDM with PC in the register list. A return when the base is sp, as `pop` is.
    - LDR (word, not byte) with Rt = 15, outside the media space. A return from sp.
    - A data-processing instruction with Rd = 15, other than the compares, which write
      no register, and the miscellaneous and multiply spaces that share its encoding.
      `mov pc, lr` is a return."""
    cond = w >> 28
    if cond == 15:
        return None
    cc = "" if cond == 14 else _A32_CC[cond]
    if (w & 0x0FFFFFF0) == 0x012FFF10:                     # bx
        return cc, (w & 0xF) == 14
    op = (w >> 25) & 7
    if op == 0b100:                                        # ldm / pop
        if w & (1 << 20) and w & (1 << 15):
            return cc, (w >> 16) & 0xF == 13
        return None
    if op in (0b010, 0b011):                               # ldr / str
        if op == 0b011 and w & 0x10:
            return None                                    # media instructions
        if w & (1 << 20) and not w & (1 << 22) and (w >> 12) & 0xF == 15:
            return cc, (w >> 16) & 0xF == 13
        return None
    if op in (0b000, 0b001):                               # data processing
        if op == 0b000 and w & 0x90 == 0x90:
            return None                                    # multiply, extra loads/stores
        opcode, s = (w >> 21) & 0xF, (w >> 20) & 1
        if 8 <= opcode <= 11:
            return None                                    # compares, or misc (bx above)
        if (w >> 12) & 0xF != 15:
            return None
        mov_lr = opcode == 13 and op == 0b000 and (w & 0xFFF) == 14
        return cc, mov_lr
    return None


def exits(image, rows) -> dict:
    """{pc_offset: (condition, is_return)} for every row of one range that leaves the
    function without being a call or a PC-relative branch; see a32_exit. arm32 only:
    arm64's `ret` and `br` are mnemonics of their own, which cfg reads directly."""
    if arch_name(image) != "arm":
        return {}
    text = image.text
    out = {}
    for pc, _mn, _op in rows:
        if pc < 0 or pc + 4 > len(text):
            continue
        ex = a32_exit(_U32(text, pc)[0])
        if ex is not None:
            out[pc] = ex
    return out
