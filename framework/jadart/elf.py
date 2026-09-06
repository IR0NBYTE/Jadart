"""Minimal dependency-free ELF reader, 32- and 64-bit.

Just enough to locate the Dart snapshot blobs in a libapp.so: parse section
headers and symbol tables, resolve a symbol by name to its virtual address, and
map a virtual address to a file offset. No external dependencies on purpose, so
the framework stays trivial to install.

The two classes differ only in field widths and, for symbols, in field ORDER:
ELF64 writes st_name, st_info, st_other, st_shndx, st_value, st_size while ELF32
writes st_name, st_value, st_size, st_info, st_other, st_shndx. Reading one with
the other's layout yields plausible nonsense rather than an error, so the layout
is selected from e_ident[EI_CLASS] and never guessed.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class Section:
    name: str
    sh_type: int
    addr: int
    offset: int
    size: int


@dataclass
class Symbol:
    name: str
    value: int
    size: int


SHT_NOBITS = 8
DART_MAGIC = 0xDCDCF5F5


class Elf:
    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        if data[4] not in (1, 2):
            raise ValueError(f"bad ELF class {data[4]}")
        if data[5] != 1:
            raise ValueError("only little-endian ELF supported")
        self.data = data
        self.bits = 64 if data[4] == 2 else 32
        self._parse()

    def _parse(self):
        d = self.data
        if self.bits == 64:
            (e_shoff,) = struct.unpack_from("<Q", d, 0x28)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 0x3A)
            shdr, sym_fmt, sym_size = "<IIQQQQIIQQ", "<IBBHQQ", 24
        else:
            (e_shoff,) = struct.unpack_from("<I", d, 0x20)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 0x2E)
            shdr, sym_fmt, sym_size = "<IIIIIIIIII", "<IIIBBH", 16
        self._sym_fmt, self._sym_size = sym_fmt, sym_size
        # raw section headers first (names resolved after we have the shstrtab)
        raw = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            (sh_name, sh_type, _flags, sh_addr, sh_offset, sh_size,
             sh_link, _info, _align, _entsize) = struct.unpack_from(shdr, d, off)
            raw.append((sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_link, _entsize))
        shstr_off = raw[e_shstrndx][3]

        def cstr(base, idx):
            end = d.index(b"\x00", base + idx)
            return d[base + idx:end].decode("utf-8", "replace")

        self.sections: list[Section] = []
        self._symtabs = []  # (offset, size, entsize, strtab_offset)
        for (sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_link, entsize) in raw:
            name = cstr(shstr_off, sh_name)
            self.sections.append(Section(name, sh_type, sh_addr, sh_offset, sh_size))
            if sh_type in (2, 11):  # SYMTAB, DYNSYM
                strtab_off = raw[sh_link][3]
                self._symtabs.append((sh_offset, sh_size, entsize or self._sym_size,
                                      strtab_off))

        self.symbols: dict[str, Symbol] = {}
        for (soff, ssize, sent, str_off) in self._symtabs:
            n = ssize // sent
            for i in range(n):
                base = soff + i * sent
                if self.bits == 64:
                    st_name, _info, _other, _shndx, st_value, st_size = struct.unpack_from(
                        self._sym_fmt, d, base)
                else:
                    st_name, st_value, st_size, _info, _other, _shndx = struct.unpack_from(
                        self._sym_fmt, d, base)
                if st_name == 0:
                    continue
                nm = cstr(str_off, st_name)
                if nm and nm not in self.symbols:
                    self.symbols[nm] = Symbol(nm, st_value, st_size)

    def va_to_offset(self, va: int) -> int:
        for s in self.sections:
            if s.sh_type != SHT_NOBITS and s.addr <= va < s.addr + s.size:
                return va - s.addr + s.offset
        raise ValueError(f"VA 0x{va:x} not in any loadable section")

    def symbol_bytes(self, name: str) -> bytes:
        sym = self.symbols.get(name)
        if sym is None:
            raise KeyError(name)
        off = self.va_to_offset(sym.value)
        return self.data[off:off + sym.size]

    def function_symbols(self, lo_va: int, hi_va: int) -> list[Symbol]:
        """Symbols with a nonzero size whose VA falls in [lo_va, hi_va), sorted by VA.
        On dwarf_stack_traces_mode builds these carry the qualified Dart names
        (`Class.method`) that the snapshot itself no longer holds."""
        out = [s for s in self.symbols.values()
               if s.size > 0 and lo_va <= s.value < hi_va]
        out.sort(key=lambda s: s.value)
        return out

    def find_snapshot_magic(self) -> list[int]:
        """Fallback for stripped binaries: file offsets where the Dart magic sits."""
        needle = struct.pack("<I", DART_MAGIC)
        out, start = [], 0
        while True:
            i = self.data.find(needle, start)
            if i < 0:
                break
            out.append(i)
            start = i + 4
        return out


# The reader handled only 64-bit when it was written, and the name is used across the
# codebase and in tests. Keep it pointing at the general class.
Elf64 = Elf
