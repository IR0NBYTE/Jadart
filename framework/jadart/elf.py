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

from .errors import ContainerError, MissingSymbol


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
        self._segments = self._program_headers()
        # A fully stripped .so can carry no section headers at all, and reading the
        # shstrtab index off an empty list raised "list index out of range" from inside
        # open_container. That made the magic-scan fallback in parse_libapp unreachable
        # for exactly the input it exists to handle. There is nothing to name here, so
        # the reader carries on with no sections and no symbols, and va_to_offset uses
        # the program headers instead.
        if e_shnum == 0 or e_shstrndx >= e_shnum:
            self.sections, self._symtabs, self.symbols = [], [], {}
            return
        # raw section headers first (names resolved after we have the shstrtab)
        raw = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            (sh_name, sh_type, _flags, sh_addr, sh_offset, sh_size,
             sh_link, _info, _align, _entsize) = struct.unpack_from(shdr, d, off)
            raw.append((sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_link, _entsize))
        shstr_off = raw[e_shstrndx][3]

        def cstr(base, idx, limit=None):
            # Bounded on purpose. d.index scans the whole file when the string table is
            # not NUL-terminated (raising ValueError from the middle of a parse), and
            # d.find returning -1 would slice to len-1 and hand back a name made of
            # whatever followed it.
            start = base + idx
            if start < 0 or start >= len(d):
                raise ContainerError(
                    f"string table offset {start} is outside the file (len {len(d)})")
            stop = len(d) if limit is None else min(len(d), base + limit)
            end = d.find(b"\x00", start, stop)
            if end < 0:
                raise ContainerError(
                    f"unterminated string at offset {start} in the string table")
            return d[start:end].decode("utf-8", "replace")

        self.sections: list[Section] = []
        self._symtabs = []  # (offset, size, entsize, strtab_offset)
        for (sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_link, entsize) in raw:
            name = cstr(shstr_off, sh_name)
            self.sections.append(Section(name, sh_type, sh_addr, sh_offset, sh_size))
            if sh_type in (2, 11):  # SYMTAB, DYNSYM
                if sh_link >= len(raw):
                    raise ContainerError(
                        f"section {name!r} links to string table {sh_link}, which does "
                        f"not exist ({len(raw)} sections)")
                strtab_off = raw[sh_link][3]
                # entsize comes from the file. Below one entry it is not a stride, and
                # ssize // 1 would run one iteration per byte of the table.
                ent = entsize or self._sym_size
                if ent < self._sym_size:
                    raise ContainerError(
                        f"section {name!r} declares a {ent}-byte symbol entry, smaller "
                        f"than the {self._sym_size}-byte ELF{self.bits} symbol")
                self._symtabs.append((sh_offset, sh_size, ent, strtab_off))

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

    def _program_headers(self) -> list:
        """(vaddr, memsz, offset, filesz) for every PT_LOAD segment.

        Sections are a linker convenience and a stripped file may have none; the program
        headers are what the loader itself uses, so they are the reliable way to map a
        virtual address back to a file offset.
        """
        d = self.data
        try:
            if self.bits == 64:
                (e_phoff,) = struct.unpack_from("<Q", d, 0x20)
                e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
                fmt, va_i, off_i, fsz_i, msz_i = "<IIQQQQQQ", 3, 2, 5, 6
            else:
                (e_phoff,) = struct.unpack_from("<I", d, 0x1C)
                e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x2A)
                fmt, va_i, off_i, fsz_i, msz_i = "<IIIIIIII", 2, 1, 4, 5
            out = []
            for i in range(e_phnum):
                f = struct.unpack_from(fmt, d, e_phoff + i * e_phentsize)
                if f[0] == 1:                       # PT_LOAD
                    out.append((f[va_i], f[msz_i], f[off_i], f[fsz_i]))
            return out
        except (struct.error, IndexError, OverflowError, ValueError):
            return []

    def va_to_offset(self, va: int) -> int:
        for s in self.sections:
            if s.sh_type != SHT_NOBITS and s.addr <= va < s.addr + s.size:
                return va - s.addr + s.offset
        for vaddr, memsz, off, filesz in self._segments:
            if vaddr <= va < vaddr + memsz:
                delta = va - vaddr
                if delta < filesz:
                    return off + delta
        raise ContainerError(f"VA 0x{va:x} not in any loadable section or segment")

    def symbol_bytes(self, name: str) -> bytes:
        # ContainerError, not KeyError. Three callers reach this outside open_container's
        # own try, so a KeyError here escaped the library as an untyped failure on the
        # commonest mistake there is: pointing the tool at libflutter.so.
        sym = self.symbols.get(name)
        if sym is None:
            raise MissingSymbol(
                f"no symbol {name!r} in this ELF. If this is a Flutter app, the snapshot "
                f"is in libapp.so, not here.")
        off = self.va_to_offset(sym.value)
        end = off + sym.size
        if off < 0 or end > len(self.data):
            raise ContainerError(
                f"symbol {name!r} spans {off}..{end}, past the end of the file "
                f"(len {len(self.data)})")
        return self.data[off:end]

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
