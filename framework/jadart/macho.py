"""Minimal dependency-free Mach-O 64 reader (iOS / macOS Dart AOT snapshots).

Same job as elf.py, different container: locate the `_kDart*` blobs, resolve a symbol to a
virtual address, map a VA to a file offset. Presents the same surface elf.py does, so the
rest of jadart doesn't know or care which container it was handed.

Since Flutter 3.44.4 the iOS `App.framework/App` is produced by gen_snapshot's own Mach-O
writer (`--snapshot_kind=app-aot-macho-dylib`) rather than by assembling and linking through
Xcode, so a production-identical artifact can be built with nothing but the cached
`ios-release/gen_snapshot_arm64`. The blobs live in `__TEXT,__const` (snapshot data) and
`__TEXT,__text` (instructions), under the same symbol names ELF uses.

The one real difference from ELF: Mach-O symbols carry no size. `nlist_64` has no
equivalent of `st_size`, so a symbol's extent has to be derived. Taking "up to the next
symbol" is wrong here. Thousands of function symbols sit inside the instructions blob, so
that rule would truncate the image to its first function. An extent instead runs to the
end of its section, tightened only by the next `_kDart*` boundary symbol in that section.
That gives exact extents for the data blobs (VmSnapshotData ends where IsolateSnapshotData
begins) and the full image for the instructions.
"""
from __future__ import annotations

import struct

# container.py imports errors.py and the stdlib and nothing else, so this is a
# downward edge: no cycle, and the container vocabulary stays in one place.
from .errors import ContainerError, MissingSymbol
from dataclasses import dataclass

from .elf import Symbol, DART_MAGIC

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE          # big-endian 64 (not supported; arm64/x64 are LE)
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
N_TYPE = 0x0E
N_SECT = 0x0E                      # n_type & N_TYPE == N_SECT -> defined in a section


@dataclass
class MachSection:
    sectname: str
    segname: str
    addr: int
    size: int
    offset: int

    @property
    def name(self) -> str:
        return f"{self.segname},{self.sectname}"

    @property
    def is_zerofill(self) -> bool:
        # __bss and friends occupy no file bytes; offset is meaningless for them
        return self.offset == 0 and self.size > 0 and self.sectname.startswith("__bss")


class MachO64:
    def __init__(self, data: bytes):
        if len(data) < 32:
            raise ValueError("not a Mach-O file (too short)")
        (magic,) = struct.unpack_from("<I", data, 0)
        if magic in (FAT_MAGIC, FAT_CIGAM):
            raise ValueError("universal (fat) Mach-O is not supported; extract one "
                             "architecture first, e.g. `lipo -thin arm64 -output ...`")
        if magic == MH_CIGAM_64:
            raise ValueError("big-endian Mach-O is not supported")
        if magic != MH_MAGIC_64:
            raise ValueError("not a Mach-O 64 file")
        self.data = data
        self._parse()

    def _parse(self):
        d = self.data
        _magic, self.cputype, _sub, self.filetype, ncmds, _size, _flags, _res = \
            struct.unpack_from("<IiiIIIII", d, 0)
        self.sections: list[MachSection] = []
        self.symbols: dict[str, Symbol] = {}
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", d, off)
            if cmdsize <= 0:
                raise ValueError(f"bad load command size at 0x{off:x}")
            if cmd == LC_SEGMENT_64:
                segname = d[off + 8:off + 24].split(b"\x00")[0].decode("utf-8", "replace")
                nsects, = struct.unpack_from("<I", d, off + 64)
                so = off + 72
                for _i in range(nsects):
                    sect = d[so:so + 16].split(b"\x00")[0].decode("utf-8", "replace")
                    addr, size = struct.unpack_from("<QQ", d, so + 32)
                    foff, = struct.unpack_from("<I", d, so + 48)
                    self.sections.append(MachSection(sect, segname, addr, size, foff))
                    so += 80
            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", d, off + 8)
                for i in range(nsyms):
                    base = symoff + i * 16
                    if base + 16 > len(d):
                        break
                    n_strx, n_type, _n_sect, _n_desc, n_value = struct.unpack_from(
                        "<IBBHQ", d, base)
                    if not n_strx or (n_type & N_TYPE) != N_SECT:
                        continue
                    # Bounded by the declared string-table size. Unbounded, a table with
                    # no NUL scans the whole file, and find returning -1 sliced to len-1
                    # and produced a name made of whatever followed the real one.
                    start = stroff + n_strx
                    end = d.find(b"\x00", start, min(len(d), stroff + strsize))
                    if end < 0:
                        continue
                    nm = d[start:end].decode("utf-8", "replace")
                    if not nm:
                        continue
                    # Keep the name exactly as written: the snapshot blobs are spelled
                    # `_kDartIsolateSnapshotData` in BOTH containers, so stripping Mach-O's
                    # C underscore here would break every existing lookup.
                    if nm not in self.symbols:
                        self.symbols[nm] = Symbol(nm, n_value, 0)   # size derived on demand
                    # ...but also accept the de-underscored spelling for --disasm by name,
                    # where a user reasonably types the Dart symbol without the prefix.
                    alias = nm[1:] if nm.startswith("_") else None
                    if alias and alias not in self.symbols:
                        self.symbols[alias] = Symbol(alias, n_value, 0)
            off += cmdsize

    # the surface jadart consumes
    def _section_of(self, va: int):
        for s in self.sections:
            if not s.is_zerofill and s.addr <= va < s.addr + s.size:
                return s
        return None

    def va_to_offset(self, va: int) -> int:
        s = self._section_of(va)
        if s is None:
            raise ValueError(f"VA 0x{va:x} not in any mapped section")
        return va - s.addr + s.offset

    def symbol_bytes(self, name: str) -> bytes:
        sym = self.symbols.get(name)
        if sym is None:
            raise MissingSymbol(
                f"no symbol {name!r} in this Mach-O. If this is a Flutter app, the "
                f"snapshot is in the App binary, not here.")
        sec = self._section_of(sym.value)
        if sec is None:
            raise ContainerError(
                f"symbol {name} at 0x{sym.value:x} is not in a mapped section")
        end = sec.addr + sec.size
        # Tighten to the next snapshot boundary symbol in the same section, but NOT to the
        # next symbol generally: that would cut the instructions image at its first
        # function. Only the _kDart* blobs delimit each other.
        for other in self.symbols.values():
            if (other.value > sym.value and other.value < end
                    and other.name.lstrip("_").startswith("kDart")
                    and self._section_of(other.value) is sec):
                end = other.value
        off = self.va_to_offset(sym.value)
        return self.data[off:off + (end - sym.value)]

    def function_symbols(self, lo_va: int, hi_va: int) -> list[Symbol]:
        """Symbols inside [lo_va, hi_va), sorted by VA, with sizes synthesised from the gap
        to the next symbol (Mach-O doesn't record them)."""
        inside = sorted((s for s in self.symbols.values() if lo_va <= s.value < hi_va),
                        key=lambda s: s.value)
        out = []
        for i, s in enumerate(inside):
            nxt = inside[i + 1].value if i + 1 < len(inside) else hi_va
            out.append(Symbol(s.name, s.value, max(0, nxt - s.value)))
        return out

    def find_snapshot_magic(self) -> list[int]:
        needle = struct.pack("<I", DART_MAGIC)
        out, start = [], 0
        while True:
            i = self.data.find(needle, start)
            if i < 0:
                break
            out.append(i)
            start = i + 4
        return out


def open_container(data: bytes):
    """Return an ELF (32- or 64-bit) or MachO64 reader for `data`, whichever it is.

    Fails loud rather than guessing: an unrecognised container is reported with its magic,
    and the case jadart still can't read (fat Mach-O) says so specifically instead of
    surfacing as a generic parse error much later.

    Every failure leaves here as `ContainerError`, including the ones the header parsers
    raise as `ValueError` and the ones a short file raises as `struct.error`. This is the
    only door into a container, so it is where the promise in the package docstring,
    typed failures, catchable without matching on messages, is actually kept. A truncated
    libapp.so used to escape all the way to a caller as `struct.error` from elf.py, which
    no documented `except` clause mentions."""
    from .elf import Elf
    try:
        if data[:4] == b"\x7fELF":
            return Elf(data)
        if len(data) >= 4:
            (magic,) = struct.unpack_from("<I", data, 0)
            if magic in (MH_MAGIC_64, MH_CIGAM_64, FAT_MAGIC, FAT_CIGAM):
                return MachO64(data)
    except ContainerError:
        raise
    except (ValueError, struct.error, IndexError, KeyError, OverflowError,
            UnicodeDecodeError, MemoryError) as exc:
        head = data[:8].hex() if data else "<empty>"
        raise ContainerError(
            f"malformed container (leading bytes {head}): {exc}") from exc
    head = data[:4].hex() if data else "<empty>"
    raise ContainerError(f"unrecognised container (leading bytes {head}); expected ELF or "
                         f"Mach-O 64")
