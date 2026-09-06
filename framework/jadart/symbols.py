"""ELF/DWARF symbol backfill for dwarf_stack_traces_mode builds.

A default `flutter build --release` compiles the isolate snapshot with
dwarf_stack_traces_mode on. The Dart class/method/field NAMES are stripped from the
snapshot, so snapshot-only recovery yields short hash tokens like `AB`, `Aba`. Those
names are still emitted into the ELF .symtab / DWARF as qualified `Class.method` symbols
at their .text addresses, for offline stack-trace symbolication. When the .so still
carries a symbol table (an unstripped build intermediate, a debug .so, or a matching
--split-debug-info file), the real names are recoverable by mapping each recovered code
range's pc_offset back to the symbol that covers it. On a default release build the snapshot no longer
carries those names, so the symbol table is where they have to come from.
"""
from __future__ import annotations

import bisect

from .elf import Elf64

ISO_INSTR = "_kDartIsolateSnapshotInstructions"


def instr_image_va(elf: Elf64):
    s = elf.symbols.get(ISO_INSTR)
    return s.value if s else None


def pc_name_map(elf: Elf64, image_len: int) -> dict:
    """pc_offset -> qualified name for every function symbol whose entry lies inside the
    isolate instructions image. Keyed on the exact entry offset, so it lines up with the
    code ranges jadart recovers. Empty when the .so has no usable symbol table (stripped)."""
    base = instr_image_va(elf)
    if base is None:
        return {}
    out = {}
    for s in elf.function_symbols(base, base + image_len):
        out.setdefault(s.value - base, s.name)   # first (lowest-addr) name wins on ties
    return out


class CoveringNames:
    """Resolve an arbitrary pc_offset to the symbol that covers it (entry <= pc < entry+size).
    Used to attribute a mid-function address (e.g. a constant load) to its function."""

    def __init__(self, elf: Elf64, image_len: int):
        base = instr_image_va(elf)
        self._base = base
        self._starts, self._items = [], []
        if base is not None:
            for s in elf.function_symbols(base, base + image_len):
                self._starts.append(s.value - base)
                self._items.append((s.value - base, s.size, s.name))

    def at(self, pc_off: int):
        if not self._starts:
            return None
        i = bisect.bisect_right(self._starts, pc_off) - 1
        if 0 <= i < len(self._items):
            start, size, name = self._items[i]
            if start <= pc_off < start + size:
                return name
        return None
