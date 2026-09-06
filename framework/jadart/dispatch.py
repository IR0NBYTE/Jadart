"""Tier 3.4: the global dispatch table (GDT) -> virtual-call selector NAMES.

Dart AOT resolves a virtual/interface call through a class-id-indexed table held in
X21 (`ldr target, [x21, (cid + offset), lsl #3]; blr target`). Tier 3.3 recovers the
receiver and that `offset`, which is a stable per-selector id but not a name. This
module recovers the name. No public tool does that: Blutter recompiles the matching
SDK and still renders these calls as `GDT[cid_x0 + 0x...]()`.

How it works
------------
The table is serialized at the very end of the isolate snapshot stream, after the fill
pass and the roots (Deserializer::ReadDispatchTable, app_snapshot.cc:9631). Its
entries encode a `code_index`, and the SAME index space is used by every Function's
serialized `code_index`, so a table slot identifies a concrete function rather than
just an address. Concretely (GetCodeAndEntryPointByIndex):

    instructions-table slot = code_index - 1

which is the slot jadart already maps to an owning function (disasm.py).

Locating the table needs no guessing. The serializer writes the Code cluster's first
ref id immediately after the length (`WriteUnsigned(code_cluster_->first_ref())`), and
jadart derives that same number independently from the alloc walk. So the right start
offset is the one whose second varint equals it. That's an exact anchor, not a heuristic.

Naming a selector
-----------------
The dispatch table register points at `&array[kOriginElement]`, so a call site's
immediate `off` and the array index `k` of the row for class `cid` relate as

    k = cid + selector_offset,   off = selector_offset - kOriginElement

A method F defined in class C (class id c) necessarily occupies C's own row, so
`selector_offset = k - c` for that row. Every class that defines the same selector must
agree on that number, which both identifies the offset and self-checks it: a name is
accepted only when at least two independent defining classes agree, and an offset
claimed by more than one name is dropped. Unrecovered selectors keep the `sel_0x<off>`
rendering rather than a guess.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from .stream import ReadStream, TruncatedSnapshot

# Serialization constants (app_snapshot.cc; identical across the supported epochs).
_RECENT_COUNT = 64
_RECENT_MASK = 63
_MAX_REPEAT = 63
_INDEX_BASE = 64

# DispatchTable::kOriginElement, the array element the dispatch register points at
# (runtime/vm/dispatch_table.h). ARM64 = "max consecutive sub immediate value".
ORIGIN_ELEMENT_ARM64 = 4096

# Accepting a name needs this many independent defining classes to agree on the offset.
MIN_AGREEING_CLASSES = 2


def _decode_entries(st: ReadStream, length: int, max_code_index: int) -> list:
    """Decode `length` dispatch entries -> list of code_index (None = no target).
    Mirrors Deserializer::ReadDispatchTable. Raises ValueError on an implausible
    stream so a wrong start offset fails fast instead of producing junk."""
    entries = [None] * length
    recent = [None] * _RECENT_COUNT
    recent_index = 0
    value = None
    repeat = 0
    for i in range(length):
        if repeat > 0:
            entries[i] = value
            repeat -= 1
            continue
        enc = st.read_int()
        if enc == 0:
            value = None                       # DispatchTableNullError entry
        elif enc < 0:
            r = ~enc
            if r >= _RECENT_COUNT:
                raise ValueError(f"recent index {r} out of range")
            value = recent[r]
        elif enc <= _MAX_REPEAT:
            repeat = enc - 1                   # repeat the previous value
        else:
            ci = enc - _INDEX_BASE
            if ci < 0 or ci > max_code_index:
                raise ValueError(f"code_index {ci} out of range")
            value = ci
            recent[recent_index] = value
            recent_index = (recent_index + 1) & _RECENT_MASK
        entries[i] = value
    return entries


def find_dispatch_table(data: bytes, start: int, end: int, code_first_ref: int,
                        max_code_index: int, max_length: int = 1 << 22):
    """Locate + decode the dispatch table in the post-fill region [start, end).

    Anchored on the serializer's own invariant: the varint right after the table
    length is the Code cluster's first ref id, which we already know. Returns
    (offset, entries, end_pos) or None when the snapshot carries no table."""
    if code_first_ref < 0:
        return None
    for p in range(start, max(start, end)):
        st = ReadStream(data, p)
        try:
            length = st.read_unsigned()
            if length == 0 or length > max_length:
                continue
            if st.read_unsigned() != code_first_ref:
                continue                        # not the table: cheap rejection
            entries = _decode_entries(st, length, max_code_index)
        except (TruncatedSnapshot, ValueError, IndexError):
            continue
        return p, entries, st.pos
    return None


def _slot_names(fr, image) -> dict:
    """instructions-table slot -> the selector name of the function that owns it.

    The ELF .symtab name wins where present: on a default `flutter build --release`
    (dwarf_stack_traces_mode) the snapshot keeps only short hash tokens, while the
    symbol table still carries the real `Class.method`, whose trailing component is the
    selector. Falls back to the snapshot name, which is what clean builds carry."""
    out = {}
    syms = image.symbol_names or {}
    if syms:
        for slot, pc in enumerate(image.pcs):
            nm = syms.get(pc)
            if nm:
                out[slot] = nm.rsplit(".", 1)[-1]
    fname = {ref: fr.strings.get(nr, "") for ref, nr, _ow, _kt in fr.functions}
    for _code_ref, owner_ref, ci in fr.codes:
        slot = image.first_code + ci
        if slot not in out:
            nm = fname.get(owner_ref)
            if nm:
                out[slot] = nm
    return out


def build_selector_map(entries: list, fr, image,
                       min_agree: int = MIN_AGREEING_CLASSES) -> dict:
    """selector_offset -> selector name.

    For every function placed in the table, each row holding its code yields the
    candidate `row - owner_class_id`; the defining class's own row gives the true
    offset, so the value that the most defining classes agree on wins. Names backed by
    fewer than `min_agree` classes, and offsets claimed by more than one name, are
    dropped rather than guessed."""
    slot_name = _slot_names(fr, image)
    class_cid = {ref: cid & 0xFFFFFFFF for ref, _n, cid, _s in fr.classes}

    rows = defaultdict(list)                    # instructions slot -> array indices
    for k, ci in enumerate(entries):
        if ci is not None:
            rows[ci - 1].append(k)
    if not rows:
        return {}

    func_slot = {}                              # function ref -> instructions slot
    for _code_ref, owner_ref, ci in fr.codes:
        func_slot[owner_ref] = image.first_code + ci

    votes = defaultdict(Counter)                # name -> Counter(candidate offset)
    for ref, name_ref, owner_ref, _kt in fr.functions:
        slot = func_slot.get(ref)
        cid = class_cid.get(owner_ref)
        if slot is None or cid is None:
            continue
        nm = slot_name.get(slot) or fr.strings.get(name_ref, "")
        if not nm:
            continue
        for k in rows.get(slot, ()):
            votes[nm][k - cid] += 1

    best = {}
    for nm, cnt in votes.items():
        off, n = cnt.most_common(1)[0]
        if n >= min_agree:
            best[nm] = (off, n)

    out, claimed = {}, {}
    for nm, (off, n) in best.items():
        prev = claimed.get(off)
        if prev is None or n > prev[1]:
            claimed[off] = (nm, n)
        elif n == prev[1]:
            claimed[off] = (None, n)            # tie -> ambiguous, drop below
    for off, (nm, _n) in claimed.items():
        if nm is not None:
            out[off] = nm
    return out


def recover_selectors(image, fr, hdr, origin: int = ORIGIN_ELEMENT_ARM64) -> dict:
    """Public entry: call-site immediate -> selector name.

    The lifter sees the immediate added to the class id, so the map is keyed that way
    (`selector_offset - kOriginElement`). Returns {} when the snapshot has no dispatch
    table or nothing clears the agreement bar. Callers then keep `sel_0x<off>`."""
    if not image.data or not image.data_length:
        return {}
    found = find_dispatch_table(image.data, fr.end_pos, image.data_length,
                                fr.code_first_ref, len(image.pcs) + 1)
    if not found:
        return {}
    _pos, entries, _end = found
    sel = build_selector_map(entries, fr, image)
    return {off - origin: nm for off, nm in sel.items()}
