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

A method F defined in a concrete class C (class id c) occupies C's own row, so
`selector_offset = k - c` for that row. Every class that defines the same selector must
agree on that number, which both identifies the offset and self-checks it: a name is
accepted only when at least two independent defining classes agree, and an offset
claimed by more than one name goes to the one more classes agree on. An abstract class
has no row; its functions fill their concrete subclasses' (_placements). And an offset
other selectors may share is not named at all (#128). Unrecovered selectors keep the
`sel_0x<off>` rendering rather than a guess.
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
    from .fill import NAME_CUT, visible
    syms = image.symbol_names or {}
    if syms:
        for slot, pc in enumerate(image.pcs):
            nm = syms.get(pc)
            if nm:
                # a name, as printed (#74, #94)
                out[slot] = visible(nm.rsplit(".", 1)[-1], limit=NAME_CUT)
    fname = {ref: fr.names.get(nr, "") for ref, nr, _ow, _kt in fr.functions}
    for _code_ref, owner_ref, ci in fr.codes:
        slot = image.first_code + ci
        if slot not in out:
            nm = fname.get(owner_ref)
            if nm:
                out[slot] = nm
    return out


#: How many names the last build_selector_map call dropped because their top two
#: candidate offsets tied, for a caller that wants to say why a name is missing. Module
#: state because the return type is the public contract and stays a dict.
LAST_AMBIGUOUS = 0


#: Class::kAbstractBit in UntaggedClass::state_bits_, after kConstBit, kImplementedBit
#: and the two-bit finalized and loading fields. Checked on 2.19.6, 3.4.4, 3.10.9 and
#: 3.12.2: set on every class upstream declares abstract that was looked at (`Widget`,
#: `State`, `RenderObject`, `Element`, `ShapeBorder`, `MapView`, ...) and clear on every
#: concrete one (`Text`, `Size`, `Color`, `Focus`, `SystemTextScaler`, ...).
_ABSTRACT = 1 << 6


def _selector(name: str) -> str:
    """`get:_foo@0150898` -> `_foo`: a name as the selector it spells, whichever of the
    snapshot and the symbol table wrote it."""
    return name.split(":", 1)[-1].split("@", 1)[0]


class Selectors(dict):
    """selector offset (or, from recover_selectors, call-site immediate) -> name, and
    what a call site needs to check the name against: `impls`, the functions the table
    places under each, and `doubles`, the ones whose implementations hand back a double
    in d0 (recover_selectors). A plain dict to every reader that does not ask."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.impls: dict = {}
        self.doubles: frozenset = frozenset()


def _placements(fr, rows, func_slot, slot_name, class_cid) -> tuple:
    """({offset: (name, class id, slot, function) of each function the table places
    there}, the same for each function that fits there and at another offset too,
    {class id: its superclass's}, {class id: the names its functions have}).

    A function F defined in class C fills, at its selector's offset, the row of every
    concrete class at or below C that inherits it, and no other row: an abstract class
    has none (dispatch_table_generator.cc only fills a concrete class's cells), and a
    class that defines F's name again, or sits below one that does, has its own. So F's
    offset is the one at which all of those classes have F in their row. Placing F at
    the least `row - cid(C)` instead put every function of an abstract class above its
    offset, beside selectors it does not share a row with.
    """
    parent = {}
    for _ref, _n, cid, sref in fr.classes:
        sup = fr.types.get(sref)
        if sup is not None and (sup & 0xFFFFFFFF) != (cid & 0xFFFFFFFF):
            parent[cid & 0xFFFFFFFF] = sup & 0xFFFFFFFF
    kids = defaultdict(list)
    for c, p in parent.items():
        kids[p].append(c)
    state = getattr(fr, "class_state", None) or {}
    concrete = {c for c in class_cid.values() if not state.get(c, 0) & _ABSTRACT}
    defines = defaultdict(set)                  # class id -> the names it defines
    owned = []
    patched = getattr(fr, "patch_class", None) or {}
    for ref, name_ref, owner_ref, _kt in fr.functions:
        # A patch class's functions are its class's: Object's `==` lives in one.
        cid = class_cid.get(owner_ref, class_cid.get(patched.get(owner_ref)))
        if cid is None:
            continue
        slot = func_slot.get(ref)
        nm = (slot_name.get(slot) if slot is not None else None) or fr.names.get(
            name_ref, "")
        defines[cid].add(nm)
        if slot is not None and rows.get(slot):
            owned.append((cid, nm, slot, ref))
    out, maybe = defaultdict(list), defaultdict(list)
    for cid, nm, slot, ref in owned:
        heirs, stack, seen = [], [cid], set()
        while stack:
            c = stack.pop()
            if c in seen:
                continue
            seen.add(c)
            if c != cid and nm and nm in defines[c]:
                continue                        # defines it again: its own row
            if c in concrete:
                heirs.append(c)
            stack.extend(kids.get(c, ()))
        if not heirs:
            continue
        # Identical code is shared between functions, so a slot's rows can be several
        # functions' rows: the offset is one at which every heir has its row, and where
        # more than one fits the function is not placed at all.
        ks, low = set(rows[slot]), min(heirs)
        fits = [k - low for k in sorted(ks) if all(h + k - low in ks for h in heirs)]
        if len(fits) == 1:
            out[fits[0]].append((nm, cid, slot, ref))
        else:
            for off in fits:                    # it may be at any of them
                maybe[off].append((nm, cid, slot, ref))
    return out, maybe, parent, defines


def build_selector_map(entries: list, fr, image,
                       min_agree: int = MIN_AGREEING_CLASSES) -> dict:
    """selector_offset -> selector name.

    For every function placed in the table, each row holding its code yields the
    candidate `row - owner_class_id`; the defining class's own row gives the true
    offset, so the value that the most defining classes agree on wins. Names backed by
    fewer than `min_agree` classes, and offsets claimed by more than one name, are
    dropped rather than guessed. So is a name whose own top two candidates tie, because
    a tie is not agreement: Counter.most_common would break it by insertion order."""
    global LAST_AMBIGUOUS
    LAST_AMBIGUOUS = 0
    slot_name = _slot_names(fr, image)
    class_cid = {ref: cid & 0xFFFFFFFF for ref, _n, cid, _s in fr.classes}

    rows = defaultdict(list)                    # instructions slot -> array indices
    for k, ci in enumerate(entries):
        if ci is not None:
            rows[ci - 1].append(k)
    if not rows:
        return Selectors()

    func_slot = {}                              # function ref -> instructions slot
    for _code_ref, owner_ref, ci in fr.codes:
        func_slot[owner_ref] = image.first_code + ci

    votes = defaultdict(Counter)                # name -> Counter(candidate offset)
    for ref, name_ref, owner_ref, _kt in fr.functions:
        slot = func_slot.get(ref)
        cid = class_cid.get(owner_ref)
        if slot is None or cid is None:
            continue
        nm = slot_name.get(slot) or fr.names.get(name_ref, "")
        if not nm:
            continue
        for k in rows.get(slot, ()):
            votes[nm][k - cid] += 1

    best, ambiguous = {}, 0
    for nm, cnt in votes.items():
        top = cnt.most_common(2)
        off, n = top[0]
        # A tie is not agreement. Counter.most_common breaks one by insertion order, which
        # is a coin flip dressed as a result: on the clean corpus 46 of 246 accepted names
        # had a tied top vote, and each printed at its call sites as a real method name.
        # `contains` had offsets 0 and 2 with three votes each. Dropping the name leaves
        # `sel_0x<off>`, which is the honest rendering and what the reader can act on.
        if len(top) > 1 and top[1][1] == n:
            ambiguous += 1
            continue
        if n >= min_agree:
            best[nm] = (off, n)

    claimed = {}
    for nm, (off, n) in best.items():
        prev = claimed.get(off)
        if prev is None or n > prev[1]:
            claimed[off] = (nm, n)
        elif n == prev[1]:
            claimed[off] = (None, n)            # tie -> ambiguous, drop below
    # Nor is an offset that other selectors share. The table is packed by row
    # displacement, so selectors whose classes never meet can take the same offset, and
    # the immediate at a call site does not say which of them it calls: the clean
    # build's 0x9c0e8 tests a bool and printed `.textScaleFactor`, whose offset
    # `Focus._usingExternalFocus` has too (#128). So an offset is named only where every
    # function the table places there has that one name.
    # A name is compared as the selector it spells: the symbol table writes `hashCode`
    # and `_foo` where the snapshot writes `get:hashCode` and `get:_foo@0150898`. A
    # function with no name is another selector as far as anything here can tell: nine
    # sit where `perform` was voted, iterables' `length` getters among them, and 122
    # calls of `.length` printed `.perform()`. So is a function that fits more than one
    # offset, at each of them.
    placed, maybe, parent, defines = _placements(fr, rows, func_slot, slot_name,
                                                 class_cid)
    # A function that fits more than one offset is at the one its own selector's vote
    # gives, where that is among them: `MapMixin.toString` fits six, and `toString`'s 67
    # defining classes say which. At that offset itself it still counts, as another
    # name may have won it.
    voted = {_selector(nm): off for nm, (off, _n) in best.items()}
    fits = defaultdict(set)
    for off, fs in maybe.items():
        for f in fs:
            fits[f[3]].add(off)
    def elsewhere(f, off):
        own = voted.get(_selector(f[0])) if f[0] else None
        return own is not None and own != off and own in fits[f[3]]
    maybe = {off: [f for f in fs if not elsewhere(f, off)] for off, fs in maybe.items()}
    out = Selectors()
    for off, (nm, _n) in claimed.items():
        if nm is None:
            continue
        sel = _selector(nm)
        own = [f for f in placed.get(off, ()) if f[0] and _selector(f[0]) == sel]

        def under(cid, sel=sel):
            seen = set()
            while cid is not None and cid not in seen:
                if any(n and _selector(n) == sel for n in defines.get(cid, ())):
                    return True
                seen.add(cid)
                cid = parent.get(cid)
            return False
        # A function with no name is the selector where a class at or above its own
        # defines the selector: that class's cell at the selector's offset is the
        # selector's.
        if any(not f[0] and not under(f[1]) or f[0] and _selector(f[0]) != sel
               for f in placed.get(off, ())):
            continue
        if any(not f[0] or _selector(f[0]) != sel for f in maybe.get(off, ())):
            continue
        out[off] = nm
        out.impls[off] = [f[3] for f in own]
    LAST_AMBIGUOUS = ambiguous
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
    out = Selectors({off - origin: nm for off, nm in sel.items()})
    out.doubles = frozenset(off - origin for off in _doubles(image, sel.impls))
    return out


def _doubles(image, impls: dict) -> set:
    """The offsets whose selector returns a double in d0, read off the smallest function
    placed under each. Every override of a selector shares its return convention, so one
    says it for all; one that cannot be decided says nothing."""
    from .disasm import MissingDisassembler, UnsupportedArch, disassemble_range
    from .expr import returns_in_d0
    out = set()
    for off, fns in impls.items():
        crs = [cr for cr in (image.code_ranges.get(f) for f in fns) if cr is not None]
        if not crs:
            continue
        cr = min(crs, key=lambda c: (c.size or 1 << 30, c.pc_offset))
        try:
            dis = disassemble_range(image, cr)
        except (MissingDisassembler, UnsupportedArch):    # no capstone: no tier 3 to tell
            return set()
        if dis and returns_in_d0([(a, mn, op, "") for a, mn, op in dis]):
            out.add(off)
    return out
