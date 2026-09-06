"""Field layout: the offset -> name map a release AOT snapshot still carries.

The project has held, in README/HOW-IT-WORKS and in DESIGN's limits section, that field
names do not survive AOT, on the evidence that every surviving `Field` object is a static.
That evidence is wrong, and the correction is measured rather than argued: on the 3.12.2
corpus binary 245 of the 420 surviving `Field` objects are INSTANCE fields, and across the
44 cached third-party apps that jadart can place (2.19.6 through 3.12.2) it is 36,555 of
59,160, or 61.8%. Each one still records where it lives.

WHERE THE NUMBER COMES FROM. `FieldSerializationCluster::WriteFill` (app_snapshot.cc:2205)
writes four refs, then `Write<uint32_t>(kind_bits_)`, then one more ref (:2234-2239):

    if (Field::StaticBit::decode(kind_bits_)) WriteFieldValue("id", host_offset_or_field_id)
    else                                      WriteFieldValue("offset", Smi::New(TargetOffsetOf(field)))

so for an instance field that last ref points at a Smi holding `Field::TargetOffsetOf`,
which is `target_offset_` (object.h:13484), which is the field's byte offset divided by
`kCompressedWordSize` (object.h:13475-13502). Smis are serialised in the Mint cluster and
their values are written in the ALLOC pass (app_snapshot.cc:5365), which is why
`clusters.py` keeps them.

WHY IT IS SAFE TO PRINT THE NAME. Two independent checks, both byte-exact, neither of them
a plausibility argument:

  * the offset must land inside the owner's own instance geometry, `instance_header_words
    <= word_offset < next_field_offset`, and `next_field_offset` is read from the Class
    object and cross-checked against the INSTANCE cluster by G6. Measured across the 44
    apps: 32,205 in range, 0 out of range.
  * an ImplicitGetter's whole body is one load of the field it reads, so the displacement
    in its compiled code and the offset in its Field object are two encodings of the same
    number that were produced by different halves of the compiler. Measured: 0 disagreements
    (verify.py G14), and the same getter's register WIDTH agrees with the owner's
    unboxed-fields bitmap on all 58 it can be read from (G15).

WHAT IT DOES NOT DO. It names a slot only where the receiver's class is known, which today
means `this` in a method whose owner class resolves. Everything else stays `field_0x8`,
because a name attributed to the wrong class is worse than an offset: the reader can see
that an offset is opaque and cannot see that a name is wrong.
"""
from __future__ import annotations

from dataclasses import dataclass, field as _dcfield

#: Field::StaticBit, object.h:4938-4940. `ConstBit` is bit 0 with no explicit position and
#: `StaticBit = ConstBit::kNextBit`, so bit 1. Not trusted on faith: every field this bit
#: calls an instance field has to place inside its owner's instance geometry, and the whole
#: map is refused if any one of them does not (see `recover_fields`). A bit that moved in
#: some future epoch would mislabel statics as instance fields, and their ids are dense
#: small integers that would fail that check immediately.
_STATIC_BIT = 1


@dataclass(frozen=True)
class FieldInfo:
    """One recovered field. Every value here was read from the snapshot."""
    name: str
    owner: str          # the class that DECLARES the slot, not the one being accessed
    offset: int         # byte offset within the instance
    inherited: bool = False
    #: The slot holds a RAW int or double rather than a tagged pointer, per the owner's
    #: unboxed-fields bitmap. Read, not inferred, and cross-checked against the width the
    #: code generator used in the field's implicit getter (verify.py G15).
    unboxed: bool = False


@dataclass
class FieldLayout:
    """Per-class instance-field maps, plus why anything was dropped.

    `by_class` is keyed by Class ref and holds the FULL map for that class, its own fields
    and every field it inherits, because a load at offset 8 of a subclass is a load of the
    superclass's slot 2 and the reader wants the name either way."""
    by_class: dict = _dcfield(default_factory=dict)     # class ref -> {byte off -> FieldInfo}
    class_name: dict = _dcfield(default_factory=dict)   # class ref -> name
    func_owner: dict = _dcfield(default_factory=dict)   # function ref -> class ref
    offset_of: dict = _dcfield(default_factory=dict)    # Field ref -> its byte offset
    #: Counters, so a caller can say what happened instead of only what worked.
    declared: int = 0          # instance fields with a name and an offset
    placed: int = 0            # ...of those, the ones inside their owner's geometry
    out_of_range: int = 0      # ...and the ones that were not, which refuse the whole map
    no_owner: int = 0          # owner ref is neither a Class nor a PatchClass we resolved
    refused: str = ""          # non-empty when the map is deliberately empty

    def for_class(self, class_ref) -> dict:
        """{byte offset -> field name} for a class ref, empty when nothing is known."""
        m = self.by_class.get(class_ref)
        return {} if not m else {off: fi.name for off, fi in m.items()}

    def for_function(self, func_ref) -> dict:
        """{byte offset -> field name} for the receiver of `func_ref`.

        Empty when the function's owner does not resolve to a class, which is the case for
        every code range on a dwarf_stack_traces_mode build. That is the right answer
        there: without an owner there is no class, and without a class an offset names
        nothing."""
        owner = self.func_owner.get(func_ref)
        return self.for_class(owner) if owner is not None else {}


def recover_fields(fr, arch) -> FieldLayout:
    """Build the instance-field layout from a completed fill walk.

    Fail-closed: if any field this reads places outside its owner's instance geometry, the
    whole map is refused rather than partially trusted, because one offset landing outside
    the object says the grammar or the StaticBit position is wrong and the offsets that DID
    land inside got there by arithmetic that is equally suspect."""
    out = FieldLayout()
    if not fr.field_meta or arch is None:
        out.refused = "no Field cluster in this snapshot"
        return out
    cws = arch.compressed_word_size
    hw = arch.instance_header_words

    S = fr.strings
    by_cid = {}
    cls_super = {}
    for ref, name_ref, cid, super_ref in fr.classes:
        out.class_name[ref] = S.get(name_ref, "")
        by_cid[cid & 0xFFFFFFFF] = ref
        cls_super[ref] = super_ref
    cls_cid = {ref: cid & 0xFFFFFFFF for ref, _n, cid, _s in fr.classes}

    # Field.owner is a Class or a PatchClass (object.h Field::owner); the PatchClass hop is
    # what places the fields of the patched core libraries.
    def owner_class(ref):
        if ref in cls_cid:
            return ref
        w = fr.patch_class.get(ref)
        return w if w in cls_cid else None

    named = {ref: (S.get(name_ref, ""), ow) for ref, name_ref, ow in fr.fields}

    own = {}
    for fref, (kind_bits, value_ref) in fr.field_meta.items():
        if (kind_bits >> _STATIC_BIT) & 1:
            continue
        word_off = fr.smi_values.get(value_ref)
        name, owner_ref = named.get(fref, ("", -1))
        if word_off is None or not name:
            continue
        out.declared += 1
        oc = owner_class(owner_ref)
        if oc is None:
            out.no_owner += 1
            continue
        sizes = fr.class_sizes.get(cls_cid[oc])
        if sizes is None or not (hw <= word_off < sizes[1]):
            out.out_of_range += 1
            continue
        out.placed += 1
        out.offset_of[fref] = word_off * cws
        bitmap = fr.class_unboxed.get(cls_cid[oc], 0)
        own.setdefault(oc, {})[word_off * cws] = FieldInfo(
            name=name, owner=out.class_name.get(oc, ""), offset=word_off * cws,
            unboxed=bool((bitmap >> word_off) & 1))

    if out.out_of_range:
        # An offset outside the object is not a field. One of them means the number being
        # read is not the number this claims to read, and every other offset came out of
        # the same read.
        return FieldLayout(class_name=out.class_name, declared=out.declared,
                           placed=0, out_of_range=out.out_of_range, no_owner=out.no_owner,
                           refused=f"{out.out_of_range} field offsets fall outside their "
                                   f"class's instance size")

    # A superclass's slots are at the same offsets in every subclass (Dart appends), so the
    # map a receiver needs is its own fields on top of its whole ancestry.
    memo = {}

    def full(ref, depth=0):
        if ref in memo:
            return memo[ref]
        if ref is None or depth > 64:
            return {}
        memo[ref] = {}                                   # cycle guard, before recursing
        sup = fr.types.get(cls_super.get(ref, -1))
        parent = by_cid.get(sup & 0xFFFFFFFF) if sup is not None else None
        merged = {off: FieldInfo(fi.name, fi.owner, fi.offset, inherited=True,
                                 unboxed=fi.unboxed)
                  for off, fi in full(parent, depth + 1).items()}
        merged.update(own.get(ref, {}))
        memo[ref] = merged
        return merged

    for ref in cls_cid:
        m = full(ref)
        if m:
            out.by_class[ref] = m
    out.func_owner = {ref: ow for ref, _n, ow, _kt in fr.functions if ow in cls_cid}
    return out
