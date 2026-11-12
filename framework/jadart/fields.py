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

WHAT IT DOES NOT DO. It names a slot only where the base's class is known. `this` in a
method whose owner class resolves is one such base, `recover_allocations` below adds a
second, and `recover_casts` a third, on the edges after a cast. Everything else stays
`field_0x8`, because a name attributed to the wrong class is worse than an offset: the
reader can see that an offset is opaque and cannot see that a name is wrong.

WHICH CLASS `this` IS. `Function::Owner` (object.cc:11358) answers it in two steps: the
owner is a Class, or it is a PatchClass and the class is the one it wraps. The second
step is what places a method whose script is not its class's, which is every member a
mixin application takes from its mixin and every member a patch file adds to a core
class, and `_place_patched` below takes it under three refusals of its own.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field as _dcfield

from .keep import kept

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
    #: Functions whose owner is a PatchClass (`_place_patched`), counted the same way.
    patched: int = 0           # ...given the class their PatchClass wraps, for `this`
    patch_declined: int = 0    # ...static, or of a kind whose first argument is not it
    patch_agreed: int = 0      # ...whose own signature names that same class as receiver
    patch_disagreed: int = 0   # ...whose signature names another, which refuses them all
    patch_refused: str = ""    # non-empty when none of them was placed, and why

    def for_class(self, class_ref) -> dict:
        """{byte offset -> field name} for a class ref, empty when nothing is known."""
        m = self.by_class.get(class_ref)
        return {} if not m else {off: fi.name for off, fi in m.items()}

    def add_accessor_names(self, acc) -> int:
        """Merge accessor-derived names in, under the offsets the map has no entry for.

        Never over an entry a `Field` object put there: where both speak they agree, and
        `recover_accessors` refuses the whole channel if they ever do not, so this adds
        and does not overwrite (#240)."""
        added = 0
        for cls, offs in acc.by_class.items():
            m = self.by_class.setdefault(cls, {})
            for off, name in offs.items():
                if off in m:
                    continue
                m[off] = FieldInfo(name=name, owner=self.class_name.get(cls, ""),
                                   offset=off, inherited=False, unboxed=False)
                added += 1
        return added

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

    S = fr.names                         # class and field names, as printed (#74)
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
    _place_patched(fr, out, cls_cid)
    return out


#: The kinds of Function whose first argument is an instance of the class they belong to,
#: by the SDK's own definition of the kind (raw_object.h FOR_EACH_RAW_FUNCTION_KIND): a
#: method, an accessor, a generative constructor, and the implicit accessors "for instance
#: fields". A closure's first argument is the closure, and a dispatcher or forwarder takes
#: its arguments off the stack, so none of those is here; a static method or a factory is
#: excluded by its StaticBit rather than by its kind.
_RECEIVER_KINDS = ("RegularFunction", "GetterFunction", "SetterFunction", "Constructor",
                   "ImplicitGetter", "ImplicitSetter")


def _place_patched(fr, out: FieldLayout, cls_cid: dict) -> None:
    """Give a method whose owner is a PatchClass the class that PatchClass wraps.

    `Function.owner` is a Class or a PatchClass, and `Function::Owner` (object.cc:11358 at
    3.12.2, :11109 at 3.13.0)
    resolves the second to `wrapped_class` (`patched_class` through 3.1, the same first
    ref). A PatchClass owns a member whose script is not its class's. On the clean 3.12.2
    fixture 1,145 functions have one, and of the 397 this places 346 belong to a mixin
    application, whose members come out of the mixin's own file
    (`SemanticsAnnotationsMixin.describeSemanticsConfiguration`, the bindings), and 43 to
    a core class a patch file adds to (`StringBuffer`). Reading the owner as a Class only
    left all of them with no receiver class, so nothing off `this` in them could be
    named. `recover_fields` already takes this hop for `Field.owner`, and dispatch.py for
    the class a table row belongs to; this is the third reader and the same fact.

    THREE REFUSALS, because the hop is a statement about `this` and not only about an
    owner:

      * the function has to BE an instance function. Its StaticBit is calibrated per
        snapshot (program.static_bit) and that can fail, in which case nothing here says
        which functions take a receiver and none is placed. Two of the seven real apps
        measured for #240 are in that state, both 3.11.5.
      * its kind has to be one whose first argument is the receiver (`_RECEIVER_KINDS`).
      * and where the function still carries its signature, the signature has to agree.
        `FunctionType.parameter_types[0]` of an instance function is the receiver's own
        type, serialised by the FunctionType cluster and resolved through `Type`'s class
        id, so it shares nothing with `PatchClass.wrapped_class` but the answer. Measured
        over both fixtures and five real apps (2.19.6, 3.3.4, 3.5.4, 3.6.2, 3.12.2,
        3.13.0): 337 of 337 agree, 0 disagree, and the 42,716 functions a Class owns that
        say it too agree 42,716 times, which is the control. ONE disagreement places none,
        the rule `recover_fields` applies to an offset outside its owner: every hop was
        read the same way.

    A function this declines keeps `for_function() == {}`, which is what it had."""
    wrapped = fr.patch_class
    cand = [(ref, wrapped[ow], kt) for ref, _n, ow, kt in fr.functions
            if ow not in cls_cid and wrapped.get(ow) in cls_cid]
    if not cand:
        return
    from .program import _KIND_INDEX, static_bit
    sb = static_bit(fr)
    if sb is None:
        out.patch_refused = ("the static bit of Function.kind_tag does not calibrate on "
                             "this snapshot, so nothing says which functions take a "
                             "receiver")
        return
    kinds = frozenset(_KIND_INDEX[k] for k in _RECEIVER_KINDS)
    by_cid = {cid: ref for ref, cid in cls_cid.items()}
    placed = {}
    for ref, cls, kt in cand:
        if (kt >> sb) & 1 or (kt & 0x1F) not in kinds:
            out.patch_declined += 1
            continue
        said = _receiver_type_class(fr, ref, by_cid)
        if said is not None:
            if said == cls:
                out.patch_agreed += 1
            else:
                out.patch_disagreed += 1
        placed[ref] = cls
    if out.patch_disagreed:
        out.patch_refused = (f"{out.patch_disagreed} functions owned by a PatchClass "
                             f"declare a receiver of another class than the one it wraps")
        return
    out.func_owner.update(placed)
    out.patched = len(placed)


def _receiver_type_class(fr, func_ref, by_cid: dict):
    """The class a function's own signature gives its first parameter, or None.

    None where the signature did not survive, which is most functions in a release build,
    or where the first parameter is not a `Type` naming a class this snapshot has."""
    params = fr.arrays.get(fr.ftype_params.get(fr.func_signature.get(func_ref, -1), -1))
    if not params:
        return None
    cid = fr.types.get(params[0])
    return None if cid is None else by_cid.get(cid & 0xFFFFFFFF)


# --------------------------------------------------------------------------------------
# A SECOND base whose class the snapshot states: the result of an allocation.

#: A64 `MOVZ Xd, #imm16, LSL #hw*16` and `MOVK Xd, #imm16, LSL #hw*16`, 64-bit forms.
#: sf=1, opc=10 for MOVZ and 11 for MOVK, then 100101, so the top nine bits decide.
_MOV_MASK, _MOVZ64, _MOVK64 = 0xFF800000, 0xD2800000, 0xF2800000

#: `AllocateObjectABI::kTagsReg` (constants_arm64.h), the register an allocation stub
#: leaves the new object's header word in for the shared stub to store. Pinned to R2
#: rather than searched for, so the cid check below is a REFUTATION and not a hunt for
#: any immediate in the body that happens to carry the right bits: all 921 stubs on both
#: 3.12.2 fixtures load their tags word into x2.
_TAGS_REG = 2

#: UntaggedObject::tags_, the two fields of it this reads. The class id is bits 12..31,
#: the same field `expr.detect_dispatch` already extracts with `ubfx cid, tags, #0xc,
#: #0x14` on every epoch the lifter runs on. The size tag is bits 8..11, holding
#: instance_size / kObjectAlignment, and 0 where the size does not fit in four bits.
_CID_POS, _CID_BITS = 12, 20
_SIZE_POS, _SIZE_BITS = 8, 4

#: How far into a stub the tags word is looked for. Every one of the 921 stubs on each
#: 3.12.2 fixture is three or five instructions long.
_MAX_STUB_WORDS = 16


@dataclass(frozen=True)
class AllocSite:
    """One allocation stub: what `new` of this class leaves in the result register."""
    class_ref: int
    name: str                 # the owner class's name, as printed
    fields: dict              # byte offset -> field name, the owner's FULL map
    instance_size: int        # bytes, the bound an access off this result must respect


@dataclass
class AllocLayout:
    """pc offset -> AllocSite for every per-class allocation stub, plus why any was
    dropped."""
    by_pc: dict = _dcfield(default_factory=dict)
    stubs: int = 0             # Code objects whose owner is a Class
    confirmed: int = 0         # ...whose tags word carries the owner's own class id
    unreadable: int = 0        # ...whose tags word does not decode as MOVZ/MOVK into x2
    size_disagreed: int = 0    # ...whose size tag is not the owner's instance size
    ambiguous: int = 0         # ...whose pc another Class's Code also claims
    unnamed: int = 0           # ...whose owner Class's name did not survive
    disagreed: int = 0         # ...that name another class, which refuses the whole map
    refused: str = ""          # non-empty when the map is deliberately empty


def _tags_immediate(words) -> int | None:
    """The value a run of MOVZ/MOVK builds in `_TAGS_REG`, or None.

    MOVZ starts a value and zeroes the rest of the register; MOVK replaces one halfword
    of it. Anything else writing the register, or a MOVK with no MOVZ before it, means the
    word this is trying to read is not being built here, and None is the only answer that
    does not invent one."""
    acc = None
    for w in words:
        kind = w & _MOV_MASK
        if kind != _MOVZ64 and kind != _MOVK64:
            continue
        if (w & 0x1F) != _TAGS_REG:
            continue
        part = ((w >> 5) & 0xFFFF) << (((w >> 21) & 3) * 16)
        if kind == _MOVZ64:
            acc = part
        elif acc is None:
            return None
        else:
            acc = (acc & ~(0xFFFF << (((w >> 21) & 3) * 16))) | part
    return acc


def recover_allocations(image, fr, layout: FieldLayout) -> AllocLayout:
    """Per-class allocation stubs, so a field loaded off one's result can be named.

    WHY THERE IS A CLASS HERE AT ALL. `Code::owner()` is the Function, Class or
    AbstractType the code belongs to (object.h), and the VM sets a CLASS as the owner of
    exactly one kind of code: that class's allocation stub, which
    `StubCode::GetAllocationStubForClass` builds and `Class::allocation_stub_` holds. So a
    `bl` to a Code object the snapshot says a Class owns allocates an instance of that
    class, and the class of the value in the result register is read rather than guessed.
    921 of the 8,194 Code objects on the clean 3.12.2 fixture are such stubs, called from
    3,185 sites.

    WHY IT IS SAFE TO ACT ON. The stub's own body says which class it allocates, and it
    says so in a form nothing here produced. Each one loads the header word the new object
    will carry into `AllocateObjectABI::kTagsReg` and tail-branches to the shared stub
    that stores it:

        mov  x2, #0x401c          ; tags: class id 804 in bits 12..31
        movk x2, #0x32, lsl #16
        b    #...                 ; the shared AllocateObject stub

    Bits 12..31 of that immediate are the class id, and they have to be the owner Class's
    own class id. Measured over both 3.12.2 fixtures: 921 of 921, with 0 disagreements,
    and ONE disagreement refuses the whole map, because a stub whose header word names
    another class says `Code.owner` does not mean what this reads it to mean and every
    other owner was read the same way. Bits 8..11 are a second, independent agreement:
    they hold instance_size / kObjectAlignment, which matches the owner's instance size
    from the Class cluster on all 916 where a four-bit field can hold it (the other 5 and
    any disagreement drop that one stub, not the map, because that bit position is not
    load-bearing anywhere else in the tool).

    AND WHAT STILL REFUSES. The name comes out of the owner's field map, so a slot whose
    `Field` object was tree-shaken has none and keeps its offset: of the 7,504 accesses
    this attributes on the clean fixture, 692 are named and 6,812 are not. Every one of
    the 7,504 lands inside the owner's instance size, which is the check `recover_fields`
    applies to the map itself, and the lifter drops the whole attribution for a base where
    one does not (expr.Lifter._alloc_field, which fires 0 times on either fixture).

    Empty on anything but arm64: the decoder above is A64, and the lifter runs nowhere
    else (expr.LIFTABLE_ARCHS)."""
    out = AllocLayout()
    arch = getattr(image, "arch", None)
    if arch is None or arch.name != "arm64" or not image.text:
        out.refused = "the allocation-stub reader decodes A64 only"
        return out
    cws = arch.compressed_word_size
    align = arch.word_size * 2          # kObjectAlignment, 2 * kWordSize
    cls_cid = {ref: cid & 0xFFFFFFFF for ref, _n, cid, _s in fr.classes}
    seen: dict = {}
    for _ref, owner, _ci in fr.codes:
        cid = cls_cid.get(owner)
        if cid is None:
            continue
        cr = image.code_ranges.get(owner)
        if cr is None:
            continue
        out.stubs += 1
        seen.setdefault(cr.pc_offset, {})[owner] = (cid, cr)
    for pc, claims in seen.items():
        if len(claims) > 1:
            # Two DIFFERENT classes claiming one range cannot both be right, and nothing
            # here says which is, so neither is named. Keyed by owner, so two Code objects
            # of the same class are one claim rather than a false ambiguity.
            out.ambiguous += len(claims)
            continue
        owner, (cid, cr) = next(iter(claims.items()))
        # A size bound, because `size` and `pc_offset` both come out of the file. Every
        # stub on both fixtures is three or five instructions, so anything outside that is
        # not stub-shaped, and this is also what stops a range claiming megabytes from
        # turning into a word list that long.
        if not (0 < cr.size <= 4 * _MAX_STUB_WORDS) or pc < 0:
            out.unreadable += 1
            continue
        body = image.text[pc:pc + cr.size]
        words = [int.from_bytes(body[i:i + 4], "little")
                 for i in range(0, len(body) - 3, 4)]
        tags = _tags_immediate(words)
        if tags is None:
            out.unreadable += 1
            continue
        if ((tags >> _CID_POS) & ((1 << _CID_BITS) - 1)) != cid:
            out.disagreed += 1
            continue
        out.confirmed += 1
        sizes = fr.class_sizes.get(cid)
        if sizes is None:
            out.unreadable += 1
            continue
        size = sizes[0] * cws
        tag = (tags >> _SIZE_POS) & ((1 << _SIZE_BITS) - 1)
        if tag and tag * align != size:
            out.size_disagreed += 1
            continue
        name = layout.class_name.get(owner, "")
        if not name:
            # The class id is proven and the field map would still be the right one, but
            # with no name for the class there is nothing to print at the allocation, and
            # a field name off a value whose provenance the reader cannot see is a name
            # with no way to check it.
            out.unnamed += 1
            continue
        m = layout.by_class.get(owner)
        out.by_pc[pc] = AllocSite(
            class_ref=owner, name=name,
            fields={} if not m else {off: fi.name for off, fi in m.items()},
            instance_size=size)
    if out.disagreed:
        return AllocLayout(stubs=out.stubs, confirmed=out.confirmed,
                           unreadable=out.unreadable, ambiguous=out.ambiguous,
                           size_disagreed=out.size_disagreed, unnamed=out.unnamed,
                           disagreed=out.disagreed,
                           refused=f"{out.disagreed} allocation stubs carry a class id "
                                   f"their owner Class does not")
    return out


# --------------------------------------------------------------------------------------
# A slot whose `Field` object survived without a readable name, named by its accessor.

#: How many instructions an accessor may be and still be read. An implicit getter is two
#: to fourteen, a setter carries the write barrier and sometimes a covariance check, and
#: every one on both 3.12.2 fixtures is well inside this. It also bounds the CFG and the
#: fixpoint below, since the words come out of the file.
_MAX_ACCESSOR_WORDS = 48

#: The two kinds whose name the compiler derives from the field and whose body it builds
#: from that field alone (see `recover_accessors`), and how many arguments each takes.
_ACCESSOR_ARGS = {"ImplicitGetter": 1, "ImplicitSetter": 2}


@dataclass
class AccessorNames:
    """{class ref: {byte offset: name}} read out of implicit accessors."""
    by_class: dict = _dcfield(default_factory=dict)
    #: Counters, so a caller can say what happened rather than only what worked.
    agreed: int = 0            # the accessor's Field names itself, and the same way
    body_agreed: int = 0       # the body reaches the receiver at the Field's own offset
    disagreed: int = 0         # either of those contradicted, which refuses the channel
    added: int = 0
    declined: int = 0
    refused: str = ""


def recover_accessors(image, fr, layout: FieldLayout) -> AccessorNames:
    """Name a slot whose `Field` object survives but whose name does not read, from the
    implicit accessor the compiler made for that Field.

    WHERE THE NAME IS. `KernelLoader::GenerateFieldAccessors` (kernel_loader.cc) makes an
    instance field's getter and setter as `kImplicitGetter` and `kImplicitSetter`
    Functions named `get:` and `set:` plus the field's own name, and calls
    `set_accessor_field(field)` on each, so the Function's `data` IS the Field
    (`Function::accessor_field`, object.cc). `FlowGraphBuilder::BuildGraphOfFieldAccessor`
    (kernel_to_il.cc) then builds the whole body from that Field: load it off parameter
    0, or store parameter 1 into it. So an implicit accessor names exactly one slot, its
    own Field's, and the offset comes from the Field object, not from the code.

    Such a Field usually names itself and is already in the map. Where it does not, its
    name is a string the VM snapshot holds, a base object the isolate snapshot refers to
    and never writes (`end`, `start`, `state`, `r`, `g`, `b`), while the accessor's name
    `get:g` is written into the isolate snapshot. All 19 such Fields on the clean fixture
    are that case, and that is the whole of this channel's reach.

    WHAT IT USED TO DO, AND WHY THAT WAS A GUESS (#258). This read every `get:` and `set:`
    Function whatever its kind, and took the one offset its body touched. A HAND-WRITTEN
    setter's name is not its slot's: Dart forbids a field and a setter of one name in one
    class, so `set capacity` stores into `_capacity`, and 56 of the 61 offsets this named
    on the clean fixture came from such setters, `this.capacity`, `this.locale` and
    `this.ellipsis` among them. Its store rule did not ask what the base register held
    either, so `RenderAnimatedSize.set:reverseDuration`, which stores into the controller
    it loads, named the receiver's offset 44, and the agreement check below refused the
    channel on all six real apps measured for #240. Its 40 agreements were all implicit.

    WHAT SAYS IT IS RIGHT. Two checks, each against a second encoding, and ONE
    contradiction of either refuses the whole channel, the rule `recover_fields` applies
    to itself:

      * where the Field's own name DOES read, it has to be the accessor's name with the
        prefix taken off. 145 of 145 on the clean fixture, 78 of 78 on the obf one.
      * the body, read from the entry convention by `_receiver_accesses`, has to reach
        the receiver at the Field's own offset and nowhere else for a store (a getter: a
        load there and nothing else). That is G14 extended to setters and to a base that
        is proved to be the receiver rather than assumed to be x1.

    A body that cannot be read that way, an accessor whose Code was deduplicated into
    another Function's, a Field with no offset or an offset outside its owner, and an
    accessor whose owner is not the Field's owner are declined, not guessed.

    Tier 3 only, arm64 only, and empty without a disassembler, because the field map
    itself is stdlib and this reads compiled bodies."""
    out = AccessorNames()
    arch = getattr(image, "arch", None)
    if arch is None or getattr(arch, "name", None) != "arm64":
        out.refused = "the accessor reader runs on arm64 only"
        return out
    try:
        from .disasm import disassemble_range
    except Exception:                                  # pragma: no cover
        out.refused = "no disassembler, so no accessor body to read"
        return out
    from .program import _KIND_INDEX
    kinds = {_KIND_INDEX[k]: k for k in _ACCESSOR_ARGS}

    cws, hw = arch.compressed_word_size, arch.instance_header_words
    cls_cid = {ref: cid & 0xFFFFFFFF for ref, _n, cid, _s in fr.classes}

    def owner_class(ref):
        if ref in cls_cid:
            return ref
        w = fr.patch_class.get(ref)
        return w if w in cls_cid else None

    field_of = {ref: (name_ref, owner) for ref, name_ref, owner in fr.fields}
    entries = getattr(image, "entry_offsets", None) or {}
    found: dict = {}
    for ref, name_ref, owner, kt in sorted(fr.functions):
        kind = kinds.get(kt & 0x1F)
        if kind is None:
            continue
        nm = fr.names.get(name_ref, "")
        prefix = "get:" if kind == "ImplicitGetter" else "set:"
        data = fr.func_data.get(ref, -1)
        if not nm.startswith(prefix) or data not in field_of or data not in fr.field_meta:
            out.declined += 1
            continue
        name = nm[len(prefix):]
        kind_bits, value_ref = fr.field_meta[data]
        word = fr.smi_values.get(value_ref)
        if (kind_bits >> _STATIC_BIT) & 1 or word is None:
            out.declined += 1
            continue
        fname_ref, fowner = field_of[data]
        fname = fr.names.get(fname_ref, "")
        if fname:
            if fname != name:
                return AccessorNames(disagreed=1, refused=(
                    f"`{nm}` accesses the Field `{fname}`, and the compiler names an "
                    f"implicit accessor after its own Field"))
            out.agreed += 1
        cls = owner_class(fowner)
        if cls is None or owner_class(owner) != cls:
            out.declined += 1
            continue
        sizes = fr.class_sizes.get(cls_cid[cls])
        if sizes is None or not (hw <= word < sizes[1]):
            return AccessorNames(disagreed=1, refused=(
                f"the Field `{nm}` accesses places outside its own class's instance"))
        off = word * cws
        cr = getattr(image, "code_ranges", {}).get(ref)
        if cr is None or not (0 < cr.size <= 4 * _MAX_ACCESSOR_WORDS):
            out.declined += 1               # no Code of its own: deduplicated
            continue
        skip = entries.get(cr.pc_offset, 0)
        try:
            dis = disassemble_range(image, cr) if skip is not None else None
        except Exception:
            dis = None
        if not dis:
            out.declined += 1
            continue
        got = _receiver_accesses([r for r in dis if r[0] >= cr.pc_offset + skip],
                                 _ACCESSOR_ARGS[kind])
        if got is None:
            out.declined += 1
            continue
        loads = {o for k, o in got if k == "ld" and o > 0}     # 0 is the header word
        stores = {o for k, o in got if k == "st" and o > 0}
        reached = stores if kind == "ImplicitSetter" else loads
        if reached and off not in reached:
            return AccessorNames(disagreed=1, refused=(
                f"`{nm}` reaches the receiver at {sorted(reached)} and its Field is at "
                f"{off}, so one of the two readings is wrong"))
        if reached != {off} or (kind == "ImplicitGetter" and stores - {off}):
            out.declined += 1
            continue
        out.body_agreed += 1
        if off in (layout.by_class.get(cls) or {}):
            continue                        # the Field named itself: nothing to add
        if found.get((cls, off), name) != name:
            found[(cls, off)] = None        # two accessors, two names, no answer
            continue
        found[(cls, off)] = name

    for (cls, off), name in sorted(found.items()):
        if name is None:
            out.declined += 1
            continue
        out.by_class.setdefault(cls, {})[off] = name
        out.added += 1
    return out


def _receiver_accesses(dis, nargs: int):
    """{("ld" | "st", byte offset)} for the accesses `dis` makes through the receiver, or
    None where that cannot be said.

    Read from the entry CONVENTION and nothing else. The receiver is parameter 0, and a
    function takes it either in x1 (the register convention, `kCpuRegistersForArgs`) or
    on the stack, the first of `nargs` pushed arguments and so at entry-SP plus 8 *
    (nargs - 1): `ldr x1, [x15, #8]` in a frameless setter, `[x29, #0x18]` after the
    frame is built. Compiled code reads neither home under the other convention, since
    neither holds anything there, so both are taken as the receiver at entry.

    A must-analysis over the body's CFG: a register holds the receiver at an instruction
    only if it does on every path there. It follows the value through `mov`, through a
    spill to a frame slot and the reload after a call, and through SP and FP moving by
    known amounts; any other write of a register forgets it, and a call forgets the
    registers a call may clobber. An access through a receiver register with an index or
    a writeback it cannot read makes the answer None, because a receiver access this
    cannot place could be the one that matters. `dis` is (addr, mn, op) from the entry
    calls land on, so a monomorphic entry's class check is not part of it."""
    from .cfg import TRAPS, build_cfg
    from .expr import ARM64, use_target
    with use_target(ARM64):
        return _receiver_walk([(a, mn, op, "") for a, mn, op in dis], nargs, build_cfg,
                              TRAPS)


def _receiver_walk(rows, nargs, build_cfg, traps):
    from . import expr as E
    blocks, entry = build_cfg(rows, traps=traps)
    if not blocks or entry not in blocks:
        return None
    # (receiver registers, entry-relative stack addresses holding it, SP and FP as
    # entry-relative offsets or None, registers holding a known constant)
    start = (frozenset({"x1"}), frozenset({8 * (nargs - 1)}), 0, None, ())
    preds = {a: [] for a in blocks}
    for a, b in blocks.items():
        for s in b.succ:
            if s in preds:
                preds[s].append(a)
    acc, bad = set(), []

    def meet(x, y):
        return (x[0] & y[0], x[1] & y[1], x[2] if x[2] == y[2] else None,
                x[3] if x[3] == y[3] else None, tuple(sorted(set(x[4]) & set(y[4]))))

    def step(state, mn, op, record):
        regs, homes, sp, fp = set(state[0]), set(state[1]), state[2], state[3]
        consts = dict(state[4])
        ops = E._split_ops(op)

        def kill(defs):
            nonlocal sp, fp
            for d in defs:
                regs.discard(d)
                consts.pop(d, None)
                if d == "x15":
                    sp = None
                elif d == "x29":
                    fp = None

        if mn in E._LOADS or mn in E._STORES:
            got = E._addr(ops)
            if got is None or got[1] is E._BAD_POST:
                kill(E._def_use(mn, op)[0])
                if got is not None and record and any(r in regs for r in E._regs(ops)):
                    bad.append(mn)
                return _pack(regs, homes, sp, fp, consts)
            (base, disp, index, _scale, wb), post = got
            load = mn in E._LOADS
            vals = [E.canon(o) for o in ops[:2 if mn in ("ldp", "ldpsw", "stp") else 1]]
            width = 4 if ops[0].strip()[:1] in ("w", "s") else 8
            if base in ("x15", "x29") and index is None:
                at = sp if base == "x15" else fp
                at = None if at is None else at + (0 if post else disp)
                for i, r in enumerate(vals):
                    if at is None:
                        if load:
                            kill((r,))
                        else:
                            homes.clear()          # a store this cannot place
                        continue
                    a = at + i * width
                    if load:
                        kill((r,))
                        if width == 8 and a in homes:
                            regs.add(r)
                    else:
                        homes -= {h for h in homes if a - 8 < h < a + width}
                        if width == 8 and r in regs:
                            homes.add(a)
            else:
                if base in regs and record:
                    if wb or post:
                        bad.append(mn)
                    elif index is None:
                        acc.add(("ld" if load else "st", disp + 1))
                    elif index in consts and not _scale:
                        acc.add(("ld" if load else "st", consts[index] + disp + 1))
                    else:
                        bad.append(mn)
                if load:
                    kill(vals)
            if wb or post:
                step_by = disp if wb else post
                if base == "x15":
                    sp = None if sp is None else sp + step_by
                elif base == "x29":
                    fp = None if fp is None else fp + step_by
                else:
                    kill((base,))
            return _pack(regs, homes, sp, fp, consts)
        if mn in ("mov", "movz") and len(ops) == 2:
            d, s = E.canon(ops[0]), E.canon(ops[1])
            k = E._imm(ops[1]) if ops[1].strip().startswith("#") else None
            was = s in regs
            nsp = sp if s == "x15" else fp if s == "x29" else None
            kill((d,))
            if d == "x29":
                fp = nsp
            elif d == "x15":
                sp = nsp
            if k is not None:
                consts[d] = k
            elif was and ops[0].strip()[:1] == "x" and ops[1].strip()[:1] == "x":
                regs.add(d)
            return _pack(regs, homes, sp, fp, consts)
        if (mn in ("add", "sub") and len(ops) == 3 and ops[2].strip().startswith("#")
                and E.canon(ops[0]) in ("x15", "x29")):
            s, k = E.canon(ops[1]), E._imm(ops[2])
            src = sp if s == "x15" else fp if s == "x29" else None
            v = None if src is None or k is None else src + (k if mn == "add" else -k)
            kill((E.canon(ops[0]),))
            if E.canon(ops[0]) == "x15":
                sp = v
            else:
                fp = v
            return _pack(regs, homes, sp, fp, consts)
        # A call clobbers what a call may (expr._A64_CLOBBERS); the frame slots it leaves,
        # because a spill slot is this frame's own and a callee writes below its SP.
        kill(E._def_use(mn, op)[0])
        return _pack(regs, homes, sp, fp, consts)

    IN, OUT = {entry: start}, {}
    work, rounds = [entry], 0
    while work:
        rounds += 1
        if rounds > 64 * len(blocks):
            return None
        a = work.pop()
        st = IN[a]
        for (_ia, mn, op, _n) in blocks[a].insns:
            st = step(st, mn, op, False)
        if OUT.get(a) == st:
            continue
        OUT[a] = st
        for s in blocks[a].succ:
            if s not in blocks:
                continue
            ins = [OUT[p] for p in preds[s] if p in OUT]
            new = ins[0]
            for x in ins[1:]:
                new = meet(new, x)
            if s == entry:
                new = meet(new, start)
            if IN.get(s) != new:
                IN[s] = new
                work.append(s)
    for a in sorted(blocks):
        st = IN.get(a)
        if st is None:
            continue                         # unreachable from the entry
        for (_ia, mn, op, _n) in blocks[a].insns:
            st = step(st, mn, op, True)
    return None if bad else acc


def _pack(regs, homes, sp, fp, consts):
    return frozenset(regs), frozenset(homes), sp, fp, tuple(sorted(consts.items()))


# --------------------------------------------------------------------------------------
# A THIRD base whose class the snapshot states: the value a cast has just let through.

#: Class::ImplementedBit and Class::AbstractBit in UntaggedClass::state_bits_. ConstBit is
#: bit 0, ImplementedBit the next one, then two two-bit fields, then AbstractBit
#: (object.h). Neither position is taken on trust: `recover_casts` checks the first
#: against every class's `interfaces` array and the second against every class that owns
#: an allocation stub, and refuses the channel on one disagreement.
_IMPLEMENTED = 1 << 1
_ABSTRACT_BIT = 1 << 6

#: The shared type-testing stubs, which test the instance in x0 against the Type in x8
#: and return only when it is assignable. `TopTypeTypeTestStub` returns for anything and
#: the TypeParameter ones are handed their type in another register, so neither is here.
#: A stub this names is used only where its own body reads as one (`_stub_accepts`).
_TTS_STUB_RE = re.compile(r"_iso_stub_Default(?:Nullable)?TypeTestStub")

#: The registers a type-testing stub hands back as it found them, TypeTestABI's
#: kPreservedAbiRegisters (constants_arm64.h: the instance, the destination type and the
#: two type argument vectors). Every other register the stub may use as scratch.
_TTS_KEEPS = frozenset({"x0", "x1", "x2", "x8"})

#: The classes a `Type` can name whose instances are not laid out as that class, or that
#: no value is an instance of: `FutureOr<T>` holds a T or a Future, and the rest are the
#: top and bottom types and Null.
_NOT_A_LAYOUT = ("FutureOrCid", "NullCid", "NeverCid", "DynamicCid", "VoidCid",
                 "InstanceCid")

#: The class ids a check may accept without saying anything about a layout: null, which
#: a cast to a nullable type lets through and no field is read off, and three types no
#: value has. The compiler's subtype ranges treat them as "don't care", as they do an
#: abstract class and an unused id (compiler/backend/il.cc, CidCheckerForRanges::
#: MayInclude), so a check may span them.
_NO_LAYOUT_CIDS = ("NullCid", "NeverCid", "DynamicCid", "VoidCid")

#: Bounds for reading one stub's paths, past which it is not read. No stub of a closed
#: class on the two fixtures or the seven app-sweep libraries reaches either.
_STUB_MAX_INSNS = 512
#: The site marker for a call through the entry point x8's Type holds.
_INDIRECT = "indirect"

#: The cast analysis's work budget, in units per instruction of the body: a unit is one
#: entry of a state a meet reads or a redefinition scans, and one instruction walked.
#: Past it the body is declined, which names nothing and is always safe. Measured with
#: no budget over the 3,890 bodies the analysis runs on in the two fixtures and the seven
#: app-sweep libraries, the most any spends is 316 per instruction (a 2,919-instruction
#: FluffyChat body), the 99th percentile 191 to 208 per binary and the median 64 to 80,
#: and 55.5M units cost 5.9 s of CPU, about 107 ns each. So 1,000 is three times the
#: most a real body spends, and caps the analysis near 0.1 ms per instruction, 0.43 s at
#: the 4,000-instruction cut, whatever a crafted body does to the state it carries.
_CAST_WORK_PER_INSN = 1000
#: Sweeps over the blocks in reverse postorder before the fixpoint counts as not found.
_CAST_SWEEPS = 64


class _OverBudget(Exception):
    """The cast analysis spent its work budget on one body."""
_STUB_MAX_STATES = 4096
_CID_TOP = 1 << 20       # class ids are 20 bits of the header word (bits 12..31)


@dataclass(frozen=True, eq=False)
class CastClass:
    """A class whose every subtype EXTENDS it, so its own map names a slot of any value
    a cast to it let through."""
    class_ref: int
    name: str
    cid: int
    fields: dict              # field name by byte offset, the class's FULL map
    subclasses: frozenset     # the class id of the class and of every class extending it
    bound: int                # bytes: the largest instance among those, 0 if one varies


@dataclass
class CastLayout:
    """What `cast_accesses` needs from the snapshot, plus why anything was dropped."""
    by_class: dict = _dcfield(default_factory=dict)   # CastClass by class ref
    pool: dict = _dcfield(default_factory=dict)       # (Type, CastClass) by pool offset
    tts: dict = _dcfield(default_factory=dict)        # stub pc: the Types owning it
    defaults: frozenset = frozenset()  # pcs of the shared stubs whose body reads as one
    free: frozenset = frozenset()      # class ids no layout is read off (see `_cid_ok`)
    known: frozenset = frozenset()     # every class id the class table holds
    predefined: int = 0                # the VM's own ids, below the first user class
    smi_cid: int = -1
    null_cid: int = -1
    closed: int = 0            # classes no class implements, by Class::is_implemented
    implemented: int = 0       # ...and the ones some class does
    iface_checked: int = 0     # interface entries the table names, checked against it
    iface_unread: int = 0      # ...entries that are not a Type of a class it holds
    contradicted: int = 0      # classes whose implemented or abstract bit is contradicted
    allocated: int = 0         # classes owning an allocation stub, checked for the bit
    stats: dict = _dcfield(default_factory=dict)       # what the stub reading found
    refused: str = ""


def _cid_ok(c: int, cc: CastClass, casts: CastLayout) -> bool:
    """Whether a check accepting class id `c` is consistent with every value it lets
    through being null or an instance of `cc`: c is the class's own id or a subclass's,
    an id no layout is read off (null, a type no value has, an abstract class), or an id
    the class table leaves unused above the VM's own. An id the table does not hold BELOW
    them is a VM class this snapshot does not describe, and counts against the cast."""
    if c in cc.subclasses or c in casts.free:
        return True
    return c not in casts.known and c >= casts.predefined


def _stub_accepts(dis, smi_cid: int, null_cid: int):
    """What a type-testing stub's own code says about x0 where it returns: a tuple of
    inclusive class-id intervals, or None where the body does not read as a stub that
    tests x0 and returns, or tail-calls through the thread, and nothing else.

    Every path is followed, with the constraint its branches put on x0's class id: the
    Smi test of bit 0, the null test against NULL_REG (x22), and compares of the class id
    loaded from x0's header, `ldur xT, [x0, #-1]; ubfx xC, xT, #0xc, #0x14`, biased by a
    `sub`. A path that reaches `ret` adds its constraint to the answer. A path that ends
    in `br` through a word the thread holds, `ldr x16, [THR, #k]` or a Code loaded off
    the thread and its entry point, hands the instance to the runtime's check against the
    type in x8 and adds nothing. Anything else, a call, a branch out of the stub, a write
    to a register TypeTestABI preserves, refuses the stub: what it accepts is then not
    read, and nothing is proved through it."""
    if not dis or len(dis) > _STUB_MAX_INSNS:
        return None
    from . import expr as E
    at = {a: i for i, (a, _m, _o) in enumerate(dis)}
    full = ((0, _CID_TOP - 1),)
    accepted: list = []
    seen: set = set()
    work = [(0, (), full, None)]
    while work:
        state = work.pop()
        if state in seen:
            continue
        seen.add(state)
        if len(seen) > _STUB_MAX_STATES:
            return None
        i, regs, cons, flags = state
        if not cons:
            continue
        if i >= len(dis):
            return None
        a, mn, op = dis[i]
        ops = E._split_ops(op)
        R = dict(regs)

        def go(j, r=R, c=cons, f=flags):
            work.append((j, tuple(sorted(r.items())), c, f))

        if mn == "ret":
            accepted.append(cons)
            continue
        if mn == "b" or mn.startswith("b.") or mn in ("tbz", "tbnz", "cbz", "cbnz"):
            tgt = E._imm(ops[-1]) if ops else None
            if tgt not in at:
                return None
            if mn == "b":
                go(at[tgt])
            elif mn in ("tbz", "tbnz"):
                taken = None
                if E.canon(ops[0]) == "x0" and E._imm(ops[1]) == 0:
                    smi = ((smi_cid, smi_cid),)
                    taken = smi if mn == "tbz" else _cid_not(smi)
                go(at[tgt], c=_cid_and(cons, taken) if taken else cons)
                go(i + 1, c=_cid_and(cons, _cid_not(taken)) if taken else cons)
            elif mn in ("cbz", "cbnz"):
                go(at[tgt])
                go(i + 1)
            else:
                cond = mn[2:]
                if flags is None:
                    go(at[tgt])
                    go(i + 1)
                elif flags[0] == "const":
                    go(at[tgt] if _const_taken(cond, flags[1], flags[2]) else i + 1)
                else:
                    s = _cid_taken(cond, flags[1], flags[2])
                    if s is None:
                        return None
                    go(at[tgt], c=_cid_and(cons, s))
                    go(i + 1, c=_cid_and(cons, _cid_not(s)))
            continue
        if mn == "br":
            if R.get(E.canon(ops[0]) if ops else "", ("",))[0] in ("thr", "thrcode"):
                continue
            return None
        if mn in ("bl", "blr", "blx", "svc", "hvc", "brk"):
            if mn == "brk":
                continue                     # a trap: the path does not return
            return None
        defs = E._def_use(mn, op)[0]
        if defs & _TTS_KEEPS:
            return None
        if mn in ("ldr", "ldur", "ldrh", "ldurh") and len(ops) == 2:
            m = E._mem(ops[1])
            d = E.canon(ops[0])
            if m and m[2] is None and op.find("]!") < 0 and len(ops) == 2:
                base, disp = m[0], m[1]
                if base == "x0" and disp == -1 and mn in ("ldr", "ldur"):
                    R[d] = ("tags",)
                    go(i + 1)
                    continue
                if base == "x0" and disp == 1 and mn in ("ldrh", "ldurh"):
                    R[d] = ("cid", 0)
                    go(i + 1)
                    continue
                if base == "x26" and mn in ("ldr", "ldur") and ops[0][:1] == "x":
                    R[d] = ("thr", disp)
                    go(i + 1)
                    continue
                bv = R.get(base)
                if (bv and bv[0] == "thr" and disp == 7 and mn in ("ldr", "ldur")
                        and ops[0][:1] == "x"):
                    R[d] = ("thrcode", bv[1])
                    go(i + 1)
                    continue
        if mn == "ubfx" and len(ops) == 4:
            d, s = E.canon(ops[0]), E.canon(ops[1])
            if R.get(s) == ("tags",) and E._imm(ops[2]) == 0xc and E._imm(ops[3]) == 0x14:
                R[d] = ("cid", 0)
                go(i + 1)
                continue
        if mn in ("mov", "movz") and len(ops) == 2:
            d = E.canon(ops[0])
            k = E._imm(ops[1]) if ops[1].startswith("#") else None
            src = None if ops[1].startswith("#") else R.get(E.canon(ops[1]))
            R.pop(d, None)
            if k is not None:
                R[d] = ("const", k)
            elif src is not None and ops[0][:1] == ops[1][:1]:
                R[d] = src
            go(i + 1)
            continue
        if mn in ("add", "sub") and len(ops) in (3, 4):
            # A bias too wide for an immediate is moved into a register first, `mov x17,
            # #-0x1229; add x9, x9, x17`, so a register holding a constant is one too.
            d, s = E.canon(ops[0]), E.canon(ops[1])
            if ops[2].startswith("#"):
                k = E._imm(ops[2])
                if len(ops) == 4:
                    k = k << 12 if k is not None and ops[3].strip() == "lsl #12" else None
            else:
                kv = (R.get(E.canon(ops[2])) if len(ops) == 3 and ops[2][:1] == "x"
                      else None)
                k = kv[1] if kv and kv[0] == "const" else None
            sv = R.get(s)
            R.pop(d, None)
            if k is not None and sv is not None and sv[0] in ("cid", "const"):
                k = k if mn == "sub" else -k
                R[d] = (sv[0], sv[1] + k) if sv[0] == "cid" else ("const", sv[1] - k)
            go(i + 1)
            continue
        if mn == "cmp" and len(ops) in (2, 3):
            f = None
            if (len(ops) == 2 and E.canon(ops[0]) == "x0" and E.canon(ops[1]) == "x22"
                    and ops[0][:1] == ops[1][:1]):
                f = ("cid", null_cid, 0)   # NULL_REG: equal is exactly the null class id
            else:
                sv = R.get(E.canon(ops[0]))
                kv = R.get(E.canon(ops[1])) if len(ops) == 2 else None
                k = (_cmp_imm(ops, E) if ops[1].startswith("#")
                     else kv[1] if kv and kv[0] == "const" else None)
                if sv and k is not None and sv[0] in ("cid", "const"):
                    f = (sv[0], sv[1], k)
            go(i + 1, f=f)
            continue
        for r in defs:
            R.pop(r, None)
        go(i + 1, f=None if mn in _FLAG_WRITERS else flags)
    out: set = set()
    for c in accepted:
        out.update(c)
    return tuple(sorted(out))


def _cid_and(a, b):
    return tuple((max(l1, l2), min(h1, h2)) for l1, h1 in a for l2, h2 in b
                 if max(l1, l2) <= min(h1, h2))


def _cid_not(a):
    out, nxt = [], 0
    for lo, hi in sorted(a):
        if lo > nxt:
            out.append((nxt, lo - 1))
        nxt = max(nxt, hi + 1)
    if nxt < _CID_TOP:
        out.append((nxt, _CID_TOP - 1))
    return tuple(out)


def _cid_taken(cond: str, bias: int, k: int):
    """The class ids for which `cmp (cid - bias), #k` takes `b.<cond>`, or None for a
    condition not read. The subtraction is the machine's: below `bias` it wraps, so an
    unsigned compare is false there and a signed one true."""
    if cond == "eq":
        s = ((bias + k, bias + k),)
    elif cond == "ls":
        s = ((bias, bias + k),)
    elif cond in ("lo", "cc"):
        s = ((bias, bias + k - 1),)
    elif cond == "lt":
        s = ((0, bias + k - 1),)
    elif cond == "le":
        s = ((0, bias + k),)
    else:
        inv = {"ne": "eq", "hi": "ls", "hs": "lo", "cs": "cc", "ge": "lt", "gt": "le"}
        return _cid_not(_cid_taken(inv[cond], bias, k)) if cond in inv else None
    return tuple((max(0, lo), min(_CID_TOP - 1, hi)) for lo, hi in s
                 if min(_CID_TOP - 1, hi) >= max(0, lo))


def _cmp_imm(ops, E):
    """The immediate a `cmp xR, #k` or `cmp xR, #k, lsl #12` compares against, or None:
    a class id past 4095 is the second form, `cmp x9, #1, lsl #12` for class 4096."""
    k = E._imm(ops[1]) if ops[1].strip().startswith("#") else None
    if k is not None and len(ops) == 3:
        k = k << 12 if ops[2].strip() == "lsl #12" else None
    return k


def _const_taken(cond: str, c: int, k: int) -> bool:
    m = (1 << 64) - 1
    uc, uk = c & m, k & m
    return {"eq": c == k, "ne": c != k, "ls": uc <= uk, "hi": uc > uk, "lo": uc < uk,
            "cc": uc < uk, "hs": uc >= uk, "cs": uc >= uk, "lt": c < k, "le": c <= k,
            "gt": c > k, "ge": c >= k}.get(cond, False)


def recover_casts(image, fr, layout: FieldLayout) -> CastLayout:
    """The classes a cast proves a value's layout for, and the type-testing stubs.

    WHAT A CAST PROVES. An `as C`, an implicit downcast and a covariant parameter check
    compile to `AssertAssignable`: inline class-id checks that jump past the stub on the
    classes the compiler enumerated, then a call to the destination type's type-testing
    stub with the instance in x0 and the `Type` in x8 (TypeTestABI, the same registers
    from 2.19.6 to 3.13.0), which returns only when the value is assignable and throws
    otherwise (flow_graph_compiler.cc GenerateAssertAssignable, GenerateTTSCall). So past
    the call, and past every inline check that jumped to the same place, the value is null
    or an instance of a subtype of C.

    WHY THAT NAMES A SLOT ONLY FOR SOME C. A subtype that IMPLEMENTS C has a layout of
    its own; only one that EXTENDS it keeps C's fields at C's offsets. The VM records
    which is which: `ClassHiearchyUpdater::MarkImplemented` (class_finalizer.cc) sets
    `is_implemented` on every class some class lists as an interface or a mixin, and on
    each of its superclasses, so a class with the bit clear has no subtype that does not
    extend it. The compiler leans on exactly that: where the bit is clear the specialised
    stub reads the type arguments at C's own offset off any instance that passed
    (type_testing_stubs.cc:974). The bit is `Class::state_bits_`, which the serializer
    writes whole.

    THREE CROSS-CHECKS, each of which refuses rather than guesses.

    * Every class's `interfaces` array is read, and each interface it names, and that
      class's superclasses, must carry the implemented bit. One that does not refuses
      the whole channel, the rule `recover_fields` applies to an offset outside its
      owner: the bit and the arrays would then not mean what they are read to mean. So
      does a table whose arrays name no interface at all while classes carry the bit.
    * The abstract bit says which class ids no instance has, which a check may accept
      without counting against a cast. A class that owns an allocation stub has
      instances, so one of those carrying the bit refuses the channel too.
    * A type-testing stub specialised for one type is a Code object whose owner is that
      Type, and the compiler built its inline ranges from the same hierarchy this reads.
      So each one's own code is read (`_stub_accepts`): a stub that accepts a class id
      outside its class's subclasses (`_cid_ok`) refuses that class everywhere, since
      the compiler then knows a subtype this table does not. A stub whose code does not
      read proves nothing, and nor does a shared default stub whose code does not read
      as one, since only its name says what it is.

    The pool's `Type` objects are what x8 is loaded from, and `cast_accesses` checks the
    owner of a specialised stub against x8 at every call."""
    out = CastLayout()
    arch = getattr(image, "arch", None)
    if arch is None or getattr(arch, "name", None) != "arm64":
        out.refused = "the cast reader runs on arm64 only"
        return out
    epoch = getattr(image, "epoch", None)
    table = getattr(epoch, "cid_table", None)
    if table is None:
        out.refused = "no class id table for this release"
        return out
    from .disasm import disassemble_range, function_name_by_pc, pool_byte_offset
    cws = arch.compressed_word_size
    cls_cid = {ref: cid & 0xFFFFFFFF for ref, _n, cid, _s in fr.classes}
    by_cid = {cid: ref for ref, cid in cls_cid.items()}
    state = getattr(fr, "class_state", None) or {}
    ifaces = getattr(fr, "class_interfaces", None) or {}
    parent = {}
    for ref, _n, cid, sref in fr.classes:
        sup = fr.types.get(sref)
        p = by_cid.get(sup & 0xFFFFFFFF) if sup is not None else None
        if p is not None and p != ref:
            parent[ref] = p

    def chain(ref):
        seen = []
        while ref is not None and ref not in seen and len(seen) < 256:
            seen.append(ref)
            ref = parent.get(ref)
        return seen

    def implemented(ref):
        return bool(state.get(cls_cid[ref], 0) & _IMPLEMENTED)

    for ref in cls_cid:
        if implemented(ref):
            out.implemented += 1
        else:
            out.closed += 1
    for ref, iref in ifaces.items():
        arr = fr.arrays.get(iref)
        if not arr:
            continue
        for t in arr:
            tc = fr.types.get(t)
            y = by_cid.get(tc & 0xFFFFFFFF) if tc is not None else None
            if y is None:
                out.iface_unread += 1
                continue
            out.iface_checked += 1
            # MarkImplemented stops below Object, which has no superclass here.
            for z in chain(y):
                if parent.get(z) is None:
                    break
                if not implemented(z):
                    out.contradicted += 1
    abstract = {c for c in cls_cid.values() if state.get(c, 0) & _ABSTRACT_BIT}
    for _ref, owner, _ci in fr.codes:
        if owner in cls_cid and owner in image.code_ranges:
            out.allocated += 1
            if cls_cid[owner] in abstract:
                out.contradicted += 1
    if out.contradicted or (out.implemented and not out.iface_checked):
        why = (f"{out.contradicted} classes carry an implemented or abstract bit that "
               f"their interfaces or allocation stubs contradict" if out.contradicted
               else "no interface array was read to check the implemented bit against")
        return CastLayout(closed=out.closed, implemented=out.implemented,
                          iface_checked=out.iface_checked, allocated=out.allocated,
                          iface_unread=out.iface_unread, contradicted=out.contradicted,
                          refused=why)

    kids: dict = {}
    for c, p in parent.items():
        kids.setdefault(p, []).append(c)
    special = {table.get(n, -1) for n in _NOT_A_LAYOUT}
    out.smi_cid = table.get("SmiCid", -1)
    out.null_cid = table.get("NullCid", -1)
    out.known = frozenset(cls_cid.values())
    out.predefined = getattr(table, "num_predefined", 0) or 0
    out.free = frozenset(abstract | {table.get(n, -1) for n in _NO_LAYOUT_CIDS})

    def cast_class(ref):
        if ref in out.by_class:
            return out.by_class[ref]
        got = None
        if (ref in cls_cid and cls_cid[ref] not in special and not implemented(ref)
                and layout.class_name.get(ref)):
            subs, work, bound = set(), [ref], 0
            while work:
                c = work.pop()
                if cls_cid[c] in subs:
                    continue
                subs.add(cls_cid[c])
                work.extend(kids.get(c, ()))
                sizes = fr.class_sizes.get(cls_cid[c])
                size = sizes[0] * cws if sizes else 0
                bound = -1 if size <= 0 or bound < 0 else max(bound, size)
            m = layout.by_class.get(ref) or {}
            got = CastClass(class_ref=ref, name=layout.class_name[ref], cid=cls_cid[ref],
                            fields={off: fi.name for off, fi in m.items()},
                            subclasses=frozenset(subs), bound=max(bound, 0))
        out.by_class[ref] = got
        return got

    stats = out.stats

    def bump(k, n=1):
        stats[k] = stats.get(k, 0) + n

    # The specialised stubs, each read once however many Types own it.
    owners_at: dict = {}
    for _ref, owner, _ci in fr.codes:
        if owner in fr.types:
            cr = image.code_ranges.get(owner)
            if cr is not None:
                owners_at.setdefault(cr.pc_offset, (cr, set()))[1].add(owner)
    known_sorted = sorted(out.known | set(range(out.predefined)))
    leaky: set = set()
    for pc, (cr, owners) in owners_at.items():
        classes = {by_cid.get(fr.types[t] & 0xFFFFFFFF) for t in owners}
        mine = [cc for cc in map(cast_class, (c for c in classes if c is not None))
                if cc is not None]
        if not mine:
            continue
        got = _stub_accepts(disassemble_range(image, cr), out.smi_cid, out.null_cid)
        if got is None:
            bump("stubs of a closed class whose code does not read")
            continue
        bump("stubs of a closed class read")
        bad = set()
        for cc in mine:
            for lo, hi in got:
                k = bisect.bisect_left(known_sorted, lo)
                while k < len(known_sorted) and known_sorted[k] <= hi:
                    if not _cid_ok(known_sorted[k], cc, out):
                        bad.add(cc.class_ref)
                        break
                    k += 1
        if bad:
            bump("stubs accepting a class id outside their class")
            leaky |= bad
        else:
            out.tts[pc] = frozenset(owners)
    stats["classes refused by their own stub"] = len(leaky)
    # The shared stubs, which only their names say are type-testing stubs: each has to
    # read as one that accepts nothing but null itself and hands the rest to the runtime.
    nulls = ((out.null_cid, out.null_cid),)
    by_pc = {cr.pc_offset: cr for cr in image.all_ranges}
    defaults = set()
    for pc, nm in function_name_by_pc(image, fr).items():
        if not _TTS_STUB_RE.fullmatch(str(nm)):
            continue
        cr = by_pc.get(pc)
        got = _stub_accepts(disassemble_range(image, cr), out.smi_cid,
                            out.null_cid) if cr is not None else None
        if got is not None and _cid_and(got, _cid_not(nulls)) == ():
            defaults.add(pc)
        else:
            bump("shared stubs whose code does not read as one")
    out.defaults = frozenset(defaults)

    for idx, (kind, val) in enumerate(fr.pool):
        if kind != "ref" or val not in fr.types:
            continue
        cls = by_cid.get(fr.types[val] & 0xFFFFFFFF)
        cc = cast_class(cls) if cls is not None and cls not in leaky else None
        if cc is not None:
            out.pool[pool_byte_offset(idx, arch)] = (val, cc)
    out.by_class = {k: v for k, v in out.by_class.items()
                    if v is not None and k not in leaky}
    return out


#: The instructions that write the condition flags, so a compare before one of them no
#: longer decides the branch after it.
_FLAG_WRITERS = frozenset({"cmp", "cmn", "tst", "fcmp", "fcmpe", "ccmp", "ccmn", "fccmp",
                           "fccmpe", "adds", "subs", "ands", "bics", "negs", "adcs",
                           "sbcs", "ngcs"})


def cast_accesses(blocks, entry, casts: CastLayout, cross=None, moves=None, clash=(),
                  stats=None, proofs=None, slow=(), raw=None) -> dict:
    """{(instruction address, base register): CastClass} for every field access whose
    base a cast proves the class of, on every path to it.

    A forward must-analysis over the body's CFG, `_receiver_walk`'s shape with value
    numbers: each register and each frame slot holds a value number, a value number
    carries the classes a cast proved for it, and two paths meet by intersection, so a
    fact that reaches an access holds on every path there. A location that holds a
    different value on each path, each proven a class, holds a value proven that class,
    and gets a value number of the join's own (`meet`). It is seeded in two places and
    nowhere else:

      * the instruction after a call to a type-testing stub, for the value in x0, when
        x8 holds a pool `Type` of a class every subtype of which extends it
        (`recover_casts`). The stub is either one specialised for that very Type, a
        Code the Type in x8 owns, or a shared default stub; `recover_casts` has read
        the code of each, and one that did not read is not called a stub here. Or it
        is the one the Type in x8 holds, called through its entry point (`_INDIRECT`),
        the call a destination with type arguments gets.
      * an inline class-id check that jumps to the same instruction, `ldur xT, [xV,
        #-1]; ubfx xC, xT, #0xc, #0x14; [sub xC, xC, #lo;] cmp xC, #n; b.eq|b.ls`, for the
        value in xV, when every class id it accepts passes `_cid_ok`: the class's own, a
        subclass's, or one no layout is read off. An id outside that set is a
        counterexample, and the cast seeds nothing at all. The Smi test
        `LoadClassIdMayBeSmi` puts in front, `mov xC, #kSmiCid; tbz wV, #0`, is read as
        what it is, the class id of a Smi.

    The value is followed through register copies and through the frame slots it is
    spilled to and reloaded from, and forgotten wherever it is redefined, at a call for
    the registers a call may clobber, at a store that may write its slot, and at every
    move of the frame. A type-testing stub keeps only the registers TypeTestABI says it
    keeps, whether or not it proves anything. `cross`, `moves` and `clash` are
    `_frame_plan`'s: a store through SP forgets every frame slot `_frame_plan` says it may
    reach, the bytes the lifter drops for it (sixteen more either side where it writes
    back), one it cannot place forgets them all, and so does a move of FP. A block that
    something the CFG does not reach from the entry flows into, a catch handler or an
    unchecked entry, is entered knowing nothing, since the runtime enters those with a
    register file this does not see. The paths
    `strip_boilerplate` cut are not that, and are walked like any other: a stack check's
    slow path (`slow`, entered from the branch it turned into a nop) and the Mint path a
    box-or-tag check takes (entered from the `b` it made of a `b.eq`; `raw` holds both
    originals).

    An access the result then names has to fit: one at or past the largest instance
    size among the class's subclasses says the proof or the tracking is wrong, and the
    whole body is refused, the rule `_alloc_field` applies to an allocation.

    WHAT IT MAY COST. The walk sweeps the blocks in reverse postorder, so a sweep meets
    each edge once, and a fact carries the classes proven and not the casts that proved
    them unless `proofs` asks. Every state entry a meet reads or a redefinition scans is
    charged to a budget of `_CAST_WORK_PER_INSN` per instruction, and a body that spends
    it is declined with nothing named: the analysis costs at most a fixed multiple of
    the body's size, whatever a crafted body does to it.

    `proofs`, when handed a dict, gets {(address, base, byte offset): the call sites of
    the casts that proved it}, for measuring; the lifter does not ask."""
    from . import expr as E
    if not casts.pool:
        return {}
    if stats is None:
        stats = {}

    def bump(k, n=1):
        stats[k] = stats.get(k, 0) + n

    # Cheap refusals first: most bodies call no type-testing stub, and most of the rest
    # load no Type of a class with a map.
    sites = {}
    for b in blocks.values():
        for (a, mn, op, _note) in b.insns:
            if mn != "bl":
                continue
            tgt = E._imm(op.strip())
            if tgt in casts.tts:
                sites[a] = casts.tts[tgt]
            elif tgt in casts.defaults:
                sites[a] = None
        # The call a destination with type arguments gets, through the stub its Type
        # holds: `ldr x9, [x8, #7]; ldr x3, [PP, #k]; blr x9` (GenerateIndirectTTSCall,
        # flow_graph_compiler_arm64.cc). Offset 7 is `type_test_stub_entry_point_`, the
        # first field of an AbstractType (raw_object.h). Whether x8 holds a pool Type is
        # the walk's to check, at the call.
        for k, (a, mn, op, _note) in enumerate(b.insns):
            if mn != "blr" or k < 1:
                continue
            r = E.canon(op.strip())
            for (_a, mn2, op2, _n2) in reversed(b.insns[:k]):
                defs = E._def_use(mn2, op2)[0]
                if r in defs:
                    if mn2 in ("ldr", "ldur") and E.canon(op2.split(",", 1)[0]) == r:
                        m = E._mem(E._split_ops(op2)[1])
                        if m and m[0] == "x8" and m[1] == 7 and m[2] is None:
                            sites[a] = _INDIRECT
                    break
                if "x8" in defs:
                    break
    if not sites:
        return {}
    named = False
    hi: dict = {}
    for b in blocks.values():
        for (a, mn, op, note) in b.insns:
            if mn == "add" and ", x27, #" in op:
                ops = E._split_ops(op)
                if len(ops) >= 3 and E.canon(ops[1]) == "x27":
                    k = E._imm(ops[2]) or 0
                    wide = len(ops) == 4 and "lsl #12" in ops[3]
                    hi[E.canon(ops[0])] = k << 12 if wide else k
            elif mn == "ldr" and op.startswith("x8, ["):
                m = E._mem(E._split_ops(op)[1])
                off = None
                if m and m[2] is None and m[0] == "x27":
                    off = m[1]
                elif m and m[2] is None and m[0] in hi:
                    off = hi[m[0]] + m[1]
                got = casts.pool.get(off)
                if got is not None and got[1].fields:
                    named = True
    if not named:
        return {}
    bump("bodies")
    declined: set = set()
    size = sum(len(b.insns) for b in blocks.values())
    allowed = _CAST_WORK_PER_INSN * max(size, 1)
    budget = [allowed]
    for _ in range(4):
        try:
            got = _cast_pass(blocks, entry, casts, sites, declined, cross or {},
                             moves or {}, frozenset(clash or ()), stats, E,
                             frozenset(slow or ()), raw or {}, budget,
                             proofs is not None)
        except _OverBudget:
            bump("refused, over the work budget")
            return {}
        finally:
            stats["work"] = allowed - budget[0]
            stats["size"] = size
        if got is None:
            bump("refused, no fixpoint")
            return {}
        out, again = got
        if not again:
            break
        declined |= again
    else:
        return {}
    for (a, base, off), (cc, _why) in out.items():
        if cc.bound and off >= cc.bound:
            bump("refused, an access past every subclass")
            return {}
    if proofs is not None:
        proofs.update({k: why for k, (_cc, why) in out.items()})
    return {(a, base): cc for (a, base, _off), (cc, _why) in out.items()}


def _cast_pass(blocks, entry, casts, sites, declined, cross, moves, clash, stats, E,
               slow=frozenset(), raw=None, budget=None, track=False):
    """One run of the analysis `cast_accesses` describes. Returns ({(addr, base, byte
    offset): (CastClass, the sites proving it)}, the call sites a counterexample
    declines), or None.

    A value number's facts are a frozenset of (class ref, call site) pairs: two paths
    keep a class both prove, with the sites of either, so the class is what holds and
    the sites say where it came from. Only where `track` asks, for measuring: otherwise
    every site is 0, so a fact is one pair per class however many casts prove it.

    Every entry a meet reads and a redefinition scans is charged to `budget`, and
    `_OverBudget` ends the walk once it is spent."""
    # The registers a cast proves nothing about: the untagged roles, and the null
    # register, a tagged object that passes a nullable cast and has none of the class's
    # fields. It left the untagged set in #330 and is kept out of this walk by name.
    fixed = E._UNTAGGED | {r for r, role in E.ROLE.items() if role == "NULL"}

    def charge(n):
        budget[0] -= n
        if budget[0] < 0:
            raise _OverBudget()

    by_class = casts.by_class
    joins = {a + 4: a for a in sites if a not in declined}
    preds = {a: [] for a in blocks}
    for a, b in blocks.items():
        for s in b.succ:
            if s in preds:
                preds[s].append(a)
    # The edges `strip_boilerplate` cut, put back: from the instruction it rewrote to the
    # path that instruction branched to, with the state at that instruction.
    raw = raw or {}
    side: dict = {}
    for b, blk in blocks.items():
        for (a, mn, _op, _n) in blk.insns:
            was = raw.get(a, ("", ""))
            tgt = None
            if mn == "nop" and E.cond_of(was[0]):
                t = E._target(was[1].rsplit(",", 1)[-1]) if was[1] else None
                tgt = t if t in slow else None
            elif mn == "b" and was[0] in ("b.eq", "b.ne"):
                tgt = a + 4
            if tgt in blocks:
                side.setdefault(b, {})[a] = tgt
                preds[tgt].append(b)
    reach, todo = set(), [entry]
    while todo:
        x = todo.pop()
        if x in reach or x not in blocks:
            continue
        reach.add(x)
        todo.extend(blocks[x].succ)
        todo.extend(side.get(x, {}).values())
    found: set = set()
    seeds: dict = {}
    nothing = ({}, {}, {}, None, frozenset())

    def bump(k, n=1):
        stats[k] = stats.get(k, 0) + n

    def step(state, here, record):
        insns = blocks[here].insns
        charge(len(insns))
        locs, facts, sym, flags, fptr = state
        locs, facts, sym, fptr = dict(locs), dict(facts), dict(sym), set(fptr)
        cur = [flags]

        def purge(vn):
            charge(len(locs) + len(sym))
            for k in [k for k, v in locs.items() if v == vn]:
                del locs[k]
            facts.pop(vn, None)
            for k in [k for k, v in sym.items() if len(v) > 1 and v[1] == vn]:
                del sym[k]

        def define(r, a):
            vn = ("d", a, r)
            purge(vn)
            locs[r] = vn
            sym.pop(r, None)
            fptr.discard(r)
            return vn

        def get(r, a):
            v = locs.get(r)
            if v is None:
                v = ("u", a, r)
                purge(v)
                locs[r] = v
            return v

        def clobber(defs, a):
            for r in defs:
                if r[:1] == "x":
                    define(r, a)

        def kill_range(lo, hi):
            for k in [k for k in locs if isinstance(k, int) and k < hi and k + 8 > lo]:
                del locs[k]

        def tts(a, seed):
            # TypeTestABI: the stub hands back x0, x1, x2 and x8 and nothing else, and
            # the flags are its own.
            for r in [r for r in locs if isinstance(r, str) and r not in _TTS_KEEPS]:
                del locs[r]
            for r in [r for r in sym if r not in _TTS_KEEPS]:
                del sym[r]
            fptr.difference_update([r for r in fptr if r not in _TTS_KEEPS])
            cur[0] = None
            if not seed:
                return
            seeds[a] = None
            if a in declined:
                return
            pv = sym.get("x8")
            pool = casts.pool.get(pv[1]) if pv and pv[0] == "pool" else None
            owners = sites[a]
            if pool is None:
                if record:
                    bump("tts calls whose type is not a closed class"
                         if pv and pv[0] == "pool"
                         else "tts calls whose x8 is not read off the pool")
                return
            if owners is not None and owners is not _INDIRECT and pool[0] not in owners:
                if record:
                    bump("CX: a specialised stub of another type than x8's")
                return
            if record:
                bump("tts calls seeding a class")
                if owners is _INDIRECT:
                    bump("...through the stub x8's own Type holds")
                elif owners is not None:
                    bump("...through a specialised stub its x8 Type owns")
            seeds[a] = pool[1]
            v = get("x0", a)
            facts[v] = (facts.get(v, frozenset())
                        | {(pool[1].class_ref, a if track else 0)})

        def memory(a, mn, op, ops, defs):
            got = E._addr(ops)
            load = mn in E._LOADS
            pair = mn in ("ldp", "ldpsw", "stp")
            regs = [E.canon(o) for o in ops[:2 if pair else 1]]
            if got is None or got[1] is E._BAD_POST:
                clobber(defs, a)
                if not load:
                    kill_range(-1 << 62, 1 << 62)
                return
            (base, disp, index, _scale, wb), post = got
            kind = ops[0].strip()[:1]
            w = 4 if kind in ("w", "s") else 16 if kind == "q" else 8
            if mn in ("ldrb", "ldurb", "strb", "sturb", "ldrsb", "ldursb"):
                w = 1
            elif mn in ("ldrh", "ldurh", "strh", "sturh", "ldrsh", "ldursh"):
                w = 2
            n = w * (2 if pair else 1)
            plain = index is None and not wb and not post
            if base == "x29" and plain:
                if not load:
                    kill_range(disp, disp + n)
                for i, r in enumerate(regs):
                    whole = w == 8 and ops[i].strip()[:1] == "x" and r != "xzr"
                    slot = disp + i * w
                    if not load:
                        if whole:
                            locs[slot] = get(r, a)
                    elif not whole:
                        clobber((r,), a)
                    elif slot in locs:
                        v = locs[slot]
                        sym.pop(r, None)
                        fptr.discard(r)
                        locs[r] = v
                    else:
                        locs[slot] = define(r, a)
                return
            if base == "x15" or base == "x29" or base in fptr:
                # Through SP, the stores `_frame_plan` placed against FP forget what they
                # may write; any other frame address this cannot place forgets it all.
                if not load:
                    c = cross.get(a) if base == "x15" else None
                    if c is None:
                        kill_range(-1 << 62, 1 << 62)
                    elif plain:
                        # The bytes `Lifter._cross_write` drops for the same store.
                        at, slack = c
                        kill_range(at + disp - slack, at + disp + n)
                    else:
                        # A write-back moved SP first, and `cross` is placed after it.
                        at, slack = c
                        kill_range(at + disp - slack - 16, at + disp + n + 16)
                clobber([r for r in defs if r != "x15"], a)
                return
            if base == "x27" or sym.get(base, ("",))[0] == "pp":
                off = disp if base == "x27" else sym[base][1] + disp
                clobber(defs, a)
                if load and not pair and plain:
                    sym[regs[0]] = ("pool", off)
                return
            bv = locs.get(base)
            if (record and bv is not None and plain and disp >= -1
                    and base not in fixed):
                cs = facts.get(bv)
                if cs:
                    found.add((a, base, disp + 1, cs))
                    if pair:
                        found.add((a, base, disp + 1 + w, cs))
            clobber(defs, a)
            if load and not pair and plain and bv is not None:
                if disp == -1 and w == 8:
                    sym[regs[0]] = ("tags", bv)
                elif disp == 1 and w == 2 and mn in ("ldrh", "ldurh"):
                    sym[regs[0]] = ("cid", bv)
            pv = sym.get(base) if base == "x8" else None
            if (load and not pair and plain and disp == 7 and w == 8 and pv
                    and pv[0] == "pool"):
                sym[regs[0]] = ("ttsentry", pv[1])

        def one(a, mn, op, note):
            ops = E._split_ops(op)
            defs = E._def_use(mn, op)[0]
            if mn == "bl":
                if a in sites:
                    tts(a, True)
                    return defs
                name = note.split("-> ", 1)[1].strip() if "-> " in note else ""
                if "_iso_stub_" in name and "TypeTest" in name:
                    tts(a, False)              # one this does not read: no proof
                    return defs
                if "_iso_stub_" in name and E._classify_stub(name)[0] == "suppress":
                    defs = frozenset({"x16", "x17", "x30"})
                cur[0] = None
                clobber(defs, a)
                return defs
            if mn in ("blr", "blx", "br"):
                pv, ep = sym.get("x8"), sym.get(E.canon(op.strip()))
                if (sites.get(a, 0) is _INDIRECT and pv and pv[0] == "pool"
                        and ep == ("ttsentry", pv[1])):
                    tts(a, True)
                    return defs
                cur[0] = None
                clobber(defs, a)
                return defs
            if mn in E._LOADS or mn in E._STORES:
                memory(a, mn, op, ops, defs)
                return defs
            if mn in ("mov", "movz") and len(ops) == 2:
                d, src = E.canon(ops[0]), ops[1].strip()
                if src.startswith("#"):
                    k = E._imm(src)
                    define(d, a)
                    if k is not None and ops[0].strip()[:1] == "x":
                        sym[d] = ("const", k)
                    return defs
                s = E.canon(src)
                if mn == "mov" and ops[0].strip()[:1] == "x" and src[:1] == "x":
                    if s in ("x29", "x15") or s in fptr:
                        define(d, a)
                        fptr.add(d)
                        return defs
                    if s not in fixed and d not in fixed:
                        v = get(s, a)
                        sym.pop(d, None)
                        fptr.discard(d)
                        locs[d] = v
                        if s in sym:
                            sym[d] = sym[s]
                        return defs
            if mn in ("add", "sub") and len(ops) >= 3:
                d, s = E.canon(ops[0]), E.canon(ops[1])
                if s == "x27" and ops[2].strip().startswith("#"):
                    k = E._imm(ops[2]) or 0
                    define(d, a)
                    sym[d] = ("pp", k << 12 if len(ops) == 4 and "lsl #12" in ops[3]
                              else k)
                    return defs
                if s in ("x29", "x15") or s in fptr:
                    define(d, a)
                    if d not in ("x29", "x15"):
                        fptr.add(d)
                    return defs
                k = None
                if ops[2].strip().startswith("#"):
                    k = E._imm(ops[2])
                    if k is not None and len(ops) == 4:
                        k = k << 12 if ops[3].strip() == "lsl #12" else None
                elif len(ops) == 3 and sym.get(E.canon(ops[2]), ("",))[0] == "const":
                    k = sym[E.canon(ops[2])][1]
                sv = sym.get(s)
                define(d, a)
                if k is not None and sv is not None:
                    k = -k if mn == "sub" else k
                    if sv[0] == "cid":
                        sym[d] = ("cidsub", sv[1], -k)
                    elif sv[0] == "cidsub":
                        sym[d] = ("cidsub", sv[1], sv[2] - k)
                    elif sv[0] == "const":
                        sym[d] = ("const", sv[1] + k)
                return defs
            if mn == "ubfx" and len(ops) == 4:
                d, s = E.canon(ops[0]), E.canon(ops[1])
                sv = sym.get(s)
                define(d, a)
                if (sv and sv[0] == "tags" and E._imm(ops[2]) == 0xc
                        and E._imm(ops[3]) == 0x14):
                    sym[d] = ("cid", sv[1])
                return defs
            if mn == "cmp" and len(ops) in (2, 3):
                c0, c1 = E.canon(ops[0]), E.canon(ops[1])
                sv = sym.get(c0)
                if ops[1].strip().startswith("#"):
                    k = _cmp_imm(ops, E)
                else:
                    kv = sym.get(c1)
                    k = kv[1] if kv and kv[0] == "const" else None
                cur[0] = ((sv, k) if sv and sv[0] in ("cid", "cidsub") and k is not None
                          else None)
                return defs
            if mn in _FLAG_WRITERS:
                cur[0] = None
            clobber(defs, a)
            return defs

        cut = side.get(here, {})
        exits = {}
        for (a, mn, op, note) in insns:
            if a in cut:
                exits[cut[a]] = (dict(locs), dict(facts), dict(sym), None,
                                 frozenset(fptr))
            if mn == "nop":
                continue
            defs = one(a, mn, op, note)
            if "x29" in defs or (a in moves and moves[a][0]):
                kill_range(-1 << 62, 1 << 62)
        return (locs, facts, sym, cur[0], frozenset(fptr)), exits

    def edge(state, src, dst, record):
        """The state on the edge from src to dst: a cid check's verdict, a Smi test's."""
        last = blocks[src].insns[-1] if blocks[src].insns else None
        if last is None:
            return state
        a, mn, op, _n = last
        ops = E._split_ops(op)
        tgt = E._target(ops[-1]) if ops else None
        if tgt is None or len(set(blocks[src].succ)) < 2:
            return state
        taken = dst == tgt
        locs, facts, sym, flags, fptr = state
        if mn in ("tbz", "tbnz") and len(ops) == 3 and E._imm(ops[1]) == 0:
            v = locs.get(E.canon(ops[0]))
            smi = taken if mn == "tbz" else not taken
            if v is not None and smi and casts.smi_cid >= 0:
                sym = {k: (("cid", v) if s == ("const", casts.smi_cid) else s)
                       for k, s in sym.items()}
                return locs, facts, sym, flags, fptr
            return state
        if flags is None or mn not in ("b.eq", "b.ne", "b.ls", "b.hi"):
            return state
        accept = taken if mn in ("b.eq", "b.ls") else not taken
        if not accept or dst not in joins:
            return state
        site = joins[dst]
        cc = seeds.get(site)
        if cc is None:
            return state
        (kind, v, *rest), n = flags
        lo = rest[0] if kind == "cidsub" else 0
        eq = mn in ("b.eq", "b.ne")
        ids = range(lo + n, lo + n + 1) if eq else range(lo, lo + n + 1)
        if len(ids) > 1 << 16:
            return state
        bad = [c for c in ids if not _cid_ok(c, cc, casts)]
        if record:
            bump("cid edges into a cast")
        if bad:
            if record:
                bump("CX: a cid edge accepts a class outside the subclasses")
            again.add(site)
            return state
        if v not in locs.values():
            return state
        facts = dict(facts)
        facts[v] = facts.get(v, frozenset()) | {(cc.class_ref, site if track else 0)}
        return locs, facts, sym, flags, fptr

    def proven(cs, o):
        common = {c for c, _s in cs} & {c for c, _s in o}
        return frozenset(p for p in cs | o if p[0] in common)

    def meet(x, y, at):
        lx, fx, sx, gx, px = x
        ly, fy, sy, gy, py = y
        charge(len(lx) + len(ly) + len(fx) + len(fy) + len(sx))
        locs = {k: v for k, v in lx.items() if ly.get(k) == v}
        # A location that holds a different value on each path, each proven the same
        # class, holds a value proven that class all the same: two casts on two paths,
        # or a copy on one and a reload of the spill on the other. It gets a value number
        # of its own, this join's, and whatever held that number before held an older
        # value under it and is forgotten, its facts and its symbols with it.
        phis = {}
        for k, v in lx.items():
            w = ly.get(k)
            if w is not None and w != v and fx.get(v) and fy.get(w):
                got = proven(fx[v], fy[w])
                if got:
                    phis[k] = got
        stale = {("phi", at, k) for k in phis}
        locs = {k: v for k, v in locs.items() if v not in stale}
        held = set(locs.values())
        facts = {}
        for vn, cs in fx.items():
            o = fy.get(vn)
            if o and vn in held:
                got = proven(cs, o)
                if got:
                    facts[vn] = got
        for k, got in phis.items():
            locs[k] = ("phi", at, k)
            facts[("phi", at, k)] = got
        sym = {k: v for k, v in sx.items() if sy.get(k) == v
               and not (len(v) > 1 and v[1] in stale)}
        flags = gx if gx == gy and not (gx and gx[0][1:2] and gx[0][1] in stale) else None
        return locs, facts, sym, flags, px | py

    # Sweeps in reverse postorder, each block's state the meet of its predecessors' at
    # the time it is reached, until a sweep changes nothing. A predecessor not yet
    # walked is left out, the optimistic start a must-analysis takes; every one is walked
    # in the first sweep, so each later sweep meets each edge once.
    order, seen, todo = [], set(), [(entry, False)]
    while todo:
        x, done = todo.pop()
        if done:
            order.append(x)
            continue
        if x in seen or x not in blocks:
            continue
        seen.add(x)
        todo.append((x, True))
        nxt = list(blocks[x].succ) + list(side.get(x, {}).values())
        todo.extend((y, False) for y in reversed(nxt) if y in blocks and y not in seen)
    order.reverse()
    again: set = set()
    IN, OUT, EXITS = {}, {}, {}
    for _sweep in range(_CAST_SWEEPS):
        changed, before = False, dict(seeds)
        for a in order:
            ins = [edge(OUT[p], p, a, False) for p in preds[a]
                   if p in OUT and a in blocks[p].succ]
            ins += [EXITS[p][a] for p in preds[a] if a in EXITS.get(p, {})]
            # The entry is entered with nothing known, and so is a block a path the
            # entry does not reach flows into.
            if a == entry or any(p not in reach for p in preds[a]):
                ins.append(nothing)
            if not ins:
                continue
            new = ins[0]
            for x in ins[1:]:
                new = meet(new, x, a)
            IN[a] = new
            st = new
            if a in clash:
                st = (({k: v for k, v in st[0].items() if not isinstance(k, int)},)
                      + st[1:])
            out, exits = step(st, a, False)
            if OUT.get(a) != out or EXITS.get(a) != exits:
                OUT[a], EXITS[a], changed = out, exits, True
        if not changed and seeds == before:
            break
    else:
        return None
    again.clear()
    for a in sorted(blocks):
        st = IN.get(a)
        if st is None:
            continue
        if a in clash:
            st = ({k: v for k, v in st[0].items() if not isinstance(k, int)},) + st[1:]
        st, _exits = step(st, a, True)
        for s in blocks[a].succ:
            if s in blocks:
                edge(st, a, s, True)
    out = {}
    for (a, base, off, cs) in found:
        classes = {by_class[c] for c, _s in cs if c in by_class}
        # Two casts of one value to two classes: one extends the other, and the deeper
        # one's map is the larger. Two that do not are a contradiction, and name nothing.
        deep = [c for c in classes
                if all(o is c or cast_extends(c, o) for o in classes)]
        if len(deep) != 1:
            bump("CX: one value, two unrelated classes")
            continue
        out[(a, base, off)] = (deep[0], tuple(sorted(s for c, s in cs
                                                     if c == deep[0].class_ref)))
    if again - declined:
        return out, again - declined
    return out, set()


def cast_extends(c: CastClass, o: CastClass) -> bool:
    """True when class `c` extends class `o`: every class extending c extends o, c's own
    id among them."""
    return c.subclasses <= o.subclasses


@kept
def lift_tables(image, fr, accessors: bool) -> tuple:
    """(layout, allocs, casts): the three tables tier 3 reads beside the selectors.

    `accessors` folds the implicit accessors' names into the field layout before the
    other two are built over it, which is what `lift` and `ffi` have always done and
    `decompile` has not. The two are kept apart, in a `jadart serve` session as well,
    so neither command's output moves (keep.py)."""
    layout = recover_fields(fr, getattr(image, "arch", None))
    if accessors:
        layout.add_accessor_names(recover_accessors(image, fr, layout))
    allocs = recover_allocations(image, fr, layout)
    return layout, allocs, recover_casts(image, fr, layout)
