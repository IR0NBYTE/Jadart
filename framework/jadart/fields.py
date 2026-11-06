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
method whose owner class resolves is one such base, and `recover_allocations` below adds a
second. Everything else stays `field_0x8`, because a name attributed to the wrong class is
worse than an offset: the reader can see that an offset is opaque and cannot see that a
name is wrong.
"""
from __future__ import annotations

import re
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
    return out


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
