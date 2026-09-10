"""Version / format-epoch resolution.

A snapshot's 32-char version hash (MD5 of the VM snapshot source files) identifies a
"format epoch": the cid table, tag-bit layout, and cluster grammar. The hash alone does
NOT identify the parse profile, because a BUILD FLAG selects part of the cluster grammar.
`Deserializer::ReadCluster` gates on `#if !defined(DART_COMPRESSED_POINTERS)`
(app_snapshot.cc:9391) and routes String, PcDescriptors, CodeSourceMap and
CompressedStackMaps to RODataDeserializationCluster, whose ReadFill is empty and whose
payload lives in the data image instead of the stream.

So one hash covers structurally incompatible profiles. Measured on this corpus, the arm64,
x64 and arm32 builds of one app all carry hash ace654289f5abc240509fc941453ebc5, but arm32
is `no-compressed-pointers` and needs a different fill grammar. The profile key is
therefore (hash, architecture, pointer model), not the hash alone.

That's correctness, not tidiness. The alloc-pass self-check (`assigned == num_objects`)
PASSES on the arm32 blob under the compressed profile, because
RODataDeserializationCluster::ReadAlloc also reads exactly one varint per object. jadart
would walk 437 clusters "successfully" and only fail later, in the fill pass. Resolving the
target up front turns that silent wrongness into an immediate rejection that says why.

Design rule, and the main fix over unflutter: never parse with a guessed profile. An
unknown hash returns None and the caller fails loud with UnknownEpoch; a known hash on a
target we have no grammar for raises UnsupportedTarget naming the offending token.
"""
from __future__ import annotations

from .errors import JadartError

from dataclasses import dataclass, field

from .cidtables import ERA_2_19, ERA_3_0, ERA_3_1, ERA_3_4, ERA_3_6, ERA_3_9, CidTable


@dataclass
class TagLayout:
    """How a cluster tag encodes its cid, and how wide the read is.

    Dart 3.4 changed this outright rather than moving a bit. Before it, ReadCluster read a
    uint64 holding `cid << 1 | is_canonical` and there was no immutable flag at all; from
    3.4 the cluster tag IS an object header word, so the cid moved into ClassIdTag's field
    and canonical/immutable became their own bits. That is the boundary the epoch names
    refer to."""

    # bit positions in the 32-bit object/cluster tag word (raw_object.h)
    cid_shift: int = 12
    cid_bits: int = 20
    canonical_bit: int = 1
    immutable_bit: int = 7
    # "objectheader" (3.4+) or "cid_and_canonical" (3.3 and earlier)
    packing: str = "objectheader"

    @property
    def wide(self) -> bool:
        """True when the tag is read as a uint64 rather than a uint32."""
        return self.packing == "cid_and_canonical"

    def decode(self, tag: int):
        if self.packing == "cid_and_canonical":
            # app_snapshot.cc @3.3: cid = (v >> 1) & kMaxUint32, canonical = v & 1.
            return (tag >> 1) & 0xFFFFFFFF, bool(tag & 1), False
        cid = (tag >> self.cid_shift) & ((1 << self.cid_bits) - 1)
        canonical = bool((tag >> self.canonical_bit) & 1)
        immutable = bool((tag >> self.immutable_bit) & 1)
        return cid, canonical, immutable


class UnsupportedTarget(JadartError):
    """The format epoch is recognised but this TARGET has no cluster grammar.

    Different from UnknownEpoch: there the version itself is unknown; here the version is
    known and the architecture or pointer model isn't covered. Raised before any snapshot
    bytes are consumed, so a mismatched profile can never start a walk."""


# Architectures the features string can name (dart.cc emits "<arch> <os> <pointer model>").
# word_size is the target word in bytes. `compressed` comes from the features string, not
# from the arch: android arm64/x64 are compressed, iOS arm64 and android arm32 are not.
_ARCH_WORDS = {"arm64": 8, "x64": 8, "arm": 4, "riscv32": 4, "riscv64": 8, "ia32": 4}


@dataclass(frozen=True)
class Arch:
    """The target half of a parse profile."""
    name: str
    word_size: int
    compressed: bool

    @property
    def compressed_word_size(self) -> int:
        """Size of an in-object pointer slot; instance field offsets are counted in these."""
        return 4 if self.compressed else self.word_size

    @property
    def object_alignment_log2(self) -> int:
        """kObjectAlignmentLog2: objects align to 2 words. RODataDeserializationCluster
        stores its running offset pre-shifted by this (app_snapshot.cc:3755)."""
        return (2 * self.word_size).bit_length() - 1

    @property
    def read32_per_word(self) -> int:
        """How many 32-bit reads make one word in the stream.

        An unboxed instance field is written with ReadWordWith32BitReads, whose loop count
        is kBitsPerWord / kBitsPerInt32 (datastream.h): two on a 64-bit target, one on a
        32-bit one. Assuming two everywhere reads four bytes too many per unboxed field and
        desyncs the fill from the first object that has one."""
        return self.word_size // 4

    @property
    def instance_header_words(self) -> int:
        """Header slots to skip before an instance's first field.

        The header is UntaggedObject's `uword tags_`, so it is one target word: eight bytes
        on a 64-bit target and four on a 32-bit one. Field offsets are counted in
        pointer slots, which is what makes a 64-bit compressed object's header two slots
        while an uncompressed one's is a single slot either way."""
        return self.word_size // self.compressed_word_size

    @property
    def rodata_clusters(self) -> bool:
        """True when String/PcDescriptors/CodeSourceMap/CompressedStackMaps deserialize as
        RODataDeserializationCluster: payload in the data image, empty ReadFill
        (app_snapshot.cc:9391). The pointer model selects this, not the architecture."""
        return not self.compressed

    @property
    def grammar_key(self) -> tuple:
        """What the cluster grammar depends on. arm64 and x64 android share one key, which
        is why the snapshot layer already parses x64 unmodified."""
        return (self.word_size, self.compressed)

    def __str__(self) -> str:
        return f"{self.name}/{'compressed' if self.compressed else 'uncompressed'}-pointers"


def parse_features(features: str) -> dict:
    """Decode the snapshot features string into the flags that select a parse profile.
    dart.cc appends "<arch> <os> <compressed-pointers|no-compressed-pointers>"."""
    tokens = features.split()
    arch_name = next((t for t in tokens if t in _ARCH_WORDS), None)
    if arch_name is None:
        # Older releases wrote the target as <arch>-<abi>: "arm64-sysv", "arm-eabi". An
        # in-the-wild 2021 build reads `... arm64-sysv no-null-safety` and nothing matched,
        # so even the architecture was lost and `info` could not name the target.
        for t in tokens:
            head = t.split("-", 1)[0]
            if head in _ARCH_WORDS:
                arch_name = head
                break
    compressed = None
    if "compressed-pointers" in tokens:
        compressed = True
    if "no-compressed-pointers" in tokens:
        compressed = False
    return {
        "arch": arch_name,
        "compressed": compressed,
        "os": next((t for t in tokens
                    if t in ("android", "ios", "macos", "linux", "windows", "fuchsia")), None),
        "product": "product" in tokens,
        "dwarf_stack_traces": "dwarf_stack_traces_mode" in tokens,
        "tokens": tokens,
    }


@dataclass(frozen=True)
class Profile:
    """A fully-resolved parse profile: the format epoch plus the target it was built for."""
    epoch: "Epoch"
    arch: Arch


@dataclass
class Epoch:
    name: str            # human label
    dart: str            # Dart SDK version(s), best-effort
    tag: TagLayout = field(default_factory=TagLayout)
    # cid -> class-name numbering. Cluster routing is written against class NAMES, which are
    # stable, while the numbers behind them are not, so the table has to come from the epoch
    # rather than from one bundled module.
    cid_table: CidTable = ERA_3_9
    num_predefined_cids: int = 0   # 0 = unknown; boundary for user classes
    # typed-data cid family layout (varies per epoch; class additions shift it).
    # internal typed-data cids are [td_int8..td_byte_data_view) with stride td_stride,
    # remainder 0 = internal (variable-size), other remainders = view/external.
    td_int8_cid: int = 0
    td_byte_data_view_cid: int = 0
    td_stride: int = 4
    # ObjectPool entry bits. From 3.3 the byte packs TypeBits(0..3), PatchableBit(4) and
    # SnapshotBehaviorBits(5..7); before that TypeBits is 7 bits wide with PatchableBit at
    # 7, and two entry types that 3.3 dropped, kSwitchableCallMissEntryPoint and
    # kMegamorphicCallEntryPoint, are still in the enum. Note this boundary is 3.2/3.3,
    # one release off the cluster-tag boundary at 3.3/3.4: the format's moving parts do not
    # change together, which is why each gets its own switch instead of one "old/new" flag.
    objpool_has_behavior: bool = True
    # ObjectPool::EntryType numbering. 3.1 orders it kTaggedObject=0, kImmediate=1; 3.2
    # swapped the two. Nothing about the encoding's SHAPE changes, so every byte-count
    # check still agrees, a tagged entry is just spelled 0x80 instead of 0x81, and reading
    # it the other way round treats a ref id as a signed immediate. That is a third boundary
    # in this one byte, at 3.1/3.2, distinct from the SnapshotBehavior change at 3.2/3.3.
    objpool_tagged_first: bool = False
    # Record layout. From 3.0 the cluster reads a packed RecordShape whose low 16 bits are
    # the field count. 2.19 instead reads a plain field count followed by a field_names
    # array ref, so the same leading varint means a different thing and there is one extra
    # ref per record.
    record_has_field_names: bool = False
    # Where TypeClassIdBits starts in UntaggedAbstractType.flags_. The field sits above
    # NullabilityBits and TypeStateBits, and NULLABILITY CHANGED WIDTH AT 3.5: it is
    # `BitField<uint32_t, uint8_t, 0, 2>` through 3.4.4 and `BitField<..., 0, 1>` from
    # 3.5.4 (raw_object.h, UntaggedAbstractType). TypeStateBits is 2 wide either way and
    # `kTypeClassIdShift = TypeStateBits::kNextBit`, so the shift is 4 on <=3.4 and 3 from
    # 3.5. jadart hardcoded 3 everywhere, decoding every Type one bit off on six of the
    # fifteen supported epochs. It did not fail loudly, it just resolved fewer
    # superclasses: measured 47.3% on 2.19.6 against 55.8% once corrected, and every epoch
    # lands on the same ~56% plateau afterwards, which is what makes this the right shift
    # rather than merely a better one.
    type_class_id_shift: int = 3
    # Per-cluster fill-spec overrides, same shape as fillwalk._REFS. A class can change how
    # many refs it serializes without app_snapshot.cc changing a line, because the range is
    # `VISIT_FROM .. to_snapshot(kFullAOT)` in raw_object.h and that cutoff moves on its own
    # Library declares fifteen pointers and serializes ten. So the base table holds the
    # 3.2+ shape and an older epoch states its differences here.
    fill_overrides: dict = field(default_factory=dict)
    # (word_size, compressed) combinations this epoch's cluster grammar covers.
    # Declaring it lets an unsupported target be rejected instead of mis-parsed.
    grammars: frozenset = frozenset({(8, True)})
    notes: str = ""

    def typed_data_kind(self, cid: int) -> str | None:
        """'internal' | 'view_or_external' | None, per this epoch's typed-data range."""
        if not self.td_int8_cid or cid < self.td_int8_cid or cid >= self.td_byte_data_view_cid:
            return None
        return "internal" if (cid - self.td_int8_cid) % self.td_stride == 0 else "view_or_external"


# hash -> Epoch. Seeded with what we have measured; grow over time.
# The hash is a pure function of VM source bytes, so different Dart versions
# with identical snapshot files can share a hash. Keep this a "format epoch"
# map, not a strict SDK-version map, and refine with features.
_EPOCHS: dict[str, Epoch] = {
    # measured from a Flutter 3.44.4 / Dart 3.12.2 release build (arm64).
    "ace654289f5abc240509fc941453ebc5": Epoch(
        name="objectheader-3.12",
        dart="3.12.2",
        tag=TagLayout(cid_shift=12, cid_bits=20, canonical_bit=1, immutable_bit=7),
        num_predefined_cids=175,
        td_int8_cid=112, td_byte_data_view_cid=168, td_stride=4,
        # All three targets. arm64/x64 android are compressed; iOS arm64 is uncompressed,
        # which routes String/PcDescriptors/CodeSourceMap/CompressedStackMaps through
        # RODataDeserializationCluster; android arm32 is uncompressed on a 32-bit word,
        # which needs that same ROData grammar plus a 32-bit container.
        grammars=frozenset({(8, True), (8, False), (4, False)}),
        notes="ObjectHeader tag era. cid numbering + Class/Closure alloc match the "
              "3.9-3.12 profile, which differs from the SDK main (3.13) checkout the base "
              "grammar was read from.",
    ),
}

# The rest of the ObjectHeader era, one entry per distinct snapshot hash. These share
# 3.12.2's cluster grammar, established by diffing every ReadAlloc and ReadFill body in
# app_snapshot.cc from 3.4.0 up with the preprocessor resolved for an AOT product build:
# no cluster changes the bytes it reads. What does move is the class-id table in
# class_id.h, which tools/gen_epoch.py derives per release.
#
# An identical grammar is still earned per epoch, not assumed: the Tier-A gates have to
# pass on a real binary before a profile claims a target.
_IDENTIFIED = {
    # hash: (name, dart, cid table, td_int8_cid, td_byte_data_view_cid, immutable bit)
    "41be3daaabd524b8aa7423bc24584957": ("objectheader-3.12", "3.12.0", ERA_3_9, 112, 168, 7),
    "78da37fed6bf1489361a312568249f3f": ("objectheader-3.11", "3.11.5", ERA_3_9, 112, 168, 6),
    "1ce86630892e2dca9a8543fdb8ed8e22": ("objectheader-3.10", "3.10.9", ERA_3_9, 112, 168, 6),
    "97ff04a728735e6b6b098bdf983faaba": ("objectheader-3.9", "3.9.2", ERA_3_9, 112, 168, 6),
    # Flutter 3.32.0 pins Dart revision b04011c7, which is not a released tag. Reachable
    # through tools/sdk_source.dart_revision_for_flutter.
    "830f4f59e7969c70b595182826435c19": ("objectheader-3.8", "3.8.1", ERA_3_6, 112, 168, 6),
    "d91c0e6f35f0eb2e44124e8f42aa44a7": ("objectheader-3.7", "3.7.2", ERA_3_6, 112, 168, 6),
    "f956f595844a2f845a55707faaaa51e4": ("objectheader-3.6", "3.6.2", ERA_3_6, 112, 168, 6),
    # 3.5 and 3.4 predate Bytecode at cid 19, so their whole table sits one lower.
    "80a49c7111088100a233b2ae788e1f48": ("objectheader-3.5", "3.5.4", ERA_3_4, 111, 167, 6),
    "d20a1be77c3d3c41b2a5accaee1ce549": ("objectheader-3.4", "3.4.4", ERA_3_4, 111, 167, 6),
    # 3.3 back to 3.1 predate the object-header cluster tag, so they are a different naming
    # family, and they still carry ExternalOneByteString / ExternalTwoByteString at 95/96,
    # which puts the typed-data range two higher than 3.4's.
    "ee1eb666c76a5cb7746faf39d0b97547": ("cidcanonical-3.3", "3.3.4", ERA_3_1, 113, 169, 0),
    "f71c76320d35b65f1164dbaa6d95fe09": ("cidcanonical-3.2", "3.2.6", ERA_3_1, 113, 169, 0),
    "7dbbeeb8ef7b91338640dca3927636de": ("cidcanonical-3.1", "3.1.5", ERA_3_1, 113, 169, 0),
    # 3.0 still has TypeRef as its own class and predates WeakArray, so its table runs one
    # longer again and the typed-data range sits one higher than 3.1's.
    "90b56a561f70cd55e972cb49b79b3d8b": ("cidcanonical-3.0", "3.0.6", ERA_3_0, 114, 170, 0),
    # 2.19, the oldest supported. Records still store a field_names array instead of a
    # packed shape, which changes how the Record cluster is read.
    "adb4292f3ec25074ca70abcd2d5c7251": ("cidcanonical-2.19", "2.19.6", ERA_2_19, 113, 169, 0),
    # Second releases of eras already above, found by running tools/sdk_source.py --identify
    # over every stable tag and then every beta. Real apps carry them: the corpus widening
    # turned up four snapshots no registered hash matched, and three are these. The fourth
    # is still open; see the note under _UNIDENTIFIED.
    #
    # A beta is not a curiosity here. Flutter's beta channel pins a Dart build that is a
    # release tag of its own, and an app published from it carries that build's hash for
    # ever, so the map has to hold them to cover what is actually shipped.
    "aa64af18e7d086041ac127cc4bc50c5e": ("cidcanonical-3.0", "3.0.1", ERA_3_0, 114, 170, 0),
    "8b43434a6666a4f8eb2de8ecf8be4f82": ("cidcanonical-3.3", "3.3.0-174.2.beta",
                                         ERA_3_1, 113, 169, 0),
    "501ef5cbd64ca70b6b42672346af6a8a": ("cidcanonical-2.19", "2.19.0-444.2.beta",
                                         ERA_2_19, 113, 169, 0),
}

#: Carried by a real app in the sweep and still not placed. Bracketed rather than guessed:
#: the features string has `no-msan`, which dart.cc gained at 3.5.0, and lacks
#: `shared_data`, which it gained at 3.9.0, so the build is somewhere in 3.5.x-3.8.x. Every
#: stable and every beta tag in that window reproduces a different hash, which leaves the
#: dev tags, 1,601 of them, and each costs a 2.5 MiB fetch to test. Recorded here so the
#: next person starts from the bracket rather than from nothing.
_UNIDENTIFIED = {
    "853774151675607809640123f1ab2cab": "Dart 3.5.x-3.8.x dev, arm64 android (com.open_usos)",
}

# Epoch families that are identified but deliberately not claimed. An entry here keeps its
# hash in the registry so the failure names the release, and gets an empty grammar set so
# nothing tries to parse it: the alloc pass would otherwise "succeed" on a wrong grammar and
# hand back a plausible, fictional object graph. A family leaves this set only when the
# Tier-A gates pass on a real binary. Empty at the moment; 3.1 sat here until its desync
# was traced to PatchClass dropping origin_class, now carried in _FILL_OVERRIDES below.
_UNVALIDATED = set()

# Per-epoch fill deltas against the 3.2+ base table in fillwalk._REFS.
#
# PatchClass serializes `VISIT_FROM(patched_class) .. to_snapshot(kFullAOT) = script_`, which
# is patched_class, origin_class and script in 3.1 but only wrapped_class and script from
# 3.2 on: origin_class was dropped and the first field renamed. Nothing in app_snapshot.cc
# records that, so a diff of the serializer sees an unchanged grammar while the fill quietly
# under-reads one ref for every PatchClass, 440 of them in the corpus app, which is the
# 785 bytes by which the walk arrived early at the following cluster.
# Scalar op codes, spelled out rather than imported from fillwalk: that module imports
# clusters, which imports this one, and the letters are part of the on-disk grammar anyway.
_T, _B = "T", "B"          # signed varint / one raw byte

#: Keyed on the epoch FAMILY, not the release. Every switch below is a property of the
#: format era, and keying them on the version string meant that registering a second
#: release of the same era (3.0.1 beside 3.0.6) silently turned four of them off and
#: produced a profile nobody had asked for. The family name is what the era is called.
_FILL_OVERRIDES = {
    "cidcanonical-3.1": {"PatchClassCid": (3, [], -1, -1)},
    "cidcanonical-2.19": {
        "PatchClassCid": (3, [], -1, -1),
        # TypeParameter is type_test_stub (inherited) plus hash and bound, where 3.1 has
        # type_test_stub, hash and a single owner, `hash` moved up into AbstractType in
        # 3.1, so the count coincidentally stays three. The scalars do differ: 2.19 writes
        # parameterized_class_id as an int32 and base/index as single bytes, and 3.0 widened
        # the latter two.
        "TypeParameterCid": (3, [_T, _B, _B, _B], -1, -1),
        "SubtypeTestCacheCid": (1, [], -1, -1),
        "FfiTrampolineDataCid": (4, [_T], -1, -1),
        "TypeRefCid": (2, [], -1, -1),
    },
    "cidcanonical-3.0": {
        "PatchClassCid": (3, [], -1, -1),
        # TypeParameter carried a base/index int32 that 3.1 dropped.
        "TypeParameterCid": (3, [_T, _T, _T, _B], -1, -1),
        # SubtypeTestCache gained its two cache counters in 3.1.
        "SubtypeTestCacheCid": (1, [], -1, -1),
        # FfiTrampolineData gained the callback-kind byte in 3.1.
        "FfiTrampolineDataCid": (4, [_T], -1, -1),
        # TypeRef: ReadFromTo over type_test_stub (inherited from UntaggedAbstractType,
        # which is where VISIT_FROM sits) plus its own `type`, and no scalars. The parent's
        # field is easy to miss, it is also why Type is three refs and not two.
        "TypeRefCid": (2, [], -1, -1),
    },
}
#: SnapshotBehavior entered the ObjectPool entry byte in 3.3, and before that the entry's
#: tagged flag came first.
_PRE_BEHAVIOUR = frozenset({"cidcanonical-2.19", "cidcanonical-3.0", "cidcanonical-3.1",
                            "cidcanonical-3.2"})
_TAGGED_FIRST = frozenset({"cidcanonical-2.19", "cidcanonical-3.0", "cidcanonical-3.1"})
#: NullabilityBits narrowed from 2 bits to 1 at 3.5, moving TypeClassIdBits down.
_WIDE_NULLABILITY = frozenset({"cidcanonical-2.19", "cidcanonical-3.0", "cidcanonical-3.1",
                               "cidcanonical-3.2", "cidcanonical-3.3", "objectheader-3.4"})

for _h, (_name, _dart, _table, _td0, _tdv, _imm) in _IDENTIFIED.items():
    _EPOCHS[_h] = Epoch(
        name=_name, dart=_dart, cid_table=_table,
        # ClassIdTag is `BitField<..., SizeTagBits::kNextBit, 20>` throughout this era, so
        # the cid field sits at bit 12 in all of them. The IMMUTABLE bit did move: a
        # canonical String cluster tag reads 0x5d082 on 3.12.2 (bit 7) and 0x5d042 on 3.11.5
        # (bit 6), and 3.4's raw_object.h still spells kImmutableBit = 6 as a literal.
        # immutable bit 0 marks the pre-3.4 packing, where the flag does not exist and the
        # cid is not a bitfield at all.
        tag=(TagLayout(packing="cid_and_canonical") if _imm == 0 else
             TagLayout(cid_shift=12, cid_bits=20, canonical_bit=1, immutable_bit=_imm)),
        num_predefined_cids=_table.num_predefined,
        objpool_has_behavior=(_name not in _PRE_BEHAVIOUR),
        fill_overrides=_FILL_OVERRIDES.get(_name, {}),
        objpool_tagged_first=(_name in _TAGGED_FIRST),
        record_has_field_names=(_name == "cidcanonical-2.19"),
        type_class_id_shift=(4 if _name in _WIDE_NULLABILITY else 3),
        td_int8_cid=_td0, td_byte_data_view_cid=_tdv, td_stride=4,
        grammars=(frozenset() if _name in _UNVALIDATED
                  else frozenset({(8, True), (8, False), (4, False)})),
        notes=(f"Dart {_dart}: identified, but the cluster grammar has not passed the "
               f"acceptance gates on a real binary yet" if _name in _UNVALIDATED else
               f"Dart {_dart}: AOT cluster grammar verified identical to 3.12.2 by source "
               f"diff, then gated on a real binary"),
    )


def resolve(version_hash: str, features: str) -> Profile | None:
    """Resolve (hash, features) -> Profile, or None when the hash is unknown.

    Returning None keeps the fail-loud contract for an unknown version. A KNOWN version on
    a target we have no grammar for is a different failure and raises UnsupportedTarget
    instead, because continuing would start a walk that can pass the alloc-pass self-check
    while parsing the wrong grammar."""
    epoch = _EPOCHS.get(version_hash)
    if epoch is None:
        return None                     # unknown epoch: caller raises UnknownEpoch
    f = parse_features(features)
    if f["arch"] is None or f["compressed"] is None:
        raise UnsupportedTarget(
            f"epoch {epoch.name} recognised, but the features string names no "
            f"{'architecture' if f['arch'] is None else 'pointer model'}: {features!r}")
    arch = Arch(name=f["arch"], word_size=_ARCH_WORDS[f["arch"]], compressed=f["compressed"])
    if not epoch.grammars:
        # Identified but unsupported: we know which release this is, we just have no
        # validated cluster grammar for it. Saying so beats blaming the pointer model.
        raise UnsupportedTarget(
            f"epoch {epoch.name} (dart {epoch.dart}) is identified but has no validated "
            f"cluster grammar, so there is nothing to parse it with. Deriving one means "
            f"working out this release's per-cluster ReadAlloc deltas and confirming them "
            f"with `--verify` on a binary built by that SDK.")
    if arch.grammar_key not in epoch.grammars:
        supported = ", ".join(f"{w * 8}-bit {'compressed' if c else 'uncompressed'}"
                              for w, c in sorted(epoch.grammars))
        raise UnsupportedTarget(
            f"epoch {epoch.name} (dart {epoch.dart}) has no cluster grammar for {arch}. "
            f"Supported: {supported}. Refusing to parse: "
            f"{'no-' if not arch.compressed else ''}compressed-pointers selects a "
            f"different cluster routing (RODataDeserializationCluster for String/"
            f"PcDescriptors/CodeSourceMap/CompressedStackMaps), which this profile "
            f"does not implement.")
    return Profile(epoch=epoch, arch=arch)


def known_hashes() -> list[str]:
    return sorted(_EPOCHS)


def _release_order(dart: str) -> tuple:
    """Sort key for a Dart release, prereleases included.

    `3.3.0-174.2.beta` sorts before `3.3.0`, which is where it was built: a beta carries
    the version it is working TOWARDS. Splitting on dots and calling int() was enough while
    every registered epoch was a stable release, and stopped being enough the moment a real
    app turned out to be running a beta, it raised ValueError from inside the handler
    that builds the unknown-epoch message, so an unplaceable binary reported a parse error
    instead of the name of the thing that could not be placed."""
    base, _, pre = dart.partition("-")
    nums = tuple(int(p) if p.isdigit() else 0 for p in base.split("."))
    # A stable release is later than every prerelease of the same number, so it sorts last.
    return nums, (0, pre) if pre else (1, "")


def known_epochs() -> list[Epoch]:
    """Every registered epoch, oldest Dart release first."""
    return sorted(_EPOCHS.values(), key=lambda e: _release_order(e.dart))
