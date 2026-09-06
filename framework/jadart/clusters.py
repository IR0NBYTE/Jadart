"""Dart clustered-snapshot ALLOC-pass walker (jadart M2, WP-1a).

Walks the whole alloc pass: for every cluster it reads the tag word, decodes the
cid + canonical/immutable bits, and consumes that cluster's ReadAlloc bytes,
assigning dense ref ids. This reaches the fill pass and yields the full cluster
map (cid, count, ref range) for every object in the snapshot.

Grammar source of truth: runtime/vm/app_snapshot.cc @ c6d9d592 (see the M2 grammar
spec in framework/docs). Target: kFullAOT, arm64, DART_COMPRESSED_POINTERS. On that
target the RODataDeserializationCluster does NOT exist (guarded
`#if !defined(DART_COMPRESSED_POINTERS)`), so PcDescriptors/CodeSourceMap/
CompressedStackMaps/String all use their own clusters (all VARIABLE), and there is
NO inter-cluster marker in a release build.

Self-check, and the reason to trust the result: after the walk, the number of
assigned refs must equal num_objects exactly. Any wrong per-cluster read pattern
desyncs the varint stream and the count won't land. Fail loud on an unknown cid
rather than guess, which is the correctness discipline this has over unflutter.
"""
from __future__ import annotations

from .errors import JadartError

from dataclasses import dataclass

from . import cids as C
from .stream import ReadStream

# alloc-read pattern codes
FIXED = "fixed"              # U count
VARIABLE = "variable"        # U count; per-obj U length
INSTANCE = "instance"        # U count; I32 next_field_offset; I32 instance_size
STRING = "string"            # U count; per-obj U (length<<1 | is_two_byte); +CSL
CODE = "code"                # U count; count x I32; U deferred; deferred x I32
MINT = "mint"                # U count; count x I64
CLASS = "class"              # predefined_count U; predefined x ReadCid(I32); new_count U
RODATA = "rodata"            # U count; per-obj U delta (<< kObjectAlignmentLog2); +CSL.
                             # Uncompressed-pointer targets only; the objects live in the
                             # RO data image and their ReadFill is EMPTY.

# Clusters whose ReadAlloc appends a canonical-set layout suffix when the cluster is the
# root unit AND canonical (app_snapshot.cc BuildCanonicalSetFromLayout). Named, not
# numbered, for the same reason as the routing below.
_CSL_NAMES = ("TypeArgumentsCid", "TypeCid", "FunctionTypeCid", "RecordTypeCid",
              "TypeParameterCid", "StringCid")


# per-cid alloc pattern for the ReadCluster switch (compressed-pointers AOT target).
# Built from the M2 grammar master table. Cids that never appear as concrete
# serialized objects are absent; an unknown one fails loud.
# This is the Dart 3.12.2 epoch profile. Two clusters differ from the SDK `main`
# (c6d9d592) checkout the grammar was extracted from, confirmed against the binary
# and cross-checked with unflutter's version-parameterized model:
#   * Class alloc reads predefined_count + predefined x ReadCid(int32) + new_count
#     (main refactored this to a plain fixed count).
#   * Closure alloc is FIXED (main added a per-object `length` for inline context in
#     3.13; it is absent in 3.12.2).
# That drift per epoch is what the version-robust design is there to handle.
# Full per-cluster alloc-kind profile for this epoch, keyed by cid enum name (from the
# confirmed master grammar table). Type/FunctionType/RecordType/TypeParameter/String/
# TypeArguments additionally carry a canonical-set tail (see _CSL_CIDS) applied on top.
_FIXED_NAMES = frozenset({
    "PatchClassCid", "TypeParametersCid", "FunctionCid", "ClosureDataCid",
    "FfiTrampolineDataCid", "FieldCid", "ScriptCid", "LibraryCid", "NamespaceCid",
    "DoubleCid", "GrowableObjectArrayCid", "ConstMapCid", "ConstSetCid",
    "UnlinkedCallCid", "ICDataCid", "MegamorphicCacheCid", "SubtypeTestCacheCid",
    "LoadingUnitCid", "ApiErrorCid", "LanguageErrorCid", "UnhandledExceptionCid",
    "UnwindErrorCid", "LibraryPrefixCid", "StackTraceCid", "RegExpCid",
    # TypeRef was its own class until 3.1 folded it away; harmless to list for later
    # epochs, whose cid tables simply have no such name.
    "TypeRefCid",
    "WeakPropertyCid", "SingleTargetCacheCid", "MonomorphicSmiableCallCid",
    "SentinelCid", "Float32x4Cid", "Int32x4Cid", "Float64x2Cid",
    "WeakSerializationReferenceCid", "MirrorReferenceCid", "WeakReferenceCid",
    "FinalizerCid", "NativeFinalizerCid", "FinalizerEntryCid", "SuspendStateCid",
    "ReceivePortCid", "SendPortCid", "CapabilityCid", "TransferableTypedDataCid",
    "UserTagCid", "PointerCid", "DynamicLibraryCid",
    "ClosureCid",   # FIXED in 3.12.2 (main added a per-object length in 3.13)
    "TypeCid", "FunctionTypeCid", "RecordTypeCid", "TypeParameterCid",  # + CSL tail
})
_VARIABLE_NAMES = frozenset({
    "TypeArgumentsCid",   # + CSL tail
    "ObjectPoolCid", "PcDescriptorsCid", "CodeSourceMapCid", "CompressedStackMapsCid",
    "LocalVarDescriptorsCid", "ExceptionHandlersCid", "ContextCid", "ContextScopeCid",
    "RecordCid", "ArrayCid", "ImmutableArrayCid", "WeakArrayCid",
})
# Everything above names CLASSES, and class names are stable across releases. The cid
# behind a name is not: Bytecode was added at cid 19 in 3.6, shifting the whole tail, and
# UnlinkedCall / MonomorphicSmiableCall / CallSiteData were reordered again in 3.9. So the
# name -> pattern rules are fixed, and the cid -> pattern map they produce is per epoch.
_ROUTING_CACHE: dict = {}


class _Routing:
    """Cid-keyed dispatch derived from one epoch's cid numbering."""

    __slots__ = ("switch", "ffi_instance", "rodata_always", "rodata_root_only",
                 "instance_cid", "names", "csl_cids")

    def __init__(self, table):
        self.names = table.names
        switch = {}
        for cid, name in table.names.items():
            if name in _FIXED_NAMES:
                switch[cid] = FIXED
            elif name in _VARIABLE_NAMES:
                switch[cid] = VARIABLE
        for nm, pattern in (("StringCid", STRING), ("CodeCid", CODE),
                            ("MintCid", MINT), ("ClassCid", CLASS)):
            switch[table.cid(nm)] = pattern
        self.switch = switch
        # FFI native-type cids have no cluster of their own and fall through to the generic
        # InstanceDeserializationCluster (app_snapshot.cc:9617-9621). Matching the "Ffi" name
        # prefix alone is wrong, and was: FfiTrampolineData starts with Ffi but is an
        # ordinary VM object with its own FIXED cluster, and routing it as an instance reads
        # two extra varints and desyncs the rest of the pass. So a cid is an FFI instance
        # only if it looks like FFI AND nothing else has claimed it.
        self.ffi_instance = frozenset(c for c, n in table.names.items()
                                      if n.startswith("Ffi") and c not in switch)
        # Cids ReadCluster sends to RODataDeserializationCluster on uncompressed-pointer
        # targets (app_snapshot.cc:9391-9408); the string cids only in the root unit.
        self.rodata_always = frozenset(table.cid(n) for n in (
            "PcDescriptorsCid", "CodeSourceMapCid", "CompressedStackMapsCid"))
        self.rodata_root_only = frozenset(table.cid(n) for n in (
            "StringCid", "OneByteStringCid", "TwoByteStringCid"))
        self.instance_cid = table.cid("InstanceCid")
        self.csl_cids = frozenset(table.cid(n) for n in _CSL_NAMES)


def routing(epoch) -> _Routing:
    """Cached per-epoch routing. Keyed on the table, since epochs share tables."""
    table = epoch.cid_table
    # The TABLE is kept alongside the routing, not just its id. Every CidTable is a module
    # constant today, so `id()` alone is stable, but versions.py says the epoch map will
    # grow, and a table built at runtime and then freed lets CPython reuse its address,
    # which would hand back another epoch's grammar under the right id. That is a wrong
    # answer delivered confidently, so the entry holds the table and the lookup checks it.
    hit = _ROUTING_CACHE.get(id(table))
    if hit is not None and hit[0] is table:
        return hit[1]
    r = _Routing(table)
    _ROUTING_CACHE[id(table)] = (table, r)
    return r


@dataclass
class Cluster:
    index: int
    cid: int
    canonical: bool
    immutable: bool
    pattern: str
    count: int
    start_ref: int      # first ref id assigned by this cluster (1-based)
    stop_ref: int       # one past the last
    alloc_start: int    # byte offset of this cluster's alloc data (after tag)
    alloc_end: int      # byte offset just past this cluster's alloc reads
    lengths: list | None = None   # per-object lengths for VARIABLE/STRING (for fill)
    next_field_offset: int = 0    # INSTANCE clusters: next_field_offset_in_words (for FillInstance)
    instance_size: int = 0        # INSTANCE clusters: instance_size_in_words
    main_count: int = 0           # CODE: non-deferred count; CLASS: predefined count (for fill)
    discarded: list | None = None  # CODE: per-code discarded flag (state_bits bit 3), for fill
    # Kept for the acceptance gates (verify.py): both are read by the alloc pass anyway and
    # are redundantly encoded elsewhere in the snapshot, which makes them free cross-checks.
    predefined_cids: list | None = None   # CLASS: the alloc-pass cid list (vs the fill pass)
    rodata_offsets: list | None = None    # RODATA: per-object offsets into the RO data image
    csl: tuple | None = None              # canonical-set layout: (table_length, first, gaps)
    mint_values: list | None = None       # MINT: the int64 each Smi/Mint in this cluster holds
    # Resolved against the epoch's own numbering at construction rather than looked up
    # later against a bundled table. The fill pass keys its grammar off this name, so a
    # cid resolved under the wrong epoch would pick the wrong field layout.
    name: str = ""


class AllocError(JadartError):
    """Alloc-pass desync. Carries the partial cluster list when there is one.

    A desync says the grammar is wrong but not where. The counts read just before it went
    wrong are the evidence that localises it, so they get attached rather than lost."""

    def __init__(self, message, clusters=None):
        super().__init__(message)
        self.clusters = clusters or []


def _pattern_for(cid: int, epoch, arch=None, is_root_unit: bool = True) -> str:
    # dispatch order mirrors Deserializer::ReadCluster (app:9371-9628).
    # The user-class boundary + typed-data range come from the EPOCH (they shift across Dart
    # versions), not from the main-derived cid table.

    # On uncompressed targets, RO data has to be checked before the typed-data and switch
    # cases, the order ReadCluster uses. Otherwise these cids get claimed by the
    # STRING/VARIABLE patterns, which read a grammar that isn't there.
    r = routing(epoch)
    if arch is not None and arch.rodata_clusters:
        if cid in r.rodata_always or (is_root_unit and cid in r.rodata_root_only):
            return RODATA

    boundary = epoch.num_predefined_cids or epoch.cid_table.num_predefined
    if cid >= boundary or cid == r.instance_cid:
        return INSTANCE
    # typed-data family is checked BEFORE the FFI/switch, matching ReadCluster order, and
    # uses the epoch's numeric range (the main-derived FFI names put FfiStruct at a
    # typed-data cid, so a name-based check would misroute it).
    tdk = epoch.typed_data_kind(cid)
    if tdk == "view_or_external":
        return FIXED
    if tdk == "internal":
        return VARIABLE
    if cid in r.ffi_instance:
        return INSTANCE
    p = r.switch.get(cid)
    if p is None:
        raise AllocError(
            f"no alloc pattern for cid {cid} ({r.names.get(cid, '?')}) under epoch "
            f"{epoch.name}. Refusing to guess (would desync the stream). Extend the "
            "switch from the grammar spec.")
    return p


def walk_alloc(st: ReadStream, num_base_objects: int, num_objects: int,
               num_clusters: int, *, epoch, is_root_unit: bool = True,
               arch=None) -> list[Cluster]:
    """Consume the entire alloc pass. `st` must be positioned at the first cluster
    tag (right after the 5 header varints). `epoch` is the resolved versions.Epoch
    (provides tag decode, cid boundary, typed-data range). Returns the ordered
    cluster list. Raises AllocError on desync (assigned refs != num_objects)."""
    if epoch is None:
        raise AllocError("epoch is required")
    tag_decode = epoch.tag.decode
    # Before 3.4 the tag is a uint64 (cid<<1|canonical); from 3.4 it is the uint32 object
    # header word. Different width, so the reader is picked per epoch too.
    read_tag = st.read_uint64_tag if epoch.tag.wide else st.read_uint32_tag
    r = routing(epoch)
    _names = r.names

    next_ref = num_base_objects + 1     # kFirstReference=1; base objs fill [1..num_base]
    clusters: list[Cluster] = []

    for i in range(num_clusters):
        tag = read_tag()
        cid, canon, imm = tag_decode(tag)
        pattern = _pattern_for(cid, epoch, arch, is_root_unit)
        alloc_start = st.pos
        lengths = None

        if pattern == CLASS:
            # predefined_count; (v2.10 heuristic: if > NUM_PREDEFINED_CIDS it was a total
            # prefix, re-read); predefined x ReadCid(=Read<int32>, signed marker); new_count.
            predefined = st.read_unsigned()
            # The boundary is this epoch's, not the bundled table's. cids.py is generated
            # from one SDK and the count moves between releases, so comparing against it
            # is the same mistake user_classes() documents having fixed.
            if predefined > (epoch.num_predefined_cids or C.NUM_PREDEFINED_CIDS):
                predefined = st.read_unsigned()
            predefined_cids = [st.read_int() for _ in range(predefined)]   # ReadCid
            new_count = st.read_unsigned()
            count = predefined + new_count
            start_ref = next_ref
            next_ref += count
            clusters.append(Cluster(
                index=i, cid=cid, canonical=canon, immutable=imm, pattern=pattern,
                name=_names.get(cid, f"cid{cid}"),
                count=count, start_ref=start_ref, stop_ref=next_ref,
                alloc_start=alloc_start, alloc_end=st.pos, lengths=None,
                main_count=predefined, predefined_cids=predefined_cids))
            continue

        if pattern == RODATA:
            # RODataDeserializationCluster::ReadAlloc (app_snapshot.cc:3750-3763): a count,
            # then one delta per object which accumulates into an offset into the RO data
            # image, pre-divided by the object alignment. ReadFill is EMPTY, because the
            # payload is already in the image, not in the stream.
            count = st.read_unsigned()
            shift = arch.object_alignment_log2 if arch else 4
            run, offsets = 0, []
            for _ in range(count):
                run += st.read_unsigned() << shift
                offsets.append(run)
            csl = None
            if is_root_unit and canon:
                table_length = st.read_unsigned()
                first_element = st.read_unsigned()
                gaps = [st.read_unsigned() for _ in range(count - first_element)]
                csl = (table_length, first_element, gaps)
            start_ref = next_ref
            next_ref += count
            clusters.append(Cluster(
                index=i, cid=cid, canonical=canon, immutable=imm, pattern=pattern,
                name=_names.get(cid, f"cid{cid}"),
                count=count, start_ref=start_ref, stop_ref=next_ref,
                alloc_start=alloc_start, alloc_end=st.pos, lengths=None,
                rodata_offsets=offsets, csl=csl))
            continue

        count = st.read_unsigned()
        nfo = iss = code_main_count = 0
        code_discarded = None
        mint_values = None

        if pattern == INSTANCE:
            nfo = st.read_int()   # next_field_offset_in_words (I32 signed varint)
            iss = st.read_int()   # instance_size_in_words
            advance = count
        elif pattern == FIXED:
            advance = count
        elif pattern == VARIABLE:
            lengths = [st.read_unsigned() for _ in range(count)]
            advance = count
        elif pattern == STRING:
            lengths = []
            for _ in range(count):
                enc = st.read_unsigned()
                lengths.append((enc >> 1, bool(enc & 1)))  # (length, is_two_byte)
            advance = count
        elif pattern == CODE:
            # per code a state_bits int32; bit 3 = DiscardedBit (needed by fill).
            disc = []
            for _ in range(count):
                sb = st.read_int()
                disc.append(bool((sb >> 3) & 1))
            deferred = st.read_unsigned()
            for _ in range(deferred):
                sb = st.read_int()
                disc.append(bool((sb >> 3) & 1))
            advance = count + deferred
            code_main_count = count      # non-deferred codes
            code_discarded = disc
        elif pattern == MINT:
            # Kept rather than skipped. The Smi/Mint cluster writes its VALUES here, in the
            # alloc pass (MintSerializationCluster::WriteAlloc, app_snapshot.cc:5365,
            # `s->Write<int64_t>(value)`), and a Field's byte offset or static-field id is a
            # Smi reached by ref (:2236-2238), so the number that turns `field_0x8` into a
            # name is in this list and in no other place in the stream.
            mint_values = [st.read_int() for _ in range(count)]
            advance = count
        else:
            raise AllocError(f"unhandled pattern {pattern}")

        # canonical-set layout suffix (root unit + canonical only)
        csl = None
        if cid in r.csl_cids and is_root_unit and canon:
            table_length = st.read_unsigned()
            first_element = st.read_unsigned()
            num_gap = count - first_element
            gaps = [st.read_unsigned() for _ in range(num_gap)]     # FillGap
            csl = (table_length, first_element, gaps)

        start_ref = next_ref
        next_ref += advance
        clusters.append(Cluster(
            index=i, cid=cid, canonical=canon, immutable=imm, pattern=pattern,
                name=_names.get(cid, f"cid{cid}"),
            count=count, start_ref=start_ref, stop_ref=next_ref,
            alloc_start=alloc_start, alloc_end=st.pos, lengths=lengths,
            next_field_offset=nfo, instance_size=iss,
            main_count=code_main_count, discarded=code_discarded, csl=csl,
            mint_values=mint_values))

    assigned = next_ref - 1
    if assigned != num_objects:
        raise AllocError(
            f"alloc desync: assigned {assigned} refs but header says "
            f"num_objects={num_objects} (delta {assigned - num_objects}). "
            f"walked {len(clusters)}/{num_clusters} clusters.", clusters)
    return clusters
