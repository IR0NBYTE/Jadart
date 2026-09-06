"""Full fill-pass walker (jadart M3).

After the alloc pass, the snapshot's fill pass runs over every cluster in the same
order, each object emitting its field data: a run of ref-ids (ReadRefId, big-endian,
for Dart >= 2.18) plus trailing scalars, sometimes with a per-object length. Walking
the whole fill pass lets us reach the Class and Function clusters, read each object's
NAME ref, and resolve it against the string pool. That gives the object-graph
structure behind a Tier-0 skeleton.

Grammar source: unflutter internal/cluster/{fill.go,fillspec.go} resolved to the
Dart 3.9-3.12 AOT PRODUCT / compressed-pointers profile, cross-checked with
runtime/vm/{app_snapshot.cc,raw_object.h}. Validated byte-for-byte against unflutter's
per-cluster fill offsets (`unflutter _debug clusters --debug-fill`): the walk must land
exactly at the roots (end of the fill section).

Profile constants (Dart 3.12.2): fill refs = ReadRefId; compressed pointers (instance
header = 2 words); Code numRefs=6, no text-offset-delta, no interleaved state_bits;
top-level cid threshold = 1<<20; classes carry no token positions in AOT.
"""
from __future__ import annotations

from .errors import JadartError

from dataclasses import dataclass, field

from . import cids as C
from .stream import ReadStream
from .clusters import Cluster, RODATA

# scalar op codes
U = "U"          # ReadUnsigned            -> read_unsigned
T = "T"          # Read<int/uint 16/32/64> -> read_int (signed varint, marker 192)
B = "B"          # Read<bool/uint8/int8>   -> one raw byte
R = "R"          # ReadRef (trailing)      -> read_ref_id


def _scalar(st: ReadStream, op: str) -> int:
    if op == U:
        return st.read_unsigned()
    if op == T:
        return st.read_int()
    if op == B:
        return st.byte()
    if op == R:
        return st.read_ref_id()
    raise ValueError(f"bad scalar op {op}")


# FillRefs specs for the 3.12 profile: name -> (num_refs, scalars, name_idx, owner_idx)
# name_idx/owner_idx = -1 when absent. Cids <96 are numbered identically to the epoch's
# low-cid table, so keying by name is exact here.
_REFS = {
    "PatchClassCid":         (2,  [],            -1, -1),
    "FunctionCid":           (4,  [U, T],         0,  1),   # name, owner, signature, data + code_index(U) + kind_tag(T)
    "TypeParametersCid":     (4,  [],            -1, -1),
    "ClosureDataCid":        (2,  [U],           -1, -1),
    # ReadFromTo covers signature_type..callback_exceptional_return (4 refs), then
    # callback_id as Read<int32_t> and ffi_function_kind as Read<uint8_t>. Identical in
    # 3.11.5 and 3.12.2. Absent until now because the 3.12.2 corpus app contains no
    # FfiTrampolineData cluster; every other corpus binary does.
    "FfiTrampolineDataCid":  (4,  [T, B],        -1, -1),
    "FieldCid":              (4,  [T, R],         0,  1),   # kind_bits(T) + host_offset(RefId)
    "ScriptCid":             (1,  [T],            0, -1),   # url + kernel_script_index
    "LibraryCid":            (10, [T, T, B, B],   0,  1),   # name, url
    "UnlinkedCallCid":       (2,  [B],            0, -1),
    # LibraryPrefix is `import ... deferred as x`. WriteFromTo runs from `name` to
    # to_snapshot(kind), and for kFullAOT that is `imports_` (raw_object.h:2891), so the
    # importer is NOT serialized, two refs, not three. Then num_imports_ as
    # Write<uint16_t> and is_deferred_load_ as Write<bool> (app_snapshot.cc:4711).
    #
    # Absent until a real app needed it: no binary in the corpus uses a deferred import,
    # because the corpus is one app we wrote. FluffyChat 1.29 (dart 3.12.2) failed on it
    # at cluster #1080 of 1090, which is how it was found.
    "LibraryPrefixCid":      (2,  [T, B],        0, -1),
    "SubtypeTestCacheCid":   (1,  [T, T],        -1, -1),
    "LoadingUnitCid":        (1,  [T],           -1, -1),
    "TypeCid":               (3,  [U],           -1, -1),
    "FunctionTypeCid":       (6,  [B, T, T],     -1, -1),
    "RecordTypeCid":         (4,  [B],           -1, -1),
    "TypeParameterCid":      (3,  [T, T, B],     -1, -1),
    "ClosureCid":            (6,  [],            -1, -1),
    "ConstMapCid":           (5,  [],            -1, -1),
    "ConstSetCid":           (5,  [],            -1, -1),
    "GrowableObjectArrayCid": (3, [],            -1, -1),
    "NamespaceCid":          (1,  [],            -1, -1),
    "MonomorphicSmiableCallCid": (0, [T, T],     -1, -1),
}

_INLINE_BYTES = frozenset({"PcDescriptorsCid", "CodeSourceMapCid", "CompressedStackMapsCid",
                           "LocalVarDescriptorsCid"})
_NONE = frozenset({"MintCid", "SentinelCid", "InstructionsTableCid"})

_TD_ELEMENT_SIZES = [1, 1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 16, 16, 16]  # by typed-data type index


@dataclass
class FillResult:
    strings: dict          # ref_id -> str (from all String clusters)
    functions: list        # (ref_id, name_ref, owner_ref, kind_tag)
    fields: list           # (ref_id, name_ref, owner_ref)
    classes: list          # (ref_id, name_ref, class_id, super_ref)
    types: dict            # ref_id -> type_class_id (for superclass/type resolution)
    codes: list            # (ref_id, owner_ref, instr_index) for main (non-deferred) codes
    pool: list             # ObjectPool entries in index order: (kind, ref_or_imm)
    end_pos: int
    code_first_ref: int = -1   # the Code cluster's first ref id; the serialized dispatch
                               # table repeats it, which anchors the table exactly (see
                               # dispatch.py / Serializer::WriteDispatchTable)
    # Redundantly-encoded values kept for the acceptance gates (verify.py). Each is read by
    # the fill pass anyway and is cross-checkable against a value the ALLOC pass read, which
    # ties the two passes together without needing an external oracle.
    func_code_index: dict = field(default_factory=dict)   # function ref -> code_index
    class_sizes: dict = field(default_factory=dict)       # class_id -> (inst_size, next_fo)
    #: cluster index -> the (length, is_two_byte) pairs the FILL pass read, in order. The
    #: ALLOC pass read the same pairs into Cluster.lengths, so the two are independently
    #: recorded encodings of one value and G4 compares them elementwise. Without this the
    #: gate could only count what alloc had, which is why it could not fail.
    string_lengths: dict = field(default_factory=dict)
    # Which library each class came from. This is the only general way to tell application
    # code from framework code: it is recorded in the snapshot, so it needs no reference
    # binary and no hardcoded list of "framework" packages.
    class_library: dict = field(default_factory=dict)     # class ref -> library ref
    library_urls: dict = field(default_factory=dict)      # library ref -> url string
    # A Field object still says WHERE it lives, and for an instance field that is the byte
    # offset a lifted `field_0x8` is spelled with. See fields.py for the join.
    field_meta: dict = field(default_factory=dict)        # Field ref -> (kind_bits, value ref)
    patch_class: dict = field(default_factory=dict)       # PatchClass ref -> wrapped Class ref
    func_data: dict = field(default_factory=dict)         # Function ref -> its `data` ref
    smi_values: dict = field(default_factory=dict)        # Mint/Smi ref -> the int it holds
    # A const list's ELEMENTS, which the fill pass was already reading and throwing away.
    # Dart puts every const data table in one of these, a keystream, an S-box, a lookup
    # of magic constants, and without them a decompiled loop shows the arithmetic over
    # `pool_0xb970[i]` and no way to say what is in it. Element refs rather than values,
    # because resolving them is the caller's business: an element may be a Smi, a string,
    # or another object entirely.
    arrays: dict = field(default_factory=dict)            # Array ref -> tuple of elem refs
    # Which of a class's slots hold a RAW value rather than a tagged pointer. Bit i is the
    # slot at byte offset i * kCompressedWordSize (object.cc:3915,
    # `host_bitmap.Set(host_offset / kCompressedWordSize)`), the same unit a Field's
    # target_offset_ is in, so the two index each other directly.
    class_unboxed: dict = field(default_factory=dict)     # class_id -> unboxed-fields bitmap


def _td_element_size(cid: int, epoch) -> int:
    if not epoch.td_int8_cid:
        return 1
    idx = (cid - epoch.td_int8_cid) // epoch.td_stride
    return _TD_ELEMENT_SIZES[idx] if 0 <= idx < len(_TD_ELEMENT_SIZES) else 1


def walk_fill(st: ReadStream, clusters: list[Cluster], epoch, *,
              oracle: dict | None = None, arch=None) -> FillResult:
    """Consume the whole fill pass. `st` positioned at the fill-section start (right
    after the alloc walk). Returns recovered strings + Function/Class name links.
    If `oracle` {cluster_index: end_offset} is given, asserts each cluster's end
    position matches (byte-exact validation)."""
    strings: dict = {}
    string_lengths: dict = {}
    arrays: dict = {}
    functions: list = []
    fields: list = []
    classes: list = []
    types: dict = {}
    codes: list = []
    pool: list = []
    func_code_index: dict = {}
    class_sizes: dict = {}
    class_unboxed: dict = {}
    class_library: dict = {}
    libraries: list = []
    meta = {"field": {}, "patch": {}, "fdata": {}}
    instr_index = [0]      # running instructions-table index across Code clusters
    boundary = epoch.num_predefined_cids or epoch.cid_table.num_predefined
    # The base table is the 3.2+ shape; an older epoch supplies only what it differs by.
    _refs = dict(_REFS, **epoch.fill_overrides) if epoch.fill_overrides else _REFS

    for cl in clusters:
        name = cl.name
        n = cl.count
        # --- dispatch, mirroring ReadFill order (fill.go) ---
        if cl.pattern == RODATA:
            # RODataDeserializationCluster::ReadFill is empty (app_snapshot.cc:3765): these
            # objects were materialised from the RO data image during the alloc pass, so
            # nothing is consumed here. The identifier pool still has to be recovered, but
            # it is read out of the image rather than the stream.
            if cl.name in ("StringCid", "OneByteStringCid", "TwoByteStringCid"):
                _rodata_strings(st.data, cl, strings, epoch.cid_table, arch)
        elif cl.name == "StringCid":
            seen_lengths = []
            for i in range(n):
                enc = st.read_unsigned()
                length, two = enc >> 1, (enc & 1)
                seen_lengths.append((length, two))
                raw = st.read_bytes(length * 2 if two else length)
                strings[cl.start_ref + i] = (raw.decode("utf-16-le", "replace") if two
                                             else raw.decode("latin-1"))
            string_lengths[cl.index] = seen_lengths
        elif name in _NONE:
            pass
        elif name == "DoubleCid":
            for _ in range(n):
                st.read_int()          # Read<double> = Read64 varint
        elif name == "CodeCid":
            _fill_code(st, cl, codes, instr_index)
        elif name == "ObjectPoolCid":
            _fill_object_pool(st, cl, pool, epoch.objpool_has_behavior,
                              epoch.objpool_tagged_first)
        elif name in ("ArrayCid", "ImmutableArrayCid"):
            for i in range(n):
                ln = st.read_unsigned()
                st.read_ref_id()       # type_arguments
                arrays[cl.start_ref + i] = tuple(st.read_ref_id() for _ in range(ln))
        elif name == "WeakArrayCid":
            for _ in range(n):
                ln = st.read_unsigned()
                for _ in range(ln):
                    st.read_ref_id()
        elif name == "TypeArgumentsCid":
            for _ in range(n):
                ln = st.read_unsigned()
                st.read_int()          # hash
                st.read_unsigned()     # nullability
                st.read_ref_id()       # instantiations
                for _ in range(ln):
                    st.read_ref_id()
        elif name == "ExceptionHandlersCid":
            for _ in range(n):
                raw = st.read_unsigned()
                length = raw >> 1
                st.read_ref_id()       # handled_types_data
                for _ in range(length):
                    st.read_int(); st.read_int()   # pc_offset, outer_try_index
                    st.byte(); st.byte(); st.byte()  # needs_stacktrace, has_catch_all, is_generated
        elif name == "ContextCid":
            for _ in range(n):
                ln = st.read_unsigned()
                st.read_ref_id()       # parent
                for _ in range(ln):
                    st.read_ref_id()
        elif name == "RecordCid":
            for _ in range(n):
                shape = st.read_unsigned()
                if epoch.record_has_field_names:
                    # 2.19: the varint is a plain field count, and a field_names array ref
                    # follows it. 3.0 packed the count into a RecordShape and dropped the
                    # array, so the same byte means something else either side of that line.
                    st.read_ref_id()
                    count = shape
                else:
                    count = shape & 0xFFFF
                for _ in range(count):
                    st.read_ref_id()
        elif name in _INLINE_BYTES:
            for _ in range(n):
                ln = st.read_unsigned()
                st.read_bytes(ln)
        elif epoch.typed_data_kind(cl.cid) == "internal":
            esz = _td_element_size(cl.cid, epoch)
            for _ in range(n):
                ln = st.read_unsigned()
                st.read_bytes(ln * esz)
        elif cl.name == "ClassCid":
            _fill_class(st, cl, classes, class_sizes, class_library, class_unboxed)
        elif cl.name == "TypeCid":
            _fill_type(st, cl, types, epoch.type_class_id_shift)
        elif cl.cid >= boundary or cl.name == "InstanceCid":
            _fill_instance(st, cl, arch)
        elif name in _refs:
            _fill_refs(st, cl, _refs[name], functions, fields, func_code_index,
                       libraries, meta)
        else:
            raise FillError(f"no fill grammar for cluster #{cl.index} cid {cl.cid} "
                            f"({name}) at 0x{st.pos:x}")

        if oracle is not None:
            exp = oracle.get(cl.index)
            if exp is not None and st.pos != exp:
                raise FillError(
                    f"fill desync at cluster #{cl.index} ({name}, count={n}): "
                    f"ended 0x{st.pos:x}, oracle 0x{exp:x} (delta {st.pos - exp})")

    code_first = next((cl.start_ref for cl in clusters if cl.name == "CodeCid"), -1)
    return FillResult(strings=strings, functions=functions, fields=fields,
                      classes=classes, types=types, codes=codes, pool=pool, end_pos=st.pos,
                      code_first_ref=code_first, func_code_index=func_code_index,
                      class_sizes=class_sizes, class_unboxed=class_unboxed,
                      string_lengths=string_lengths,
                      class_library=class_library,
                      library_urls={r: (strings.get(u) or strings.get(n) or '')
                                   for r, n, u in libraries},
                      field_meta=meta["field"], patch_class=meta["patch"],
                      func_data=meta["fdata"],
                      arrays=arrays,
                      smi_values={cl.start_ref + i: v
                                  for cl in clusters if cl.mint_values
                                  for i, v in enumerate(cl.mint_values)})


class FillError(JadartError):
    pass


def _rodata_strings(blob: bytes, cl, strings: dict, table, arch=None) -> None:
    """Recover a ROData String cluster's text straight out of the RO data image.

    On uncompressed-pointer targets the identifier pool is not serialized into the stream at
    all: the alloc pass hands out offsets into the read-only data image and the fill pass
    reads nothing. Each object there is a plain heap String at
    `roundUp(Snapshot::length(), 64) + offset`, with the cid in tag bits 12..31 selecting
    one- or two-byte characters.

    Its header is target-dependent, and the difference is not just widths. HASH_IN_OBJECT_HEADER
    is defined only for 64-bit (globals.h), so there the hash lives in the spare upper half of
    the 8-byte tags word and UntaggedString declares length alone, `[tags+hash 8][length 8]`.
    A 32-bit build has no room for it, so String carries an explicit hash field ahead of
    length: `[tags 4][hash 4][length 4]`. Reading the 64-bit shape on 32-bit lands four bytes
    past every string.

    Without this, name recovery yields nothing on iOS and the walk still completes, so the
    empty result looks like an answer instead of a failure."""
    import struct as _struct
    offsets = cl.rodata_offsets or []
    if not offsets:
        return
    word = arch.word_size if arch else 8
    slot = arch.compressed_word_size if arch else 8
    # 64-bit keeps the hash in the header word; 32-bit stores it as a field of its own.
    hash_field = 0 if word == 8 else slot
    len_off = word + hash_field
    from .disasm import _string_header_size
    head = _string_header_size(word, slot)      # rounded to a word: that is where data starts
    len_fmt = "<Q" if slot == 8 else "<I"
    header_length = _struct.unpack_from("<q", blob, 4)[0] + 4      # Snapshot::length()
    image = (header_length + 63) & ~63
    for i, off in enumerate(offsets):
        base = image + off
        if base + head > len(blob):
            continue
        tags, = _struct.unpack_from("<I", blob, base)
        length_smi, = _struct.unpack_from(len_fmt, blob, base + len_off)
        length = length_smi >> 1
        cid = (tags >> 12) & 0xFFFFF
        two = (cid == table.cid("TwoByteStringCid"))
        nbytes = length * 2 if two else length
        # len_fmt is unsigned, so length cannot be negative; the bound is the only
        # thing standing between a garbage tags word and a multi-gigabyte slice.
        if base + head + nbytes > len(blob):
            continue
        raw = blob[base + head:base + head + nbytes]
        strings[cl.start_ref + i] = (raw.decode("utf-16-le", "replace") if two
                                     else raw.decode("latin-1"))


def _fill_refs(st, cl, spec, functions, fields, func_code_index=None,
               libraries=None, meta=None):
    num_refs, scalars, name_idx, owner_idx = spec
    is_func = (cl.name == "FunctionCid")
    is_field = (cl.name == "FieldCid")
    is_patch = (cl.name == "PatchClassCid")
    for i in range(cl.count):
        name_ref = owner_ref = first_ref = data_ref = -1
        for j in range(num_refs):
            r = st.read_ref_id()
            if j == 0:
                first_ref = r
            if j == 3:
                data_ref = r            # Function's 4th ref is `data`; for an implicit
                                        # accessor that is the Field it accesses
            if j == name_idx:
                name_ref = r
            if j == owner_idx:
                owner_ref = r
        kind_tag = 0
        code_index = -1
        kind_bits = 0
        value_ref = -1
        for op in scalars:
            v = _scalar(st, op)
            if is_func and op == T:
                kind_tag = v            # Function's last T scalar is kind_tag
            elif is_func and op == U:
                code_index = v          # Function's U scalar is its Code's code_index
            elif is_field and op == T:
                kind_bits = v           # Field's T scalar is kind_bits_ (Write<uint32_t>)
            elif is_field and op == R:
                # WriteFieldValue at app_snapshot.cc:2236-2238: a ref to the Smi holding
                # either the static field's table id or the instance field's offset in
                # compressed words. Which one is selected by StaticBit.
                value_ref = v
        if libraries is not None and cl.name == "LibraryCid":
            # name and url both. Internal libraries (the patch libraries that hold private
            # VM classes like _RegExp) carry a name but no url, and dropping those loses
            # every class they own.
            libraries.append((cl.start_ref + i, name_ref, owner_ref))
        if is_func:
            functions.append((cl.start_ref + i, name_ref, owner_ref, kind_tag))
            if func_code_index is not None and code_index >= 0:
                func_code_index[cl.start_ref + i] = code_index
            if meta is not None and data_ref != -1:
                meta["fdata"][cl.start_ref + i] = data_ref
        elif is_field:
            fields.append((cl.start_ref + i, name_ref, owner_ref))
            if meta is not None:
                meta["field"][cl.start_ref + i] = (kind_bits, value_ref)
        elif is_patch and meta is not None:
            # Field.owner is a Class OR a PatchClass (object.h Field::owner), and a
            # PatchClass's first ref is the class it wraps (raw_object.h:1348). Without
            # this hop 2,643 of the 34,848 named instance fields across the 44 cached apps
            # have an owner that resolves to nothing.
            meta["patch"][cl.start_ref + i] = first_ref


def _fill_class(st, cl, classes, class_sizes=None, class_library=None, class_unboxed=None):
    top_level = 1 << 20
    for i in range(cl.count):
        refs = [st.read_ref_id() for _ in range(13)]
        # UntaggedClass ReadFromTo order (PRODUCT AOT): [0]name [1]functions
        # [2]functions_hash_table [3]fields [4]offset_in_words_to_field [5]interfaces
        # [6]script [7]library [8]type_parameters [9]super_type [10]constants
        # [11]... [12]invocation_dispatcher_cache.
        name_ref = refs[0]
        super_ref = refs[9]
        if class_library is not None:
            class_library[cl.start_ref + i] = refs[7]
        class_id = st.read_int()
        instance_size = st.read_int()
        next_field_offset = st.read_int()
        if class_sizes is not None:
            # cross-checkable against the INSTANCE cluster's alloc-pass pair (see verify.py)
            class_sizes[class_id & 0xFFFFFFFF] = (instance_size, next_field_offset)
        st.read_int()   # type_args_offset
        st.read_int()   # num_type_arguments (int16)
        st.read_int()   # num_native_fields (uint16)
        st.read_int()   # state_bits (uint32)
        if i < cl.main_count or (class_id & 0xFFFFFFFF) < top_level:
            bitmap = st.read_unsigned()   # unboxed-fields bitmap
            if class_unboxed is not None:
                class_unboxed[class_id & 0xFFFFFFFF] = bitmap
        classes.append((cl.start_ref + i, name_ref, class_id, super_ref))


def _fill_type(st, cl, types, shift: int = 3):
    # v3.x Type fill: ReadFromTo = 3 refs (type_test_stub, arguments, hash);
    # then ReadUnsigned(flags). type_class_id is packed in the low bits of flags
    # (UntaggedType::type_class_id_ was folded into the flags word in 3.x).
    for i in range(cl.count):
        st.read_ref_id(); st.read_ref_id(); st.read_ref_id()
        flags = st.read_unsigned()
        # UntaggedAbstractType.flags_ (raw_object.h): nullability, then TypeStateBits (2),
        # then TypeClassIdBits (20). `kTypeClassIdShift = TypeStateBits::kNextBit`, so the
        # shift follows the WIDTH OF NULLABILITY, and that changed: `NullabilityBits` is
        # 2 bits through 3.4.4 and `NullabilityBit` is 1 bit from 3.5.4. Shift 4 then 3.
        # Hardcoding 3 read every Type one bit off on the six epochs at or below 3.4, which
        # cost superclass resolution rather than raising an error.
        types[cl.start_ref + i] = (flags >> shift) & 0xFFFFF


def _fill_instance(st, cl, arch=None):
    bitmap = st.read_unsigned()
    nfo = cl.next_field_offset
    header_words = arch.instance_header_words if arch else 2
    # ReadWordWith32BitReads loops kBitsPerWord/kBitsPerInt32 times, so an unboxed field is
    # two 32-bit reads on a 64-bit target and one on a 32-bit one.
    per_word = arch.read32_per_word if arch else 2
    num_fields = max(0, nfo - header_words)
    for _ in range(cl.count):
        for j in range(num_fields):
            if (bitmap >> (header_words + j)) & 1:
                for _ in range(per_word):
                    st.read_int()
            else:
                st.read_ref_id()


def _fill_code(st, cl, codes, instr_index):
    disc = cl.discarded or [False] * cl.count
    for i in range(cl.count):
        cluster_index = -1
        if i < cl.main_count:
            st.read_unsigned()          # payload_info
            cluster_index = instr_index[0]
            instr_index[0] += 1
            if disc[i]:
                st.read_ref_id()        # discarded: compressed_stackmaps, then stop
                continue
        elif disc[i]:
            continue                    # deferred + discarded: nothing
        owner_ref = -1
        for j in range(6):
            r = st.read_ref_id()        # owner, exc_handlers, pc_descriptors, catch_entry, inlined_id, code_source_map
            if j == 0:
                owner_ref = r
        if cluster_index >= 0:
            codes.append((cl.start_ref + i, owner_ref, cluster_index))


def _fill_object_pool(st, cl, pool, has_behavior: bool = True, tagged_first: bool = False):
    for _ in range(cl.count):
        length = st.read_unsigned()
        for _ in range(length):
            bits = st.byte()
            if not has_behavior:
                # Dart 3.2 and earlier: TypeBits is the low 7 bits and PatchableBit is bit
                # 7, so the patchable flag must be masked off rather than read as a
                # behavior. Reading it the 3.3 way makes every patchable entry look like a
                # non-zero behavior, which then skips the entry's value and desyncs.
                typ = bits & 0x7F
                if tagged_first:
                    # 3.1 numbers kTaggedObject first; 3.2 swapped it with kImmediate.
                    typ = {0: 1, 1: 0}.get(typ, typ)
                if typ == 0:
                    pool.append(("imm", st.read_int()))
                elif typ == 1:
                    pool.append(("ref", st.read_ref_id()))
                elif typ in (2, 3, 4):
                    # kNativeFunction, kSwitchableCallMissEntryPoint and
                    # kMegamorphicCallEntryPoint all resolve to a runtime address the VM
                    # fills in, so none of them carries a value in the stream. The last two
                    # were removed in 3.3.
                    pool.append(("native" if typ == 2 else "empty", 0))
                else:
                    raise FillError(f"objpool bad type {typ} bits 0x{bits:02x}")
                continue
            behavior = bits >> 5
            typ = bits & 0x0F
            if behavior == 0:
                if typ == 0:
                    pool.append(("imm", st.read_int()))       # raw immediate
                elif typ == 1:
                    pool.append(("ref", st.read_ref_id()))    # tagged object ref
                elif typ == 2:
                    pool.append(("native", 0))                # native function
                else:
                    raise FillError(f"objpool bad type {typ} bits 0x{bits:02x}")
            elif behavior in (1, 2, 3, 4):
                pool.append(("empty", 0))
            else:
                raise FillError(f"objpool bad behavior {behavior} bits 0x{bits:02x}")
