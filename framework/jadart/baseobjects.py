"""The isolate snapshot's base objects, read out of the vm snapshot beside it.

Through Dart 3.12 a library holds two snapshots. The VM loads the vm one first and
keeps every object of it in a table indexed by ref (`Object::
set_vm_isolate_snapshot_object_table(refs)`, VMDeserializationRoots::PostLoad). The
isolate snapshot then opens by taking that table as its base objects, in order
(ProgramDeserializationRoots::AddBaseObjects), and numbers its own objects after them.
So base ref N of the isolate snapshot IS ref N of the vm snapshot, and the isolate
snapshot writes nothing of it but the number: a function named `==`, `add` or
`<anonymous closure>` names a string that is only in the vm snapshot, and so do the
Smis 0, 1 and 2 of an arguments descriptor on the releases whose vm snapshot holds
them.

The vm snapshot is read with the grammar of the isolate one, alloc pass and fill
pass, with the one difference clusters.walk_alloc documents under `vm`. It was read
on 35 real builds: 14 releases from 2.19.6 to 3.12.2, each on arm64 and 13 on arm32
as well, and the lines this rests on are in app_snapshot.cc unchanged in every
registered release from 2.19.6 to 3.12.2. On each of those builds the fill and the
roots behind it end on the last byte the header counts.

What is read is the strings, the Smis and the Arrays. What is not: the vm snapshot's
own base objects, refs 1 to its num_base_objects (null, the sentinels, true, false,
the cached arguments descriptors, the VM's internal classes). The VM makes those
before it loads any snapshot (Object::InitOnce) and no file states them, so they stay
as they were: unnamed.

Dart 3.13 writes one snapshot, whose base objects are seven fixed roots, so there is
nothing to read there and nothing is.

All or nothing. The vm snapshot has to be the one this isolate snapshot was written
against, it has to walk to its last byte, and its roots have to be the ones the VM
reads there. Short of that nothing of it is used, and every base ref is as blank as
it was before this was read: a wrong table would put a neighbour's name on every
function that has one. A refusal is kept, with the bytes of the file it is about, for
the command to state (`refusal`): a listing with a fifth of its names missing looks
like any other listing.
"""
from __future__ import annotations

import struct
from bisect import bisect_right
from dataclasses import dataclass, field

from .errors import InputError, JadartError, MissingSymbol
from .stream import ReadStream
from .vmstubs import read_stub_code

_STRINGS = frozenset({"StringCid", "OneByteStringCid", "TwoByteStringCid"})
#: What the symbol-table root may be: a WeakArray (3.3.4 and later builds), an Array
#: (2.19.6), or null where the strings are in the RO data image and the table is
#: rebuilt from the cluster's canonical-set layout (`should_write_symbol_table_`).
_TABLES = frozenset({"WeakArrayCid", "ArrayCid"})
#: Snapshot::kMagicSize. The length a header stores leaves the magic out.
_MAGIC_SIZE = 4


class BaseObjectsError(InputError):
    """The vm snapshot is there and is not one the base objects can be read from."""


@dataclass
class BaseObjects:
    """What the vm snapshot states, by ref. A ref is the isolate snapshot's as well."""
    first_ref: int       # the first ref the vm snapshot's own clusters allocate
    stop_ref: int        # one past its last: the isolate snapshot's first own ref
    strings: dict        # ref -> str
    smi_values: dict     # ref -> int
    arrays: dict         # ref -> tuple of element refs
    #: What `read_stub_code` reads the stubs' instructions from, or (). They are read
    #: on first use: only the commands that match stub code need them, and reading
    #: them imports the disassembler, which `classes` and `info` never load.
    stub_source: tuple = field(default=(), repr=False, compare=False)
    _stub_code: tuple = field(default=None, init=False, repr=False, compare=False)

    @property
    def stub_code(self) -> tuple:
        """The instructions of each of its stubs, in the order its roots list them,
        where that is the order of the release's VM_STUB_CODE_LIST
        (vmstubs.read_stub_code), or ()."""
        if self._stub_code is None:
            self._stub_code = (read_stub_code(*self.stub_source) if self.stub_source
                               else ())
        return self._stub_code


def read_base_objects(container, hdr):
    """The BaseObjects of the snapshot whose header is `hdr`, read from `container`.

    None where there is no vm snapshot to read: a Dart 3.13 library, or one that does
    not export the vm snapshot's symbol. BaseObjectsError, or the walk's own
    JadartError, where there is one and it does not hold together."""
    from .snapshot import VM_DATA, parse_blob
    from .clusters import walk_alloc
    from .fillwalk import walk_fill

    if hdr.epoch is None or hdr.epoch.merged:
        return None
    try:
        blob = container.symbol_bytes(VM_DATA)
    except MissingSymbol:
        return None
    vm = parse_blob(blob, "vm", strict=True)
    # The VM checks each snapshot's version and target against itself before it reads
    # either, so the two always agree in a file it loads. One that differs would be
    # read here with the wrong grammar.
    if vm.version_hash != hdr.version_hash or vm.arch != hdr.arch:
        raise BaseObjectsError(
            f"vm: the vm snapshot is version {vm.version_hash!r:.40}, and the isolate "
            f"snapshot is {hdr.version_hash!r:.40}, or their targets differ. The base "
            f"objects of one are not the objects of the other.")
    # Deserializer::Deserialize: "Snapshot expects %d base objects, but deserializer
    # provided %d", a FATAL in a release build. It is what makes the refs line up.
    if vm.num_objects != hdr.num_base_objects:
        raise BaseObjectsError(
            f"vm: the vm snapshot holds {vm.num_objects} objects, and the isolate "
            f"snapshot counts {hdr.num_base_objects} base objects. Every base ref "
            f"would name a neighbour.")

    st = ReadStream(blob, 52)
    st.read_cstring()
    for _ in range(5):
        st.read_unsigned()
    clusters = walk_alloc(st, vm.num_base_objects, vm.num_objects, vm.num_clusters,
                          epoch=vm.epoch, is_root_unit=True, arch=vm.arch, vm=True)
    fr = walk_fill(st, clusters, vm.epoch, arch=vm.arch)
    end = struct.unpack_from("<q", blob, 4)[0] + _MAGIC_SIZE
    stubs = _check_roots(st, clusters, end)
    return BaseObjects(first_ref=vm.num_base_objects + 1, stop_ref=vm.num_objects + 1,
                       strings=fr.strings, smi_values=fr.smi_values, arrays=fr.arrays,
                       stub_source=(container, blob, end, vm, fr.codes, stubs))


def _check_roots(st: ReadStream, clusters, end: int) -> list:
    """Read the vm snapshot's roots, which have to end where the header says the
    snapshot does, and be the roots the VM reads. Returns the stubs' refs, in the
    order the roots hold them.

    VMDeserializationRoots::ReadRoots: from 3.9 a ref for each predefined symbol, then
    in every release the symbol table and a ref for each stub (StubCode::EntryAtPut).
    What is held to is what the 35 real builds have:

      the stubs come last and are the vm snapshot's Code objects, each of them once.
        Not in rising order on any build, so the order is not held to here; it is
        the order of VM_STUB_CODE_LIST, which vmstubs.py holds a build to.
      the one ref before them is a WeakArray or an Array of the vm snapshot, or null,
        which is what every arm32 build writes.
      the refs before that are strings, and between them they name every string the vm
        snapshot holds (806 roots for 804 strings on 3.12.2: a symbol may be named
        twice), or there are none, as before 3.9.

    What is not: which release writes the symbols, how many it has and their order.
    None of that is looked up, so roots with no symbol at all pass on a 3.12 build and
    so do the symbols in another order. Every string is read by the fill either way,
    at the ref the cluster gives it; the roots add no name and move none. A stream
    read with a wrong grammar does not end on these, on the byte the header counts."""
    if st.pos > end:
        raise BaseObjectsError(
            f"vm: the fill ends at offset {st.pos}, past the {end} bytes the header "
            f"says the snapshot has.")
    roots = []
    while st.pos < end:                 # one byte a ref at least, so at most `end` refs
        roots.append(st.read_ref_id())
    if st.pos != end:
        raise BaseObjectsError(
            f"vm: the roots end at offset {st.pos}, and the header says the snapshot "
            f"ends at {end}.")
    # The refs of each kind, as the clusters allocate them: in order, no two sharing a
    # ref. A root is looked up by bisection, so a crafted snapshot of many clusters and
    # many roots costs the roots times a logarithm, not the product of the two.
    code, tables, strings = _Spans(), _Spans(), _Spans()
    for cl in clusters:
        if cl.name == "CodeCid":
            code.add(cl.start_ref, cl.stop_ref)
        elif cl.name in _TABLES:
            tables.add(cl.start_ref, cl.stop_ref)
        elif cl.name in _STRINGS:
            strings.add(cl.start_ref, cl.stop_ref)
    codes = code.refs
    if not codes or len(roots) <= codes:
        raise BaseObjectsError(
            f"vm: {len(roots)} roots and {codes} Code objects. An AOT vm snapshot's "
            f"roots are its symbol table and then every stub.")
    stubs, table, symbols = roots[-codes:], roots[-codes - 1], roots[:-codes - 1]
    if (len(set(stubs)) != codes or not all(r in code for r in stubs)
            or not (table == 1 or table in tables)
            or not all(r in strings for r in symbols)
            or (symbols and len(set(symbols)) != strings.refs)):
        raise BaseObjectsError(
            "vm: the roots are not predefined symbols, the symbol table and one ref "
            "for each Code object, which is what the VM reads there.")
    return stubs


class _Spans:
    """Ref ranges added in rising order, and whether a ref is in one of them."""

    def __init__(self):
        self.starts, self.stops, self.refs = [], [], 0

    def add(self, start: int, stop: int) -> None:
        if stop > start:
            self.starts.append(start)
            self.stops.append(stop)
            self.refs += stop - start

    def __contains__(self, ref) -> bool:
        i = bisect_right(self.starts, ref) - 1
        return i >= 0 and ref < self.stops[i]


#: The bytes of the last file whose vm snapshot was refused, and why. A process reads
#: one file and a server holds one, and the bytes are held so that `is` names them.
_refused = (None, "")


def base_objects(container, hdr, data=None):
    """`read_base_objects`, or None where the vm snapshot is refused.

    A file whose vm snapshot does not hold together is read as every file was before
    the vm snapshot was: its base refs are blank. The isolate snapshot is still what
    it says it is. `data` is the bytes of the file `container` was opened on, and
    with it the reason is kept for `refusal`: the command says it once on stderr and
    in `-j`, and `verify` fails G13 with it."""
    global _refused
    try:
        return read_base_objects(container, hdr)
    except JadartError as e:
        if data is not None:
            _refused = (data, str(e))
        return None


def refusal(data) -> str:
    """Why the vm snapshot of the file whose bytes are `data` was refused, or "" where
    it was read, there is none, or nothing has read that file here."""
    return _refused[1] if data is not None and _refused[0] is data else ""
