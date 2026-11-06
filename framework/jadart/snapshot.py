"""Dart clustered snapshot parser (stable core).

Parses the parts of the snapshot format that are stable across versions:
  header (magic/length/kind) -> version hash -> features -> counts -> the
  cluster-alloc tag sequence (cid + flags per cluster).

Byte layout verified against runtime/vm/{snapshot.h, app_snapshot.cc,
datastream.h} (dart-lang/sdk). See DESIGN.md for the annotated layout.

Per-cluster ReadAlloc/ReadFill bodies (the ~50 predefined clusters) are the
version-parameterized part and are NOT yet implemented here; walking past the
first cluster requires them. This module gives a correct, validated foundation:
header, version epoch (fail-loud), counts, and the first cluster's cid.
"""
from __future__ import annotations

from .errors import ContainerError, InputError, JadartError, MissingSymbol

import struct
from dataclasses import dataclass

from . import versions
from .macho import open_container

#: The symbols a library names its snapshot images with: two layouts, and the release
#: decides which. Through Dart 3.12 a library holds two snapshots, the vm one and the
#: isolate one, each a data image and an instructions image, four symbols in all. Dart
#: 3.13 writes one snapshot and so one pair (`kSnapshotDataAsmSymbol` and
#: `kSnapshotTextAsmSymbol`, runtime/include/dart_api.h at 3.13.0; the vm and isolate
#: definitions are gone from that header). The Asm spellings are what ImageWriter's
#: SectionSymbol returns for every container it writes (image_snapshot.cc), so a
#: Mach-O carries the same two names as an ELF.
VM_DATA = "_kDartVmSnapshotData"
ISOLATE_DATA = "_kDartIsolateSnapshotData"
#: Where the isolate instructions image starts, through 3.12. Every address jadart
#: prints is the instructions symbol plus a pc_offset; which symbol that is comes from
#: `images` below, never from this constant alone.
ISOLATE_INSTRUCTIONS = "_kDartIsolateSnapshotInstructions"
MERGED_DATA = "_kDartSnapshotData"
MERGED_INSTRUCTIONS = "_kDartSnapshotText"
from .stream import ReadStream

DART_MAGIC = 0xDCDCF5F5
#: Snapshot::Kind, snapshot.h. 0..3 are identical in every release jadart parses. Index 4
#: is not (kModule was inserted there in 3.12), so anything past kFullAOT reports its
#: number rather than a name no release binary would reach anyway.
KIND = {0: "kFull", 1: "kFullCore", 2: "kFullJIT", 3: "kFullAOT"}
_MAX_KIND = max(KIND)


class UnknownEpoch(JadartError):
    """Raised when the snapshot's (hash, features) is not a known format epoch."""


@dataclass
class SnapshotHeader:
    which: str            # "vm" or "isolate"
    length: int
    kind: int
    version_hash: str
    features: str
    num_base_objects: int
    num_objects: int
    num_clusters: int
    instr_table_len: int
    instr_table_rodata_offset: int
    first_cluster_cid: int | None
    epoch: versions.Epoch | None
    arch: versions.Arch | None = None   # the target half of the profile (see versions.py)

    @property
    def kind_name(self) -> str:
        return KIND.get(self.kind, f"?{self.kind}")


#: magic(4) + length(8) + kind(8) + the 32-char version hash. Anything shorter is not a
#: header, and struct.unpack_from would raise struct.error from inside the parse.
_MIN_HEADER = 52

#: The longest features string read, in bytes. It names the build's VM flags and target:
#: 310 AOT headers from 2.19.6 to 3.12.2 hold 118 to 159, and a JIT one up to 211. A
#: string as long as the file was read whole and given to `info -j` whole, six times over
#: as JSON escapes (#101).
_MAX_FEATURES = 4096

#: How many snapshots a library holds at most: the vm one and the isolate one, each
#: starting with the magic (a deferred loading unit has only an isolate one). Each of 46
#: real libapp.so (the corpus, the CTF apps, the fixtures) has the magic exactly twice,
#: and the scan for a stripped binary refuses a third rather than parsing every hit,
#: which cost a copy of the rest of the file for each one (#99).
_SNAPSHOTS = 2


@dataclass(frozen=True)
class Images:
    """The two symbols that locate a program's snapshot in one container.

    They say WHERE the images are and nothing about how to read them: the grammar comes
    from the version hash in the header, as it does for every other release, so a
    renamed symbol can never select a parse."""
    data: str            # the clustered stream, then the RO data image
    instructions: str    # the machine code; every pc_offset is relative to it
    merged: bool         # one snapshot (3.13 and later), not a vm and an isolate one


_SEPARATE = Images(ISOLATE_DATA, ISOLATE_INSTRUCTIONS, merged=False)
_MERGED = Images(MERGED_DATA, MERGED_INSTRUCTIONS, merged=True)


def _layout(container, label: str):
    """Which of the two symbol layouts `container` carries, or None for neither.

    Carrying both is refused. No toolchain writes that: the engine that loads the file
    looks up one family or the other, so which snapshot is the program depends on a
    reader jadart cannot see, and picking one would be a guess."""
    syms = container.symbols
    separate = [n for n in (VM_DATA, ISOLATE_DATA, ISOLATE_INSTRUCTIONS) if n in syms]
    merged = [n for n in (MERGED_DATA, MERGED_INSTRUCTIONS) if n in syms]
    if separate and merged:
        raise ContainerError(
            f"{label}: exports both snapshot layouts, {separate[0]} (Dart through 3.12) "
            f"and {merged[0]} (3.13 and later). A library carries one of them, so "
            f"jadart will not guess which snapshot is the program.")
    return _SEPARATE if separate else _MERGED if merged else None


def images(container, label: str = "this file") -> Images:
    """The symbols holding the program's snapshot, or the reason there are none.

    Every command that reads past the header starts here. Asking for the isolate
    symbol by name refused a Dart 3.13 library, which exports the merged pair, with
    "the snapshot is in libapp.so, not here" about the libapp.so itself (#253)."""
    found = _layout(container, label)
    if found is not None:
        return found
    wanted = f"{ISOLATE_DATA} (Dart through 3.12) or {MERGED_DATA} (3.13 and later)"
    at = container.find_snapshot_magic(limit=1)
    if at:
        raise MissingSymbol(
            f"{label}: a Dart snapshot starts at file offset 0x{at[0]:x}, but the "
            f"file exports neither {wanted}, so nothing says where its data and "
            f"instructions images are. `jadart info` reads the header from the magic "
            f"alone; every other command needs the symbols.")
    raise MissingSymbol(
        f"{label}: no Dart snapshot here. The file exports neither {wanted} and the "
        f"snapshot magic is nowhere in it. In a Flutter app the snapshot is in "
        f"libapp.so (Android) or the App binary (iOS), not in the engine or a plugin "
        f"library.")


def parse_blob(blob: bytes, which: str, *, strict: bool = True) -> SnapshotHeader:
    if len(blob) < _MIN_HEADER:
        raise InputError(
            f"{which}: {len(blob)} bytes is too short to be a snapshot header "
            f"(needs {_MIN_HEADER})")
    magic, = struct.unpack_from("<I", blob, 0)
    if magic != DART_MAGIC:
        # InputError, not ValueError: a caller following the documented API catches
        # JadartError, and a bare ValueError from here escaped every such clause.
        raise InputError(
            f"{which}: bad snapshot magic 0x{magic:08x} (expected 0x{DART_MAGIC:08x}). "
            f"This is not a Dart AOT snapshot.")
    length, = struct.unpack_from("<q", blob, 4)
    kind, = struct.unpack_from("<q", blob, 12)
    # Both come straight off disk and are trusted downstream: `length` locates the RO data
    # image on uncompressed targets, so a corrupt one silently mislocates every string.
    if not 0 < length <= len(blob):
        raise InputError(
            f"{which}: header declares length {length}, outside the blob "
            f"(0 < length <= {len(blob)})")
    if not 0 <= kind <= _MAX_KIND:
        raise InputError(
            f"{which}: header declares snapshot kind {kind}, which is not one of "
            f"{sorted(KIND)}")
    version_hash = blob[20:52].decode("ascii", "replace")
    if (blob.find(b"\x00", 52, 52 + _MAX_FEATURES + 1) < 0
            and len(blob) > 52 + _MAX_FEATURES):
        raise InputError(
            f"{which}: the features string is longer than {_MAX_FEATURES} bytes. A "
            f"real one from an AOT build is under 160, so this is not a snapshot header "
            f"jadart will read.")

    st = ReadStream(blob, 52)
    features = st.read_cstring()
    num_base_objects = st.read_unsigned()
    num_objects = st.read_unsigned()
    num_clusters = st.read_unsigned()
    instr_table_len = st.read_unsigned()
    instr_table_rodata_offset = st.read_unsigned()

    # UnsupportedTarget propagates even when strict=False: --lenient means "this version is
    # unknown, try anyway", but a known version on an unimplemented pointer model is a
    # grammar we know is wrong, not one we're just unsure of.
    profile = versions.resolve(version_hash, features)
    epoch = profile.epoch if profile else None
    arch = profile.arch if profile else None
    if epoch is None and strict:
        # Say what was found, what is covered, and what to do next. Listing fifteen raw
        # hashes answers none of those: a reader wants to know whether their app is inside
        # the supported range and, if not, how to place it.
        known = versions.known_epochs()
        lo, hi = (known[0].dart, known[-1].dart) if known else ("?", "?")
        f = versions.parse_features(features)
        target = f["arch"] or "unknown arch"
        if f["compressed"] is not None:
            target += "/compressed-pointers" if f["compressed"] else "/uncompressed-pointers"
        raise UnknownEpoch(
            f"unknown format epoch: version_hash={version_hash!r} ({target}).\n"
            f"  Refusing to guess, because the wrong grammar mis-parses rather than "
            f"failing.\n"
            f"  Supported: Dart {lo} through {hi}, {len(known)} epochs "
            f"(`jadart --version` lists them).\n"
            f"  To place this build:  python3 tools/sdk_source.py --identify "
            f"{version_hash} --tags <candidate SDK tags>")

    first_cid = None
    if num_clusters > 0 and epoch is not None:
        tag = st.read_uint32_tag()
        first_cid, _canon, _imm = epoch.tag.decode(tag)

    return SnapshotHeader(
        which=which, length=length, kind=kind, version_hash=version_hash,
        features=features, num_base_objects=num_base_objects,
        num_objects=num_objects, num_clusters=num_clusters,
        instr_table_len=instr_table_len,
        instr_table_rodata_offset=instr_table_rodata_offset,
        first_cluster_cid=first_cid, epoch=epoch, arch=arch)


def walk_isolate(path, *, full: bool = False) -> dict:
    """Full M2 pass on the isolate snapshot: parse header, walk the entire alloc
    pass (fail-loud on desync), then recover the canonical String cluster's text.
    Returns {header, clusters, cid_histogram, strings}. The `strings` are the
    interned identifier pool (class/method/field/type names), the raw material for
    name recovery. Raises on an unknown epoch or an alloc desync.

    `full=True` runs the complete fill walk instead, which reads every String cluster
    rather than only the canonical one. That is what the library API and `export` report,
    and the `strings` command used to take the cheaper path and answer 23 short, one
    tool, two numbers, with nothing to say which was meant."""
    from collections import Counter
    from .clusters import walk_alloc
    from .fill import recover_canonical_strings

    from .source import read_binary
    src = read_binary(path)
    elf = open_container(src.data)
    blob = elf.symbol_bytes(images(elf, src.label).data)
    hdr = parse_blob(blob, "isolate", strict=True)
    if hdr.epoch is None:
        raise UnknownEpoch(f"unknown epoch for {src.label}")

    st = ReadStream(blob, 52)
    st.read_cstring()
    for _ in range(5):
        st.read_unsigned()
    clusters = walk_alloc(st, hdr.num_base_objects, hdr.num_objects,
                          hdr.num_clusters, epoch=hdr.epoch, is_root_unit=True, arch=hdr.arch)
    if full:
        from .fillwalk import walk_fill
        strings = sorted(set(walk_fill(st, clusters, hdr.epoch, arch=hdr.arch)
                             .strings.values()))
    else:
        strings = recover_canonical_strings(st, clusters, hdr.epoch, hdr.arch)
    hist = Counter()
    for cl in clusters:
        hist[cl.name] += cl.count      # objects per cid, summed across clusters
    return {"header": hdr, "clusters": clusters, "strings": strings,
            "cid_histogram": dict(hist.most_common())}


def parse_libapp(path, *, strict: bool = True) -> dict[str, SnapshotHeader]:
    """Parse every snapshot header in a libapp.so, keyed "vm" and "isolate".

    A Dart 3.13 library holds one snapshot, which is the program's, so it is keyed
    "isolate" and there is no "vm" entry: `header(path)["isolate"]` means the same
    thing on every release.

    `path` is a libapp.so, a directory, an APK or IPA, or a Source already read out of
    one. A container is read in place, never unpacked; see source.py."""
    return parse_libapp_with_anchor(path, strict=strict)[0]


def parse_libapp_with_anchor(path, *, strict: bool = True):
    """`(headers, anchor)` from a single read of the container.

    `anchor` describes where the isolate instructions image sits, or is None when the
    binary has no such export. It comes from here rather than from a second open because
    holding the file twice cost `jadart info` a third of its memory, and reporting the
    anchor is the whole reason it needs the container at all."""
    from .source import read_binary
    src = read_binary(path)
    data = src.data
    elf = open_container(data)
    layout = _layout(elf, src.label)
    anchor = _anchor_from(elf, layout)
    out: dict[str, SnapshotHeader] = {}
    named = () if layout is None else (
        (("isolate", layout.data),) if layout.merged
        else (("vm", VM_DATA), ("isolate", layout.data)))
    for which, sym in named:
        try:
            blob = elf.symbol_bytes(sym)
        except MissingSymbol:
            # Absent is an answer here: a stripped build has neither symbol and falls
            # through to the magic scan below. Anything else (a symbol pointing outside
            # the file) is corruption and propagates.
            continue
        out[which] = parse_blob(blob, which, strict=strict)
    if not out:
        # stripped: fall back to magic scan. One hit past what a library holds is enough
        # to refuse, so the scan stops there instead of finding them all.
        found = elf.find_snapshot_magic(limit=_SNAPSHOTS + 1)
        if len(found) > _SNAPSHOTS:
            raise InputError(
                f"{src.label}: no _kDart*SnapshotData symbols, and the snapshot magic is "
                f"at {len(found)} or more file offsets "
                f"({', '.join(hex(o) for o in found)}). A Flutter library holds at most "
                f"{_SNAPSHOTS} snapshots, the vm and the isolate one, so jadart will not "
                f"guess which of these they are.")
        for i, off in enumerate(found):
            out[f"blob{i}"] = parse_blob(data[off:], f"blob{i}", strict=strict)
    if not out:
        raise InputError(
            f"{src.label}: no Dart snapshot found (missing _kDart*SnapshotData symbols and "
            f"no snapshot magic). Not a Flutter/Dart AOT library?")
    return out, anchor


def _anchor_from(elf, layout):
    """Where the program's instructions image sits, read off the container it came from.

    The symbol names live here rather than being imported from disasm.py: that module
    imports capstone, which costs 8 MB of RSS, and `info` does not disassemble anything.
    disasm.py re-exports the pre-3.13 name so there is still one definition of it."""
    name = layout.instructions if layout is not None else None
    sym = elf.symbols.get(name) if name else None
    if sym is None:
        return None
    try:
        # ELF records the size; Mach-O leaves it 0 and derives it by copying the image, so
        # only pay that where there is no recorded size.
        size = sym.size or len(elf.symbol_bytes(name))
        return {"symbol": name, "va": sym.value,
                "file_offset": elf.va_to_offset(sym.value), "size": size,
                "container": "macho" if type(elf).__name__ == "MachO64" else "elf"}
    except JadartError:
        return None
