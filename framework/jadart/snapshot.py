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

from .errors import JadartError

import struct
from dataclasses import dataclass

from . import versions
from .macho import open_container
from .stream import ReadStream

DART_MAGIC = 0xDCDCF5F5
#: Snapshot::Kind, snapshot.h. kFullCore was missing from this table, so every value
#: from 1 up was shifted by one and every Flutter release snapshot, which is kind 3,
#: kFullAOT, was reported as "kModule". Wrong in `info`, in the export header, and in
#: anything quoting them.
#:
#: It also misleads about the format: LibraryPrefix serialises `name` and `imports` under
#: kFullAOT but is UNREACHABLE under kModule (raw_object.h:2891), so the mislabel makes
#: the cluster grammar look impossible to derive.
#:
#: 0..3 are identical in every release jadart parses. Index 4 is not: kModule was inserted
#: there in 3.12 and everything below it has kNone. Rather than pick one, anything past
#: kFullAOT reports its number, which no release binary reaches.
KIND = {0: "kFull", 1: "kFullCore", 2: "kFullJIT", 3: "kFullAOT"}


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


def parse_blob(blob: bytes, which: str, *, strict: bool = True) -> SnapshotHeader:
    magic, = struct.unpack_from("<I", blob, 0)
    if magic != DART_MAGIC:
        raise ValueError(f"bad snapshot magic 0x{magic:08x}")
    length, = struct.unpack_from("<q", blob, 4)
    kind, = struct.unpack_from("<q", blob, 12)
    version_hash = blob[20:52].decode("ascii", "replace")

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


def walk_isolate(path: str, *, full: bool = False) -> dict:
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

    data = open(path, "rb").read()
    elf = open_container(data)
    blob = elf.symbol_bytes("_kDartIsolateSnapshotData")
    hdr = parse_blob(blob, "isolate", strict=True)
    if hdr.epoch is None:
        raise UnknownEpoch(f"unknown epoch for {path}")

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


def parse_libapp(path: str, *, strict: bool = True) -> dict[str, SnapshotHeader]:
    """Parse both snapshots (vm + isolate) from a libapp.so."""
    data = open(path, "rb").read()
    elf = open_container(data)
    out: dict[str, SnapshotHeader] = {}
    for which, sym in (("vm", "_kDartVmSnapshotData"),
                       ("isolate", "_kDartIsolateSnapshotData")):
        try:
            blob = elf.symbol_bytes(sym)
        except KeyError:
            continue
        out[which] = parse_blob(blob, which, strict=strict)
    if not out:
        # stripped: fall back to magic scan
        for i, off in enumerate(elf.find_snapshot_magic()):
            out[f"blob{i}"] = parse_blob(data[off:], f"blob{i}", strict=strict)
    if not out:
        raise ValueError(
            f"{path}: no Dart snapshot found (missing _kDart*SnapshotData symbols and "
            f"no snapshot magic). Not a Flutter/Dart AOT library?")
    return out
