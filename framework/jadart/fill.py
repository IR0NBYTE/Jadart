"""Fill-pass recovery for the name-bearing clusters (jadart M2, WP-1b).

The clustered snapshot runs alloc for ALL clusters, then fill for ALL clusters in
the same order. The canonical String cluster is the first cluster, so its fill data
(the actual character bytes) sits at the very start of the fill section, right after
the alloc pass ends. Recovering it yields the interned identifier pool: class names,
method selectors, field names, type names. That pool is what a name-recovery tool
needs, and it is where obfuscation's effect shows up (the identifier strings are
absent from an --obfuscate build).

String fill grammar (app_snapshot.cc:7081-7134, confirmed): per string, re-read the
`encoded` length varint (encoded>>1 = code-unit length, encoded&1 = is-two-byte),
then the raw code units: one Latin-1 byte per unit for OneByteString, two
little-endian bytes per unit for TwoByteString. The hash is computed, not stored.
"""
from __future__ import annotations

from . import cids as C
from .stream import ReadStream
from .clusters import Cluster


def read_string_cluster_fill(st: ReadStream, cluster: Cluster) -> list[str]:
    """Read one String cluster's fill body. `st` must be positioned at the start of
    this cluster's fill section. Returns the recovered strings in ref-id order."""
    if cluster.name != "StringCid":
        raise ValueError(f"not a String cluster: {cluster.name}")
    out: list[str] = []
    for _ in range(cluster.count):
        enc = st.read_unsigned()
        length, two_byte = enc >> 1, (enc & 1)
        if two_byte:
            raw = st.read_bytes(length * 2)
            out.append(raw.decode("utf-16-le", "replace"))
        else:
            raw = st.read_bytes(length)
            out.append(raw.decode("latin-1"))
    return out


def recover_canonical_strings(st: ReadStream, clusters: list[Cluster],
                              epoch=None, arch=None) -> list[str]:
    """After a completed alloc walk (st at the fill-section start), recover the first
    (canonical) String cluster's text. Returns [] if the first cluster is not String.

    On an uncompressed-pointer target that cluster is still named StringCid but is read
    through RODataDeserializationCluster: its ReadFill is empty and the characters live in
    the data image. Keying on the name alone therefore aims a stream reader at bytes that
    belong to the next cluster, which is how this used to die on arm32 and iOS."""
    from .clusters import RODATA
    if not clusters or clusters[0].name != "StringCid":
        return []
    if clusters[0].pattern == RODATA:
        if epoch is None:
            return []
        from .fillwalk import _rodata_strings
        out: dict = {}
        _rodata_strings(st.data, clusters[0], out, epoch.cid_table, arch)
        return [out[k] for k in sorted(out)]
    return read_string_cluster_fill(st, clusters[0])


def printable(s: str) -> str:
    """One recovered string, safe to put on a line of output.

    Dart string literals are arbitrary text: they contain newlines, tabs, NULs and lone
    surrogates from UTF-16 pairs. Writing them raw makes the output not line-oriented, so a
    string holding a newline becomes two lines and `file` reports the whole dump as binary,
    at which point grep skips it silently and the answer looks absent rather than unreadable.
    Escaping keeps one string on one line and keeps the dump greppable, which is the entire
    point of having it.
    """
    out = []
    for ch in s:
        if ch in "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif (ch < " " or ch == "\x7f" or "\ud800" <= ch <= "\udfff"
              # NEL, LINE SEPARATOR and PARAGRAPH SEPARATOR are not ASCII newlines but
              # several tools still break lines on them, which would undo the point of this.
              or ch in "  "):
            out.append(f"\\x{ord(ch):02x}" if ord(ch) < 256 else f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)
