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

import re
import unicodedata

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

    It escapes what a name escapes (`_hides`): every control character, C1 included, every
    format character such as a bidi override or a zero width space, separators other than
    the space, and the blank-rendering letters in `_BLANKS`. A literal holding U+202E
    reversed the line it was printed on, and 0x80 to 0x9f went out raw (#78). An emoji
    built with U+200D or U+FE0F shows those as escapes too, which costs a dump read to
    find things nothing. Spelled `\\n`, `\\r`, `\\t` and `\\\\`, `\\xNN` below 0x100,
    `\\uNNNN`, and `\\UNNNNNNNN` past the BMP, where `\\u1f600` would read ambiguously.
    """
    if s.isprintable() and "\\" not in s and not _ODD.search(s):
        return s
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif _hides(ch):
            o = ord(ch)
            out.append(f"\\x{o:02x}" if o < 256 else
                       f"\\u{o:04x}" if o <= 0xFFFF else f"\\U{o:08x}")
        else:
            out.append(ch)
    return "".join(out)


def quoted(s: str, limit: int = 0) -> str:
    """One recovered string as a literal between double quotes: printable(), and `"`
    written as `\\"`, so that a quote in the string cannot end the literal early. A string
    holding `a" ; isAdmin = true; x = "b` printed raw reads as code the binary does not
    hold, and clean's own 128-character ASCII table read as `"... !"` and then code (#83).

    With a `limit`, a body longer than it is cut to `limit - 3` characters and `...`, at
    the end of an escape, never inside one, so a cut cannot leave a backslash that takes
    the closing quote or half of a `\\xNN`. Only the first `limit + 1` characters are
    read: an escape is never shorter than its character, so past them the body is long
    already. Escaping all of a long string before cutting it made each slot naming it
    cost its whole length, and a crafted pool names one string from every slot (#91)."""
    body = printable(s[:limit + 1] if limit else s).replace('"', '\\"')
    if not limit or len(body) <= limit:
        return f'"{body}"'
    out, n = [], 0
    for ch in s:
        piece = printable(ch).replace('"', '\\"')
        if n + len(piece) > limit - 3:
            break
        out.append(piece)
        n += len(piece)
    return '"' + "".join(out) + '..."'


#: Code points that are not in a C* or Z* category but still render as nothing, so a name
#: carrying them looks like a different name. Unicode calls most of these
#: Default_Ignorable_Code_Point; HANGUL FILLER and HALFWIDTH HANGUL FILLER are letters by
#: category, and BRAILLE PATTERN BLANK is a symbol, which is exactly why they get through
#: a category test. The variation selectors and the Mongolian range are here for the same
#: reason. A combining solidus is not blank but stacks onto its neighbour, so it goes too.
_BLANKS = frozenset(
    "\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u3164\u2800\ufeff\uffa0\u0338"
    + "".join(chr(c) for c in range(0x180B, 0x180F))
    + "".join(chr(c) for c in range(0x200B, 0x2010))
    + "".join(chr(c) for c in range(0x2060, 0x2070))
    + "".join(chr(c) for c in range(0xFE00, 0xFE10))
    + "".join(chr(c) for c in range(0xFFF0, 0xFFF9))
)
#: Longest name printed whole, counted as printed. The longest across the fixtures, the
#: CTF apps and the corpus is 165 characters, a mixin application class
#: (`__ConstMap&_HashVMImmutableBase&MapMixin&...`), and an app that mixes more in makes
#: longer ones, so this is no shorter. Printed whole, one long name cost its length at
#: every slot, call and member that names it, and one string names any number (#94).
NAME_CUT = 200
#: What visible() escapes that str.isprintable() lets through.
_ODD = re.compile("[" + re.escape("".join(sorted(_BLANKS))) + "]")


def _hides(ch: str) -> bool:
    """Whether `ch` renders as nothing or changes how its neighbours render: a control or
    format character, a surrogate, an unassigned or private code point, a line or
    paragraph separator, a space other than U+0020, or one of `_BLANKS`. What
    isprintable() refuses, plus `_BLANKS`."""
    cat = unicodedata.category(ch)
    return (cat[0] == "C" or cat in ("Zl", "Zp") or (cat == "Zs" and ch != " ")
            or ch in _BLANKS)


def visible(text: str, backslash: bool = True, limit: int = 0) -> str:
    """`text` with every character that renders as nothing, or changes how its neighbours
    render, written as a \\u escape: controls, bidi overrides, zero width and other
    format characters, line and paragraph separators, unassigned code points, and the
    blank-rendering letters and symbols in `_BLANKS`. A name holding U+202E shows reversed
    in a disassembler, and one padded with U+3164 looks like a shorter name, so either can
    pass for another one.

    It is how a name from the binary reaches output, where printable() is how a string
    literal does: a name has to read as one token, so it escapes more (#74). A backslash
    is escaped too, so the result reads back unambiguously, unless `backslash` is False,
    for text that may already be the output of this function and must not be escaped
    twice.

    With a `limit`, text longer than that once escaped is cut, at the end of an escape,
    to at most `limit` characters, and `\\... (N chars)` follows, N its length as written.
    Read left to right, every other backslash in the result starts `\\\\`, `\\u` or `\\U`
    as long as `backslash` holds, so the marker reads as a cut and no name can spell one.
    Only the first `limit + 1` characters are read, as in quoted(). A name is printed
    with NAME_CUT wherever it is named (#94).

    A name that needs none of it, which is every name a compiler wrote, costs an
    isprintable() and a regex search: isprintable() refuses exactly categories C* and Z*
    but the space."""
    if limit:
        head = visible(text[:limit + 1], backslash)
        if len(head) <= limit:
            return head
        out, n = [], 0
        for ch in text:
            piece = visible(ch, backslash)
            if n + len(piece) > limit:
                break
            out.append(piece)
            n += len(piece)
        return "".join(out) + f"\\... ({len(text)} chars)"
    if text.isprintable() and not _ODD.search(text) and not (backslash and "\\" in text):
        return text
    out = []
    for ch in text:
        if _hides(ch) or (backslash and ch == "\\"):
            out.append("\\\\" if ch == "\\" else
                       f"\\u{ord(ch):04x}" if ord(ch) <= 0xFFFF else f"\\U{ord(ch):08x}")
        else:
            out.append(ch)
    return "".join(out)
