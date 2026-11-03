#!/usr/bin/env python3
"""Generate a jadart object-store root layout for one SDK release, from object_store.h.

An AOT program snapshot writes its ROOTS after the fill pass: the isolate ObjectStore's
pointer fields, in declaration order, from `from()` through `to_snapshot(kFullAOT)`
(app_snapshot.cc, ProgramDeserializationRoots::ReadRoots). Most of the tail of that run is
the runtime stubs generated code calls, so the sequence is where a stub's NAME comes from
on a build that carries no symbol for one.

The order is a macro expansion, OBJECT_STORE_FIELD_LIST, so don't transcribe it by hand:
expand it from the release's own header, the way gen_cids.py expands the cid enum. A field
inserted or dropped shifts every later index, and a shifted index would name a stub after
its neighbour. OBJECT_STORE_STUB_CODE_LIST beside it gives each field's stub name in the
spelling the VM's own symbols use (`_iso_stub_<Name>Stub`, image_snapshot.cc).

DEV-TIME ONLY. jadart itself stays offline and ships the generated table; nothing under
jadart/ imports this.

    python3 tools/gen_objstore.py --tag 3.12.2            # what the release declares
    python3 tools/gen_objstore.py --tag 3.12.2 --emit     # the Python literal
    python3 tools/gen_objstore.py --check            # bundled layouts vs their source
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from sdk_source import fetch, FetchError  # noqa: E402

#: The macro parameters OBJECT_STORE_FIELD_LIST takes. Every one of them declares a
#: pointer field, so all of them count towards a root index, not just RW.
_MACROS = ("R_", "RW", "ARW_RELAXED", "ARW_AR",
           "LAZY_CORE", "LAZY_ASYNC", "LAZY_ISOLATE", "LAZY_INTERNAL", "LAZY_FFI")
_ENTRY_RE = re.compile(r"(" + "|".join(_MACROS) + r")\(\s*(\w+)\s*,\s*(\w+)\s*\)")
_STUB_ENTRY_RE = re.compile(r"DO\(\s*(\w+)\s*,\s*(\w+)\s*\)")
_AOT_RE = re.compile(r"case Snapshot::kFullAOT:\s*"
                     r"return reinterpret_cast<ObjectPtr\*>\(&(\w+)_\);")


def _macro_body(src: str, name: str) -> str:
    """The body of `#define <name>(...)`, with its line continuations folded away.

    Folding matters: an entry whose field name is long enough wraps, and a line-by-line
    read drops exactly those (`null_cast_error_stub_without_fpu_regs_stub` is one), which
    would leave the stub unnamed rather than fail."""
    head = f"#define {name}("
    i = src.index(head)
    out = []
    for line in src[i:].split("\n"):
        out.append(line)
        if not line.rstrip().endswith("\\"):
            break
    return re.sub(r"\\\s*\n\s*", " ", "\n".join(out))


def layout_for_tag(tag: str) -> dict:
    """{count, codes, fields} for the AOT root run at this SDK tag.

    `count` is how many refs the deserializer reads, `codes` is (root index, stub name or
    None) for every Code-typed field in that run, and `fields` is the whole ordered run,
    which --check uses to say WHERE two releases differ."""
    src = fetch(tag, "object_store.h").decode("utf-8", "replace")
    entries = _ENTRY_RE.findall(_macro_body(src, "OBJECT_STORE_FIELD_LIST"))
    if not entries:
        raise FetchError(f"{tag}: OBJECT_STORE_FIELD_LIST expanded to nothing")
    m = _AOT_RE.search(re.sub(r"\s+", " ", src))
    if m is None:
        raise FetchError(f"{tag}: no `case Snapshot::kFullAOT:` in to_snapshot()")
    names = [e[2] for e in entries]
    if m.group(1) not in names:
        raise FetchError(f"{tag}: to_snapshot(kFullAOT) names {m.group(1)}, which is not "
                         "a field of OBJECT_STORE_FIELD_LIST")
    count = names.index(m.group(1)) + 1
    stubs = dict(_STUB_ENTRY_RE.findall(_macro_body(src, "OBJECT_STORE_STUB_CODE_LIST")))
    codes = tuple((i, stubs.get(names[i]))
                  for i in range(count) if entries[i][1] == "Code")
    return {"count": count, "codes": codes, "fields": tuple(names[:count]),
            "boundary": m.group(1)}


#: Which releases share one root run, newest first. A layout is keyed on the release
#: because the root count moves nearly every release (244 at 3.12, 224 at 2.19), while the
#: cluster grammar epochs are much broader. Grouping is not assumed either: --emit-all
#: re-derives every tag in a group and refuses to emit if they are not identical.
#:
#: `3.8.1` is the tag read for the objectheader-3.8 epoch, whose binary was identified
#: from a Dart revision (Flutter 3.32.0 pins b04011c7) rather than from a release tag; the
#: reader's agreement check is what decides whether the tag's layout fits such a binary.
GROUPS = (
    ("3_12", ("3.12.2", "3.12.0")),
    ("3_11", ("3.11.5",)),
    ("3_10", ("3.10.9",)),
    ("3_9", ("3.9.2",)),
    ("3_6", ("3.8.1", "3.7.2", "3.6.2")),
    ("3_5", ("3.5.4",)),
    ("3_4", ("3.4.4",)),
    ("3_1", ("3.3.4", "3.3.0-174.2.beta", "3.1.5")),
    ("3_0", ("3.2.6", "3.0.6", "3.0.1")),
    ("2_19", ("2.19.6", "2.19.0-444.2.beta")),
)


def _releases(tags) -> str:
    return tags[0] if len(tags) == 1 else ", ".join(tags[:-1]) + " and " + tags[-1]


def emit_group(label: str, tags, got: dict) -> str:
    """One layout as the Python literal jadart/objstore.py holds."""
    head = (f"Dart {_releases(tags)}. {got['count']} roots, ending at "
            f"`{got['boundary']}`; {len(got['codes'])} of them Code.")
    out = [f"#: {line}" for line in textwrap.wrap(head, 86)]
    out.append(f"_STUBS_{label}: dict[int, str] = {{")
    for i, name in got["codes"]:
        if name is not None:
            out.append(f"    {i}: {name!r},")
    out.append("}")
    unnamed = tuple(i for i, name in got["codes"] if name is None)
    if not unnamed:
        out.append(f"ROOTS_{label} = RootLayout(count={got['count']}, "
                   f"stubs=_STUBS_{label})")
        return "\n".join(out)
    note = ("Code-typed roots OBJECT_STORE_STUB_CODE_LIST does not name: "
            + ", ".join(got["fields"][i] for i in unnamed) + ".")
    out.append(f"ROOTS_{label} = RootLayout(")
    out.append(f"    count={got['count']}, stubs=_STUBS_{label},")
    out += [f"    #: {line}" for line in textwrap.wrap(note, 82)]
    out.append(f"    unnamed=frozenset({{{', '.join(map(str, unnamed))}}}))")
    return "\n".join(out)


def emit_all() -> str:
    """The whole generated section of jadart/objstore.py."""
    parts, index = [], []
    for label, tags in GROUPS:
        got = [layout_for_tag(t) for t in tags]
        for g in got[1:]:
            if (g["count"], g["codes"], g["boundary"]) != (
                    got[0]["count"], got[0]["codes"], got[0]["boundary"]):
                raise FetchError(f"group {label}: {tags} do not share one root run")
        parts.append(emit_group(label, tags, got[0]))
        index += [(t, f"ROOTS_{label}") for t in tags]
    body = "\n\n".join(parts)
    rows = "\n".join(f"    {t!r}: {name}," for t, name in sorted(index))
    return (f"{body}\n\n"
            "#: SDK release -> its root layout. The key is the release the layout was "
            "generated\n#: from, and an Epoch looks itself up by the release it names.\n"
            f"LAYOUTS: dict[str, RootLayout] = {{\n{rows}\n}}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tag", help="SDK tag or revision to read object_store.h at")
    ap.add_argument("--emit", action="store_true", help="print the Python literal")
    ap.add_argument("--emit-all", action="store_true",
                    help="print the whole generated section of jadart/objstore.py")
    ap.add_argument("--check", action="store_true",
                    help="re-derive every bundled layout from its SDK tag and diff")
    args = ap.parse_args(argv)

    if args.emit_all:
        print(emit_all())
        return 0

    if args.check:
        from jadart.objstore import LAYOUTS
        bad = 0
        for tag in sorted(LAYOUTS):
            try:
                got = layout_for_tag(tag)
            except FetchError as exc:
                print(f"{tag}: FETCH FAILED: {exc}")
                bad += 1
                continue
            have = LAYOUTS[tag]
            stubs = {i: n for i, n in got["codes"] if n is not None}
            unnamed = frozenset(i for i, n in got["codes"] if n is None)
            if (have.count, have.stubs, have.unnamed) == (got["count"], stubs, unnamed):
                print(f"{tag}: ok ({got['count']} roots, {len(stubs)} named stubs)")
                continue
            bad += 1
            print(f"{tag}: DIFFERS")
            if have.count != got["count"]:
                print(f"  count: bundled {have.count}, source {got['count']}")
            for i in sorted(set(have.stubs) | set(stubs)):
                if have.stubs.get(i) != stubs.get(i):
                    print(f"  index {i}: bundled {have.stubs.get(i)!r}, "
                          f"source {stubs.get(i)!r}")
            if have.unnamed != unnamed:
                print(f"  unnamed: bundled {sorted(have.unnamed)}, "
                      f"source {sorted(unnamed)}")
        return 1 if bad else 0

    if not args.tag:
        ap.error("--tag is required unless --check or --emit-all is given")
    got = layout_for_tag(args.tag)
    if args.emit:
        print(emit_group(args.tag.replace(".", "_").replace("-", "_"), (args.tag,), got))
        return 0
    print(f"Dart {args.tag}: {got['count']} AOT roots, ending at `{got['boundary']}`")
    print(f"  Code-typed fields in the run: {len(got['codes'])}")
    unnamed = [i for i, n in got["codes"] if n is None]
    print(f"  without an OBJECT_STORE_STUB_CODE_LIST name: {len(unnamed)} {unnamed}")
    first = got["codes"][0]
    print(f"  first Code field: index {first[0]} {first[1]}")
    print(f"  last Code field:  index {got['codes'][-1][0]} {got['codes'][-1][1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
