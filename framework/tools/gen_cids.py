#!/usr/bin/env python3
"""Generate a jadart cid table for one SDK release, from that release's class_id.h.

The VM builds its class-id enum from an X-macro (`CLASS_ID_LIST` expanded through
`CID(cid) k##cid,`), so don't transcribe the table by hand. Expand it the way the compiler
does. This script fetches class_id.h at a given SDK tag (tools/sdk_source.py, keyed by the
snapshot version hash), strips the two #includes so the macro definitions stand alone, and
runs the real C preprocessor over them.

Why it matters: cid numbering shifts between releases whenever a predefined class is added
or removed, and a shifted table silently mislabels clusters. jadart's bundled table was
expanded from SDK main while every binary in the corpus is 3.12.2, so it disagreed on ~80
cids at and above 96. It called cid 112 FfiStructCid when the 3.12.2 truth is
TypedDataInt8ArrayCid, the anchor of the typed-data range.

    python3 tools/gen_cids.py --tag 3.12.2                 # print a summary + diff
    python3 tools/gen_cids.py --tag 3.12.2 --emit          # print the Python table
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sdk_source import fetch, FetchError  # noqa: E402


def cid_names_for_tag(tag: str) -> dict:
    """cid -> class name, expanded from class_id.h at `tag` with the C preprocessor."""
    header = fetch(tag, "class_id.h").decode("utf-8", "replace")
    # Preprocess the ClassId enum itself, not one particular list macro. How the enum gets
    # assembled drifts between releases: 3.12 builds it from a single CLASS_ID_LIST, while
    # 3.11 and earlier write the body inline with per-family DEFINE_OBJECT_KIND blocks and
    # have no CLASS_ID_LIST at all. The enum the compiler ends up seeing is the authority
    # in every version, so expanding that is version-agnostic.
    head, sep, rest = header.partition("enum ClassId")
    if not sep:
        raise SystemExit("gen_cids: no `enum ClassId` in class_id.h")
    end = rest.find("};")
    if end < 0:
        raise SystemExit("gen_cids: unterminated ClassId enum")
    enum_body = "enum ClassId" + rest[:end + 2]
    # The includes pull in the whole VM tree and the macros don't need them. Cutting the
    # file also orphans its include guard, so drop that too.
    drop = re.compile(r"^\s*#\s*(include\b|ifndef\s+RUNTIME_VM_CLASS_ID_H_|"
                      r"define\s+RUNTIME_VM_CLASS_ID_H_\s*$)")
    body = "\n".join(l for l in head.splitlines() if not drop.match(l))
    stray = [l for l in body.splitlines()
             if re.match(r"\s*#\s*(if|ifdef|ifndef|else|elif|endif)\b", l)]
    if stray:
        raise SystemExit("gen_cids: unexpected conditional in the macro region, refusing to "
                         f"guess its truth value: {stray[0].strip()!r}")
    src = body + "\n\n" + enum_body + "\n"
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as fh:
        fh.write(src)
        path = fh.name
    # `clang -E -x c`, not `cpp`: on macOS /usr/bin/cpp runs in traditional mode, where ##
    # isn't the paste operator. DEFINE_CLASS_ID(Object) would yield the literal token
    # "Object##Cid" instead of ObjectCid, and it would do it silently, with the cid count
    # still coming out right.
    try:
        out = subprocess.run(["clang", "-E", "-P", "-x", "c", path],
                             capture_output=True, text=True, check=True).stdout
    except FileNotFoundError:
        raise SystemExit("gen_cids: clang not found (needed for token pasting)")
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"gen_cids: preprocessor failed: {e.stderr[:400]}")
    finally:
        os.unlink(path)
    if "##" in out:
        raise SystemExit("gen_cids: token pasting did not run (traditional-mode cpp?); "
                         "refusing to emit a table with unpasted names")
    m = re.search(r"enum\s+ClassId[^{]*\{(.*?)\}", out, re.S)
    if not m:
        raise SystemExit("gen_cids: the ClassId enum did not survive preprocessing")
    names, idx = {}, 0
    for item in m.group(1).split(","):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            nm, _, val = item.partition("=")
            nm, val = nm.strip(), val.strip()
            try:
                idx = int(val, 0)
            except ValueError:
                raise SystemExit(f"gen_cids: non-literal enumerator value {item!r}")
        else:
            nm = item
        if not re.fullmatch(r"k\w+", nm):
            raise SystemExit(f"gen_cids: unexpected enumerator {nm!r}")
        if nm == "kNumPredefinedCids":
            break                      # the boundary itself, not a class
        names[idx] = nm[1:]            # kObjectCid -> ObjectCid
        idx += 1
    if not names:
        raise SystemExit("gen_cids: the ClassId enum expanded to nothing")
    return names


# The cids the parser dispatches on. Emitted as lookups into the generated table rather
# than as literals, so a regenerated table can never silently disagree with them.
_DISPATCH_CIDS = [
    "Illegal", "Object", "Class", "Function", "Field", "Script", "Library", "Code",
    "ObjectPool", "Instance", "TypeArguments", "Type", "FunctionType", "TypeParameter",
    "TypeParameters", "Closure", "ClosureData", "Mint", "Double", "Array", "ImmutableArray",
    "GrowableObjectArray", "WeakArray", "Record", "RecordType", "String", "OneByteString",
    "TwoByteString", "Context", "ContextScope", "PcDescriptors", "CodeSourceMap",
    "CompressedStackMaps", "LocalVarDescriptors", "ExceptionHandlers", "ConstMap",
    "ConstSet", "FfiTrampolineData", "PatchClass", "LibraryPrefix", "TypedDataInt8Array",
]


def emit(tag: str, names: dict) -> str:
    lines = [
        f'"""Dart cid -> class-name table, generated for SDK {tag}.',
        "",
        "Written by tools/gen_cids.py, which runs the C preprocessor over the",
        f"runtime/vm/class_id.h CLASS_ID_LIST at tag {tag}. That's the same X-macro",
        "the VM uses to build its ClassId enum.",
        "",
        "Don't hand-edit this file, regenerate it per epoch. cid numbering shifts",
        "whenever a predefined class is added or removed, and a shifted table",
        "mislabels clusters.",
        '"""',
        "from __future__ import annotations",
        "",
        f"NUM_PREDEFINED_CIDS = {len(names)}",
        "",
        "CID_NAMES: dict[int, str] = {",
    ]
    lines += [f"    {c}: {n!r}," for c, n in sorted(names.items())]
    lines += [
        "}", "",
        "NAME_TO_CID: dict[str, int] = {v: k for k, v in CID_NAMES.items()}", "",
        "# Named cids the parser dispatches on, resolved through the table above so they",
        "# can't drift from it. A name this epoch doesn't define is just absent.",
    ]
    missing = []
    for base in _DISPATCH_CIDS:
        key = f"{base}Cid"
        if key in names.values():
            lines.append(f'k{key} = NAME_TO_CID[{key!r}]')
        else:
            missing.append(key)
    if missing:
        lines += ["", "# not present in this epoch: " + ", ".join(missing)]
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="generate a jadart cid table from class_id.h")
    ap.add_argument("--tag", required=True, help="SDK release tag, e.g. 3.12.2")
    ap.add_argument("--emit", action="store_true", help="print the Python table")
    ap.add_argument("--compare", metavar="MODULE", default="jadart.cids",
                    help="compare against this bundled table (default jadart.cids)")
    args = ap.parse_args(argv)

    try:
        names = cid_names_for_tag(args.tag)
    except FetchError as e:
        print(f"gen_cids: {e}", file=sys.stderr)
        return 2

    if args.emit:
        print(emit(args.tag, names))
        return 0

    print(f"tag {args.tag}: {len(names)} predefined cids "
          f"(kNumPredefinedCids = {len(names)})")
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    mod = __import__(args.compare, fromlist=["CID_NAMES"])
    cur = mod.CID_NAMES
    print(f"bundled {args.compare}: {mod.NUM_PREDEFINED_CIDS} predefined cids")
    diffs = sorted(c for c in set(names) | set(cur) if names.get(c) != cur.get(c))
    print(f"disagreements: {len(diffs)}")
    if diffs:
        print(f"first differing cid: {diffs[0]}")
        for c in diffs[:12]:
            print(f"  {c:4d}  generated={names.get(c)!r:38s} bundled={cur.get(c)!r}")
        if len(diffs) > 12:
            print(f"  ... {len(diffs) - 12} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
