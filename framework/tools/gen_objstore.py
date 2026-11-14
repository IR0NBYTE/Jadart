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

Dart 3.13 folded the vm snapshot into the program's, and the root run grew a prefix: the
Roots struct (roots.h: the raw roots, the handles, the API handles) and then the class
table, all read ahead of the ObjectStore. The stubs moved with it. They are no longer
ObjectStore fields but `stub_handles_`, in VM_STUB_CODE_LIST order (stub_code_list.h),
and OBJECT_STORE_STUB_CODE_LIST is gone. So for such a release the layout is assembled
from five files, each read rather than assumed: roots.h for the struct, symbol_list.h and
stub_code_list.h for the two arrays the handles end with, app_snapshot.cc for the order
the three parts are read in and for which class ids have no Class to read, and class_id.h
for the ids themselves.

DEV-TIME ONLY. jadart itself stays offline and ships the generated table; nothing under
jadart/ imports this.

    python3 tools/gen_objstore.py --tag 3.12.2            # what the release declares
    python3 tools/gen_objstore.py --tag 3.12.2 --emit     # the Python literal
    python3 tools/gen_objstore.py --check            # bundled layouts vs their source
    python3 tools/gen_objstore.py --emit-vm-stubs    # jadart/vmstubs.py's lists
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


def _one_macro(src: str, name: str, tag: str, where: str) -> str:
    """`_macro_body`, for a macro that must be defined exactly once in its header.

    Twice means an #if picks between two lists, and taking the first would be choosing
    a build configuration without saying so."""
    n = src.count(f"#define {name}(")
    if n != 1:
        raise FetchError(f"{tag}: {where} defines {name} {n} times, so which list a "
                         "build gets is not something this can read off the header")
    return _macro_body(src, name)


def _stub_list(tag: str) -> list:
    """VM_STUB_CODE_LIST expanded, in order: the names `stub_handles_` is indexed by."""
    src = fetch(tag, "stub_code_list.h").decode("utf-8", "replace")

    def expand(name, depth=0):
        if depth > 4:
            raise FetchError(f"{tag}: {name} nests deeper than a stub list does")
        body = _one_macro(src, name, tag, "stub_code_list.h").split(")", 1)[1]
        out = []
        for head, arg in re.findall(r"(\w+)\(\s*(\w+)\s*\)", body):
            if head == "V":
                out.append(arg)
            elif arg == "V" and f"#define {head}(" in src:
                out += expand(head, depth + 1)
            else:
                raise FetchError(f"{tag}: {name} holds `{head}({arg})`, which is "
                                 "neither an entry nor a list in the same header")
        return out

    stubs = expand("VM_STUB_CODE_LIST")
    if not stubs or len(set(stubs)) != len(stubs):
        raise FetchError(f"{tag}: VM_STUB_CODE_LIST expanded to {len(stubs)} entries, "
                         f"{len(set(stubs))} distinct")
    return stubs


def _struct(src: str, name: str, tag: str) -> str:
    m = re.search(r"\n  struct " + name + r" \{\n(.*?)\n  \};", src, re.S)
    if m is None:
        raise FetchError(f"{tag}: no `struct {name}` in roots.h")
    return m.group(1)


def _roots_prefix(tag: str):
    """The names of the refs ReadRoots reads ahead of the ObjectStore, or None.

    None is every release through 3.12, where the roots open with the ObjectStore. From
    3.13 ProgramDeserializationRoots::ReadRoots first fills the Roots struct, three
    loops over `from()..to()`, `fromh()..toh()` and `fromah()..toah()`, and then the
    class table. Each name is tagged with what it is (`raw:`, `handle:`, `symbol:`,
    `stub:`, `api:`, `class:`), which is what the caller and --check read."""
    snap = fetch(tag, "app_snapshot.cc").decode("utf-8", "replace")
    m = re.search(r"class ProgramDeserializationRoots\b.*?\n  void ReadRoots\("
                  r"Deserializer\* d\) override \{\n(.*?)\n  \}\n", snap, re.S)
    if m is None:
        raise FetchError(f"{tag}: no ProgramDeserializationRoots::ReadRoots")
    body = m.group(1)
    store = body.find("object_store_->from()")
    if store < 0:
        raise FetchError(f"{tag}: ReadRoots does not read the ObjectStore")
    if "Roots::Current()" not in body[:store]:
        return None
    body = body[:store]
    loops = [(body.find(f"roots->{k}()"), part)
             for k, part in (("from", "raw"), ("fromh", "handles"), ("fromah", "api"))]
    if min(at for at, _ in loops) < 0:
        raise FetchError(f"{tag}: ReadRoots fills Roots, but not as three loops over "
                         "from(), fromh() and fromah()")
    order = [part for _at, part in sorted(loops)]

    src = fetch(tag, "roots.h").decode("utf-8", "replace")
    stubs = _stub_list(tag)
    # One V(Name, "literal") per symbol. The literals go first, because some hold a
    # parenthesis; then anything that is not a V( entry would be a nested list this
    # is not counting, and a short count shifts every root after the symbols.
    listed = re.sub(r'"(?:[^"\\]|\\.)*"', '""', _one_macro(
        fetch(tag, "symbol_list.h").decode("utf-8", "replace"),
        "PREDEFINED_SYMBOLS_LIST", tag, "symbol_list.h").split(")", 1)[1])
    heads = re.findall(r"(\w+)\s*\(", listed)
    if not heads or set(heads) != {"V"}:
        raise FetchError(f"{tag}: PREDEFINED_SYMBOLS_LIST holds more than V() entries: "
                         f"{sorted(set(heads) - {'V'})[:3]}")
    symbols = len(heads)
    sizes = {"kNumPredefinedSymbols + 256": symbols + 256, "kNumStubEntries": len(stubs)}

    def members(struct, listname, pattern, tagged):
        """One struct's roots in declaration order: its list, then its arrays."""
        decl = _struct(src, struct, tag)
        if decl.count(f"{listname}(DECL)") != 1:
            raise FetchError(f"{tag}: struct {struct} does not expand {listname} once")
        out = [f"{tagged}:{n}" for n in re.findall(
            pattern, _one_macro(src, listname, tag, "roots.h"))]
        after = decl[decl.index(f"{listname}(DECL)"):].split("#undef DECL", 1)[1]
        for line in after.split("\n"):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            arr = re.fullmatch(r"\w+ (\w+)_\[([^\]]+)\](?: = \{\})?;", line)
            if arr is None:
                raise FetchError(f"{tag}: struct {struct} holds `{line}` after its "
                                 "list, which is not an array of roots")
            base, size = arr.groups()
            if size.isdigit():
                n = int(size)
            elif size in sizes:
                n = sizes[size]
            else:
                raise FetchError(f"{tag}: {struct}.{base}_ is sized `{size}`, which "
                                 "this cannot evaluate")
            if base == "stub_handles":
                out += [f"stub:{s}" for s in stubs]
            else:
                out += [f"{'symbol' if base == 'symbol_handles' else tagged}:"
                        f"{base}[{i}]" for i in range(n)]
        return out

    parts = {
        "raw": members("Raw", "RAW_ROOTS_LIST", r"V\(\s*\w+\s*,\s*(\w+)\s*\)", "raw"),
        "handles": members("Internal", "HANDLE_ROOTS_LIST",
                           r"V\(\s*\w+\s*,\s*(\w+)\s*\)", "handle"),
        "api": members("Api", "API_HANDLE_ROOTS_LIST", r"V\(\s*(\w+)\s*\)", "api"),
    }
    names = [n for part in order for n in parts[part]]

    # The class table: every predefined cid from kObjectCid up, in two loops that meet at
    # kInstanceCid, less the ones IsAbsentCid says have no Class object.
    tail = body[max(at for at, _ in loops):]
    spans = re.findall(r"for \(intptr_t cid = (k\w+); cid < (k\w+); cid\+\+\) \{\s*"
                       r"if \(IsAbsentCid\(cid\)\) continue;", tail)
    if spans != [("kObjectCid", "kInstanceCid"), ("kInstanceCid", "kNumPredefinedCids")]:
        raise FetchError(f"{tag}: the class-table loops in ReadRoots are {spans}")
    m = re.search(r"static bool IsAbsentCid\(intptr_t cid\) \{\s*switch \(cid\) \{(.*?)"
                  r"return true;", snap, re.S)
    if m is None:
        raise FetchError(f"{tag}: no IsAbsentCid switch in app_snapshot.cc")
    absent = set(re.findall(r"case k(\w+):", m.group(1)))
    from gen_cids import cid_names_for_tag
    cids = cid_names_for_tag(tag)
    by_name = {v: k for k, v in cids.items()}
    missing = sorted(absent - set(by_name))
    if missing or "ObjectCid" not in by_name:
        raise FetchError(f"{tag}: IsAbsentCid names {missing}, which class_id.h does "
                         "not define")
    names += [f"class:{c}" for c in range(by_name["ObjectCid"], len(cids))
              if cids[c] not in absent]
    return names


def layout_for_tag(tag: str) -> dict:
    """{count, codes, fields} for the AOT root run at this SDK tag.

    `count` is how many refs the deserializer reads, `codes` is (root index, stub name or
    None) for every Code-typed field in that run, and `fields` is the whole ordered run,
    which --check uses to say WHERE two releases differ. From 3.13 the run opens with
    the Roots struct and the class table (`_roots_prefix`); `class_base` and
    `class_cids` then say which roots are the class table and which cid each is."""
    src = fetch(tag, "object_store.h").decode("utf-8", "replace")
    if "#define OBJECT_STORE_STUB_CODE_LIST(" not in src:
        # No stub list beside the fields: the stubs are in Roots, or this is a header
        # nothing here knows how to read.
        prefix = _roots_prefix(tag)
        if prefix is None:
            raise FetchError(f"{tag}: object_store.h has no OBJECT_STORE_STUB_CODE_LIST "
                             "and ReadRoots reads no Roots struct ahead of it")
        return _merged_layout(tag, prefix, src)
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
            "boundary": m.group(1), "class_base": -1, "class_cids": ()}


def _merged_layout(tag: str, prefix: list, src: str) -> dict:
    """The 3.13 root run: the prefix, then the ObjectStore fields as before.

    The stubs are the prefix's `stub:` entries and nothing else. A Code-typed field in
    the ObjectStore run would be a stub this does not know how to name, so it is
    refused rather than left out of the set the reader checks the binary against."""
    entries = _ENTRY_RE.findall(_macro_body(src, "OBJECT_STORE_FIELD_LIST"))
    m = _AOT_RE.search(re.sub(r"\s+", " ", src))
    if not entries or m is None:
        raise FetchError(f"{tag}: object_store.h has no field list or no "
                         "to_snapshot(kFullAOT)")
    names = [e[2] for e in entries]
    if m.group(1) not in names:
        raise FetchError(f"{tag}: to_snapshot(kFullAOT) names {m.group(1)}, which is not "
                         "a field of OBJECT_STORE_FIELD_LIST")
    store = names.index(m.group(1)) + 1
    typed = [e[2] for e in entries[:store] if e[1] == "Code"]
    if typed:
        raise FetchError(f"{tag}: the ObjectStore still holds stubs ({typed[:3]}) beside "
                         "the ones in Roots, and this names only the latter")
    classes = [i for i, n in enumerate(prefix) if n.startswith("class:")]
    if classes != list(range(classes[0], len(prefix))):
        raise FetchError(f"{tag}: the class table is not the end of the roots prefix")
    codes = tuple((i, n[5:]) for i, n in enumerate(prefix) if n.startswith("stub:"))
    return {"count": len(prefix) + store, "codes": codes,
            "fields": tuple(prefix) + tuple(names[:store]), "boundary": m.group(1),
            "class_base": classes[0],
            "class_cids": tuple(int(prefix[i][6:]) for i in classes)}


#: Which releases share one root run, newest first. A layout is keyed on the release
#: because the root count moves nearly every release (244 at 3.12, 224 at 2.19), while the
#: cluster grammar epochs are much broader. Grouping is not assumed either: --emit-all
#: re-derives every tag in a group and refuses to emit if they are not identical.
#:
#: `3.8.1` is the tag read for the objectheader-3.8 epoch, whose binary was identified
#: from a Dart revision (Flutter 3.32.0 pins b04011c7) rather than from a release tag; the
#: reader's agreement check is what decides whether the tag's layout fits such a binary.
GROUPS = (
    ("3_13", ("3.13.0",)),
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
    classes = got["class_cids"]
    if classes:
        kinds = [n.split(":", 1)[0] for n in got["fields"][:got["class_base"]]]
        head += (f" The first {got['class_base'] + len(classes)} are read ahead of the "
                 f"ObjectStore: {kinds.count('raw')} raw roots, "
                 f"{sum(kinds.count(k) for k in ('handle', 'symbol', 'stub'))} handles "
                 f"(the stubs are the last {kinds.count('stub')} of them), "
                 f"{kinds.count('api')} API handles and the class table, "
                 f"{len(classes)} classes from root {got['class_base']}.")
    out = [f"#: {line}" for line in textwrap.wrap(head, 86)]
    out.append(f"_STUBS_{label}: dict[int, str] = {{")
    for i, name in got["codes"]:
        if name is not None:
            out.append(f"    {i}: {name!r},")
    out.append("}")
    unnamed = tuple(i for i, name in got["codes"] if name is None)
    if classes:
        if unnamed:
            raise FetchError(f"group {label}: a Roots stub with no name")
        out.append("#: The cid each class-table root is the Class of, in the order read.")
        rows = textwrap.wrap(", ".join(map(str, classes)), 84)
        out.append(f"_CLASSES_{label} = (")
        out += [f"    {row}" for row in rows]
        out[-1] += ")"
        out.append(f"ROOTS_{label} = RootLayout(")
        out.append(f"    count={got['count']}, stubs=_STUBS_{label},")
        out.append(f"    class_base={got['class_base']}, "
                   f"class_cids=_CLASSES_{label})")
        return "\n".join(out)
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
            if any(g[k] != got[0][k] for k in ("count", "codes", "boundary",
                                               "class_base", "class_cids")):
                raise FetchError(f"group {label}: {tags} do not share one root run")
        parts.append(emit_group(label, tags, got[0]))
        index += [(t, f"ROOTS_{label}") for t in tags]
    body = "\n\n".join(parts)
    rows = "\n".join(f"    {t!r}: {name}," for t, name in sorted(index))
    return (f"{body}\n\n"
            "#: SDK release -> its root layout. The key is the release the layout was "
            "generated\n#: from, and an Epoch looks itself up by the release it names.\n"
            f"LAYOUTS: dict[str, RootLayout] = {{\n{rows}\n}}")


#: The releases whose VM_STUB_CODE_LIST jadart/vmstubs.py holds, newest first. A release
#: is here only where a real build of it was read: the list has to be as long as the vm
#: snapshot has Code objects, and on a build that keeps a symbol table the stub at each
#: list position has to carry that name. 26 corpus builds, arm64 and arm32, 159 to 172
#: symbols each, none differing; the 3.12.2 builds keep no symbol and are held to the
#: 3.12.0 list, which is the same list. The four registered releases with no build to
#: read (2.19.0-444.2.beta, 3.0.1, 3.3.0-174.2.beta, 3.8.1) are left out on purpose:
#: a list nobody checked would name a stub after its neighbour. 3.13 has one snapshot
#: and names every stub from its roots (GROUPS).
VM_STUB_TAGS = ("3.12.2", "3.12.0", "3.11.5", "3.10.9", "3.9.2", "3.7.2", "3.6.2",
                "3.5.4", "3.4.4", "3.3.4", "3.2.6", "3.1.5", "3.0.6", "2.19.6")


def emit_vm_stubs() -> str:
    """The generated section of jadart/vmstubs.py: one tuple for each distinct list."""
    lists = {}
    for tag in VM_STUB_TAGS:
        lists.setdefault(tuple(_stub_list(tag)), []).append(tag)
    parts, index = [], []
    for names, tags in lists.items():
        label = "_VM_" + re.sub(r"\W", "_", tags[0])
        parts.append("\n".join(
            [f"#: Dart {_releases(tags)}. {len(names)} stubs.", f'{label} = tuple("""']
            + textwrap.wrap(" ".join(names), 88) + ['""".split())']))
        index += [(t, label) for t in tags]
    rows = "\n".join(f"    {t!r}: {label}," for t, label in sorted(index))
    return ("\n\n".join(parts) + "\n\n"
            "#: SDK release -> its VM_STUB_CODE_LIST, in order.\n"
            f"VM_STUBS: dict[str, tuple] = {{\n{rows}\n}}")


def check_vm_stubs() -> int:
    """How many bundled VM stub lists differ from their release's own header."""
    from jadart.vmstubs import VM_STUBS
    bad = 0
    for tag in sorted(set(VM_STUBS) | set(VM_STUB_TAGS)):
        have = VM_STUBS.get(tag)
        if have is None or tag not in VM_STUB_TAGS:
            print(f"{tag}: vm stubs: bundled and VM_STUB_TAGS disagree about it")
            bad += 1
            continue
        try:
            got = tuple(_stub_list(tag))
        except FetchError as exc:
            print(f"{tag}: vm stubs: FETCH FAILED: {exc}")
            bad += 1
            continue
        if have == got:
            print(f"{tag}: vm stubs ok ({len(got)})")
            continue
        bad += 1
        print(f"{tag}: vm stubs DIFFER: bundled {len(have)}, source {len(got)}")
        for i in range(max(len(have), len(got))):
            a = have[i] if i < len(have) else None
            b = got[i] if i < len(got) else None
            if a != b:
                print(f"  first difference at {i}: bundled {a!r}, source {b!r}")
                break
    return bad


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tag", help="SDK tag or revision to read object_store.h at")
    ap.add_argument("--emit", action="store_true", help="print the Python literal")
    ap.add_argument("--emit-all", action="store_true",
                    help="print the whole generated section of jadart/objstore.py")
    ap.add_argument("--emit-vm-stubs", action="store_true",
                    help="print the whole generated section of jadart/vmstubs.py")
    ap.add_argument("--check", action="store_true",
                    help="re-derive every bundled layout from its SDK tag and diff")
    args = ap.parse_args(argv)

    if args.emit_all:
        print(emit_all())
        return 0

    if args.emit_vm_stubs:
        print(emit_vm_stubs())
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
            if (have.count, have.stubs, have.unnamed, have.class_base,
                    have.class_cids) == (got["count"], stubs, unnamed,
                                         got["class_base"], got["class_cids"]):
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
            if (have.class_base, have.class_cids) != (got["class_base"],
                                                      got["class_cids"]):
                print(f"  class table: bundled {len(have.class_cids)} from root "
                      f"{have.class_base}, source {len(got['class_cids'])} from root "
                      f"{got['class_base']}")
        bad += check_vm_stubs()
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
    print(f"  without a name in the release's stub list: {len(unnamed)} {unnamed}")
    first = got["codes"][0]
    print(f"  first Code field: index {first[0]} {first[1]}")
    print(f"  last Code field:  index {got['codes'][-1][0]} {got['codes'][-1][1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
