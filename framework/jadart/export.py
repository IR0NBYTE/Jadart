"""Whole-binary export: point it at an app, get a browsable source tree.

Every other command needs you to already know a name. That is backwards for a first look
at an unknown binary, which is what a decompiler is usually for. This takes an APK, an IPA,
a libapp.so or an iOS App binary and writes out everything it can recover.

The layout follows the tools people already use, rather than inventing one:

  jadx -d out app.apk        ->  out/sources/<package path>/Class.java
  blutter <dir> out          ->  out/asm/<library path>.dart, out/pp.txt, out/objs.txt

Both put decompiled code in a directory tree that mirrors the program's own package
structure, and both drop supporting dumps beside it. So:

    out/
      sources/                    one file per library, mirroring its url
        myapp/main.dart           package:myapp/main.dart
        flutter/src/widgets/...   package:flutter/src/widgets/...
        dart/core.dart            dart:core
      assets/                     the Flutter asset bundle, unwrapped and decoded
      assets.txt                  what each asset is, and which are worth opening
      container.txt               what else is in the container, and what reads it
      strings.txt                 the recovered identifier and literal pool
      pool.txt                    ObjectPool entries that resolve to a name
      constants.txt               the elements behind each const[N] label
      selectors.txt               virtual-dispatch selector offsets -> names
      summary.txt                 what was recovered, and what was not

jadx's split between what it decompiles and what it merely extracts is the idea worth
borrowing; copying its output is not. Only the Flutter asset bundle is written out, because
it is the only part jadart leaves more readable than the zip did, it decodes the gzipped
NOTICES and the binary AssetManifest. Everything else is inventoried in container.txt and
attributed to the tool that owns it.

The url -> path mapping is Blutter's (DartLibrary::CreatePath): strip `package:`, put
`dart:core` under `dart/core.dart`, and give an obfuscated library its token as a filename.
Matching it means output from the two tools can be diffed directly.
"""
from __future__ import annotations

from .errors import InputError, JadartError
from .fill import visible

import contextlib
import os
import re
import unicodedata

#: Every text file jadart writes is UTF-8 with LF endings, on every platform.
#: Without the explicit encoding Python uses the locale one, and a Windows console
#: at cp1252 aborted an export partway through on the first recovered string it
#: could not represent. Recovered text is arbitrary bytes out of someone else's
#: binary, so it is escaped rather than allowed to fail, and the newline is pinned
#: so the same input exports to the same bytes wherever it runs.
TEXT_OUT = {"encoding": "utf-8", "errors": "backslashreplace", "newline": "\n"}


def is_framework(url: str) -> bool:
    """True for a library that ships with Dart or Flutter rather than with the app.

    Both spellings have to be matched. A library the snapshot names by url gives
    "dart:core", but the internal patch libraries carry no url at all and are identified by
    their dotted name instead ("dart.core", "dart._internal"). Matching only the colon form
    lets several hundred VM classes through a filter that claims to show app code."""
    return (url.startswith("dart:") or url.startswith("dart.")
            or url.startswith("package:flutter"))


def library_path(url: str) -> str:
    """Library url -> relative file path, following Blutter's DartLibrary::CreatePath."""
    if url.startswith("package:"):
        rel = url[len("package:"):]
    elif url.startswith("dart:"):
        rel = "dart/" + url[len("dart:"):] + ".dart"
    elif url.startswith("file:///"):
        i = url.find("/.dart_tool/")
        rel = url[i + 1:] if i >= 0 else url.rsplit("/", 1)[-1]
    elif re.fullmatch(r"dart\.[\w.]+", url):
        # Internal patch libraries carry a NAME and no url, in dotted form: dart.core,
        # dart._internal. They own the private VM classes (_RegExp, _SendPort), so skipping
        # them the way blutter does would drop several hundred classes. Land them beside
        # their dart: siblings.
        rel = "dart/" + url[len("dart."):].replace(".", "/") + ".dart"
    else:
        # obfuscated builds reduce the url to a token with no path in it
        rel = re.sub(r"[^\w.\-]", "_", url) + ".dart"
    if not rel.endswith(".dart"):
        rel += ".dart"
    return _safe_relpath(rel)


#: Windows treats these as devices whatever the extension, so a library called `con`
#: would produce a file that cannot be created or opened. COM0, LPT0 and the superscript
#: digits are among them too.
_WIN_RESERVED = frozenset(
    ["con", "prn", "aux", "nul"]
    + [f"{d}{i}" for d in ("com", "lpt") for i in "0123456789\u00b9\u00b2\u00b3"])
#: Illegal in a Windows filename; the control range is illegal everywhere worth caring,
#: and a lone surrogate is no character at all, so no filesystem can name a file with it.
_BAD_CHARS = re.compile(r'[<>:"|?*\x00-\x1f\ud800-\udfff]')
#: A component longer than this is refused by most filesystems, and the library url is
#: attacker-controlled text out of the snapshot. In UTF-8 bytes, which is what ext4
#: counts: 120 characters of a four-byte script came to 480, past its 255.
_MAX_COMPONENT = 120
#: The longest relative path a library is written to, in UTF-8 bytes. A url nests as
#: deep as it likes, and with the output directory a long one passed the 1024 bytes
#: macOS takes in one path (#96). Real ones come to 71 at most; see _safe_relpath for
#: what gives way.
_MAX_PATH = 400
#: The most directories a library path goes down. Real ones go 3 deep at most, and each
#: directory is one more thing to make on disk and to remember while paths are checked.
_MAX_DEPTH = 16


def _safe_relpath(rel: str, fallback: str = "unnamed.dart") -> str:
    """A library url turned into a relative path that cannot leave the output directory.
    An asset's name too (#104), with a `fallback` of its own for a name that comes to
    nothing.

    Splitting on "/" alone was POSIX-only thinking: on Windows a backslash is also a
    separator, so `package:foo\\..\\..\\evil` kept its `..` as part of a single
    component here and then escaped once the OS resolved it. Everything else below is the
    same class of problem, a name coming out of an untrusted binary and being trusted as
    a filename.
    """
    parts = []
    raws = re.split(r"[/\\]", rel)
    for i, raw in enumerate(raws):
        if raw in ("", ".", ".."):
            continue
        p = _BAD_CHARS.sub("_", raw)
        # a drive letter or a trailing dot/space, both of which Windows strips silently
        p = p.rstrip(". ")
        if len(p.encode("utf-8")) > _MAX_COMPONENT - 1:
            # cut on a character, and the cut can leave a dot or a space at the end; one
            # byte short of the bound, for the `_` below
            p = p.encode("utf-8")[:_MAX_COMPONENT - 1].decode("utf-8", "ignore")
            p = p.rstrip(". ")
        if not p:
            continue
        # After the cut, which can leave a bare `nul` where there was more
        stem = p.split(".", 1)[0].lower()
        if stem in _WIN_RESERVED:
            p = "_" + p
        parts.append(p)
        last = i == len(raws) - 1
    if not parts:
        return fallback
    if not last:
        # The file's own name came to nothing, and the directory above it is not a file.
        parts.append(fallback)
    # Too deep or too long: the deepest directories give way and the file keeps its name,
    # so the package it is in still leads the path. Counted as it goes, since a url can
    # hold a great many components and joining them again for each one dropped is
    # quadratic.
    room = _MAX_PATH - len(parts[-1].encode("utf-8"))
    keep = []
    for p in parts[:-1][:_MAX_DEPTH]:
        room -= len(p.encode("utf-8")) + 1
        if room < 0:
            break
        keep.append(p)
    return os.path.join(*keep, parts[-1])


def _fold(rel: str) -> str:
    """The form two paths are the same file under somewhere: macOS and Windows ignore
    case, and macOS also ignores how an accented character is composed. Unicode's
    canonical caseless match, which composed forms are not: `\u0391\u0342\u0345` and
    `\u0391\u0342\u0399` are one file on APFS, and composed they fold apart."""
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", rel).casefold())


def unique_paths(rels, reserved=()) -> dict:
    """Each path, mapped to the path it is written to. `reserved` are paths jadart writes
    itself beside them, which a path that lands on one gives way to (#104).

    Two libraries can need one file, and one can need for a file what another needs for a
    directory. Obfuscation names libraries by short tokens, and `Ahd` and `ahd` are one
    file on macOS and Windows: the second overwrote the first, and the obfuscated fixture
    lost 99 of its 307 libraries without a word. `package:a/b` writes `a/b.dart`, and
    `package:a/b.dart/c` then needs `a/b.dart` as a directory, which ended the export
    with exit 3 (#96). So every path is held to be unique under _fold, the first in
    sorted order keeps its own, a path some library needs as a directory keeps it for
    that, and the file that gives way takes `~N` before `.dart` (or its last extension),
    never a name another has. Same output on every platform, since the rule ignores which
    one it is. Assets take the same rule: an APK's `Logo.txt` and `logo.txt` were one file
    too."""
    rels = sorted(set(rels))
    return dict(zip(rels, unique_each(rels, reserved)))


def needed_dirs(rels) -> set:
    """Every directory the paths need, folded (see _fold)."""
    dirs = set()
    for r in rels:
        d = os.path.dirname(r)
        while d and _fold(d) not in dirs:
            dirs.add(_fold(d))
            d = os.path.dirname(d)
    return dirs


def unique_each(rels, reserved=()) -> list:
    """unique_paths for a list that can hold one path more than once, as an archive's
    members can: the result is in the list's order, and each copy after the first, in
    the list's order, is a file of its own."""
    names = {_fold(r) for r in rels} | {_fold(r) for r in reserved}
    dirs = needed_dirs(set(rels))
    taken, nxt = {_fold(r) for r in reserved}, {}
    out = [None] * len(rels)
    for i in sorted(range(len(rels)), key=lambda i: rels[i]):    # stable: the first keeps
        r = rels[i]
        k = _fold(r)
        new = r
        if k in taken or k in dirs:
            head, name = os.path.split(r)
            stem, ext = ((name[:-5], ".dart") if name.endswith(".dart")
                         else os.path.splitext(name))
            # Each base counts on from where it got to: ten thousand spellings of one
            # name in different cases, or ten thousand copies of it, would otherwise try
            # every number again each time.
            base = _fold(os.path.join(head, stem))
            n = nxt.get(base, 2)
            while True:
                new = os.path.join(head, f"{stem}~{n}{ext}")
                k = _fold(new)
                n += 1
                if k not in taken and k not in names and k not in dirs:
                    break
            nxt[base] = n
        taken.add(k)
        out[i] = new
    return out


def _check_outdir(outdir: str) -> None:
    """Refuse an output directory that cannot be one, before anything is recovered.

    It is user input, and a file in its place, or under it, raised the OSError from
    os.makedirs only once the binary had been read, which the CLI calls a bug in jadart
    (#96). Anything this cannot see, a directory it may not write say, is caught where
    the files are written and is the same InputError."""
    if os.path.lexists(outdir) and not os.path.isdir(outdir):
        raise InputError(f"{outdir}: is not a directory, so jadart cannot export into it")
    up = os.path.dirname(os.path.abspath(outdir))
    while not os.path.lexists(up):
        parent = os.path.dirname(up)
        if parent == up:
            # the root itself is missing: a drive or a share that is not there
            raise InputError(f"{outdir}: cannot export there: {up} does not exist")
        up = parent
    if not os.path.isdir(up):
        raise InputError(f"{outdir}: cannot export there: {up} is not a directory")


@contextlib.contextmanager
def _writing(outdir: str, path: str):
    """open(path, "w") for a file of the export, with a failure to write it (permission,
    a full disk) an InputError naming the output directory rather than a bug report."""
    try:
        with open(path, "w", **TEXT_OUT) as fh:
            yield fh
    except OSError as exc:
        raise InputError(f"{outdir}: cannot write the export there: "
                         f"{exc.strerror or exc}: {exc.filename or path}") from exc


def _makedirs(outdir: str, path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        raise InputError(f"{outdir}: cannot write the export there: "
                         f"{exc.strerror or exc}: {exc.filename or path}") from exc


def export(path, outdir: str, tier: int = 3, app_only: bool = False,
           max_methods: int = 200, progress=None, label: str = None,
           container: str = None, sigs: str = None) -> dict:
    """Recover everything and write it to `outdir`. Returns a stats dict.

    `container` is the apk/ipa the snapshot came out of, when there was one. The Dart is
    one file out of a hundred in a shipped app, and the assets beside it, pinned
    certificates, backend config, bundled models, are usually the next thing anyone
    wants, so they are unpacked too. See container.py for the layout."""
    from .branches import exits, row_kinds
    from .disasm import (load_instructions, disassemble_function, build_pool_map,
                         render_body, annotate, truncated_by, addr_label, rebaser,
                         cut_end)
    from .signatures import names_with_signatures
    from .cfg import render_function
    from .expr import lift_function, make_arity_resolver, make_return_resolver
    from .dispatch import recover_selectors, ORIGIN_ELEMENT_ARM64
    from .fields import recover_fields
    from .program import build_program

    _check_outdir(outdir)
    image, fr, hdr = load_instructions(path)
    prog = build_program(fr, hdr)
    S = fr.names                         # names, as printed (#74)

    # Load once. decompile_class re-reads the whole snapshot per class, which is fine for
    # one class and unusable for seventeen hundred.
    pc_to_name, signote = names_with_signatures(image, fr, sigs)
    pool_map = build_pool_map(fr, getattr(image, "arch", None))
    arity = make_arity_resolver(image) if tier >= 3 else None
    returns = make_return_resolver(image) if tier >= 3 else None
    selectors = recover_selectors(image, fr, hdr) if tier >= 3 else None
    from .program import static_function_refs, receiver_for
    static_refs = static_function_refs(fr)
    layout = recover_fields(fr, getattr(image, "arch", None))

    methods: dict = {}
    for ref, nr, ow, kt in fr.functions:
        nm = S.get(nr, "")
        if nm:
            methods.setdefault(ow, []).append((nm, ref, kt))

    def render_class(k) -> list:
        head = f"class {k.name}"
        if k.super_name and k.super_name != "Object":
            head += f" extends {k.super_name}"
        out = [head + " {"]
        # By offset, not by name: a reader arriving from `x2.field_0x18` in a body wants to
        # scan the column of offsets, and the order the fields sit in the object is also
        # the order they were declared in.
        seen_f = {}
        for m in k.members:
            if m.kind == "field":
                seen_f.setdefault(m.name, m)
        fields = sorted(seen_f.values(), key=lambda m: (m.offset < 0, m.offset, m.name))
        for m in fields:
            where = (f"   // @0x{m.offset:x}" + (" unboxed" if m.unboxed else "")
                     if m.offset >= 0 else "")
            out.append(f"  {m.name};{where}")
        if fields:
            out.append("")
        for nm, ref, kt in sorted(methods.get(k.ref, []))[:max_methods]:
            disp = nm.split(":", 1)[1] if nm.startswith(("get:", "set:")) else nm.rstrip(".")
            dis = disassemble_function(image, ref)
            if not dis:
                out.append(f"  {disp}();  // no code (inlined, abstract, or no range)")
                continue
            cr = image.code_ranges[ref]
            cut = truncated_by(cr, dis)
            note = f", TRUNCATED: {len(dis)} of {len(dis) + cut} instructions" if cut else ""
            out.append(f"  {disp}() {{  // {addr_label(image, cr.pc_offset)}, "
                       f"{cr.size} bytes{note}")
            if tier >= 3:
                ann = annotate(dis, pc_to_name, pool_map, kinds=row_kinds(image, dis))
                out.extend(lift_function(ann, pool_map,
                                         receiver=receiver_for(ref, static_refs),
                                         arity=arity, indent="  ", depth=2,
                                         selectors=selectors,
                                         arch=getattr(image, "arch", None),
                                         fields=layout.for_function(ref),
                                         show=rebaser(image), cut_end=cut_end(cr, dis),
                                         returns=returns))
            elif tier == 2:
                ann = annotate(dis, pc_to_name, pool_map, kinds=row_kinds(image, dis))
                out.extend(render_function(ann, exits=exits(image, dis),
                                           cut_end=cut_end(cr, dis), indent="  ",
                                           depth=2, show=rebaser(image)))
            else:
                out.extend(render_body(dis, pc_to_name, pool_map, indent="      ",
                                       kinds=row_kinds(image, dis),
                                       show=rebaser(image)))
            out.append("  }")
        out.append("}")
        return out

    libs = prog.libraries()
    named = [k for k in prog.classes if k.name and not k.name.startswith("<")]
    attributed = {id(k) for ks in libs.values() for k in ks}
    orphans = [k for k in named if id(k) not in attributed]
    anonymous = len(prog.classes) - len(named)
    unattributed = None
    if orphans and not app_only:
        # A class with no library at all still gets written, in its own file. Silently
        # dropping classes from a tree that looks complete is the worst option here. A
        # library whose url is `_unattributed` lost its classes to these (#96).
        libs = dict(libs)
        unattributed, n = "_unattributed", 2
        while unattributed in libs:
            unattributed, n = f"_unattributed~{n}", n + 1
        libs[unattributed] = orphans
    if app_only:
        libs = {u: ks for u, ks in libs.items() if not is_framework(u)}

    src = os.path.join(outdir, "sources")
    _makedirs(outdir, src)

    # Group by output path before writing. Two library objects can map to one path: an
    # internal patch library (name "dart.core") is the same logical library as its public
    # side (url "dart:core"), so they belong in one file rather than clobbering each other.
    # A cut url is named after what is left of it: the mark ends in `\... (N chars)`,
    # whose backslash _safe_relpath splits on, which made a directory where another url
    # had made a file (#94).
    from .fill import uncut
    by_path: dict = {}
    for url, ks in sorted(libs.items()):
        by_path.setdefault(library_path(uncut(url)), []).append((url, ks))
    written = unique_paths(by_path)

    stats = {"libraries": 0, "classes": 0, "methods": 0, "files": [],
             "renamed": {r: w for r, w in written.items() if r != w}}
    for i, (want, entries) in enumerate(sorted(by_path.items())):
        rel = written[want]
        dest = os.path.join(src, rel)
        _makedirs(outdir, os.path.dirname(dest) or src)
        body = [f"// jadart tier {tier}, epoch {prog.epoch_name}, dart {prog.dart}"]
        for url, ks in entries:
            body.append(f"// lib: {url}")
        body.append("")
        for url, ks in entries:
            for k in sorted(ks, key=lambda x: x.name):
                if not k.name or k.name.startswith("<"):
                    continue
                body.extend(render_class(k))
                body.append("")
                stats["classes"] += 1
                stats["methods"] += len(methods.get(k.ref, []))
            stats["libraries"] += 1
        with _writing(outdir, dest) as fh:
            fh.write("\n".join(body))
        stats["files"].append(rel)
        if progress:
            progress(i + 1, len(by_path), rel)

    from .fill import printable
    with _writing(outdir, os.path.join(outdir, "strings.txt")) as fh:
        # Escaped, so one recovered string is one line. Literals contain newlines and NULs,
        # and writing them raw makes the dump binary as far as grep is concerned.
        # The literals as read, not the names view `S` is: printable() escapes them.
        for s in sorted(set(fr.strings.values())):
            fh.write(printable(s) + "\n")
    with _writing(outdir, os.path.join(outdir, "pool.txt")) as fh:
        for off, entry in sorted(pool_map.items()):
            fh.write(f"0x{off:x}\t{entry}\n")
    # The elements behind every `const[N] @0xOFF{...}` label pool.txt and the lifted
    # bodies print. Without this the label is a pointer to nothing: a reader following
    # `const[200] @0x60d8` into pool.txt found the same truncated label again, and the 200
    # values existed only behind the Python API. A table lookup is half an answer without
    # the table.
    from .disasm import const_lists, const_listing
    consts = const_lists(fr, getattr(image, "arch", None))
    if consts:
        with _writing(outdir, os.path.join(outdir, "constants.txt")) as fh:
            for off, n, body in const_listing(consts):
                fh.write(f"0x{off:x}\t[{n}]\t{body}\n")
    if selectors:
        with _writing(outdir, os.path.join(outdir, "selectors.txt")) as fh:
            for imm, name in sorted(selectors.items(), key=lambda kv: kv[1]):
                fh.write(f"{name}\tselector_offset={imm + ORIGIN_ELEMENT_ARM64}\t"
                         f"call_site_imm={imm}\n")

    stats["classes_named"] = len(named)
    stats["classes_anonymous"] = anonymous
    stats["classes_total"] = len(prog.classes)
    stats["orphans"] = len(orphans)
    stats["strings"] = len(set(fr.strings.values()))
    stats["selectors"] = len(selectors or {})

    from .container import unpack
    # A directory resolves to a "container" that holds nothing to unpack. Reporting
    # `0 files` three times reads as a failure; having no container is not one.
    #
    # `members` is the test because it is the same one container.py uses to decide whether
    # to write container.txt, and the summary block below is what points the reader at
    # that file. Gating the two on different things is how you get a summary that describes
    # a file nobody wrote, or a file nothing mentions. The previous test read `resources`
    # and `native`, which no version of unpack has ever returned. A container with assets
    # never noticed, because `or` stops at the first truthy value; a directory, or an apk
    # carrying no flutter_assets, reached the second name and exited 3, which claims a bug
    # in jadart rather than naming the input.
    c = unpack(container, outdir) if container else None
    stats["container"] = c if c and c["members"] else None

    with _writing(outdir, os.path.join(outdir, "summary.txt")) as fh:
        fh.write(f"source      {label or path}\n")
        fh.write(f"epoch       {prog.epoch_name} (dart {prog.dart})\n")
        fh.write(f"target      {hdr.arch}\n")
        fh.write(f"tier        {tier}\n")
        fh.write(f"libraries   {stats['libraries']}\n")
        fh.write(f"classes     {stats['classes']} written\n")
        fh.write(f"            {stats['classes_total']} in the snapshot: "
                 f"{stats['classes_named']} named, {stats['classes_anonymous']} anonymous\n")
        if stats["orphans"] and unattributed:
            went = written[library_path(unattributed)].replace(os.sep, "/")
            fh.write(f"            {stats['orphans']} had no library and went to "
                     f"sources/{went}\n")
        elif stats["orphans"]:
            # `-a` keeps the app's own libraries, so these are not written; saying they
            # went to a file pointed at one that does not exist.
            fh.write(f"            {stats['orphans']} had no library and are left out "
                     f"with the framework (-a)\n")
        if stats["renamed"]:
            fh.write(f"renamed     {len(stats['renamed'])} library files, so that no "
                     f"two are one file on a disk that ignores case and none is where "
                     f"another needs a directory; the `// lib:` line in each names its "
                     f"library\n")
            for want, rel in sorted(stats["renamed"].items()):
                want, rel = want.replace(os.sep, "/"), rel.replace(os.sep, "/")
                fh.write(f"              {visible(want)} -> {visible(rel)}\n")
        fh.write(f"methods     {stats['methods']}\n")
        fh.write(f"strings     {stats['strings']}\n")
        fh.write(f"selectors   {stats['selectors']}\n")
        if signote:
            fh.write(f"signatures  {signote}\n")

        c = stats.get("container")
        if c:
            fh.write(f"\nContainer:  {c['members']} "
                     f"member{'' if c['members'] == 1 else 's'}, "
                     f"{c['bytes'] / 1e6:.1f} MB uncompressed\n")
            # assets/ is only created when something is written into it, so naming it
            # here on a container that carried none sends the reader to a path that does
            # not exist. `jadart export` prints the same summary to the terminal and has
            # always guarded it this way; this is the file catching up.
            if c["assets"]:
                fh.write(f"  assets      {c['assets']} files "
                         f"({c['assets_bytes'] / 1e6:.1f} MB) -> assets/\n")
                if c["renamed"]:
                    fh.write(f"              {len(c['renamed'])} written under another "
                             f"name; assets.txt lists them\n")
                if c["declared_assets"]:
                    fh.write(f"              {c['declared_assets']} declared in "
                             f"AssetManifest\n")
                if c["packages"]:
                    fh.write(f"  packages    {c['packages']} third-party packages named in "
                             f"NOTICES -> assets/dependencies.txt\n")
            if c["notable"]:
                notable = ", ".join(visible(n) for n in c["notable"][:6])   # (#78)
                fh.write(f"  worth a look: {notable}"
                         f"{' ...' if len(c['notable']) > 6 else ''}\n")
            fh.write(f"  the rest    left in the container and attributed to the tool "
                     f"that reads it -> container.txt\n")

        fh.write("\nNot recovered, and why:\n")
        fh.write(f"  anonymous     {stats['classes_anonymous']} classes have no name in the "
                 f"snapshot at all (mixin applications and similar); there is nothing to "
                 f"call them\n")
        fh.write("  field names   AOT tree-shakes the metadata; fields render by byte "
                 "offset\n")
        fh.write("  arguments     shown only where the callee's register arity is known; "
                 "stack-convention calls render as (...)\n")
        fh.write("  unmodelled    any instruction the lifter does not model is emitted as "
                 "its arm64 line rather than guessed\n")
    return stats
