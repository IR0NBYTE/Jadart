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

from .errors import JadartError

import os
import re
import shutil
import zipfile


class InputError(JadartError):
    pass


# Preferred first: arm64 is what jadart lifts, and what nearly every shipped app carries.
_ABI_ORDER = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

# Ceiling on what will be unpacked out of an untrusted container (see resolve_input).
_MAX_EXTRACT = 1_500_000_000


_EXTRACTED: dict = {}


def resolve_cached(path: str) -> str:
    """An apk/ipa/directory becomes the snapshot inside it; a snapshot stays itself.

    The extracted copy has to outlive this call, because the readers returned below keep
    reading from it, so it lives as long as the process and is removed at exit rather than
    left behind. It is also cached per source file: `header(apk)` then `program(apk)` then
    `strings(apk)` used to mean three temp directories holding three copies of the same
    libapp.so, which for a large app is most of a gigabyte to say three things about one
    file."""
    import atexit
    import os
    import shutil
    import tempfile
    import zipfile
    if os.path.isfile(path) and not zipfile.is_zipfile(path):
        return path
    stat = os.stat(path)
    key = (os.path.abspath(path), stat.st_mtime_ns, stat.st_size)
    if key not in _EXTRACTED:
        workdir = tempfile.mkdtemp(prefix="jadart-")
        atexit.register(shutil.rmtree, workdir, True)
        _EXTRACTED[key] = resolve_input(path, workdir)
    return _EXTRACTED[key]


def resolve_input(path: str, workdir: str) -> str:
    """Accept what a user actually has and return a snapshot binary path.

    An APK or IPA is a zip, so the snapshot can be pulled straight out of it. jadx and
    blutter both take the container rather than making you unzip first, and asking a user
    to know that `lib/arm64-v8a/libapp.so` is the interesting member is a poor greeting."""
    if os.path.isdir(path):                        # an extracted lib/ tree or .framework
        for abi in _ABI_ORDER:
            cand = os.path.join(path, "lib", abi, "libapp.so")
            if os.path.exists(cand):
                return cand
        for name in ("libapp.so", "App"):
            cand = os.path.join(path, name)
            if os.path.exists(cand):
                return cand
        raise InputError(f"{path}: no libapp.so or App binary under this directory")

    if not os.path.exists(path):
        raise InputError(f"{path}: no such file")
    if not zipfile.is_zipfile(path):
        return path                                # a .so / .dylib / App binary

    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        cands = [n for n in names if n.endswith("libapp.so")]
        cands.sort(key=lambda n: next((i for i, a in enumerate(_ABI_ORDER) if a in n), 99))
        if not cands:
            # an IPA keeps it in Payload/<App>.app/Frameworks/App.framework/App
            cands = [n for n in names if n.endswith("App.framework/App")]
        if not cands:
            # A debug build has no AOT snapshot at all: the Dart code ships as kernel
            # bytecode that the JIT loads at runtime. Saying so is worth a line, because
            # "no snapshot found" otherwise reads as a jadart limitation rather than as a
            # fact about the build, and the two need completely different tools.
            if any(n.endswith("flutter_assets/kernel_blob.bin") for n in names):
                raise InputError(
                    f"{path}: a debug/JIT build. Its Dart code is kernel bytecode in "
                    f"assets/flutter_assets/kernel_blob.bin, not an AOT snapshot, so there "
                    f"is nothing here for jadart to parse.\n"
                    f"  You are better off than with a release build, though: a debug "
                    f"kernel embeds the ORIGINAL SOURCE for hot reload and stack traces, "
                    f"so `strings` on that blob gives back the app's own .dart files "
                    f"verbatim, names, comments and literals included.")
            if any("libflutter.so" in n for n in names):
                raise InputError(
                    f"{path}: carries libflutter.so but no libapp.so. That is a Flutter "
                    f"app whose Dart code is not AOT-compiled into the APK, a debug "
                    f"build, or one that loads its code some other way.")
            raise InputError(
                f"{path}: a zip with no Flutter snapshot in it (looked for libapp.so and "
                f"App.framework/App). Not a Flutter app?")
        pick = cands[0]
        # A member's declared size is free to read and a lie is cheap to tell, so check it
        # before writing a gigabyte of someone else's zip to this machine's disk. The
        # largest real libapp.so in the corpus is under 60 MB; the cap is generous enough
        # not to argue with a genuinely huge app and small enough to be a cap.
        declared = z.getinfo(pick).file_size
        if declared > _MAX_EXTRACT:
            raise InputError(
                f"{path}: {pick} claims to be {declared / 1e6:.0f} MB, over the "
                f"{_MAX_EXTRACT / 1e6:.0f} MB limit for an extracted snapshot. Unpack it "
                f"yourself and point jadart at the file if that is genuinely its size.")
        os.makedirs(workdir, exist_ok=True)
        out = os.path.join(workdir, os.path.basename(pick))
        with z.open(pick) as src, open(out, "wb") as dst:
            shutil.copyfileobj(src, dst)
        return out


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
    # never let a crafted url escape the output directory
    parts = [p for p in rel.split("/") if p not in ("", ".", "..")]
    return os.path.join(*parts) if parts else "unnamed.dart"


def export(path: str, outdir: str, tier: int = 3, app_only: bool = False,
           max_methods: int = 200, progress=None, label: str = None,
           container: str = None, sigs: str = None) -> dict:
    """Recover everything and write it to `outdir`. Returns a stats dict.

    `container` is the apk/ipa the snapshot came out of, when there was one. The Dart is
    one file out of a hundred in a shipped app, and the assets beside it, pinned
    certificates, backend config, bundled models, are usually the next thing anyone
    wants, so they are unpacked too. See container.py for the layout."""
    from .disasm import (load_instructions, disassemble_function, build_pool_map,
                         render_body, annotate, truncated_by)
    from .signatures import names_with_signatures
    from .cfg import build_cfg, structure, render as render_cfg
    from .expr import lift_function, make_arity_resolver
    from .dispatch import recover_selectors, ORIGIN_ELEMENT_ARM64
    from .fields import recover_fields
    from .program import build_program

    image, fr, hdr = load_instructions(path)
    prog = build_program(fr, hdr)
    S = fr.strings

    # Load once. decompile_class re-reads the whole snapshot per class, which is fine for
    # one class and unusable for seventeen hundred.
    pc_to_name, signote = names_with_signatures(image, fr, sigs)
    pool_map = build_pool_map(fr, getattr(image, "arch", None))
    arity = make_arity_resolver(image) if tier >= 3 else None
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
            out.append(f"  {disp}() {{  // .text+0x{cr.pc_offset:x}, {cr.size} bytes{note}")
            if tier >= 3:
                ann = annotate(dis, pc_to_name, pool_map)
                out.extend(lift_function(ann, pool_map,
                                         receiver=receiver_for(ref, static_refs),
                                         arity=arity, indent="  ", depth=2,
                                         selectors=selectors,
                                         arch=getattr(image, "arch", None),
                                         fields=layout.for_function(ref)))
            elif tier == 2:
                ann = annotate(dis, pc_to_name, pool_map)
                blocks, entry = build_cfg(ann)
                out.extend(render_cfg(blocks, structure(blocks, entry), indent="  ", depth=2))
            else:
                out.extend(render_body(dis, pc_to_name, pool_map, indent="      "))
            out.append("  }")
        out.append("}")
        return out

    libs = prog.libraries()
    named = [k for k in prog.classes if k.name and not k.name.startswith("<")]
    attributed = {id(k) for ks in libs.values() for k in ks}
    orphans = [k for k in named if id(k) not in attributed]
    anonymous = len(prog.classes) - len(named)
    if orphans and not app_only:
        # A class with no library at all still gets written, in its own file. Silently
        # dropping classes from a tree that looks complete is the worst option here.
        libs = dict(libs)
        libs["_unattributed"] = orphans
    if app_only:
        libs = {u: ks for u, ks in libs.items() if not is_framework(u)}

    src = os.path.join(outdir, "sources")
    os.makedirs(src, exist_ok=True)

    # Group by output path before writing. Two library objects can map to one path: an
    # internal patch library (name "dart.core") is the same logical library as its public
    # side (url "dart:core"), so they belong in one file rather than clobbering each other.
    by_path: dict = {}
    for url, ks in sorted(libs.items()):
        by_path.setdefault(library_path(url), []).append((url, ks))

    stats = {"libraries": 0, "classes": 0, "methods": 0, "files": []}
    for i, (rel, entries) in enumerate(sorted(by_path.items())):
        dest = os.path.join(src, rel)
        os.makedirs(os.path.dirname(dest) or src, exist_ok=True)
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
        with open(dest, "w") as fh:
            fh.write("\n".join(body))
        stats["files"].append(rel)
        if progress:
            progress(i + 1, len(by_path), rel)

    from .fill import printable
    with open(os.path.join(outdir, "strings.txt"), "w") as fh:
        # Escaped, so one recovered string is one line. Literals contain newlines and NULs,
        # and writing them raw makes the dump binary as far as grep is concerned.
        for s in sorted(set(S.values())):
            fh.write(printable(s) + "\n")
    with open(os.path.join(outdir, "pool.txt"), "w") as fh:
        for off, entry in sorted(pool_map.items()):
            fh.write(f"0x{off:x}\t{entry}\n")
    # The elements behind every `const[N] @0xOFF{...}` label pool.txt and the lifted
    # bodies print. Without this the label is a pointer to nothing: a reader following
    # `const[200] @0x60d8` into pool.txt found the same truncated label again, and the 200
    # values existed only behind the Python API. A table lookup is half an answer without
    # the table.
    from .disasm import const_lists
    consts = const_lists(fr, getattr(image, "arch", None))
    if consts:
        with open(os.path.join(outdir, "constants.txt"), "w") as fh:
            for off, vals in sorted(consts.items()):
                body = ", ".join(printable(v) if isinstance(v, str) else hex(v)
                                 for v in vals)
                fh.write(f"0x{off:x}\t[{len(vals)}]\t{body}\n")
    if selectors:
        with open(os.path.join(outdir, "selectors.txt"), "w") as fh:
            for imm, name in sorted(selectors.items(), key=lambda kv: kv[1]):
                fh.write(f"{name}\tselector_offset={imm + ORIGIN_ELEMENT_ARM64}\t"
                         f"call_site_imm={imm}\n")

    stats["classes_named"] = len(named)
    stats["classes_anonymous"] = anonymous
    stats["classes_total"] = len(prog.classes)
    stats["orphans"] = len(orphans)
    stats["strings"] = len(set(S.values()))
    stats["selectors"] = len(selectors or {})

    from .container import unpack
    # A directory or a bare .so resolves to a "container" that holds nothing to unpack.
    # Reporting `0 files` three times reads as a failure; having no container is not one.
    c = unpack(container, outdir) if container else None
    stats["container"] = c if c and (c["assets"] or c["resources"] or c["native"]) else None

    with open(os.path.join(outdir, "summary.txt"), "w") as fh:
        fh.write(f"source      {label or path}\n")
        fh.write(f"epoch       {prog.epoch_name} (dart {prog.dart})\n")
        fh.write(f"target      {hdr.arch}\n")
        fh.write(f"tier        {tier}\n")
        fh.write(f"libraries   {stats['libraries']}\n")
        fh.write(f"classes     {stats['classes']} written\n")
        fh.write(f"            {stats['classes_total']} in the snapshot: "
                 f"{stats['classes_named']} named, {stats['classes_anonymous']} anonymous\n")
        if stats["orphans"]:
            fh.write(f"            {stats['orphans']} had no library and went to "
                     f"sources/_unattributed.dart\n")
        fh.write(f"methods     {stats['methods']}\n")
        fh.write(f"strings     {stats['strings']}\n")
        fh.write(f"selectors   {stats['selectors']}\n")
        if signote:
            fh.write(f"signatures  {signote}\n")

        c = stats.get("container")
        if c:
            fh.write(f"\nContainer:  {c['members']} members, "
                     f"{c['bytes'] / 1e6:.1f} MB uncompressed\n")
            fh.write(f"  assets      {c['assets']} files "
                     f"({c['assets_bytes'] / 1e6:.1f} MB) -> assets/\n")
            if c["declared_assets"]:
                fh.write(f"              {c['declared_assets']} declared in "
                         f"AssetManifest\n")
            if c["packages"]:
                fh.write(f"  packages    {c['packages']} third-party packages named in "
                         f"NOTICES -> assets/dependencies.txt\n")
            if c["notable"]:
                fh.write(f"  worth a look: {', '.join(c['notable'][:6])}"
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
