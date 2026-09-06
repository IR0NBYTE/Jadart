"""jadart command line: one subcommand per view of a Dart AOT snapshot.

The shape follows radare2, jadx and objdump. A command word says what you want to see,
the shared options stay global, and each command carries its own `--help`. The older
flag form (`jadart <libapp> --tier0`) still runs: `_translate_legacy` rewrites it into
the new argv and hands it to the same parser, so no command has two implementations.

Exit codes are part of the interface:
  0  the command produced its output
  1  the thing asked for isn't in this binary, or the acceptance gates failed
  2  bad usage, or the file could not be parsed as a snapshot
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys

from . import console
from .errors import JadartError
from .console import bold, comment, dim, error, heading
from .snapshot import parse_libapp, walk_isolate

EXIT_OK = 0
EXIT_MISS = 1        # nothing recovered under that name, or a Tier-A gate failed
EXIT_USAGE = 2       # argparse rejected the command line, or the snapshot won't parse
EXIT_INTERNAL = 3    # a bug in jadart, not a problem with the input

_COMMANDS = ("info", "libraries", "classes", "disasm", "lift", "decompile",
             "selectors", "strings", "constants", "verify", "export", "xrefs",
             "signatures",
             "functions", "ffi")

_EXAMPLES = """\
examples:
  jadart info libapp.so                    header, epoch, target, object counts
  jadart classes libapp.so -f Bench        Tier 0 skeleton, names matching Bench
  jadart disasm libapp.so benchWithdraw    annotated arm64 for one symbol
  jadart decompile libapp.so BenchAccount  class header plus reconstructed bodies
  jadart decompile libapp.so Foo -t 2      same class, control-flow view
  jadart selectors libapp.so               virtual-dispatch selector names
  jadart ffi libapp.so                     native libraries and the symbols read out
  jadart strings libapp.so -g flutter      the identifier and string pool
  jadart verify libapp.so                  byte-exact acceptance gates

`jadart <command> --help` documents one command.
`python3 -m jadart` and `python3 -m jadart.cli` are the same entry point.
"""


def emit(obj, code: int = EXIT_OK) -> int:
    """Write one JSON document to stdout and return `code`.

    One object per run, never a stream of them: a caller can `json.load` the whole thing
    without framing it first, which is what makes `jadart -j ... | jq` work the way people
    expect from r2's `cmdj` or any of the other tools they already have.

    The exit code has to be passed in rather than assumed successful. `-j` used to report 0
    on every path that printed `"ok": false` (including a failed acceptance gate) so a
    script branching on `$?` saw success where the same command without `-j` said 1."""
    import json
    json.dump(obj, sys.stdout, indent=2, sort_keys=False, default=str)
    sys.stdout.write("\n")
    return code


def _json_error(exc, code: int) -> int:
    """The same failure a human would see, shaped so a script can branch on it."""
    import json
    json.dump({"ok": False, "error": str(exc), "type": type(exc).__name__,
               "exit": code}, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return code


_JSON = [False]          # set once from argv, so _fail can honour it without threading


def _fail(exc) -> int:
    """A snapshot that would not load: unknown epoch, unsupported target, or a
    container that isn't ELF or Mach-O."""
    if _JSON[0]:
        return _json_error(exc, EXIT_USAGE)
    error(exc)
    return EXIT_USAGE


# ----------------------------------------------------------------- commands

def cmd_info(args) -> int:
    """Header summary for both snapshots in the library."""
    try:
        snaps = parse_libapp(args.libapp, strict=not args.lenient)
    except JadartError as e:    # UnknownEpoch, truncated/malformed, or not-a-Dart-lib
        return _fail(e)

    if getattr(args, "json", False):
        return emit({"ok": True, "file": args.libapp, "snapshots": {
            which: {
                "kind": h.kind_name,
                "version_hash": h.version_hash,
                "epoch": h.epoch.name if h.epoch else None,
                "dart": h.epoch.dart if h.epoch else None,
                "target": str(h.arch) if h.arch else None,
                "arch": h.arch.name if h.arch else None,
                "word_size": h.arch.word_size if h.arch else None,
                "compressed_pointers": h.arch.compressed if h.arch else None,
                "features": h.features,
                "base_objects": h.num_base_objects,
                "objects": h.num_objects,
                "clusters": h.num_clusters,
                "instr_table_len": h.instr_table_len,
                "first_cid": h.first_cluster_cid,
            } for which, h in snaps.items()}})

    for which, h in snaps.items():
        print(heading(f"[{which}] snapshot"))
        print(f"  kind            {h.kind_name}")
        print(f"  version_hash    {h.version_hash}")
        epoch = h.epoch.name if h.epoch else "UNKNOWN (lenient)"
        dart = h.epoch.dart if h.epoch else "?"
        print(f"  epoch           {epoch}  (dart {dart})")
        print(f"  target          {h.arch if h.arch else 'unresolved'}")
        print(f"  features        {h.features[:72]}"
              f"{'...' if len(h.features) > 72 else ''}")
        print(f"  base_objects    {h.num_base_objects}")
        print(f"  objects         {h.num_objects}")
        print(f"  clusters        {h.num_clusters}")
        print(f"  instr_table_len {h.instr_table_len}")
        print(f"  first_cid       {h.first_cluster_cid}")
    return EXIT_OK


def cmd_classes(args) -> int:
    """Tier 0: the recovered class and member skeleton (M3)."""
    from .program import recover_program, emit_tier0
    try:
        prog = recover_program(args.libapp)
    except JadartError as e:
        return _fail(e)

    if args.library:
        keep = {k.name for k in prog.classes if args.library in k.library}
        prog.classes = [k for k in prog.classes if k.name in keep]
    ucs = prog.user_classes()
    nmembers = sum(len(k.members) for k in ucs)
    if getattr(args, "json", False):
        keep = [k for k in ucs if not args.filter or args.filter in (k.name or "")]
        return emit({"ok": True, "epoch": prog.epoch_name, "dart": prog.dart,
                     "count": len(keep),
                     "classes": [{"name": k.name, "superclass": k.super_name,
                                  "library": k.library,
                                  "members": [{"name": m.name, "kind": m.kind}
                                              for m in k.members]} for k in keep]})
    print(comment(f"// jadart Tier 0 skeleton  "
                  f"(epoch {prog.epoch_name}, dart {prog.dart})"))
    print(comment(f"// {len(ucs)} named classes, {nmembers} members, "
                  f"{len(prog.strings)} strings recovered") + "\n")
    print(emit_tier0(prog, name_filter=args.filter))
    return EXIT_OK


def cmd_export(args) -> int:
    """Decompile the whole binary to a browsable source tree, the way jadx and blutter do."""
    from .export import export
    # main() has already turned an apk/ipa/directory into a snapshot path.
    seen = [0]
    # Progress goes to stdout, so in JSON mode it would land inside the document. Same
    # reason the bare newline below is conditional: it used to precede a JSON error.
    as_json = getattr(args, "json", False)
    quiet = args.quiet or as_json

    def progress(done, total, url):
        if done == total or done - seen[0] >= 25:
            seen[0] = done
            print(f"\r  {done}/{total} libraries", end="", flush=True)

    try:
        stats = export(args.libapp, args.out, tier=args.tier, app_only=args.app,
                       progress=None if quiet else progress,
                       label=getattr(args, "container", None) or args.libapp,
                       container=getattr(args, "container", None),
                       sigs=getattr(args, "sigs", None))
    except JadartError as e:
        if not quiet:
            print()
        return _fail(e)
    if as_json:
        return emit({"ok": True, "out": args.out, "tier": args.tier, **stats})
    if not quiet:
        print()
    print(comment(f"// wrote {stats['libraries']} libraries, {stats['classes']} classes, "
                  f"{stats['methods']} methods to {args.out}/"))
    print(f"  {args.out}/sources/     decompiled tree, one file per library")
    c = stats.get("container")
    if c and c["assets"]:
        extra = f", {c['packages']} packages named" if c["packages"] else ""
        print(f"  {args.out}/assets/      {c['assets']} files, "
              f"{c['assets_bytes'] / 1e6:.1f} MB{extra}")
        if c["notable"]:
            print(f"  {args.out}/assets.txt   what each asset is; "
                  + bold(f"{len(c['notable'])} worth opening first"))
        else:
            print(f"  {args.out}/assets.txt   what each asset is")
    if c and c["members"]:
        print(f"  {args.out}/container.txt  the other {c['members'] - c['assets']} members, "
              f"and what reads them")
    print(f"  {args.out}/strings.txt  {stats['strings']} strings")
    print(f"  {args.out}/pool.txt     resolved ObjectPool entries")
    if stats["selectors"]:
        print(f"  {args.out}/selectors.txt  {stats['selectors']} dispatch selectors")
    print(f"  {args.out}/summary.txt  what was recovered, and what was not")
    return EXIT_OK


def cmd_libraries(args) -> int:
    """Which libraries the snapshot was built from, and how many classes each declares.

    This is how you find the application's own code. Every class records the library it was
    declared in, so an app's classes sit under its own package (`package:myapp/main.dart`)
    among the framework's. It reads out of the snapshot, so it needs no reference binary."""
    from .program import recover_program
    try:
        prog = recover_program(args.libapp)
    except JadartError as e:
        return _fail(e)
    libs = prog.libraries()
    rows = sorted(libs.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    if args.app:
        from .export import is_framework
        rows = [(u, k) for u, k in rows if not is_framework(u)]
    if args.grep:
        rows = [(u, k) for u, k in rows if args.grep in u]
    if getattr(args, "json", False):
        return emit({"ok": True, "epoch": prog.epoch_name, "dart": prog.dart,
                     "libraries": [{"url": u, "classes": len(ks),
                                    "names": sorted(k.name for k in ks if k.name)}
                                   for u, ks in rows]}, EXIT_OK if rows else EXIT_MISS)
    if not rows:
        print("jadart: no libraries matched", file=sys.stderr)
        return EXIT_MISS
    print(comment(f"// {len(rows)} libraries  (epoch {prog.epoch_name}, dart {prog.dart})\n"))
    for url, ks in rows:
        print(f"{len(ks):5d}  {url}")
    return EXIT_OK


def cmd_lift(args) -> int:
    """Tier 3 for a single function, including top-level ones that belong to no class."""
    from .disasm import (load_instructions, named_ranges, disassemble_range, annotate,
                         build_pool_map)
    from .signatures import names_with_signatures
    from .expr import lift_function, make_arity_resolver
    from .dispatch import recover_selectors
    from .fields import recover_fields
    try:
        image, fr, hdr = load_instructions(args.libapp)
    except JadartError as e:
        return _fail(e)
    ranges = named_ranges(image, fr, args.symbol)
    if not ranges:
        if getattr(args, "json", False):
            return emit({"ok": False, "symbol": args.symbol, "count": 0,
                         "functions": [], "error": "no function of that name recovered"},
                        EXIT_MISS)
        print(f"jadart: no function named {args.symbol!r} recovered", file=sys.stderr)
        return EXIT_MISS
    try:
        pc_to_name, signote = names_with_signatures(image, fr, getattr(args, "sigs", None))
    except JadartError as e:
        return _fail(e)
    if signote and not getattr(args, "json", False):
        print(comment(f"// {signote}"))
    pool_map = build_pool_map(fr, getattr(image, "arch", None))
    from .program import static_function_refs, receiver_for
    static_refs = static_function_refs(fr)
    arity = make_arity_resolver(image)
    selectors = recover_selectors(image, fr, hdr)
    layout = recover_fields(fr, getattr(image, "arch", None))
    out = []
    for nm, cr in ranges:
        dis = disassemble_range(image, cr)
        if not dis:
            continue
        body = lift_function(annotate(dis, pc_to_name, pool_map), pool_map,
                             receiver=receiver_for(cr.owner_ref, static_refs),
                             arity=arity, selectors=selectors,
                             arch=getattr(image, "arch", None),
                             fields=layout.for_function(cr.owner_ref))
        if getattr(args, "json", False):
            out.append({"name": nm, "pc_offset": cr.pc_offset, "size": cr.size,
                        "instructions": len(dis), "body": [ln.strip() for ln in body]})
            continue
        print(comment(f"// {nm}  .text+0x{cr.pc_offset:x}  ({cr.size} bytes)"))
        for ln in body:
            print(ln)
        print()
    if getattr(args, "json", False):
        return emit({"ok": bool(out), "symbol": args.symbol, "count": len(out),
                     "functions": out}, EXIT_OK if out else EXIT_MISS)
    return EXIT_OK


def cmd_disasm(args) -> int:
    """Tier 1: annotated arm64 for every code range under one name."""
    from .disasm import (load_instructions, disassemble_range, named_ranges,
                         annotate, build_pool_map)
    from .signatures import names_with_signatures
    try:
        image, fr, _hdr = load_instructions(args.libapp)
    except JadartError as e:
        return _fail(e)

    as_json = getattr(args, "json", False)
    ranges = named_ranges(image, fr, args.symbol)
    if not ranges:
        if as_json:
            return emit({"ok": False, "symbol": args.symbol, "count": 0, "functions": [],
                         "error": "no function of that name recovered"}, EXIT_MISS)
        error(f"no function named {args.symbol!r} recovered")
        return EXIT_MISS
    try:
        pc_to_name, signote = names_with_signatures(image, fr, getattr(args, "sigs", None))
    except JadartError as e:
        return _fail(e)
    if signote and not as_json:
        print(comment(f"// {signote}"))
    pool_map = build_pool_map(fr, getattr(image, "arch", None))
    printed, out = 0, []
    for nm, cr in ranges:
        dis = disassemble_range(image, cr)
        if not dis:
            continue
        ann = annotate(dis, pc_to_name, pool_map)
        printed += 1
        if as_json:
            out.append({"name": nm, "pc_offset": cr.pc_offset, "size": cr.size,
                        "instructions": [{"addr": a, "mnemonic": mn, "operands": op,
                                          "note": note.strip().lstrip("; ").strip()}
                                         for a, mn, op, note in ann]})
            continue
        print(dim("// ") + bold(nm)
              + dim(f"  @ .text+0x{cr.pc_offset:x}  ({cr.size} bytes)"))
        for addr, mn, op, note in ann:
            print("  " + dim(f"0x{addr:06x}") + f"  {mn:<7} {op}" + dim(note))
        print()
    if as_json:
        return emit({"ok": bool(out), "symbol": args.symbol, "count": len(out),
                     "functions": out}, EXIT_OK if out else EXIT_MISS)
    if not printed:
        error(f"{args.symbol} has no resolvable code range")
        return EXIT_MISS
    return EXIT_OK


def cmd_decompile(args) -> int:
    """The unified view: Tier 0 class header with each method body at the chosen tier."""
    from .program import decompile_class
    try:
        out = decompile_class(args.libapp, args.klass,
                              structured=args.tier >= 2, tier=args.tier,
                              sigs=getattr(args, "sigs", None))
    except JadartError as e:
        return _fail(e)

    if getattr(args, "json", False):
        # The body is a source listing, so it goes over as lines rather than as one blob
        # with embedded newlines, that is what makes `jq '.lines[]'` useful.
        return emit({"ok": out is not None, "class": args.klass, "tier": args.tier,
                     "lines": out.splitlines() if out else [],
                     **({} if out is not None
                        else {"error": "no class of that name recovered"})},
                    EXIT_OK if out is not None else EXIT_MISS)
    if out is None:
        error(f"no class named {args.klass!r} recovered")
        return EXIT_MISS
    print(out)
    return EXIT_OK


def cmd_functions(args) -> int:
    """Every code range in the image, the way `afl` and IDA's Functions window list them."""
    from .disasm import load_instructions
    from .callgraph import function_table, ORIGINS
    try:
        image, fr, hdr = load_instructions(args.libapp)
        table, graph_error = function_table(image, fr, hdr,
                                            sigs=getattr(args, "sigs", None))
    except JadartError as e:
        return _fail(e)

    rows = table
    if args.filter:
        rows = [f for f in rows if args.filter.lower() in f.label.lower()]
    if args.library:
        rows = [f for f in rows if args.library.lower() in (f.library or "").lower()]
    if args.named:
        rows = [f for f in rows if f.origin != "anonymous"]
    if args.anonymous:
        rows = [f for f in rows if f.origin == "anonymous"]
    if args.called:
        rows = [f for f in rows if f.callers]
    if args.virtual:
        rows = [f for f in rows if f.virtual_callers]
    keys = {"addr": lambda f: f.pc_offset, "size": lambda f: -f.size,
            "callers": lambda f: -(f.callers + f.virtual_callers),
            "name": lambda f: f.label.lower()}
    rows = sorted(rows, key=keys[args.sort])
    shown = rows if args.limit <= 0 else rows[:args.limit]

    if getattr(args, "json", False):
        return emit({"ok": True, "total": len(table), "matched": len(rows),
                     "call_graph": None if graph_error else "built",
                     "call_graph_error": str(graph_error) if graph_error else None,
                     "functions": [{"pc_offset": f.pc_offset, "size": f.size,
                                    "name": f.name, "label": f.label, "origin": f.origin,
                                    "library": f.library, "callers": f.callers,
                                    "callees": f.callees, "indirect": f.indirect,
                                    "virtual_callers": f.virtual_callers,
                                    "overloads": f.overloads}
                                   for f in shown]})

    from collections import Counter
    by_origin = Counter(f.origin for f in table)
    print(comment(f"// {len(table)} code ranges  "
                  + "  ".join(f"{k} {by_origin[k]}" for k in ORIGINS if by_origin[k])))
    if len(rows) != len(table):
        print(comment(f"// {len(rows)} match the filter"))
    if graph_error:
        # The list is real; the edge columns are not. Printing 0 for every function would
        # read as "nothing calls this" when the truth is that nothing could look.
        print(comment(f"// no call graph: {graph_error}"))
        print(comment("// the calls/in/vin columns are omitted rather than shown as 0"))
    if graph_error:
        print(heading(f"{'address':<14} {'size':>7}  name"))
    else:
        print(heading(f"{'address':<14} {'size':>7} {'calls':>6} {'in':>5} {'vin':>5}  name"))
    for f in shown:
        lib = dim(f"   {f.library}") if f.library and args.verbose else ""
        if graph_error:
            print(f".text+0x{f.pc_offset:<7x} {f.size:>7}  {f.label}{lib}")
            continue
        # `vin` counts sites that could reach this through the dispatch table. It is a
        # maybe, not a fact, which is why it never merges into the direct `in` column.
        vin = str(f.virtual_callers) if f.virtual_callers else dim("-")
        print(f".text+0x{f.pc_offset:<7x} {f.size:>7} {f.callees:>6} {f.callers:>5} "
              f"{vin:>5}  {f.label}{lib}")
    if args.limit > 0 and len(rows) > args.limit:
        print(dim(f"... {len(rows) - args.limit} more (raise with -n, or -n 0 for all)"))
    return EXIT_OK


def cmd_signatures(args) -> int:
    """Build a signature library from reference binaries whose names survived."""
    from . import signatures as sig
    quiet = getattr(args, "quiet", False) or getattr(args, "json", False)
    try:
        lib = sig.build(args.refs,
                        progress=None if quiet else
                        (lambda p: print(comment(f"// reading {p}"), file=sys.stderr)))
        sig.save(lib, args.out)
    except JadartError as e:
        return _fail(e)

    refs = [{"path": s, "dart": d, "named": n} for s, d, n in lib.sources]
    if getattr(args, "json", False):
        return emit({"ok": True, "out": args.out, "shapes": len(lib),
                     "dropped": lib.dropped, "references": refs})
    print(comment(f"// wrote {len(lib)} shapes to {args.out}"))
    for r in refs:
        print(f"  {r['named']:6d} named functions   dart {r['dart']:<9} {r['path']}")
    # Not a warning. A shape two references disagree about is exactly what a single
    # reference cannot show you, and dropping it is the point of passing several.
    print(comment(f"// {lib.dropped} shapes dropped: more than one function has them, so "
                  f"they name nothing"))
    return EXIT_OK


def cmd_selectors(args) -> int:
    """Tier 3.4: selector names read back out of the serialized dispatch table."""
    from .disasm import load_instructions
    from .dispatch import recover_selectors, ORIGIN_ELEMENT_ARM64 as ORIGIN
    try:
        image, fr, hdr = load_instructions(args.libapp)
        sel = recover_selectors(image, fr, hdr)
    except JadartError as e:
        return _fail(e)

    if getattr(args, "json", False):
        return emit({"ok": bool(sel), "origin_element": ORIGIN, "count": len(sel),
                     "selectors": [{"name": nm, "selector_offset": imm + ORIGIN,
                                    "call_site_imm": imm}
                                   for imm, nm in sorted(sel.items(), key=lambda kv: kv[1])]},
                    EXIT_OK if sel else EXIT_MISS)
    if not sel:
        error("no dispatch-table selector names recovered "
              "(no table, or the snapshot's names are stripped)")
        return EXIT_MISS
    print(comment(f"// {len(sel)} virtual-dispatch selectors recovered "
                  f"(selector_offset = call-site immediate + {ORIGIN})"))
    for imm, nm in sorted(sel.items(), key=lambda kv: kv[1]):
        print(f"  {nm:<40} "
              + dim(f"selector_offset={imm + ORIGIN:<7} call-site imm={imm}"))
    return EXIT_OK


def cmd_constants(args) -> int:
    """The const lists in the object pool, elements and all.

    `decompile` prints `const[47] @0xb9b0{0xed, 0xba, 0x2a, ...}` for a table too long to
    spell at every use site. This is where the rest of it lives, keyed on the same offset,
    so the label in a body is followed rather than merely noticed.
    """
    from .fill import printable
    from .disasm import load_instructions, const_lists
    try:
        image, fr, _hdr = load_instructions(args.libapp)
        lists = const_lists(fr, getattr(image, "arch", None))
    except JadartError as e:
        return _fail(e)
    if getattr(args, "json", False):
        return emit({"ok": True, "count": len(lists),
                     "constants": [{"offset": off, "length": len(v), "elements": v}
                                   for off, v in sorted(lists.items())]})
    if not lists:
        print("no const list in the object pool resolves to elements this can name")
        return 0
    for off, vals in sorted(lists.items()):
        body = ", ".join(printable(v) if isinstance(v, str) else hex(v) for v in vals)
        print(f"0x{off:x}\t[{len(vals)}]\t{body}")
    return 0


def cmd_strings(args) -> int:
    """Full M2 pass: walk the alloc, recover the identifier pool, print an inventory."""
    from .fill import printable
    try:
        r = walk_isolate(args.libapp, full=True)
    except JadartError as e:    # UnknownEpoch or AllocError
        return _fail(e)

    h, strings = r["header"], r["strings"]
    if getattr(args, "json", False):
        vals = sorted(set(strings))
        if args.grep:
            vals = [v for v in vals if args.grep in v]
        return emit({"ok": True, "epoch": h.epoch.name if h.epoch else None,
                     "count": len(vals), "strings": vals})
    if args.plain:
        # One string per line and nothing else, so the output composes with grep, sort and
        # wc. The inventory below is for reading; this is for piping.
        for s in sorted(set(strings)):
            if args.grep and args.grep not in s:
                continue
            print(printable(s))
        return EXIT_OK
    print(f"epoch {h.epoch.name} (dart {h.epoch.dart}); {h.num_clusters} clusters, "
          f"{h.num_objects} objects; {len(strings)} interned strings recovered")
    print("\n" + heading("top clusters by object count:"))
    for name, cnt in list(r["cid_histogram"].items())[:12]:
        print(f"  {cnt:>7}  {name}")
    # identifier-looking names (a practical Tier-0 precursor: the class/method/field pool)
    idents = sorted({s for s in strings
                     if s and (s[0].isalpha() or s[0] == "_")
                     and 2 <= len(s) <= 60 and all(c.isalnum() or c in "_$." for c in s)})
    print("\n" + heading(f"{len(idents)} identifier-like names. sample:"))
    for s in idents[:40]:
        print(f"  {printable(s)}")
    if args.grep:
        hits = sorted(s for s in strings if args.grep in s)
        print("\n" + heading(f"grep '{args.grep}': {len(hits)} hits"))
        for s in hits[:40]:
            print(f"  {printable(s)}")
    return EXIT_OK


def _xrefs_to_function(args, image, fr) -> int | None:
    """`xrefs` when the pattern names a function rather than a pool entry: report the
    call sites. Returns an exit code, or None if the pattern names no function.

    The two questions really are one question (what references this) so they share a
    command rather than making a caller guess which of two to reach for. A pool entry is
    tried first because a string is the more specific ask; a bare name that matches both
    reports both.
    """
    from .disasm import named_ranges
    from .callgraph import callers_of
    try:
        ranges = named_ranges(image, fr, args.pattern)
    except JadartError:
        # The pattern names nothing this binary can offer. A bug in named_ranges is a
        # different thing and belongs in main's internal-error path, not silently in None.
        return None
    if not ranges:
        return None

    targets = {cr.pc_offset: nm for nm, cr in ranges}
    # A --sigs library feeds the selector vote as well as the name column: on an
    # --obfuscate build it is the only thing that gives the vote anything to count.
    extra = None
    sigs = getattr(args, "sigs", None)
    if sigs:
        from .signatures import load, match
        extra = {pc: m.name for pc, m in match(image, fr, load(sigs)).items()}
    found = callers_of(image, fr, list(targets), extra_names=extra)
    fns = []
    for pc in sorted(targets):
        r = found[pc]
        fns.append({
            "name": targets[pc], "pc_offset": pc, "overloads": r["overloads"],
            "called_by": [{"pc_offset": c.pc_offset, "size": c.size} for c in r["direct"]],
            "may_be_called_by": [{"pc_offset": c.pc_offset, "size": c.size}
                                 for c in r["virtual"]],
        })
    total = sum(len(f["called_by"]) for f in fns)
    virt = sum(len(f["may_be_called_by"]) for f in fns)
    if getattr(args, "json", False):
        return emit({"ok": True, "pattern": args.pattern, "kind": "function",
                     "count": len(fns), "call_sites": total, "virtual_call_sites": virt,
                     "functions": fns})
    for f in fns:
        print(comment(f"// {f['name']}  .text+0x{f['pc_offset']:x}"))
        if f["called_by"]:
            n = len(f["called_by"])
            print(heading(f"  {n} direct call site{'' if n == 1 else 's'}"))
            for c in f["called_by"]:
                print(f"    .text+0x{c['pc_offset']:<8x} {dim(str(c['size']) + ' bytes')}")
        if f["may_be_called_by"]:
            n, m = f["overloads"], len(f["may_be_called_by"])
            # An honest header. One implementation means the site can only land here; many
            # means this is one candidate among them, and the receiver's runtime class
            # decides. Printing both as "callers" would sell the second as the first.
            certainty = ("the only implementation, so these sites resolve here" if n <= 1
                         else f"one of {n} implementations of this selector")
            print(heading(f"  {m} virtual call site{'' if m == 1 else 's'}")
                  + dim(f"  ({certainty})"))
            for c in f["may_be_called_by"]:
                print(f"    .text+0x{c['pc_offset']:<8x} {dim(str(c['size']) + ' bytes')}")
        if not f["called_by"] and not f["may_be_called_by"]:
            # Still not the same as "unused": a closure is reached through a captured
            # context and leaves no edge any static pass can see.
            print(dim("    no call sites found (may be reached through a closure, "
                      "or only from the runtime)"))
    return EXIT_OK


#: What a native library is called on the platforms Flutter builds for: an ELF `.so`, a
#: Mach-O `.dylib`, a Windows `.dll`, or a path into a `.framework`. Matched on the STRING
#: and nothing else, which is why the report says "named in the object pool" rather than
#: "loaded": jadart can see that the literal is there and which code reads it, and it
#: cannot see that `DynamicLibrary.open` was the reader. Both facts are printed, neither is
#: merged into a claim the binary does not support.
_SONAME_RE = None


def _soname_re():
    global _SONAME_RE
    if _SONAME_RE is None:
        import re
        _SONAME_RE = re.compile(
            r'^"(?:[^"/]*/)*[\w.+-]+\.(?:so|dylib|dll)(?:\.\d+)*"$|\.framework/')
    return _SONAME_RE


#: A quoted literal inside a lifted line. The looked-up symbol name is an argument to the
#: resolver call, and the lifter already reconstructs it where it can; where it cannot the
#: line reads `(...)` and there is nothing here to print.
_LITERAL_RE = None


def _literal_re():
    global _LITERAL_RE
    if _LITERAL_RE is None:
        import re
        _LITERAL_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
    return _LITERAL_RE


def cmd_ffi(args) -> int:
    """The native boundary: which shared objects the Dart names, and what it reads out.

    On a Flutter app that pushes its interesting code into C, the Dart half stops being the
    answer and becomes the map to it. What an analyst needs at that point is the name of
    the library, the symbols looked up in it, and the address of the code that does the
    looking, and jadart already recovers all three, scattered across `strings`, `xrefs`
    and `lift`. This puts them on one page.
    """
    from .disasm import (load_instructions, build_pool_map, pool_xrefs, disassemble_range,
                         annotate)
    from .signatures import names_with_signatures
    from .expr import lift_function, make_arity_resolver
    from .dispatch import recover_selectors
    from .fields import recover_fields
    from .program import static_function_refs, receiver_for
    try:
        image, fr, hdr = load_instructions(args.libapp)
    except JadartError as e:
        return _fail(e)
    pool = build_pool_map(fr, getattr(image, "arch", None))
    rx = _soname_re()
    libs = {off: lab for off, lab in pool.items() if rx.search(lab)}
    refs = pool_xrefs(image, libs) if libs else {}

    # One function can name several libraries, and lifting is the expensive half, so each
    # is lifted once and reported under every library it mentions.
    by_fn: dict = {}
    for off, crs in refs.items():
        for cr in crs:
            by_fn.setdefault(cr.pc_offset, cr)
    bodies: dict = {}
    if by_fn:
        pc_to_name, _note = names_with_signatures(image, fr, getattr(args, "sigs", None))
        static_refs = static_function_refs(fr)
        arity = make_arity_resolver(image)
        selectors = recover_selectors(image, fr, hdr)
        layout = recover_fields(fr, getattr(image, "arch", None))
        lit = _literal_re()
        for pc, cr in by_fn.items():
            dis = disassemble_range(image, cr)
            if not dis:
                continue
            try:
                body = lift_function(annotate(dis, pc_to_name, pool), pool,
                                     receiver=receiver_for(cr.owner_ref, static_refs),
                                     arity=arity, selectors=selectors,
                                     arch=getattr(image, "arch", None),
                                     fields=layout.for_function(cr.owner_ref))
            except JadartError:
                # Tier 3 declines on a target it has no register model for (UnsupportedArch
                # is a JadartError). The pool and xref halves still hold, so the library is
                # reported without its symbols rather than the whole command failing. Any
                # OTHER exception is a defect and goes to main's internal-error path.
                body = []
            keep = [ln.strip() for ln in body if lit.search(ln)]
            bodies[pc] = {"name": pc_to_name.get(pc), "size": cr.size,
                          "lines": keep if getattr(args, "full", False) is False
                          else [ln.rstrip() for ln in body]}

    entries = []
    for off in sorted(libs):
        entries.append({
            "pool_offset": off,
            "library": libs[off].strip('"'),
            "referenced_by": [
                {"pc_offset": cr.pc_offset, "name": bodies.get(cr.pc_offset, {}).get("name"),
                 "size": cr.size, "lines": bodies.get(cr.pc_offset, {}).get("lines", [])}
                for cr in sorted(refs.get(off, ()), key=lambda c: c.pc_offset)],
        })
    if getattr(args, "json", False):
        return emit({"ok": bool(entries), "count": len(entries), "libraries": entries},
                    EXIT_OK if entries else EXIT_MISS)
    if not entries:
        error("no shared-object name in the ObjectPool, so nothing here says this "
              "snapshot reaches native code. That is evidence, not proof: a name built "
              "at runtime, or passed in from the Java side, leaves no literal to find")
        return EXIT_MISS
    ep = hdr.epoch
    print(comment(f"// jadart FFI boundary  (epoch {ep.name if ep else '?'}, "
                  f"dart {ep.dart if ep else '?'})"))
    print(comment("// shared-object names in the ObjectPool, and the code that reads them"))
    for e in entries:
        print()
        print(bold(e["library"]) + dim(f"   pool_0x{e['pool_offset']:x}"))
        if not e["referenced_by"]:
            print(dim("    no direct loads found "
                      "(reached through a closure, or built at runtime)"))
        for r in e["referenced_by"]:
            nm = r["name"] or f"sub_0x{r['pc_offset']:x}"
            print(f"  {heading(nm)}  .text+0x{r['pc_offset']:x}  {dim(str(r['size']) + ' bytes')}")
            for ln in r["lines"]:
                print(f"      {ln}")
            if not r["lines"]:
                print(dim("      no literal reached a call site here"))
    print()
    print(dim("Symbol names are string arguments the lifter could attribute to a call. "
              "A call it could not read prints (...) and is not listed."))
    return EXIT_OK


def cmd_xrefs(args) -> int:
    """Which functions load a given string or pool entry, or call a given function."""
    from .disasm import load_instructions, build_pool_map, pool_xrefs
    try:
        image, fr, hdr = load_instructions(args.libapp)
    except JadartError as e:
        return _fail(e)
    pool = build_pool_map(fr, getattr(image, "arch", None))
    needle = args.pattern
    addr = None
    try:
        addr = int(needle, 0)
    except ValueError:
        pass
    matches = {off: lab for off, lab in pool.items()
               if (addr is not None and off == addr) or (addr is None and needle in lab)}
    if not matches:
        rc = _xrefs_to_function(args, image, fr)
        if rc is not None:
            return rc
        if getattr(args, "json", False):
            return emit({"ok": False, "pattern": needle, "count": 0, "entries": []},
                        EXIT_MISS)
        error(f"nothing matching {needle!r}: no ObjectPool entry holds it, and no "
              f"function goes by that name or address")
        return EXIT_MISS

    refs = pool_xrefs(image, matches)
    entries = [{"pool_offset": off, "entry": matches[off],
                "referenced_by": [{"pc_offset": c.pc_offset, "size": c.size}
                                  for c in refs[off]]}
               for off in sorted(matches)]
    if getattr(args, "json", False):
        return emit({"ok": True, "pattern": needle, "count": len(entries),
                     "entries": entries})
    for e in entries:
        print(comment(f"// pool_0x{e['pool_offset']:x}  {e['entry']}"))
        if not e["referenced_by"]:
            print(dim("    no direct loads found "
                      "(reached through a closure or built at runtime)"))
        for r in e["referenced_by"]:
            size = dim(f"{r['size']} bytes")
            print(f"    .text+0x{r['pc_offset']:<8x} {size}")
    return EXIT_OK


def cmd_verify(args) -> int:
    """The acceptance gates. Is this snapshot being parsed with the right grammar?"""
    from .verify import verify_file
    try:
        rep = verify_file(args.libapp)
    except JadartError as e:
        return _fail(e)

    if getattr(args, "json", False):
        return emit({"ok": rep.supported, "epoch": rep.epoch, "target": str(rep.arch),
                     "gates": [{"gate": g.gate, "tier": g.tier, "status": g.status,
                                "passed": g.passed, "checks": g.checks,
                                "detail": g.detail, "skipped": g.skipped}
                               for g in rep.gates],
                     "passed": sum(1 for g in rep.gates if g.passed and not g.skipped),
                     "failed": [g.gate for g in rep.gates
                                if not g.passed and not g.skipped]},
                    EXIT_OK if rep.supported else EXIT_MISS)
    print(rep.render())
    return EXIT_OK if rep.supported else EXIT_MISS


# ----------------------------------------------------------------- version

def _version_text() -> str:
    """`--version` reports the epochs too, because that's what decides whether a given
    libapp.so can be opened at all. A bare version number wouldn't answer that.

    versions.py exports only known_hashes(), so the epoch table is read directly.
    getattr keeps this from being the thing that breaks if that private name moves.
    """
    from . import __version__, versions

    lines = [f"jadart {__version__}"]
    table = getattr(versions, "_EPOCHS", None)
    if not table:
        return lines[0]

    def release_order(ep):
        # Sort by release, not by spelling: sorted() alone puts 3.10 before 3.4, which
        # reads as a mistake in a list whose whole job is showing the supported range.
        return [int(part) for part in ep.dart.split(".") if part.isdigit()]

    supported, identified = [], []
    for h, ep in sorted(table.items(), key=lambda kv: release_order(kv[1])):
        row = f"  {ep.name:<19} dart {ep.dart:<8} {h[:8]}"
        if ep.grammars:
            grammars = ", ".join(f"{w * 8}-bit {'compressed' if c else 'uncompressed'}"
                                 for w, c in sorted(ep.grammars))
            supported.append(f"{row}  {grammars}")
        else:
            identified.append(row)
    if supported:
        lines += ["", f"supported epochs ({len(supported)}), oldest first:"] + supported
    if identified:
        lines += ["", "identified, no validated cluster grammar yet:"] + identified
    return "\n".join(lines)


class _VersionAction(argparse.Action):
    """Like argparse's built-in version action, but the text is built on demand so
    every other command avoids importing versions.py just to build the parser."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, help=None):
        super().__init__(option_strings=option_strings, dest=dest,
                         default=argparse.SUPPRESS, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        print(_version_text())
        parser.exit(EXIT_OK)


# ----------------------------------------------------------------- parser

def _common() -> argparse.ArgumentParser:
    """Options accepted both before and after the command word.

    default=SUPPRESS is load-bearing. A subparser writes its own defaults over whatever
    the top-level parser already stored, so without it `jadart --color never info x`
    would silently lose the flag. SUPPRESS leaves the attribute unset unless typed.
    """
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--color", choices=("auto", "always", "never"),
                   default=argparse.SUPPRESS, metavar="WHEN",
                   help="colourise output: auto (default, only on a tty), always, never")
    p.add_argument("-j", "--json", action="store_true", default=argparse.SUPPRESS,
                   help="emit JSON on stdout instead of a report, for scripting. Errors "
                        "become JSON too, so a caller never has to read stderr")
    return p


def _add(sub, common, name: str, summary: str) -> argparse.ArgumentParser:
    p = sub.add_parser(name, parents=[common], help=summary, description=summary)
    p.add_argument("libapp", metavar="<libapp.so>",
                   help="path to the Flutter shared object (or the iOS App binary)")
    return p


def _add_sigs(p) -> None:
    """The --sigs option, for the commands that render function names."""
    p.add_argument("--sigs", metavar="FILE",
                   help="name library code by matching its shape against a signature "
                        "file built with `jadart signatures`. Matched names end in ~ "
                        "because they are inferred from another binary, not read from "
                        "this one. Worth it on --obfuscate builds, where the names are "
                        "genuinely absent")


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    ap = argparse.ArgumentParser(
        prog="jadart", parents=[common],
        description="Reverse-engineering toolkit for Flutter/Dart AOT snapshots.",
        epilog=_EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action=_VersionAction,
                    help="print the tool version and the format epochs it can parse")
    sub = ap.add_subparsers(title="commands", metavar="<command>", dest="command",
                            required=True)

    p = _add(sub, common, "info", "header, epoch, target and object counts")
    p.add_argument("--lenient", action="store_true",
                   help="do not fail on an unknown format epoch (unsafe)")
    p.set_defaults(func=cmd_info)

    p = _add(sub, common, "export", "decompile the whole binary to a source tree")
    p.add_argument("-o", "--out", default="jadart-out", metavar="DIR",
                   help="output directory (default jadart-out)")
    p.add_argument("-t", "--tier", type=int, choices=(1, 2, 3), default=3)
    p.add_argument("-a", "--app", action="store_true",
                   help="only the app's own libraries, skipping dart: and package:flutter")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    _add_sigs(p)
    p.set_defaults(func=cmd_export)

    p = _add(sub, common, "libraries", "libraries the snapshot was built from")
    p.add_argument("-g", "--grep", metavar="STR", help="keep only matching urls")
    p.add_argument("-a", "--app", action="store_true",
                   help="hide dart: and package:flutter libraries")
    p.set_defaults(func=cmd_libraries)

    p = _add(sub, common, "classes", "Tier 0 class and member skeleton")
    p.add_argument("-f", "--filter", metavar="STR", help="keep only matching names")
    p.add_argument("-l", "--library", metavar="URL",
                   help="keep only classes declared in a matching library")
    p.set_defaults(func=cmd_classes)

    p = _add(sub, common, "functions", "every function in the image, with call counts")
    p.add_argument("-f", "--filter", metavar="STR", help="keep only matching names")
    p.add_argument("-l", "--library", metavar="URL",
                   help="keep only functions owned by a matching library")
    p.add_argument("-s", "--sort", choices=("addr", "size", "callers", "name"),
                   default="addr", help="order (default addr)")
    p.add_argument("-n", "--limit", type=int, default=200, metavar="N",
                   help="show at most N (default 200; 0 for all)")
    p.add_argument("--named", action="store_true", help="only functions with a name")
    p.add_argument("--anonymous", action="store_true",
                   help="only the ones with no name, which is what is left after a match "
                        "pass and therefore where an app's own code is")
    p.add_argument("--called", action="store_true",
                   help="only functions something calls directly")
    p.add_argument("--virtual", action="store_true",
                   help="only functions a dispatch-table call site can reach")
    p.add_argument("-v", "--verbose", action="store_true", help="show the owning library")
    _add_sigs(p)
    p.set_defaults(func=cmd_functions)

    p = _add(sub, common, "lift", "Tier 3 pseudo-Dart for one function")
    p.add_argument("symbol", help="function name, including top-level functions")
    _add_sigs(p)
    p.set_defaults(func=cmd_lift)

    p = _add(sub, common, "disasm", "annotated arm64 for one symbol")
    p.add_argument("symbol", metavar="SYMBOL",
                   help="a recovered function name, or an ELF .symtab name on "
                        "dwarf builds")
    _add_sigs(p)
    p.set_defaults(func=cmd_disasm)

    p = _add(sub, common, "decompile", "class header plus reconstructed method bodies")
    p.add_argument("klass", metavar="CLASS", help="name of a recovered class")
    p.add_argument("-t", "--tier", type=int, choices=(1, 2, 3), default=3,
                   help="3=expressions (default), 2=control flow, 1=arm64")
    _add_sigs(p)
    p.set_defaults(func=cmd_decompile)

    p = sub.add_parser("signatures", parents=[common],
                       help="build a signature library from reference binaries",
                       description="Build a signature library from reference binaries "
                                   "whose function names survived, so that a stripped or "
                                   "--obfuscate build can be named by shape. Pass several "
                                   "references: a shape they disagree about is dropped "
                                   "rather than guessed at, and one reference cannot "
                                   "disagree with itself.")
    p.add_argument("refs", nargs="+", metavar="<reference>",
                   help="one or more normal builds of the same Dart release")
    p.add_argument("-o", "--out", required=True, metavar="FILE",
                   help="where to write the signature library")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    p.set_defaults(func=cmd_signatures)

    p = _add(sub, common, "selectors", "recovered virtual-dispatch selector names")
    p.set_defaults(func=cmd_selectors)

    p = _add(sub, common, "constants",
             "the const lists in the object pool, elements and all")
    p.set_defaults(func=cmd_constants)

    p = _add(sub, common, "strings", "the recovered identifier and string pool")
    p.add_argument("-g", "--grep", metavar="PATTERN",
                   help="keep only strings containing PATTERN")
    p.add_argument("-p", "--plain", action="store_true",
                   help="one string per line and nothing else, for piping. Control "
                        "characters and backslashes are escaped so each string stays on "
                        "one line; decode with unicode_escape to get the exact bytes back")
    p.set_defaults(func=cmd_strings)

    p = _add(sub, common, "xrefs", "what references a string, a pool entry or a function")
    p.add_argument("pattern", metavar="STRING|0xOFFSET|FUNCTION",
                   help="substring of a pool entry, a pool offset, or the name or "
                        "address of a function whose call sites you want")
    _add_sigs(p)
    p.set_defaults(func=cmd_xrefs)

    p = _add(sub, common, "ffi", "the native boundary: shared objects and what is read out")
    p.add_argument("--full", action="store_true",
                   help="print the whole lifted body of each referencing function, not "
                        "only the lines carrying a string literal")
    _add_sigs(p)
    p.set_defaults(func=cmd_ffi)

    p = _add(sub, common, "verify", "byte-exact acceptance gates for the parse")
    p.set_defaults(func=cmd_verify)
    return ap


# ----------------------------------------------------------------- legacy form

def _legacy_parser() -> argparse.ArgumentParser:
    """The pre-subcommand flag set. Hidden from --help, still fully supported.

    add_help=False because `-h` is intercepted before this parser ever sees it, and a
    legacy usage line is not what someone asking for help wants to read.
    """
    ap = argparse.ArgumentParser(prog="jadart", add_help=False)
    ap.add_argument("libapp")
    ap.add_argument("--lenient", action="store_true")
    ap.add_argument("--names", action="store_true")
    ap.add_argument("--grep", metavar="STR")
    ap.add_argument("--tier0", action="store_true")
    ap.add_argument("--filter", metavar="STR")
    ap.add_argument("--disasm", metavar="FUNC")
    ap.add_argument("--decompile", metavar="CLASS")
    ap.add_argument("--tier", type=int, choices=(1, 2, 3), default=3)
    ap.add_argument("--selectors", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--color", choices=("auto", "always", "never"))
    return ap


def _looks_legacy(argv: list[str]) -> bool:
    """True for the old form, `jadart <libapp> --flag`.

    The test is positional. In the new form the first word is always a command name or
    an option; in the old form it's always a path. The one ambiguous case is a file
    actually named `info` or `verify`, which `./info` disambiguates.
    """
    if not argv:
        return False
    head = argv[0]
    return not (head.startswith("-") or head in _COMMANDS)


def _pos(name: str) -> list[str]:
    """Guard a rewritten positional whose value could start with a dash."""
    return ["--", name] if name.startswith("-") else [name]


def _translate_legacy(argv: list[str]) -> list[str]:
    """Rewrite an old-style command line into the subcommand form.

    The if-order reproduces the old precedence exactly. The old CLI tested --verify
    first and fell through to the header summary, so `--verify --tier0` ran verify and
    still does.
    """
    args = _legacy_parser().parse_args(argv)
    lib = args.libapp
    pre = ["--color", args.color] if args.color else []

    if args.verify:
        return pre + ["verify", lib]
    if args.selectors:
        return pre + ["selectors", lib]
    if args.decompile:
        return pre + ["decompile", lib, "-t", str(args.tier)] + _pos(args.decompile)
    if args.disasm:
        return pre + ["disasm", lib] + _pos(args.disasm)
    if args.tier0:
        return pre + ["classes", lib] + (["-f", args.filter] if args.filter else [])
    if args.names:
        return pre + ["strings", lib] + (["-g", args.grep] if args.grep else [])
    return pre + ["info", lib] + (["--lenient"] if args.lenient else [])


# ----------------------------------------------------------------- entry point

def main(argv=None) -> int:
    # Recovered text is arbitrary bytes out of someone else's binary, and a console that
    # cannot represent them is the user's environment, not an error in the file. Without
    # this, `jadart strings` on a cp1252 console died with a UnicodeEncodeError traceback
    # partway through the output.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass                      # not a real stream (a StringIO in the tests), fine
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    if not argv:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    if _looks_legacy(argv):
        if "-h" in argv or "--help" in argv:
            parser.print_help()
            return EXIT_OK
        argv = _translate_legacy(argv)

    args = parser.parse_args(argv)
    console.configure(getattr(args, "color", "auto"))
    _JSON[0] = bool(getattr(args, "json", False))
    if _JSON[0]:
        console.configure("never")      # escape codes would corrupt the document

    # Accept a container for EVERY command, not just export. An APK or IPA is what a user
    # actually has, and making `info` reject one that `export` accepts is a papercut with
    # no reason behind it, the extraction is the same three lines either way.
    workdir = None
    if getattr(args, "libapp", None):
        import tempfile
        from .export import resolve_input, InputError
        try:
            workdir = tempfile.mkdtemp(prefix="jadart-")
            target = resolve_input(args.libapp, workdir)
        except InputError as e:
            shutil.rmtree(workdir, ignore_errors=True)
            return _fail(e)
        if target != args.libapp:
            print(comment(f"// {os.path.basename(target)} from "
                          f"{os.path.basename(args.libapp)}"), file=sys.stderr)
            # Keep the container itself. `export` unpacks the assets and the Android side
            # out of it, and once libapp is rewritten to the extracted path there is no
            # way back to the apk it came from.
            args.container = args.libapp
            args.libapp = target

    try:
        return args.func(args)
    except BrokenPipeError:
        # `jadart classes lib | head` closes the pipe on us. That's the reader's
        # choice, not a failure. Point stdout at devnull so the interpreter's exit
        # flush has somewhere to go, otherwise Python prints "Exception ignored".
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except KeyboardInterrupt:
        error("interrupted")
        return 130
    except Exception as e:
        from .disasm import UnsupportedArch, MissingDisassembler
        if isinstance(e, MissingDisassembler):
            return _fail(e)
        if isinstance(e, UnsupportedArch):
            # The snapshot parsed; only the machine-code layer is out of reach. Say which
            # commands still work rather than leaving the user to find out one at a time.
            if _JSON[0]:
                return _json_error(e, EXIT_MISS)
            error(e)
            print("  try: jadart classes / libraries / strings / info / verify",
                  file=sys.stderr)
            return EXIT_MISS
        if isinstance(e, JadartError):
            return _fail(e)
        # Anything left is a bug in jadart, and it gets its own exit code and its own
        # wording. Reporting it through _fail said "your file is bad" about a defect in
        # this program: pointing any command at libflutter.so printed
        # `jadart: '_kDartIsolateSnapshotData'` and exited 2, while the issue template
        # asked the reporter for a traceback the tool had just swallowed.
        if _JSON[0]:
            import json
            json.dump({"ok": False, "error": str(e), "type": type(e).__name__,
                       "internal": True, "exit": EXIT_INTERNAL},
                      sys.stdout, indent=2, default=str)
            sys.stdout.write("\n")
            return EXIT_INTERNAL
        if os.environ.get("JADART_DEBUG"):
            raise
        error(f"internal error: {type(e).__name__}: {e}")
        print("  This is a bug in jadart, not a problem with your file.\n"
              "  Re-run with JADART_DEBUG=1 for the traceback, and please report it:\n"
              "  https://github.com/IR0NBYTE/Jadart/issues", file=sys.stderr)
        return EXIT_INTERNAL
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
