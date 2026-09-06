"""jadart: a decompiler for Flutter/Dart AOT snapshots.

Parses a stripped `libapp.so` (or an iOS `App` dylib) and gives back the class tree,
method bodies as pseudo-Dart, the string pool, and the source names of virtual calls.

The command line is one caller of this and the library is the other; neither wraps the
other. Everything below takes a path to a snapshot, an APK, an IPA or a directory:

    import jadart

    prog = jadart.program("app.apk")            # class tree + strings + libraries
    for k in prog.user_classes():
        print(k.name, [m.name for m in k.members])

    hdr = jadart.header("app.apk")["isolate"]   # which Dart release, which target
    print(hdr.epoch.dart, hdr.arch)

    rep = jadart.verify("app.apk")              # the byte-exact acceptance gates
    print(rep.supported, [g.gate for g in rep.gates if not g.passed])

    jadart.export("app.apk", "out/")            # the whole browsable tree

Failure is loud and typed, never a guess. Everything raised for input this library cannot
handle derives from `JadartError`, so

    except jadart.JadartError:

skips a file that cannot be processed without listing class names or matching on messages
which is what a batch scan over a directory of APKs needs, and what it did not get while
a truncated snapshot escaped as `struct.error`. Catch a subclass to say why: `UnknownEpoch`
for a Dart release with no registered grammar, `UnsupportedTarget` for a known release on
an architecture or pointer model that has none, `InputError` for something that is not a
Flutter snapshot, `ContainerError` for a malformed ELF or Mach-O, `TruncatedSnapshot` for a
stream that ends mid-object, `AllocError` and `FillError` for a snapshot whose clusters do
not walk, `UnsupportedArch` where a tier does not model the target, and
`MissingDisassembler` when instruction-level work is asked for without capstone.

A bug in this library is deliberately NOT a `JadartError`, so it keeps its own type instead
of being swallowed by an `except` that meant to skip a bad file.

THREAD SAFETY: none. The lifter binds its architecture tables as module state, capstone
handles are shared, and the extraction cache is process-global. Use processes, not threads.

Three entry points share a name with the submodule behind them: `program`, `verify` and
`export`. The function wins, on purpose: `jadart.verify(path)` is the interface and the
submodule is an implementation detail. But that means `import jadart.verify` binds the
function, and `jadart.export.library_path` does not resolve. The from-import works, and so
does importlib, either of which is the supported way to reach an internal:

    from jadart.export import library_path
    importlib.import_module("jadart.export").library_path(url)

Reading instructions (`decompile`, `selectors`) needs the extra:
`pip install jadart[disasm]`. Everything else is stdlib only, on purpose, the part that
has to be correct is the part with nothing underneath it.
"""
from .errors import JadartError
from .snapshot import parse_libapp, parse_blob, SnapshotHeader, UnknownEpoch
from .versions import UnsupportedTarget
from .export import InputError
# The rest of the taxonomy, reachable by name. Five of these used to exist only inside the
# modules that raise them, so a caller following the docstring below could not name what it
# was catching and fell back to matching on messages.
from .container import ContainerError
from .stream import TruncatedSnapshot
from .clusters import AllocError
from .fillwalk import FillError

# Bound up here, under private names, and never imported again from inside a function.
# `program`, `verify` and `export` are the names of both a submodule and an entry point
# below, and importing a submodule rebinds it on the package, so a lazy
# `from .program import ...` inside program() would quietly replace this module's own
# function with the module, on the first call. None of these three pulls capstone.
from .program import recover_program as _recover_program
from .verify import verify_file as _verify_file
from .export import export as _export_tree
# Lives in export.py beside `resolve_input`, which it wraps. It used to be defined
# here and reached by `from . import _resolve` in signatures.py, a leaf importing a
# private out of the package root, which inverts the layering and drags APK
# extraction, an atexit hook and a process-lifetime cache into the analysis layer
# with nothing in that module saying so.
from .export import resolve_cached as _resolve

#: Covers the INTERFACE, the command set and their options, the exit codes, the shape of
#: `--json`, and the names in `__all__`. Everything under `jadart.*` is implementation.
#: A new format epoch is a minor release: it only ever adds binaries that parse.
#: ../../CHANGELOG.md is the record, and a test pins the two together.
__version__ = "1.1.0"

__all__ = [
    "header", "program", "verify", "export", "decompile", "strings", "selectors",
    "constants",
    "parse_libapp", "parse_blob", "SnapshotHeader",
    "JadartError", "UnknownEpoch", "UnsupportedTarget", "InputError", "ContainerError",
    "TruncatedSnapshot", "AllocError", "FillError", "UnsupportedArch",
    "MissingDisassembler",
    "__version__",
]


def header(path: str) -> dict:
    """{"vm": SnapshotHeader, "isolate": SnapshotHeader}: release, target, counts."""
    return parse_libapp(_resolve(path))


def program(path: str):
    """The recovered object graph: classes, members, libraries, strings."""
    return _recover_program(_resolve(path))


def verify(path: str):
    """Run the byte-exact acceptance gates. `.supported` is the headline."""
    return _verify_file(_resolve(path))


def export(path: str, outdir: str, **kw):
    """Write the whole browsable source tree. Returns a stats dict."""
    return _export_tree(_resolve(path), outdir, **kw)


def strings(path: str) -> list:
    """Every recovered string, sorted. Run them through `jadart.fill.printable` before
    printing: Dart literals contain newlines and NULs, and raw output stops being
    line-oriented."""
    from .disasm import load_instructions
    _image, fr, _hdr = load_instructions(_resolve(path))
    return sorted(set(fr.strings.values()))


def selectors(path: str) -> dict:
    """call-site immediate -> selector name, from the serialized dispatch table."""
    from .disasm import load_instructions
    from .dispatch import recover_selectors
    image, fr, hdr = load_instructions(_resolve(path))
    return recover_selectors(image, fr, hdr)


def constants(path: str) -> dict:
    """pool byte offset -> the const list at it, elements resolved to ints and strings.

    A decompiled body names a long table rather than spelling it out, because inlining a
    keystream at every use site buries the loop that reads it. This is where the elements
    come back, keyed the same way the body labels them: `const[47] @0xb9b0` in a lifted
    line is `0xb9b0` here."""
    from .disasm import load_instructions, const_lists
    image, fr, _hdr = load_instructions(_resolve(path))
    return const_lists(fr, getattr(image, "arch", None))


def decompile(path: str, symbol: str) -> list:
    """Lifted pseudo-Dart for every function matching `symbol`.

    `symbol` is an exact name, a bare private stem (`_onPressed` finds
    `_onPressed@19445826`, whose suffix nobody can guess), or an address (`0xfea30`),
    AOT emits closures anonymously and they are regularly the interesting function.

    Returns [{"name", "pc_offset", "size", "body": [str, ...]}, ...]."""
    from .disasm import (load_instructions, named_ranges, disassemble_range, annotate,
                         function_name_by_pc, build_pool_map)
    from .expr import lift_function, make_arity_resolver
    from .dispatch import recover_selectors
    from .fields import recover_fields

    from .program import static_function_refs, receiver_for

    image, fr, hdr = load_instructions(_resolve(path))
    static_refs = static_function_refs(fr)
    ranges = named_ranges(image, fr, symbol)
    if not ranges:
        return []
    pc_to_name = function_name_by_pc(image, fr)
    pool_map = build_pool_map(fr, getattr(image, "arch", None))
    arity = make_arity_resolver(image)
    sels = recover_selectors(image, fr, hdr)
    layout = recover_fields(fr, getattr(image, "arch", None))
    out = []
    for nm, cr in ranges:
        dis = disassemble_range(image, cr)
        if not dis:
            continue
        body = lift_function(annotate(dis, pc_to_name, pool_map), pool_map,
                             # NOT {"x1": "this"}. x1 holds the receiver in an INSTANCE
                             # method and something else entirely in a static one, so
                             # hardcoding it renames a live value after the fact, a
                             # guess printed as a fact, which is the one thing this tool
                             # does not do. `receiver_for` is what the CLI, `export` and
                             # `program` all use; this was the only caller that did not,
                             # and it differed from them on 403 functions and 1,534 lines
                             # of the corpus binary.
                             receiver=receiver_for(cr.owner_ref, static_refs),
                             arity=arity, selectors=sels,
                             arch=getattr(image, "arch", None),
                             fields=layout.for_function(cr.owner_ref))
        out.append({"name": nm, "pc_offset": cr.pc_offset, "size": cr.size,
                    "body": [ln.strip() for ln in body]})
    return out


def __getattr__(name):
    # Resolved on use rather than at import, so `import jadart` stays stdlib-only and a
    # bare install does not trip over a missing capstone just to name an exception.
    if name in ("MissingDisassembler", "UnsupportedArch"):
        from . import disasm
        return getattr(disasm, name)
    raise AttributeError(name)
