"""Naming library code whose names were stripped, by matching its shape against
reference builds where the names survived.

WHY THIS EXISTS. jadart recovers ~73% of function names on an ordinary Flutter build,
straight out of the snapshot. On a `--obfuscate` build that collapses to ~2%: Dart's
obfuscator renames dart:core and the Flutter framework too, so `toRadixString` and
`padLeft` are not merely hidden, they are absent from the binary. Nothing in the file
can be parsed into them.

But the *code* of those functions is still there, and it is the same code every app of
that Dart release ships. So the names can come from somewhere else: a reference build
where they survive. That is what this module does.

THE IDEA IS GHIDRA'S Function ID, not the implementation. Ghidra hashes each function
twice, once with operands masked (robust to relinking) and once with constants kept (tells
near-identical variants apart), and disambiguates what is left using the call graph: two
functions with identical bodies that call different subfunctions are told apart by their
callees. Entries known to be undiscriminating are marked Auto Fail and never matched.
Every one of those ideas is used below. See DESIGN.md for what we do differently.

WHAT WE DO DIFFERENTLY, because the target is Dart AOT rather than native object code:

  * Ghidra masks constant operands because it cannot say what they mean. We can. An arm64
    Dart function reaches its constants through the object pool (`ldr xN, [x27, #off]`),
    and jadart already resolves that offset to the string or function it names. So where
    Ghidra keeps a raw immediate, we key on the *resolved referent*: `[PP:"time of
    request: "]`. String literals survive obfuscation untouched, which makes them the
    single strongest signal available on exactly the builds that need it most.

  * The pool also tells us an entry's KIND (a tagged ref, a raw immediate, a native
    function, or empty). That is stable across builds of the same source and costs
    nothing to include.

  * Ghidra's parent/child relation walks call edges. Ours does too, but a Dart AOT call is
    often an indirect jump through a pool entry rather than a `bl`, so the direct-call
    graph is thinner than in native code. We use it where it exists and lean on the pool
    referents where it does not.

WHAT THIS WILL NEVER DO. It names library code, not the program. An app's own functions
appear in no reference build, so they stay anonymous, exactly as FLIRT names libc and not
your `main`. That is the useful half of the split: after a match pass, what is still
unnamed is the part somebody wrote.

HONESTY. A matched name is an inference from a different binary, not a fact read out of
this one. Every caller must keep the two apart; `Match.level` says how it was reached and
renderers mark matched names so a reader can see which is which.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re

from .disasm import (MAX_INSNS, MissingDisassembler, UnsupportedArch, build_pool_map,
                     disassemble_range, function_name_by_pc, pool_byte_offset,
                     _add_imm_from_pp, _imm_from, _mem_base_disp)

# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

_IMM = re.compile(r"#-?(?:0x[0-9a-f]+|\d+)")

# A call or a branch scores nothing towards a function being distinctive: a body made of
# calls looks like every other body made of calls. Ghidra excludes calls and no-ops from
# its instruction-count threshold for the same reason.
_UNSCORED = frozenset(("bl", "blr", "b", "br", "ret", "nop", "b.eq", "b.ne", "b.lt",
                       "b.le", "b.gt", "b.ge", "b.hi", "b.hs", "b.lo", "b.ls", "b.mi",
                       "b.pl", "b.vs", "b.vc", "b.al"))

# A function that only sets up an arguments descriptor and jumps through a native pool
# entry carries no shape of its own: dart:core generates the same wrapper for many
# different natives, and the pool entry that would tell them apart holds a null that the
# runtime patches on load. Recognising the shape is cheaper and more honest than
# discovering the collision later, so these never enter a library (Ghidra's Auto Fail).
_NATIVE_KINDS = frozenset(("native", "empty"))

# How far into a function to look. Long enough to be distinctive, short enough that a
# tail difference (an inlined callee that only one build chose to inline) does not throw
# the whole match away.
WINDOW = 24

# Minimum scored instructions for a function to be worth signing at all.
MIN_SCORE = 10


def _pool_kinds(fr) -> dict:
    """ObjectPool byte offset -> a stable description of what the entry holds.

    build_pool_map only labels strings and function names, because that is all a human
    reader wants in a listing. For matching we also want the entries it leaves out: an
    immediate's value and an entry's kind are both stable across builds of the same
    source, and they are all that separates some functions.
    """
    out = {}
    for idx, (kind, val) in enumerate(fr.pool):
        off = pool_byte_offset(idx)
        out[off] = f"imm:{val}" if kind == "imm" else kind
    return out


def normalise(dis, pool_map: dict, pool_kinds: dict, window: int = WINDOW):
    """Turn a disassembled range into (body, pooled, score, calls, is_native_thunk).

    `body`   masks every operand that legitimately moves between two builds of the same
             source: pc-relative branch displacements, and pool offsets (the pool is laid
             out differently in every build).
    `pooled` is `body` with each pool reference replaced by what it actually points at,
             which is the discriminating detail `body` throws away.
    """
    body, pooled, score, calls = [], [], 0, []
    far_base = {}
    native_thunk = False

    for _addr, mn, op in dis[:window]:
        masked = _IMM.sub("#I", op)
        ref = None

        if mn in ("ldr", "ldur"):
            off = None
            if "x27" in op:
                off = _imm_from(op, "x27")
            else:
                md = _mem_base_disp(op)
                if md and md[0] in far_base:
                    off = far_base[md[0]] + md[1]
            if off is not None:
                ref = pool_map.get(off) or pool_kinds.get(off)
                if pool_kinds.get(off) in _NATIVE_KINDS:
                    native_thunk = True

        # Track the far-load base registers exactly as annotate() does, and drop one the
        # moment anything overwrites it, an untracked clobber turns a later load into a
        # reference to a pool entry that was never read.
        fb = _add_imm_from_pp(op) if mn == "add" else None
        if fb is not None:
            far_base[fb[0]] = fb[1]
        elif far_base:
            far_base.pop(op.split(",", 1)[0].strip(), None)

        body.append(f"{mn} {masked}")
        pooled.append(f"{mn} {masked}" + (f" |{ref}" if ref else ""))
        if mn not in _UNSCORED:
            score += 1
        if mn == "bl" and op.startswith("#"):
            try:
                calls.append(int(op[1:], 16))
            except ValueError:
                pass

    return tuple(body), tuple(pooled), score, calls, native_thunk


def _h(parts) -> int:
    """FNV-1a over the joined parts.

    Deliberately NOT Python's hash(): that is salted per process for strings, so a library
    written today would miss every entry when read back tomorrow, and the file format
    would be silently worthless. Signature files have to mean the same thing in every run
    on every machine, so the hash is spelled out here.
    """
    h = 0xCBF29CE484222325
    for b in "\n".join(str(p) for p in parts).encode("utf-8", "surrogatepass"):
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Sig:
    body: int          # shape alone, operands masked
    pooled: int        # shape plus what its pool references point at
    ctx: int           # pooled plus the shapes of the functions it calls
    score: int


def signatures(image, fr, window: int = WINDOW, min_score: int = MIN_SCORE) -> dict:
    """pc_offset -> Sig for every range in the image worth signing.

    Two passes, because a context hash needs its callees' body hashes: the first pass
    signs every range on its own, the second folds in the callees. One level deep only.
    Deeper is possible and buys little: by the second level the shapes being folded in
    are mostly the same runtime stubs for every function in the binary.
    """
    pool_map = build_pool_map(fr, getattr(image, "arch", None))
    kinds = _pool_kinds(fr)

    first, edges = {}, {}
    for cr in image.all_ranges:
        try:
            dis = disassemble_range(image, cr, max_insns=window)
        except (MissingDisassembler, UnsupportedArch):
            # Same reason as callgraph.build_index: caught per range this returns an
            # empty signature set, so `--sigs` on arm32 would quietly match nothing and
            # look like a library with no entries for this binary.
            raise
        except Exception:
            continue
        if len(dis) < 4:
            continue
        body, pooled, score, calls, thunk = normalise(dis, pool_map, kinds, window)
        if score < min_score or thunk:
            continue
        first[cr.pc_offset] = (_h(body), _h(pooled), score)
        edges[cr.pc_offset] = calls

    out = {}
    for pc, (b, p, score) in first.items():
        kids = sorted(first[t][0] for t in edges.get(pc, ()) if t in first)
        out[pc] = Sig(body=b, pooled=p, ctx=_h((p,) + tuple(kids)), score=score)
    return out


# ---------------------------------------------------------------------------
# The library
# ---------------------------------------------------------------------------

_AT = re.compile(r"@\d+")     # per-build private-library id, not part of the source name

#: Compiler-generated forwarders, excluded from every library. `dyn:+`, `dyn:-` and
#: `dyn:*` are the dynamic-invocation forwarders for those operators; they are emitted
#: from one template and differ only in an operand this normalisation masks, so within a
#: single reference build four of thirty of their shape groups already carry more than one
#: name. Nothing is lost by dropping them: the name only says "dynamic call forwarder",
#: which the call site already shows. Ghidra reaches for Auto Fail on the same grounds.
_GENERATED = ("dyn:",)


def is_signable(name: str) -> bool:
    return not name.startswith(_GENERATED)


def base_name(n: str) -> str:
    """`_debugPrintTask@126110992` and `_debugPrintTask@114110992` are the same function.
    The trailing number is a per-build id for the private library that owns it, so it
    differs between two builds of identical source and must not count as a disagreement."""
    return _AT.sub("", n)


@dataclass
class Library:
    """Signatures from one or more reference builds, indexed for lookup.

    A hash that two reference builds disagree about is dropped rather than guessed at.
    That is the whole reason to ingest more than one reference: with a single build,
    a shape shared by two functions is invisible, because only one of them survived
    tree-shaking to claim it.
    """
    by_ctx: dict = field(default_factory=dict)
    by_pooled: dict = field(default_factory=dict)
    by_body: dict = field(default_factory=dict)
    sources: list = field(default_factory=list)
    dropped: int = 0

    def __len__(self):
        return len(self.by_body)


def _index(pairs) -> tuple:
    """Collapse (hash -> names seen) to (hash -> the one name), dropping every hash that
    more than one name claims."""
    seen = {}
    for h, name in pairs:
        seen.setdefault(h, set()).add(name)
    keep = {h: next(iter(v)) for h, v in seen.items() if len(v) == 1}
    return keep, sum(1 for v in seen.values() if len(v) > 1)


def build(paths, window: int = WINDOW, min_score: int = MIN_SCORE,
          progress=None) -> Library:
    """Build a signature library from reference binaries whose names survive."""
    from .disasm import load_instructions
    from .export import resolve_cached as _resolve

    ctx_p, pool_p, body_p, sources = [], [], [], []
    for path in paths:
        if progress:
            progress(path)
        image, fr, hdr = load_instructions(_resolve(path))
        names = function_name_by_pc(image, fr)
        sigs = signatures(image, fr, window, min_score)
        n = 0
        for cr in image.all_ranges:
            nm = names.get(cr.pc_offset)
            sig = sigs.get(cr.pc_offset)
            if not nm or sig is None or not is_signable(nm):
                continue
            b = base_name(nm)
            ctx_p.append((sig.ctx, b))
            pool_p.append((sig.pooled, b))
            body_p.append((sig.body, b))
            n += 1
        sources.append((path, hdr.epoch.dart if hdr.epoch else "?", n))

    by_ctx, d1 = _index(ctx_p)
    by_pooled, d2 = _index(pool_p)
    by_body, d3 = _index(body_p)
    return Library(by_ctx=by_ctx, by_pooled=by_pooled, by_body=by_body,
                   sources=sources, dropped=d1 + d2 + d3)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Match:
    name: str
    level: str      # "context" | "pool" | "shape", strongest first
    score: int


#: How a match was reached, strongest first. `context` agreed on the shape, on everything
#: its pool entries point at, AND on the shapes of the functions it calls; `shape` agreed
#: on the masked instruction sequence alone.
LEVELS = ("context", "pool", "shape")


def match(image, fr, lib: Library, window: int = WINDOW,
          min_score: int = MIN_SCORE, min_level: str = "shape") -> dict:
    """pc_offset -> Match for every range this library can name."""
    cutoff = LEVELS.index(min_level)
    out = {}
    for pc, sig in signatures(image, fr, window, min_score).items():
        for i, (level, table, key) in enumerate((
                ("context", lib.by_ctx, sig.ctx),
                ("pool", lib.by_pooled, sig.pooled),
                ("shape", lib.by_body, sig.body))):
            if i > cutoff:
                break
            nm = table.get(key)
            if nm:
                out[pc] = Match(name=nm, level=level, score=sig.score)
                break
    return out


# ---------------------------------------------------------------------------
# Folding matches into the names a binary carries itself
# ---------------------------------------------------------------------------

#: Marks a name this binary does not contain. Everything without it was read out of the
#: snapshot or the ELF symbol table and is a fact; everything with it was inferred from a
#: different binary that happened to have the same code, and is right around 99% of the
#: time rather than always. A reader who cannot tell those apart has been misled, so the
#: mark is not optional and renderers must not strip it.
MARK = "~"


def merge(pc_to_name: dict, matches: dict) -> tuple:
    """Fold matched names into recovered ones. Returns (merged, added).

    A name the binary carries always wins over a matched one, even when they disagree:
    the binary is evidence and the library is inference.
    """
    merged = dict(pc_to_name)
    added = 0
    for pc, m in matches.items():
        if pc in merged:
            continue
        merged[pc] = m.name + MARK
        added += 1
    return merged, added


def names_with_signatures(image, fr, sigs_path: str | None) -> tuple:
    """The pc -> name map every renderer uses, with a signature library folded in when
    one was asked for. Returns (pc_to_name, note) where note is a one-line summary for
    the output header, or None when no library was used."""
    pc_to_name = function_name_by_pc(image, fr)
    if not sigs_path:
        return pc_to_name, None
    lib = load(sigs_path)
    merged, added = merge(pc_to_name, match(image, fr, lib))
    refs = ", ".join(sorted({d for _s, d, _n in lib.sources})) or "?"
    note = (f"{added} names matched against {len(lib)} reference shapes (dart {refs}); "
            f"they end in {MARK} and are inferred, not read from this binary")
    return merged, note


# ---------------------------------------------------------------------------
# On-disk form
# ---------------------------------------------------------------------------

FORMAT = "jadart-signatures-1"


def save(lib: Library, path: str) -> None:
    with open(path, "w") as f:
        f.write(f"# {FORMAT}\n")
        for src, dart, n in lib.sources:
            f.write(f"# from\t{dart}\t{n}\t{src}\n")
        for tag, table in (("c", lib.by_ctx), ("p", lib.by_pooled), ("b", lib.by_body)):
            for h, nm in sorted(table.items()):
                f.write(f"{tag}\t{h:016x}\t{nm}\n")


def load(path: str) -> Library:
    lib = Library()
    tables = {"c": lib.by_ctx, "p": lib.by_pooled, "b": lib.by_body}
    with open(path) as f:
        head = f.readline().strip()
        if head != f"# {FORMAT}":
            raise ValueError(f"{path}: not a jadart signature file (got {head!r})")
        for line in f:
            if line.startswith("# from\t"):
                _, dart, n, src = line.rstrip("\n").split("\t", 3)
                lib.sources.append((src, dart, int(n)))
                continue
            if line.startswith("#") or not line.strip():
                continue
            tag, h, nm = line.rstrip("\n").split("\t", 2)
            tables[tag][int(h, 16)] = nm
    return lib
