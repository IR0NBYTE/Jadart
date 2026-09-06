#!/usr/bin/env python3
"""Score the lifter against the corpus app's own source, across every epoch.

The snapshot layer proves itself byte-exactly: a wrong cluster grammar desyncs the stream
and the acceptance gates catch it. The machine-code layer has no such property. A wrong
idiom rule does not desync anything, it just prints a plausible expression that happens to
be wrong, so Tiers 1-3 have been trusted rather than checked.

The corpus app is the missing oracle. We wrote it, so we know what each construct does, and
it is compiled by every SDK in the corpus. Asserting source-derived facts about the lifted
output turns "looks reasonable" into "still true on thirteen releases".

What this is not: a decompiler-equivalence check. AOT is free to compile the same Dart very
differently across releases, 2.19 lowers `for (final b in data)` to an iterator loop with
a virtual dispatch, while 3.6 onward specialises it to an indexed loop, so an expectation
that holds everywhere would have to be so weak it proves nothing. Instead each expectation
declares where it must hold, and everything else is reported as a score rather than
enforced, so real codegen differences read as data instead of as failures.

    python3 tools/semdiff.py                 # score every corpus binary
    python3 tools/semdiff.py --hard          # only the must-hold checks, exit 1 on failure
"""
from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FRAMEWORK = os.path.dirname(HERE)
CORPUS = os.path.join(os.path.dirname(FRAMEWORK), "flubench", "corpus")
sys.path.insert(0, FRAMEWORK)


class Check:
    """One source-derived fact about a lifted function.

    `hard` marks a check that must hold on every epoch that has the function at all. Those
    are the ones tied to arithmetic the compiler cannot restructure: a constant that has to
    appear, a comparison that has to happen before a subtraction. Everything else is scored.
    """

    def __init__(self, func, pattern, why, hard=False, source=""):
        self.func = func
        self.pattern = re.compile(pattern)
        self.why = why
        self.hard = hard
        self.source = source

    def __str__(self):
        return f"{self.func}: {self.why}"


# Derived from flubench/app/lib/constructs.dart. Each entry cites the line it comes from,
# so a failure can be read against the source without going hunting.
CHECKS = [
    Check("benchDecodeFlag", r"\^ 66\b",
          "xor with 0x42 appears", hard=True,
          source="out.add(bytes[i] ^ 0x42)"),
    Check("benchWithdraw", r"return false;",
          "the over-balance branch returns false", hard=True,
          source="if (amount > balance) return false;"),
    Check("benchWithdraw", r"-=",
          "the balance is decremented in place", hard=True,
          source="balance -= amount;"),
    Check("benchWithdraw", r"return true;",
          "the success path returns true", hard=True,
          source="return true;"),
    Check("benchComputeChecksum", r"& 0xffffffff",
          "the 32-bit mask survives", hard=True,
          source="acc = (acc * 31 + b) & 0xffffffff"),
    # Scored, not enforced: whether 31 shows as a literal depends on whether the backend
    # kept it in a register for that release.
    Check("benchComputeChecksum", r"\* 31\b",
          "the multiplier is recovered as a constant",
          source="acc * 31"),
    Check("benchComputeChecksum", r"\bwhile \(true\)|\bfor\b",
          "the accumulation loop is structured",
          source="for (final b in data)"),
    Check("benchDecodeFlag", r"\bdecode\b",
          "the base64 decode call is named",
          source="base64.decode(encoded)"),
    # Held on no epoch until stack-passed arguments were reconstructed; holds on all of
    # them now, so it is enforced. The comparison lowers to a virtual dispatch whose
    # arguments are pushed, and a literal cannot be restructured out of one.
    Check("benchCheckSecret", r"FLUBENCH\{str_literal_compare\}",
          "the compared literal reaches the call site", hard=True,
          source="input == 'FLUBENCH{str_literal_compare}'"),
]


def lift_named(path, symbol):
    """Lifted lines for every function with this name, or None when it is absent."""
    from jadart.disasm import (load_instructions, named_ranges, disassemble_range, annotate,
                               function_name_by_pc, build_pool_map)
    from jadart.expr import lift_function, make_arity_resolver
    from jadart.dispatch import recover_selectors
    from jadart.fields import recover_fields

    image, fr, hdr = load_instructions(path)
    ranges = named_ranges(image, fr, symbol)
    if not ranges:
        return None
    pc_to_name = function_name_by_pc(image, fr)
    pool_map = build_pool_map(fr, getattr(image, "arch", None))
    arity = make_arity_resolver(image)
    selectors = recover_selectors(image, fr, hdr)
    layout = recover_fields(fr, getattr(image, "arch", None))
    out = []
    for _nm, cr in ranges:
        dis = disassemble_range(image, cr)
        if not dis:
            continue
        out.extend(lift_function(annotate(dis, pc_to_name, pool_map), pool_map,
                                 receiver={"x1": "this"}, arity=arity, selectors=selectors,
                                 arch=getattr(image, "arch", None),
                                 fields=layout.for_function(cr.owner_ref)))
    return out


def binaries():
    if not os.path.isdir(CORPUS):
        return []
    def key(d):
        return [int(p) for p in d.split(".") if p.isdigit()]
    out = []
    for d in sorted(os.listdir(CORPUS), key=key):
        p = os.path.join(CORPUS, d, "libapp.so")
        if os.path.exists(p):
            out.append((d, p))
    return out


def run(hard_only=False):
    bins = binaries()
    if not bins:
        print(f"no corpus binaries under {CORPUS}; build them with tools/build_corpus.py")
        return 0

    checks = [c for c in CHECKS if c.hard or not hard_only]
    funcs = sorted({c.func for c in checks})
    failures, rows = [], []

    from jadart.disasm import UnsupportedArch
    skipped = []
    for dart, path in bins:
        lifted, absent, arch_skip = {}, [], False
        for f in funcs:
            try:
                body = lift_named(path, f)
            except UnsupportedArch:
                # arm32 parses and now DECODES, but these checks read Tier 3 expressions
                # and Tier 3 models arm64's register roles only, so there is nothing here
                # to score. That is a scope limit, not a failure.
                arch_skip = True
                break
            except Exception as exc:                       # a parse failure is not a
                print(f"dart {dart}: {type(exc).__name__}: {exc}")   # lifter result
                return 1
            if body is None:
                absent.append(f)
            lifted[f] = "\n".join(body or [])
        if arch_skip:
            skipped.append(dart)
            continue

        got = []
        for c in checks:
            if c.func in absent:
                got.append(None)                            # not present to check
                continue
            ok = bool(c.pattern.search(lifted[c.func]))
            got.append(ok)
            if c.hard and not ok:
                failures.append((dart, c))
        rows.append((dart, got, absent))

    if not rows:
        print("no binaries with decodable instructions")
        return 0
    width = max(len(d) for d, _, _ in rows) + 1
    print(f"{'dart':<{width}}" + "".join(f"{i:>4}" for i in range(len(checks)))
          + "   score")
    for dart, got, absent in rows:
        marks = "".join("   ." if g is None else ("   +" if g else "   X") for g in got)
        have = [g for g in got if g is not None]
        score = f"{sum(1 for g in have if g)}/{len(have)}"
        note = f"   (absent: {', '.join(absent)})" if absent else ""
        print(f"{dart:<{width}}{marks}   {score}{note}")

    print("\nchecks:")
    for i, c in enumerate(checks):
        print(f"  {i:>2}  {'HARD' if c.hard else '    '}  {c.func}: {c.why}")
        if c.source:
            print(f"        source: {c.source}")
    print("\n  + holds   X does not   . function not in this binary")

    if skipped:
        print(f"\nskipped (Tier 3 does not model this target's register roles; "
              f"Tier 1 and 2 do decode it): {', '.join(skipped)}")
    if failures:
        print(f"\n{len(failures)} HARD check(s) failed:")
        for dart, c in failures:
            print(f"  dart {dart}: {c}")
            print(f"    source: {c.source}")
        return 1
    print("\nall hard checks hold")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--hard", action="store_true",
                    help="only run the must-hold checks")
    args = ap.parse_args(argv)
    return run(hard_only=args.hard)


if __name__ == "__main__":
    raise SystemExit(main())
