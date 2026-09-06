#!/usr/bin/env python3
"""Regenerate EVAL.md's measured tables from the corpus that is actually on disk.

EVAL.md is the measurements document, and it went stale the ordinary way: every number in
it was typed by hand, so each one was true when written and silently wrong a fortnight
later. It claimed eight gates on five binaries long after there were nine on thirty-five.

So the numbers are generated. Run this and paste, or diff it against the file to see what
has drifted:

    python3 tools/measure.py                # markdown for the measured sections
    python3 tools/measure.py --check        # exit 1 if EVAL.md disagrees with reality

Nothing here is a claim in its own right; it reads the epoch registry and runs the same
`jadart verify` a user would.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FRAMEWORK = os.path.dirname(HERE)
ROOT = os.path.dirname(FRAMEWORK)
sys.path.insert(0, FRAMEWORK)


def binaries():
    """Every snapshot this checkout can verify, labelled by where it came from."""
    out = []
    corpus = os.path.join(ROOT, "flubench", "corpus")
    if os.path.isdir(corpus):
        for d in sorted(os.listdir(corpus)):
            p = os.path.join(corpus, d, "libapp.so")
            if os.path.exists(p):
                out.append((("arm32 " if d.startswith("arm32") else "corpus ") + d, p))
    for label, rel in (("flubench clean", "flubench/artifacts/clean/lib/arm64-v8a/libapp.so"),
                       ("flubench --obfuscate", "flubench/artifacts/obf/lib/arm64-v8a/libapp.so")):
        p = os.path.join(ROOT, rel)
        if os.path.exists(p):
            out.append((label, p))
    # Optional extra binaries, from an env var rather than one person's home directory.
    # These paths were hardcoded to `~/My_MVPs/jadart_e2e/...`, which published a private
    # directory layout in a public repo and silently found nothing for everyone else.
    #   JADART_EXTRA_BINARIES=/path/to/re   (expects re/<name>/lib/arm64-v8a/libapp.so)
    root = os.environ.get("JADART_EXTRA_BINARIES", "")
    extra = ((("e2e counter", f"{root}/counter_lifecycle/lib/arm64-v8a/libapp.so"),
              ("e2e vault", f"{root}/vault_logic/lib/arm64-v8a/libapp.so"),
              ("e2e shapes", f"{root}/shapes_oop/lib/arm64-v8a/libapp.so"),
              ("iOS Mach-O", f"{root}/ios/vault_ios.dylib")) if root else ())
    for label, p in extra:
        p = os.path.expanduser(p)
        if os.path.exists(p):
            out.append((label, p))
    return out


def epoch_table() -> str:
    from jadart import versions
    rows = ["| Dart | snapshot hash | epoch | targets |",
            "|------|---------------|-------|---------|"]
    for h, ep in sorted(versions._EPOCHS.items(),
                        key=lambda kv: [int(p) for p in kv[1].dart.split(".") if p.isdigit()]):
        targets = ", ".join(f"{w * 8}-bit {'compressed' if c else 'uncompressed'}"
                            for w, c in sorted(ep.grammars)) or "identified only"
        rows.append(f"| {ep.dart} | `{h}` | {ep.name} | {targets} |")
    return "\n".join(rows)


def gate_table() -> str:
    """The gates as they run on one real binary, with their live check counts."""
    from jadart.verify import verify_file
    clean = os.path.join(ROOT, "flubench/artifacts/clean/lib/arm64-v8a/libapp.so")
    if not os.path.exists(clean):
        return "_(no fixture available)_"
    rep = verify_file(clean)
    rows = ["| gate | tier | checks on the clean corpus | what it pins |",
            "|------|------|---------------------------|--------------|"]
    for g in rep.gates:
        note = g.detail or g.skipped or ""
        rows.append(f"| {g.gate} | {g.tier} | {g.checks if not g.skipped else '-'} | {note} |")
    return "\n".join(rows)


def results():
    """Run the gates over everything and return (rows, npass, ntotal)."""
    from jadart.verify import verify_file
    rows, npass = [], 0
    for label, path in binaries():
        try:
            rep = verify_file(path)
        except Exception as exc:
            rows.append((label, f"ERROR: {type(exc).__name__}", False))
            continue
        a = [g for g in rep.gates if g.tier == "A"]
        run = [g for g in a if not g.skipped]
        ok = all(g.passed for g in run) and rep.supported
        npass += ok
        skipped = ",".join(g.gate.split()[0] for g in a if g.skipped) or "-"
        rows.append((label, f"{sum(1 for g in run if g.passed)}/{len(run)} tier A"
                            f" (skipped: {skipped})", ok))
    return rows, npass, len(rows)


def check_doc_test_counts() -> list:
    """Docs that state a test count, against the number of tests that exist.

    EVAL.md stayed accurate because this script checks it; the README badge drifted to 79
    and CONTRIBUTING to 59 because nothing did. Hand-maintained numbers are wrong the
    moment someone adds a test, and the reader has no way to tell.

    Only the docs meant to describe the CURRENT state are checked. FINDINGS.md is a dated
    phase log, where "10 tests pass" is a record of that milestone and correct as written.
    """
    tests = os.path.join(FRAMEWORK, "tests", "test_core.py")
    if not os.path.exists(tests):
        return []
    with open(tests) as f:
        actual = len(re.findall(r"^def (test_\w+)", f.read(), re.M))
    pats = (r"tests-(\d+)%20passing",
            r"tests-(\d+)-brightgreen",
            r"test_core\.py\s*#\s*(\d+)\s+passing",
            r"test_core\.py\s+#\s+(\d+)\s+tests")
    bad = []
    for rel in ("README.md", "CONTRIBUTING.md", os.path.join("framework", "README.md")):
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            continue
        with open(path) as f:
            text = f.read()
        for pat in pats:
            for m in re.finditer(pat, text):
                if int(m.group(1)) != actual:
                    bad.append(f"{rel}: claims {m.group(1)} tests, {actual} exist")
    return bad


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if EVAL.md's headline numbers disagree with reality")
    args = ap.parse_args(argv)

    rows, npass, ntotal = results()

    if args.check:
        # Two separate questions, and conflating them makes this useless in CI. First: does
        # everything present actually pass? That is checkable anywhere. Second: does
        # EVAL.md's headline match? That is only checkable where the whole corpus exists,
        # and most of it is gitignored because it is regenerable.
        failed = [label for label, _detail, ok in rows if not ok]
        if failed:
            print(f"{len(failed)} of {ntotal} binaries fail their gates: "
                  f"{', '.join(failed[:5])}")
            return 1

        # Checkable on any checkout: it needs the test file, not the corpus.
        stale = check_doc_test_counts()
        if stale:
            for s in stale:
                print(s)
            return 1

        path = os.path.join(ROOT, "EVAL.md")
        text = ""
        if os.path.exists(path):
            with open(path) as f:
                text = f.read()
        claimed = re.search(r"all (\d+) binaries in this checkout", text)
        if not claimed:
            print("EVAL.md states no binary count to check against.")
            return 1
        claimed = int(claimed.group(1))
        if ntotal < claimed:
            print(f"partial checkout: {ntotal} of {claimed} binaries present, all pass. "
                  f"Build the rest with tools/build_corpus.py to check the headline.")
            return 0
        if ntotal != claimed:
            print(f"EVAL.md claims {claimed} binaries; {ntotal} are present and passing. "
                  f"Run tools/measure.py and update the measured sections.")
            return 1
        print(f"EVAL.md agrees: {ntotal} binaries, all passing.")
        return 0

    from jadart import versions
    print(f"## Supported epochs ({len(versions._EPOCHS)})\n")
    print(epoch_table())
    print(f"\n## The gates\n")
    print(gate_table())
    print("\nG4 and G4b are a complementary pair: exactly one runs per target, because a")
    print("compressed build keeps its strings in the stream and an uncompressed one keeps")
    print("them in the RO data image. Whichever applies, the alloc->fill boundary is pinned.")
    print(f"\n## Results: {npass} of {ntotal} binaries pass every applicable Tier-A gate\n")
    print("| binary | result |")
    print("|--------|--------|")
    for label, detail, ok in rows:
        print(f"| {label} | {'PASS' if ok else 'FAIL'} - {detail} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
