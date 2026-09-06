#!/usr/bin/env python3
"""Score a tool's recovery of a libapp.so against FluBench ground truth.

Currently supports the `unflutter` backend (its output dir). Scoring is recall:
of the ground-truth class/function/string symbols, how many appear anywhere in
the tool's recovered output. This is intentionally generous (substring match)
so a tool is never under-credited for a naming-format difference; false-positive
analysis is a separate axis.

Usage:
  score.py --truth ground_truth.json --unflutter-out path/to/libapp.unflutter --label clean
"""
import argparse
import json
import os
import sys


def load_unflutter_corpus(out_dir):
    """Concatenate the text unflutter emits that could carry recovered names."""
    blobs = []
    for name in ("flutter_meta.json", "functions.jsonl", "classes.jsonl",
                 "string_refs.jsonl", "index.jsonl"):
        p = os.path.join(out_dir, name)
        if os.path.exists(p):
            blobs.append(open(p, encoding="utf-8", errors="replace").read())
    # asm filenames encode recovered function names too
    asm = os.path.join(out_dir, "asm")
    if os.path.isdir(asm):
        for root, _dirs, files in os.walk(asm):
            blobs.append(os.path.basename(root))
            blobs.append("\n".join(files))
    return "\n".join(blobs)


def load_jadart_corpus(lib_path):
    """Run jadart's version-robust alloc walk + string recovery on a libapp.so and
    return its recovered identifier pool as a corpus. Fail-loud: an unknown epoch or
    an alloc desync raises rather than silently returning a partial corpus."""
    fw = os.path.join(os.path.dirname(__file__), "..", "framework")
    sys.path.insert(0, os.path.abspath(fw))
    from jadart.snapshot import walk_isolate
    result = walk_isolate(lib_path)
    return "\n".join(result["strings"])


def recall(items, corpus):
    hit = [x for x in items if x in corpus]
    miss = [x for x in items if x not in corpus]
    pct = (100.0 * len(hit) / len(items)) if items else 0.0
    return {"total": len(items), "recovered": len(hit),
            "recall_pct": round(pct, 1), "missed": miss}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--truth", required=True)
    ap.add_argument("--unflutter-out", help="unflutter output dir (unflutter backend)")
    ap.add_argument("--jadart-lib", help="libapp.so to run the jadart backend on")
    ap.add_argument("--label", default="run")
    args = ap.parse_args()

    truth = json.load(open(args.truth))
    if args.jadart_lib:
        backend = "jadart"
        corpus = load_jadart_corpus(args.jadart_lib)
    elif args.unflutter_out:
        backend = "unflutter"
        corpus = load_unflutter_corpus(args.unflutter_out)
    else:
        sys.exit("provide --jadart-lib or --unflutter-out")
    if not corpus:
        sys.exit("no recovered output found")

    report = {
        "label": args.label,
        "backend": backend,
        "classes": recall(truth["classes"], corpus),
        "functions": recall(truth["functions"], corpus),
        "strings": recall(truth["strings"], corpus),
    }
    print(json.dumps(report, indent=2))

    # human line
    for k in ("classes", "functions", "strings"):
        r = report[k]
        print(f"  {args.label:10s} {k:10s} {r['recovered']}/{r['total']}"
              f"  ({r['recall_pct']}%)", file=sys.stderr)


if __name__ == "__main__":
    main()
