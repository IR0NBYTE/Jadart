#!/usr/bin/env python3
"""Time and measure the memory of jadart's whole-image workloads, reproducibly.

`tools/measure.py` keeps the documented *results* honest. This keeps the documented
*costs* honest, which went stale the same way and for the same reason: every timing in a
commit message was typed by hand from one run on one machine.

    python3 tools/bench.py                      # the five whole-image workloads
    python3 tools/bench.py -n 5 export lift     # more repetitions, named workloads
    python3 tools/bench.py --list

Each run is a fresh subprocess, so nothing is warm that would not be warm for a user, and
peak RSS is that child's own (`/usr/bin/time -l` on darwin, `-v` on linux) rather than the
cumulative children maximum, which never falls once a heavy workload has run. Best-of is
reported alongside the median because the median moves with whatever else the machine is
doing and the best does not.

`lift` is the only workload with no command behind it: it lifts every code range in the
image rather than the ones a class owns, which is the honest upper bound on Tier 3 and
about 1.6x what `export` reaches. It prints a digest of every line it produced, so two
checkouts can be compared for output equivalence and not just for speed.
"""
from __future__ import annotations

import argparse
import os
import platform
import re
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FRAMEWORK = os.path.dirname(HERE)
ROOT = os.path.dirname(FRAMEWORK)
CLEAN = os.path.join(ROOT, "flubench/artifacts/clean/lib/arm64-v8a/libapp.so")
OBF = os.path.join(ROOT, "flubench/artifacts/obf/lib/arm64-v8a/libapp.so")
CORPUS = os.path.join(ROOT, "flubench/corpus")

_LIFT_ALL = """
import hashlib, sys
from jadart.disasm import (load_instructions, disassemble_range, annotate,
                           build_pool_map, function_name_by_pc)
from jadart.expr import lift_function, make_arity_resolver
from jadart.dispatch import recover_selectors
from jadart.program import static_function_refs, receiver_for

image, fr, hdr = load_instructions(sys.argv[1])
pc_to_name = function_name_by_pc(image, fr)
pool_map = build_pool_map(fr, getattr(image, "arch", None))
static_refs = static_function_refs(fr)
arity = make_arity_resolver(image)
selectors = recover_selectors(image, fr, hdr)
h, n, lines = hashlib.sha256(), 0, 0
for cr in image.all_ranges:
    dis = disassemble_range(image, cr)
    if not dis:
        continue
    body = lift_function(annotate(dis, pc_to_name, pool_map), pool_map,
                         receiver=receiver_for(cr.owner_ref, static_refs),
                         arity=arity, selectors=selectors,
                         arch=getattr(image, "arch", None))
    n += 1
    lines += len(body)
    h.update(("%x\\n" % cr.pc_offset).encode())
    for ln in body:
        h.update(ln.encode()); h.update(b"\\n")
print("functions=%d lines=%d sha256=%s" % (n, lines, h.hexdigest()))
"""


def workloads(out: str) -> dict:
    """name -> (argv, one-line description). Paths are resolved, not relative to cwd."""
    py = [sys.executable]
    jd = py + ["-m", "jadart"]
    refs = [os.path.join(CORPUS, v, "libapp.so") for v in ("3.12.2", "3.11.5", "3.10.9")]
    return {
        "import":     (py + ["-c", "import jadart"], "cost of importing the package"),
        "info":       (jd + ["info", CLEAN], "header and epoch only"),
        "classes":    (jd + ["classes", CLEAN], "Tier 0 skeleton (snapshot layer only)"),
        "strings":    (jd + ["strings", CLEAN], "the identifier pool"),
        "selectors":  (jd + ["selectors", CLEAN], "dispatch-table selector names"),
        "verify":     (jd + ["verify", CLEAN], "the acceptance gates"),
        "functions":  (jd + ["functions", CLEAN], "the call graph over the whole image"),
        "xrefs":      (jd + ["xrefs", CLEAN, "flutter"], "who loads this string"),
        "export":     (jd + ["export", CLEAN, "-q", "-o", os.path.join(out, "clean")],
                       "Tier 3 source tree for the whole binary"),
        "exportobf":  (jd + ["export", OBF, "-q", "-o", os.path.join(out, "obf")],
                       "the same on an --obfuscate build"),
        "lift":       (py + ["-c", _LIFT_ALL, CLEAN],
                       "Tier 3 for every code range, digest included"),
        "signatures": (jd + ["signatures"] + refs + ["-q", "-o", os.path.join(out, "sigs.json")],
                       "build a signature library from three references"),
    }


DEFAULT = ("functions", "xrefs", "export", "lift", "signatures")


def _rss_command(argv):
    """argv wrapped so the child's own peak RSS lands on stderr, and the scale to bytes."""
    if platform.system() == "Darwin":
        return ["/usr/bin/time", "-l"] + argv, 1
    return ["/usr/bin/time", "-v"] + argv, 1024      # GNU time reports kilobytes


_RSS_RE = re.compile(r"(\d+)\s+maximum resident set size|Maximum resident set size[^:]*:\s*(\d+)")


def run_once(argv, cwd):
    wrapped, scale = _rss_command(argv)
    t0 = time.perf_counter()
    p = subprocess.run(wrapped, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    dt = time.perf_counter() - t0
    err = p.stderr.decode(errors="replace")
    rss = 0
    for m in _RSS_RE.finditer(err):
        rss = int(m.group(1) or m.group(2)) * scale
    if p.returncode != 0:
        sys.stderr.write(err[-3000:])
        raise SystemExit(f"bench: workload failed (exit {p.returncode}): {' '.join(argv)}")
    return dt, rss, p.stdout.decode(errors="replace").strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("workloads", nargs="*", help=f"default: {' '.join(DEFAULT)}")
    ap.add_argument("-n", type=int, default=3, help="repetitions (default 3)")
    ap.add_argument("-o", "--out", default=os.path.join(FRAMEWORK, "build", "bench"),
                    help="scratch directory for the workloads that write one")
    ap.add_argument("--list", action="store_true", help="list the workloads and exit")
    ap.add_argument("--digest", action="store_true",
                    help="print each workload's last stdout line, for comparing checkouts")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    known = workloads(a.out)
    if a.list:
        for name, (_argv, doc) in known.items():
            print(f"  {name:11s} {doc}")
        return 0
    for name in a.workloads:
        if name not in known:
            print(f"bench: no workload {name!r}; --list shows them", file=sys.stderr)
            return 2
    names = a.workloads or list(DEFAULT)

    missing = [p for p in (CLEAN, OBF) if not os.path.exists(p)]
    if missing:
        print(f"bench: no fixture at {missing[0]}; nothing to measure", file=sys.stderr)
        return 1

    for name in names:
        argv, _doc = known[name]
        if any(isinstance(x, str) and x.startswith(CORPUS) and not os.path.exists(x)
               for x in argv):
            print(f"  {name:11s} SKIP (corpus binary absent)")
            continue
        times, peak, last = [], 0, ""
        for _ in range(a.n):
            dt, rss, out = run_once(argv, FRAMEWORK)
            times.append(dt)
            peak = max(peak, rss)
            last = out
        print(f"  {name:11s} best={min(times):7.3f}s  median={statistics.median(times):7.3f}s"
              f"  peakRSS={peak / (1 << 20):6.1f}MB")
        if a.digest and last:
            print(f"              {last.splitlines()[-1][:100]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
