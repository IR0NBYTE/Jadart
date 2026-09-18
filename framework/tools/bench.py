#!/usr/bin/env python3
"""Time and measure the memory of jadart's whole-image workloads, reproducibly.

`tools/measure.py` keeps the documented *results* honest. This keeps the documented
*costs* honest, which went stale the same way and for the same reason: every timing in a
commit message was typed by hand from one run on one machine.

    python3 tools/bench.py                      # the five whole-image workloads
    python3 tools/bench.py -n 5 export lift     # more repetitions, named workloads
    python3 tools/bench.py --list
    python3 tools/bench.py --check              # fail if anything got slower than the baseline
    python3 tools/bench.py --baseline           # retake flubench/bench/baseline.json
    python3 tools/bench.py xrefs --check -n 5   # one workload, more carefully

Each run is a fresh subprocess, so nothing is warm that would not be warm for a user, and
peak RSS is that child's own (`/usr/bin/time -l` on darwin, `-v` on linux) rather than the
cumulative children maximum, which never falls once a heavy workload has run. Best-of is
reported alongside the median because the median moves with whatever else the machine is
doing and the best does not.

`lift` is the only workload with no command behind it: it lifts every code range in the
image rather than the ones a class owns, which is the honest upper bound on Tier 3 and
about 1.6x what `export` reaches. It prints a digest of every line it produced, so two
checkouts can be compared for output equivalence and not just for speed.

The baseline is the guarded workloads measured on one machine, and the file names that
machine so a reader knows what the numbers mean. `--check` reruns them and fails when a
median is over 1.5x its baseline or peak RSS over 1.25x. Each has a small absolute floor
as well, so a 40 ms workload cannot fail on scheduler noise. `info` must also finish
inside 200 ms outright: that is the cold start an agent pays on every call. The README's
"How fast" table is generated from the same file by tools/measure.py, so the claim and
the guard are one set of numbers.

Timings only compare on the machine that took them. On another machine, take a baseline
on main first, then check the branch against it:

    python3 tools/bench.py --baseline --file /tmp/main.json     # on main
    python3 tools/bench.py --check --file /tmp/main.json        # on the branch
"""
from __future__ import annotations

import argparse
import json
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
BASELINE = os.path.join(ROOT, "flubench", "bench", "baseline.json")

#: The workloads a baseline records and `--check` guards. `signatures` is left out because
#: it needs corpus binaries the checkout may not have, and `import` because 15 ms is
#: below what a fresh process can measure repeatably.
GUARDED = ("info", "classes", "strings", "functions", "xrefs", "export", "exportobf", "lift")

TIME_TOLERANCE = 1.5     # a median may grow to this multiple of its baseline
RSS_TOLERANCE = 1.25     # peak RSS likewise
TIME_FLOOR_S = 0.02      # and must also have grown by at least this much: a ratio alone
RSS_FLOOR_MB = 4.0       # fails a 40 ms workload on scheduler noise or one more cached page
COLD_START_S = 0.200     # `info` on a .so, the price of every call an agent makes. Absolute,
                         # because a baseline that was itself slow must not excuse it.

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


class BaselineError(ValueError):
    """A baseline file that cannot be checked against, and why."""


_REQUIRED = ("jadart", "python", "machine", "taken", "repetitions", "fixtures_mb", "workloads")


def _rel(path: str) -> str:
    """A path as the reader would type it: relative inside the repo, as given outside."""
    full = os.path.abspath(path)
    return os.path.relpath(full, ROOT) if full.startswith(ROOT + os.sep) else path


def load_baseline(path: str) -> dict:
    """Read and validate a baseline. A stale or hand edited file used to surface as a
    KeyError three functions down, and a run where /usr/bin/time reported nothing wrote a
    zero that later divided something."""
    try:
        with open(path) as f:
            doc = json.load(f)
    except OSError as exc:
        raise BaselineError(f"{_rel(path)}: {exc.strerror}") from exc
    except ValueError as exc:
        raise BaselineError(f"{_rel(path)}: not JSON ({exc})") from exc
    retake = "retake it with --baseline"
    missing = [k for k in _REQUIRED if k not in doc]
    if missing:
        raise BaselineError(f"{_rel(path)}: missing {', '.join(missing)}; {retake}")
    if not isinstance(doc["workloads"], dict) or not doc["workloads"]:
        raise BaselineError(f"{_rel(path)}: no workloads; {retake}")
    for name, w in doc["workloads"].items():
        for key in ("doc", "median_s", "peak_rss_mb"):
            if key not in w:
                raise BaselineError(f"{_rel(path)}: workload {name!r} has no {key}; {retake}")
        if not (w["median_s"] > 0 and w["peak_rss_mb"] > 0):
            raise BaselineError(f"{_rel(path)}: workload {name!r} records a zero, which is "
                                f"/usr/bin/time reporting nothing; {retake}")
    return doc


def _rss_command(argv):
    """argv wrapped so the child's own peak RSS lands on stderr, and the scale to bytes."""
    if platform.system() == "Darwin":
        return ["/usr/bin/time", "-l"] + argv, 1
    return ["/usr/bin/time", "-v"] + argv, 1024      # GNU time reports kilobytes


_RSS_RE = re.compile(r"(\d+)\s+maximum resident set size|Maximum resident set size[^:]*:\s*(\d+)")


def run_once(argv, cwd):
    wrapped, scale = _rss_command(argv)
    t0 = time.perf_counter()
    try:
        p = subprocess.run(wrapped, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        raise SystemExit(f"bench: {wrapped[0]} is missing; on linux it is the `time` package")
    dt = time.perf_counter() - t0
    err = p.stderr.decode(errors="replace")
    rss = 0
    for m in _RSS_RE.finditer(err):
        rss = int(m.group(1) or m.group(2)) * scale
    if p.returncode != 0:
        sys.stderr.write(err[-3000:])
        raise SystemExit(f"bench: workload failed (exit {p.returncode}): {' '.join(argv)}")
    return dt, rss, p.stdout.decode(errors="replace").strip()


def measure(known: dict, names, n: int):
    """Yield (name, result) per workload as each finishes, so a long run shows progress.

    result is {"median_s", "best_s", "peak_rss_mb", "last"}, or None when the workload
    needs a corpus binary this checkout does not have."""
    for name in names:
        argv, _doc = known[name]
        if any(isinstance(x, str) and x.startswith(CORPUS) and not os.path.exists(x)
               for x in argv):
            yield name, None
            continue
        times, peak, last = [], 0, ""
        for _ in range(n):
            dt, rss, out = run_once(argv, FRAMEWORK)
            times.append(dt)
            peak = max(peak, rss)
            last = out
        yield name, {"median_s": statistics.median(times), "best_s": min(times),
                     "peak_rss_mb": peak / (1 << 20), "last": last}


def _cpu_name() -> str:
    try:
        if platform.system() == "Darwin":
            return subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                  capture_output=True, text=True, timeout=5).stdout.strip()
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return platform.processor() or "unknown"


def machine() -> dict:
    return {"cpu": _cpu_name(), "arch": platform.machine(),
            "system": f"{platform.system()} {platform.release()}"}


def write_baseline(path: str, known: dict, measured: dict, n: int) -> None:
    """The guarded workloads as JSON, with enough context to know what the numbers mean."""
    sys.path.insert(0, FRAMEWORK)
    from jadart import __version__
    doc = {
        "jadart": __version__,
        "python": platform.python_version(),
        "machine": machine(),
        "taken": time.strftime("%Y-%m-%d"),
        "repetitions": n,
        "fixtures_mb": {"clean": round(os.path.getsize(CLEAN) / 1e6, 1),
                        "obf": round(os.path.getsize(OBF) / 1e6, 1)},
        "workloads": {name: {"doc": known[name][1],
                             "median_s": round(r["median_s"], 3),
                             "peak_rss_mb": round(r["peak_rss_mb"], 1)}
                      for name, r in measured.items() if r is not None},
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def compare(baseline: dict, measured: dict) -> tuple:
    """Judge `measured` against `baseline`: (rows, failures).

    rows are (name, base, got, tags) for the report; failures are the lines that explain
    an exit of 1, each naming the workload, the baseline and what was measured. Pure, so
    the tolerances are testable without running anything.
    """
    rows, failures = [], []
    for name, base in baseline["workloads"].items():
        got = measured.get(name)
        if got is None:
            rows.append((name, base, None, ["skip"]))
            continue
        tags = []
        bt, gt = base["median_s"], got["median_s"]
        bm, gm = base["peak_rss_mb"], got["peak_rss_mb"]
        if gt > bt * TIME_TOLERANCE and gt - bt > TIME_FLOOR_S:
            tags.append("SLOWER")
            failures.append(f"bench: {name} median {gt:.3f}s is {gt / bt:.2f}x the baseline "
                            f"{bt:.3f}s (limit {TIME_TOLERANCE}x)")
        if gm > bm * RSS_TOLERANCE and gm - bm > RSS_FLOOR_MB:
            tags.append("BIGGER")
            failures.append(f"bench: {name} peak RSS {gm:.1f}MB is {gm / bm:.2f}x the baseline "
                            f"{bm:.1f}MB (limit {RSS_TOLERANCE}x)")
        if name == "info" and gt > COLD_START_S:
            tags.append("COLD START")
            failures.append(f"bench: info median {gt:.3f}s is over the {COLD_START_S:.3f}s "
                            f"cold start budget")
        rows.append((name, base, got, tags or ["ok"]))
    return rows, failures


def _line(name: str, r: dict) -> str:
    return (f"  {name:11s} best={r['best_s']:7.3f}s  median={r['median_s']:7.3f}s"
            f"  peakRSS={r['peak_rss_mb']:6.1f}MB")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("workloads", nargs="*", help=f"default: {' '.join(DEFAULT)}")
    ap.add_argument("-n", type=int, default=3, help="repetitions (default 3)")
    ap.add_argument("-o", "--out", default=os.path.join(FRAMEWORK, "build", "bench"),
                    help="scratch directory for the workloads that write one")
    ap.add_argument("--list", action="store_true", help="list the workloads and exit")
    ap.add_argument("--digest", action="store_true",
                    help="print each workload's last stdout line, for comparing checkouts")
    ap.add_argument("--baseline", action="store_true",
                    help="measure the guarded workloads and write them to --file")
    ap.add_argument("--check", action="store_true",
                    help="rerun the workloads in --file and exit 1 if any got slower or "
                         "bigger than it allows")
    ap.add_argument("--file", default=BASELINE, metavar="FILE",
                    help=f"the baseline to write or check (default {os.path.relpath(BASELINE, ROOT)})")
    a = ap.parse_args()
    if a.n < 1:
        ap.error("-n must be at least 1")

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

    missing = [p for p in (CLEAN, OBF) if not os.path.exists(p)]
    if missing:
        print(f"bench: no fixture at {missing[0]}; nothing to measure", file=sys.stderr)
        return 1

    if a.baseline:
        if a.workloads:
            print("bench: a baseline is every guarded workload, so --baseline takes no names; "
                  "retake them all", file=sys.stderr)
            return 2
        names = list(GUARDED)
        measured = {}
        for name, r in measure(known, names, a.n):
            measured[name] = r
            print(_line(name, r) if r else f"  {name:11s} SKIP (corpus binary absent)")
        write_baseline(a.file, known, measured, a.n)
        print(f"  baseline written to {_rel(a.file)} "
              f"on {machine()['cpu']}")
        return 0

    if a.check:
        try:
            baseline = load_baseline(a.file)
        except BaselineError as exc:
            print(f"bench: {exc}", file=sys.stderr)
            return 2
        names = a.workloads or list(baseline["workloads"])
        unknown = [n for n in names if n not in baseline["workloads"]]
        if unknown:
            print(f"bench: {unknown[0]!r} is not in the baseline", file=sys.stderr)
            return 2
        stale = [n for n in names if n not in known]
        if stale:
            print(f"bench: the baseline names {stale[0]!r} and this checkout has no such "
                  f"workload; retake it with --baseline", file=sys.stderr)
            return 2
        here, there = machine(), baseline["machine"]
        py_here, py_there = platform.python_version(), baseline["python"]
        if here["cpu"] != there.get("cpu") or py_here.rsplit(".", 1)[0] != py_there.rsplit(".", 1)[0]:
            print(f"  baseline: {there.get('cpu', '?')}, Python {py_there}. This run: "
                  f"{here['cpu']}, Python {py_here}. Ratios across machines are a hint, not "
                  f"a verdict: take one on main with --baseline --file and check against that")
        measured = {}
        for name, r in measure(known, names, a.n):
            measured[name] = r
            base = baseline["workloads"][name]
            if r is None:
                print(f"  {name:11s} SKIP (corpus binary absent)")
                continue
            print(f"  {name:11s} median {r['median_s']:7.3f}s vs {base['median_s']:7.3f}s "
                  f"({r['median_s'] / base['median_s']:4.2f}x)   peakRSS {r['peak_rss_mb']:6.1f}MB "
                  f"vs {base['peak_rss_mb']:6.1f}MB ({r['peak_rss_mb'] / base['peak_rss_mb']:4.2f}x)")
        sub = {"workloads": {n: baseline["workloads"][n] for n in names}}
        _rows, failures = compare(sub, measured)
        for line in failures:
            print(line)
        if failures:
            print(f"  {len(failures)} regression(s) against {_rel(a.file)}")
            return 1
        print(f"  nothing slower than {_rel(a.file)} "
              f"(limits {TIME_TOLERANCE}x time, {RSS_TOLERANCE}x memory)")
        return 0

    names = a.workloads or list(DEFAULT)
    for name, r in measure(known, names, a.n):
        if r is None:
            print(f"  {name:11s} SKIP (corpus binary absent)")
            continue
        print(_line(name, r))
        if a.digest and r["last"]:
            print(f"              {r['last'].splitlines()[-1][:100]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
