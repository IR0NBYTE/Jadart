#!/usr/bin/env python3
"""Sweep real Flutter apps from F-Droid and report what jadart does with each.

WHY THIS EXISTS. flubench is fifteen epochs of ONE app, the one we wrote. Every gate is
green on it by construction, because the app only uses Dart features we thought to put in
it. The first real shipped app pointed at jadart (FluffyChat 1.29, dart 3.12.2) failed at
cluster #1080 of 1090 on `LibraryPrefixCid`, `import ... deferred as`, which flubench
never used. A corpus that cannot produce that cluster cannot catch its absence.

So this widens the evidence to apps nobody here compiled, and it is deliberately cheap
enough to re-run:

  * F-Droid publishes an index of ~4,200 packages. Most are not Flutter.
  * A zip keeps its central directory at the end, member names in plain text, so ONE
    range request for the tail says whether `lib/arm64-v8a/libapp.so` is in there. No
    download, no unzip. 700 probes take about eight minutes.
  * For the hits, two more range requests, the central-directory record, then the
    member's own bytes, pull out just the snapshot. 26-180 MB of APK becomes 6-24 MB of
    libapp.so, and the icons, fonts and other three ABIs are never transferred.

A failure here is a result, not an error. An unknown version hash means the epoch registry
needs an entry and prints the `sdk_source.py --identify` line that places it; a missing
fill grammar names the cluster. Both are reported rather than raised, because the point of
the sweep is the list.

    python3 tools/appsweep.py --probe 700        # find Flutter apps, cache the list
    python3 tools/appsweep.py --fetch 25         # pull just the snapshots
    python3 tools/appsweep.py --verify           # run the gates over everything fetched
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import struct
import subprocess
import sys
import urllib.request
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
FRAMEWORK = os.path.dirname(HERE)
sys.path.insert(0, FRAMEWORK)

CACHE = os.environ.get("JADART_APPSWEEP_CACHE",
                       os.path.expanduser("~/.cache/jadart-appsweep"))
REPO = "https://f-droid.org/repo/"
INDEX = REPO + "index-v1.jar"
WANT = "lib/arm64-v8a/libapp.so"

#: How much of the file tail to read when looking for a member name. The central directory
#: of a 180 MB APK with a few thousand entries fits well inside this; a miss is reported
#: rather than retried, because the cost of being wrong is one app skipped out of hundreds.
TAIL = 3_000_000
#: A Flutter APK carries the engine, so it is never small. Below this is not worth a probe.
MIN_APK = 6_000_000


def _get(url, start=None, length=None, suffix=None, timeout=120):
    h = {}
    if suffix is not None:
        h["Range"] = f"bytes=-{suffix}"
    elif start is not None:
        h["Range"] = f"bytes={start}-{start + length - 1}"
    return urllib.request.urlopen(urllib.request.Request(url, headers=h),
                                  timeout=timeout).read()


def index(refresh=False) -> list:
    """[(package, apkName, size)] newest-version-first, largest first."""
    os.makedirs(CACHE, exist_ok=True)
    raw = os.path.join(CACHE, "index-v1.json")
    if refresh or not os.path.exists(raw):
        jar = os.path.join(CACHE, "index-v1.jar")
        open(jar, "wb").write(_get(INDEX, timeout=300))
        with zipfile.ZipFile(jar) as z:
            open(raw, "wb").write(z.read("index-v1.json"))
    d = json.load(open(raw))
    out = []
    for pn, vers in d["packages"].items():
        if vers and vers[0].get("apkName") and vers[0].get("size", 0) > MIN_APK:
            out.append((pn, vers[0]["apkName"], vers[0]["size"]))
    out.sort(key=lambda c: -c[2])
    return out


def _probe(item):
    pn, apk, size = item
    try:
        tail = _get(REPO + apk, suffix=min(size, TAIL), timeout=45)
    except Exception:
        return None
    return item if b"libapp.so" in tail else None


def probe(n: int) -> list:
    cand = index()[:n]
    hits = []
    with cf.ThreadPoolExecutor(max_workers=24) as ex:
        for r in ex.map(_probe, cand):
            if r:
                hits.append(r)
                print(f"  flutter  {r[2] / 1048576:7.1f} MB  {r[0]}", flush=True)
    json.dump(hits, open(os.path.join(CACHE, "flutter.json"), "w"))
    print(f"\nprobed {len(cand)}, flutter {len(hits)} "
          f"({len(hits) / max(len(cand), 1):.0%})")
    return hits


def _grab(item):
    """Two range requests: the tail to locate the member, then the member itself."""
    pn, apk, size = item
    dest = os.path.join(CACHE, "libapps", pn + ".so")
    if os.path.exists(dest):
        return (pn, "cached", os.path.getsize(dest))
    url = REPO + apk
    try:
        tail = _get(url, suffix=min(size, TAIL))
        i = tail.find(WANT.encode())
        if i < 0:
            return (pn, "member outside the tail", 0)
        cd = tail.rfind(b"PK\x01\x02", 0, i)
        if cd < 0:
            return (pn, "no central directory record", 0)
        method, = struct.unpack_from("<H", tail, cd + 10)
        csize, = struct.unpack_from("<I", tail, cd + 20)
        lho, = struct.unpack_from("<I", tail, cd + 42)
        head = _get(url, start=lho, length=30)
        nlen, elen = struct.unpack_from("<HH", head, 26)
        raw = _get(url, start=lho + 30 + nlen + elen, length=csize)
        blob = raw if method == 0 else zlib.decompress(raw, -15)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        open(dest, "wb").write(blob)
        return (pn, "ok", len(blob))
    except Exception as e:
        return (pn, f"{type(e).__name__}: {str(e)[:40]}", 0)


def fetch(n: int):
    hits = json.load(open(os.path.join(CACHE, "flutter.json")))
    hits.sort(key=lambda h: h[2])          # smallest first: more apps per byte
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for pn, st, size in ex.map(_grab, hits[:n]):
            print(f"  {st:<28} {size / 1048576:7.1f} MB  {pn}")


_UNKNOWN = re.compile(r"--identify (\w+)")


def verify():
    d = os.path.join(CACHE, "libapps")
    files = sorted(f for f in os.listdir(d)) if os.path.isdir(d) else []
    rows, epochs, missing = [], {}, {}
    for f in files:
        path = os.path.join(d, f)
        r = subprocess.run([sys.executable, "-m", "jadart.cli", "verify", path],
                           capture_output=True, text=True, cwd=FRAMEWORK)
        out = r.stdout + r.stderr
        # Match "every applicable Tier-A gate passed", not a fixed count. The literal
        # "Tier A: 8/8" was here, and it stopped matching the moment a tenth gate was
        # added: the sweep then reported 0 of 48 passing and nobody read it as a bug in
        # the sweep. A gate count is not a constant and must not be spelled as one.
        m_ok = re.search(r"Tier A: (\d+)/(\d+) passed", r.stdout)
        if m_ok and m_ok.group(1) == m_ok.group(2) and m_ok.group(1) != "0":
            i = subprocess.run([sys.executable, "-m", "jadart.cli", "info", path],
                               capture_output=True, text=True, cwd=FRAMEWORK).stdout
            m = re.search(r"epoch\s+(\S+)\s+\(dart (\S+)\)", i)
            ep = m.group(2) if m else "?"
            epochs[ep] = epochs.get(ep, 0) + 1
            rows.append(("pass", ep, f))
        elif "no fill grammar" in out:
            cl = re.search(r"cid \d+ \((\w+)\)", out)
            key = cl.group(1) if cl else "?"
            missing[key] = missing.get(key, 0) + 1
            rows.append(("missing grammar: " + key, "-", f))
        elif h := _UNKNOWN.search(out):
            rows.append(("unknown epoch " + h.group(1)[:8], "-", f))
        else:
            rows.append((out.strip().split("\n")[-1][:48], "-", f))

    ok = sum(1 for r in rows if r[0] == "pass")
    print(f"{len(rows)} real apps: {ok} pass every applicable Tier-A gate, "
          f"{len(rows) - ok} do not\n")
    for st, ep, f in sorted(rows):
        print(f"  {st:<34} {ep:<9} {f[:-3]}")
    if epochs:
        print("\nepochs covered:",
              ", ".join(f"{k} x{v}" for k, v in sorted(epochs.items())))
    if missing:
        print("MISSING FILL GRAMMARS:",
              ", ".join(f"{k} ({v} apps)" for k, v in sorted(missing.items())))
    return 0 if ok == len(rows) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--probe", type=int, metavar="N",
                    help="probe the N largest F-Droid packages for a Dart snapshot")
    ap.add_argument("--fetch", type=int, metavar="N",
                    help="range-fetch the snapshot out of N of the apps found")
    ap.add_argument("--verify", action="store_true",
                    help="run the acceptance gates over every snapshot fetched")
    a = ap.parse_args()
    if a.probe:
        probe(a.probe)
    if a.fetch:
        fetch(a.fetch)
    if a.verify:
        return verify()
    if not (a.probe or a.fetch or a.verify):
        ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
