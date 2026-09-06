#!/usr/bin/env python3
"""Benchmark jadart against real CTF binaries nobody here compiled.

The corpus in `flubench/` answers "is the grammar right", byte-exactly, and it is built by
us. It cannot answer the other question: does this hold up on apps written by strangers,
built with toolchains we never chose, and deliberately made awkward. Those are different
failure modes, an app using a Dart feature the corpus never exercises, an obfuscated
build, a debug build, an architecture nobody tests.

So this pulls the mobile challenges out of sajjadium/ctf-archives, works out which are
Flutter, and records what jadart does with each. A challenge jadart cannot open is a result
too, and is reported rather than dropped: the interesting number is not "how many did it
solve" but "how many did it open, and of the rest, did it say something true about why".

    python3 tools/ctfbench.py --fetch          # download into the cache (~166 MB)
    python3 tools/ctfbench.py                  # run and print the scorecard
    python3 tools/ctfbench.py --json           # same, machine-readable

Downloads are cached and never re-fetched, so a re-run is offline and fast.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
FRAMEWORK = os.path.dirname(HERE)
sys.path.insert(0, FRAMEWORK)

RAW = "https://raw.githubusercontent.com/sajjadium/ctf-archives/main/"
CACHE = os.environ.get("JADART_CTF_CACHE",
                       os.path.expanduser("~/.cache/jadart-ctfbench"))

# Mobile challenges from the archive, listed by path so a re-run fetches the same bytes.
# Not curated for Flutter on purpose: which of these are even Flutter is one of the things
# being measured, and a tool that only ever meets its own corpus learns nothing.
CHALLENGES = [
    "ctfs/0xL4ugh/2024/mobile/Brave/brave.apk",
    "ctfs/0xL4ugh/2024/mobile/MyVault/MyVault.apk",
    "ctfs/0xV01D/2026/mobile/Mawj_Relay/mawj.zip",
    "ctfs/0xV01D/2026/mobile/Qasr_Backup/7mias6.zip",
    "ctfs/0xV01D/2026/mobile/Qasr_Cache/qasr.zip",
    "ctfs/1337UP/2022/mobile/GandalfsInterface/Gandalf Baba.apk",
    "ctfs/1337UP/2023/mobile/MemDump/memdump.apk",
    "ctfs/1337UP/2024/mobile/Cold_Storage/cryptovault.apk",
    "ctfs/1337UP/2024/mobile/Quiz/quiz.apk",
    "ctfs/24hCTF/2024/mobile/HiveHex_Solitary_Timer/TheTimer.apk",
    "ctfs/24hCTF/2024/mobile/Ungoing_Cafeteria_Development/cafeteria_dev.apk",
    "ctfs/ADDA/2022/mobile/CoffeeCounter/CoffeeCounter.apk",
    "ctfs/ADDA/2022/mobile/WonderMaze/wondermaze.apk",
    "ctfs/BSidesMumbai/2024/mobile/Conundrum/Login_Bypass.zip",
    "ctfs/BSidesMumbai/2024/mobile/Modded_Game_with_Backdoor/Flappy_Bird_Mod.zip",
    "ctfs/BSidesSF/2026/mobile/doremi/doremi.apk",
    "ctfs/BSidesSF/2026/mobile/vinyl_drop/vinyl-drop.apk",
    "ctfs/BSidesTLV/2023/mobile/FangLight/app-release.apk",
    "ctfs/BSidesTLV/2023/mobile/KeyHunter/app-release.apk",
    "ctfs/BrunnerCTF/2025/mobile/BakeDown/mobile_bakedown.zip",
    "ctfs/BrunnerCTF/2025/mobile/Brod_and_Co./mobile_brod-and-co.zip",
    "ctfs/BrunnerCTF/2025/mobile/FridayCake/mobile_fridaycake.zip",
    "ctfs/Defcamp/2022/mobile/new-buldozer/myapp-0.1-armeabi-v7a-debug.apk",
    "ctfs/Defcamp/2023/Quals/mobile/papp/keykey.apk",
]


def label(path: str) -> str:
    """"<ctf> <year> / <challenge>", where challenge is the directory holding the file.

    The archive is not uniformly deep, some years interpose a round ("Quals"), so the
    challenge name is at index 4 for most and 5 for those. Counting from the end instead
    of the start is right for both, and stays right for whatever the archive does next.
    """
    p = path.split("/")
    return f"{p[1]} {p[2]} / {p[-2]}"


def fetch(path: str) -> str:
    """Download once into the cache and return the local path.

    Written to a .part file and renamed, because the cache is keyed on "exists and is
    non-empty": a download interrupted halfway would otherwise leave a truncated APK that
    every later run trusts. A partial file is a far worse outcome than no file, since it
    parses as a corrupt zip rather than as a missing one.
    """
    dest = os.path.join(CACHE, path.replace("/", "_").replace(" ", "_"))
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return dest
    os.makedirs(CACHE, exist_ok=True)
    url = RAW + urllib.parse.quote(path)
    tmp = dest + ".part"
    try:
        with urllib.request.urlopen(url, timeout=180) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
        os.replace(tmp, dest)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return dest


def apks_in(container: str):
    """The APKs an artefact contains, as (cache path, original name) pairs.

    Extracted APKs are cached under a name that includes the artefact they came from.
    Android's own names are not unique (every split bundle contains a `base.apk`) so
    keying the cache on the basename alone would make the second bundle silently reuse the
    first one's bytes and report them under the wrong challenge.
    """
    if container.lower().endswith(".apk"):
        return [(container, os.path.basename(container))]
    stem = os.path.splitext(os.path.basename(container))[0]
    out = []
    try:
        with zipfile.ZipFile(container) as z:
            for n in z.namelist():
                if not n.lower().endswith(".apk"):
                    continue
                inner = os.path.basename(n)
                dest = os.path.join(CACHE, f"x_{stem}_{inner}".replace(" ", "_"))
                if not os.path.exists(dest):
                    with z.open(n) as src, open(dest, "wb") as f:
                        shutil.copyfileobj(src, f)
                out.append((dest, inner))
    except zipfile.BadZipFile:
        pass
    return out


def kind_of(apk: str) -> str:
    """release-aot | debug-kernel | not-flutter | unreadable."""
    try:
        with zipfile.ZipFile(apk) as z:
            names = z.namelist()
    except Exception:
        return "unreadable"
    if any(n.endswith("libapp.so") for n in names):
        return "release-aot"
    if any(n.endswith("kernel_blob.bin") for n in names):
        return "debug-kernel"
    if any("libflutter.so" in n for n in names):
        return "flutter-no-code"
    return "not-flutter"


def run(apk: str, args: list) -> tuple:
    """(exit code, stdout, stderr) for `jadart <args> <apk>`, run as a user would.

    A hang is a result, not a reason to lose the other twenty-three: 124 is what `timeout`
    reports, and the caller treats it like any other refusal.
    """
    cmd = [sys.executable, "-m", "jadart"] + args + [apk]
    try:
        p = subprocess.run(cmd, cwd=FRAMEWORK, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after 600s: jadart {' '.join(args)}"
    return p.returncode, p.stdout, p.stderr


def probe(apk: str) -> dict:
    """Everything jadart can say about one APK, plus how long it took."""
    out = {"kind": kind_of(apk), "size_mb": round(os.path.getsize(apk) / 1e6, 1)}
    if out["kind"] != "release-aot":
        rc, so, se = run(apk, ["info", "-j"])
        out["refused_cleanly"] = rc != 0 and bool((so or se).strip())
        try:
            out["message"] = json.loads(so).get("error", "")[:120]
        except Exception:
            out["message"] = (se or so).strip().splitlines()[0][:120] if (se or so) else ""
        return out

    t0 = time.time()
    rc, so, _ = run(apk, ["info", "-j"])
    try:
        info = json.loads(so)["snapshots"]["isolate"]
        out.update(dart=info["dart"], epoch=info["epoch"], target=info["target"],
                   objects=info["objects"])
    except Exception:
        out["parse_error"] = (so or "")[:160]
        rc2, so2, se2 = run(apk, ["info"])
        out["message"] = (se2 or so2).strip().splitlines()[0][:160]
        return out

    rc, so, _ = run(apk, ["verify", "-j"])
    try:
        v = json.loads(so)
        run_a = [g for g in v["gates"] if g["tier"] == "A" and not g["skipped"]]
        out["gates"] = f"{sum(1 for g in run_a if g['passed'])}/{len(run_a)}"
        out["supported"] = v["ok"]
    except Exception:
        out["gates"] = "error"

    rc, so, _ = run(apk, ["libraries", "--app", "-j"])
    try:
        libs = json.loads(so)["libraries"]
        out["app_libraries"] = len(libs)
        out["app_classes"] = sum(l["classes"] for l in libs)
    except Exception:
        pass

    rc, so, _ = run(apk, ["strings", "-j"])
    try:
        out["strings"] = json.loads(so)["count"]
    except Exception:
        pass
    out["seconds"] = round(time.time() - t0, 1)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fetch", action="store_true", help="download only, then stop")
    ap.add_argument("--json", action="store_true", help="machine-readable scorecard")
    ap.add_argument("--only", metavar="SUBSTR", help="restrict to matching challenges")
    args = ap.parse_args(argv)

    todo = [c for c in CHALLENGES if not args.only or args.only.lower() in c.lower()]
    rows = []
    for path in todo:
        try:
            local = fetch(path)
        except Exception as exc:
            rows.append({"challenge": label(path), "kind": "download-failed",
                         "message": str(exc)[:100]})
            continue
        if args.fetch:
            print(f"  cached {label(path)}")
            continue
        found = apks_in(local)
        if not found:
            rows.append({"challenge": label(path), "kind": "no-apk-inside"})
            continue
        for apk, inner in found:
            # A split bundle is several APKs and only one of them carries the native code,
            # so name which is which rather than printing the challenge twice.
            name = label(path) + (f" [{inner}]" if len(found) > 1 else "")
            rows.append({"challenge": name, **probe(apk)})

    if args.fetch:
        print(f"cached {len(todo)} artefacts in {CACHE}")
        return 0

    if args.json:
        json.dump({"cache": CACHE, "results": rows}, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return 0

    aot = [r for r in rows if r.get("kind") == "release-aot"]
    parsed = [r for r in aot if r.get("dart")]
    gated = [r for r in parsed if r.get("gates", "").count("/") and
             r["gates"].split("/")[0] == r["gates"].split("/")[1]]

    w = max((len(r["challenge"]) for r in rows), default=10) + 1
    print(f"{'challenge':<{w}} {'kind':<16} {'dart':<8} {'gates':<6} {'app cls':<8} strings")
    for r in sorted(rows, key=lambda r: r["challenge"]):
        print(f"{r['challenge']:<{w}} {r.get('kind',''):<16} {r.get('dart',''):<8} "
              f"{r.get('gates',''):<6} {str(r.get('app_classes','')):<8} "
              f"{r.get('strings','')}")
        if r.get("message"):
            print(f"{'':<{w}}   -> {r['message']}")

    # Every row is accounted for by kind. Naming only the three interesting categories let
    # a download failure sit in the total without appearing anywhere underneath it, which
    # reads as "we looked at this one" when nobody did.
    kinds = {}
    for r in rows:
        kinds[r.get("kind", "?")] = kinds.get(r.get("kind", "?"), 0) + 1
    print(f"\n{len(rows)} artefacts: " +
          ", ".join(f"{n} {k}" for k, n in sorted(kinds.items(), key=lambda kv: -kv[1])))
    print(f"of the {len(aot)} Flutter AOT builds, jadart parsed {len(parsed)} "
          f"and {len(gated)} passed every applicable Tier-A gate")
    probed = [r for r in rows if r.get("kind") in
              ("not-flutter", "debug-kernel", "flutter-no-code", "unreadable")]
    refused = [r for r in probed if r.get("refused_cleanly")]
    print(f"{len(refused)} of the {len(probed)} non-AOT artefacts were refused with a "
          f"specific reason rather than a crash")
    broken = [r for r in rows if r.get("kind") == "download-failed"]
    if broken:
        print(f"WARNING: {len(broken)} could not be downloaded and were not examined: "
              + ", ".join(r["challenge"] for r in broken))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
