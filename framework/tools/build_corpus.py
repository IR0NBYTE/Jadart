#!/usr/bin/env python3
"""Build a multi-epoch corpus: one Flutter/Dart version per snapshot format hash.

The version-robustness claim is only as good as the corpus behind it. jadart has been
validated against a single epoch, so this drives an app through several pinned Flutter SDKs
(installed with fvm) and collects one libapp.so per SDK.

Two things make the sweep cheaper than it looks.

First, the target list is chosen by *format hash*, not by version number. The snapshot hash
is an MD5 over 15 files in runtime/vm (tools/sdk_source.py), so it can be computed for any
SDK tag over HTTP before installing anything. Measured that way, a whole minor line usually
shares one hash (Dart 3.11.0 and 3.11.5 are identical, as are 3.10.0 and 3.10.9), so a
handful of builds covers years of releases. That isn't a rule though: 3.12.0 and 3.12.2
differ, so the mapping has to be measured, not assumed.

Second, failures are data. Old Flutter stables drag in old Gradle/AGP/JDK expectations, and
some won't build on a current toolchain. That's a finding about how far back the corpus can
reach, so this records what failed and why instead of quietly dropping it.

    python3 tools/build_corpus.py --plan                 # what would be built, and why
    python3 tools/build_corpus.py --build 3.41.9         # one version
    python3 tools/build_corpus.py --verify               # gates over everything collected
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
FRAMEWORK = os.path.dirname(HERE)
ROOT = os.path.dirname(FRAMEWORK)
APP = os.path.join(ROOT, "flubench", "app")
CORPUS = os.path.join(ROOT, "flubench", "corpus")
FVM_STORE = os.path.expanduser("~/fvm/versions")

# flutter release -> the Dart version it ships, for the distinct format hashes we care
# about. Regenerate with --plan, which re-reads Flutter's release index.
TARGETS = [
    ("3.44.8", "3.12.2"),
    ("3.44.0", "3.12.0"),
    ("3.41.9", "3.11.5"),
    ("3.38.10", "3.10.9"),
    ("3.35.7", "3.9.2"),
    # Reaching back below 3.8. Diffing the AOT-live ReadAlloc/ReadFill bodies across these
    # releases says the grammar does not move at all between 3.4 and 3.12, but a source diff
    # is a hypothesis: only a binary that walks and passes the gates settles it.
    ("3.29.3", "3.7.2"),
    ("3.27.4", "3.6.2"),
    ("3.24.5", "3.5.4"),
    ("3.22.3", "3.4.4"),
    # 3.1 through 3.3 share their AOT fill grammar with everything above, and the snapshot
    # header is the same five varints all the way back to 2.19, so these builds exist to
    # turn that source-level claim into a gated one.
    ("3.19.6", "3.3.4"),
    ("3.16.9", "3.2.6"),
    ("3.13.9", "3.1.5"),
]


def sdk_path(flutter_version: str) -> str:
    return os.path.join(FVM_STORE, flutter_version)


def snapshot_hash_for(dart_version: str):
    sys.path.insert(0, HERE)
    from sdk_source import snapshot_hash, FetchError
    try:
        return snapshot_hash(dart_version)
    except FetchError as e:
        return f"<fetch failed: {e}>"


def plan():
    print(f"{'flutter':10s} {'dart':9s} {'snapshot hash':34s} installed  built")
    for fv, dv in TARGETS:
        h = snapshot_hash_for(dv)
        inst = "yes" if os.path.isdir(sdk_path(fv)) else "-"
        out = os.path.join(CORPUS, dv, "libapp.so")
        print(f"{fv:10s} {dv:9s} {h:34s} {inst:9s}  {'yes' if os.path.exists(out) else '-'}")
    print("\nOne build per distinct hash is enough: a hash covers every release whose 15 "
          "snapshot source files are byte-identical.")


def build(flutter_version: str, dart_version: str) -> dict:
    """Build the corpus app with one pinned SDK; return a result record."""
    sdk = sdk_path(flutter_version)
    if not os.path.isdir(sdk):
        return {"flutter": flutter_version, "dart": dart_version, "ok": False,
                "stage": "install", "error": f"not installed: fvm install {flutter_version}"}
    flutter = os.path.join(sdk, "bin", "flutter")
    env = dict(os.environ)
    env["PATH"] = os.path.join(sdk, "bin") + os.pathsep + env.get("PATH", "")
    env.setdefault("JAVA_HOME",
                   "/Applications/Android Studio.app/Contents/jbr/Contents/Home")

    # Build from a COPY, never the corpus app itself: the ground-truth sources must not be
    # mutated to satisfy a build, and an older SDK can't resolve the app's own `sdk:`
    # constraint (it's pinned at the version it was authored against). Relaxing that bound
    # in the copy is the only source change, and it doesn't touch the app's own code.
    work = os.path.join(CORPUS, ".build", dart_version)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(os.path.dirname(work), exist_ok=True)
    shutil.copytree(APP, work, ignore=shutil.ignore_patterns(
        ".dart_tool", "build", ".gradle", "*.iml"))
    spec = os.path.join(work, "pubspec.yaml")
    txt = open(spec).read()
    txt = re.sub(r"sdk:\s*['\"]?\^?[\d.]+['\"]?", "sdk: '>=2.19.0 <4.0.0'", txt, count=1)
    # Drop dev_dependencies as well. They pin their own SDK floors, flutter_lints 6
    # demands ^3.8.0, so pub refuses to resolve on an older release even though nothing
    # in that group reaches the compiler. Linters and the test harness do not contribute a
    # single byte to a snapshot, so removing them changes the toolchain's mind without
    # changing the program being built.
    txt = re.sub(r"^dev_dependencies:\n(?:[ \t]+\S.*\n|[ \t]*\n)*", "", txt, flags=re.M)
    # Loosen the remaining hosted constraints too. Pinned versions carry their own SDK
    # floors (cupertino_icons 1.0.8 wants >=3.1.0) and reaching back several years means
    # no single pin resolves everywhere. `any` lets pub pick whatever that SDK can take.
    # This does mean the corpus app is not byte-identical across releases, which is fine for
    # what the corpus is for: exercising the snapshot grammar, not diffing program output.
    txt = re.sub(r"^(\s+)(\w+):\s*\^?[\d][\w.+\-]*\s*$", r"\1\2: any", txt, flags=re.M)
    open(spec, "w").write(txt)

    def run(cmd, stage):
        p = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True)
        if p.returncode != 0:
            tail = (p.stderr or p.stdout or "").strip().splitlines()
            return {"flutter": flutter_version, "dart": dart_version, "ok": False,
                    "stage": stage, "error": "\n".join(tail[-10:])}
        return None

    err = run([flutter, "pub", "get"], "pub")
    if err:
        return err

    # Drive the Dart toolchain directly instead of `flutter build apk`.
    #
    # Gradle is the fragile part of an old Flutter release, not Dart. Building the corpus app
    # with 3.41.9 fails in the Kotlin DSL ("Unresolved reference 'jvmTarget'") because the
    # app's Gradle config was authored against a newer AGP. None of that has anything to do
    # with the snapshot we want. Inside, `flutter build apk` runs a kernel compile and then
    # gen_snapshot, and both tools ship in every SDK, so running those two steps ourselves
    # produces the same libapp.so with no Android toolchain involved at all.
    cache = os.path.join(sdk, "bin", "cache")
    engine = os.path.join(cache, "artifacts", "engine")
    host = "darwin-arm64" if os.path.isdir(os.path.join(engine, "darwin-arm64")) else "darwin-x64"
    # Prefer the frontend server that ships inside dart-sdk over the engine's copy. The
    # engine copy is built per host architecture, and an older release may only carry the
    # darwin-x64 flavour while the dartaotruntime beside it is arm64, running one on the
    # other dies with "Architecture mismatch. Invalid vm isolate snapshot seen". The dart-sdk
    # copy sits next to the runtime that executes it, so the two always agree.
    fes = os.path.join(cache, "dart-sdk", "bin", "snapshots",
                       "frontend_server_aot.dart.snapshot")
    if not os.path.exists(fes):
        fes = os.path.join(engine, host, "frontend_server_aot.dart.snapshot")
    aotrt = os.path.join(cache, "dart-sdk", "bin", "dartaotruntime")
    if not os.path.exists(fes):
        # Flutter 3.13 and earlier predate the AOT frontend server and ship the JIT one,
        # which dartaotruntime cannot execute, it needs plain `dart`. Same compiler and
        # same arguments either way; only the snapshot kind and its runtime differ.
        jit = os.path.join(cache, "dart-sdk", "bin", "snapshots",
                           "frontend_server.dart.snapshot")
        if os.path.exists(jit):
            fes, aotrt = jit, os.path.join(cache, "dart-sdk", "bin", "dart")
    patched = os.path.join(engine, "common", "flutter_patched_sdk_product") + os.sep
    def find_gen():
        for h in (host, "darwin-x64", "darwin-arm64"):
            c = os.path.join(engine, "android-arm64-release", h, "gen_snapshot")
            if os.path.exists(c):
                return c
        return None

    gen = find_gen()
    if gen is None or not os.path.exists(fes):
        # `fvm install` only unpacks the SDK; the engine artifacts (gen_snapshot, the
        # frontend server, the patched SDK) are fetched lazily on first build. Ask for them
        # explicitly rather than reporting a missing toolchain.
        subprocess.run([flutter, "precache", "--android", "--universal"],
                       cwd=work, env=env, capture_output=True, text=True)
        gen = find_gen()
        if not os.path.exists(fes):
            fes = os.path.join(cache, "dart-sdk", "bin", "snapshots",
                               "frontend_server_aot.dart.snapshot")
    for name, path in (("frontend_server", fes), ("dartaotruntime", aotrt),
                       ("gen_snapshot", gen), ("flutter_patched_sdk", patched)):
        if not path or not os.path.exists(path):
            return {"flutter": flutter_version, "dart": dart_version, "ok": False,
                    "stage": "toolchain", "error": f"{name} not found in {engine}"}

    dill = os.path.join(work, "app.dill")
    kernel = [aotrt, fes, "--sdk-root", patched, "--target=flutter", "--aot", "--tfa"]
    if dart_version.startswith("2."):
        # The corpus app uses records, which are a 3.0 language feature that 2.19 ships
        # behind an experiment. Enabling it keeps the Record cluster in the snapshot, and
        # that cluster is precisely the one whose grammar differs on 2.19, dropping the
        # code to make the build pass would remove the thing worth testing.
        kernel.append("--enable-experiment=records")
    err = run(kernel + ["--packages", os.path.join(work, ".dart_tool", "package_config.json"),
                        "--output-dill", dill, "lib/main.dart"], "kernel")
    if err:
        return err
    if not os.path.exists(dill):
        return {"flutter": flutter_version, "dart": dart_version, "ok": False,
                "stage": "kernel", "error": "no app.dill produced"}

    dest = os.path.join(CORPUS, dart_version)
    os.makedirs(dest, exist_ok=True)
    out = os.path.join(dest, "libapp.so")
    err = run([gen, "--deterministic", "--snapshot_kind=app-aot-elf",
               f"--elf={out}", dill], "gen_snapshot")
    if err:
        return err
    return {"flutter": flutter_version, "dart": dart_version, "ok": True, "path": out}


def observed_hash(path: str) -> str:
    """The version hash actually carried by a built binary."""
    sys.path.insert(0, FRAMEWORK)
    from jadart.macho import open_container
    data = open_container(open(path, "rb").read()).symbol_bytes("_kDartIsolateSnapshotData")
    return data[20:52].decode("ascii", "replace")


def verify_all():
    sys.path.insert(0, FRAMEWORK)
    from jadart.snapshot import UnknownEpoch
    from jadart import versions
    rows = []
    for fv, dv in TARGETS:
        path = os.path.join(CORPUS, dv, "libapp.so")
        if not os.path.exists(path):
            rows.append((dv, "-", "not built", ""))
            continue
        got = observed_hash(path)
        want = snapshot_hash_for(dv)
        agree = "yes" if got == want else "NO"
        try:
            from jadart.verify import verify_file
            rep = verify_file(path)
            ran = [g for g in rep.tier_a if not g.skipped]
            bad = [g for g in ran if not g.passed]
            status = f"{len(ran) - len(bad)}/{len(ran)} gates"
        except UnknownEpoch:
            status = "epoch not in versions.py (expected until a profile is generated)"
        except versions.UnsupportedTarget as e:
            status = f"unsupported target: {str(e)[:40]}"
        except Exception as e:
            status = f"{type(e).__name__}: {str(e)[:60]}"
        rows.append((dv, got[:12] + "...", status, f"predicted hash agrees: {agree}"))
    print(f"{'dart':9s} {'observed hash':16s} {'status':46s} note")
    for r in rows:
        print(f"{r[0]:9s} {r[1]:16s} {r[2]:46s} {r[3]}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="multi-epoch corpus builder")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--build", metavar="FLUTTER_VERSION")
    ap.add_argument("--build-all", action="store_true")
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args(argv)

    if args.plan:
        plan()
        return 0
    if args.verify:
        verify_all()
        return 0
    todo = []
    if args.build:
        todo = [(fv, dv) for fv, dv in TARGETS if fv == args.build]
        if not todo:
            print(f"unknown target {args.build}; see --plan", file=sys.stderr)
            return 2
    elif args.build_all:
        todo = TARGETS
    else:
        ap.print_help()
        return 2

    results = []
    for fv, dv in todo:
        print(f"== building flutter {fv} (dart {dv}) ...", flush=True)
        r = build(fv, dv)
        results.append(r)
        print("   ok" if r["ok"] else f"   FAILED at {r['stage']}: {r['error'][:200]}")
    os.makedirs(CORPUS, exist_ok=True)
    log = os.path.join(CORPUS, "build_log.json")
    prev = []
    if os.path.exists(log):
        prev = json.load(open(log))
    json.dump(prev + results, open(log, "w"), indent=1)
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
