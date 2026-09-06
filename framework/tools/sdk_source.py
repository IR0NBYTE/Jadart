#!/usr/bin/env python3
"""Fetch Dart SDK source for a given release, keyed by the snapshot version hash.

Per-epoch profiles are only tractable because of this lookup. A snapshot's 32-char version
hash isn't opaque: it's an MD5 over the raw bytes of exactly 15 files in runtime/vm/,
concatenated in a fixed order (tools/make_version.py, VM_SNAPSHOT_FILES, fed to
MakeSnapshotHashString). So for a candidate SDK tag we can compute the hash its binaries
would carry without building the VM or even cloning the repo. It costs ~2.5 MiB over HTTP.

Verified: tag 3.12.2 reproduces ace654289f5abc240509fc941453ebc5, the hash carried by every
binary in the corpus.

That turns "which SDK produced this snapshot?" into a search over tags rather than a guess.
It is also the input side of generating an epoch profile: the cid table comes from
class_id.h, the cluster field counts from raw_object.h and app_snapshot.cc.

DEV-TIME ONLY. jadart itself stays dependency-free and offline; nothing under jadart/
imports this. Fetched files are cached under framework/.sdkcache/ (gitignored).

    python3 tools/sdk_source.py --tag 3.12.2 --hash
    python3 tools/sdk_source.py --tag 3.12.2 --fetch class_id.h
    python3 tools/sdk_source.py --identify ace654289f5abc240509fc941453ebc5 --tags 3.12.2 3.11.0
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import urllib.error
import urllib.request

# Fallback list, matching Dart 3.12.2. Only used when tools/make_version.py cannot be
# fetched, because the real list has to come from the version being identified: both its
# CONTENTS and its ORDER have changed over time, and MD5 is order-sensitive. Dart 3.8 lists
# the seven headers first and then the eight sources, where 3.12 is plain alphabetical, so
# hashing 3.8's files in 3.12's order yields a hash no binary carries.
VM_SNAPSHOT_FILES = [
    "app_snapshot.cc", "app_snapshot.h", "dart.cc", "dart_api_impl.cc", "datastream.h",
    "image_snapshot.cc", "image_snapshot.h", "object.cc", "object.h", "raw_object.cc",
    "raw_object.h", "snapshot.cc", "snapshot.h", "symbols.cc", "symbols.h",
]

RAW = "https://raw.githubusercontent.com/dart-lang/sdk/{tag}/runtime/vm/{name}"
MAKE_VERSION = "https://raw.githubusercontent.com/dart-lang/sdk/{tag}/tools/make_version.py"
CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".sdkcache")


class FetchError(Exception):
    pass


def fetch(tag: str, name: str, cache_dir: str = CACHE, timeout: int = 30) -> bytes:
    """Return the bytes of runtime/vm/<name> at <tag>, caching under cache_dir."""
    path = os.path.join(cache_dir, tag, name)
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return fh.read()
    url = RAW.format(tag=tag, name=name)
    try:
        data = urllib.request.urlopen(url, timeout=timeout).read()
    except urllib.error.HTTPError as e:
        raise FetchError(f"{url}: HTTP {e.code} (is {tag!r} a real SDK tag?)") from e
    except Exception as e:                                   # network down, DNS, TLS
        raise FetchError(f"{url}: {e}") from e
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return data


def snapshot_files(tag: str, cache_dir: str = CACHE) -> list:
    """The file list this SDK revision hashes, read from its own tools/make_version.py.

    Reading it per version is not pedantry. The list is order-sensitive and the order
    changed: hashing Dart 3.8's sources in Dart 3.12's order produces fa07b8a2..., while
    real 3.8 binaries carry 830f4f59...."""
    path = os.path.join(cache_dir, tag, "make_version.py")
    if os.path.exists(path):
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
    else:
        try:
            text = urllib.request.urlopen(MAKE_VERSION.format(tag=tag),
                                          timeout=30).read().decode("utf-8", "replace")
        except Exception:
            return list(VM_SNAPSHOT_FILES)          # fall back to the 3.12 list
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
    m = re.search(r"VM_SNAPSHOT_FILES\s*=\s*\[(.*?)\]", text, re.S)
    if not m:
        return list(VM_SNAPSHOT_FILES)
    files = re.findall(r"'([^']+)'", m.group(1))
    return files or list(VM_SNAPSHOT_FILES)


def snapshot_hash(tag: str, cache_dir: str = CACHE) -> str:
    """The snapshot version hash a build from this SDK revision would carry.

    `tag` can be a release tag or a git revision, so a Flutter release can be identified
    through the dart_revision it pins in DEPS."""
    h = hashlib.md5()
    for name in snapshot_files(tag, cache_dir):
        h.update(fetch(tag, name, cache_dir))
    return h.hexdigest()


FLUTTER_DEPS = "https://raw.githubusercontent.com/flutter/flutter/{ver}/DEPS"


def dart_revision_for_flutter(flutter_version: str, timeout: int = 30):
    """The exact Dart SDK revision a Flutter release pins, or None.

    Flutter pins a revision in DEPS, and it is not always a released Dart tag, so going
    through DEPS is what makes a shipped binary identifiable. Older Flutter kept DEPS in the
    separate engine repo, where this will not find it."""
    try:
        text = urllib.request.urlopen(FLUTTER_DEPS.format(ver=flutter_version),
                                      timeout=timeout).read().decode("utf-8", "replace")
    except Exception:
        return None
    m = re.search(r"'dart_revision'\s*:\s*'([0-9a-f]{7,40})'", text)
    return m.group(1) if m else None


def identify(version_hash: str, tags, cache_dir: str = CACHE) -> str | None:
    """Return the first tag whose source reproduces `version_hash`, or None."""
    for tag in tags:
        try:
            if snapshot_hash(tag, cache_dir) == version_hash:
                return tag
        except FetchError as e:
            print(f"  {tag}: {e}", file=sys.stderr)
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Dart SDK source lookup by snapshot hash")
    ap.add_argument("--tag", help="SDK release tag, e.g. 3.12.2")
    ap.add_argument("--hash", action="store_true",
                    help="print the snapshot version hash for --tag")
    ap.add_argument("--fetch", metavar="FILE",
                    help="fetch runtime/vm/FILE at --tag and print it")
    ap.add_argument("--identify", metavar="HASH",
                    help="find which of --tags produces HASH")
    ap.add_argument("--tags", nargs="*", default=[], help="candidate tags for --identify")
    ap.add_argument("--cache", default=CACHE)
    args = ap.parse_args(argv)

    try:
        if args.identify:
            if not args.tags:
                print("--identify needs --tags", file=sys.stderr)
                return 2
            hit = identify(args.identify, args.tags, args.cache)
            print(hit if hit else "no candidate tag reproduces that hash")
            return 0 if hit else 1
        if args.fetch:
            if not args.tag:
                print("--fetch needs --tag", file=sys.stderr)
                return 2
            sys.stdout.write(fetch(args.tag, args.fetch, args.cache).decode("utf-8", "replace"))
            return 0
        if args.hash:
            if not args.tag:
                print("--hash needs --tag", file=sys.stderr)
                return 2
            print(snapshot_hash(args.tag, args.cache))
            return 0
    except FetchError as e:
        print(f"sdk_source: {e}", file=sys.stderr)
        return 2
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
