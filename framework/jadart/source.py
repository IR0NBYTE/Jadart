"""What a command was pointed at, read once and never unpacked.

A user has an APK. The snapshot is one member inside it, and every command has to get at
that member before it can do anything. jadart used to get there by copying the member into
a temp directory, reading the copy back, and removing the directory at exit. That is a
write, a read and a delete to answer a question about bytes that were already on disk.

The copy is not needed. Since Android Gradle Plugin 3.6 a release APK stores native
libraries uncompressed so the loader can map them in place, so `libapp.so` comes straight
out of the central directory with no inflate at all: 1 ms for 4.2 MB on the XORGate build.
A container that does deflate its libraries still works, zipfile inflates into memory, and
the result is still one read rather than three filesystem operations.

Three things follow from not writing the copy, and they are the point of this module:

  A killed process leaves nothing behind. The temp directory was removed by an `atexit`
  hook, which does not run on SIGKILL, on `os._exit`, or when the machine loses power.
  Every such death leaked a full copy of the snapshot into the temp directory, and they
  accumulate silently because nothing goes looking for them.

  jadart runs where it cannot write. A read only container, a sandbox with no writable
  temp, a CI step with a read only workspace: all of them ran the tool today and got an
  OSError from a copy nobody asked for.

  An error names what the user typed. A message about `/var/folders/x/T/jadart-ab12/
  libapp.so` tells a reader nothing. `app.apk!lib/arm64-v8a/libapp.so` tells them the
  container, the member, and that the member was the one picked out of several ABIs.

The readers take `str | Source` rather than only `Source`, so `jadart.parse_libapp(path)`
keeps the signature it documents, and nothing that already had a path has to learn a type.
"""
from __future__ import annotations

from dataclasses import dataclass

import os
import zipfile

from .errors import InputError

# Preferred first: arm64 is what jadart lifts, and what nearly every shipped app carries.
ABI_ORDER = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

#: Ceiling on a member read out of an untrusted container. A declared size is free to
#: write into a zip and costs the writer nothing, so it is checked before the read rather
#: than discovered by watching this process grow. The number is the one that used to guard
#: the extraction to disk, so no container that works today stops working; what changed is
#: that it now bounds memory instead of bounding the write.
MAX_SNAPSHOT_BYTES = 1_500_000_000

#: An IPA keeps the snapshot here instead.
_IOS_MEMBER_SUFFIX = "App.framework/App"

#: How much of a container member is inflated before the running total is consulted.
_CHUNK = 1 << 20


# eq=False keeps identity comparison: the payload is the whole snapshot, and a stray
# `==` between two of these would be a 60 MB memcmp that reads like a cheap test.
@dataclass(frozen=True, eq=False)
class Source:
    """A snapshot binary in memory, and enough about where it came from to say so.

    `origin` is what the user typed. `path` is the file on disk when one exists, which is
    every case except a member read out of a container. `member` names the member, or the
    file found inside a directory, and is what the `// x from y` line reports.

    `label` is the only one of the four a caller should print, and it stays openable
    wherever it can: a real path when there is one, and `container!member` when the bytes
    exist nowhere but here. A reader who pastes it into another command gets either a file
    or an obvious explanation, never a path that quietly does not exist."""

    data: bytes
    origin: str
    path: str | None = None
    member: str | None = None

    @property
    def label(self) -> str:
        return self.path if self.path else f"{self.origin}!{self.member}"

    def __str__(self) -> str:
        return self.label


def read_binary(target) -> Source:
    """`str | Source` -> Source. A Source is already read; a path is read now.

    Every reader starts with this line, so a caller may hand any of them a path, a Source,
    or the container the Source came out of, and get the same answer."""
    if isinstance(target, Source):
        return target
    return open_source(target)


def open_source(path) -> Source:
    """Accept what a user actually has and return the snapshot bytes.

    An APK or IPA is a zip, so the snapshot can be read straight out of it. jadx and
    blutter both take the container rather than making you unzip first, and asking a user
    to know that `lib/arm64-v8a/libapp.so` is the interesting member is a poor greeting."""
    if isinstance(path, Source):
        return path

    if os.path.isdir(path):                        # an extracted lib/ tree or .framework
        for abi in ABI_ORDER:
            cand = os.path.join(path, "lib", abi, "libapp.so")
            if os.path.exists(cand):
                return _read_file(cand, origin=path)
        for name in ("libapp.so", "App"):
            cand = os.path.join(path, name)
            if os.path.exists(cand):
                return _read_file(cand, origin=path)
        raise InputError(f"{path}: no libapp.so or App binary under this directory")

    if not os.path.exists(path):
        # Before os.stat, which raised FileNotFoundError: the commonest failure of all
        # (a typo in a path) escaped every `except jadart.JadartError` the package
        # docstring tells callers to write.
        raise InputError(f"{path}: no such file or directory")
    if not zipfile.is_zipfile(path):
        return _read_file(path, origin=path)       # a .so / .dylib / App binary
    return _read_member(path)


def _read_file(path: str, origin: str) -> Source:
    """A binary the user named, or found for them inside a directory they named.

    Either way the bytes have a file behind them, so `path` is set and `label` is that
    file. A directory also records which member was found, because the user asked about a
    tree and deserves to be told which of its four ABIs answered."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise InputError(f"{path}: cannot read this file: {exc.strerror}") from exc
    member = os.path.relpath(path, origin) if origin != path else None
    return Source(data=data, origin=origin, path=path, member=member)


def _read_member(path: str) -> Source:
    """The snapshot member of a zip, read in place."""
    try:
        with zipfile.ZipFile(path) as z:
            pick = _pick_member(path, z.namelist())
            info = z.getinfo(pick)
            if info.file_size > MAX_SNAPSHOT_BYTES:
                raise InputError(
                    f"{path}: {pick} claims to be {info.file_size / 1e6:.0f} MB, over the "
                    f"{MAX_SNAPSHOT_BYTES / 1e6:.0f} MB limit for a snapshot. Unpack it "
                    f"yourself and point jadart at the file if that is genuinely its size.")
            with z.open(info) as fh:
                data = _read_member_bytes(fh, info.file_size)
    except InputError:
        raise
    except (zipfile.BadZipFile, OSError, EOFError, NotImplementedError, RuntimeError) as exc:
        # Everything zipfile raises on a malformed or hostile archive, turned into the one
        # error the package documents: BadZipFile for a broken central directory or a
        # failed CRC, NotImplementedError for a compression method it does not have,
        # RuntimeError for an encrypted member.
        raise InputError(f"{path}: cannot read this archive: {exc}") from exc
    return Source(data=data, origin=path, member=pick)


def _read_member_bytes(fh, declared: int) -> bytes:
    """Inflate a member a megabyte at a time, never further than it said it would go.

    `ZipExtFile.read()` with no argument asks zlib for up to a gigabyte in one call and
    only then truncates the result to the declared size, so the size check the caller has
    already done is consulted after the memory has been spent rather than before. A 199 KB
    archive declaring a four byte member and holding a 200 MB deflate stream reached 422 MB
    of resident memory that way; read in bounded pieces it reaches 26 MB and fails on the
    member's own CRC, which is the honest answer for an archive like that.

    The loop stops at the declared size rather than at MAX_SNAPSHOT_BYTES because the
    caller refuses anything over the cap before this runs, and a second test against a
    ceiling the bytes cannot reach would look like a guard while guarding nothing."""
    out = bytearray()
    while len(out) < declared:
        chunk = fh.read(min(_CHUNK, declared - len(out)))
        if not chunk:
            break              # short member: the CRC check on close is what rejects it
        out += chunk
    return bytes(out)


def _pick_member(path: str, names: list) -> str:
    """Which member of a container holds the snapshot, or why none of them does."""
    cands = [n for n in names if n.endswith("libapp.so")]
    cands.sort(key=lambda n: next((i for i, a in enumerate(ABI_ORDER) if a in n), 99))
    if not cands:
        cands = [n for n in names if n.endswith(_IOS_MEMBER_SUFFIX)]
    if cands:
        return cands[0]

    # A debug build has no AOT snapshot at all: the Dart code ships as kernel bytecode
    # that the JIT loads at runtime. Saying so is worth a line, because "no snapshot
    # found" otherwise reads as a jadart limitation rather than as a fact about the
    # build, and the two need completely different tools.
    if any(n.endswith("flutter_assets/kernel_blob.bin") for n in names):
        raise InputError(
            f"{path}: a debug/JIT build. Its Dart code is kernel bytecode in "
            f"assets/flutter_assets/kernel_blob.bin, not an AOT snapshot, so there "
            f"is nothing here for jadart to parse.\n"
            f"  You are better off than with a release build, though: a debug "
            f"kernel embeds the ORIGINAL SOURCE for hot reload and stack traces, "
            f"so `strings` on that blob gives back the app's own .dart files "
            f"verbatim, names, comments and literals included.")
    if any("libflutter.so" in n for n in names):
        raise InputError(
            f"{path}: carries libflutter.so but no libapp.so. That is a Flutter "
            f"app whose Dart code is not AOT-compiled into the APK, a debug "
            f"build, or one that loads its code some other way.")
    raise InputError(
        f"{path}: a zip with no Flutter snapshot in it (looked for libapp.so and "
        f"App.framework/App). Not a Flutter app?")
