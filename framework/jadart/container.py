"""Read the APK or IPA around the snapshot: extract its assets, inventory the rest.

`export` recovers the Dart. That is one file out of a hundred in a real app, and everything
an analyst wants next is in the others: the certificate the app pins against, the JSON that
names the backend, the model it ships, the manifest that says whether it allows cleartext
traffic. jadx already draws this line, `sources/` for the code it decompiles, `resources/`
for everything else, and the split is right. What changes for Flutter is where the line
falls, because a Flutter APK holds two programs:

    lib/<abi>/libapp.so            the Dart, which is what jadart decompiles
    classes.dex                    the Android embedding, which is jadx's job
    assets/flutter_assets/         the Dart side's data, in Flutter's own formats
    AndroidManifest.xml, res/      the Android container

The idea is borrowed; the implementation should not be. Copying `res/`, `META-INF/` and
three copies of a 10 MB Flutter engine out of the zip would add nothing to bytes the user
already has, and `unzip` and apktool do it better. So only the part jadart improves is
written out, and everything else is inventoried and handed to whichever tool owns it:

    sources/        decompiled Dart                     (written by export)
    assets/         the Flutter asset bundle, unwrapped and decoded
    assets.txt      what each asset is, and which are worth opening first
    container.txt   everything else in the container, and what reads it

Two of Flutter's own formats are decoded rather than copied, because a byte-for-byte copy
of either is useless to a reader:

`NOTICES.Z` is gzip. Inside is every licence of every package the app links, which is a
complete third-party dependency inventory, often the fastest way to learn that an app
bundles a particular crypto or analytics library. Nobody thinks to gunzip a file with that
extension, so it is unpacked here and the package names are pulled out beside it.

`AssetManifest.bin` is Flutter's StandardMessageCodec. This one is not optional: Flutter
stopped shipping the readable `AssetManifest.json` after 3.10, so on any current app the
binary is the ONLY index of what the app declares as an asset.
"""
from __future__ import annotations

from .errors import ContainerError, InputError, JadartError
from .fill import visible

import contextlib
import gzip
import json
import os
import posixpath
import shutil
import zipfile
import zlib

#: Every text file jadart writes is UTF-8 with LF endings, on every platform.
#: Without the explicit encoding Python uses the locale one, and a Windows console
#: at cp1252 aborted an export partway through on the first recovered string it
#: could not represent. Recovered text is arbitrary bytes out of someone else's
#: binary, so it is escaped rather than allowed to fail, and the newline is pinned
#: so the same input exports to the same bytes wherever it runs.
TEXT_OUT = {"encoding": "utf-8", "errors": "backslashreplace", "newline": "\n"}

# Anything bigger than this is not being unpacked from an untrusted container.
MAX_MEMBER = 1_500_000_000
MAX_TOTAL = 4_000_000_000
#: NOTICES.Z is a licence text file. Anything past this is a decompression bomb, not a
#: licence: the whole Flutter framework's notices come to a few hundred KB.
MAX_NOTICES = 64_000_000
#: AssetManifest.bin nests lists and maps, and the reader recurses once per level. Flutter
#: writes two. A crafted file nesting thousands raises RecursionError, which is neither a
#: ContainerError nor catchable by anyone following the documented API.
MAX_MANIFEST_DEPTH = 64


# ── Flutter's StandardMessageCodec ──────────────────────────────────────────

_NULL, _TRUE, _FALSE, _I32, _I64, _BIGINT, _F64 = 0, 1, 2, 3, 4, 5, 6
_STR, _U8, _I32L, _I64L, _F64L, _LIST, _MAP, _F32L = 7, 8, 9, 10, 11, 12, 13, 14


class _Reader:
    """Just enough of StandardMessageCodec to read an AssetManifest.

    lib/src/services/message_codecs.dart. Sizes are one byte under 254, else a 254 marker
    plus uint16 or a 255 marker plus uint32; typed-data payloads are aligned to their
    element size measured from the start of the buffer.
    """

    def __init__(self, buf: bytes):
        self.b, self.i = buf, 0
        self.depth = 0

    def _take(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.b):
            raise ContainerError("AssetManifest.bin: read past the end of the buffer")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def _size(self) -> int:
        n = self._take(1)[0]
        if n < 254:
            return n
        if n == 254:
            return int.from_bytes(self._take(2), "little")
        return int.from_bytes(self._take(4), "little")

    def _align(self, to: int):
        pad = (-self.i) % to
        self.i += pad

    def value(self):
        t = self._take(1)[0]
        if t == _NULL:
            return None
        if t == _TRUE:
            return True
        if t == _FALSE:
            return False
        if t == _I32:
            return int.from_bytes(self._take(4), "little", signed=True)
        if t == _I64:
            return int.from_bytes(self._take(8), "little", signed=True)
        if t == _BIGINT:
            return int(self._take(self._size()).decode("utf-8"), 16)
        if t == _F64:
            import struct
            self._align(8)
            return struct.unpack("<d", self._take(8))[0]
        if t == _STR:
            return self._take(self._size()).decode("utf-8", "replace")
        if t == _U8:
            return list(self._take(self._size()))
        if t in (_I32L, _I64L, _F64L, _F32L):
            width = {_I32L: 4, _I64L: 8, _F64L: 8, _F32L: 4}[t]
            n = self._size()
            self._align(width)
            self._take(n * width)
            return f"<{n} x {width * 8}-bit>"
        if t in (_LIST, _MAP):
            self.depth += 1
            if self.depth > MAX_MANIFEST_DEPTH:
                raise ContainerError(
                    f"AssetManifest.bin nests past {MAX_MANIFEST_DEPTH} levels at offset "
                    f"{self.i - 1}; refusing to recurse further.")
            try:
                if t == _LIST:
                    return [self.value() for _ in range(self._size())]
                return {self._key(): self.value() for _ in range(self._size())}
            finally:
                self.depth -= 1
        raise ContainerError(f"AssetManifest.bin: unknown type byte {t} at offset {self.i - 1}")

    def _key(self):
        k = self.value()
        return k if isinstance(k, str) else json.dumps(k, default=str)


def decode_asset_manifest(raw: bytes):
    """AssetManifest.bin -> the same structure the old AssetManifest.json carried."""
    return _Reader(raw).value()


# ── NOTICES ────────────────────────────────────────────────────────────────

_SEP = "-" * 80


def notice_packages(text: str) -> list:
    """The package names out of a decompressed NOTICES file.

    Each block is one or more package names on their own lines, a blank line, then the
    licence text, and blocks are separated by a rule of eighty dashes. Several packages
    commonly share one licence, so a block can name more than one.
    """
    names = []
    for block in text.split(_SEP):
        for line in block.strip().splitlines():
            line = line.strip()
            if not line:
                break                      # the blank line ends the name list
            names.append(line)
    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


# ── type sniffing ──────────────────────────────────────────────────────────

_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"),
    (b"RIFF", "riff/webp"), (b"OTTO", "otf font"), (b"\x00\x01\x00\x00", "ttf font"),
    (b"true", "ttf font"), (b"wOFF", "woff font"), (b"wOF2", "woff2 font"),
    (b"PK\x03\x04", "zip"), (b"\x1f\x8b", "gzip"), (b"SQLite format 3\x00", "sqlite db"),
    (b"%PDF", "pdf"), (b"-----BEGIN", "PEM key/certificate"), (b"\x30\x82", "DER certificate"),
    (b"\x7fELF", "ELF binary"), (b"dex\n", "android dex"), (b"\xca\xfe\xba\xbe", "mach-o/class"),
    (b"<?xml", "xml"), (b"<svg", "svg"), (b"OggS", "ogg audio"), (b"ID3", "mp3"),
    (b"\x1aE\xdf\xa3", "webm/mkv"), (b"TFL3", "tflite model"),
)

# Names that are worth a second look on any app: material an analyst is usually hunting for.
_NOTABLE = ("cert", "key", "token", "secret", "password", "credential", "config", "api",
            "firebase", "google-services", ".env", "private", "keystore", "jks", "p12",
            "pem", "seed", "license", "auth")


def sniff(name: str, head: bytes) -> tuple:
    """(type, notable) for one asset, from its magic bytes and its name."""
    kind = None
    for magic, label in _MAGIC:
        if head.startswith(magic):
            kind = label
            break
    if kind == "riff/webp":
        kind = "webp" if head[8:12] == b"WEBP" else "riff"
    if kind is None:
        stripped = head.lstrip()
        if stripped[:1] in (b"{", b"["):
            kind = "json"
        else:
            try:
                head.decode("utf-8")
                kind = "text"
            except UnicodeDecodeError:
                kind = "binary"
    low = name.lower()
    notable = (kind in ("PEM key/certificate", "DER certificate", "sqlite db", "tflite model")
               or any(w in low for w in _NOTABLE))
    return kind, notable


# ── routing ────────────────────────────────────────────────────────────────

def asset_path(member: str):
    """Where a flutter_assets member lands under `assets/`, or None if it is not one.

    Matching is on path segments rather than on container type, so an APK's
    `assets/flutter_assets/...` and an IPA's
    `Frameworks/App.framework/flutter_assets/...` are handled by one rule with neither
    special-cased. `.` and `..` are dropped before anything is written.
    """
    norm = member.replace("\\", "/")
    if norm.endswith("/"):
        return None
    parts = [p for p in norm.split("/") if p not in ("", ".", "..")]
    if "flutter_assets" not in parts:
        return None
    rest = parts[parts.index("flutter_assets") + 1:]
    return posixpath.join(*rest) if rest else None


# Each bucket is (label, what actually reads it). Naming the right tool is more use than
# a worse copy of its output, jadart does not decode AXML or Android resources, and
# pretending otherwise by dumping the raw blobs helps nobody.
GROUPS = (
    ("dart snapshot", "the Dart, which is what jadart just decompiled"),
    ("flutter engine", "the Flutter runtime itself, not this app's code"),
    ("native library", "the app's own FFI/JNI code, not Flutter's: `ghidra`, `radare2 -A`"),
    ("java/kotlin", "the Flutter embedding and any plugins: `jadx -d out-java <app>`"),
    ("manifest", "binary AXML (permissions, exported components): `apktool d <app>`"),
    ("android resources", "`apktool d <app>`"),
    ("signing", "`apksigner verify -v <app>`"),
    ("other", ""),
)


def group_of(member: str) -> str:
    """Which inventory bucket a non-asset container member belongs to.

    A Flutter app ships three kinds of native code and they want three different answers.
    Two are the platform's: the snapshot jadart just read, and the engine, which is
    Flutter's own binary and not this app at all. The third is the app's, and it is the
    one an analyst usually needs next, `package:ffi` targets and plugin JNI both land
    there, and in a CTF it is routinely where the check actually lives. Leaving it in
    `other` says "nothing here", which is the opposite of true.
    """
    parts = [p for p in member.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    if not parts:
        return "other"
    base = parts[-1]
    if base == "libapp.so" or base == "App" and "App.framework" in parts:
        return "dart snapshot"
    if base.startswith("libflutter.") or (base == "Flutter"
                                          and "Flutter.framework" in parts):
        return "flutter engine"
    # Anything else compiled: `lib/<abi>/*.so` on Android, a `.dylib` or the Mach-O at the
    # root of a `<Name>.framework` on iOS. Matched by shape rather than by name, so a
    # library nobody has heard of is still routed rather than silently pooled.
    if (base.endswith((".so", ".dylib"))
            or (len(parts) >= 2 and parts[-2] == base + ".framework")):
        return "native library"
    if base.endswith(".dex"):
        return "java/kotlin"
    if base == "AndroidManifest.xml":
        return "manifest"
    if base == "resources.arsc" or parts[0] == "res":
        return "android resources"
    if parts[0] == "META-INF":
        return "signing"
    return "other"


def abi_of(member: str):
    """The ABI directory a native library sits in, e.g. `lib/arm64-v8a/libapp.so`."""
    parts = member.split("/")
    return parts[1] if len(parts) >= 3 and parts[0] == "lib" else None


def unpack(container: str, outdir: str) -> dict:
    """Write outdir/assets/ and inventory the rest of `container`. Returns a stats dict.

    Only the Flutter asset bundle is extracted, because it is the only part jadart leaves
    more readable than the zip did. Everything else is counted and attributed to the tool
    that owns it.

    A directory or a bare .so is not a container and yields an empty result rather than an
    error: `export` is expected to work on all of them.
    """
    stats = {"assets": 0, "assets_bytes": 0, "notable": [], "abis": [], "packages": 0,
             "declared_assets": 0, "members": 0, "bytes": 0, "groups": {}, "renamed": []}
    if not os.path.isfile(container) or not zipfile.is_zipfile(container):
        return stats

    total, inventory, groups = 0, [], {}
    # Everything zipfile raises on a malformed or hostile archive is turned into a
    # ContainerError here: BadZipFile for a broken central directory or a failed CRC,
    # zlib.error mid-stream, NotImplementedError for a compression method it does not
    # have, RuntimeError for an encrypted member, and OSError reading it. None of those
    # are catchable by a caller following the documented API. What goes wrong writing
    # the output is the output's, not the archive's: an InputError naming it (#104).
    try:
        return _unpack_members(container, outdir, stats, total, inventory, groups)
    except ContainerError:
        raise
    except (zipfile.BadZipFile, zlib.error, NotImplementedError, RuntimeError,
            OSError, EOFError) as exc:
        raise ContainerError(f"{container}: cannot read this archive: {exc}") from exc


def _unpack_members(container, outdir, stats, total, inventory, groups):
    from .export import _fold, _safe_relpath, needed_dirs, unique_each
    adir = os.path.join(outdir, "assets")
    with zipfile.ZipFile(container) as z:
        # Every member is counted and checked before any is written, so one past the
        # limits refuses the archive with nothing of it on disk.
        wanted, written = [], []
        for info in z.infolist():
            if info.filename.endswith("/"):
                continue
            stats["members"] += 1
            stats["bytes"] += info.file_size
            abi = abi_of(info.filename)
            if abi and abi not in stats["abis"]:
                stats["abis"].append(abi)

            rel = asset_path(info.filename)
            if rel is None:
                g = group_of(info.filename)
                n, b = groups.get(g, (0, 0))
                groups[g] = (n + 1, b + info.file_size)
                continue

            if info.file_size > MAX_MEMBER:
                raise ContainerError(
                    f"{info.filename}: {info.file_size / 1e6:.0f} MB exceeds the extraction "
                    f"limit. Unpack this container yourself if that is genuinely its size.")
            total += info.file_size
            if total > MAX_TOTAL:
                raise ContainerError(
                    f"{container}: total extracted size passed "
                    f"{MAX_TOTAL / 1e9:.1f} GB; refusing to continue.")
            wanted.append((info, rel, _safe_relpath(rel, fallback="unnamed")))

        # One asset written over another lost it without a word, and one whose file
        # another needed as a directory refused the whole archive after the sources were
        # written (#104). Asset paths take the library rule (export.unique_each), a name
        # the archive holds twice is two files, and the files jadart writes beside them
        # are taken first: from the members named exactly NOTICES.Z and
        # AssetManifest.bin, which is what Flutter writes. A name that only differs in
        # case is an asset like any other, where asking the filesystem whether NOTICES.Z
        # exists said yes to notices.z on macOS and no on Linux. And where an asset needs
        # one of jadart's names as a directory, jadart does without that file.
        safe = [s for _info, _rel, s in wanted]
        dirs = needed_dirs(safe)
        first = {}
        for i, (_info, rel, _s) in enumerate(wanted):
            first.setdefault(rel, i)
        notices, manifest = first.get("NOTICES.Z"), first.get("AssetManifest.bin")
        if notices is not None and {_fold("NOTICES"), _fold("dependencies.txt")} & dirs:
            notices = None
        decoded = manifest is not None and _fold("AssetManifest.decoded.json") not in dirs
        reserved = (["NOTICES", "dependencies.txt"] if notices is not None else []) + (
            ["AssetManifest.decoded.json"] if decoded else [])
        written = unique_each(safe, reserved)

        for (info, rel, _s), path in zip(wanted, written):
            dest = os.path.join(adir, path)
            _makedirs(outdir, os.path.dirname(dest))
            head = _copy_out(container, outdir, z, info, dest)
            shown = path.replace(os.sep, "/")
            if shown != rel:
                stats["renamed"].append([rel, shown])
            stats["assets"] += 1
            stats["assets_bytes"] += info.file_size
            kind, notable = sniff(rel, head)
            inventory.append((shown, info.file_size, kind, notable))
            if notable:
                stats["notable"].append(shown)

    def at(i):
        return None if i is None else os.path.join(adir, written[i])

    stats["groups"] = groups
    if stats["assets"]:
        stats["packages"] = _expand_notices(outdir, adir, at(notices))
        stats["declared_assets"] = _expand_manifest(
            outdir, adir, at(manifest), at(first.get("AssetManifest.json")), decoded)
        _write_inventory(outdir, inventory, stats["renamed"])
    if stats["members"]:
        _write_container_map(outdir, container, stats)
    return stats


def _out_error(outdir: str, exc: OSError, path: str) -> InputError:
    return InputError(f"{outdir}: cannot write the export there: {exc.strerror or exc}: "
                      f"{exc.filename or path}")


@contextlib.contextmanager
def _writing(outdir: str, path: str, mode: str = "w"):
    """open(path, mode) for a file of the export, with a failure to write it an
    InputError naming the output directory, as export.py's own files are (#96)."""
    try:
        with open(path, mode, **({} if "b" in mode else TEXT_OUT)) as fh:
            yield fh
    except OSError as exc:
        raise _out_error(outdir, exc, path) from exc


def _makedirs(outdir: str, path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        raise _out_error(outdir, exc, path) from exc


def _copy_out(container: str, outdir: str, z, info, dest: str) -> bytes:
    """Write one member to `dest` and return its first 64 bytes, for sniff(). A failure
    reading it is the archive's and one writing it the output's, so the two are told
    apart here, where it is still known which was which."""
    head = b""
    with z.open(info) as src, _writing(outdir, dest, "wb") as out:
        while True:
            try:
                chunk = src.read(1 << 20)
            except OSError as exc:
                raise ContainerError(f"{container}: cannot read this archive: {exc}") \
                    from exc
            if not chunk:
                break
            if len(head) < 64:
                head += chunk[:64 - len(head)]
            out.write(chunk)
    return head


def _write_container_map(outdir: str, container: str, stats: dict):
    """container.txt: what else is in here, and which tool reads it.

    Someone opening an unfamiliar app needs orientation more than a second copy of bytes
    they already have. Two lines naming jadx and apktool are worth more than the 37 MB of
    Flutter engine and Android resources that copying everything used to produce.
    """
    def plural(n):
        return "file " if n == 1 else "files"

    snap_n, snap_b = stats["groups"].get("dart snapshot", (0, 0))
    out = [f"{os.path.basename(container)}: {stats['members']} members, "
           f"{stats['bytes'] / 1e6:.1f} MB uncompressed\n",
           "\njadart handled\n"]
    # The snapshot belongs here, not below: listing it again under "also in here" reads as
    # something left undone, when the whole point is that it was done.
    which = (f" ({snap_b / 1e6:.1f} MB across {snap_n} ABIs, one of them read)"
             if snap_n > 1 else f" ({snap_b / 1e6:.1f} MB)")
    out.append(f"  the Dart snapshot{which}\n      -> sources/\n")
    if stats["assets"]:
        out.append(f"  the Flutter asset bundle ({stats['assets']} "
                   f"{plural(stats['assets']).strip()}, "
                   f"{stats['assets_bytes'] / 1e6:.1f} MB)\n"
                   f"      -> assets/, catalogued in assets.txt\n")
    rest = [(label, note) for label, note in GROUPS
            if stats["groups"].get(label) and label != "dart snapshot"]
    if rest:
        out.append("\nAlso in here, and what reads it\n")
        for label, note in rest:
            n, b = stats["groups"][label]
            out.append(f"  {label:<19} {n:>4} {plural(n)} {b / 1e6:>6.1f} MB"
                       f"{'  ' + note if note else ''}\n")
    if len(stats["abis"]) > 1:
        abis = ", ".join(visible(a) for a in stats["abis"])    # directory names (#78)
        out.append(f"\nABIs present: {abis}. They carry the same Dart "
                   f"compiled for\ndifferent targets; jadart read the arm64 one.\n")
    with _writing(outdir, os.path.join(outdir, "container.txt")) as fh:
        fh.writelines(out)


def _expand_notices(outdir: str, adir: str, src) -> int:
    """NOTICES.Z is gzip. Unpack it and list the packages beside it.

    Read through GzipFile in chunks rather than gzip.decompress, because the compressed
    size says nothing about the expanded size: a 400 KB member of nothing but zeroes
    expands to 419 MB, and decompress() had already built the whole bytes object before
    anything could look at it. Measured on a crafted APK: 1.68 GB resident and 838 MB
    written before the cap existed.
    """
    if src is None:                 # no NOTICES.Z, or an asset needs its names (#104)
        return 0
    try:
        buf = bytearray()
        with gzip.open(src, "rb") as gz:
            while True:
                chunk = gz.read(1 << 20)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_NOTICES:
                    raise ContainerError(
                        f"NOTICES.Z expands past {MAX_NOTICES / 1e6:.0f} MB, which no "
                        f"licence file legitimately does. Refusing to keep decompressing.")
        text = bytes(buf).decode("utf-8", "replace")
    except ContainerError:
        raise
    except (OSError, EOFError, zlib.error, ValueError):
        return 0
    with _writing(outdir, os.path.join(adir, "NOTICES")) as fh:
        fh.write(text)
    names = notice_packages(text)
    with _writing(outdir, os.path.join(adir, "dependencies.txt")) as fh:
        fh.write(f"# {len(names)} packages named in NOTICES: everything this build links.\n")
        fh.write("# Decompressed from NOTICES.Z, which ships gzipped and unreadable.\n\n")
        for n in names:
            fh.write(visible(n) + "\n")      # read out of NOTICES, as names are (#78)
    return len(names)


def _expand_manifest(outdir: str, adir: str, src, plain, decoded: bool) -> int:
    """Decode AssetManifest.bin. Current Flutter ships no readable manifest at all.

    `src` and `plain` are where the members named AssetManifest.bin and
    AssetManifest.json were written, or None, and `decoded` is False where an asset needs
    the decoded file's name as a directory (#104)."""
    if src is None:
        if plain is not None:
            try:
                with open(plain) as fh:
                    return len(json.load(fh))
            except Exception:
                return 0
        return 0
    try:
        with open(src, "rb") as fh:
            data = decode_asset_manifest(fh.read())
    except (ContainerError, OSError):
        return 0
    if decoded:
        out = os.path.join(adir, "AssetManifest.decoded.json")
        with _writing(outdir, out) as fh:
            json.dump(data, fh, indent=2, sort_keys=True, default=str)
            fh.write("\n")
    return len(data) if isinstance(data, dict) else 0


def _write_inventory(outdir: str, inventory: list, renamed: list):
    """One line per asset: what it is, how big, and whether it is worth opening."""
    inventory.sort(key=lambda r: (not r[3], r[0]))
    # A member's path is the container's to choose, so it is listed escaped (#78).
    inventory = [(visible(rel), size, kind, notable)
                 for rel, size, kind, notable in inventory]
    width = min(max((len(r[0]) for r in inventory), default=10), 68)
    with _writing(outdir, os.path.join(outdir, "assets.txt")) as fh:
        fh.write(f"{len(inventory)} files in the Flutter asset bundle. "
                 f"`*` marks ones worth opening first:\n")
        fh.write("a certificate, a key, a database, a model, or a name suggesting "
                 "configuration.\n\n")
        for rel, size, kind, notable in inventory:
            mark = "*" if notable else " "
            fh.write(f"{mark} {rel:<{width}} {size:>10,}  {kind}\n")
        if renamed:
            fh.write(f"\n{len(renamed)} written under another name, so that each has a "
                     f"file of its own: no two are one file on a disk that ignores case, "
                     f"none is where another needs a directory or jadart writes a file, "
                     f"and a name a filesystem cannot hold is cut or replaced:\n")
            for rel, path in sorted(renamed):
                fh.write(f"  {visible(rel)} -> {visible(path)}\n")
