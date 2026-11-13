"""`jadart serve`: one process that holds a binary and answers commands about it.

An agent reads a binary one function at a time, each call a new process, and each of
those repeats the whole setup (#352). `jadart serve <libapp> --socket PATH` reads the
binary once and listens on a unix socket. A command given `--server PATH` (or run with
JADART_SERVER set) sends its own command line there and prints what comes back, so the
setup is paid by the first command that needs it and by none after (keep.py).

What is kept lives in the server's memory and nowhere else. The one thing on disk is
the socket, at the path the user gave, mode 0600, removed when the server stops.

Why not an index on disk. It would have to be a hand-written format for eight object
graphs (pickle is out: reading it back runs what the file says), reloaded on every call,
and a well formed file that lies cannot be told from one that does not without redoing
the work it stands for. A process cannot be left behind by an older jadart, copied from
another machine, or half written.

The rules that make an answer from the server the answer a fresh process would give:

  The same bytes. The client reads the file it was pointed at, as it always has, and
  sends the SHA-256 of what it read. The server compares that with the bytes it holds.
  The path is not compared: the same file under another name is the same question, and
  another file under the same name is not.

  The same program. Both sides send a digest of the version, of every source file
  beside this one, of the interpreter and of the capstone it would import. The server
  takes its own when it starts, with every module loaded, so it is the code it runs
  and not the code that is on disk by the time it is asked.

  The same user. The socket is one the client's own user owns, in a directory no one
  else can write, and neither side follows a symbolic link to it.

  The same command. The server runs the command line through the parser and the
  dispatcher `jadart` itself uses, with stdout and stderr recorded in the order they
  were written, and the client replays them. Colour is decided by the client, whose
  terminal it is, and so is how deep the command may recurse: tier 3 gives up its
  structure at the recursion limit, so the limit is moved by however much deeper the
  server's own frames put the command.

When any of that fails, or nothing is listening, or the reply is cut short, too long
or late, the client says so in one line on stderr and runs the command itself. A server
is never believed on the strength of being there.

`export` writes files and takes its paths relative to the caller, and `--sigs` names a
second file the server has not read, so neither is sent. One request runs at a time;
a second client waits its turn, for as long as it was told to (`--server-wait`).
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import socket
import stat
import sys
import time

from . import __version__
from .errors import InputError
from .source import Source

#: A request is a command line and three short strings. Past this it is not one.
MAX_REQUEST = 1 << 20
#: The longest reply a client reads, and so the longest a server sends. `symbols` as
#: JSON for an app of 90,000 functions is under a tenth of it.
MAX_REPLY = 1 << 28
#: How long a client has to send its whole request, however it spaces the bytes.
REQUEST_SECONDS = 5.0
#: How long a client has to take the reply once it is ready.
REPLY_SECONDS = 30.0
#: How long a client waits for an answer unless told otherwise (`--server-wait`).
ANSWER_SECONDS = 10.0
#: The most nested calls a client may say it had left. Python's default is 1,000.
MAX_ROOM = 1 << 20

_BUILD = None


def _source_digest() -> str:
    h = hashlib.sha256(__version__.encode())
    h.update(repr((sys.version, sys.prefix, _disassembler())).encode())
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        for name in sorted(os.listdir(here)):
            if name.endswith(".py"):
                with open(os.path.join(here, name), "rb") as fh:
                    h.update(name.encode() + b"\0" + fh.read())
    except OSError:
        pass
    return h.hexdigest()


def _disassembler() -> tuple:
    """What tells one installed capstone from another: where this interpreter finds it,
    its package file, and the name and file list of its install record, which carry
    the version and a hash of every file. `(None,)` when there is none."""
    import importlib.util
    try:
        spec = importlib.util.find_spec("capstone")
    except (ImportError, ValueError):
        spec = None
    origin = getattr(spec, "origin", None)
    if not origin:
        return (None,)
    h = hashlib.sha256()
    try:
        with open(origin, "rb") as fh:
            h.update(fh.read())
        site = os.path.dirname(os.path.dirname(origin))
        for name in sorted(os.listdir(site)):
            if name.lower().startswith("capstone-") and name.endswith("-info"):
                h.update(name.encode())
                with open(os.path.join(site, name, "RECORD"), "rb") as fh:
                    h.update(fh.read())
    except OSError:
        pass
    return origin, h.hexdigest()


def build_id() -> str:
    """This copy of jadart: its version, the bytes of its source files, the interpreter
    running them and the capstone it has, as a digest. Taken once per process.

    The version alone would let a server started from one checkout answer for another
    with the same number and different code. The interpreter is in it because the same
    source answers differently without a disassembler: `verify` runs two gates fewer.
    A directory that cannot be listed (a zipped install) leaves the rest, and the
    version is what tells two releases apart."""
    global _BUILD
    if _BUILD is None:
        _BUILD = _source_digest()
    return _BUILD


def _load_everything() -> None:
    """Import every module of jadart, and capstone, and take the build digest of exactly
    that: a server imports most of its code when a command first needs it, which may be
    hours after it started, and by then the file may be another one."""
    global _BUILD
    import importlib
    before = _source_digest()
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        names = [n[:-3] for n in sorted(os.listdir(here)) if n.endswith(".py")]
    except OSError:
        names = []                    # a zipped install: nothing beside this to edit
    for name in names + ["capstone"]:
        if name in ("__main__", "__init__"):
            continue
        try:
            importlib.import_module("capstone" if name == "capstone"
                                    else f"{__package__}.{name}")
        except ImportError:
            pass                      # no capstone: the digest says so
    if _source_digest() != before:
        raise InputError("jadart's own files changed while the server was starting; "
                         "start it again")
    _BUILD = before


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def headroom() -> int:
    """How many calls deep the caller could still go before the recursion limit.

    Measured by going there, because that is the number tier 3 depends on: it lifts a
    body by recursion and prints it flat when that runs out. A client sends its own and
    the server runs the command with as much (cli._answer)."""
    def down(n):
        try:
            return down(n + 1)
        except RecursionError:
            return n
    return down(0)


def _unix():
    family = getattr(socket, "AF_UNIX", None)
    if family is None:
        raise InputError("jadart serve needs unix domain sockets, and this platform's "
                         "Python has none")
    return family


def _shared(path: str):
    """Why the directory of `path` is no place for the socket, or None when it is one
    only this user can put things in. Anywhere else, another user could have a socket
    of their own, or a link, waiting at the path."""
    try:
        st = os.stat(os.path.dirname(os.path.abspath(path)))
    except OSError as e:
        return f"its directory cannot be read ({e.strerror or e})"
    if st.st_uid != os.getuid():
        return "its directory belongs to another user"
    if st.st_mode & 0o022:
        return "other users can write to its directory"
    return None


# ------------------------------------------------------------------ the client

def _exchange(path: str, request: bytes, wait: float):
    """Send `request` to the socket at `path` and read the reply to its end: the bytes,
    or (None, why). The whole of it takes at most `wait` seconds."""
    st = os.lstat(path)               # the path itself: a link to a socket is not one
    if not stat.S_ISSOCK(st.st_mode):
        return None, "it is not a socket"
    if st.st_uid != os.getuid():
        return None, "the socket belongs to another user"
    why = _shared(path)
    if why:
        return None, why
    deadline = time.monotonic() + wait
    raw = bytearray()
    try:
        with socket.socket(_unix(), socket.SOCK_STREAM) as conn:
            conn.settimeout(wait)
            conn.connect(path)
            conn.sendall(request)
            conn.shutdown(socket.SHUT_WR)
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise socket.timeout()
                conn.settimeout(left)
                chunk = conn.recv(1 << 16)
                if not chunk:
                    return bytes(raw), None
                raw += chunk
                if len(raw) > MAX_REPLY:
                    return None, "the reply was too long"
    except socket.timeout:
        return None, f"no answer in {wait:g} s"


def ask(path: str, argv: list, src: Source, color: tuple, room: int,
        wait: float = ANSWER_SECONDS, tty: tuple = (False, False)):
    """Send one command line to the server at `path`.

    Returns (exit code, [(fd, text), ...]) for the caller to replay, or (None, why) when
    the server cannot be used, with nothing printed either way. `room` is the caller's
    `headroom()` where it would have run the command, `wait` how many seconds it gives
    the server before it does, and `tty` whether its stdout and stderr are terminals,
    which is what decides how `-j` is laid out."""
    try:
        _unix()
        request = json.dumps({"build": build_id(), "sha256": digest(src.data),
                              "argv": list(argv), "origin": src.origin,
                              "path": src.path, "member": src.member,
                              "color": [bool(color[0]), bool(color[1])],
                              "tty": [bool(tty[0]), bool(tty[1])],
                              "room": room}).encode("ascii")
        raw, why = _exchange(path, request, wait)
        if raw is None:
            return None, why
        reply = json.loads(raw.decode("ascii"))
    except InputError as e:
        return None, str(e)
    except FileNotFoundError:
        return None, "nothing is there"
    except ConnectionRefusedError:
        return None, "nothing is listening"
    except OSError as e:
        return None, f"no reply ({e.strerror or e})"
    except (ValueError, RecursionError, MemoryError):
        # A reply cut short, or not a reply at all: brackets nested past what the
        # parser will follow are one of those. Either way the answer did not arrive,
        # and a part of one is not printed.
        return None, "the reply was cut short"
    if not isinstance(reply, dict) or reply.get("ok") is not True:
        why = reply.get("why") if isinstance(reply, dict) else None
        if isinstance(why, str) and len(why) < 200 and why.isprintable():
            return None, why
        return None, "the reply was not one"
    code, out = reply.get("exit"), reply.get("out")
    if type(code) is not int or not isinstance(out, list) or not all(
            isinstance(c, list) and len(c) == 2 and c[0] in (1, 2)
            and isinstance(c[1], str)
            for c in out):
        return None, "the reply was not one"
    return code, [(fd, text) for fd, text in out]


# ------------------------------------------------------------------ the server

class _Tap:
    """Stands in for sys.stdout or sys.stderr while a command runs in the server: what
    is written is recorded, with which of the two it went to, in the order it came."""
    encoding = "utf-8"
    errors = "backslashreplace"

    def __init__(self, fd: int, chunks: list, tty: bool):
        self._fd, self._chunks, self._tty = fd, chunks, tty

    def write(self, s) -> int:
        if s:
            last = self._chunks[-1] if self._chunks else None
            if last is not None and last[0] == self._fd:
                last[1].append(s)
            else:
                self._chunks.append((self._fd, [s]))
        return len(s)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        """What the client's own stream is: a command asks, and `-j` is indented for a
        terminal and compact for anything else."""
        return self._tty


def _bind(path: str):
    """A listening socket at `path`, mode 0600, and what lstat says of it.

    The path is in a directory only this user can write and is not a symbolic link:
    binding follows one, and would make the socket wherever it pointed. A socket
    already there is taken over only when nothing answers on it, which is what a
    server killed before it could tidy up leaves behind. Anything else is left alone."""
    family = _unix()
    hint = ("--socket names a path for jadart to create, in a directory only you can "
            "write (mkdir -m 700)")
    why = _shared(path)
    if why:
        raise InputError(f"{path}: {why}; {hint}")
    try:
        there = os.lstat(path)
    except FileNotFoundError:
        there = None
    except OSError as e:
        raise InputError(f"{path}: cannot listen there: {e.strerror or e}") from e
    if there is not None:
        if stat.S_ISLNK(there.st_mode):
            raise InputError(f"{path}: is a symbolic link; {hint}")
        if not stat.S_ISSOCK(there.st_mode):
            raise InputError(f"{path}: exists and is not a socket; {hint}")
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.settimeout(REQUEST_SECONDS)
            try:
                probe.connect(path)
            except OSError:
                pass
            else:
                raise InputError(f"{path}: a server is already listening there")
    sock = socket.socket(family, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        if there is not None:
            now = os.lstat(path)
            if (now.st_ino, now.st_dev) == (there.st_ino, there.st_dev):
                os.unlink(path)       # still the dead one, not a server just started
        sock.bind(path)
        mine = os.lstat(path)
        sock.listen(64)
    except OSError as e:
        sock.close()
        if e.errno == errno.EADDRINUSE:
            raise InputError(f"{path}: a server is already listening there") from None
        raise InputError(f"{path}: cannot listen there: {e.strerror or e}") from e
    finally:
        os.umask(old)
    return sock, mine


def _read_request(conn) -> bytes:
    """The request, read to its end. A client has REQUEST_SECONDS for all of it: one
    that sends a byte now and then is not sending a request."""
    deadline = time.monotonic() + REQUEST_SECONDS
    raw = bytearray()
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout()
        conn.settimeout(left)
        chunk = conn.recv(1 << 16)
        if not chunk:
            return bytes(raw)
        raw += chunk
        if len(raw) > MAX_REQUEST:
            raise ValueError("request too long")


_UNREAD = {"ok": False, "why": "the server could not read the request"}


def _reply(src: Source, sha: str, raw: bytes, answer) -> dict:
    """The reply to one request: the command's exit code and output, or why not."""
    try:
        req = json.loads(raw.decode("ascii"))
    except (ValueError, RecursionError, MemoryError):
        return dict(_UNREAD)          # not JSON, or nested past what the parser follows
    if not isinstance(req, dict):
        return dict(_UNREAD)
    if req.get("build") != build_id():
        return {"ok": False, "why": "it is a different build of jadart"}
    if req.get("sha256") != sha:
        return {"ok": False, "why": "it holds a different binary"}
    argv, origin, color = req.get("argv"), req.get("origin"), req.get("color")
    path, member, room = req.get("path"), req.get("member"), req.get("room")
    tty = req.get("tty")
    if not (isinstance(argv, list) and all(isinstance(a, str) for a in argv)
            and isinstance(origin, str)
            and isinstance(path, (str, type(None)))
            and isinstance(member, (str, type(None)))
            and isinstance(color, list) and len(color) == 2
            and all(type(c) is bool for c in color)
            and isinstance(tty, list) and len(tty) == 2
            and all(type(t) is bool for t in tty)
            and type(room) is int and 0 < room <= MAX_ROOM):
        return dict(_UNREAD)
    # The client's name for the file, on the server's copy of its bytes: the digest says
    # they are the same bytes, and the name is what the output prints.
    named = Source(data=src.data, origin=origin, path=path, member=member)
    chunks: list = []
    saved = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = _Tap(1, chunks, tty[0]), _Tap(2, chunks, tty[1])
    try:
        code = answer(argv, named, tuple(color), room)
    except Exception:
        # A command that raises past the dispatcher is run again by the client, where
        # the failure is reported the way it would have been without a server.
        return {"ok": False, "why": "the command failed inside the server"}
    finally:
        sys.stdout, sys.stderr = saved
    if code is None:
        return {"ok": False, "why": "the server does not answer that command"}
    out = [[fd, "".join(parts)] for fd, parts in chunks]
    return {"ok": True, "exit": code, "out": out}


def _serve_one(conn, src: Source, sha: str, answer) -> None:
    """One connection: read a request, answer it, send the reply. A request that is
    late, too long or not one costs its sender the answer and the server nothing."""
    try:
        try:
            raw = _read_request(conn)
        except ValueError:
            raw = b""                 # too long to be one
        body = json.dumps(_reply(src, sha, raw, answer)).encode("ascii")
        if len(body) > MAX_REPLY:
            body = json.dumps({"ok": False, "why": "the answer is too long to send"}
                              ).encode("ascii")
        conn.settimeout(REPLY_SECONDS)
        conn.sendall(body)
    except (OSError, ValueError, RecursionError, MemoryError):
        pass                          # the client went away, or was never one


def serve(src: Source, path: str, idle_minutes: float, answer) -> int:
    """Answer commands about `src` on a unix socket at `path` until stopped, or until no
    request has come for `idle_minutes` (0: never).

    `answer(argv, source, color, room)` runs one command line and returns its exit
    code, or None for one this server does not take. It is cli's, so that a served
    command goes through the parser and dispatcher a fresh process uses."""
    import signal
    from . import keep
    from .console import error

    _load_everything()                # before the socket: what it runs is now fixed
    sha = digest(src.data)
    sock, mine = _bind(path)

    def stop(_sig, _frame):
        raise SystemExit(0)

    try:
        keep.open_session(src.data)
        for name in ("SIGTERM", "SIGHUP"):
            if hasattr(signal, name):
                signal.signal(getattr(signal, name), stop)
        wait = f"it stops after {idle_minutes:g} idle minutes" if idle_minutes > 0 \
            else "it runs until stopped"
        error(f"serving {src.label} at {path} (pid {os.getpid()}); {wait}")
        sock.settimeout(idle_minutes * 60 if idle_minutes > 0 else None)
        while True:
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                error(f"no request for {idle_minutes:g} minutes, stopped")
                return 0
            with conn:
                _serve_one(conn, src, sha, answer)
    except KeyboardInterrupt:
        return 0
    finally:
        keep.close_session()
        sock.close()
        try:
            now = os.lstat(path)
            # Only the socket this process made: a second server may have taken the path.
            if (now.st_ino, now.st_dev) == (mine.st_ino, mine.st_dev):
                os.unlink(path)
        except OSError:
            pass
