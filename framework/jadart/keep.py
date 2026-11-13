"""What `jadart serve` keeps between two commands on one binary.

A command spends nearly all of its time on work that does not depend on what was asked:
walking the snapshot, the pool map, the dispatch table, the field and cast tables. `lift`
of a 200 byte function on a 26 MB app is 1.35 s of that and 0.004 s of lifting (#352).
A process that answers one command and exits has nowhere to keep it, so nothing is kept
there, and `kept` is then one test of a module global and the call it wraps.

`jadart serve` opens a Session on the bytes it read and answers many commands in one
process. Inside it, a function marked `kept` runs once and hands the same result to every
later call that asks the same question about the same binary.

The answer never leaves the process that worked it out of the bytes. Nothing is written
to disk and nothing is read back, so there is no stored form for a crafted, stale or
foreign file to stand in for.

What may be kept is what no caller changes. Every kept result is read by its callers and
by the lifter and written by none of them (tests/test_core.py compares a kept answer with
a fresh one, command by command). A table a caller does write to is built inside one kept
function per way it is finished: fields.lift_tables takes `accessors` because `lift`
folds accessor names into the field layout and `decompile` does not.

A call is answered from the session only when every argument is one of
  the Source the session was opened on (by its bytes, whatever path named them),
  an object a kept function of this session returned (by identity),
  None, a bool, an int, or an Arch (by value).
Anything else is a question about something the session does not hold: a path, a
signature library, a dict built for one call. It runs as it always has and is not kept,
so a session grows by one entry per kept function and flag, never per request.
"""
from __future__ import annotations

import functools

from .source import Source
from .versions import Arch

_BY_VALUE = (type(None), bool, int, Arch)

#: The open session, or None in every process that is not `jadart serve`.
_live = None


class Session:
    """One binary's kept results. `data` is the snapshot bytes it answers about."""
    __slots__ = ("data", "memo", "own")

    def __init__(self, data: bytes):
        self.data = data
        self.memo: dict = {}
        #: id -> object, for every result handed out. Holding the object is what makes
        #: its id a name: an id is reused once its object is gone.
        self.own: dict = {}

    def _key(self, fn, args, kw):
        key = [fn]
        for name, v in [(None, a) for a in args] + sorted(kw.items()):
            if isinstance(v, _BY_VALUE):
                part = (type(v), v)
            elif isinstance(v, Source):
                if v.data is not self.data:
                    return None
                part = Source
            elif self.own.get(id(v)) is v:
                part = id(v)
            else:
                return None
            key.append((name, part))
        return tuple(key)

    def _adopt(self, out) -> None:
        for o in out if type(out) is tuple else (out,):
            if not isinstance(o, _BY_VALUE):
                self.own[id(o)] = o


def open_session(data: bytes) -> Session:
    """Start keeping results for the snapshot bytes `data`, and for nothing else."""
    global _live
    _live = Session(data)
    return _live


def in_session() -> bool:
    """Whether results are being kept here, which is when the first question may do the
    work of every later one."""
    return _live is not None


def close_session() -> None:
    global _live
    _live = None


def kept(fn):
    """Mark `fn` as work a session does once. Outside a session it is `fn`."""
    @functools.wraps(fn)
    def call(*args, **kw):
        s = _live
        if s is None:
            return fn(*args, **kw)
        key = s._key(fn, args, kw)
        if key is None:
            return fn(*args, **kw)
        if key in s.memo:
            return s.memo[key]
        out = fn(*args, **kw)
        s.memo[key] = out
        s._adopt(out)
        return out
    return call
