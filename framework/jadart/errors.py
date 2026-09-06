"""The exception base every jadart failure derives from.

Its own module, and not `__init__.py`, because nine modules raise these and several sit
below the package root in the import order; a base defined at the root would have every
one of them importing upward to reach it.

The contract this exists to make true: a caller can write

    except jadart.JadartError:

and catch everything this library raises on a file it cannot handle, without matching on
messages and without listing nine class names. That was promised in the package docstring
before it was true, a truncated snapshot escaped as `struct.error` and an unrecognised
file as a bare `ValueError`, so a batch scan over a directory of APKs died on the first
bad one no matter how carefully it had been written against the documentation.

Subclasses stay where they are raised. This module only supplies the base, so importing
it costs nothing and creates no cycle.
"""
from __future__ import annotations


class JadartError(Exception):
    """Base for every error jadart raises on input it cannot handle.

    Catch this to mean "jadart could not process this file". Catch a subclass to
    distinguish why: `UnknownEpoch` for a Dart release with no registered grammar,
    `UnsupportedTarget` for a known release on an architecture that has none, `InputError`
    for something that is not a Flutter snapshot at all, `MissingDisassembler` when
    instruction-level work is asked for without capstone.

    An error that is NOT about the input (a bug in this library) is deliberately not a
    subclass, so it keeps its own type and is not swallowed by a `except JadartError` that
    was meant to skip a bad file.
    """


class ContainerError(JadartError):
    """A malformed or unreadable ELF, Mach-O, APK or IPA.

    Lives here rather than in container.py because elf.py and macho.py raise it too, and
    a base defined in the container module would have the readers importing sideways to
    reach it. `jadart.ContainerError` and `jadart.container.ContainerError` are the same
    object, so existing `except` clauses are unaffected.
    """


class InputError(JadartError):
    """The path is not something jadart can work with: not a Flutter app, no snapshot in
    it, or nothing there at all.

    Also defined here rather than in export.py, because the snapshot layer needs to raise
    it for "this file has no Dart snapshot" and cannot import the output layer to do so.
    """


class MissingSymbol(ContainerError):
    """A named symbol is not in this container.

    Its own class because absence is sometimes an answer rather than a failure:
    `parse_libapp` tries the vm and isolate symbols in turn and falls back to a magic
    scan when neither is present, and it must not confuse that with a symbol that IS
    present but points outside the file.
    """
