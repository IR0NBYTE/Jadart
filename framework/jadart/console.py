"""Terminal output helpers for the CLI: optional colour and one error format.

Colour is decided per stream, not once for the process. stdout is usually piped into
grep or a file while stderr stays on the terminal, and each should keep its own answer.
`configure()` is called once from main before any command runs.

The palette is deliberately small. Dim for addresses and comment lines, bold for
headings, red for the error prefix. Nothing else earns a colour.
"""
from __future__ import annotations

import os
import sys

_RESET = "\033[0m"
_STYLES = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
}

# Resolved by configure(). Default off so importing this module never emits escapes.
_out = False
_err = False


def _resolve(mode: str, stream) -> bool:
    """Decide colour for one stream.

    `always` wins over everything, including NO_COLOR, because an explicit flag should
    beat the environment. Otherwise NO_COLOR set to any value at all disables colour,
    which is what the no-color.org convention asks for. TERM=dumb means the terminal
    can't render the escapes, so treat it as not a terminal.
    """
    if mode == "never":
        return False
    if mode == "always":
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        # ValueError covers a stream that has already been closed.
        return False


def configure(mode: str = "auto", stdout=None, stderr=None) -> None:
    """Set colour for both streams. `mode` is auto, always or never."""
    global _out, _err
    _out = _resolve(mode, sys.stdout if stdout is None else stdout)
    _err = _resolve(mode, sys.stderr if stderr is None else stderr)


def enabled(stream_err: bool = False) -> bool:
    return _err if stream_err else _out


def paint(text: str, *styles: str, stream_err: bool = False) -> str:
    """Wrap text in the named styles when the target stream is in colour."""
    if not text or not enabled(stream_err):
        return text
    codes = "".join(_STYLES[s] for s in styles if s in _STYLES)
    return f"{codes}{text}{_RESET}" if codes else text


def bold(text: str) -> str:
    return paint(text, "bold")


def dim(text: str) -> str:
    return paint(text, "dim")


def heading(text: str) -> str:
    """A section title. Printed bold, never decorated with rules or boxes."""
    return paint(text, "bold")


def comment(text: str) -> str:
    """A `//` banner line. These are metadata about the listing, not the listing."""
    return paint(text, "dim")


def error(msg) -> None:
    """Report a failure on stderr as `jadart: <msg>`.

    Every diagnostic in the tool goes through here, so the prefix is spelled once and
    scripts can match on it. Colour covers the prefix only, leaving the message itself
    greppable when stderr is a terminal.
    """
    prefix = paint("jadart:", "bold", "red", stream_err=True)
    print(f"{prefix} {msg}", file=sys.stderr)
