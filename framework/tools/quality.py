#!/usr/bin/env python3
"""Measure how READABLE the lifted output is, over a whole image.

`measure.py` checks the snapshot layer is right and `bench.py` checks it is fast. Neither
says anything about the thing a user actually reads. The symptoms below are the ones that
make Tier 3 read like a disassembly rather than like source, and each is countable:

  regline    a line still carrying a bare machine register (`x0`, `d2`, `w5`)
  field      a field rendered by byte offset (`this.field_0x8`)
  ellipsis   a call whose argument list could not be reconstructed, `f(...)`
  goto       an unstructured jump, plus the share of functions that emit one
  rawasm     an instruction the lifter does not model, printed as arm64

Percentages are of all lifted lines, so a change that trades one symptom for another is
visible rather than hidden. `--json` emits the same numbers for scripting, and
`--baseline FILE` prints a before/after table against a saved run.

    python3 tools/quality.py ../flubench/artifacts/clean/lib/arm64-v8a/libapp.so
    python3 tools/quality.py LIB --json -o build/before.json
    python3 tools/quality.py LIB --baseline build/before.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FRAMEWORK = os.path.dirname(HERE)
ROOT = os.path.dirname(FRAMEWORK)
sys.path.insert(0, FRAMEWORK)

DEFAULT_LIB = os.path.join(ROOT, "flubench/artifacts/clean/lib/arm64-v8a/libapp.so")

#: Same spelling the lifter uses for a register token, so "a bare register survived" here
#: and "this is a register operand" there cannot drift apart.
_REG_RE = re.compile(r"\b([wx](?:3[01]|[12]\d|\d)|[ds](?:3[01]|[12]\d|\d))\b")
_GOTO_RE = re.compile(r"\bgoto L_0x")
_FIELD_RE = re.compile(r"\.(?:field_0x[0-9a-fA-F]+|tags)\b")
_ELLIPSIS_RE = re.compile(r"\(\.\.\.\)")
#: A trailing `// ...` is a note the lifter attaches to a statement it DID model, so it
#: has to come off before asking whether the line ends like a statement.
_NOTE_RE = re.compile(r"\s*//.*$")


def is_raw_asm(line: str) -> bool:
    """True when the line is an instruction the lifter did not model.

    A statement the lifter produced on purpose ends in `;`, opens or closes a block, or
    is a label. Anything else is arm64 that fell through to the verbatim fallback."""
    s = _NOTE_RE.sub("", line).strip()
    if not s:
        return False
    return not (s.endswith((";", "{", "}")) or s.endswith(":"))


def measure(path):
    from jadart.disasm import (load_instructions, disassemble_range, annotate,
                               build_pool_map, function_name_by_pc)
    from jadart.expr import lift_function, make_arity_resolver
    from jadart.dispatch import recover_selectors
    from jadart.fields import recover_fields
    from jadart.program import static_function_refs, receiver_for

    image, fr, hdr = load_instructions(path)
    pc_to_name = function_name_by_pc(image, fr)
    pool_map = build_pool_map(fr, getattr(image, "arch", None))
    static_refs = static_function_refs(fr)
    arity = make_arity_resolver(image)
    selectors = recover_selectors(image, fr, hdr)
    layout = recover_fields(fr, getattr(image, "arch", None))

    c = dict(functions=0, lines=0, regline=0, field=0, ellipsis=0, goto=0,
             rawasm=0, goto_funcs=0, label=0)
    for cr in image.all_ranges:
        dis = disassemble_range(image, cr)
        if not dis:
            continue
        body = lift_function(annotate(dis, pc_to_name, pool_map), pool_map,
                             receiver=receiver_for(cr.owner_ref, static_refs),
                             arity=arity, selectors=selectors,
                             arch=getattr(image, "arch", None),
                             fields=layout.for_function(cr.owner_ref))
        c["functions"] += 1
        c["lines"] += len(body)
        had_goto = False
        for ln in body:
            if _REG_RE.search(ln):
                c["regline"] += 1
            if _FIELD_RE.search(ln):
                c["field"] += 1
            if _ELLIPSIS_RE.search(ln):
                c["ellipsis"] += 1
            if _GOTO_RE.search(ln):
                c["goto"] += 1
                had_goto = True
            if ln.strip().startswith("L_0x") and ln.strip().endswith(":"):
                c["label"] += 1
            if is_raw_asm(ln):
                c["rawasm"] += 1
        c["goto_funcs"] += had_goto
    return c


ROWS = [("lines with a bare machine register", "regline", "lines"),
        ("lines with a byte-offset field", "field", "lines"),
        ("lines with an unreconstructed call `(...)`", "ellipsis", "lines"),
        ("goto lines", "goto", "lines"),
        ("functions emitting at least one goto", "goto_funcs", "functions"),
        ("raw arm64 lines", "rawasm", "lines"),
        ("labels defined", "label", "lines")]


def report(c, base=None):
    print(f"functions={c['functions']}  lines={c['lines']}")
    if base:
        print(f"baseline: functions={base['functions']}  lines={base['lines']}")
    w = max(len(t) for t, _, _ in ROWS)
    hdr = f"{'symptom':<{w}} {'count':>9} {'share':>8}"
    if base:
        hdr += f" {'was':>9} {'was%':>8} {'delta':>9}"
    print(hdr)
    for title, key, denom in ROWS:
        n, d = c[key], c[denom]
        line = f"{title:<{w}} {n:>9} {100.0 * n / d:>7.1f}%"
        if base:
            bn, bd = base[key], base[denom]
            bp = 100.0 * bn / bd
            delta = 100.0 * (n - bn) / bn if bn else 0.0
            line += f" {bn:>9} {bp:>7.1f}% {delta:>+8.1f}%"
        print(line)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("lib", nargs="?", default=DEFAULT_LIB)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-o", "--out")
    ap.add_argument("--baseline")
    a = ap.parse_args(argv)
    c = measure(a.lib)
    if a.out:
        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
        with open(a.out, "w") as f:
            json.dump(c, f, indent=1)
    base = None
    if a.baseline and os.path.exists(a.baseline):
        with open(a.baseline) as f:
            base = json.load(f)
    if a.json:
        print(json.dumps(c))
    else:
        report(c, base)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
