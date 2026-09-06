#!/usr/bin/env python3
"""Check that the structured statement tree describes the SAME control flow as the CFG.

"No block is emitted twice and none is dropped" is necessary and nowhere near sufficient:
a structuring pass can place every block exactly once and still claim an edge that does
not exist, which is the failure mode that matters. This reads the tree back as a program
and asks, for every block, where the RENDERING says control goes next, fall-through to
the next statement, into an arm, round a back edge, out through a break, along a goto,
and compares that set against the block's real successors.

    python3 tools/cfgcheck.py [BINARY]        # 0 violations is the contract

Reported separately:

  edge      a block whose rendered successors are not its real ones
  dropped   a reachable block that reaches no statement
  twice     a block emitted more than once
"""
from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FRAMEWORK = os.path.dirname(HERE)
ROOT = os.path.dirname(FRAMEWORK)
sys.path.insert(0, FRAMEWORK)

DEFAULT_LIB = os.path.join(ROOT, "flubench/artifacts/clean/lib/arm64-v8a/libapp.so")

#: Where control goes when a statement list runs off its end without a block: the caller's
#: continuation. `None` means "the function returns / nothing follows", which claims no
#: edge at all.
_END = object()


def _entry(stmts, cont, brk, cont_of_loop):
    """The first thing this statement list transfers control to."""
    for s in stmts:
        k = s[0]
        if k in ("asm", "loop", "goto"):
            return s[1]
        if k == "break":
            return brk
        if k == "continue":
            return cont_of_loop
        if k == "if":                    # only ever preceded by its own `asm`
            return _entry(s[2], cont, brk, cont_of_loop) if s[2] else cont
    return cont


def check_function(blocks, stmts):
    """(edge violations, blocks the tree places) for one structured function."""
    from jadart.cfg import _is_cond
    bad, placed = [], []

    def walk(seq, cont, brk, cont_of_loop):
        i = 0
        while i < len(seq):
            s = seq[i]
            k = s[0]
            if k == "asm":
                placed.append(s[1])
                blk = blocks[s[1]]
                if i + 1 < len(seq) and seq[i + 1][0] == "if":
                    _, _cond, then, els = seq[i + 1]
                    after = _entry(seq[i + 2:], cont, brk, cont_of_loop)
                    claimed = {_entry(then, after, brk, cont_of_loop),
                               _entry(els, after, brk, cont_of_loop)}
                    if claimed != set(blk.succ):
                        bad.append((s[1], sorted(x for x in claimed if x is not None),
                                    sorted(blk.succ)))
                    walk(then, after, brk, cont_of_loop)
                    walk(els, after, brk, cont_of_loop)
                    i += 2
                    continue
                nxt = _entry(seq[i + 1:], cont, brk, cont_of_loop)
                claimed = set() if not blk.succ else {nxt}
                if claimed - {None} != set(blk.succ):
                    bad.append((s[1], sorted(x for x in claimed if x is not None),
                                sorted(blk.succ)))
            elif k == "loop":
                after = _entry(seq[i + 1:], cont, brk, cont_of_loop)
                # falling off the end of a loop body is the back edge to its header
                walk(s[2], s[1], after, s[1])
            i += 1

    walk(stmts, None, None, None)
    return bad, placed


def run(path):
    from jadart.cfg import build_cfg, structure
    from jadart.disasm import (load_instructions, disassemble_range, annotate,
                               build_pool_map, function_name_by_pc)
    from jadart.expr import strip_boilerplate

    image, fr, _hdr = load_instructions(path)
    pc_to_name, pool_map = function_name_by_pc(image, fr), build_pool_map(fr, getattr(image, "arch", None))
    n = edges = dropped = twice = badfn = 0
    worst = None
    for cr in image.all_ranges:
        dis = disassemble_range(image, cr)
        if not dis:
            continue
        blocks, entry = build_cfg(strip_boilerplate(annotate(dis, pc_to_name, pool_map)))
        if not blocks:
            continue
        n += 1
        bad, placed = check_function(blocks, structure(blocks, entry))
        reach, stack = set(), [entry]
        while stack:
            b = stack.pop()
            if b in reach or b not in blocks:
                continue
            reach.add(b)
            stack.extend(blocks[b].succ)
        miss = reach - set(placed)
        dup = len(placed) - len(set(placed))
        if bad or miss or dup:
            badfn += 1
            if worst is None:
                worst = (cr.pc_offset, bad[:3], sorted(miss)[:3], dup)
        edges += len(bad)
        dropped += len(miss)
        twice += dup
    return n, badfn, edges, dropped, twice, worst


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("lib", nargs="?", default=DEFAULT_LIB)
    a = ap.parse_args(argv)
    n, badfn, edges, dropped, twice, worst = run(a.lib)
    print(f"{n} functions: {edges} edge violations, {dropped} dropped blocks, "
          f"{twice} blocks emitted twice ({badfn} functions affected)")
    if worst:
        off, bad, miss, dup = worst
        print(f"  first at .text+0x{off:x}: "
              + "; ".join(f"0x{b:x} renders -> {[hex(x) for x in c]} but goes to "
                          f"{[hex(x) for x in r]}" for b, c, r in bad)
              + (f" dropped {[hex(x) for x in miss]}" if miss else "")
              + (f" {dup} duplicated" if dup else ""))
    return 1 if (edges or dropped or twice) else 0


if __name__ == "__main__":
    raise SystemExit(main())
