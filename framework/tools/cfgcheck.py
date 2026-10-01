#!/usr/bin/env python3
"""Check that the structured statement tree describes the SAME control flow as the CFG.

"No block is emitted twice and none is dropped" is necessary and nowhere near sufficient:
a structuring pass can place every block exactly once and still claim an edge that does
not exist, which is the failure mode that matters. This reads the tree back as a program
and asks, for every block, where the RENDERING says control goes next, fall-through to
the next statement, into an arm, round a back edge, out through a break, along a goto,
and compares that set against the block's real successors.

    python3 tools/cfgcheck.py [BINARY]        # 0 violations is the contract
    python3 tools/cfgcheck.py --synthetic     # the exit check on fixed arm32 words

Reported separately:

  edge      a block whose rendered successors are not its real ones
  dropped   a reachable block that reaches no statement
  twice     a block emitted more than once
  exit      an instruction that leaves the function or always branches elsewhere, which
            the tier 2 CFG lets control run on past

The first three compare the rendering against the CFG, so they pass a CFG that is wrong
and rendered faithfully: arm32's `pop {fp, pc}` once had an edge to the code after it in
a quarter of its functions, and every function read 0 violations (#45). The exit check
judges the CFG itself, by capstone's own reading of each word (which registers it writes,
whether it is a call), not by the rules build_cfg uses.
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
                if blk.cexit:
                    # Its raw instruction is not printed, so the `if` that follows has to
                    # hold the exit, or the conditional return is gone from the output.
                    nxt = seq[i + 1] if i + 1 < len(seq) else None
                    if not (nxt and nxt[0] == "if" and nxt[2] and nxt[2][0][0] == "exit"):
                        bad.append((s[1], ["no exit rendered"], sorted(blk.succ)))
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


def _pc_writes(image, cr):
    """{address: (conditional, direct target or None)} for every instruction of the range
    that writes PC without being a call, read by capstone in detail mode."""
    import capstone
    from jadart.disasm import MAX_INSNS
    if image.arch.name == "arm":
        from capstone import arm
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        always, pc_reg = (arm.ARM_CC_AL, arm.ARM_CC_INVALID), arm.ARM_REG_PC
    else:
        from capstone import arm64
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        always = (arm64.ARM64_CC_AL, arm64.ARM64_CC_NV, arm64.ARM64_CC_INVALID)
        pc_reg = None
    md.detail = True
    end = min(len(image.text), cr.pc_offset + (cr.size or 512))
    out = {}
    for i in md.disasm(image.text[cr.pc_offset:end][:MAX_INSNS * 4], cr.pc_offset):
        if i.group(capstone.CS_GRP_CALL):
            continue
        if pc_reg is not None:
            writes = pc_reg in i.regs_access()[1]
        else:
            writes = i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_RET)
        if not writes:
            continue
        cond = i.cc not in always or i.mnemonic in ("cbz", "cbnz", "tbz", "tbnz")
        direct = None
        if i.group(capstone.CS_GRP_BRANCH_RELATIVE) and i.operands:
            direct = i.operands[-1].imm
        out[i.address] = (cond, direct)
    return out


def exit_violations(image, cr, blocks):
    """Where the CFG lets control past an instruction that does not allow it: one that
    writes PC in the middle of a block, one that always leaves (a return, an indirect
    jump, a branch elsewhere) with the next instruction among its block's successors, and
    a conditional return or indirect jump whose block records no exit."""
    where = {}
    for blk in blocks.values():
        for k, ins in enumerate(blk.insns):
            where[ins[0]] = (blk, k == len(blk.insns) - 1)
    bad = []
    for addr, (cond, direct) in _pc_writes(image, cr).items():
        if addr not in where:
            continue
        blk, last = where[addr]
        nxt = addr + 4
        if not last:
            bad.append((addr, "mid-block"))
        elif not cond and nxt in blk.succ and direct != nxt:
            bad.append((addr, "falls through"))
        elif cond and direct is None and not blk.cexit:
            bad.append((addr, "no exit"))
    return bad


def _tier2_cfg(image, dis, pc_to_name, pool_map, with_exits=True):
    """The CFG tier 2 renders, as decompile and export build it."""
    from jadart.branches import exits, row_kinds
    from jadart.cfg import build_cfg
    from jadart.disasm import annotate
    ann = annotate(dis, pc_to_name, pool_map, kinds=row_kinds(image, dis))
    return build_cfg(ann, exits=exits(image, dis) if with_exits else None)[0]


def run(path):
    from jadart.cfg import build_cfg, structure
    from jadart.branches import exits, row_kinds
    from jadart.disasm import (load_instructions, disassemble_range, annotate,
                               build_pool_map, function_name_by_pc)
    from jadart.expr import strip_boilerplate

    image, fr, _hdr = load_instructions(path)
    pc_to_name, pool_map = function_name_by_pc(image, fr), build_pool_map(fr, getattr(image, "arch", None))
    n = edges = dropped = twice = badfn = 0
    worst = None
    exit_bad, exit_first = 0, None
    for cr in image.all_ranges:
        dis = disassemble_range(image, cr)
        if not dis:
            continue
        ex = exit_violations(image, cr, _tier2_cfg(image, dis, pc_to_name, pool_map))
        exit_bad += len(ex)
        if ex and exit_first is None:
            exit_first = ex[0]
        ann = annotate(dis, pc_to_name, pool_map, kinds=row_kinds(image, dis))
        blocks, entry = build_cfg(strip_boilerplate(ann), exits=exits(image, dis))
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
    return n, badfn, edges, dropped, twice, worst, exit_bad, exit_first


#: arm32 words for --synthetic: each range ends at a return or an indirect jump that the
#: mnemonic test missed, conditional or not, and has code after it to run on into.
_A32_RANGES = (
    # cmp r0, #0; bne #0x10; mov r0, #1; pop {fp, pc}; mov r0, #2; pop {fp, pc}
    [0xE3500000, 0x1A000001, 0xE3A00001, 0xE8BD8800, 0xE3A00002, 0xE8BD8800],
    [0xE3500000, 0x012FFF1E, 0xE3A00001, 0xE12FFF1E],   # bxeq lr
    [0xE3500000, 0x18BD8800, 0xE3A00001, 0xE12FFF1E],   # popne {fp, pc}
    [0xE3A00001, 0xE49DF004, 0xE3A00002, 0xE12FFF1E],   # ldr pc, [sp], #4 (pop {pc})
    [0xE3A00001, 0xE8908000, 0xE3A00002, 0xE12FFF1E],   # ldm r0, {pc}
    [0xE3A00001, 0xE1A0F00E, 0xE3A00002, 0xE12FFF1E],   # mov pc, lr
    [0xE3500000, 0x159AF01C, 0xE3A00001, 0xE12FFF1E],   # ldrne pc, [sl, #0x1c]
)


def synthetic():
    """(violations with the exits, violations without them) over _A32_RANGES. The first
    must be 0, and the second must not, or the check could not tell a wrong CFG apart."""
    import struct
    from jadart.disasm import InstrImage, CodeRange, disassemble_range
    words = [w for r in _A32_RANGES for w in r]
    image = InstrImage(text=b"".join(struct.pack("<I", w) for w in words), pcs=[0],
                       first_code=0, code_ranges={}, all_ranges=[], symbol_names={})
    image.arch = type("Arch", (), {"name": "arm", "compressed": False, "word_size": 4})()
    image.anchor_va = None
    at = 0
    for r in _A32_RANGES:
        image.all_ranges.append(CodeRange(pc_offset=at, size=4 * len(r), owner_ref=-1))
        at += 4 * len(r)
    found = [0, 0]
    for cr in image.all_ranges:
        dis = disassemble_range(image, cr)
        for i, with_exits in enumerate((True, False)):
            found[i] += len(exit_violations(image, cr,
                                            _tier2_cfg(image, dis, {}, {}, with_exits)))
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("lib", nargs="?", default=DEFAULT_LIB)
    ap.add_argument("--synthetic", action="store_true",
                    help="run the exit check on fixed arm32 words instead of a binary")
    a = ap.parse_args(argv)
    if a.synthetic:
        good, broken = synthetic()
        print(f"{len(_A32_RANGES)} synthetic arm32 ranges: {good} exit violations; "
              f"{broken} without the exits, which the check has to see")
        return 0 if good == 0 and broken > 0 else 1
    n, badfn, edges, dropped, twice, worst, exit_bad, exit_first = run(a.lib)
    print(f"{n} functions: {edges} edge violations, {dropped} dropped blocks, "
          f"{twice} blocks emitted twice ({badfn} functions affected), "
          f"{exit_bad} exit violations")
    if exit_first:
        print(f"  first exit violation at isolate+0x{exit_first[0]:x}: {exit_first[1]}")
    if worst:
        off, bad, miss, dup = worst
        shown = lambda xs: [hex(x) if isinstance(x, int) else x for x in xs]
        print(f"  first at .text+0x{off:x}: "
              + "; ".join(f"0x{b:x} renders -> {shown(c)} but goes to "
                          f"{shown(r)}" for b, c, r in bad)
              + (f" dropped {[hex(x) for x in miss]}" if miss else "")
              + (f" {dup} duplicated" if dup else ""))
    return 1 if (edges or dropped or twice or exit_bad) else 0


if __name__ == "__main__":
    raise SystemExit(main())
