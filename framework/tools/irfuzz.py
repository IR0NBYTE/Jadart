#!/usr/bin/env python3
"""Differential execution: check jadart's value DAG against a real arm64 CPU.

THE ASSUMPTION THIS REFUTES. jadart's snapshot layer self-validates byte-exactly, so a
wrong cluster grammar fails loudly. The machine-code layer was held to have no equivalent,
and that asymmetry is what capped the project's own estimate of how good the decompiler
could get: a wrong idiom rule there produces plausible WRONG source rather than a visible
failure, and nothing catches it.

But an oracle does exist. Build the same block twice, once as instructions run on an
emulated CPU, once as a value DAG evaluated symbolically, put random values in the input
registers, and compare the results bit-exactly. If the DAG says a block computes something
the CPU does not, that is a defect, not a matter of taste.

WHAT IT CANNOT CHECK, stated because a partial oracle sold as a total one is worse than
none:

  * anything about DISPLAY. Whether `x0 = a + b` reads well is not a question with a
    bit-exact answer.
  * Smi-tag elimination, and any other rewrite that deliberately changes the value.
    Rendering `x >> 1` as `x` is the whole point of that pass and the emulator will
    rightly disagree. Those must be marked as reinterpretations and fuzzed against the
    pre-reinterpretation graph.
  * CALLS. A `bl` can write any memory and return anything, and neither is a claim the
    lifter makes, so there is nothing to compare. Memory used to be on this list with
    them, and that was the wrong lesson drawn from a true observation: a real Dart
    function with several blocks also calls out, but a GENERATED one does not have to.
    See `--mem` and `--cfgmem`.

THE OTHER LIFTER. jadart has two, and for a while only one of them was under an oracle.
ir.py/lower.py build the value DAG that everything above checks, but `jadart export` does
not go through it: expr.py lifts straight into pseudo-Dart text, and that is the code
whose output a user acts on. So the same trick is applied one level up, lift real runs
with expr.py and EVALUATE THE TEXT IT PRINTED against the CPU. That pass found `30 - x1 - 2`
where the hardware computes `30 - (x1 - 2)`.

Needs `pip install unicorn`. Without it the harness reports that it was skipped rather
than passing vacuously.

CONTROL FLOW. Fuzzing one block at a time cannot see the failure that matters most across
a whole function: a value the walker carries into a block along a path the machine did not
take. The third oracle GENERATES functions, random arithmetic in random blocks, wired by
forward branches only so they always terminate, lifts them, and evaluates what the text
claims against the CPU. It reproduces the goto-join defect on the lifter that had it.

MEMORY, and FLOATING POINT. Both were excluded from the sample rather than checked, and
both are places a wrong value can live undetected. `--mem` generates load/store runs over
one object and INTERPRETS the printed statements in order against an emulated CPU with
real memory behind it; `--cfgmem` does the same for whole generated control-flow graphs,
so a field expression that survives a join or a back edge is decided rather than assumed.
Between them they found four defects: a value loaded before a store to the same field kept
printing as a read of that field, a group of assignments read the values the group itself
had just written, a phi assignment redefined a register that earlier expressions still
named, and a join left a register bare after the body had already assigned that name. The
first two are fixed here; the last two only exist while a phi writes a MACHINE register,
and the join naming below retired that, so they are now unreachable rather than patched.
`--fp` fuzzes the scalar-double runs the compiler really emits; a Python float is an
IEEE-754 binary64, so that comparison is bit-exact.

AND IT RUNS THE BODY, not only the expressions in it. Scoring a printed value means
folding each `var tN = ...` back into its use, which works for a name assigned ONCE and
gives up on every name assigned twice, which is every phi. So when the lifter started
naming the value an `if`-join produces, the join stopped being scored at all and the
harness went on reporting zero mismatches: a green number covering the exact change that
had just landed. `--cfg` now also parses the printed body as a small program and executes
it on the same inputs the emulator got. It refuses the renderings that are not programs (a
`goto`, or a block the CFG cannot reach but `structure` prints anyway), and scores only
what the run assigned plus the value it returned, because a body that reads x11 and returns
makes no claim about x6. Reading a `var` the run never assigned is counted as a DEFECT
rather than a refusal; that is what catches a join name bound on one path only.

    python3 tools/irfuzz.py                # the built-in instruction set, 200 trials each
    python3 tools/irfuzz.py --trials 2000
    python3 tools/irfuzz.py --corpus BIN --runs 3000     # real code, every oracle
    python3 tools/irfuzz.py --cfg 500                    # generated control flow only
    python3 tools/irfuzz.py --mem 500                    # generated loads and stores
    python3 tools/irfuzz.py --cfgmem 500                 # both, printed text interpreted
    python3 tools/irfuzz.py --fp BIN                     # real scalar-double runs
"""
from __future__ import annotations

import argparse
import os
import random
import re
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from jadart.ir import Graph, evaluate, mask   # noqa: E402

BASE = 0x100000
XREGS = 8          # x0..x7 are enough to express every shape worth fuzzing


def _unicorn():
    try:
        import unicorn
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN
        from unicorn import arm64_const
        return unicorn, Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, arm64_const
    except Exception:
        return None


#: (encoding word, what capstone must decode it to, how to build the same value).
#: The encodings are hardcoded so the harness needs only unicorn, and they are VERIFIED
#: with capstone before anything runs, two of the fifteen were wrong when first written
#: (`lsl w0,w1,#9` was an off-by-one in imms and decoded as `ubfx`, and
#: `sbfx x0,x1,#1,#31` decoded as `sxtw`), and without the check the harness would have
#: cheerfully fuzzed the wrong instruction and reported a pass.
CASES = [
    (0x8B020020, "add x0, x1, x2",          lambda g, r: g.binop("+", r("x1"), r("x2"))),
    (0xCB020020, "sub x0, x1, x2",          lambda g, r: g.binop("-", r("x1"), r("x2"))),
    (0x8A020020, "and x0, x1, x2",          lambda g, r: g.binop("&", r("x1"), r("x2"))),
    (0xAA020020, "orr x0, x1, x2",          lambda g, r: g.binop("|", r("x1"), r("x2"))),
    (0xCA020020, "eor x0, x1, x2",          lambda g, r: g.binop("^", r("x1"), r("x2"))),
    (0x9B027C20, "mul x0, x1, x2",          lambda g, r: g.binop("*", r("x1"), r("x2"))),
    (0xD37DF020, "lsl x0, x1, #3",          lambda g, r: g.binop("<<", r("x1"), g.const(3))),
    (0xD347FC20, "lsr x0, x1, #7",          lambda g, r: g.binop(">>", r("x1"), g.const(7))),
    (0x9345FC20, "asr x0, x1, #5",          lambda g, r: g.binop(">>s", r("x1"), g.const(5))),
    (0x8B021020, "add x0, x1, x2, lsl #4",  lambda g, r: g.binop(
        "+", r("x1"), g.binop("<<", r("x2"), g.const(4)))),
    (0xCB420820, "sub x0, x1, x2, lsr #2",  lambda g, r: g.binop(
        "-", r("x1"), g.binop(">>", r("x2"), g.const(2)))),
    # 32-bit destinations. The top half must be CLEARED, which is exactly what canon()'s
    # w -> x folding erases, at 59,073 sites on the corpus binary.
    (0x0B020020, "add w0, w1, w2",          lambda g, r: g.ext(
        "zext", g.binop("+", g.ext("trunc", r("x1"), 32),
                        g.ext("trunc", r("x2"), 32), 32), 64)),
    (0x0A020020, "and w0, w1, w2",          lambda g, r: g.ext(
        "zext", g.binop("&", g.ext("trunc", r("x1"), 32),
                        g.ext("trunc", r("x2"), 32), 32), 64)),
    (0x53175820, "lsl w0, w1, #9",          lambda g, r: g.ext(
        "zext", g.binop("<<", g.ext("trunc", r("x1"), 32), g.const(9, 32), 32), 64)),
    # the Smi untag jadart already models: bits [31:1], sign-extended
    (0x93417C20, "sbfx x0, x1, #1, #0x1f",  lambda g, r: g.ext(
        "sext", g.ext("trunc", g.binop(">>", r("x1"), g.const(1)), 31), 64)),
]


def verify_encodings() -> list:
    """Assert every hardcoded word decodes to the instruction it claims.

    Without this the harness can silently fuzz a different instruction than the one the
    DAG models and report a clean pass, which is the exact failure mode the whole oracle
    exists to prevent."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    bad = []
    for word, want, _b in CASES:
        got = [f"{i.mnemonic} {i.op_str}"
               for i in md.disasm(struct.pack("<I", word), BASE)]
        actual = got[0] if got else "<undecodable>"
        if actual != want:
            bad.append((want, actual))
    return bad


def run(trials: int, seed: int, verbose: bool) -> int:
    uc_mod = _unicorn()
    if uc_mod is None:
        print("SKIP: unicorn is not installed (pip install unicorn); no oracle available")
        return 0
    _unic, Uc, ARCH, MODE, a64 = uc_mod

    bad = verify_encodings()
    if bad:
        for want, actual in bad:
            print(f"BAD ENCODING: claimed {want!r}, decodes to {actual!r}")
        return 1

    regs = [getattr(a64, f"UC_ARM64_REG_X{i}") for i in range(XREGS)]
    rng = random.Random(seed)
    failures = checked = 0

    for word, asm, build in CASES:
        code = struct.pack("<I", word)
        g = Graph()
        cache = {}

        def r(name, _c=cache, _g=g):
            if name not in _c:
                _c[name] = _g.reg(name, 64)
            return _c[name]

        node = build(g, r)
        mismatched = False

        for _ in range(trials):
            env = {f"x{i}": rng.getrandbits(64) for i in range(XREGS)}
            mu = Uc(ARCH, MODE)
            mu.mem_map(BASE, 0x1000)
            mu.mem_write(BASE, code)
            for i in range(XREGS):
                mu.reg_write(regs[i], env[f"x{i}"])
            mu.emu_start(BASE, BASE + len(code))
            want = mu.reg_read(regs[0]) & mask(64)
            got = evaluate(node, env) & mask(64)
            checked += 1
            if got != want:
                failures += 1
                mismatched = True
                if failures <= 5:
                    ins = " ".join(f"x{i}={env[f'x{i}']:#018x}" for i in range(3))
                    print(f"MISMATCH {asm}\n  in  {ins}\n  cpu {want:#018x}\n  ir  {got:#018x}")
                break
        if verbose and not mismatched:
            print(f"  ok  {asm:<28} x{trials}")

    print(f"\n{len(CASES)} instructions, {checked} random comparisons, "
          f"{failures} mismatches")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--trials", type=int, default=200)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--corpus", metavar="BINARY",
                    help="also fuzz real straight-line runs lifted out of this binary")
    ap.add_argument("--runs", type=int, default=300,
                    help="how many real runs to sample with --corpus")
    ap.add_argument("--cfg", type=int, metavar="N",
                    help="fuzz N generated control-flow graphs and nothing else")
    ap.add_argument("--mem", type=int, metavar="N",
                    help="fuzz N generated load/store runs and nothing else")
    ap.add_argument("--fp", metavar="BINARY",
                    help="fuzz the scalar-double runs of this binary and nothing else")
    ap.add_argument("--cfgmem", type=int, metavar="N",
                    help="fuzz N generated control-flow graphs WITH memory, by "
                         "interpreting the printed program, and nothing else")
    ap.add_argument("--seed-outputs", action="store_true",
                    help="with --cfgmem: load every destination register from memory "
                         "before the graph runs, so a loop-carried value has a decidable "
                         "start and the write-back defects become scoreable")
    a = ap.parse_args()
    if a.cfg is not None:
        return run_cfg(a.cfg, max(a.trials // 4, 25), a.seed, a.verbose)
    if a.mem is not None:
        return run_mem(a.mem, max(a.trials // 4, 25), a.seed, a.verbose)
    if a.cfgmem is not None:
        return run_cfgmem(a.cfgmem, max(a.trials // 4, 25), a.seed, a.verbose,
                          seed_outs=a.seed_outputs)
    if a.fp:
        return run_fp(a.fp, a.runs, max(a.trials // 4, 25), a.seed, a.verbose)
    rc = run(a.trials, a.seed, a.verbose)
    if a.corpus:
        print()
        rc |= run_corpus(a.corpus, a.runs, max(a.trials // 4, 25), a.seed, a.verbose)
        print()
        rc |= run_expr(a.corpus, a.runs, max(a.trials // 4, 25), a.seed, a.verbose)
        print()
        rc |= run_fp(a.corpus, a.runs, max(a.trials // 4, 25), a.seed, a.verbose)
        print()
        # Generated, so it does not read the corpus binary; sized off the same flag so one
        # command covers all three and a caller cannot run two of them by accident.
        rc |= run_cfg(max(a.runs // 4, 100), max(a.trials // 4, 25), a.seed, a.verbose)
        print()
        rc |= run_mem(max(a.runs // 4, 100), max(a.trials // 4, 25), a.seed, a.verbose)
        print()
        rc |= run_cfgmem(max(a.runs // 4, 100), max(a.trials // 4, 25), a.seed, a.verbose)
    return rc




# ---------------------------------------------------------------------------
# Fuzzing REAL code, which is the point
# ---------------------------------------------------------------------------

def corpus_cases(path: str, want: int, min_len: int = 3):
    """Straight-line runs of real instructions the lowering claims to model completely.

    Synthetic cases test the rules I thought to write. This tests the ones the compiler
    actually emits, in the combinations it actually emits them, which is where a lowering
    is wrong in ways nobody thought to check.
    """
    import struct as _s
    from jadart.disasm import load_instructions, disassemble_range
    from jadart.lower import lower_block, _reg, RESERVED

    image, _fr, _h = load_instructions(path)
    out = []       # (run, code bytes), arm64 is fixed-width, so the bytes are exact
    for cr in image.all_ranges:
        if len(out) >= want:
            break
        try:
            dis = disassemble_range(image, cr, max_insns=64)
        except Exception:
            continue
        run = []
        for ins in dis:
            addr, mn, op = ins
            probe = lower_block([ins])
            d = _reg(op.split(",")[0]) if op else None
            usable = (probe.skipped == 0 and not probe.opaque and d is not None
                      and d[0] not in RESERVED)
            if usable:
                run.append(ins)
                continue
            if len(run) >= min_len:
                out.append((run, _bytes_for(image, run)))
                if len(out) >= want:
                    break
            run = []
        if len(run) >= min_len:
            out.append((run, _bytes_for(image, run)))
    return out


def _bytes_for(image, run):
    """The original encodings, straight out of the instructions image.

    Every arm64 instruction is exactly four bytes at its pc_offset, so this is the real
    encoding rather than a re-assembly, which matters, because re-assembling would test
    an instruction the binary does not contain."""
    return b"".join(image.text[a:a + 4] for a, _m, _o in run)


def run_corpus(path: str, want: int, trials: int, seed: int, verbose: bool) -> int:
    uc_mod = _unicorn()
    if uc_mod is None:
        print("SKIP: unicorn is not installed")
        return 0
    _u, Uc, ARCH, MODE, a64 = uc_mod
    from jadart.lower import lower_block
    from jadart.ir import Graph

    cases = corpus_cases(path, want)
    if not cases:
        print("no fully-modelled straight-line runs found")
        return 0

    # x0..x28 so real register numbers land somewhere; the reserved ones are never
    # written by a modelled instruction, so seeding them is harmless.
    idx = list(range(29))
    regs = {i: getattr(a64, f"UC_ARM64_REG_X{i}") for i in idx}
    rng = random.Random(seed)
    failures = checked = insns = 0

    for run, code in cases:
        if not code or len(code) != 4 * len(run):
            continue
        lo = lower_block(run, Graph())
        watched = [r for r in lo.regs if r.startswith("x") and r[1:].isdigit()
                   and int(r[1:]) < 29 and r not in lo.opaque]
        if not watched:
            continue
        insns += len(run)
        bad = False
        for _ in range(trials):
            env = {f"x{i}": rng.getrandbits(64) for i in idx}
            mu = Uc(ARCH, MODE)
            mu.mem_map(BASE, 0x10000)
            mu.mem_write(BASE, code)
            for i in idx:
                mu.reg_write(regs[i], env[f"x{i}"])
            mu.emu_start(BASE, BASE + len(code))
            for name in watched:
                want_v = mu.reg_read(regs[int(name[1:])]) & mask(64)
                got_v = evaluate(lo.regs[name], env) & mask(64)
                checked += 1
                if got_v != want_v:
                    failures += 1
                    bad = True
                    if failures <= 5:
                        print(f"MISMATCH in a {len(run)}-instruction run, {name}")
                        for a, m, o in run:
                            print(f"    {m} {o}")
                        print(f"  cpu {want_v:#018x}\n  ir  {got_v:#018x}")
                    break
            if bad:
                break
        if verbose and not bad:
            print(f"  ok  {len(run):>2} insns, {len(watched)} regs")

    print(f"\n{len(cases)} real straight-line runs ({insns} instructions), "
          f"{checked} register comparisons, {failures} mismatches")
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# The SECOND lifter. jadart has two, and only one of them was under an oracle.
# ---------------------------------------------------------------------------
#
# ir.py/lower.py build a value DAG, and everything above fuzzes that. But `jadart export`
# does not go through it: expr.py lifts straight from the instruction text into pseudo-Dart
# by abstract interpretation over a register map, and that is the code whose output a user
# reads. Its rules were checked by reading them.
#
# So the same trick applies one level up. Take real straight-line runs, lift them with
# expr.py, and EVALUATE THE TEXT IT PRINTED against random inputs on an emulated CPU. If
# `x1 * 31 + x2` is what the tool prints, then feeding numbers into that string has to
# produce what the hardware produces.
#
# The evaluator works in exact Python integers and refuses trials it cannot decide rather
# than guessing, which is what keeps it from reporting a false mismatch against a rendering
# that is deliberately approximate. Two of those approximations are documented in expr.py
# and are visible here: `>>` stands for both lsr and asr, and `<` for both signed and
# unsigned, so a trial where any operand of a shift, comparison or division falls outside
# an unsigned 64-bit range is skipped, the text genuinely does not say which was meant.
# Bitwise and additive operators need no such care: their low 64 bits depend only on the
# low 64 bits of their inputs, so masking once at the end is exact.

#: Instructions whose printed form is a value-preserving reading of what the CPU does.
#:
#: The DELIBERATE reinterpretations are absent, and a run splits at one rather than
#: running through it: `sbfiz xD, xS, #1` prints as plain `xS` because that is the Smi tag
#: and showing it helps nobody, `sbfx xD, xS, #1, #31` prints as `xS >> 1`, and the
#: sign/zero extensions print as the value they extend. Fuzzing those against the hardware
#: would report the rewrite working as designed as a defect, which is how a partial oracle
#: gets switched off.
_PURE = frozenset({
    "mov", "movz", "movk", "movn", "mvn", "neg", "add", "sub", "mul", "madd", "msub",
    "mneg", "sdiv", "and", "orr", "eor", "lsl", "lsr", "asr", "ubfx",
    "cmp", "cmn", "tst", "subs", "adds",
    "ands", "csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv", "cneg",
})

#: An operand modifier that expr.py folds away with the width conversion it stands for.
_EXTEND_MODS = ("sxtw", "uxtw", "sxth", "uxth", "sxtb", "uxtb", "sxtx", "uxtx")

#: Role registers, so a run that reads one still evaluates. expr.py prints these by name.
_ROLE_ENV = {"SP": "x15", "FP": "x29", "LR": "x30", "THR": "x26", "PP": "x27",
             "HEAP": "x28", "NULL": "x22", "DISPATCH": "x21"}


class _Undecidable(Exception):
    """The printed text does not say enough to decide this trial."""


def _texpr(text: str) -> str:
    """The lifted text as a Python expression. `~/` and `?:` have no Python spelling."""
    out = text.replace("~/", "//")
    depth = 0
    for i, ch in enumerate(out):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "?" and depth == 0:
            head, rest = out[:i], out[i + 1:]
            d2 = 0
            for j, c2 in enumerate(rest):
                if c2 == "(":
                    d2 += 1
                elif c2 == ")":
                    d2 -= 1
                elif c2 == ":" and d2 == 0:
                    return f"({_texpr(rest[:j])}) if ({_texpr(head)}) else ({_texpr(rest[j + 1:])})"
            raise _Undecidable("unbalanced ternary")
    return out


_U64 = (1 << 64) - 1


def _in_range(*vals):
    for v in vals:
        if v < 0 or v > _U64:
            raise _Undecidable("operand outside an unsigned 64-bit range")


def _ev(node, env):
    import ast
    if isinstance(node, ast.Expression):
        return _ev(node.body, env)
    if isinstance(node, ast.Constant):
        if not isinstance(node.value, int):
            raise _Undecidable("non-integer literal")
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in env:
            raise _Undecidable(f"unknown name {node.id}")
        return env[node.id]
    if isinstance(node, ast.UnaryOp):
        v = _ev(node.operand, env)
        if isinstance(node.op, ast.USub):
            return -v
        if isinstance(node.op, ast.Invert):
            return ~v
        raise _Undecidable("unary operator")
    if isinstance(node, ast.IfExp):
        return _ev(node.body, env) if _ev(node.test, env) else _ev(node.orelse, env)
    if isinstance(node, ast.Compare):
        if len(node.ops) != 1:
            raise _Undecidable("chained comparison")
        a, b = _ev(node.left, env), _ev(node.comparators[0], env)
        _in_range(a, b)
        op = node.ops[0]
        # Equality is the same question signed or unsigned, so only the ORDERING
        # comparisons have to decline. That matters for the interpreter below: every
        # condition it has to follow to take the machine's path comes from a cbz/cbnz and
        # reads `== 0`, and refusing those would leave it unable to decide any branch.
        if (not isinstance(op, (ast.Eq, ast.NotEq))
                and (a >= 1 << 63 or b >= 1 << 63)):   # signedness is not in the text
            raise _Undecidable("signed or unsigned comparison")
        for kind, fn in ((ast.Eq, lambda: a == b), (ast.NotEq, lambda: a != b),
                         (ast.Lt, lambda: a < b), (ast.LtE, lambda: a <= b),
                         (ast.Gt, lambda: a > b), (ast.GtE, lambda: a >= b)):
            if isinstance(op, kind):
                return fn()
        raise _Undecidable("comparison operator")
    if isinstance(node, ast.BinOp):
        a, b = _ev(node.left, env), _ev(node.right, env)
        op = node.op
        if isinstance(op, ast.Add):
            return a + b
        if isinstance(op, ast.Sub):
            return a - b
        if isinstance(op, ast.Mult):
            return a * b
        if isinstance(op, ast.BitAnd):
            return a & b
        if isinstance(op, ast.BitOr):
            return a | b
        if isinstance(op, ast.BitXor):
            return a ^ b
        if isinstance(op, ast.LShift):
            _in_range(b)
            if b >= 64:
                raise _Undecidable("shift amount")
            return a << b
        if isinstance(op, ast.RShift):
            _in_range(a, b)
            if a >= 1 << 63:                  # lsr and asr are both printed `>>`
                raise _Undecidable("logical or arithmetic shift right")
            if b >= 64:
                raise _Undecidable("shift amount")
            return a >> b
        if isinstance(op, ast.FloorDiv):
            _in_range(a, b)                   # `~/` truncates, Python floors
            if a >= 1 << 63 or b >= 1 << 63:
                raise _Undecidable("signed or unsigned division")
            if b == 0:
                raise _Undecidable("division by zero")
            return a // b
    raise _Undecidable("unsupported syntax")


def expr_cases(path: str, want: int, min_len: int = 3):
    """Straight-line runs of pure register arithmetic, as (run, code bytes).

    Only x-register forms. `canon()` folds the w view onto the x view on purpose, which
    erases the 32-bit truncation, a documented display choice, and not something an
    oracle over 64-bit registers can or should adjudicate.
    """
    from jadart.disasm import load_instructions, disassemble_range

    image, _fr, _h = load_instructions(path)
    out, run = [], []

    def usable(mn, op):
        # `sp` is excluded, not fuzzed: jadart canonicalises the hardware stack pointer
        # onto x15 because Dart AOT keeps its own SP there (constants_arm64.h), and on the
        # emulator those are two different registers. That conflation is a statement about
        # the calling convention, not about arithmetic, and this oracle cannot judge it.
        # x28 is HEAP_BASE, and `add xD, xN, x28, lsl #32` is pointer decompression,
        # which expr.py prints as the pointer. Another deliberate reinterpretation.
        if mn not in _PURE or "[" in op or re.search(r"\b([wx]?sp|[wx]28)\b", op):
            return False
        for t in op.split(","):
            t = t.strip().lstrip("#")
            if t.split()[0].lower() in _EXTEND_MODS if t else False:
                return False
            if t[:1] in ("w", "s", "d", "q", "v") and t[1:].split(".")[0].isdigit():
                return False
        return True

    for cr in image.all_ranges:
        if len(out) >= want:
            break
        try:
            dis = disassemble_range(image, cr, max_insns=64)
        except Exception:
            continue
        run = []
        for addr, mn, op in dis:
            if usable(mn, op):
                run.append((addr, mn, op))
                continue
            if len(run) >= min_len:
                out.append((run, _bytes_for(image, run)))
                if len(out) >= want:
                    break
            run = []
        if len(run) >= min_len:
            out.append((run, _bytes_for(image, run)))
    return out


def run_expr(path: str, want: int, trials: int, seed: int, verbose: bool) -> int:
    import ast
    uc_mod = _unicorn()
    if uc_mod is None:
        print("SKIP: unicorn is not installed")
        return 0
    _u, Uc, ARCH, MODE, a64 = uc_mod
    from jadart.cfg import Block
    from jadart.expr import Lifter, State

    cases = expr_cases(path, want)
    if not cases:
        print("no pure-arithmetic runs found")
        return 0

    idx = list(range(31))
    regs = {i: getattr(a64, f"UC_ARM64_REG_X{i}") for i in idx}
    rng = random.Random(seed)
    failures = checked = skipped = insns = 0
    covered = {}

    for run, code in cases:
        if not code or len(code) != 4 * len(run):
            continue
        blk = Block(addr=run[0][0], insns=[(a, m, o, "") for a, m, o in run],
                    succ=[], term=run[-1][1])
        lif = Lifter({blk.addr: blk})
        st = State()
        lines, _f = lif._lift_block(blk.addr, st)
        if lines:
            continue                      # emitted a statement: not a pure value run
        watched = sorted(r for r in st.reg if r[:1] == "x" and r[1:].isdigit()
                         and int(r[1:]) < 31)
        if not watched:
            continue
        trees = {}
        for r in watched:
            try:
                trees[r] = ast.parse(_texpr(st.reg[r].text), mode="eval")
            except (_Undecidable, SyntaxError):
                pass
        if not trees:
            continue
        insns += len(run)
        for _a, m, _o in run:
            covered[m] = covered.get(m, 0) + 1
        bad = False
        for _ in range(trials):
            env = {f"x{i}": rng.getrandbits(64) for i in idx}
            env["xzr"] = 0
            for name, reg in _ROLE_ENV.items():
                env[name] = env[reg]
            mu = Uc(ARCH, MODE)
            mu.mem_map(BASE, 0x1000)
            mu.mem_write(BASE, code)
            for i in idx:
                mu.reg_write(regs[i], env[f"x{i}"])
            mu.emu_start(BASE, BASE + len(code))
            for r, tree in trees.items():
                try:
                    got = _ev(tree, env) & mask(64)
                except _Undecidable:
                    skipped += 1
                    continue
                want_v = mu.reg_read(regs[int(r[1:])]) & mask(64)
                checked += 1
                if got != want_v:
                    failures += 1
                    bad = True
                    if failures <= 5:
                        print(f"MISMATCH expr, {r} = {st.reg[r].text}")
                        for a, m, o in run:
                            print(f"    {m} {o}")
                        print(f"  cpu {want_v:#018x}  txt {got:#018x}")
                    break
            if bad:
                break
        if verbose and not bad:
            print(f"  ok  {len(run):>2} insns, {len(trees)} expressions")

    top = ", ".join(f"{m}x{n}" for m, n in sorted(covered.items(), key=lambda kv: -kv[1])[:14])
    print(f"\n{len(cases)} pure-arithmetic runs ({insns} instructions), "
          f"{checked} printed expressions evaluated, {skipped} undecidable, "
          f"{failures} mismatches")
    print(f"  covering: {top}")
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# Fuzzing SCALAR FLOATING POINT, which nothing above samples
# ---------------------------------------------------------------------------
#
# `expr_cases` throws away any run with an s/d/q/v operand, so the whole FP path in
# expr.py has been checked by reading and by nothing else. That is not a safe place for it
# to be: the scalar-FP arithmetic sits at a SEPARATE call site from the integer arithmetic
# and has already diverged from it once. When `_bin` learned to wrap its right operand,
# the integer half was fixed and the FP half was not, so `fsub d0, d1, d2` with d2 holding
# `d3 - d4` printed `d1 - d3 - d4`, four terms where the hardware computes three. That
# was found by reading. Nothing would have found the next one.
#
# It is a well-posed oracle and does not need a single approximation. A Python float IS an
# IEEE-754 binary64, and `+ - * /` and `sqrt` are correctly rounded in both, so the printed
# text and the register agree BIT for bit or the rendering is wrong. Only the two places
# where Python declines what the hardware defines, division by zero and the square root
# of a negative, are skipped, and they are the evaluator's limits, not the tool's.
#
# REAL runs, not generated ones. The corpus has 152 two-instruction and 52 three-plus
# scalar-double runs, up to one of 35, and that is what the compiler actually emits.

#: Scalar-double instructions whose printed form is a value-preserving reading of what the
#: CPU does. `fcvt` (a precision change rendered as the same value), `scvtf`/`fcvtz*` (the
#: int/double conversions) and `fmov` between banks are deliberate reinterpretations and
#: are excluded for the reason the Smi tag is.
_FP_PURE = frozenset({"fadd", "fsub", "fmul", "fdiv", "fneg", "fabs", "fsqrt", "fmov"})
_DREG_RE = re.compile(r"^d(?:3[01]|[12]\d|\d)$")


def fp_cases(path: str, want: int, min_len: int = 2):
    """Straight-line runs of scalar-double arithmetic, as (run, code bytes).

    Only bare `d` registers. An `s` operand is single precision, which `canon` folds onto
    the d view, `s0` is the low half of `d0` the way `w0` is of `x0`, except that for
    floating point the two are not the same NUMBER, and fuzzing that fold would be asking
    this oracle to adjudicate a display choice. It is moot on real code in any case: across
    the corpus binary and three shipped apps the only `s`-register instruction the compiler
    emits is `fcvt`, and there is no scalar single-precision arithmetic at all.
    """
    from jadart.disasm import load_instructions, disassemble_range

    image, _fr, _h = load_instructions(path)
    out = []

    def usable(mn, op):
        if mn not in _FP_PURE or not op:
            return False
        return all(_DREG_RE.match(t.strip()) for t in op.split(","))

    for cr in image.all_ranges:
        if len(out) >= want:
            break
        try:
            dis = disassemble_range(image, cr, max_insns=200)
        except Exception:
            continue
        run = []
        for addr, mn, op in dis:
            if usable(mn, op):
                run.append((addr, mn, op))
                continue
            if len(run) >= min_len:
                out.append((run, _bytes_for(image, run)))
                if len(out) >= want:
                    break
            run = []
        if len(run) >= min_len:
            out.append((run, _bytes_for(image, run)))
    return out


_FP_METHOD = re.compile(r"\b(d\d+|\([^()]*\))\.(abs|sqrt)\(\)")


def _fexpr(text: str):
    """The printed text as a Python expression over floats."""
    import ast
    prev = None
    while prev != text:                       # `x.abs().sqrt()` needs a second pass
        prev = text
        text = _FP_METHOD.sub(lambda m: f"_{m.group(2)}({m.group(1)})", text)
    if "." in re.sub(r"\d\.\d|\bd\d+\b", "", text):
        raise _Undecidable(f"unresolved method call in {text!r}")
    return ast.parse(text, mode="eval")


def _fev(node, env):
    import ast
    import math
    if isinstance(node, ast.Expression):
        return _fev(node.body, env)
    if isinstance(node, ast.Constant):
        if not isinstance(node.value, (int, float)):
            raise _Undecidable("non-numeric literal")
        return float(node.value)
    if isinstance(node, ast.Name):
        if node.id not in env:
            raise _Undecidable(f"unknown name {node.id}")
        return env[node.id]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_fev(node.operand, env)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if len(node.args) != 1:
            raise _Undecidable("call arity")
        v = _fev(node.args[0], env)
        if node.func.id == "_abs":
            return abs(v)
        if node.func.id == "_sqrt":
            if v < 0 or v != v:
                # IEEE says NaN; Python raises. The evaluator's limit, not the tool's.
                raise _Undecidable("square root of a negative")
            return math.sqrt(v)
        raise _Undecidable(f"unknown call {node.func.id}")
    if isinstance(node, ast.BinOp):
        a, b = _fev(node.left, env), _fev(node.right, env)
        op = node.op
        if isinstance(op, ast.Add):
            return a + b
        if isinstance(op, ast.Sub):
            return a - b
        if isinstance(op, ast.Mult):
            return a * b
        if isinstance(op, ast.Div):
            if b == 0.0:
                raise _Undecidable("division by zero")   # IEEE gives an infinity
            return a / b
    raise _Undecidable("unsupported syntax")


def _fp_bits(x: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def run_fp(path: str, want: int, trials: int, seed: int, verbose: bool) -> int:
    uc_mod = _unicorn()
    if uc_mod is None:
        print("SKIP: unicorn is not installed")
        return 0
    _u, Uc, ARCH, MODE, a64 = uc_mod
    from jadart.cfg import Block
    from jadart.expr import Lifter, State, use_target, ARM64

    cases = fp_cases(path, want)
    if not cases:
        print("no scalar-double runs found")
        return 0

    dregs = {i: getattr(a64, f"UC_ARM64_REG_D{i}") for i in range(32)}
    rng = random.Random(seed)
    failures = checked = skipped = insns = 0
    covered = {}

    def sample():
        # a finite double, from random bits. NaN and infinity are excluded on the way IN
        # rather than compared: a NaN result carries a payload the two evaluators are not
        # obliged to agree on, and that is not a claim the lifter is making.
        while True:
            bits = rng.getrandbits(64)
            v = struct.unpack("<d", struct.pack("<Q", bits))[0]
            if v == v and v not in (float("inf"), float("-inf")):
                return v

    for run, code in cases:
        if not code or len(code) != 4 * len(run):
            continue
        blk = Block(addr=run[0][0], insns=[(a, m, o, "") for a, m, o in run],
                    succ=[], term="")
        with use_target(ARM64):
            st = State()
            lines, _f = Lifter({blk.addr: blk})._lift_block(blk.addr, st)
            texts = {r: v.text for r, v in st.reg.items() if _DREG_RE.match(r)}
        if lines:
            continue                          # a statement: not a pure value run
        trees = {}
        for r, t in texts.items():
            try:
                trees[r] = _fexpr(t)
            except (_Undecidable, SyntaxError):
                pass
        if not trees:
            continue
        insns += len(run)
        for _a, m, _o in run:
            covered[m] = covered.get(m, 0) + 1

        bad = False
        for _ in range(trials):
            env = {f"d{i}": sample() for i in range(32)}
            mu = Uc(ARCH, MODE)
            mu.mem_map(BASE, 0x1000)
            mu.mem_write(BASE, code)
            mu.reg_write(a64.UC_ARM64_REG_CPACR_EL1, 3 << 20)   # enable the FP unit
            for i in range(32):
                mu.reg_write(dregs[i], _fp_bits(env[f"d{i}"]))
            mu.emu_start(BASE, BASE + len(code))
            for r, tree in trees.items():
                try:
                    got = _fev(tree, env)
                except _Undecidable:
                    skipped += 1
                    continue
                want_v = mu.reg_read(dregs[int(r[1:])]) & mask(64)
                if got != got:                # a NaN the text produced and the CPU may not
                    skipped += 1
                    continue
                checked += 1
                if _fp_bits(got) != want_v:
                    failures += 1
                    bad = True
                    if failures <= 5:
                        cpu = struct.unpack("<d", struct.pack("<Q", want_v))[0]
                        print(f"MISMATCH fp, {r} = {texts[r]}")
                        for a, m, o in run:
                            print(f"    {m} {o}")
                        print("  in  " + " ".join(
                            f"{n}={env[n]!r}" for n in sorted(set(
                                re.findall(r"\bd\d+\b", texts[r])))))
                        print(f"  cpu {cpu!r}  txt {got!r}")
                    break
            if bad:
                break
        if verbose and not bad:
            print(f"  ok  {len(run):>2} insns, {len(trees)} expressions")

    top = ", ".join(f"{m}x{n}" for m, n in sorted(covered.items(), key=lambda kv: -kv[1]))
    print(f"\n{len(cases)} real scalar-double runs ({insns} instructions), "
          f"{checked} printed expressions evaluated, {skipped} undecidable, "
          f"{failures} mismatches")
    print(f"  covering: {top}")
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# Fuzzing MEMORY, which every oracle above excludes by construction
# ---------------------------------------------------------------------------
#
# The three oracles above all drop memory on the floor. `expr_cases` refuses any operand
# containing `[`, `corpus_cases` only takes runs the DAG models completely, and the
# generated control-flow functions emit no load or store at all. The stated reason is that
# a real Dart function with memory in it also calls out, and once a call is in the picture
# there is nothing left to compare, which is true of CORPUS code and says nothing about
# generated code. Memory can be generated exactly as arithmetic is: map a page, point one
# register at it, and the emulator has an answer for every byte.
#
# It matters because expr.py's register map holds EXPRESSIONS, not values, and a field
# expression is only sound while the field still holds what it held. `_pin` already knows
# this for the base register, `ldr x16, [x4], #8` has to be written out before x4
# advances, and nothing applied the same rule to the memory itself. So a value loaded
# before a store to the same field kept printing as a read of that field, which now names
# the value the store put there. On the 3.12.2 clean build that is 1,146 printed
# expressions across 377 of 8,194 functions.
#
# WHAT MAKES THE COMPARISON WELL-POSED. The printed text is not one expression here, it is
# a small program: `var t0 = ...;` declarations and field assignments in order, then the
# register expressions a reader would see at the end. So it is INTERPRETED in order rather
# than folded into one expression, which is the whole point, since folding a declaration
# past a store to a field it mentions is the defect, not a way to check for it. One base
# register (x20, which has no role in constants_arm64.h and so renders as itself) keeps
# every field name a single flat `x20.field_0xNN`, and the tag bias makes the mapping to an
# address exact: Dart reaches field F of a tagged pointer P as [P, #F-1], so x20 is seeded
# with SCRATCH+1 and `[x20, #8k-1]` is both `field_0x{8k}` and SCRATCH+8k.

_MEM_BASE = 20                      # x20
SCRATCH = 0x300000
#: Few slots on purpose. The interesting collision is load-modify-store to the SAME field
#: with the loaded value still live, and a wide address space makes it rare.
_MEM_SLOTS = 4
_MEM_DISPS = tuple(8 * k - 1 for k in range(1, _MEM_SLOTS + 1))


def _enc_ldur(t: int, n: int, imm: int) -> int:
    return 0xF8400000 | ((imm & 0x1FF) << 12) | (n << 5) | t


def _enc_stur(t: int, n: int, imm: int) -> int:
    return 0xF8000000 | ((imm & 0x1FF) << 12) | (n << 5) | t


def verify_mem_encodings() -> list:
    """Same contract as verify_encodings, plus the field-name mapping this oracle seeds on.

    The second half is the one that would fail silently: if expr.py ever spelled a field
    at a different offset, every trial would still run and compare a register against the
    contents of the wrong address, and the harness would report a clean pass."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from jadart.cfg import Block
    from jadart.expr import Lifter, State, use_target, ARM64
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    def decode(word):
        got = [f"{i.mnemonic} {i.op_str}".strip()
               for i in md.disasm(struct.pack("<I", word), BASE)]
        return got[0] if got else "<undecodable>"

    bad = []
    for d in _MEM_DISPS:
        shown = f"#{d}" if d < 10 else f"#{d:#x}"
        for want, word in ((f"ldur x3, [x20, {shown}]", _enc_ldur(3, _MEM_BASE, d)),
                           (f"stur x5, [x20, {shown}]", _enc_stur(5, _MEM_BASE, d))):
            got = decode(word)
            if got != want:
                bad.append((want, got))
    with use_target(ARM64):
        for d in _MEM_DISPS:
            ins = [(BASE, "ldur", f"x0, [x20, #{d:#x}]", "")]
            blk = Block(addr=BASE, insns=ins, succ=[], term="")
            st = State()
            Lifter({BASE: blk})._lift_block(BASE, st)
            got = st.reg.get("x0")
            want = _mem_name(d)
            if got is None or got.text != want:
                bad.append((f"[x20, #{d:#x}] lifts to {want}",
                            got.text if got else "<nothing>"))
    return bad


def _mem_name(disp: int) -> str:
    """The field expression expr.py prints for `[x20, #disp]`, tag bias included."""
    return f"x20.field_0x{disp + 1:x}"


def _mem_key(disp: int) -> str:
    """The same slot as a Python identifier, for the expression evaluator."""
    return f"m_{disp + 1:x}"


_MEM_FIELD_RE = re.compile(r"\bx20\.field_0x([0-9a-f]+)\b")
_MEM_DECL_RE = re.compile(r"^var (t\d+) = (.+);$")
_MEM_STORE_RE = re.compile(r"^(x20\.field_0x[0-9a-f]+) ([-+*&|^]?)= (.+);$")
_MEM_COMPOUND = {"+": lambda a, b: a + b, "-": lambda a, b: a - b,
                 "*": lambda a, b: a * b, "&": lambda a, b: a & b,
                 "|": lambda a, b: a | b, "^": lambda a, b: a ^ b}


def _mem_expr(text: str):
    """Parse one printed expression, with field accesses rewritten to plain names."""
    import ast
    return ast.parse(_texpr(_MEM_FIELD_RE.sub(lambda m: f"m_{m.group(1)}", text)),
                     mode="eval")


def _mem_interp(lines: list, env: dict) -> None:
    """Run the printed statements in order, updating `env` in place.

    Order is the whole point. A `var t0 = x20.field_0x8;` before a store to field_0x8
    means the value the field held THEN, and evaluating the declaration where it stands is
    what says so. Anything the generator did not mean to produce, a raw arm64 line, an
    unmodelled statement, raises rather than being skipped over, because a statement that
    is silently ignored is a side effect the comparison would then be blind to."""
    for ln in lines:
        s = ln.strip()
        cut = s.find("   //")               # the `if Smi` note _assign appends
        if cut >= 0:
            s = s[:cut].rstrip()
        m = _MEM_DECL_RE.match(s)
        if m:
            env[m.group(1)] = _ev(_mem_expr(m.group(2)), env) & mask(64)
            continue
        m = _MEM_STORE_RE.match(s)
        if m:
            key = f"m_{m.group(1).split('_0x')[1]}"
            val = _ev(_mem_expr(m.group(3)), env) & mask(64)
            if m.group(2):
                if key not in env:
                    raise _Undecidable(f"compound assignment to unknown {key}")
                val = _MEM_COMPOUND[m.group(2)](env[key], val) & mask(64)
            env[key] = val
            continue
        raise _Undecidable(f"unmodelled statement {s!r}")


def _gen_mem_block(rng) -> list:
    """A straight-line run of loads, stores and arithmetic over one object.

    No control flow: this oracle is about the memory model, and the generated-CFG oracle
    already covers joins. Keeping it flat makes the printed text a plain statement list,
    so interpreting it needs no path reconstruction and cannot itself be wrong about which
    branch ran."""
    src = _FUZZ_IN + _FUZZ_OUT
    words = []
    for _ in range(rng.randint(4, 12)):
        roll = rng.random()
        if roll < 0.30:
            words.append(_enc_ldur(rng.choice(_FUZZ_OUT), _MEM_BASE,
                                   rng.choice(_MEM_DISPS)))
        elif roll < 0.55:
            words.append(_enc_stur(rng.choice(src), _MEM_BASE, rng.choice(_MEM_DISPS)))
        elif roll < 0.85:
            _t, enc = rng.choice(_FUZZ_ALU)
            words.append(enc(rng.choice(_FUZZ_OUT), rng.choice(src), rng.choice(src)))
        else:
            _t, enc = rng.choice(_FUZZ_IMM)
            words.append(enc(rng.choice(_FUZZ_OUT), rng.choice(src), rng.randint(1, 63)))
    return words


def run_mem(count: int, trials: int, seed: int, verbose: bool) -> int:
    uc_mod = _unicorn()
    if uc_mod is None:
        print("SKIP: unicorn is not installed")
        return 0
    _u, Uc, ARCH, MODE, a64 = uc_mod
    bad = verify_fuzz_encodings() + verify_mem_encodings()
    if bad:
        for want, actual in bad:
            print(f"BAD ENCODING: claimed {want!r}, decodes to {actual!r}")
        return 1

    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from jadart.cfg import Block
    from jadart.expr import Lifter, State, use_target, ARM64

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    regs = {i: getattr(a64, f"UC_ARM64_REG_X{i}") for i in range(31)}
    rng = random.Random(seed)
    failures = checked = memchecked = skipped = stores = 0

    for _case in range(count):
        words = _gen_mem_block(rng)
        code = b"".join(struct.pack("<I", w) for w in words)
        ann = [(i.address, i.mnemonic, i.op_str, "") for i in md.disasm(code, BASE)]
        if len(ann) != len(words):
            continue
        # A successor that READS every output register, so the lifter's liveness says the
        # values are wanted. Without it x0-x6 are dead at the end of the only block, and a
        # dead register is one the tool never prints, scoring its expression would be
        # scoring something no user ever sees, and would demand a materialisation the tool
        # is right not to emit.
        use = BASE + 0x1000
        useblk = Block(addr=use, insns=[(use + 4 * i, "cmp", f"x{a}, x{b}", "")
                                        for i, (a, b) in enumerate(((0, 1), (2, 3),
                                                                    (4, 5), (6, 6)))],
                       succ=[], term="ret")
        blk = Block(addr=BASE, insns=ann, succ=[use], term="b")
        with use_target(ARM64):
            st = State()
            lines, _f = Lifter({BASE: blk, use: useblk})._lift_block(BASE, st)
            texts = {f"x{i}": st.reg[f"x{i}"].text for i in _FUZZ_OUT
                     if f"x{i}" in st.reg}
        stores += sum(1 for w in words if (w & 0xFFE00C00) == 0xF8000000)
        try:
            trees = {r: _mem_expr(t) for r, t in texts.items()}
        except (_Undecidable, SyntaxError):
            skipped += 1
            continue

        bad_case = False
        for _ in range(trials):
            env = {f"x{i}": rng.getrandbits(64) for i in range(31)}
            env["xzr"] = 0
            slots = {d: rng.getrandbits(64) for d in _MEM_DISPS}
            mu = Uc(ARCH, MODE)
            mu.mem_map(BASE, 0x2000)
            mu.mem_map(SCRATCH, 0x1000)
            mu.mem_write(BASE, code)
            for d, v in slots.items():
                mu.mem_write(SCRATCH + d + 1, struct.pack("<Q", v))
            for i in range(31):
                mu.reg_write(regs[i], env[f"x{i}"])
            # tagged, exactly as a Dart object pointer is: field F is reached at [P, #F-1].
            mu.reg_write(regs[_MEM_BASE], SCRATCH + 1)
            env[f"x{_MEM_BASE}"] = SCRATCH + 1
            for d, v in slots.items():
                env[_mem_key(d)] = v
            mu.emu_start(BASE, BASE + len(code))
            try:
                _mem_interp(lines, env)
            except (_Undecidable, SyntaxError, KeyError):
                skipped += 1
                break
            for r, tree in trees.items():
                try:
                    got = _ev(tree, env) & mask(64)
                except _Undecidable:
                    skipped += 1
                    continue
                want_v = mu.reg_read(regs[int(r[1:])]) & mask(64)
                checked += 1
                if got != want_v:
                    failures += 1
                    bad_case = True
                    if failures <= 5:
                        _mem_report(f"{r} = {texts[r]}", ann, lines, slots, env,
                                    want_v, got)
                    break
            if bad_case:
                break
            for d in _MEM_DISPS:              # the stores themselves, not just the registers
                want_v = struct.unpack("<Q", mu.mem_read(SCRATCH + d + 1, 8))[0]
                got = env[_mem_key(d)] & mask(64)
                memchecked += 1
                if got != want_v:
                    failures += 1
                    bad_case = True
                    if failures <= 5:
                        _mem_report(f"memory at {_mem_name(d)}", ann, lines, slots, env,
                                    want_v, got)
                    break
            if bad_case:
                break
        if verbose and not bad_case:
            print(f"  ok  {len(words):>2} insns, {len(trees)} expressions")

    print(f"\n{count} generated memory runs ({stores} stores), {checked} printed "
          f"expressions and {memchecked} field values evaluated, {skipped} undecidable, "
          f"{failures} mismatches")
    return 1 if failures else 0


def _mem_report(what, ann, lines, slots, env, want_v, got):
    print(f"MISMATCH mem, {what}")
    for a, m, o, _n in ann:
        print(f"    {a - BASE:#06x}  {m} {o}")
    print("  lifted:")
    for ln in lines:
        print(f"    {ln}")
    print("  in  " + " ".join(f"x{i}={env[f'x{i}']:#x}" for i in _FUZZ_IN))
    print("      " + " ".join(f"{_mem_name(d)}={v:#x}" for d, v in slots.items()))
    print(f"  cpu {want_v:#018x}  txt {got:#018x}")


# ---------------------------------------------------------------------------
# Fuzzing CONTROL FLOW, which the two oracles above deliberately do not reach
# ---------------------------------------------------------------------------
#
# The two oracles above fuzz one basic block. That covers where the folding and width
# rules live, and it cannot see the thing that actually goes wrong across a whole function:
# a value the walker carries into a block along a path the machine did not take. The
# if/else join has a meet, the loop header has one, and the block a `goto` lands on had
# none at all, which printed `createFromCharCodes(x2, x2, x3)` for a call whose first
# argument register is x1.
#
# Corpus code cannot fuzz that. A real Dart function with several blocks also loads memory
# and calls, and once memory is in the picture there is nothing to compare against. So the
# function is GENERATED instead: random arithmetic in random blocks, wired by forward
# branches only, so it always terminates and there is always a CPU answer.
#
# Two register banks, and that is what makes the comparison well-posed. INPUTS (x8-x14)
# are read and never written, so an expression in terms of them alone means the same thing
# at entry and at the `ret`, and the emulator can be seeded with the same values the text
# is evaluated in. OUTPUTS (x0-x7) are the only destinations. A printed expression that
# still mentions one of them is the lifter saying it does not know, which is not a claim
# and is not scored. Neither bank touches a role register (x15 SP, x21, x22, x26-x30), so
# nothing here depends on the calling convention.

_FUZZ_IN = tuple(range(8, 15))       # read-only inputs
_FUZZ_OUT = tuple(range(0, 7))       # the only destinations
#: The loop counter, written by nothing else so a generated back edge is guaranteed to
#: retire. Readable as a source like any other output register.
_FUZZ_CTR = 7

#: (mnemonic template, encoder). Every word these build is checked against capstone before
#: a single trial runs, for the reason CASES is: a harness that fuzzes a different
#: instruction than the one it names reports a clean pass and proves nothing.
_FUZZ_ALU = [
    ("add {d}, {n}, {m}", lambda d, n, m: 0x8B000000 | (m << 16) | (n << 5) | d),
    ("sub {d}, {n}, {m}", lambda d, n, m: 0xCB000000 | (m << 16) | (n << 5) | d),
    ("and {d}, {n}, {m}", lambda d, n, m: 0x8A000000 | (m << 16) | (n << 5) | d),
    ("orr {d}, {n}, {m}", lambda d, n, m: 0xAA000000 | (m << 16) | (n << 5) | d),
    ("eor {d}, {n}, {m}", lambda d, n, m: 0xCA000000 | (m << 16) | (n << 5) | d),
    ("mul {d}, {n}, {m}", lambda d, n, m: 0x9B007C00 | (m << 16) | (n << 5) | d),
]
_FUZZ_IMM = [
    ("add {d}, {n}, #{i}", lambda d, n, i: 0x91000000 | (i << 10) | (n << 5) | d),
    ("sub {d}, {n}, #{i}", lambda d, n, i: 0xD1000000 | (i << 10) | (n << 5) | d),
]
_RET_WORD = 0xD65F03C0


def _enc_b(delta_words: int) -> int:
    return 0x14000000 | (delta_words & 0x03FFFFFF)


def _enc_cbz(reg: int, delta_words: int, nonzero: bool) -> int:
    return (0xB5000000 if nonzero else 0xB4000000) | ((delta_words & 0x7FFFF) << 5) | reg


def _enc_cmp(n: int, m: int) -> int:
    return 0xEB00001F | (m << 16) | (n << 5)          # subs xzr, xn, xm


#: The pairs the memory generator compares at the end of the function, purely so that
#: every output register is READ after the last store. Nothing depends on the result.
_LIVE_TAIL = ((0, 1), (2, 3), (4, 5), (6, 6))


def verify_fuzz_encodings() -> list:
    """Same contract as verify_encodings, for the words the generator builds."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    def decode(word, at=BASE):
        got = [f"{i.mnemonic} {i.op_str}".strip()
               for i in md.disasm(struct.pack("<I", word), at)]
        return got[0] if got else "<undecodable>"

    bad = []
    for tmpl, enc in _FUZZ_ALU:
        want = tmpl.format(d="x3", n="x9", m="x11")
        got = decode(enc(3, 9, 11))
        if got != want:
            bad.append((want, got))
    for tmpl, enc in _FUZZ_IMM:
        want = tmpl.format(d="x5", n="x12", i="0x2a")
        got = decode(enc(5, 12, 42))
        if got != want:
            bad.append((want, got))
    for want, word in ((f"b #{BASE + 12:#x}", _enc_b(3)),
                       (f"cbz x9, #{BASE + 8:#x}", _enc_cbz(9, 2, False)),
                       (f"cbnz x10, #{BASE + 16:#x}", _enc_cbz(10, 4, True)),
                       ("cmp x4, x5", _enc_cmp(4, 5)),
                       ("cmp x6, x6", _enc_cmp(6, 6)),
                       ("ret", _RET_WORD)):
        got = decode(word)
        if got != want:
            bad.append((want, got))
    return bad


def _gen_function(rng, mem: bool = False, seed_outs: bool = False):
    """A random function, as a list of encoded words.

    `mem` mixes loads and stores through x20 into the arithmetic and appends a tail of
    compares that READ every output register. The tail is what makes the memory question
    well-posed: `_pin_mem` writes a value out before the memory it reads changes only
    where something reads the value again, and with nothing after the `ret` every output
    register is dead at the store. A dead register is one the tool never prints, so
    scoring its expression would demand a materialisation the tool is right not to emit.

    Blocks are laid out in address order and every branch except the back edge goes
    FORWARD, so the graph always terminates and there is always a CPU answer. Targets are
    drawn from anywhere ahead rather than only the next block, because a branch that skips
    over the block after it is exactly the edge the structurer cannot nest, the one that
    becomes a goto.

    Loops are kept REDUCIBLE: no block ahead of the header may be jumped over into the
    body, so the header dominates its latch. That is a real restriction and it is stated
    rather than hidden. Dart has no `goto` and its front end cannot emit an irreducible
    loop, so every loop in a Flutter snapshot has one entry; jadart's loop structuring
    assumes as much. Lifting a generated two-entry loop does print a value the CPU
    disagrees with, and that is recorded in FINDINGS.md as a known limit rather than
    fuzzed here, because an oracle that fails on input the tool never sees stops being
    run.
    """
    n = rng.randint(3, 7)
    src = _FUZZ_IN + _FUZZ_OUT + (_FUZZ_CTR,)
    body = [[] for _ in range(n)]                 # per block: list of ALU words
    for b in range(n):
        for _ in range(rng.randint(1, 3)):
            d = rng.choice(_FUZZ_OUT)
            roll = rng.random()
            if mem and roll < 0.22:
                body[b].append(_enc_ldur(d, _MEM_BASE, rng.choice(_MEM_DISPS)))
            elif mem and roll < 0.44:
                body[b].append(_enc_stur(rng.choice(src), _MEM_BASE,
                                         rng.choice(_MEM_DISPS)))
            elif rng.random() < 0.25:
                _t, enc = rng.choice(_FUZZ_IMM)
                body[b].append(enc(d, rng.choice(src), rng.randint(1, 63)))
            else:
                _t, enc = rng.choice(_FUZZ_ALU)
                body[b].append(enc(d, rng.choice(src), rng.choice(src)))
    # terminator kind per block; the last one returns
    term = []
    for b in range(n - 1):
        term.append(rng.choice(["fall", "fall", "cbz", "cbnz", "b"]))
    term.append("ret")

    # Half the graphs get a back edge, because a loop header is the OTHER join with a meet
    # of its own and a DAG never reaches it. Termination is by construction rather than by
    # hope: block 0 sets the counter to a small constant, the latch decrements it, and no
    # other instruction may write it, so the loop retires after at most that many trips
    # however the branches inside it fall.
    header = None
    if n >= 4 and rng.random() < 0.5:
        header = rng.randint(1, n - 2)
        latch = rng.randint(header, n - 2)
        # so the header dominates the latch: nothing before it may reach past it
        for b in range(header):
            if term[b] == "b":
                term[b] = "fall" if b + 1 == header else "b"
        zero, _ = _FUZZ_ALU[1]                          # sub xC, xC, xC -> 0
        body[0] = ([_FUZZ_ALU[1][1](_FUZZ_CTR, _FUZZ_CTR, _FUZZ_CTR),
                    _FUZZ_IMM[0][1](_FUZZ_CTR, _FUZZ_CTR, rng.randint(2, 5))] + body[0])
        body[latch] = body[latch] + [_FUZZ_IMM[1][1](_FUZZ_CTR, _FUZZ_CTR, 1)]
        term[latch] = "back"
    if mem:
        body[n - 1] = body[n - 1] + [_enc_cmp(a, b) for a, b in _LIVE_TAIL]
    if seed_outs:
        # Every destination register loaded from memory before anything else runs.
        #
        # The harness leaves x0-x6 UNBOUND so that a bare one in the printed text reads as
        # the lifter declining rather than as a claim about the entry state. That is right,
        # and it also means a loop-carried variable, which by definition reads its own
        # previous value, so it is one of these, can never be evaluated, and the whole
        # class of write-back defects is invisible. Seeding them from memory gives the
        # chain a decidable start without changing what a bare register means anywhere
        # else, because after these loads the lifter holds a field expression for each and
        # prints THAT. Slots are reused round-robin: four is deliberate (see _MEM_SLOTS)
        # and two registers starting equal diverge on the first generated instruction.
        body[0] = [_enc_ldur(d, _MEM_BASE, _MEM_DISPS[i % _MEM_SLOTS])
                   for i, d in enumerate(_FUZZ_OUT)] + body[0]

    starts, at = [], 0
    for b in range(n):
        starts.append(at)
        at += len(body[b]) + (0 if term[b] == "fall" else 1)
    end = at

    words = []
    for b in range(n):
        words.extend(body[b])
        kind = term[b]
        if kind == "fall":
            continue
        here = starts[b] + len(body[b])
        if kind == "ret":
            words.append(_RET_WORD)
            continue
        if kind == "back":
            words.append(_enc_cbz(_FUZZ_CTR, starts[header] - here, True))
            continue
        hi = header if (header is not None and b < header) else n - 1
        tgt = starts[rng.randint(b + 1, hi)] if b + 1 <= hi else end
        if kind == "b":
            words.append(_enc_b(tgt - here))
        else:
            words.append(_enc_cbz(rng.choice(_FUZZ_IN), tgt - here, kind == "cbnz"))
    return words


def _resolve_temps(text: str, subs: dict) -> str:
    """Fold `var tN = ...;` definitions back into an expression that mentions them.

    `subs` must hold ONLY names assigned exactly once in the whole body. A loop-carried
    name is declared with its entry value and assigned again at the bottom, so folding the
    declaration in would compare the text against the value it had before the loop ran,
    an oracle bug that reported eight mismatches a CPU trace showed were not there.
    """
    for _ in range(8):
        hit = re.search(r"\bt\d+\b", text)
        if not hit:
            return text
        name = hit.group(0)
        if name not in subs:
            raise _Undecidable(f"no definition for {name}")
        text = re.sub(rf"\b{name}\b", f"({subs[name]})", text)
    raise _Undecidable("temporary substitution did not settle")


class _Unsound(Exception):
    """The printed body is not a program: it reads a name no path to here defines.

    Distinct from _Undecidable on purpose. "I cannot decide this trial" is a refusal and
    costs nothing; "the text declares a variable and reads it on a path that never assigns
    it" is a defect in the rendering and has to be counted as one, or the oracle passes on
    exactly the mistake it was added to catch."""


_ASSIGN = re.compile(r"^(?:var )?([A-Za-z_]\w*) ([-+*&|^]|~/|<<|>>)?= (.+);$")
_DECL = re.compile(r"^var ([A-Za-z_]\w*);$")
_IF = re.compile(r"^if \((.+)\) \{$")
_IF1 = re.compile(r"^if \((.+)\) (break|continue);$")
_RET = re.compile(r"^return(?: (.+))?;$")


def _parse_body(lines, i=0, depth=0):
    """The printed body as a statement tree, or _Undecidable.

    `_resolve_temps` can only fold a name the body assigns ONCE, so it gives up on any
    value that reaches a join from two places, which is every phi, and phis are the
    thing the control-flow oracle exists to check. Reading the body as a PROGRAM and
    running it removes that limit: a name assigned in both arms of an `if` is decided by
    running the arm the inputs select, exactly as the CPU does.

    Anything outside the grammar below is refused rather than guessed at, and `goto` is
    the important one: a rendering with a goto is not a structured program and executing
    it top to bottom would compare against a path the machine never took."""
    out = []
    while i < len(lines):
        s = lines[i].strip()
        if s in ("}", "} else {"):
            return out, i
        m = _IF.match(s)
        if m:
            then, i = _parse_body(lines, i + 1, depth + 1)
            els = []
            if lines[i].strip() == "} else {":
                els, i = _parse_body(lines, i + 1, depth + 1)
            out.append(("if", m.group(1), then, els))
            i += 1
            continue
        if s == "while (true) {":
            body, i = _parse_body(lines, i + 1, depth + 1)
            out.append(("loop", body))
            i += 1
            continue
        m = _IF1.match(s)
        if m:
            out.append(("if", m.group(1), [(m.group(2),)], []))
            i += 1
            continue
        if s in ("break;", "continue;"):
            out.append((s[:-1],))
            i += 1
            continue
        m = _RET.match(s)
        if m:
            out.append(("return", m.group(1)))
            i += 1
            continue
        m = _DECL.match(s)
        if m:
            out.append(("decl", m.group(1)))
            i += 1
            continue
        m = _ASSIGN.match(s)
        if m and s.startswith("var ") or (m and m.group(1)[:1] in "xdt"):
            out.append(("set", m.group(1), m.group(2), m.group(3)))
            i += 1
            continue
        raise _Undecidable(f"statement outside the executable grammar: {s!r}")
    return out, i


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class _Return(Exception):
    pass


_NAME_RE = re.compile(r"\b[A-Za-z_]\w*\b")
#: The registers the generator writes. The harness's rule for the expression oracle is
#: that a printed expression still mentioning one of these is the lifter saying it does
#: not know; the same rule has to hold statement by statement here, or a body that ends
#: `return x0;` (a refusal) gets scored against the x0 the CPU actually computed.
_UNKNOWN_RE = re.compile(r"\b(x[0-7])\b")


class _Run:
    """One execution of a printed body: the values, and what is trustworthy in them."""

    def __init__(self, env):
        self.env = env
        self.assigned = set()     # names this run has assigned
        self.dead = set()         # `var n;` with nothing assigned to it yet
        self.tainted = set()      # values resting on a register the lifter had lost

    def unknown(self, text) -> bool:
        names = _NAME_RE.findall(text)
        return (any(n in self.tainted for n in names)
                or any(m not in self.assigned for m in _UNKNOWN_RE.findall(text)))

    def value(self, text):
        import ast
        for name in _NAME_RE.findall(text):
            if name in self.dead:
                raise _Unsound(f"{name} is read on a path that never assigns it")
        return _ev(ast.parse(_texpr(text), mode="eval"), self.env) & _U64


def _exec_body(stmts, run, budget, wrote):
    """Run the parsed body over `env`, masking every write to 64 bits.

    `dead` holds the names a `var` declared without an initialiser and nothing has
    assigned yet. Reading one is _Unsound: the text bound the value on some other path
    and not on this one. `wrote` collects what the run actually assigned, because that is
    the only part of the register file the text makes a claim about, a body that reads
    x11 and returns says nothing at all about x6, and comparing x6 anyway reported 271
    mismatches on a lifter with no defect in it."""
    for st in stmts:
        if budget[0] <= 0:
            raise _Undecidable("statement budget exhausted")
        budget[0] -= 1
        k = st[0]
        if k == "set":
            _n, name, op, rhs = st
            if op:
                rhs = f"{name} {op} ({rhs})"
            bad = run.unknown(rhs)
            run.env[name] = run.value(rhs)
            run.dead.discard(name)
            run.assigned.add(name)
            (run.tainted.add if bad else run.tainted.discard)(name)
            wrote.add(name)
        elif k == "decl":
            run.dead.add(st[1])
            run.tainted.discard(st[1])
            run.env.pop(st[1], None)
        elif k == "if":
            # A condition the lifter could not spell steers the run down a path the
            # machine may not have taken, and every claim after it would be scored
            # against the wrong trace. That is a refusal, not a defect.
            if run.unknown(st[1]):
                raise _Undecidable("branch condition rests on a register the lifter lost")
            cond = run.value(st[1])
            _exec_body(st[2] if cond else st[3], run, budget, wrote)
        elif k == "loop":
            while True:
                try:
                    _exec_body(st[1], run, budget, wrote)
                except _Continue:
                    continue
                except _Break:
                    break
                if budget[0] <= 0:
                    raise _Undecidable("statement budget exhausted")
        elif k == "break":
            raise _Break
        elif k == "continue":
            raise _Continue
        elif k == "return":
            if not st[1] or run.unknown(st[1]):
                raise _Return()
            raise _Return(run.value(st[1]))


def _run_body(stmts, env, budget):
    """(the run, names it assigned, the value it returned or None)."""
    run, wrote = _Run(env), set()
    try:
        _exec_body(stmts, run, [budget], wrote)
    except _Return as r:
        return run, wrote, (r.args[0] if r.args else None)
    except (_Break, _Continue):
        pass
    return run, wrote, None


def _report_cfg(what, ann, lines, env):
    print(f"MISMATCH cfg, {what}")
    for a, m, o, _n in ann:
        print(f"    {a - BASE:#06x}  {m} {o}")
    print("  lifted:")
    for ln in lines:
        print(f"    {ln}")
    print("  in  " + " ".join(f"x{i}={env[f'x{i}']:#x}" for i in _FUZZ_IN))


def _reachable(blocks, entry):
    seen, stack = set(), [entry]
    while stack:
        n = stack.pop()
        if n in seen or n not in blocks:
            continue
        seen.add(n)
        stack.extend(blocks[n].succ)
    return seen


def run_cfg(count: int, trials: int, seed: int, verbose: bool) -> int:
    import ast
    uc_mod = _unicorn()
    if uc_mod is None:
        print("SKIP: unicorn is not installed")
        return 0
    _u, Uc, ARCH, MODE, a64 = uc_mod
    bad = verify_fuzz_encodings()
    if bad:
        for want, actual in bad:
            print(f"BAD ENCODING: claimed {want!r}, decodes to {actual!r}")
        return 1

    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from jadart.cfg import build_cfg, structure, label_targets
    from jadart.expr import Lifter, State

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    regs = {i: getattr(a64, f"UC_ARM64_REG_X{i}") for i in range(31)}
    lr = a64.UC_ARM64_REG_X30
    rng = random.Random(seed)
    failures = checked = skipped = executed = 0
    withgoto = joins = loops = 0

    for _case in range(count):
        words = _gen_function(rng)
        code = b"".join(struct.pack("<I", w) for w in words)
        ann = [(i.address, i.mnemonic, i.op_str, "")
               for i in md.disasm(code, BASE)]
        if len(ann) != len(words):
            continue                                  # a word capstone will not decode
        blocks, entry = build_cfg(ann)
        if len(blocks) < 2:
            continue
        joins += sum(1 for b in blocks
                     if sum(1 for o in blocks if b in blocks[o].succ) > 1)
        stmts = structure(blocks, entry)
        lif = Lifter(blocks, entry=entry)
        lif.labels = label_targets(stmts)
        st = State()
        lines, _falls = lif.walk(stmts, st, "  ", 0)
        if lif.labels:
            withgoto += 1
        if any(t <= a for a in blocks for t in blocks[a].succ):
            loops += 1
        # The body is a PROGRAM only when the structurer had to invent nothing: a `goto`
        # is not a Dart statement and a block the CFG cannot reach is printed anyway (see
        # `_reenter`), so running either top to bottom would compare against a path the
        # machine never took. Where both are absent the rendering is executable, and
        # running it is the only oracle that can decide a value with two definitions.
        prog = None
        if not lif.labels and len(_reachable(blocks, entry)) == len(blocks):
            try:
                prog, _end = _parse_body([ln.strip() for ln in lines])
            except _Undecidable:
                prog = None
        subs, assigned = {}, {}
        for ln in lines:
            m = re.match(r"\s*(?:var )?(t\d+) [-+*/&|^]?= (.+);$", ln)
            if m:
                assigned[m.group(1)] = assigned.get(m.group(1), 0) + 1
            m = re.match(r"\s*var (t\d+) = (.+);$", ln)
            if m:
                subs[m.group(1)] = m.group(2)
        subs = {k: v for k, v in subs.items() if assigned.get(k) == 1}
        trees = {}
        for r, v in st.reg.items():
            if not (r[:1] == "x" and r[1:].isdigit() and int(r[1:]) in _FUZZ_OUT):
                continue
            if v.text == r:
                continue                              # the lifter says it does not know
            try:
                text = _resolve_temps(v.text, subs)
                if re.search(r"\bx[0-7]\b", text):
                    continue                          # still rests on an unknown
                trees[r] = ast.parse(_texpr(text), mode="eval")
            except (_Undecidable, SyntaxError, re.error):
                continue
        if not trees and prog is None:
            continue

        end = BASE + len(code)
        for _ in range(trials):
            env = {f"x{i}": rng.getrandbits(64) for i in range(31)}
            env["xzr"] = 0
            mu = Uc(ARCH, MODE)
            mu.mem_map(BASE, 0x2000)
            mu.mem_write(BASE, code)
            for i in range(31):
                mu.reg_write(regs[i], env[f"x{i}"])
            mu.reg_write(lr, end)
            env["x30"] = end
            try:
                # generous, because a generated loop runs up to five trips; a run that
                # has not reached the `ret` by then is dropped rather than compared, since
                # the register file mid-loop answers no question the text is making.
                mu.emu_start(BASE, end, count=64 * len(words) + 64)
            except Exception:
                break
            if mu.reg_read(a64.UC_ARM64_REG_PC) != end:
                skipped += 1
                continue
            if prog is not None:
                run_env = dict(env)
                try:
                    run, wrote, retval = _run_body(prog, run_env, 4096)
                except _Undecidable:
                    skipped += 1
                    run_env = None
                except _Unsound as exc:
                    run_env = None
                    failures += 1
                    executed += 1
                    if failures <= 5:
                        _report_cfg(f"unbound name: {exc}", ann, lines, env)
                if run_env is not None:
                    bust = None
                    # Only what the run ASSIGNED, plus the returned value against the
                    # result register. Everything else the text is silent about.
                    claims = [(f"x{i}", run_env[f"x{i}"]) for i in _FUZZ_OUT + (_FUZZ_CTR,)
                              if f"x{i}" in wrote and f"x{i}" not in run.tainted]
                    if retval is not None:
                        claims.append(("x0", retval))
                    for name, got_v in claims:
                        executed += 1
                        want_r = mu.reg_read(regs[int(name[1:])]) & mask(64)
                        if got_v != want_r:
                            bust = (name, got_v, want_r)
                            break
                    if bust:
                        failures += 1
                        if failures <= 5:
                            _report_cfg(f"executed body disagrees on {bust[0]}: "
                                        f"text {bust[1]:#018x} cpu {bust[2]:#018x}",
                                        ann, lines, env)
                        break
            for r, tree in trees.items():
                try:
                    got = _ev(tree, env) & mask(64)
                except _Undecidable:
                    skipped += 1
                    continue
                want_v = mu.reg_read(regs[int(r[1:])]) & mask(64)
                checked += 1
                if got != want_v:
                    failures += 1
                    if failures <= 5:
                        print(f"MISMATCH cfg, {r} = {st.reg[r].text}")
                        for a, m, o, _n in ann:
                            print(f"    {a - BASE:#06x}  {m} {o}")
                        print("  lifted:")
                        for ln in lines:
                            print(f"    {ln}")
                        ins = " ".join(f"x{i}={env[f'x{i}']:#x}" for i in _FUZZ_IN)
                        print(f"  in  {ins}")
                        print(f"  cpu {want_v:#018x}  txt {got:#018x}")
                    break
            else:
                continue
            break

    print(f"\n{count} generated control-flow graphs ({joins} joins, {withgoto} needing a "
          f"goto, {loops} with a back edge), {checked} printed expressions evaluated, "
          f"{executed} register results from RUNNING the printed body, "
          f"{skipped} undecidable, {failures} mismatches")
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# CONTROL FLOW *and* MEMORY, which is where the two exclusions meet
# ---------------------------------------------------------------------------
#
# `run_mem` above is flat on purpose, so the printed text is a plain statement list and
# reading it needs no idea of which path ran. That leaves the question the flat oracle
# cannot ask: a field expression that survives a JOIN or a loop back edge. `_merge` keeps
# the registers two arms agree on, and two arms agree about a register neither of them
# wrote, even when one of them wrote the FIELD that register reads. The value is then
# stale on exactly one of the two paths.
#
# Deciding that needs the printed program run as a program, on the same path the CPU took,
# which is what the interpreter below does: nested `if`/`while`, `break`/`continue`, the
# `var tN =` declarations and the field and register assignments, in order. Evaluating a
# declaration WHERE IT STANDS rather than folding it into the final expression is the whole
# point, folding a declaration past a store to a field it mentions is the defect, not a
# way to look for it.
#
# The tree is then LINEARISED into a flat op list, because `goto` has no meaning in a tree
# walk. The renderer emits one for an edge it cannot nest, about 7% of generated graphs,
# and those are exactly the shape the join defects live in; skipping them would leave the
# oracle blind where it is most wanted. Flat, a label is an index and a goto is a program
# counter. The fourth defect below was found only after this.
#
# WHAT IT SKIPS, and why that is not a quiet hole:
#   * a final expression that still mentions an output register with nothing in the printed
#     body defining it. That is the lifter saying it does not know, and there is no claim
#     to score. The evaluator declines by itself: x0-x7 are left unbound, so a text that
#     rests on one raises rather than reading the entry value as though it were meant.


class _Return(Exception):
    """The printed program reached a `return`. `break` and `continue` need no exception:
    `_flatten` turns both into a jump before the interpreter ever sees them."""


_STMT_DECL = re.compile(r"^var (t\d+) = (.+);$")
_STMT_BARE_DECL = re.compile(r"^var (t\d+);$")
_STMT_ASSIGN = re.compile(
    r"^(x20\.field_0x[0-9a-f]+|t\d+|x(?:3[01]|[12]\d|\d)) ([-+*&|^]?)= (.+);$")
_STMT_IF = re.compile(r"^if \((.+)\) \{$")
_STMT_IF1 = re.compile(r"^if \((.+)\) (break|continue);$")
_STMT_RET = re.compile(r"^return (.+);$")
_STMT_LABEL = re.compile(r"^(L_0x[0-9a-f]+):$")
_STMT_GOTO = re.compile(r"^goto (L_0x[0-9a-f]+);$")
#: Ops the interpreter may retire, per op in the flattened program, before it gives up. A
#: generated loop retires after at most five trips by construction, so anything past this
#: is the printed text disagreeing about termination, not a slow case.
_LOOP_BUDGET = 200


def _parse_stmts(lines: list, i: int, nested: bool):
    """(statement tree, index of the `}` that closed this block)."""
    out = []
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("}"):
            if not nested:
                raise _Undecidable(f"unexpected {s!r}")
            return out, i
        m = _STMT_IF.match(s)
        if m:
            then, i = _parse_stmts(lines, i + 1, True)
            els = []
            if i < len(lines) and lines[i].strip() == "} else {":
                els, i = _parse_stmts(lines, i + 1, True)
            if i >= len(lines) or lines[i].strip() != "}":
                raise _Undecidable("unbalanced if")
            out.append(("if", m.group(1), then, els))
            i += 1
            continue
        if s == "while (true) {":
            body, i = _parse_stmts(lines, i + 1, True)
            if i >= len(lines) or lines[i].strip() != "}":
                raise _Undecidable("unbalanced loop")
            out.append(("loop", body, None))
            i += 1
            continue
        out.append(("stmt", s, None))
        i += 1
    if nested:
        raise _Undecidable("block never closed")
    return out, i


def _exec_one(s: str, env: dict) -> None:
    """One printed statement.

    A value the interpreter cannot decide is UNBOUND rather than fatal, and that is how
    the lifter's own refusals are modelled. `x20.field_0x10 = x3` with a bare x3 is the
    tool saying it does not know what is being stored, after a loop that wrote x3, the
    honest answer, so the field becomes unknown too and is not scored, instead of the
    harness reading `x3` as the value the register came in with and reporting a defect
    that is really the oracle over-reading a gap.
    """
    cut = s.find("   //")                 # the `if Smi` note _assign appends
    if cut >= 0:
        s = s[:cut].rstrip()
    if _STMT_RET.match(s):
        raise _Return
    m = _STMT_BARE_DECL.match(s)
    if m:
        # `var t3;`, a phi whose every arm assigns needs no initialiser, so the name is
        # bound but has no value until an arm runs. Unbound is exactly right; reading it
        # before an assignment is a defect the caller scores, not a statement to refuse.
        # Refusing it instead made every graph whose join had two assigning arms
        # undecidable, which is most of them, and the oracle reported zero because it had
        # scored nothing.
        env.pop(m.group(1), None)
        return
    m = _STMT_DECL.match(s)
    if m:
        _bind(env, m.group(1), m.group(2), "")
        return
    m = _STMT_ASSIGN.match(s)
    if m:
        key = (f"m_{m.group(1).split('_0x')[1]}" if m.group(1).startswith("x20.")
               else m.group(1))
        _bind(env, key, m.group(3), m.group(2))
        return
    raise _Undecidable(f"unmodelled statement {s!r}")


def _bind(env: dict, key: str, text: str, compound: str) -> None:
    try:
        val = _ev(_mem_expr(text), env) & mask(64)
        if compound:
            val = _MEM_COMPOUND[compound](env[key], val) & mask(64)
    except (_Undecidable, SyntaxError, KeyError):
        env.pop(key, None)                # unknown from here on, and it propagates
        return
    env[key] = val


def _flatten(tree: list, ops: list, brk, cont, gen) -> None:
    """Compile the statement tree to a flat op list with explicit labels and jumps.

    Flat rather than recursive because of `goto`. The renderer emits one for an edge it
    cannot nest, and a `goto` out of one arm into a block printed further down has no
    meaning in a tree walk, which is exactly the shape the join defects live in, so
    skipping it would leave the oracle blind where it is most wanted. Once the tree is
    linearised, a jump to a label is a program counter and nothing more.
    """
    for kind, a, b in tree:
        if kind == "stmt":
            s = a
            m = _STMT_LABEL.match(s)
            if m:
                ops.append(("label", m.group(1), None))
                continue
            m = _STMT_GOTO.match(s)
            if m:
                ops.append(("jump", m.group(1), None))
                continue
            if s == "break;":
                ops.append(("jump", brk, None))
                continue
            if s == "continue;":
                ops.append(("jump", cont, None))
                continue
            m = _STMT_IF1.match(s)
            if m:
                ops.append(("jnz", m.group(1),
                            brk if m.group(2) == "break" else cont))
                continue
            ops.append(("stmt", s, None))
        elif kind == "if":
            els, end = gen(), gen()
            ops.append(("jz", b[0], els))
            _flatten(a, ops, brk, cont, gen)
            ops.append(("jump", end, None))
            ops.append(("label", els, None))
            _flatten(b[1], ops, brk, cont, gen)
            ops.append(("label", end, None))
        else:                                       # loop
            top, end = gen(), gen()
            ops.append(("label", top, None))
            _flatten(a, ops, end, top, gen)
            ops.append(("jump", top, None))
            ops.append(("label", end, None))


def _run_printed(lines: list, env: dict) -> None:
    """Run the printed program in `env`. Raises _Undecidable on anything unmodelled."""
    tree, _i = _parse_stmts(lines, 0, False)

    # `if` carries (cond, else-branch) in one slot so the tuples stay uniform.
    def fix(seq):
        out = []
        for s in seq:
            if s[0] == "if":
                out.append(("if", fix(s[2]), (s[1], fix(s[3]))))
            elif s[0] == "loop":
                out.append(("loop", fix(s[1]), None))
            else:
                out.append(s)
        return out

    counter = [0]

    def gen():
        counter[0] += 1
        return f"#{counter[0]}"

    ops = []
    _flatten(fix(tree), ops, None, None, gen)
    labels = {}
    for i, (kind, a, _b) in enumerate(ops):
        if kind == "label":
            if a in labels:
                raise _Undecidable(f"label {a} defined twice")
            labels[a] = i
    budget = _LOOP_BUDGET * max(len(ops), 1)
    pc = 0
    while pc < len(ops):
        budget -= 1
        if budget < 0:
            raise _Undecidable("the printed program did not terminate")
        kind, a, b = ops[pc]
        if kind == "label":
            pc += 1
        elif kind == "stmt":
            try:
                _exec_one(a, env)
            except _Return:
                return
            pc += 1
        elif kind == "jump":
            if a not in labels:
                raise _Undecidable(f"jump to an undefined {a}")
            pc = labels[a]
        else:                                       # jz / jnz on a rendered condition
            taken = bool(_ev(_mem_expr(a), env))
            if kind == "jz":
                taken = not taken
            if taken:
                if b not in labels:
                    raise _Undecidable(f"branch to an undefined {b}")
                pc = labels[b]
            else:
                pc += 1


def run_cfgmem(count: int, trials: int, seed: int, verbose: bool,
               seed_outs: bool = False) -> int:
    uc_mod = _unicorn()
    if uc_mod is None:
        print("SKIP: unicorn is not installed")
        return 0
    _u, Uc, ARCH, MODE, a64 = uc_mod
    bad = verify_fuzz_encodings() + verify_mem_encodings()
    if bad:
        for want, actual in bad:
            print(f"BAD ENCODING: claimed {want!r}, decodes to {actual!r}")
        return 1

    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from jadart.cfg import build_cfg, structure, label_targets
    from jadart.expr import Lifter, State, use_target, ARM64

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    regs = {i: getattr(a64, f"UC_ARM64_REG_X{i}") for i in range(31)}
    lr = a64.UC_ARM64_REG_X30
    rng = random.Random(seed)
    failures = checked = memchecked = skipped = 0
    joins = loops = withgoto = scored = 0

    for _case in range(count):
        words = _gen_function(rng, mem=True, seed_outs=seed_outs)
        code = b"".join(struct.pack("<I", w) for w in words)
        ann = [(i.address, i.mnemonic, i.op_str, "") for i in md.disasm(code, BASE)]
        if len(ann) != len(words):
            continue
        blocks, entry = build_cfg(ann)
        if len(blocks) < 2:
            continue
        stmts = structure(blocks, entry)
        with use_target(ARM64):
            lif = Lifter(blocks, entry=entry)
            lif.labels = label_targets(stmts)
            st = State()
            lines, _falls = lif.walk(stmts, st, "  ", 0)
            # The state at the RETURN, not at the end of the walk. `structure` emits blocks
            # in an order that is not a path, so with a goto in the graph the last block
            # printed is not the one the function leaves from, and the register map the
            # walk ends holding then describes some other block. `_exit` is what the lifter
            # left each block in, which is the claim it is actually making about that one.
            end_blk = next((a for a, b in blocks.items() if b.term == "ret"), None)
            exit_st = lif._exit.get(end_blk, st)
            texts = {f"x{i}": exit_st.reg[f"x{i}"].text for i in _FUZZ_OUT
                     if f"x{i}" in exit_st.reg}
        if lif.labels:
            withgoto += 1
        joins += sum(1 for b in blocks
                     if sum(1 for o in blocks if b in blocks[o].succ) > 1)
        if any(t <= a for a in blocks for t in blocks[a].succ):
            loops += 1
        trees = {}
        for r, t in texts.items():
            if t == r:
                continue                       # the lifter says it does not know
            # Unlike run_cfg, a text that MENTIONS an output register is not filtered out
            # here. It is scored where a printed statement bound that register, `_phi`
            # writes the arms' disagreement out as `x3 = ...;` and the reader takes it,
            # and declines by itself where nothing did, because x0-x7 are left unbound.
            try:
                trees[r] = _mem_expr(t)
            except (_Undecidable, SyntaxError):
                pass
        if not trees:
            continue
        scored += 1

        end = BASE + len(code)
        bad_case = False
        for _ in range(trials):
            seeded = {f"x{i}": rng.getrandbits(64) for i in range(31)}
            # x0-x7 are the registers the generator WRITES, so a bare one in the printed
            # text is the lifter declining rather than a reference to the incoming value.
            # This holds under `--seed-outputs` too, and binding them there was tried and
            # is wrong: the preamble loads them, so the CPU has a knowable value and it is
            # tempting to put it in the map, but after a loop the lifter prints a bare `x3`
            # meaning "I do not know" while the CPU has moved on, and every one of those
            # gaps is then reported as a defect. The preamble already does the work without
            # it, what it buys is that the lifter holds a FIELD EXPRESSION for each of
            # these instead of nothing, so the loop-carried chains become decidable.
            # Leaving them unbound is what makes `_ev` decline in turn; binding them would
            # read every gap as a claim about the entry state.
            env = {k: v for k, v in seeded.items()
                   if not (k[1:].isdigit() and int(k[1:]) <= _FUZZ_CTR)}
            env["xzr"] = 0
            slots = {d: rng.getrandbits(64) for d in _MEM_DISPS}
            mu = Uc(ARCH, MODE)
            mu.mem_map(BASE, 0x2000)
            mu.mem_map(SCRATCH, 0x1000)
            mu.mem_write(BASE, code)
            for d, v in slots.items():
                mu.mem_write(SCRATCH + d + 1, struct.pack("<Q", v))
            for i in range(31):
                mu.reg_write(regs[i], seeded[f"x{i}"])
            mu.reg_write(regs[_MEM_BASE], SCRATCH + 1)
            env[f"x{_MEM_BASE}"] = SCRATCH + 1
            for d, v in slots.items():
                env[_mem_key(d)] = v
            mu.reg_write(lr, end)
            env["x30"] = end
            try:
                mu.emu_start(BASE, end, count=64 * len(words) + 64)
            except Exception:
                break
            if mu.reg_read(a64.UC_ARM64_REG_PC) != end:
                skipped += 1
                continue                       # still mid-loop: the text claims nothing
            try:
                _run_printed(lines, env)
            except (_Undecidable, SyntaxError, KeyError):
                skipped += 1
                break
            for r, tree in trees.items():
                try:
                    got = _ev(tree, env) & mask(64)
                except _Undecidable:
                    skipped += 1
                    continue
                want_v = mu.reg_read(regs[int(r[1:])]) & mask(64)
                checked += 1
                if got != want_v:
                    failures += 1
                    bad_case = True
                    if failures <= 5:
                        _mem_report(f"{r} = {texts[r]}", ann, lines, slots, env,
                                    want_v, got)
                    break
            if bad_case:
                break
            for d in _MEM_DISPS:
                if _mem_key(d) not in env:
                    skipped += 1
                    continue              # a store the printed text did not pin down
                want_v = struct.unpack("<Q", mu.mem_read(SCRATCH + d + 1, 8))[0]
                got = env[_mem_key(d)] & mask(64)
                memchecked += 1
                if got != want_v:
                    failures += 1
                    bad_case = True
                    if failures <= 5:
                        _mem_report(f"memory at {_mem_name(d)}", ann, lines, slots, env,
                                    want_v, got)
                    break
            if bad_case:
                break
        if verbose and not bad_case:
            print(f"  ok  {len(words):>2} insns, {len(trees)} expressions")

    print(f"\n{count} generated graphs with memory{' and seeded outputs' if seed_outs else ''} "
          f"({joins} joins, {loops} with a back "
          f"edge, {withgoto} needing a goto), {scored} interpreted, {checked} "
          f"printed expressions and {memchecked} field values evaluated, {skipped} "
          f"undecidable, {failures} mismatches")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
