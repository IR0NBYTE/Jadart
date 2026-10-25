#!/usr/bin/env python3
"""Differential execution of the PRINTED BODY against a real arm64 CPU.

The criterion is the one the rest of the tool already states: registers in the output
start at their entry values and mean whatever the printed body last assigned them. A
register the printed body never assigns reads as the value the function came in with,
which for x1-x7 is an argument. `expr._verbatim` says it ("a register the lifter holds as
an expression was never assigned in the printed body"), `expr._phi_name` says it from the
other side, and `test_every_printed_write_to_a_machine_register_comes_from_a_pinned_bump`
says why it matters: "from that line on, the token `x3` in the output means what the
statement put there".

Two things make a register write PRINTED, and both are outside what irfuzz can score:

  * a line printed RAW. `irfuzz._exec_one` raises _Undecidable on one, so the case is
    dropped before it is compared. Here the line is executed on the CPU against the
    printed body's own state, which is what "the printed body reads the line as having
    run" means, and the `// x1 holds x1 + 8` note is bound first because `_verbatim`
    prints that note instead of an assignment on purpose (#120).
  * a MOVING base. `irfuzz._mem_expr` maps `x20.field_0xN` to a fixed slot key, so a
    `_bump` that advances the base still reads the old slot. Here memory is a real byte
    array and `.field_0xN` is a load from (base + N - 1), so a moved base is modelled.

A printed register write is the PRECONDITION for the staleness #187 is about: with none,
a folded expression still reads the entry registers and is right. So this is the oracle
that scores #187's class, and the frame-slot path the issue asks for ("the repo's
tools/irfuzz.py memory and corpus oracles use x20 for every object base, never x29, so
they never exercise the frame-slot path").

WHAT IS NOT SCORED. A bare register in the output can be the lifter DECLINING rather than
naming the entry value, and FINDINGS.md records that a lost value "rests on the bare
register meaning nothing to the reader". A printed store is therefore scored only when
every register in its text is either one the generated code never writes, so it is an
argument and means the entry value, or one the printed body has already assigned, so it
is a claim. Anything else is counted undecidable, never as a defect: a harness that reads
a decline as a wrong answer reports defects that are its own.

WHAT IT CANNOT SEE. It lifts ONE BLOCK through `_lift_block`, so a decision
`lift_function` makes over the whole body is invisible: the `keep`, `carry` and
`join_phi` passes, and anything else that re-walks. And a store resting on a bare
register is counted undecidable, so a defect spelled AS a decline is not reported as
one. #196 and the #199 regression were both of those at once, and this tool was silent
on both in either direction; a census of what each drop loses, plus a direct comparison
of candidate spellings against the CPU, are what found and settled them. Silence here is
not a pass, and `run()` returning 0 while scoring nothing is tracked in #199.

Usage:
  python framework/tools/pbfuzz.py --cases 400 --trials 12 --seed 1
  python framework/tools/pbfuzz.py --no-args      # destinations preloaded, declines kept
Exit code 1 if any scored store disagreed with the CPU.
"""
import argparse
import ast
import operator
import os
import random
import re
import struct
import sys

CODE = 0x100000
MEM = 0x400000
MEMSZ = 0x10000
MASK = (1 << 64) - 1
XI = list(range(31))

OBS = 20                        # the observable object, as irfuzz uses x20
FPR = 29                        # frame pointer, the slot path #187 asks for
BASES = (9, 10, 11, 12)         # pointer bases a writeback may advance
VALUES = (1, 2, 3, 4, 5, 6, 7)  # the argument registers the runs compute with
SEED_BASE = 13                  # read-only base --no-args preloads the values from
OBS_DISPS = (7, 15, 23, 31)     # observable store displacements
FRAME = (-8, -16, -24, -32)     # frame slots the runs spill to

#: Role names expr.py prints for the registers it knows by role.
ROLE = {"SP": "x15", "FP": f"x{FPR}", "LR": "x30", "THR": "x26", "PP": "x27",
        "HEAP": "x28", "NULL": "x22", "DISPATCH": "x21"}


def _enc_alu(base):
    return lambda d, n, m: base | (m << 16) | (n << 5) | d


#: (text template, encoder). Every word is checked against capstone before a trial runs,
#: for the reason irfuzz's own tables are: a harness that fuzzes a different instruction
#: than the one it names reports a clean pass and proves nothing.
ALU = [("add {d}, {n}, {m}", _enc_alu(0x8B000000)),
       ("sub {d}, {n}, {m}", _enc_alu(0xCB000000)),
       ("and {d}, {n}, {m}", _enc_alu(0x8A000000)),
       ("orr {d}, {n}, {m}", _enc_alu(0xAA000000)),
       ("eor {d}, {n}, {m}", _enc_alu(0xCA000000))]
IMM = [("add {d}, {n}, #{i}", lambda d, n, i: 0x91000000 | (i << 10) | (n << 5) | d),
       ("sub {d}, {n}, #{i}", lambda d, n, i: 0xD1000000 | (i << 10) | (n << 5) | d)]
#: Printed RAW, so the printed line assigns its destination itself. `adcs` also reads the
#: carry, which is why the interpreter carries NZCV across raw lines.
RAW = [("adcs {d}, {n}, {m}", _enc_alu(0xBA000000)),
       ("umulh {d}, {n}, {m}", lambda d, n, m: 0x9BC07C00 | (m << 16) | (n << 5) | d)]


def enc_ldur(t, n, imm):
    return 0xF8400000 | ((imm & 0x1FF) << 12) | (n << 5) | t


def enc_stur(t, n, imm):
    return 0xF8000000 | ((imm & 0x1FF) << 12) | (n << 5) | t


def enc_ldr_post(t, n, imm):
    """`ldr xt, [xn], #imm`: the writeback that makes `_bump` print `xn = xn + imm;`."""
    return 0xF8400400 | ((imm & 0x1FF) << 12) | (n << 5) | t


def enc_mov(d, m):
    return 0xAA0003E0 | (m << 16) | d


RET_WORD = 0xD65F03C0


def _capstone():
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        return None
    return Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def _unicorn():
    try:
        import unicorn
    except ImportError:
        return None
    return unicorn


def verify_encodings() -> list:
    """Every encoder this oracle uses, decoded back by capstone and compared to the text
    the generator claims it assembled. Returns the disagreements."""
    md = _capstone()
    bad = []

    def decode(word):
        got = [f"{i.mnemonic} {i.op_str}".strip()
               for i in md.disasm(struct.pack("<I", word), CODE)]
        return got[0] if got else "<undecodable>"

    for tmpl, enc in ALU + RAW:
        want = tmpl.format(d="x3", n="x4", m="x5")
        got = decode(enc(3, 4, 5))
        if got != want:
            bad.append((want, got))
    for tmpl, enc in IMM:
        want = tmpl.format(d="x3", n="x4", i="0x1f")
        got = decode(enc(3, 4, 0x1F))
        if got != want:
            bad.append((want, got))
    for d in OBS_DISPS:
        shown = f"#{d}" if d < 10 else f"#{d:#x}"
        for want, word in ((f"ldur x3, [x{OBS}, {shown}]", enc_ldur(3, OBS, d)),
                           (f"stur x3, [x{OBS}, {shown}]", enc_stur(3, OBS, d))):
            got = decode(word)
            if got != want:
                bad.append((want, got))
    for d in FRAME:
        shown = f"#-{-d}" if -d < 10 else f"#-{-d:#x}"
        for want, word in ((f"ldur x3, [x{FPR}, {shown}]", enc_ldur(3, FPR, d)),
                           (f"stur x3, [x{FPR}, {shown}]", enc_stur(3, FPR, d))):
            got = decode(word)
            if got != want:
                bad.append((want, got))
    for want, word in ((f"ldr x3, [x9], #0x10", enc_ldr_post(3, 9, 16)),
                       ("mov x3, x5", enc_mov(3, 5)),
                       ("ret", RET_WORD)):
        got = decode(word)
        if got != want:
            bad.append((want, got))
    return bad


def gen(rng, preload: bool):
    """A run as (text, word) pairs.

    It opens by filling every frame slot it may later reload. Without that a reload reads
    a slot nothing wrote and `expr._reload` returns the register's own name, the lifter
    declining, and irfuzz says at `run_cfgmem` why a decline must not be scored: "binding
    them would read every gap as a claim about the entry state". With `preload` the value
    registers are loaded from a read-only base first, so each holds a FIELD EXPRESSION
    rather than its own name and a bare one anywhere is unambiguously a decline. That is
    `--seed-outputs`' argument applied to this oracle.
    """
    rows = []
    if preload:
        for k, d in enumerate(VALUES):
            rows.append((f"ldur x{d}, [x{SEED_BASE}, #{8 * k:#x}]",
                         enc_ldur(d, SEED_BASE, 8 * k)))
    for k, off in enumerate(FRAME):
        d = VALUES[k % len(VALUES)]
        rows.append((f"stur x{d}, [x{FPR}, #-{-off:#x}]", enc_stur(d, FPR, off)))
    for _ in range(rng.randint(5, 13)):
        rows.append(_row(rng))
    for _ in range(rng.randint(1, 3)):
        d, off = rng.choice(VALUES), rng.choice(OBS_DISPS)
        rows.append((f"stur x{d}, [x{OBS}, #{off:#x}]", enc_stur(d, OBS, off)))
    rows.append(("ret", RET_WORD))
    return rows


def _row(rng):
    """One instruction, weighted so SELF-REFERENTIAL writes, PRINTED register writes and
    frame-slot round trips all occur often, and often in the same run."""
    roll, d = rng.random(), rng.choice(VALUES)
    if roll < 0.20:                                   # self-referential: d is a source
        tmpl, enc = rng.choice(ALU)
        m = rng.choice(VALUES)
        n, m = (m, d) if rng.random() < 0.5 else (d, m)
        return tmpl.format(d=f"x{d}", n=f"x{n}", m=f"x{m}"), enc(d, n, m)
    if roll < 0.30:                                   # self-referential, immediate
        tmpl, enc = rng.choice(IMM)
        i = rng.randint(1, 500)
        return tmpl.format(d=f"x{d}", n=f"x{d}", i=f"{i:#x}"), enc(d, d, i)
    if roll < 0.42:
        off = rng.choice(FRAME)
        return f"stur x{d}, [x{FPR}, #-{-off:#x}]", enc_stur(d, FPR, off)
    if roll < 0.54:
        off = rng.choice(FRAME)
        return f"ldur x{d}, [x{FPR}, #-{-off:#x}]", enc_ldur(d, FPR, off)
    if roll < 0.62:                                   # writeback: `_bump` prints the base
        b, i = rng.choice(BASES), rng.choice((8, 16, 24))
        return f"ldr x{d}, [x{b}], #{i:#x}", enc_ldr_post(d, b, i)
    if roll < 0.70:                                   # printed RAW
        tmpl, enc = rng.choice(RAW)
        m = rng.choice(VALUES)
        return tmpl.format(d=f"x{d}", n=f"x{d}", m=f"x{m}"), enc(d, d, m)
    if roll < 0.80:
        tmpl, enc = rng.choice(ALU)
        n, m = rng.choice(VALUES), rng.choice(VALUES)
        return tmpl.format(d=f"x{d}", n=f"x{n}", m=f"x{m}"), enc(d, n, m)
    if roll < 0.88:
        b, off = rng.choice(BASES), rng.choice((0, 8, 16, 24))
        return f"ldur x{d}, [x{b}, #{off:#x}]", enc_ldur(d, b, off)
    if roll < 0.94:
        m = rng.choice(VALUES)
        return f"mov x{d}, x{m}", enc_mov(d, m)
    d2, off = rng.choice(VALUES), rng.choice(OBS_DISPS)
    return f"stur x{d2}, [x{OBS}, #{off:#x}]", enc_stur(d2, OBS, off)


class Undecidable(Exception):
    """The printed body says something this harness cannot resolve, so the case is
    dropped rather than scored. A gap here must never read as a defect in the lifter."""


DECL = re.compile(r"^\s*var (t\d+) = (.+);$")
BARE = re.compile(r"^\s*var (t\d+);$")
REGA = re.compile(r"^\s*(x(?:3[01]|[12]\d|\d)) ([-+*&|^]?)= (.+);$")
FLDA = re.compile(r"^\s*(.+)\.field_(-?0x[0-9a-fA-F]+) ([-+*&|^]?)= (.+);$")
RETL = re.compile(r"^\s*return (.+);$")
#: `_verbatim`'s note, `// x1 holds x1 + 8, x3 holds t0`.
HOLDS = re.compile(r"\b([a-z]\d+) holds ((?:(?!, [a-z]\d+ holds ).)+)")
REGTOK = re.compile(r"\b([wx](?:3[01]|[12]\d|\d))\b")
COMPOUND = {"+": operator.add, "-": operator.sub, "*": operator.mul,
            "&": operator.and_, "|": operator.or_, "^": operator.xor}
BINOP = ((ast.Add, operator.add), (ast.Sub, operator.sub), (ast.Mult, operator.mul),
         (ast.BitAnd, operator.and_), (ast.BitOr, operator.or_),
         (ast.BitXor, operator.xor))


class Body:
    """The printed body, interpreted. Registers start at the values the function came in
    with and mean what the body last assigned them; memory is a real array its stores
    update, so a moved base reads where it now points."""

    def __init__(self, uc, ureg, nzcv_id, regs, mem, written):
        self.uc = uc
        self.ureg = ureg
        self.nzcv_id = nzcv_id
        self.reg = dict(regs)
        self.mem = bytearray(mem)
        self.t = {}
        self.nzcv = 0
        self.written = written      # registers the generated code writes somewhere
        self.bound = set()          # registers the printed body has assigned
        self.writes = {}            # addr -> whether its last printed store was scorable

    def load(self, addr):
        addr &= MASK
        if not (MEM <= addr < MEM + MEMSZ - 8):
            raise Undecidable("load outside the mapped window")
        return struct.unpack_from("<Q", self.mem, addr - MEM)[0]

    def store(self, addr, val):
        addr &= MASK
        if not (MEM <= addr < MEM + MEMSZ - 8):
            raise Undecidable("store outside the mapped window")
        struct.pack_into("<Q", self.mem, addr - MEM, val & MASK)

    def ev(self, text):
        try:
            tree = ast.parse(text.replace("~/", "//").replace(">>>", ">>"), mode="eval")
        except SyntaxError:
            raise Undecidable(f"unparsed {text!r}")

        def go(n):
            if isinstance(n, ast.Expression):
                return go(n.body)
            if isinstance(n, ast.Constant):
                if not isinstance(n.value, int):
                    raise Undecidable("non-integer literal")
                return n.value
            if isinstance(n, ast.Name):
                if n.id in self.t:
                    if self.t[n.id] is None:
                        raise Undecidable(f"{n.id} read before an arm assigned it")
                    return self.t[n.id]
                if n.id == "xzr":
                    return 0
                key = ROLE.get(n.id, n.id)
                if key in self.reg:
                    return self.reg[key]
                raise Undecidable(f"unbound {n.id}")
            if isinstance(n, ast.Attribute):
                if not n.attr.startswith("field_"):
                    raise Undecidable(f"unknown attribute {n.attr}")
                return self.load(go(n.value) + int(n.attr[6:], 16) - 1)
            if isinstance(n, ast.UnaryOp):
                v = go(n.operand)
                if isinstance(n.op, ast.USub):
                    return -v
                if isinstance(n.op, ast.Invert):
                    return ~v
                raise Undecidable("unmodelled unary operator")
            if isinstance(n, ast.BinOp):
                a, b = go(n.left), go(n.right)
                for kind, fn in BINOP:
                    if isinstance(n.op, kind):
                        return fn(a, b)
                if isinstance(n.op, ast.LShift):
                    if not 0 <= (b & MASK) < 64:
                        raise Undecidable("shift amount out of range")
                    return a << b
                if isinstance(n.op, ast.RShift):
                    if (a & MASK) >= 1 << 63:
                        raise Undecidable("printed >> of a value with the top bit set")
                    return (a & MASK) >> b
                if isinstance(n.op, ast.FloorDiv):
                    if (b & MASK) == 0:
                        raise Undecidable("division by zero")
                    return (a & MASK) // (b & MASK)
                raise Undecidable("unmodelled binary operator")
            raise Undecidable(f"unmodelled node {type(n).__name__}")
        return go(tree) & MASK

    def raw(self, line, word, held, defs, uses):
        """A line printed raw, executed on the CPU against the body's own state.

        `held` is the line's own `// x6 holds t1` note. `_verbatim` prints that instead of
        an assignment on purpose, so the printed body still assigns a register only where
        the machine's instruction does (#120); the value is in the output and a reader is
        meant to take it, so binding it is reading the line as the lifter writes it.
        Only the registers the line WRITES are read back: one it merely reads keeps what
        the printed body gave it.
        """
        regs = dict(self.reg)
        for r, text in held:
            regs[r] = self.ev(text)
        for u in uses:
            if u != "xzr" and u not in regs:
                raise Undecidable(f"{line!r} reads {u}, which the body never bound")
        uc = self.uc
        uc.mem_write(CODE, struct.pack("<I", word))
        uc.mem_write(MEM, bytes(self.mem))
        for i in XI:
            uc.reg_write(self.ureg[i], regs.get(f"x{i}", 0))
        uc.reg_write(self.nzcv_id, self.nzcv)
        try:
            uc.emu_start(CODE, CODE + 4, count=1)
        except Exception:
            raise Undecidable(f"{line!r} faulted")
        for d in defs:
            if d != "xzr" and REGTOK.fullmatch(d):
                self.reg[d] = uc.reg_read(self.ureg[int(d[1:])])
                self.bound.add(d)
        self.nzcv = uc.reg_read(self.nzcv_id)
        self.mem = bytearray(uc.mem_read(MEM, MEMSZ))

    def run(self, lines, words, defuse):
        for ln in lines:
            cut = ln.find("   //")
            note = ln[cut + 5:] if cut >= 0 else ""
            s = (ln[:cut] if cut >= 0 else ln).strip()
            if not s:
                continue
            if not s.endswith((";", "{", "}", ":")):
                if s not in words:
                    raise Undecidable(f"raw line {s!r} is not one of the generated words")
                self.raw(s, words[s], HOLDS.findall(note), *defuse[s])
                continue
            m = BARE.match(s)
            if m:
                self.t[m.group(1)] = None
                continue
            m = DECL.match(s)
            if m:
                self.t[m.group(1)] = self.ev(m.group(2))
                continue
            if RETL.match(s):
                return
            m = REGA.match(s)
            if m:
                val = self.ev(m.group(3))
                if m.group(2):
                    val = COMPOUND[m.group(2)](self.reg[m.group(1)], val) & MASK
                self.reg[m.group(1)] = val
                self.bound.add(m.group(1))
                continue
            m = FLDA.match(s)
            if m:
                addr = self.ev(m.group(1)) + int(m.group(2), 16) - 1
                val = self.ev(m.group(4))
                if m.group(3):
                    val = COMPOUND[m.group(3)](self.load(addr), val) & MASK
                self.store(addr, val)
                risky = set(REGTOK.findall(m.group(1) + " " + m.group(4)))
                self.writes[addr & MASK] = not (risky & self.written) - self.bound
                continue
            raise Undecidable(f"unmodelled statement {s!r}")


def lift(ann):
    """The printed body for one block, straight from `_lift_block`'s return value.

    Not by patching: `_pin` and `_bump` are reached from inside `_step`, so hooking them
    and `_step` records their lines twice, and a doubled `x10 = x10 + 24;` makes a correct
    body look always-wrong. `_lift_block` drains `st.spill` into the list it returns, so
    that list is the whole body.
    """
    from jadart.cfg import Block
    from jadart.expr import Lifter, State, use_target, ARM64
    with use_target(ARM64):
        blk = Block(addr=CODE, insns=ann, succ=[], term="ret")
        lines, _falls = Lifter({CODE: blk})._lift_block(CODE, State())
    return lines


def env_for(rng, bind_values: bool):
    """(cpu registers, printed-body registers, memory).

    The CPU gets every register. The printed body gets the value registers only when the
    run reads them before writing them, which is what an argument is.
    """
    cpu = {}
    for i in XI:
        if i in VALUES:
            cpu[f"x{i}"] = rng.getrandbits(64)      # wide, so nothing cancels by luck
        else:
            cpu[f"x{i}"] = (MEM + 0x1000 + i * 0x600
                            + 16 * rng.randrange(0, 0x20)) & ~0xF
    body = (dict(cpu) if bind_values
            else {k: v for k, v in cpu.items() if int(k[1:]) not in VALUES})
    return cpu, body, bytes(rng.randbytes(MEMSZ))


class Oracle:
    """unicorn, capstone and the lifter, set up once and reused across runs."""

    def __init__(self):
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN
        from unicorn import arm64_const as A
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.ureg = {i: getattr(A, f"UC_ARM64_REG_X{i}") for i in XI}
        self.nzcv_id = A.UC_ARM64_REG_NZCV

        def fresh():
            uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
            uc.mem_map(CODE, 0x1000)
            uc.mem_map(MEM, MEMSZ)
            return uc
        self.runner, self.scratch = fresh(), fresh()

    def score(self, rows, trials=12, seed=0, bind_values=True):
        """(clean, wrong, undecidable, lines) for ONE run over `trials` environments.

        `clean` counts environments where every SCORED store agreed with the CPU, `wrong`
        those where one did not, and `undecidable` those with nothing to score. A shape
        the tests hand to this either agrees everywhere or it does not.
        """
        from jadart.expr import use_target, ARM64, _def_use, canon
        code = b"".join(struct.pack("<I", w) for _t, w in rows)
        ann = [(i.address, i.mnemonic, i.op_str, "") for i in self.md.disasm(code, CODE)]
        if len(ann) != len(rows):
            raise AssertionError(f"{len(rows)} words encoded, {len(ann)} decoded")
        words = {f"{m} {o}".strip(): w for (_t, w), (_a, m, o, _n) in zip(rows, ann)}
        with use_target(ARM64):
            defuse, written = {}, set()
            for _a, m, o, _n in ann:
                defs, uses = (({canon(r) for r in side}) for side in _def_use(m, o))
                defuse[f"{m} {o}".strip()] = (defs, uses)
                written |= defs
        lines = lift(ann)
        rng = random.Random(seed)
        clean = wrong = undec = 0
        for _ in range(trials):
            cpu, body_regs, mem = env_for(rng, bind_values)
            self.runner.mem_write(CODE, code)
            self.runner.mem_write(MEM, mem)
            for i in XI:
                self.runner.reg_write(self.ureg[i], cpu[f"x{i}"])
            # The flags start cleared, exactly as the printed body's interpreter starts
            # them. Left over from the previous trial instead, a raw `adcs` reads a carry
            # the body cannot know and a correct body scores as sometimes-wrong.
            self.runner.reg_write(self.nzcv_id, 0)
            try:                                      # stop before the closing `ret`
                self.runner.emu_start(CODE, CODE + len(code) - 4)
            except Exception:
                undec += 1
                continue
            want = bytes(self.runner.mem_read(MEM, MEMSZ))
            body = Body(self.scratch, self.ureg, self.nzcv_id, body_regs, mem, written)
            try:
                body.run(lines, words, defuse)
            except Undecidable:
                undec += 1
                continue
            keep = [a for a, flag in body.writes.items() if flag]
            if not keep:
                undec += 1
            elif all(body.mem[a - MEM:a - MEM + 8] == want[a - MEM:a - MEM + 8]
                     for a in keep):
                clean += 1
            else:
                wrong += 1
        return clean, wrong, undec, lines


def run(cases, trials, seed, preload, verbose):
    if _unicorn() is None or _capstone() is None:
        print("SKIP: pbfuzz needs unicorn and capstone")
        return 0
    bad_enc = verify_encodings()
    if bad_enc:
        for want, got in bad_enc:
            print(f"  ENCODER: wanted {want!r}, capstone read {got!r}")
        return 2
    oracle = Oracle()
    rng = random.Random(seed)
    scored = clean = wrong = skipped = 0
    worst = []
    for case in range(cases):
        rows = gen(rng, preload)
        try:
            ok, no, _undec, lines = oracle.score(rows, trials, seed * 10007 + case,
                                                 not preload)
        except AssertionError:
            continue
        except Exception as exc:                       # a lifter crash is a defect too
            print(f"  LIFTER RAISED {type(exc).__name__}: {exc}")
            wrong += 1
            continue
        if ok == 0 and no == 0:
            skipped += 1
            continue
        scored += 1
        if no == 0:
            clean += 1
            continue
        wrong += 1
        if len(worst) < 3:
            worst.append((rows, lines, ok, no))
    print(f"\n{cases} generated runs, {scored} scored ({skipped} undecidable), "
          f"{clean} clean, {wrong} with a disagreement")
    for rows, lines, ok, no in (worst if verbose or wrong else []):
        print("\n  run:")
        for t, _w in rows:
            print(f"    {t}")
        print(f"  printed body (agreed in {ok} of {ok + no} environments):")
        for ln in lines:
            print(f"    {ln.strip()}")
    return 1 if wrong else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cases", type=int, default=400)
    ap.add_argument("--trials", type=int, default=12)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--no-args", dest="preload", action="store_true",
                    help="preload the value registers from memory instead of reading "
                         "them as arguments, so every bare register is a decline")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    if a.cases < 1 or a.trials < 1:
        ap.error("--cases and --trials must be positive")
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return run(a.cases, a.trials, a.seed, a.preload, a.verbose)


if __name__ == "__main__":
    sys.exit(main())
