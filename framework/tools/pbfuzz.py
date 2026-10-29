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
    ap.add_argument("--census", metavar="BINARY",
                    help="classify every frame reload of a real image instead of "
                         "fuzzing; needs capstone only, no emulator")
    a = ap.parse_args()
    if a.census:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        if _capstone() is None:
            print("SKIP: the census needs capstone")
            return 0
        t = census(a.census, a.verbose)
        print(f"{t['ranges']} ranges: {t['spelled']} records spelled "
              f"({t['stale']} stale); the fallback took its own register "
              f"{t['same_reg']} times correctly, {t['diff_reg']} where the slot held "
              f"another register and {t['expr']} where it held an expression; "
              f"{t['name']} out-of-scope names and {t['never']} genuine declines")
        print(f"  of {t['lifted']} ranges lifted, {t['oos_fns']} read a name whose "
              f"declaration has closed, {t['oos']} reads in all")
        print(f"WRONG READS: {t['wrong']}   STALE RECORDS: {t['stale']}")
        return 1 if t["stale"] else 0
    if a.cases < 1 or a.trials < 1:
        ap.error("--cases and --trials must be positive")
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return run(a.cases, a.trials, a.seed, a.preload, a.verbose)



# THE CENSUS: the one check for #196's class that needs no CPU.
#
# A reload that spells a register the slot did not hold, and a record spelled on a path
# that superseded it, are both properties of the PRINTED BODY and the instruction list.
# No emulator is involved, so unlike everything above this runs wherever capstone does,
# which is every pull request. #197 shipped 2,023 stale spellings past four green CI jobs
# and a clean suite because nothing looked; this is what looks.
#
# The bookkeeping has to fork where the lifter forks its state, or the numbers are wrong
# in both directions. That cost five wrong measurements to learn, so it is spelled out:
# a per-key history travels with `State.copy`, is intersected by `_merge`, and only the
# LAST walk of each function is scored, because `lift_function` walks up to three times
# and the earlier walks' lines are thrown away.

def _census_hooks(expr):
    """Install the hooks, returning (restore, totals, per-walk cell)."""
    hist, alive, walk = {}, [], {"cur": None}
    tot = {"spelled": 0, "stale": 0, "same_reg": 0, "diff_reg": 0, "name": 0,
           "expr": 0, "never": 0, "ranges": 0, "oos": 0, "oos_fns": 0, "lifted": 0,
           "undecl": 0,
           "regline": 0, "empty": 0, "unbalanced": 0, "twice": 0, "above": 0,
           "sole": 0}
    saved = {n: getattr(expr.State, n)
             for n in ("note_slot", "record_drop", "forget_slot", "copy",
                       "stale_on_write")}
    real_merge, real_reload = expr._merge, expr.Lifter._reload
    real_init = expr.Lifter.__init__

    def h(st):
        alive.append(st)
        return hist.setdefault(id(st), {})

    def note_slot(self, key, v):
        h(self)[key] = ("fill", v.text)
        return saved["note_slot"](self, key, v)

    def record_drop(self, key, v):
        out = saved["record_drop"](self, key, v)
        if key in self.dropped:
            h(self)[key] = ("drop", v.text)
        return out

    def forget_slot(self, key):
        h(self)[key] = ("forget", None)
        return saved["forget_slot"](self, key)

    def stale_on_write(self, written, keep=()):
        before = {k: v.text for k, v in self.slot.items()}
        out = saved["stale_on_write"](self, written, keep)
        for k, t in before.items():
            if k not in self.slot and h(self).get(k, (None,))[0] != "drop":
                h(self)[k] = ("lost", t)
        return out

    def copy(self):
        s = saved["copy"](self)
        hist[id(s)] = dict(h(self))
        alive.append(s)
        return s

    def merge(dst, a, b):
        real_merge(dst, a, b)
        ha, hb = h(a), h(b)
        h(dst).clear()
        h(dst).update({k: v for k, v in ha.items() if hb.get(k) == v})

    def init(self, *a, **k):
        real_init(self, *a, **k)
        walk["cur"] = {"spelled": 0, "stale": 0, "same_reg": 0, "diff_reg": 0,
                       "name": 0, "expr": 0, "never": 0, "worst": []}

    def reload(self, st, key, mn, reg):
        before = st.dropped.get(key)
        out = real_reload(self, st, key, mn, reg)
        w = walk["cur"]
        if w is None:
            return out
        r = expr.canon(reg)
        if before is not None and out is before[0]:
            w["spelled"] += 1
            ev = h(st).get(key)
            # A record spelled where this path's last event was not the drop that made it,
            # unless the event put the same TEXT back, which is harmless by value.
            if ev != ("drop", before[0].text) and not (ev and ev[1] == before[0].text):
                w["stale"] += 1
                if len(w["worst"]) < 3:
                    w["worst"].append(("stale", key, before[0].text, ev))
            return out
        if out.text != r or not (self._live_after & expr._reg_mask((r,))):
            return out
        # The fallback ran and the register is read again: classify by what the slot held,
        # because the fallback is RIGHT only where that was this very register.
        ev = h(st).get(key)
        held = ev[1] if ev and ev[0] in ("drop", "lost", "fill") else None
        if held is None:
            w["never"] += 1
        elif expr._REG_RE.fullmatch(held):
            if held == r:
                w["same_reg"] += 1
            else:
                w["diff_reg"] += 1
                if len(w["worst"]) < 3:
                    w["worst"].append(("diff", key, held, r))
        elif expr._MINTED_RE.fullmatch(held):
            # The slot held a NAME. A name cannot go stale, so the only reason the reload
            # cannot spell it is that its declaration does not dominate the reload, which
            # is a forced decline and not a fixable read: spelling it would be a reference
            # out of scope. Counted apart from `diff_reg` for that reason (#198).
            w["name"] += 1
        else:
            w["expr"] += 1
            if len(w["worst"]) < 3:
                w["worst"].append(("expr", key, held, r))
        return out

    expr.State.note_slot, expr.State.record_drop = note_slot, record_drop
    expr.State.forget_slot, expr.State.copy = forget_slot, copy
    expr.State.stale_on_write = stale_on_write
    expr._merge, expr.Lifter._reload, expr.Lifter.__init__ = merge, reload, init

    def restore():
        for n, f in saved.items():
            setattr(expr.State, n, f)
        expr._merge, expr.Lifter._reload = real_merge, real_reload
        expr.Lifter.__init__ = real_init

    return restore, tot, walk, hist, alive


_DECLARES = re.compile(r"(?:var )?(t\d+)\s*(?:=[^=]|;)")
_NAME = re.compile(r"\bt\d+\b")


def _shape(flat: list) -> dict:
    """The rendered text's own invariants, for one function's stripped lines.

    Counted here rather than in a script because a script is what #206 did not have: two
    review rounds verified its per-symptom counts and missed 112 empty blocks, because a
    count says how much and not what shape (#210).
    """
    out = {"unbalanced": 0, "twice": 0, "above": 0, "sole": 0}
    depth, bad = 0, False
    declared, first = {}, {}
    body: list = []
    for i, ln in enumerate(flat):
        if ln.startswith("}"):
            depth -= 1
            if depth < 0:
                bad = True
            if body:
                body.pop()
        elif body:
            body[-1].append(i)
        if ln.endswith("{"):
            depth += 1
            body.append([])
        m = _DECLARES.match(ln)
        if m:
            # `var` only for the count: a hoisted name is `var tN;` at the top and
            # `tN = ...;` where the value is, and reading the second as a declaration made
            # this say 17,882 names were declared twice.
            if ln.startswith("var "):
                declared[m.group(1)] = declared.get(m.group(1), 0) + 1
            first.setdefault(m.group(1), i)
        rest = ln[m.end(1):] if m else ln
        for n in _NAME.findall(rest):
            # A name declared LATER in the text than it is read. One declared nowhere at
            # all is #205's and `oos`'s, not this counter's.
            if n in first and first[n] > i:
                out["above"] += 1
    out["unbalanced"] = 1 if (bad or depth != 0) else 0
    out["twice"] = sum(n - 1 for n in declared.values() if n > 1)
    read = set()
    for i, ln in enumerate(flat):
        m = _DECLARES.match(ln)
        read.update(_NAME.findall(ln[m.end(1):] if m else ln))
    for a, b, c in zip(flat, flat[1:], flat[2:]):
        m = _DECLARES.match(b)
        if a.endswith("{") and c.startswith("}") and m and m.group(1) not in read:
            out["sole"] += 1
    # A name read where NO line of the body binds it, anywhere, at any depth. Worse than
    # `oos`, which at least has a declaration to look at: this is not valid Dart and a
    # reader has nothing to go on. `_DECLARES` matches a binding occurrence whether it
    # declares or assigns, so the set it builds is every name the body ever writes (#205).
    bound = set()
    for ln in flat:
        m = _DECLARES.match(ln)
        if m:
            bound.add(m.group(1))
    out["undecl"] = sum(1 for n in read if n not in bound)
    return out


def census(path: str, verbose: bool = False, limit: int = 0) -> dict:
    """Lift EVERY range of the image at `path` and classify what each frame reload prints.

    Over `image.all_ranges`, not `fr.functions`: the latter is the attributed functions,
    238 of 8,188 on the obfuscated fixture, so a census over it covers 3% of that image
    and reads as "unaffected" (#198).

    Returns counts over the LAST walk of each range:
      diff_reg  the fallback spelled its own register where the slot held a DIFFERENT
                one; a wrong read, and the class #198's fix targets
      expr      the same, where the slot held an expression; also a wrong read
      name      the slot held a minted NAME. A name cannot go stale, so the reload could
                only fail to spell it because its declaration does not dominate; that is a
                forced decline, not a fixable read, and is counted apart
      same_reg  the fallback spelled the register the slot held; correct, the spill and
                reload round-trip
      never     the slot never held anything on this path; a genuine decline
      undecl    names read where no line of the body binds them, anywhere. Must be 0:
                the output is not valid Dart and a reader has nothing to go on, which is
                worse than a name that is merely out of scope. Counted per name and
                not per read, as `twice` is: four of them, six reads, shipped in
                `parsePartialNumber` on both fixtures, from a loop collapsing a carried
                name whose value a goto target outside the loop had already been handed
                (#205)
      oos       reads of a minted name whose declaration has closed, by the lifter's own
                `expr._out_of_scope`. Measured HERE and nowhere else: four separate
                scripts of mine drifted from that function's rules and each one reported a
                number I then had to withdraw (#198)
      regline   lines carrying a bare machine register, by `tools/quality.py`'s own
                regex and not a copy of it. A frame reload that declines used to keep the
                load's register and print nothing, so this is where #198's fix shows:
                every decline it names is a line that stops reading a register (#198)
      empty     blocks the rendering leaves holding nothing, `if (c) {` with `}` under
                it. Must be 0. A pass that drops a declaration nothing reads can take
                the only line an `if` arm has, which is why three of them carry a guard
                against it; 112 of these shipped on the clean build while one did not

    The five below are the rest of what #210 asks for: the invariants of the rendered
    TEXT, which the per-symptom counts cannot see. #206 nearly shipped 112 empty blocks
    past two review rounds that checked the counts and not the shape, so these exist to
    make the shape a number as well.

      unbalanced  functions whose braces do not balance under the scanner the drop passes
                  use, so a `{` or `}` inside a raw line cannot mislead them. Must be 0
      twice       a name the body declares twice. Must be 0
      above       a name read on a line ABOVE its declaration, which makes the hoist
                  textually sound and not only sound by scope. Must be 0
      sole        blocks whose only statement is a declaration nothing reads. The guard in
                  `_drop_unread` trades an empty block for one of these on purpose, so it
                  is a bound and not a zero

    A sixth was measured and NOT kept: a declaration whose text repeats one already used
    in the same function, which is the readability half of #207. It comes out at 12,192 on
    the clean build and cannot tell the defect (two reads of different addresses printing
    the same text once the frame register has moved) from reading one field twice, which
    is correct and common. A number that cannot say which it is counting is not a gate.
      spelled   records `_reload` spelled instead of falling back
      stale     records spelled although this path superseded them; must be 0 (#199)

    `limit` scores only the first N ranges, for a caller that wants the property rather
    than the whole image.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    # The regex, not a copy of it: a second implementation of a rule measured in two
    # places is how four numbers in #198 came to be wrong.
    from quality import _REG_RE
    from jadart import expr
    from jadart.branches import row_kinds
    from jadart.disasm import (load_instructions, disassemble_range, annotate,
                               function_name_by_pc, build_pool_map, cut_end)
    image, fr, _hdr = load_instructions(path)
    pc_to_name = function_name_by_pc(image, fr)
    pool_map = build_pool_map(fr, getattr(image, "arch", None))
    restore, tot, walk, hist, alive = _census_hooks(expr)
    worst = []
    ranges = image.all_ranges[:limit] if limit else image.all_ranges
    try:
        for cr in ranges:
            dis = disassemble_range(image, cr)
            if not dis:
                continue
            hist.clear()
            del alive[:]
            walk["cur"] = None
            ann = annotate(dis, pc_to_name, pool_map, kinds=row_kinds(image, dis))
            lines = None
            try:
                # `arch=` is not optional: without it an arm32 range lifts through
                # arm64's register roles and prints confident nonsense, which
                # `test_every_lift_call_site_passes_the_target` exists to stop.
                lines = expr.lift_function(ann, pool_map,
                                           arch=getattr(image, "arch", None),
                                           cut_end=cut_end(cr, dis))
            except RecursionError:
                continue
            # Counted for every range that LIFTED, before the slot census's own guards:
            # those drop a range that built no Lifter, and letting them drop it here too
            # silently shrank this population by 27 ranges (#198).
            if lines is not None:
                hits: list = []
                expr._out_of_scope([l.rstrip() for l in lines], hits)
                if hits:
                    tot["oos"] += len(hits)
                    tot["oos_fns"] += 1
                tot["lifted"] += 1
                tot["regline"] += sum(1 for l in lines if _REG_RE.search(l))
                flat = [l.strip() for l in lines]
                tot["empty"] += sum(1 for a, b in zip(flat, flat[1:])
                                    if a.endswith("{") and b.startswith("}"))
                for k, n in _shape(flat).items():
                    tot[k] += n
            w = walk["cur"]
            if w is None or lines is None:
                continue
            tot["ranges"] += 1
            for k in ("spelled", "stale", "same_reg", "diff_reg", "name", "expr",
                      "never"):
                tot[k] += w[k]
            if verbose and w["worst"] and len(worst) < 8:
                worst.append((cr.pc_offset, w["worst"][0]))
    finally:
        restore()
    # The ACTIONABLE class: the slot held a spelling that was still available, and the
    # reload named something else. `name` is excluded because a name out of its
    # declaration's scope cannot be spelled at all, and `never` because the slot genuinely
    # held nothing on that path.
    tot["wrong"] = tot["diff_reg"] + tot["expr"]
    if verbose:
        for at, item in worst:
            print(f"    {at:#x}: {item}")
    return tot

if __name__ == "__main__":
    sys.exit(main())
