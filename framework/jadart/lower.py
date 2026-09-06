"""Lower arm64 into the value DAG.

This is the half of the lifter that `expr.py` does with strings. `_step` decides what a
mnemonic MEANS and then writes that meaning into a register map as text; here the same
decision produces a Node, so the result can be counted, shared, evaluated and checked
against a CPU.

TWO RULES THAT ARE NOT NEGOTIABLE, both learned from the existing lifter's defects:

  * WIDTH IS CARRIED, NEVER FOLDED. `expr.canon()` maps `w` to `x` and erases operand
    width at 59,073 sites on the corpus binary. That is fine for a name and wrong for a
    value: a 32-bit destination CLEARS the top half, and compressed builds do Smi
    arithmetic in 32-bit registers precisely because a tagged Smi fits. So `w3` and `x3`
    are the same storage at two widths, and the lowering says which one it meant.

  * UNMODELLED MEANS OPAQUE, NEVER APPROXIMATED. Anything this file does not understand
    makes its destination a fresh opaque value rather than a guess. An opaque register is
    honest and testable; a plausible wrong node is neither. `Lowering.opaque` records
    which registers went that way so a caller can decline to make claims about them, and
    so the fuzzer can restrict itself to blocks it is entitled to check.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .ir import Graph, Node

#: Register roles Dart AOT reserves. A write to one of these is not ordinary dataflow, so
#: the lowering refuses rather than modelling it (constants_arm64.h; see expr.ROLE).
RESERVED = frozenset({"x15", "x16", "x17", "x18", "x21", "x22", "x26", "x27", "x28",
                      "x29", "x30", "xzr"})

_SHIFTS = {"lsl": "<<", "lsr": ">>", "asr": ">>s", "ror": "ror"}

#: Instructions whose first operand is a SOURCE, not a destination. They write only the
#: condition flags, which this lowering does not model.
#:
#: Getting this wrong is destructive rather than merely incomplete: `cmp x1, x2` would
#: otherwise be read as "x1 is written by something unmodelled", poisoning a register that
#: is still live and turning every later use of it into an opaque value. Found by lowering
#: a diamond and seeing the then-arm come back as `?x1 + x3` when the source plainly says
#: `x1 + x3`.
_NO_DEST = frozenset({"cmp", "cmn", "tst", "teq", "fcmp", "fcmpe", "ccmp", "ccmn"})

#: mnemonic -> DAG operator, for the three-operand register/immediate forms.
_ALU = {
    "add": "+", "sub": "-", "and": "&", "orr": "|", "eor": "^", "mul": "*",
    "lsl": "<<", "lsr": ">>", "asr": ">>s", "ror": "ror",
}


def _reg(tok: str):
    """(canonical 64-bit name, width) for a register token, or None.

    The canonical name is the x-form because that is the storage; the width is kept
    alongside rather than thrown away, which is the whole difference from `canon()`.
    """
    t = tok.strip().lower()
    if not t:
        return None
    if t in ("xzr", "wzr"):
        return "xzr", 64 if t[0] == "x" else 32
    if t in ("sp", "wsp"):
        return "x15", 64
    if t[0] in "xw" and t[1:].isdigit() and int(t[1:]) <= 30:
        return "x" + t[1:], 64 if t[0] == "x" else 32
    return None


def _imm(tok: str):
    t = tok.strip().lower()
    if not t.startswith("#"):
        return None
    t = t[1:].strip()
    try:
        return int(t, 16) if t.startswith("0x") else int(t, 0)
    except ValueError:
        return None


@dataclass
class Lowering:
    graph: Graph
    regs: dict = field(default_factory=dict)     # x-name -> Node (64-bit view)
    opaque: set = field(default_factory=set)     # registers whose value is not modelled
    modelled: int = 0
    skipped: int = 0
    # When these are set the register file lives in the SSA rather than in `regs`, so a
    # read that crosses a block boundary becomes a phi instead of a fresh input value.
    ssa: object = None
    block: int = 0

    def read(self, name: str, width: int) -> Node:
        if self.ssa is not None:
            n = self.ssa.read(self.block, name, 64)
        else:
            n = self.regs.get(name)
            if n is None:
                n = self.graph.reg(name, 64)
                self.regs[name] = n
        return n if width == 64 else self.graph.ext("trunc", n, 32)

    def write(self, name: str, value: Node, width: int) -> None:
        if name == "xzr":
            return
        # A 32-bit destination ZEROES the upper half. Making that explicit keeps every
        # stored value 64 bits wide, so a later width-consistency check has something to
        # check and a reader is never left inferring the extension from context.
        #
        # It is NOT load-bearing for evaluation today, and saying so is the honest form:
        # `evaluate` masks a node to its own width, so a 32-bit node already yields the
        # zero-extended value. Deleting this line changes no result on 5,000 random
        # inputs, which is how it was measured rather than assumed.
        v = value if width == 64 else self.graph.ext("zext", value, 64)
        self.regs[name] = v
        if self.ssa is not None:
            self.ssa.write(self.block, name, v)
        self.opaque.discard(name)

    def spoil(self, name: str) -> None:
        if name == "xzr":
            return
        v = self.graph.reg("?%s_%x_%d" % (name, self.block, len(self.opaque)), 64)
        self.regs[name] = v
        if self.ssa is not None:
            self.ssa.write(self.block, name, v)
        self.opaque.add(name)


def _operand(lo: Lowering, tok: str, width: int, nxt: str = ""):
    """A source operand, applying any `, lsl #n` / `, uxtw` modifier that follows it."""
    g = lo.graph
    r = _reg(tok)
    if r is None:
        v = _imm(tok)
        if v is None:
            return None
        # `add xD, xN, #9, lsl #12` is ONE immediate scaled by the shift, not an immediate
        # followed by an unrelated modifier. Returning the bare constant made every such
        # operand 4096 times too small. Caught by evaluating against the hardware, not by
        # reading: 129 mismatches over 2,361 real corpus runs.
        mod = (nxt or "").strip().lower()
        if mod:
            amt = _imm("#" + mod.split("#")[-1]) if "#" in mod else None
            if mod.split()[0] != "lsl" or amt is None:
                return None         # an unmodelled modifier is a refusal, not a guess
            v <<= amt
        return g.const(v, width)
    node = g.const(0, width) if r[0] == "xzr" else lo.read(r[0], width)

    mod = (nxt or "").strip().lower()
    if not mod:
        return node
    kind = mod.split()[0]
    amt = _imm("#" + mod.split("#")[-1]) if "#" in mod else 0
    if kind in _SHIFTS:
        return node if not amt else g.binop(_SHIFTS[kind], node, g.const(amt, width),
                                            width)
    if kind in ("uxtw", "uxtb", "uxth"):
        bits = {"uxtb": 8, "uxth": 16, "uxtw": 32}[kind]
        v = g.ext("zext", g.ext("trunc", node, bits), width)
        return v if not amt else g.binop("<<", v, g.const(amt, width), width)
    if kind in ("sxtw", "sxtb", "sxth"):
        bits = {"sxtb": 8, "sxth": 16, "sxtw": 32}[kind]
        v = g.ext("sext", g.ext("trunc", node, bits), width)
        return v if not amt else g.binop("<<", v, g.const(amt, width), width)
    return None                     # an unmodelled modifier is a refusal, not a guess


def _split(op: str):
    """Split an operand string, keeping bracketed groups intact."""
    out, depth, cur = [], 0, ""
    for ch in op:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return [p.strip() for p in out if p.strip()]


def lower_block(dis, graph: Graph = None) -> Lowering:
    """Lower a straight-line run of (addr, mnemonic, operands) into the DAG.

    Every instruction either produces a Node for its destination or marks that destination
    opaque. Nothing is skipped silently: `Lowering.modelled` and `.skipped` count both, so
    a caller can see how much of a block it is entitled to reason about.
    """
    lo = Lowering(graph or Graph())
    for item in dis:
        lower_one(lo, item)
    return lo


def lower_one(lo: Lowering, item, ssa=None, block: int = None) -> None:
    """Lower ONE instruction into `lo`, optionally through an SSA register file."""
    if ssa is not None:
        lo.ssa, lo.block = ssa, block
    g = lo.graph
    if True:
        mn, op = item[1], item[2]
        ops = _split(op)
        mn = mn.lower()

        if mn in _NO_DEST:
            # Flags only. Nothing to write, and crucially nothing to spoil.
            lo.skipped += 1
            return

        dst = _reg(ops[0]) if ops else None
        if dst is None or dst[0] in RESERVED:
            # No destination register we track. Calls and branches also land here, and a
            # call additionally destroys the volatile registers, but this lowering is
            # for straight-line arithmetic, so the caller is expected not to hand it one.
            lo.skipped += 1
            return
        name, width = dst

        if mn in ("mov", "movz") and len(ops) >= 2:
            src = _operand(lo, ops[1], width, ops[2] if len(ops) > 2 else "")
            if src is None:
                lo.spoil(name)
                lo.skipped += 1
            else:
                lo.write(name, src, width)
                lo.modelled += 1
            return

        if mn in _ALU and len(ops) >= 3:
            a = _operand(lo, ops[1], width)
            b = _operand(lo, ops[2], width, ops[3] if len(ops) > 3 else "")
            if a is None or b is None:
                lo.spoil(name)
                lo.skipped += 1
            else:
                lo.write(name, g.binop(_ALU[mn], a, b, width), width)
                lo.modelled += 1
            return

        if mn in ("mvn", "neg") and len(ops) >= 2:
            a = _operand(lo, ops[1], width, ops[2] if len(ops) > 2 else "")
            if a is None:
                lo.spoil(name)
                lo.skipped += 1
            else:
                lo.write(name, g.unop("~" if mn == "mvn" else "neg", a, width), width)
                lo.modelled += 1
            return

        if mn in ("sxtw", "uxtw", "sxth", "uxth", "sxtb", "uxtb") and len(ops) >= 2:
            bits = {"b": 8, "h": 16, "w": 32}[mn[-1]]
            a = _operand(lo, ops[1], 64)
            if a is None:
                lo.spoil(name)
                lo.skipped += 1
            else:
                kind = "sext" if mn[0] == "s" else "zext"
                lo.write(name, g.ext(kind, g.ext("trunc", a, bits), width), width)
                lo.modelled += 1
            return

        # ubfx/sbfx Rd, Rn, #lsb, #width  ->  extract then extend
        if mn in ("ubfx", "sbfx") and len(ops) >= 4:
            lsb, w = _imm(ops[2]), _imm(ops[3])
            a = _operand(lo, ops[1], width)
            if a is None or lsb is None or w is None or w <= 0 or w > 63:
                lo.spoil(name)
                lo.skipped += 1
            else:
                shifted = g.binop(">>", a, g.const(lsb, width), width)
                kind = "sext" if mn[0] == "s" else "zext"
                lo.write(name, g.ext(kind, g.ext("trunc", shifted, w), width), width)
                lo.modelled += 1
            return

        # ubfiz/sbfiz Rd, Rn, #lsb, #width  ->  take low `width` bits, shift up by lsb
        if mn in ("ubfiz", "sbfiz") and len(ops) >= 4:
            lsb, w = _imm(ops[2]), _imm(ops[3])
            a = _operand(lo, ops[1], width)
            if a is None or lsb is None or w is None or w <= 0 or w > 63:
                lo.spoil(name)
                lo.skipped += 1
            else:
                kind = "sext" if mn[0] == "s" else "zext"
                low = g.ext(kind, g.ext("trunc", a, w), width)
                lo.write(name, g.binop("<<", low, g.const(lsb, width), width), width)
                lo.modelled += 1
            return

        lo.spoil(name)
        lo.skipped += 1

