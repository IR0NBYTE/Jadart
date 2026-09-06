"""SSA construction over jadart's existing basic blocks.

THE PROBLEM THIS SOLVES, measured. `expr._merge` keeps only the registers both arms of a
branch agree on and drops the rest to a bare register name. 40.1% of all instructions on
the corpus binary sit in a join block (183,656 of 457,622, across 26,545 joins), so at
every one of those joins the value being computed is thrown away and the output falls back
to `x0`, `x4`, `d2`. That is most of the 35.9% of lifted lines that leak a machine
register.

A phi IS the value `_merge` discards. It is not an optimisation, it is the missing term.

THE ALGORITHM is Braun et al., "Simple and Efficient Construction of SSA Form" (CC 2013),
not Cytron. Cytron needs dominance frontiers computed up front and a separate renaming
pass; Braun builds SSA on demand while lowering, which fits a lifter that is already
walking blocks and already threading a register map. Measured CFG sizes here make the
asymptotic argument moot anyway: median 5 blocks, p90 21, p99 86.

The one subtlety is loops. A loop header's back edge comes from a block that has not been
lowered yet, so its phi cannot be completed when the header is first visited. Braun handles
this with SEALING: a block is sealed once all its predecessors are known, an unsealed block
gets an incomplete phi as a promise, and sealing fills the operands in. Getting this wrong
does not crash, it silently drops the loop-carried value, which is exactly the class of
bug the emulator oracle exists to catch, and `tools/irfuzz.py --whole` does catch it.
"""
from __future__ import annotations

from .ir import Graph, Phi
from .lower import Lowering, RESERVED, _reg, _split, lower_one


class SSA:
    """Braun-style on-demand SSA over a {addr: Block} CFG."""

    def __init__(self, graph: Graph, preds: dict):
        self.g = graph
        self.preds = preds                 # block addr -> [pred addrs]
        self.defs: dict = {}               # (block, reg) -> value
        self.sealed: set = set()
        self.incomplete: dict = {}         # block -> {reg: Phi}
        self.phis: list = []

    # the two operations the lowering needs
    def write(self, block, reg, value):
        self.defs[(block, reg)] = value

    def read(self, block, reg, width=64):
        v = self.defs.get((block, reg))
        if v is not None:
            return v
        return self._read_recursive(block, reg, width)

    def _read_recursive(self, block, reg, width):
        if block not in self.sealed:
            # The block may gain predecessors later, so promise a value now and fill the
            # operands in at seal time. Skipping this is how a loop-carried value vanishes.
            phi = Phi(block, width)
            self.incomplete.setdefault(block, {})[reg] = phi
            self.phis.append(phi)
            val = phi
        else:
            ps = self.preds.get(block, [])
            if len(ps) == 1:
                val = self.read(ps[0], reg, width)
            elif not ps:
                val = self.g.reg(reg, 64)          # function entry: an incoming value
            else:
                phi = Phi(block, width)
                self.phis.append(phi)
                # Write the phi BEFORE filling it, or a loop reaches this same read again
                # and recurses forever.
                self.defs[(block, reg)] = phi
                self._add_operands(phi, block, reg, width)
                val = self._maybe_trivial(phi)
        self.defs[(block, reg)] = val
        return val

    def _add_operands(self, phi, block, reg, width):
        for p in self.preds.get(block, []):
            phi.add(p, self.read(p, reg, width))
        phi.sealed = True

    def _maybe_trivial(self, phi):
        """Collapse a phi that is not a choice.

        Without this every loop-carried register becomes a named variable even when the
        loop does not change it, and the output grows variables the source never had."""
        same = phi.trivial()
        if same is None:
            return phi
        for key, v in list(self.defs.items()):
            if v is phi:
                self.defs[key] = same
        return same

    def seal(self, block):
        if block in self.sealed:
            return
        self.sealed.add(block)
        for reg, phi in self.incomplete.pop(block, {}).items():
            self._add_operands(phi, block, reg, phi.width)
            resolved = self._maybe_trivial(phi)
            self.defs[(block, reg)] = resolved


def _preds_of(blocks: dict) -> dict:
    out = {a: [] for a in blocks}
    for a, b in blocks.items():
        for s in (b.succ or ()):
            if s in out:
                out[s].append(a)
    return out


def lower_function(blocks: dict, entry: int, graph: Graph = None):
    """Lower a whole CFG into one DAG with phis at the joins.

    Returns (ssa, lowerings, order). `lowerings[addr]` carries the per-block bookkeeping
    (what was modelled, what went opaque) so a caller can still see how much of each block
    the IR actually claims.
    """
    g = graph or Graph()
    preds = _preds_of(blocks)
    ssa = SSA(g, preds)

    # Reverse postorder, so a block is normally lowered after its predecessors and only a
    # genuine back edge leaves anything incomplete.
    order, seen, stack = [], set(), [entry]
    while stack:
        b = stack.pop()
        if b in seen or b not in blocks:
            continue
        seen.add(b)
        order.append(b)
        for s in (blocks[b].succ or ()):
            stack.append(s)

    lowerings = {}
    for addr in order:
        if all(p in seen and p in lowerings for p in preds.get(addr, [])):
            ssa.seal(addr)
        lo = Lowering(g)
        for ins in blocks[addr].insns:
            lower_one(lo, ins, ssa=ssa, block=addr)
        lowerings[addr] = lo

    for addr in order:                     # anything a back edge left open
        ssa.seal(addr)
    return ssa, lowerings, order
