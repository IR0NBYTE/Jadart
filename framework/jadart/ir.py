"""A hash-consed value DAG for one basic block, and an evaluator for it.

WHY THIS EXISTS. Tier 3 lifts by abstract interpretation over the register file with
TEXTUAL substitution: each register maps to a string, and reading a register pastes its
text. Everything the output does badly follows from that, and none of it is fixable inside
it.

The sharpest symptom is that a value used twice DOUBLES the text, so a chain of pure
combines grows 2^n. `SystemHash.hash20` renders a 397-character line today; raise
`MAX_INLINE_CHARS` from 200 to 20,000 and it becomes 38,527 characters. The cap does not
fix the exponential, it truncates it into 390 temporaries whose boundary is a string
length rather than anything about the program.

Both production decompilers answer one question the current design CANNOT ASK: how many
places read this value? Ghidra reads it straight off SSA descendant counts and marks a
varnode `explicit` (gets a name) or `implied` (inlined into its use), with
`max_implied_ref = 2` and `max_term_duplication = 2` in architecture.cc. Hex-Rays arrives
at the same rule from the other side, nesting whatever propagation could fold into a
`mop_d` operand and naming the residue at MMAT_LVARS.

Once a value is a Python string that question is unanswerable, and length is the only
proxy left, measured after the duplication has already been paid for. So the DAG is not
the deliverable. The DAG is what lets the printer ask.

WHAT IS DIFFERENT HERE, versus copying Ghidra's varnode model:

  * Width is part of the intern key, not an afterthought. jadart's `canon()` folds `w` to
    `x` and erases operand width at 59,073 sites on the corpus binary, which matters
    because compressed builds do Smi arithmetic in 32-bit registers. Two nodes that differ
    only in width are NOT the same value and must not intern together.
  * Nodes are evaluable. `eval()` exists so the whole graph can be checked against a real
    arm64 emulator on random inputs (tools/irfuzz.py). The project has held that the
    machine-code layer has no byte-exact oracle and is therefore structurally capped where
    the snapshot layer is not; that is false, and this is the half of the refutation that
    lives in the library.
  * Effects are not in the DAG. Loads, stores and calls stay in an ordered statement list,
    because a DAG has no notion of "before" and silently reordering a store past a load is
    exactly the bug that makes a decompiler untrustworthy.
"""
from __future__ import annotations

from dataclasses import dataclass, field


def mask(width: int) -> int:
    return (1 << width) - 1


def sext(value: int, width: int) -> int:
    """Interpret the low `width` bits of `value` as signed."""
    v = value & mask(width)
    return v - (1 << width) if v >> (width - 1) else v


# --------------------------------------------------------------------------
# Nodes
# --------------------------------------------------------------------------

@dataclass(frozen=True, eq=False)
class Node:
    """One value. Immutable and interned, so `a is b` means `a` and `b` ARE the same
    value and the number of readers is exactly the number of edges into it.

    `eq=False` IS LOad-BEARING, not a micro-optimisation. A frozen dataclass derives
    __hash__ and __eq__ from the field tuple, and `args` holds Nodes, so hashing one node
    recursively hashes its entire subtree, which is exponential on exactly the shared
    chains this class exists to make cheap. Building a 7-deep hash chain cost 8.1 million
    __hash__ calls before this line. Interning makes structural equality unnecessary:
    identical values are the same object, so identity is the correct comparison as well as
    the fast one.
    """
    op: str                 # "const" | "reg" | a binary/unary operator | "ext"
    width: int              # 32 or 64; part of identity, never inferred later
    args: tuple = ()        # child Nodes
    imm: object = None      # const value, register name, or extension kind

    def __repr__(self):     # short, for test failures
        if self.op == "const":
            return f"#{self.imm:#x}:{self.width}"
        if self.op == "reg":
            return f"{self.imm}:{self.width}"
        return f"({self.op} {' '.join(map(repr, self.args))}):{self.width}"


#: Pure integer operators, and how to evaluate one. Every result is masked to the node's
#: width by `evaluate`, so these only have to be right about the value.
_BIN = {
    "+":   lambda a, b, w: a + b,
    "-":   lambda a, b, w: a - b,
    "*":   lambda a, b, w: a * b,
    "&":   lambda a, b, w: a & b,
    "|":   lambda a, b, w: a | b,
    "^":   lambda a, b, w: a ^ b,
    "<<":  lambda a, b, w: a << (b & (w - 1)),
    ">>":  lambda a, b, w: (a & mask(w)) >> (b & (w - 1)),          # logical
    ">>s": lambda a, b, w: sext(a, w) >> (b & (w - 1)),             # arithmetic
    "ror": lambda a, b, w: ((a & mask(w)) >> (b & (w - 1)))
                           | (a << (w - (b & (w - 1)))),
}

_UN = {
    "~": lambda a, w: ~a,
    "neg": lambda a, w: -a,
}

#: Width changes are explicit nodes, never implied by context. p-code spells these
#: INT_ZEXT / INT_SEXT / SUBPIECE for the same reason: leaving them implicit is how an
#: operand's width gets erased.
_EXT = ("zext", "sext", "trunc")


class Graph:
    """The interning table for one function.

    Hash-consing gives copy propagation and common-subexpression elimination for free and
    by construction, which is a stronger position than Ghidra's: its standalone
    `ActionCse` is commented out in the current tree, and what survives is a handful of
    opcode-specific rules.
    """

    def __init__(self):
        self._intern: dict = {}
        self.uses: dict = {}        # Node -> how many places read it

    def _mk(self, op, width, args=(), imm=None) -> Node:
        # Key on the children's IDENTITIES, never on the children themselves: a key
        # containing Nodes would hash them structurally and reintroduce the exponential
        # that `eq=False` just removed. The intern table owns a reference to every node,
        # so the ids stay valid for the graph's lifetime.
        key = (op, width, tuple(id(a) for a in args), imm)
        n = self._intern.get(key)
        if n is None:
            n = Node(op=op, width=width, args=args, imm=imm)
            self._intern[key] = n
            self.uses[n] = 0
        for a in args:
            self.uses[a] = self.uses.get(a, 0) + 1
        return n

    # constructors
    def const(self, value: int, width: int = 64) -> Node:
        return self._mk("const", width, (), value & mask(width))

    def reg(self, name: str, width: int = 64) -> Node:
        return self._mk("reg", width, (), name)

    def binop(self, op: str, a: Node, b: Node, width: int = None) -> Node:
        if op not in _BIN:
            raise ValueError(f"unknown binary op {op!r}")
        w = width or a.width
        # Fold now rather than in a later pass: a folded constant cannot be un-folded, and
        # doing it at construction keeps the intern table free of duplicates that differ
        # only by how far constant propagation had got.
        if a.op == "const" and b.op == "const":
            return self.const(_BIN[op](a.imm, b.imm, w), w)
        return self._mk(op, w, (a, b))

    def unop(self, op: str, a: Node, width: int = None) -> Node:
        if op not in _UN:
            raise ValueError(f"unknown unary op {op!r}")
        w = width or a.width
        if a.op == "const":
            return self.const(_UN[op](a.imm, w), w)
        return self._mk(op, w, (a,))

    def ext(self, kind: str, a: Node, to_width: int) -> Node:
        if kind not in _EXT:
            raise ValueError(f"unknown extension {kind!r}")
        if a.width == to_width and kind != "sext":
            return a
        return self._mk("ext", to_width, (a,), kind)


class Phi:
    """A value that depends on which edge reached its block.

    Deliberately NOT a Node and deliberately NOT interned. Every other value is frozen at
    construction, but SSA discovers a phi's operands as it finds predecessors, and a loop
    header's back edge is only resolvable after the loop body has been walked. So a phi is
    mutable while it is being built and settles once its block is sealed.

    This is what `expr._merge` cannot express. It keeps only the registers both arms agree
    on and drops the rest to a bare register name, which is why 40.1% of instructions,
    everything in a join block, lose their value at the join. A phi IS that value.
    """
    __slots__ = ("block", "width", "preds", "args", "sealed")

    def __init__(self, block, width):
        self.block = block
        self.width = width
        self.preds = []
        self.args = []
        self.sealed = False

    def add(self, pred, value):
        self.preds.append(pred)
        self.args.append(value)

    @property
    def op(self):
        return "phi"

    @property
    def imm(self):
        return self.block

    def trivial(self):
        """The operand this phi collapses to, or None.

        A phi whose operands are all the same value (ignoring itself, which happens on a
        loop back edge) is not a choice at all. Removing it matters beyond tidiness: left
        in, every loop-carried value looks like a join even when nothing joins, and the
        printer names a variable the source never had.
        """
        seen = None
        for a in self.args:
            if a is self:
                continue
            if seen is None:
                seen = a
            elif a is not seen:
                return None
        return seen

    def __repr__(self):
        return f"phi@{self.block:#x}({len(self.args)})"


def evaluate(node, env: dict, memo: dict = None, taken: dict = None) -> int:
    """The value of `node` given `env` mapping register name -> integer.

    This is what makes the graph falsifiable. tools/irfuzz.py runs the same block under a
    real arm64 emulator and compares, so a wrong construction rule fails a bit-exact test
    instead of printing plausible wrong source.

    `taken` maps a block address to the predecessor that actually reached it on the run
    being checked, which is what resolves a phi. It comes from the emulator's own trace,
    so the IR is asked the same question the CPU answered rather than a hypothetical one.
    """
    if memo is None:
        memo = {}
    hit = memo.get(id(node))
    if hit is not None:
        return hit
    if isinstance(node, Phi):
        if not node.args:
            raise ValueError(f"phi at {node.block:#x} has no operands")
        pred = (taken or {}).get(node.block)
        if pred is None or pred not in node.preds:
            # Refuse rather than pick an arm. A phi evaluated without knowing which edge
            # was taken has no value, and inventing one is how a checker starts agreeing
            # with itself instead of with the machine.
            raise KeyError(f"no incoming edge recorded for block {node.block:#x}")
        v = evaluate(node.args[node.preds.index(pred)], env, memo, taken)
        memo[id(node)] = v
        return v
    w = node.width
    if node.op == "const":
        v = node.imm & mask(w)
    elif node.op == "reg":
        v = env.get(node.imm, 0) & mask(w)
    elif node.op == "ext":
        src = evaluate(node.args[0], env, memo, taken)
        sw = node.args[0].width
        if node.imm == "sext":
            v = sext(src, sw) & mask(w)
        else:                       # zext and trunc are both a mask at this width
            v = src & mask(w)
    elif node.op in _UN:
        v = _UN[node.op](evaluate(node.args[0], env, memo, taken), w) & mask(w)
    elif node.op in _BIN:
        a = evaluate(node.args[0], env, memo, taken)
        b = evaluate(node.args[1], env, memo, taken)
        # Shifts and arithmetic-shift read their left operand as signed at ITS width.
        v = _BIN[node.op](a, b, w) & mask(w)
    else:
        raise ValueError(f"cannot evaluate {node.op!r}")
    memo[id(node)] = v
    return v


# --------------------------------------------------------------------------
# The printer's question: inline this, or give it a name?
# --------------------------------------------------------------------------

#: Ghidra's architecture.cc defaults, and they are defaults worth taking rather than
#: re-deriving: three or more readers always becomes a named local, and exactly two
#: readers becomes one when duplicating the expression would exceed two terms.
MAX_IMPLIED_REF = 2
MAX_TERM_DUPLICATION = 2


def term_count(node: Node, cap: int = 8, memo: dict = None) -> int:
    """How many operator terms rendering `node` inline would duplicate, capped at `cap`.

    Counts the expression as it would be PRINTED, so a shared subterm counts once per
    appearance: that is the cost the reader actually pays, and the cost the old character
    limit was trying to measure from the far side.

    THE CAP IS NOT A TUNING KNOB, it is what makes this terminate. The printed size of a
    shared chain is exponential in its depth, that is the whole problem being solved,
    so computing it exactly would take as long as printing it, which is the failure the
    caller is trying to avoid. Only the comparison against MAX_TERM_DUPLICATION matters,
    so saturate at `cap` and memoise the saturated value: once a subtree is known to be
    over budget, nothing above it can be under.
    """
    if memo is None:
        memo = {}
    hit = memo.get(node)
    if hit is not None:
        return hit
    if node.op in ("const", "reg"):
        return 0
    n = 1
    for a in node.args:
        n += term_count(a, cap, memo)
        if n >= cap:
            n = cap
            break
    memo[node] = n
    return n


def explicit(node: Node, graph: Graph, roots: frozenset = frozenset()) -> bool:
    """Should this value get a name instead of being pasted into its reader?

    This is the whole reason the DAG exists. `MAX_INLINE_CHARS = 200` was reaching for
    this rule with the only instrument a string offers.
    """
    if node in roots:
        return True
    if node.op in ("const", "reg"):
        return False            # atoms are always cheaper inline
    uses = graph.uses.get(node, 0)
    if uses > MAX_IMPLIED_REF:
        return True
    if uses == MAX_IMPLIED_REF and term_count(node) > MAX_TERM_DUPLICATION:
        return True
    return False


def render(node: Node, graph: Graph, names: dict, roots: frozenset = frozenset()) -> str:
    """Render one value, inlining what should be inlined and naming what should not."""
    if node in names:
        return names[node]
    if node.op == "const":
        v = node.imm
        return hex(v) if v > 9 else str(v)
    if node.op == "reg":
        return str(node.imm)
    if node.op == "ext":
        inner = render(node.args[0], graph, names, roots)
        return inner if node.imm == "zext" else f"{node.imm}({inner})"
    if node.op in _UN:
        return f"{node.op}{render(node.args[0], graph, names, roots)}"
    a = render(node.args[0], graph, names, roots)
    b = render(node.args[1], graph, names, roots)
    op = ">>" if node.op == ">>s" else node.op
    return f"({a} {op} {b})"


def schedule(values, graph: Graph, roots: frozenset = frozenset()) -> tuple:
    """(lines, names) for a list of result values.

    Every node the policy calls explicit gets a `var tN` binding emitted before its first
    reader, in dependency order. What is left inlines. This replaces the spill machinery
    that fired on a character count.
    """
    names: dict = {}
    lines: list = []
    counter = [0]
    seen = set()

    def walk(n: Node):
        if n in seen or n in names:
            return
        seen.add(n)
        for a in n.args:
            walk(a)
        if explicit(n, graph, roots) and n.op not in ("const", "reg"):
            text = render(n, graph, names, roots)
            names[n] = f"t{counter[0]}"
            counter[0] += 1
            lines.append(f"var {names[n]} = {text};")

    for v in values:
        walk(v)
    return lines, names
