"""The call graph and one function's blocks, written out as graphs (#446).

`functions` counts callers and callees and `xrefs function` lists the callers one name at
a time; a reader looking for the path from an entry point to a sink wants the graph
itself, in a graph tool. This writes it as an edge list (for `-j`) and as DOT, from the
same two builders the rest of Jadart reads: callgraph.build_index for calls and
expr.tier3_graph, the CFG the lifter structures, for blocks.

Three things it holds to:

  * A virtual edge is a MAY call. Its targets are the functions a dispatch-table offset
    can reach, picked by a vote on their names (callgraph.selector_targets), not a target
    the binary proves. It keeps kind `virtual` in `-j` and is dashed in DOT, so it never
    draws like a `bl`.
  * Names come from the binary. A DOT node id is the function's address, never its name,
    and a name is only ever a quoted, escaped label (dot_quote), so no name can close the
    string, add an attribute or start a statement.
  * Output is bounded. A graph around one function stops at `limit` nodes and five times
    as many edges and says what it left out; the whole graph is asked for by name.
"""
from __future__ import annotations

from .callgraph import _graph, range_classes, range_names, selector_targets

#: How deep a graph around a function may go. Each level is one sweep of the image
#: (build_index with `only`), so the bound is on time as much as on output.
MAX_DEPTH = 6
#: Default bound on the nodes of a graph around a function; edges get EDGE_FACTOR times
#: as many.
NODE_LIMIT = 200
EDGE_FACTOR = 5
DIRECTIONS = ("both", "callers", "callees")
_KIND_ORDER = {"direct": 0, "pool": 1, "virtual": 2}


def dot_quote(text: str) -> str:
    """`text` as one DOT quoted string that reads back as exactly that text.

    Inside a DOT string only `\\"` is an escape to the parser, and Graphviz then reads
    `\\n`, `\\l`, `\\N` and the like out of a label. So a backslash is doubled, which
    every reader shows as one backslash, a quote is escaped, and every control character
    is written out as visible text: a raw newline is legal inside a DOT string, but a
    backslash before one joins two lines, and nothing a binary names should rely on
    either. `]`, `;` and `->` are plain text inside the quotes."""
    out = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\\\x{ord(ch):02x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _namer(image, fr, matched):
    """pc -> {"name", "class"} the way xrefs names a range, and pc -> the label DOT and
    the text listing print: Class.name, the name, or sub_0x... for a range with none."""
    from .disasm import sub_label
    from .fill import NAME_CUT, visible
    names, classes = range_names(image, fr, matched), range_classes(image, fr)

    def who(pc):
        nm = names.get(pc, ("",))[0]
        cls = classes.get(pc, "")
        return {"name": nm, "class": visible(cls, limit=NAME_CUT) if cls else ""}

    def label(pc):
        w = who(pc)
        if not w["name"]:
            return sub_label(image, pc)
        # A top-level function's owner is the library's `::`, and a constructor's
        # name already starts with its class: neither is said twice.
        cls = w["class"]
        if not cls or cls == "::" or w["name"].startswith(cls + "."):
            return w["name"]
        return f"{cls}.{w['name']}"
    return who, label


def _virtual_callees(image, fr, idx, srcs, extra_names) -> dict:
    """caller pc -> {pc it may call through a dispatch site}, for the callers in `srcs`.

    A graph built with `only` keeps a virtual edge only where its TARGET is in `only`,
    and resolves only the selector offsets whose sets can reach `only`, so the sites of
    a range in it are not resolved for what they call. The offsets it left out are voted
    here, over the same table, and an offset it kept already holds its whole set."""
    sites = {s: idx.sites.get(s, ()) for s in srcs}
    offsets = {off for ss in sites.values() for _a, off in ss}
    sets = dict(idx.sel_targets)
    missing = offsets - set(sets)
    if missing:
        sets.update(selector_targets(image, fr, missing, extra_names))
    out = {}
    for s, ss in sites.items():
        for _a, off in ss:
            out.setdefault(s, set()).update(sets.get(off, ()))
    return out


def call_graph(image, fr, roots, depth=1, direction="both", whole=False,
               limit=NODE_LIMIT, sigs=None) -> dict:
    """The call graph around the ranges `roots` (pcs), or the whole one.

    Around: up to `depth` levels of callers (what reaches a root) and of callees (what a
    root reaches), as `direction` says; `both` is the two together, not the callers of a
    callee. Each level builds the graph for that level's ranges only (build_index's
    `only`), so depth 1 costs what `xrefs function` does. An edge is drawn where one end
    was expanded: the edges among the outermost ranges are not looked for.

    Returns {"nodes": [...], "edges": [...], "cut": {...} or None, "notes": [...]}, nodes
    as {"pc_offset", "va", "name", "class", "label", "depth"} and edges as {"from", "to",
    "kind"} keyed by pc_offset; the caller turns them into its output."""
    from .disasm import va_of
    matched = extra = None
    if sigs:
        from .signatures import load, match
        matched = match(image, fr, load(sigs))
        extra = {pc: m.name for pc, m in matched.items()}
    edges = {}                      # (from, to, kind) -> None, in the order found
    notes = []
    undecodable = set()

    def add(a, b, kind):
        edges.setdefault((a, b, kind), None)

    if whole:
        idx = _graph(image, fr, extra, None)
        dist = {cr.pc_offset: None for cr in image.all_ranges}
        for src, tgts in idx.callees.items():
            for t in tgts:
                add(src, t, "pool" if (src, t) in idx.pool else "direct")
        for src, tgts in idx.may_call.items():
            for t in sorted(tgts):
                add(src, t, "virtual")
        undecodable.update(idx.undecodable)
    else:
        dist = {r: 0 for r in roots}
        up = set(roots) if direction in ("both", "callers") else set()
        down = set(roots) if direction in ("both", "callees") else set()
        level = 0
        while level < depth and (up or down):
            if limit and len(dist) >= limit:
                # Every node past here would be cut, so the sweep is not paid for.
                notes.append(f"stopped after depth {level} of {depth}: the bound of "
                             f"{limit} nodes was reached")
                break
            idx = _graph(image, fr, extra, up | down)
            undecodable.update(idx.undecodable)
            level += 1
            nup, ndown = set(), set()
            for t in sorted(up):
                for c in idx.callers.get(t, ()):
                    add(c, t, "pool" if (c, t) in idx.pool else "direct")
                    nup.add(c)
                for c in sorted(idx.may_be_called_by.get(t, ())):
                    add(c, t, "virtual")
                    nup.add(c)
            for s in sorted(down):
                for t in idx.callees.get(s, ()):
                    add(s, t, "pool" if (s, t) in idx.pool else "direct")
                    ndown.add(t)
            if down:
                for s, tgts in sorted(_virtual_callees(image, fr, idx, down,
                                                       extra).items()):
                    for t in sorted(tgts):
                        add(s, t, "virtual")
                        ndown.add(t)
            up = {n for n in nup if n not in dist}
            down = {n for n in ndown if n not in dist}
            for n in sorted(up | down):
                dist[n] = level
    if undecodable:
        shown = ", ".join(f"0x{va_of(image, pc):x}" for pc in sorted(undecodable)[:5])
        more = f" and {len(undecodable) - 5} more" if len(undecodable) > 5 else ""
        notes.append(f"{len(undecodable)} code ranges would not decode and their calls "
                     f"are absent from the graph: {shown}{more}")

    order = sorted(dist, key=lambda pc: (dist[pc] or 0, pc))
    elist = sorted(edges, key=lambda e: (e[0], e[1], _KIND_ORDER[e[2]]))
    cut = None
    if not whole and limit:
        keep = set(order[:limit])
        kept = [e for e in elist if e[0] in keep and e[1] in keep]
        emax = limit * EDGE_FACTOR
        stopped = level < depth and bool(up or down)
        if stopped or len(order) > limit or len(kept) > emax:
            cut = {"nodes": max(0, len(order) - limit),
                   "edges": len(elist) - min(len(kept), emax),
                   "depth": level if stopped else None}
            if cut["nodes"] or cut["edges"]:
                notes.append(f"cut at {limit} nodes and {emax} edges: {cut['nodes']} "
                             f"nodes and {cut['edges']} edges left out, nearest kept "
                             f"(raise with -n, or -n 0 for all)")
            order = order[:limit]
            # The edges nearest a root are the ones kept, then in address order again.
            near = sorted(kept, key=lambda e: (max(dist[e[0]] or 0, dist[e[1]] or 0),
                                                e[0], e[1], _KIND_ORDER[e[2]]))
            elist = sorted(near[:emax], key=lambda e: (e[0], e[1], _KIND_ORDER[e[2]]))
    who, label = _namer(image, fr, matched)
    nodes = [{"pc_offset": pc, "va": va_of(image, pc), **who(pc), "label": label(pc),
              "depth": dist[pc]} for pc in order]
    return {"nodes": nodes,
            "edges": [{"from": a, "to": b, "kind": k} for a, b, k in elist],
            "cut": cut, "notes": notes}


_CALL_STYLE = {"direct": "", "pool": ", style=bold",
               "virtual": ", style=dashed"}


def call_graph_dot(graph, image, title: str) -> list:
    """The lines of `graph` (call_graph's) as one DOT digraph. Node ids are addresses
    and every name is a quoted label; an edge's kind is its `class` attribute and its
    style: a virtual edge is dashed, because it is a possible target, not a proven one."""
    from .disasm import va_of
    out = [f"digraph {dot_quote(title)} {{", "  node [shape=box];"]
    for n in graph["nodes"]:
        out.append(f'  "0x{n["va"]:x}" [label={dot_quote(n["label"])}];')
    for e in graph["edges"]:
        out.append(f'  "0x{va_of(image, e["from"]):x}" -> "0x{va_of(image, e["to"]):x}"'
                   f' [class="{e["kind"]}"{_CALL_STYLE[e["kind"]]}];')
    out.append("}")
    return out


def block_graph(image, cr, dis, ann, mono=None):
    """One function's blocks and the edges between them, from the graph the lifter
    builds (expr.tier3_graph), or None where it makes none.

    Blocks are {"start", "end", "instructions"} as pc_offsets, `end` the address after
    the last instruction. Edges are {"from", "to", "kind"}, one per successor the CFG
    records: `taken` and `fall` for the two arms of a conditional branch, `jump` for an
    unconditional one, `fall` where a block runs into the next. A call does not end a
    block in this CFG, so there is no call-return edge; a branch out of the function, a
    return and a trap end a block with no edge. Raises expr.TooDeep as tier3_graph
    does."""
    from .cfg import _is_cond, _target
    from .disasm import cut_end
    from .expr import tier3_graph
    g = tier3_graph(ann, cut_end(cr, dis), mono)
    if g is None:
        return None
    blocks, edges = [], []
    for addr in sorted(g.blocks):
        blk = g.blocks[addr]
        if not blk.insns:
            continue
        last = blk.insns[-1]
        blocks.append({"start": addr, "end": last[0] + 4, "instructions": len(blk.insns)})
        mn = blk.term
        if blk.cexit:
            kinds = ["fall"]
        elif _is_cond(mn):
            inside = _target(last[2]) is not None and blk.exit_target == -1
            kinds = ["taken", "fall"] if inside else ["fall"]
        elif mn == "b":
            kinds = ["jump"]
        else:
            kinds = ["fall"]
        for i, to in enumerate(blk.succ):
            edges.append({"from": addr, "to": to,
                          "kind": kinds[i] if i < len(kinds) else "fall"})
    return {"entry": g.entry, "blocks": blocks, "edges": edges}


_BLOCK_STYLE = {"taken": ", color=darkgreen", "fall": ", color=red",
                "jump": ""}


def block_graph_dot(graph, image, title: str) -> list:
    """The lines of one block_graph as a DOT digraph, block ids by start address."""
    from .disasm import va_of
    out = [f"digraph {dot_quote(title)} {{", "  node [shape=box];"]
    for b in graph["blocks"]:
        va = va_of(image, b["start"])
        n = b["instructions"]
        out.append(f'  "0x{va:x}" [label="0x{va:x} ({n} insn{"" if n == 1 else "s"})"'
                   + (", penwidth=2" if b["start"] == graph["entry"] else "") + "];")
    for e in graph["edges"]:
        out.append(f'  "0x{va_of(image, e["from"]):x}" -> "0x{va_of(image, e["to"]):x}"'
                   f' [class="{e["kind"]}"{_BLOCK_STYLE[e["kind"]]}];')
    out.append("}")
    return out
