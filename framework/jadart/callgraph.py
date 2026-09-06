"""The function table and the call graph: what is in here, and what calls what.

Every disassembler opens on a function list (radare2's `afl`, IDA's Functions window,
Ghidra's Symbol Tree) and answers "who calls this" (`axt`, Ghidra's References To). jadart
had neither: `classes` lists members class by class, which leaves out top-level functions
and everything obfuscation stripped an owner from, and `xrefs` resolved ObjectPool entries
only. Measured on the corpus that is 349 pool references against 34,979 direct calls, so
the old answer to "where is this used" covered one call site in a hundred.

WHAT A DART AOT FUNCTION TABLE HAS THAT A NATIVE ONE DOES NOT:

  * Provenance. A name here is either read out of the snapshot, backfilled from the ELF
    symbol table, or matched against a reference build by shape. Those are three different
    strengths of evidence and the table says which, because a reader who cannot tell an
    inference from a fact has been misled. IDA and Ghidra show one name column.
  * The owning library. A Dart function belongs to a library url, so the table groups by
    `package:myapp/main.dart` rather than by address range, and app code separates from
    framework code with no reference binary and no list of known packages.
  * Discarded functions. `--obfuscate` drops a function's Code object while keeping its
    instructions. Those ranges are real, reachable, and nameless, and they are listed as
    such rather than omitted.

CALL EDGES COME IN THREE KINDS and only the first is a plain `bl`:

    direct      bl #target                     34,979 sites on the corpus binary
    indirect    blr xN                          5,370   closures and virtual dispatch
    pool        ldr xN,[x27,#off] -> a Function    349   torn off and called later

The indirect ones are where a Dart image differs most from native code. A virtual call
goes through the dispatch-table register, and jadart already recovers the selector behind
it, so those sites are attributed by selector rather than left as "indirect". What remains
genuinely unresolvable is a closure call through a captured context.
"""
from dataclasses import dataclass, field

from .disasm import (CodeRange, MissingDisassembler, UnsupportedArch, disassemble_range,
                     build_pool_map, _mem_base_disp, _add_imm_from_pp)


@dataclass
class CallIndex:
    """Who calls whom, built in one sweep of the instruction image.

    Keyed on pc_offset throughout, because that is the only identifier every range has:
    a name is optional and a ref exists only for functions that kept their Code object.

    Direct and virtual edges are kept apart on purpose. A `bl` names one callee and that
    is a fact. A virtual site names a selector, and the dispatch table says which classes
    implement it, so the honest answer is a SET of possible callees. Merging the two would
    let one `toString` call site add sixty-odd edges indistinguishable from real ones, and
    "who calls this" would stop meaning anything.
    """
    callers: dict = field(default_factory=dict)    # target pc -> [caller pc, ...]
    callees: dict = field(default_factory=dict)    # caller pc -> [target pc, ...]
    indirect: dict = field(default_factory=dict)   # caller pc -> count of blr sites
    unresolved: int = 0                            # bl to something that is not a range

    # virtual dispatch, resolved through the serialized dispatch table
    sites: dict = field(default_factory=dict)      # caller pc -> [(blr addr, sel off)]
    may_call: dict = field(default_factory=dict)   # caller pc -> {possible target pc}
    may_be_called_by: dict = field(default_factory=dict)   # target pc -> {caller pc}
    sel_targets: dict = field(default_factory=dict)        # sel off -> {target pc}
    virtual_sites: int = 0                         # blr sites attributed to a selector
    opaque_sites: int = 0                          # blr sites nothing could attribute


def selector_targets(image, fr, offsets, extra_names: dict = None) -> dict:
    """Selector call-site immediate -> the set of functions a site could reach.

    This is what makes a virtual edge real rather than a label. The dispatch table maps
    array index k to a code_index, and `k = cid + selector_offset`, so walking every class
    id at one selector offset enumerates exactly the implementations the runtime could
    land on. It is the same table Tier 3.4 reads for names, decoded once and asked a
    different question.

    Only the offsets actually seen at call sites are resolved. Crossing every class id
    with every possible offset would be millions of lookups to answer a question nobody
    asked.

    THE PART THAT IS NOT OBVIOUS. `k = cid + selector_offset` is a packing, not a matrix:
    two different (class, selector) pairs legitimately share a row, so walking every class
    id at one offset returns the implementations of that selector MIXED WITH whatever
    unrelated pairs happen to land on the same rows. Taken raw, the median selector came
    back with 370 targets, which is nonsense for a method a few dozen classes override.
    The filter is the one Tier 3.4 already trusts for naming: every real implementation of
    a selector carries the same method name, so the modal name among the candidates is the
    selector, and rows disagreeing with it are collisions. That drops `toString` from 649
    candidates to the classes that actually define it.

    Which means this pass needs NAMES, and an `--obfuscate` build has almost none: the
    vote has nothing to vote with and virtual resolution collapses to a handful of
    selectors. `extra_names` (pc -> name) is how signature matching feeds it, so the two
    features compose instead of each stopping at the same wall.
    """
    from collections import Counter
    from .dispatch import find_dispatch_table, ORIGIN_ELEMENT_ARM64, _slot_names
    if not offsets or not image.data or not image.data_length:
        return {}
    found = find_dispatch_table(image.data, fr.end_pos, image.data_length,
                                fr.code_first_ref, len(image.pcs) + 1)
    if not found:
        return {}
    _pos, entries, _end = found
    slot_name = _slot_names(fr, image)
    cids = sorted({cid & 0xFFFFFFFF for _r, _n, cid, _s in fr.classes})
    npc, nrows = len(image.pcs), len(entries)
    out = {}
    for off in offsets:
        sel = off + ORIGIN_ELEMENT_ARM64        # call-site immediate back to row space
        cand = []
        for c in cids:
            k = c + sel
            if 0 <= k < nrows:
                ci = entries[k]
                if ci is not None and 0 < ci <= npc:
                    slot = ci - 1               # slot = code_index - 1
                    pc = image.pcs[slot]
                    # A matched name is only a selector once its class qualifier is off:
                    # the vote compares method names, not `Class.method`.
                    nm = slot_name.get(slot) or ""
                    if not nm and extra_names:
                        nm = extra_names.get(pc, "").rsplit(".", 1)[-1]
                    cand.append((pc, nm))
        named = Counter(nm for _pc, nm in cand if nm)
        if not named:
            continue                            # nothing to vote with: leave unresolved
        top = named.most_common(2)
        # Same rule as dispatch.build_selector_map: a tie is not a winner. most_common
        # settles one by insertion order, which would attribute the call site to whichever
        # name happened to be counted first.
        if len(top) > 1 and top[1][1] == top[0][1]:
            continue
        winner, _n = top[0]
        hits = {pc for pc, nm in cand if nm == winner}
        if hits:
            out[off] = hits
    return out


def build_index(image, fr=None, virtual: bool = True,
                extra_names: dict = None) -> CallIndex:
    """One pass over every code range, collecting direct, pool-mediated and virtual edges.

    A `bl` whose target is not the start of a known range is counted rather than recorded:
    those are branches into a runtime stub that lives outside the instructions table, and
    silently dropping them would make the edge counts look complete when they are not.

    Virtual sites need the dispatch table, which is decoded after the sweep so that only
    the selector offsets actually used get resolved.
    """
    idx = CallIndex()
    starts = {cr.pc_offset for cr in image.all_ranges}
    pool = build_pool_map(fr, getattr(image, "arch", None)) if fr is not None else {}
    # A pool entry that names a function: `&name` is build_pool_map's spelling.
    fn_by_pool = {off: lbl[1:] for off, lbl in pool.items() if lbl.startswith("&")}
    name_to_pc = {}
    if fr is not None:
        from .disasm import function_name_by_pc
        for pc, nm in function_name_by_pc(image, fr).items():
            name_to_pc.setdefault(nm, pc)

    want_virtual = virtual and fr is not None
    if want_virtual:
        from .expr import detect_dispatch

    for cr in image.all_ranges:
        try:
            dis = disassemble_range(image, cr)
        except (MissingDisassembler, UnsupportedArch):
            # Not per-range noise: capstone is absent, or this is arm32 and there is no
            # decoder for it. Swallowing it once per range built an EMPTY call graph and
            # presented it as fact, every arm32 function came back with zero callers,
            # which reads as "nothing calls this" rather than "we cannot see calls here".
            raise
        except Exception:
            continue
        src = cr.pc_offset
        if want_virtual:
            disp = detect_dispatch(dis)
            for blr_addr, (_recv, off) in disp.items():
                if off is None:
                    continue
                idx.sites.setdefault(src, []).append((blr_addr, off))
                idx.virtual_sites += 1
        far, seen = {}, set()
        for _addr, mn, op in dis:
            op = op or ""
            if mn == "bl" and op.startswith("#"):
                try:
                    t = int(op[1:], 16)
                except ValueError:
                    continue
                if t in starts:
                    if t not in seen:
                        seen.add(t)
                        idx.callees.setdefault(src, []).append(t)
                        idx.callers.setdefault(t, []).append(src)
                else:
                    idx.unresolved += 1
            elif mn == "blr":
                idx.indirect[src] = idx.indirect.get(src, 0) + 1
            elif mn in ("ldr", "ldur") and fn_by_pool:
                md = _mem_base_disp(op)
                off = None
                if md and md[0] == "x27":
                    off = md[1]
                elif md and md[0] in far:
                    off = far[md[0]] + md[1]
                # A function torn out of the pool is a reference to it even though the
                # call happens later through a register, so it belongs in the graph.
                t = name_to_pc.get(fn_by_pool.get(off)) if off is not None else None
                if t is not None and t not in seen:
                    seen.add(t)
                    idx.callees.setdefault(src, []).append(t)
                    idx.callers.setdefault(t, []).append(src)

            fb = _add_imm_from_pp(op) if mn == "add" else None
            if fb is not None:
                far[fb[0]] = fb[1]
            elif far:
                far.pop(op.split(",", 1)[0].strip(), None)

    # Every blr the dispatch detector could not attribute is a closure call or a call
    # through a captured context. Counting them is the difference between "we resolved
    # the indirect calls" and knowing how many are left.
    idx.opaque_sites = sum(idx.indirect.values()) - idx.virtual_sites

    if want_virtual and idx.sites:
        offsets = {off for sites in idx.sites.values() for _a, off in sites}
        idx.sel_targets = selector_targets(image, fr, offsets, extra_names)
        for caller, sites in idx.sites.items():
            for _addr, off in sites:
                for t in idx.sel_targets.get(off, ()):
                    idx.may_call.setdefault(caller, set()).add(t)
                    idx.may_be_called_by.setdefault(t, set()).add(caller)
    return idx


# ---------------------------------------------------------------------------
# The function table
# ---------------------------------------------------------------------------

@dataclass
class Func:
    pc_offset: int
    size: int
    name: str = ""
    origin: str = "anonymous"   # snapshot | symtab | signature | anonymous
    library: str = ""
    callers: int = 0
    callees: int = 0
    indirect: int = 0
    virtual_callers: int = 0    # call sites that could reach this through the dispatch table
    overloads: int = 0          # how many functions share its selector; 1 means unambiguous

    @property
    def label(self) -> str:
        return self.name or f"sub_0x{self.pc_offset:x}"


#: Where a name came from, strongest evidence first. `snapshot` was serialised into the
#: binary; `symtab` was backfilled from the ELF symbol table on a dwarf_stack_traces_mode
#: build; `signature` was matched against a reference binary and is an inference, not a
#: reading. Keeping them apart is the whole point of showing an origin column.
ORIGINS = ("snapshot", "symtab", "signature", "anonymous")


def function_table(image, fr, hdr=None, sigs: str = None) -> tuple:
    """Every code range in the image as a Func. Returns (rows, graph_error).

    `graph_error` is None when the call graph was built, and the exception when it could
    not be: arm32 has no instruction decoder, and capstone is an optional extra. Both are
    returned rather than raised because the LIST still works there, names, sizes and
    owning libraries all come from the snapshot, which is target-independent. Only the
    columns that need decoded instructions are missing, and the caller says so instead of
    printing zeros that read as "nothing calls this".
    """
    from .disasm import function_name_by_pc
    from .signatures import MARK

    snapshot_names = {}
    for ref, name_ref, _ow, _kt in fr.functions:
        nm = fr.strings.get(name_ref, "")
        cr = image.code_ranges.get(ref)
        if nm and cr is not None:
            snapshot_names[cr.pc_offset] = nm
    symtab = dict(image.symbol_names or {})

    names = function_name_by_pc(image, fr)
    matched = {}
    if sigs:
        from .signatures import load, match
        try:
            matched = match(image, fr, load(sigs))
        except (MissingDisassembler, UnsupportedArch):
            matched = {}      # reported once below, through graph_error

    # function pc -> owning library, through the class that owns the function
    lib_by_pc = {}
    if hdr is not None:
        try:
            from .program import build_program
            prog = build_program(fr, hdr)
            lib_by_ref = {k.ref: k.library for k in prog.classes if k.library}
            for ref, _nr, ow, _kt in fr.functions:
                cr = image.code_ranges.get(ref)
                if cr is not None and ow in lib_by_ref:
                    lib_by_pc[cr.pc_offset] = lib_by_ref[ow]
        except Exception:
            lib_by_pc = {}

    graph_error = None
    try:
        idx = build_index(image, fr, extra_names={
            pc: m.name for pc, m in matched.items()} if matched else None)
    except (MissingDisassembler, UnsupportedArch) as e:
        idx, graph_error = CallIndex(), e
    # How many implementations share a target's selector. 1 means a virtual site reaching
    # it has exactly one possible landing, which is as good as a direct edge.
    share = {}
    for _off, tgts in idx.sel_targets.items():
        for t in tgts:
            share[t] = max(share.get(t, 0), len(tgts))

    out = []
    for cr in image.all_ranges:
        pc = cr.pc_offset
        nm = names.get(pc, "")
        if nm and pc in snapshot_names:
            origin = "snapshot"
        elif nm and pc in symtab:
            origin = "symtab"
        elif pc in matched:
            nm, origin = matched[pc].name + MARK, "signature"
        else:
            origin = "snapshot" if nm else "anonymous"
        out.append(Func(pc_offset=pc, size=cr.size, name=nm, origin=origin,
                        library=lib_by_pc.get(pc, ""),
                        callers=len(idx.callers.get(pc, ())),
                        callees=len(idx.callees.get(pc, ())),
                        indirect=idx.indirect.get(pc, 0),
                        virtual_callers=len(idx.may_be_called_by.get(pc, ())),
                        overloads=share.get(pc, 0)))
    out.sort(key=lambda f: f.pc_offset)
    return out, graph_error


def callers_of(image, fr, targets, extra_names: dict = None) -> dict:
    """target pc -> {"direct": [CodeRange], "virtual": [CodeRange], "overloads": int},
    for the `xrefs` of a function.

    Direct and virtual are reported separately because they answer different questions. A
    direct entry calls this function. A virtual entry reaches this SELECTOR, and
    `overloads` says how many implementations share it: 1 means the site can only land
    here, 82 means it is one of eighty-two `toString`s and the site may never reach this
    one at runtime. Collapsing the two would turn a certainty into a maybe with no way to
    tell which is which.
    """
    idx = build_index(image, fr, extra_names=extra_names)
    by_pc = {cr.pc_offset: cr for cr in image.all_ranges}
    share = {}
    for _off, tgts in idx.sel_targets.items():
        for t in tgts:
            share[t] = max(share.get(t, 0), len(tgts))
    out = {}
    for t in targets:
        out[t] = {
            "direct": [by_pc[c] for c in idx.callers.get(t, ()) if c in by_pc],
            "virtual": [by_pc[c] for c in sorted(idx.may_be_called_by.get(t, ()))
                        if c in by_pc],
            "overloads": share.get(t, 0),
        }
    return out
