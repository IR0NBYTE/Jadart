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
from typing import NamedTuple

from .errors import JadartError

from .disasm import (CodeRange, MissingDisassembler, UnsupportedArch, disassemble_range,
                     build_pool_map, _mem_base_disp, _add_imm_from_pp, require_decoder,
                     MAX_INSNS, A64Words, A64_BL, A64_BLR, A64_DISPATCH, _PP, _word_load,
                     _word_add_pp, _word_loadstore, _word_loads_x)


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
    undecodable: list = field(default_factory=list)  # pcs of ranges that would not decode


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

    Only the ranges that need operands are decoded. A `bl` is one fixed opcode, so direct
    edges come straight off the raw words (A64Words). The other two kinds need text: a
    virtual site is read by detect_dispatch off decoded instructions, and a pool-mediated
    call needs its load resolved. So a range goes through capstone only when it holds a
    `blr` beside a load from the dispatch table, or a pool access that could name a
    function, which is about a fifth of the ranges in a real image.
    Everything else is answered from the words, and the answer is the same one: capstone
    decodes every word of every range on all sixteen arm64 binaries in the corpus, so the
    words it would have printed a `bl` for are exactly the words read here.
    """
    idx = CallIndex()
    ranges = image.all_ranges
    # Fail the way the full decode did, and before any work: an image that could not be
    # decoded must not come back as a graph of only its direct calls.
    arch_name = require_decoder(image) if ranges else None
    starts = {cr.pc_offset for cr in ranges}
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

    # The raw word reading is arm64 only; any other decoder keeps the full sweep.
    words = A64Words(image.text) if arch_name == "arm64" else None
    fn_offsets = set(fn_by_pool)

    for cr in ranges:
        src = cr.pc_offset
        if words is not None and src % 4 == 0:
            rw = _read_words(words, image, cr, fn_offsets, want_virtual)
        else:
            rw = _RangeWords(None, 0, want_virtual, True, None)
        if not (rw.need_virtual or rw.need_pool):
            _words_edges(idx, src, rw.targets, rw.nblr, starts)
            continue
        # detect_dispatch answers each `blr` from the instructions before it, so a range
        # decoded only for dispatch can stop at its last `blr`. Nothing past that point
        # could change a site, and it is a little under a third of what they hold.
        limit = MAX_INSNS if rw.need_pool else rw.last_blr
        try:
            dis = disassemble_range(image, cr, limit)
        except (MissingDisassembler, UnsupportedArch):
            # Not per-range noise: capstone is absent, or this is arm32 and there is no
            # decoder for it. Swallowing it once per range built an EMPTY call graph and
            # presented it as fact, every arm32 function came back with zero callers,
            # which reads as "nothing calls this" rather than "we cannot see calls here".
            raise
        except Exception:
            # One range that will not decode must not take the graph down with it, but it
            # must not vanish either: a function missing from the graph reads as "nothing
            # calls this" when the truth is that nothing could look. Recorded by pc so the
            # caller can say how many and which.
            idx.undecodable.append(cr.pc_offset)
            continue
        if rw.need_virtual:
            disp = detect_dispatch(dis)
            for blr_addr, (_recv, off) in disp.items():
                if off is None:
                    continue
                idx.sites.setdefault(src, []).append((blr_addr, off))
                idx.virtual_sites += 1
        if not rw.need_pool:
            # Decoded for detect_dispatch alone. The words already hold every `bl` and
            # `blr` in order, so re-reading them from text would only cost the time.
            _words_edges(idx, src, rw.targets, rw.nblr, starts)
            continue
        # A pool-mediated edge interleaves with the direct ones in instruction order and
        # shares their dedupe, so a range that may have one keeps the whole decoded walk.
        far, seen = {}, set()
        for _addr, mn, op in dis:
            op = op or ""
            if mn == "bl" and op.startswith("#"):
                try:
                    t = int(op[1:], 16)
                except ValueError:
                    continue
                _direct_edge(idx, src, t, starts, seen)
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


def _words_edges(idx: CallIndex, src: int, targets: list, nblr: int, starts: set) -> None:
    """The direct edges and the `blr` count of one range, as read off its words."""
    seen = set()
    for t in targets:
        _direct_edge(idx, src, t, starts, seen)
    if nblr:
        idx.indirect[src] = idx.indirect.get(src, 0) + nblr


def _direct_edge(idx: CallIndex, src: int, t: int, starts: set, seen: set) -> None:
    """Record `src` calling `t`, once per pair, or count it when `t` is not a range."""
    if t in starts:
        if t not in seen:
            seen.add(t)
            idx.callees.setdefault(src, []).append(t)
            idx.callers.setdefault(t, []).append(src)
    else:
        idx.unresolved += 1


def _far_pool_hit(words: A64Words, first: int, nwords: int, fn_set: set) -> bool:
    """Whether any load off a far pool base in this window could name a function.

    A far load is two instructions, `add xD, x27, #hi` then `ldr xT, [xD, #lo]`, and the
    second one does not mention x27, so it is not a candidate and the whole window is
    walked instead.

    What this may forget has to be a subset of what the decoded path forgets, or it would
    miss a load the decoded path resolves and lose an edge. The decoded path drops a base
    whenever an instruction's first operand spells that register, which includes a store
    or a compare that only reads it. This drops a base only when a 64-bit load writes it,
    which is one of those cases. Dart builds a far load as `add x16, x27, #hi` then
    `ldr x16, [x16, #lo]`, reusing x16 at once, and dropping the base there keeps a later
    unrelated load off x16 from reading as a pool entry. With _word_load reading every
    load exactly that saves little, one range in 8,194 on the clean fixture, but it is the
    same rule the decoded path applies, so the two agree on which bases are live.

    Register 31 is never dropped. As a load destination it is spelled `xzr` and as a base
    `sp`: `add sp, x27, #hi; ldr xzr, [x0]; ldr x1, [sp, #8]` still reads through sp in
    the decoded path, and dropping it here would lose that edge. An SVE load off a far
    base goes unread for the reason _read_words gives.
    """
    far = {}
    data = words.words
    for i in range(first, first + nwords):
        w = data[i]
        base = _word_add_pp(w)
        if base is not None:
            if base[0] != _PP:                # x27 itself is read directly, never as a base
                far[base[0]] = base[1]
            continue
        if not far:
            continue
        ld = _word_load(w)
        if ld is None:
            continue                          # not an ldr or ldur the decoded path resolves
        if ld[0] in far and far[ld[0]] + ld[1] in fn_set:
            return True
        rt = w & 31
        if rt != 31 and rt in far and _word_loads_x(w):
            del far[rt]                       # read first, then overwritten, as decoded
    return False


class _RangeWords(NamedTuple):
    """One range as read off its raw words, and what still needs a decode."""
    targets: list          # bl targets in instruction order; None when not read
    nblr: int              # blr sites
    need_virtual: bool     # detect_dispatch has something to find here
    need_pool: bool        # a pool load may name a function
    last_blr: int          # instructions up to and including the last blr


def _read_words(words: A64Words, image, cr, fn_offsets: set, want_virtual: bool):
    """Read one range off its raw words into a _RangeWords. The two flags say what, if
    anything, still needs the range decoded.

    The window is the one disassemble_range reads, `size or 512` bytes capped at
    MAX_INSNS instructions, so a range is scanned over exactly the words capstone would
    have been handed.

    need_virtual is a `blr` in a range that also loads from the dispatch table, when
    virtual sites are wanted, because only detect_dispatch can say which selector it
    calls. need_pool is a pool load, direct or far, whose offset is an entry that names a
    function. A missed one would read as "nothing calls this", which is the one answer
    the graph must not give by accident, so pool loads are read with _word_load and
    _word_add_pp, which say exactly what the decoded path reads out of capstone's text for
    every scalar and floating point `ldr`, `ldur` and `add` from x27.

    The shapes they do not read are the scalable ones: SVE `ldr z0, [x27]` and
    `ldr p0, [x27]`, and SME `ldr za[w12, 0], [x27]`. They sit outside that encoding
    group, and at displacement zero the decoded path would resolve them. Dart AOT emits
    none of them, and a vector, predicate or matrix loaded out of the object pool would
    not be a function reference if it did, so the edge that would be missed is one that
    should never have been drawn.

    A `blr` with no dispatch load anywhere in its range is answered here. detect_dispatch
    attributes a `blr` only when its register came out of an indexed load off x21, so
    such a range gives it nothing to find: every one of its calls is a closure call, and
    the count of them is all the graph keeps.
    """
    end = min(len(image.text), cr.pc_offset + (cr.size or 512))
    nwords = min(max(0, end - cr.pc_offset) // 4, MAX_INSNS)
    targets, nblr, far, dispatch, need_pool, last_blr = [], 0, False, False, False, 0
    first = cr.pc_offset // 4
    for i, w in words.window(cr.pc_offset, nwords):
        if (w & 0xFC000000) == A64_BL:
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            targets.append(i * 4 + imm * 4)
        elif (w & 0xFFFFFC1F) == A64_BLR:
            nblr += 1
            last_blr = i - first + 1
        elif ((w >> 5) & 31) == A64_DISPATCH:
            dispatch = dispatch or _word_loadstore(w)
        elif ((w >> 5) & 31) == _PP and fn_offsets and not need_pool:
            ld = _word_load(w)
            if ld is not None:
                need_pool = ld[1] in fn_offsets
            elif _word_add_pp(w) is not None:
                far = True                   # the load that uses it is not a candidate
            # anything else with 27 in bits 5-9 is not an ldr, ldur or add from the pool,
            # which are the only three the decoded path resolves
        # Whatever is left is a pool word nothing asked about (no function entries, or
        # the range already needs a decode) or a 0xD6 word that is not a plain blr: ret,
        # br, or blraaz and its kin, which the decoded path does not count either.
    if far and not need_pool:
        need_pool = _far_pool_hit(words, first, nwords, fn_offsets)
    return _RangeWords(targets, nblr, bool(want_virtual and nblr and dispatch), need_pool,
                       last_blr)


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
    """Every code range in the image as a Func. Returns (rows, graph_error, notes).

    `notes` is a list of things the caller should print beside the table: ranges that
    were dropped from the graph, or a library attribution that could not be made. They
    are gaps in the output, and a gap that is not named reads as a fact.

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
    notes = []
    if hdr is not None:
        try:
            from .program import build_program
            prog = build_program(fr, hdr)
            lib_by_ref = {k.ref: k.library for k in prog.classes if k.library}
            for ref, _nr, ow, _kt in fr.functions:
                cr = image.code_ranges.get(ref)
                if cr is not None and ow in lib_by_ref:
                    lib_by_pc[cr.pc_offset] = lib_by_ref[ow]
        except JadartError as e:
            # Every function then prints with no library, which is indistinguishable from
            # a snapshot that records none. Say why instead. Anything that is not a
            # JadartError is a defect in this program and propagates to the caller.
            lib_by_pc = {}
            notes.append(f"library attribution unavailable: {e}")

    graph_error = None
    try:
        idx = build_index(image, fr, extra_names={
            pc: m.name for pc, m in matched.items()} if matched else None)
    except (MissingDisassembler, UnsupportedArch) as e:
        idx, graph_error = CallIndex(), e
    if idx.undecodable:
        shown = ", ".join(f"0x{pc:x}" for pc in idx.undecodable[:5])
        more = f" and {len(idx.undecodable) - 5} more" if len(idx.undecodable) > 5 else ""
        notes.append(f"{len(idx.undecodable)} code ranges would not decode and are absent "
                     f"from the call graph: {shown}{more}")
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
    return out, graph_error, notes


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
