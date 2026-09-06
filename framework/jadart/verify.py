"""Acceptance gates: is this snapshot being parsed with the RIGHT grammar?

The alloc-pass self-check (`assigned == num_objects`) is necessary but not sufficient. It
passes on a build whose pointer model we have no grammar for, because the wrong grammar
reads the same NUMBER of varints. So "it parsed" is not evidence that a profile is correct,
and claiming support for a new epoch or target on that basis would be claiming too much.

A stronger claim is possible because the snapshot encodes a number of values twice, in
independently-derived places. The alloc pass and the fill pass each read the class list;
Function objects carry a code_index that must agree with the instructions table; the header
states a table length the rodata also implies. None of these agreements can survive a
misparse, and none of them need an external oracle. That matters: the only byte-exact
oracle jadart ever had (unflutter's per-cluster offsets) is not something a shipped copy
can consult.

Tier A gates are byte-exact: a failure means the grammar is wrong. Tier B gates are
plausibility checks that report but never gate, because they can pass on a wrong parse.

A target counts as SUPPORTED only when every Tier-A gate passes on at least three
independent binaries built with that SDK, including one --obfuscate build, on both the vm
and isolate snapshots. Anything less is a hypothesis.

    jadart verify <libapp.so>
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class GateResult:
    gate: str
    tier: str            # "A" (byte-exact) or "B" (plausibility)
    passed: bool
    checks: int          # how many individual comparisons the gate made
    detail: str = ""
    skipped: str = ""    # non-empty when the gate could not run at all

    @property
    def status(self) -> str:
        if self.skipped:
            return "SKIP"
        return "PASS" if self.passed else "FAIL"


@dataclass
class VerifyReport:
    path: str
    which: str                                  # "isolate" or "vm"
    epoch: str = ""
    arch: str = ""
    gates: list = field(default_factory=list)

    @property
    def tier_a(self) -> list:
        return [g for g in self.gates if g.tier == "A"]

    @property
    def supported(self) -> bool:
        """Every Tier-A gate that could run must pass, and at least one must have run."""
        ran = [g for g in self.tier_a if not g.skipped]
        return bool(ran) and all(g.passed for g in ran)

    def render(self) -> str:
        out = [f"// jadart verify: {self.path} [{self.which}]",
               f"//   epoch {self.epoch}   target {self.arch}", ""]
        for tier, label in (("A", "Tier A, byte-exact (a failure means the grammar is wrong)"),
                            ("B", "Tier B, plausibility (reported, never gating)")):
            rows = [g for g in self.gates if g.tier == tier]
            if not rows:
                continue
            out.append(label)
            for g in rows:
                note = g.skipped or g.detail
                out.append(f"  [{g.status}] {g.gate:<34} {g.checks:>7} checks  {note}")
            out.append("")
        ran = [g for g in self.tier_a if not g.skipped]
        bad = [g for g in ran if not g.passed]
        out.append(f"Tier A: {len(ran) - len(bad)}/{len(ran)} passed"
                   + (f"  FAILED: {', '.join(g.gate for g in bad)}" if bad else ""))
        out.append("VERDICT: " + ("grammar consistent with this snapshot"
                                  if self.supported else "GRAMMAR MISMATCH"))
        out.append("  (one binary is not support; that needs >=3 binaries incl. an "
                   "--obfuscate build, on both snapshots)")
        return "\n".join(out)


#: Mnemonics whose first operand is a SOURCE, so they do not kill a tracked register.
#: The same list expr.py keeps for the same reason (`cmp x1, x2` has no destination).
_NO_DEST_VERIFY = frozenset({"cmp", "cmn", "tst", "teq", "ccmp", "ccmn", "fcmp", "fcmpe",
                             "str", "stur", "stp", "strb", "strh", "sturb", "sturh",
                             "b", "bl", "blr", "br", "ret", "cbz", "cbnz", "tbz", "tbnz"})


def _g(gate, tier, passed, checks, detail="", skipped=""):
    return GateResult(gate=gate, tier=tier, passed=passed, checks=checks,
                      detail=detail, skipped=skipped)


#: `[base]`, `[base, #imm]` and `[base, index]`, with the second operand captured raw so
#: the register-offset form is recognised rather than skipped. See getter_field_load.
_MEM = re.compile(r"\[\s*(\w+)\s*(?:,\s*([^\],]+?)\s*)?\]")
_IMM = re.compile(r"#(-?(?:0x)?[0-9a-fA-F]+)")


def _wide_reg(r):
    """The destination is a whole register, so the value loaded is not a compressed one."""
    return r[:1] in ("x", "d", "s", "q", "r")


def _reg64(r):
    #: w1 and x1 are the same register, so a write through the 32-bit name has to
    #: kill the 64-bit one. Not doing that let `add x1, x1, HEAP`, the pointer
    #: decompression AFTER the field load, leave x1 still marked as the receiver.
    return "x" + r[1:] if (r[:1] == "w" and r[1:].isdigit()) else r


def getter_field_load(dis, recv0="x1", frame=("x15", "x29")):
    """(byte offset, is_wide) for the field load in an implicit getter, or None.

    Not "the first [x1, #imm]", which is what this was and which read three
    different things wrong. The receiver arrives in x1 (program.receiver_for), but
    a getter with a frame reloads it (`ldr x0, [x15]`), a getter without one may
    copy it (`mov x0, x1`), and an offset too large for a 9-bit displacement is
    materialised in a register first (`mov x17, #0x15f; ldr w1, [x0, x17]`).
    Missing the last of those made the reader skip the real load and take the
    LATER `ldur d0, [x1, #7]`, the payload of the boxed double it had just
    loaded, reporting field 0x8 for a field at 0x160 on xyz.deepdaikon.xeonjia.
    The gate fired and the defect was in the gate, which is the right way round.

    Returns None rather than a guess wherever the shape is not one of these; a
    gate that cannot read a case must not score it."""
    recv = {recv0}
    consts = {}
    for _pc, mn, ops in dis:
        parts = [o.strip() for o in ops.split(",")]
        dst = _reg64(parts[0]) if parts else ""
        if mn in ("ldur", "ldr", "ldrsw", "ldursw", "ldp"):
            m = _MEM.search(ops)
            if m is not None and _reg64(m.group(1)) in recv:
                idx = m.group(2)
                if idx is None:
                    return 1, _wide_reg(parts[0])     # [recv] is offset 0 + tag
                im = _IMM.fullmatch(idx)
                off = int(im.group(1), 0) if im else consts.get(_reg64(idx))
                if off is None:
                    return None
                return off + 1, _wide_reg(parts[0])   # tagged: [recv, #off-1]
            recv.discard(dst)
            if m is not None and m.group(1) in frame:
                recv.add(dst)     # the prologue's reload of the incoming receiver
            continue
        if mn in ("mov", "movz") and len(parts) >= 2:
            im = _IMM.fullmatch(parts[1])
            consts[dst] = int(im.group(1), 0) if im else None
            if _reg64(parts[1]) in recv:
                recv.add(dst)                        # a copy of `this`
            else:
                recv.discard(dst)
            continue
        if parts and parts[0] and mn not in _NO_DEST_VERIFY:
            recv.discard(dst)
            consts.pop(dst, None)
    return None


def run_gates(clusters, fr, hdr, image=None, dispatch=None) -> list:
    """Evaluate every gate we can from an already-completed walk."""
    import collections
    from . import cids as C

    gates = []
    # Cids read back out of the RO data image are raw numbers, so naming them needs the
    # numbering this snapshot was built with, not the bundled one.
    table = hdr.epoch.cid_table
    by_name = collections.defaultdict(list)
    for cl in clusters:
        by_name[cl.name].append(cl)

    # G3: the class list is encoded twice
    # The CLASS cluster's alloc pass reads a list of predefined cids; the fill pass then
    # reads each Class object's own class_id. Two different encodings (signed varint list vs
    # per-object field) of the same information, so they must agree elementwise.
    cls_clusters = by_name.get("ClassCid", [])
    pre = next((cl.predefined_cids for cl in cls_clusters if cl.predefined_cids), None)
    if pre is None:
        gates.append(_g("G3 class-cid prefix", "A", False, 0,
                        skipped="no CLASS cluster with a predefined list"))
    else:
        fill_cids = [c & 0xFFFFFFFF for _r, _n, c, _s in fr.classes]
        n = min(len(pre), len(fill_cids))
        bad = [i for i in range(n) if pre[i] != fill_cids[i]]
        gates.append(_g("G3 class-cid prefix", "A", not bad, n,
                        f"{len(pre)} predefined"
                        + (f"; first mismatch at {bad[0]}" if bad else "")))

    # G4: String lengths are encoded twice
    # The alloc pass reads each string's (length, is_two_byte); the fill pass reads the same
    # header again before the bytes. This pins the alloc->fill boundary to the byte: a
    # one-byte slip makes the very first string's length disagree.
    # This compared nothing until it was measured: the pass condition was `total > 0`,
    # where total counted only what ALLOC had recorded, so the gate reported thousands of
    # checks it never made and FAIL was unreachable. The fill walk now keeps the pairs it
    # read (fillwalk.FillResult.string_lengths) and they are compared elementwise here.
    total, bad = 0, []
    for cl in by_name.get("StringCid", []):
        alloc = cl.lengths or []
        fill = getattr(fr, "string_lengths", {}).get(cl.index)
        if fill is None:
            continue
        if len(alloc) != len(fill):
            bad.append(f"cluster {cl.index}: alloc has {len(alloc)} strings, "
                       f"fill read {len(fill)}")
            total += min(len(alloc), len(fill))
            continue
        total += len(alloc)
        for i, (a, f) in enumerate(zip(alloc, fill)):
            if tuple(a) != tuple(f):
                bad.append(f"cluster {cl.index} string {i}: alloc {tuple(a)} != fill "
                           f"{tuple(f)}")
                break
    gates.append(_g("G4 string alloc/fill lengths", "A", total > 0 and not bad, total,
                    f"{total} strings agree on (length, is_two_byte) in both passes"
                    if total and not bad else
                    (f"{len(bad)} disagreements; first: {bad[0]}" if bad else ""),
                    skipped="" if total else "no String cluster read by the fill pass"))

    # G4b: the same pinning for RO-data strings
    # Uncompressed targets have no stream-based String cluster, so G4 can't run and the
    # suite would quietly lose a gate on the target that needs the most scrutiny.
    # The ROData equivalent: offsets must be strictly increasing and land on objects whose
    # tag word actually decodes to a string cid. A wrong alignment shift or a misread delta
    # puts them on non-string tags almost immediately.
    from .clusters import RODATA as _RODATA
    ro_str = [cl for cl in clusters if cl.pattern == _RODATA
              and cl.name in ("StringCid", "OneByteStringCid", "TwoByteStringCid")]
    if not ro_str:
        gates.append(_g("G4b rodata string objects", "A", False, 0,
                        skipped="no ROData string cluster (compressed target)"))
    else:
        import struct as _struct
        blob = image.data if image is not None else None
        checked4 = bad4 = 0
        if blob:
            hl = _struct.unpack_from("<q", blob, 4)[0] + 4
            di = (hl + 63) & ~63
            for cl in ro_str:
                offs = cl.rodata_offsets or []
                if any(offs[i] >= offs[i + 1] for i in range(len(offs) - 1)):
                    bad4 += 1
                for off in offs:
                    base = di + off
                    if base + 16 > len(blob):
                        bad4 += 1
                        continue
                    tags, = _struct.unpack_from("<I", blob, base)
                    cid = (tags >> 12) & 0xFFFFF
                    checked4 += 1
                    if table.name(cid) not in ("StringCid", "OneByteStringCid", "TwoByteStringCid"):
                        bad4 += 1
        gates.append(_g("G4b rodata string objects", "A", bad4 == 0 and checked4 > 0,
                        checked4,
                        f"{checked4} objects, offsets monotonic and tagged as strings"
                        + (f"; {bad4} bad" if bad4 else ""),
                        skipped="" if blob else "needs the snapshot blob"))

    # G5: every ref id is in range
    # ReadRefId is self-resynchronising, so a desync yields plausible-looking ids; what it
    # cannot do is keep them all inside [0, num_objects].
    lo, hi, bad = 0, hdr.num_objects, 0
    for ref, name_ref, owner_ref, _kt in fr.functions:
        for r in (name_ref, owner_ref):
            if r != -1 and not (lo <= r <= hi):
                bad += 1
    for _r, name_ref, _cid, super_ref in fr.classes:
        for r in (name_ref, super_ref):
            if r != -1 and not (lo <= r <= hi):
                bad += 1
    checked = len(fr.functions) * 2 + len(fr.classes) * 2
    gates.append(_g("G5 ref ids in range", "A", bad == 0, checked,
                    f"0 <= ref <= {hi}" + (f"; {bad} out of range" if bad else "")))

    # G6: instance geometry is encoded twice
    # An INSTANCE cluster's alloc pass reads (next_field_offset, instance_size) for the cid;
    # the Class object for that same cid carries (instance_size, next_field_offset) in its
    # fill data. The order differs between the two, which is a useful trap in itself.
    from .clusters import INSTANCE as _INSTANCE
    pairs = bad6 = 0
    for cl in clusters:
        if cl.pattern != _INSTANCE or not cl.instance_size:
            continue
        got = fr.class_sizes.get(cl.cid)
        if got is None:
            continue
        pairs += 1
        if (got[0], got[1]) != (cl.instance_size, cl.next_field_offset):
            bad6 += 1
    gates.append(_g("G6 instance size vs class", "A", bad6 == 0, pairs,
                    f"{pairs} INSTANCE clusters matched to their Class"
                    + (f"; {bad6} mismatched" if bad6 else ""),
                    skipped="" if pairs else "no INSTANCE cluster with a Class object"))

    # G7: Function.code_index agrees with the instructions table
    # GetCodeAndEntryPointByIndex: instructions-table slot == code_index - 1, in both the
    # discarded and the Code-cluster case. The Function fill pass and the Code fill pass
    # derive that number independently, so agreement ties them together.
    if image is None:
        gates.append(_g("G7 code_index vs instr slot", "A", False, 0,
                        skipped="needs the instructions image (--verify on a .so)"))
    else:
        slot_of = {}
        for _code_ref, owner_ref, ci in fr.codes:
            slot_of[owner_ref] = image.first_code + ci
        checked7 = bad7 = 0
        for ref, ci in fr.func_code_index.items():
            slot = slot_of.get(ref)
            if slot is None or ci <= 0:
                continue
            checked7 += 1
            if ci - 1 != slot:
                bad7 += 1
        cover = (100.0 * checked7 / len(fr.func_code_index)) if fr.func_code_index else 0.0
        gates.append(_g("G7 code_index vs instr slot", "A", bad7 == 0, checked7,
                        f"{cover:.0f}% of functions have both halves"
                        + (f"; {bad7} mismatched" if bad7 else ""),
                        skipped="" if checked7 else "no function has both halves"))

    # G8: the header's table length is implied by the rodata
    # instr_table_len is stated in the header; the InstructionsTable rodata separately holds
    # length and first_entry_with_code. One equality validates the five header varints, the
    # data-image alignment, and the rodata header layout at once.
    if image is None:
        gates.append(_g("G8 instr_table_len vs rodata", "A", False, 0,
                        skipped="needs the instructions image"))
    else:
        implied = len(image.pcs) - image.first_code
        ok = (hdr.instr_table_len == implied)
        gates.append(_g("G8 instr_table_len vs rodata", "A", ok, 1,
                        f"header {hdr.instr_table_len} == {len(image.pcs)} - "
                        f"{image.first_code} = {implied}" if ok else
                        f"header {hdr.instr_table_len} != {implied}"))

    # G10: canonical-set table shape
    # The canonical set is a power-of-two open-addressed table plus two sentinel slots, and
    # its gap list has to fit inside it. The most fragile sub-grammar in the alloc pass.
    csl = [(cl, cl.csl) for cl in clusters if cl.csl]
    bad10 = []
    for cl, (table_length, first_element, gaps) in csl:
        size = table_length - 2
        if size <= 0 or (size & (size - 1)) != 0:
            bad10.append(f"{cl.name}: table_length-2={size} not a power of two")
        elif sum(gaps) + (cl.count - first_element) > size:
            bad10.append(f"{cl.name}: gaps overflow the table")
    gates.append(_g("G10 canonical-set shape", "A", not bad10, len(csl),
                    f"{len(csl)} canonical sets" + (f"; {bad10[0]}" if bad10 else ""),
                    skipped="" if csl else "no canonical-set clusters"))

    # G11: the dispatch table closes the byte chain
    # Anchored on the Code cluster's first ref (which the serializer writes into the table
    # header), and it must consume the stream to its exact end. Together with G4 this pins
    # the whole stream: start, alloc->fill boundary, and end.
    if dispatch is None:
        gates.append(_g("G11 dispatch anchor + exact end", "A", False, 0,
                        skipped="needs the instructions image"))
    else:
        pos, entries, end, expected_end = dispatch
        ok = (end == expected_end)
        gates.append(_g("G11 dispatch anchor + exact end", "A", ok, len(entries),
                        f"table at 0x{pos:x}, {len(entries)} entries, ends exactly at "
                        f"0x{end:x}" if ok else f"ends 0x{end:x}, stream ends 0x{expected_end:x}"))

    # G12: a field's offset lands inside its own class
    # A Field object records where it lives, `Smi::New(Field::TargetOffsetOf(field))`,
    # app_snapshot.cc:2238, and its owner Class separately records how big an instance is.
    # The two are written by different clusters from different sources, so a field placed
    # outside its own object means one of them is being misread. Instance fields only: a
    # static's number is a field-table id and is bounded by nothing here.
    from .fields import recover_fields
    layout = recover_fields(fr, hdr.arch)
    gates.append(_g("G12 field offset vs instance size", "A",
                    layout.out_of_range == 0, layout.placed,
                    f"{layout.placed} instance fields inside their class"
                    + (f"; {layout.out_of_range} outside" if layout.out_of_range else ""),
                    skipped="" if layout.declared else "no instance Field object survived"))

    # G14: the compiler agrees with the metadata about where the field is
    # An ImplicitGetter's entire body is one load of the field it reads (its Function.data
    # IS that Field, raw_object.h Function::data), so the displacement the code generator
    # emitted and the offset the serialiser wrote are two encodings of one number produced
    # by two halves of the compiler that never consult each other. This is the check that
    # makes printing the NAME defensible rather than merely self-consistent: nothing in the
    # snapshot alone could catch an off-by-one in the units of `target_offset_`.
    is_arm32 = bool(hdr.arch and hdr.arch.name == "arm")
    frame = ("r13", "r11") if is_arm32 else ("x15", "x29")
    recv0 = "r1" if is_arm32 else "x1"
    if image is None or not layout.placed:
        gates.append(_g("G14 getter code vs field offset", "A", False, 0,
                        skipped="needs the instructions image and a placed field"))
    else:
        from .disasm import disassemble_function, MissingDisassembler
        off_of = {}
        for fref, (kind_bits, value_ref) in fr.field_meta.items():
            if not (kind_bits >> 1) & 1:
                w = fr.smi_values.get(value_ref)
                if w is not None:
                    off_of[fref] = w * hdr.arch.compressed_word_size
        owner_of = {ref: ow for ref, _n, ow in fr.fields}
        cid_of = {ref: cid & 0xFFFFFFFF for ref, _n, cid, _s in fr.classes}
        checked14 = bad14 = checked15 = bad15 = 0
        try:
            for ref, _nr, _ow, kt in fr.functions:
                if (kt & 0x1F) != 6:                       # Function::Kind ImplicitGetter
                    continue
                fld = fr.func_data.get(ref, -1)
                want = off_of.get(fld)
                if want is None:
                    continue
                dis = disassemble_function(image, ref)
                if not dis:
                    continue
                got = getter_field_load(dis, recv0, frame)
                if got is None:
                    continue                                # nothing receiver-relative to read
                first, wide = got
                checked14 += 1
                if first != want:
                    bad14 += 1
                # G15: the same getter says how WIDE the slot is, and the owner's
                # unboxed-fields bitmap says the same thing from the other side.
                ow = owner_of.get(fld)
                cid = cid_of.get(ow, cid_of.get(fr.patch_class.get(ow, -1), None))
                bm = fr.class_unboxed.get(cid) if cid is not None else None
                if bm is None or hdr.arch.compressed_word_size == hdr.arch.word_size:
                    # On an uncompressed target a tagged load is already word-wide, so the
                    # register width says nothing and this gate has no signal to read.
                    continue
                checked15 += 1
                if bool((bm >> (want // hdr.arch.compressed_word_size)) & 1) != bool(wide):
                    bad15 += 1
        except MissingDisassembler:
            checked14 = -1
        if checked14 < 0:
            gates.append(_g("G14 getter code vs field offset", "A", False, 0,
                            skipped="no disassembler installed"))
        else:
            gates.append(_g("G14 getter code vs field offset", "A", bad14 == 0, checked14,
                            f"{checked14} implicit getters load the offset their Field "
                            f"records" + (f"; {bad14} disagree" if bad14 else ""),
                            skipped="" if checked14 else "no implicit getter has code"))
            # G15: the unboxed-fields bitmap vs the width the code generator used
            # `host_bitmap.Set(host_offset / kCompressedWordSize)` (object.cc:3915) marks a
            # slot as holding a raw int or double, and a getter for such a slot loads a
            # whole register where a tagged slot loads 32 bits and decompresses. Two sources
            # again, and this is the one that says whether `field_0x8` is a pointer.
            gates.append(_g("G15 unboxed bitmap vs load width", "A", bad15 == 0, checked15,
                            f"{checked15} getters load the width the bitmap implies"
                            + (f"; {bad15} disagree" if bad15 else ""),
                            skipped="" if checked15
                            else "no getter on a compressed target to read a width from"))

    # ---- Tier B ------------------------------------------------------------------------
    # G13: the isolate snapshot's base objects are the vm snapshot's objects. The VM asserts
    # this at load with a release FATAL, so it is a real format invariant. We can check it
    # only when both snapshots were parsed.
    gates.append(_g("G13 base objects vs vm snapshot", "B", True, 0,
                    skipped="checked by --verify only when both snapshots are present"))

    # G2: no unknown bits set in cluster tags.
    stray = [cl.cid for cl in clusters if cl.cid < 0]
    gates.append(_g("G2 cluster tags decode", "B", not stray, len(clusters),
                    f"{len(clusters)} clusters, all cids non-negative"))

    # G9: the instructions table is monotonic and inside the image.
    if image is not None:
        pcs = image.pcs
        mono = all(pcs[i] < pcs[i + 1] for i in range(len(pcs) - 1))
        inside = (not pcs) or pcs[-1] < len(image.text)
        gates.append(_g("G9 instr table monotonic", "B", mono and inside, len(pcs),
                        "strictly increasing, last pc inside the image"
                        if mono and inside else "NOT monotonic or runs past the image"))
    return gates


def verify_file(path: str) -> VerifyReport:
    """Full-pipeline verification of one .so."""
    from .disasm import load_instructions
    from .dispatch import find_dispatch_table
    from .clusters import walk_alloc
    from .stream import ReadStream

    image, fr, hdr = load_instructions(path)
    # re-walk the alloc pass to keep the Cluster objects (load_instructions discards them)
    data = image.data
    st = ReadStream(data, 52)
    st.read_cstring()
    for _ in range(5):
        st.read_unsigned()
    clusters = walk_alloc(st, hdr.num_base_objects, hdr.num_objects, hdr.num_clusters,
                          epoch=hdr.epoch, is_root_unit=True, arch=hdr.arch)

    dispatch = None
    found = find_dispatch_table(data, fr.end_pos, image.data_length,
                                fr.code_first_ref, len(image.pcs) + 1)
    if found:
        pos, entries, end = found
        dispatch = (pos, entries, end, image.data_length)

    rep = VerifyReport(path=path, which="isolate",
                       epoch=hdr.epoch.name if hdr.epoch else "?",
                       arch=str(hdr.arch) if hdr.arch else "?")
    rep.gates = run_gates(clusters, fr, hdr, image=image, dispatch=dispatch)
    return rep
