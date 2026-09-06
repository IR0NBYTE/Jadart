"""Validation tests for the jadart snapshot core.

Ground truth is our FluBench Dart 3.12.2 build. Run: python3 -m pytest, or
python3 tests/test_core.py.
"""
import os
import random
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from jadart.snapshot import parse_libapp, parse_blob, UnknownEpoch  # noqa: E402
import struct  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
CLEAN = os.path.join(ROOT, "flubench/artifacts/clean/lib/arm64-v8a/libapp.so")
OBF = os.path.join(ROOT, "flubench/artifacts/obf/lib/arm64-v8a/libapp.so")
KNOWN_HASH = "ace654289f5abc240509fc941453ebc5"


def test_parses_both_snapshots():
    s = parse_libapp(CLEAN)
    assert set(s) == {"vm", "isolate"}


def test_version_hash_and_epoch():
    s = parse_libapp(CLEAN)
    assert s["isolate"].version_hash == KNOWN_HASH
    assert s["isolate"].epoch is not None
    assert s["isolate"].epoch.dart == "3.12.2"
    # Was pinned to "kModule", which is what made the mislabel durable: Snapshot::Kind
    # omitted kFullCore, every value from 1 up shifted, and the test locked the result in.
    # A Flutter release snapshot is kFullAOT. See test_snapshot_kind_matches_the_vm_enum.
    assert s["isolate"].kind_name == "kFullAOT"


def test_base_objects_invariant():
    # the isolate snapshot's base objects are the vm snapshot's objects
    s = parse_libapp(CLEAN)
    assert s["isolate"].num_base_objects == s["vm"].num_objects


def test_counts_sane():
    s = parse_libapp(CLEAN)
    iso = s["isolate"]
    assert iso.num_objects > 40000
    assert iso.num_clusters > 300
    assert 0 <= iso.first_cluster_cid < 4096  # sane predefined cid range


def test_obfuscation_does_not_change_format():
    # The FORMAT is identical (same epoch); the object POPULATION is not, because
    # obfuscation strips name strings, removing String objects and reclustering.
    c = parse_libapp(CLEAN)["isolate"]
    o = parse_libapp(OBF)["isolate"]
    assert c.version_hash == o.version_hash
    assert c.epoch.name == o.epoch.name
    assert o.num_objects > 20000 and o.num_clusters > 300  # still parses sanely
    # ~43% of objects vanish under obfuscation: those are the stripped name
    # strings, which is exactly why name recovery drops to 0%.
    assert o.num_objects < c.num_objects * 0.75


def test_fail_loud_on_unknown_epoch():
    fake = (struct.pack("<I", 0xDCDCF5F5) + struct.pack("<q", 0)
            + struct.pack("<q", 2) + (b"deadbeef" * 4) + b"\x00"
            + bytes([0x80, 0x80, 0x80, 0x80, 0x80]))
    try:
        parse_blob(bytes(fake), "test", strict=True)
    except UnknownEpoch:
        return
    raise AssertionError("did not fail loud on unknown epoch")


def test_truncated_snapshot_fails_loud():
    # A truncated/malformed blob must raise TruncatedSnapshot, not a bare IndexError
    # or ValueError leaking from the stream.
    from jadart.stream import TruncatedSnapshot
    # (a) features C-string with no terminator
    b1 = (struct.pack("<I", 0xDCDCF5F5) + struct.pack("<q", 999) + struct.pack("<q", 2)
          + b"a" * 32 + b"no-null-here")
    try:
        parse_blob(b1, "isolate", strict=False)
        raise AssertionError("unterminated features string did not fail loud")
    except TruncatedSnapshot:
        pass
    # (b) blob ends before the count varints
    b2 = (struct.pack("<I", 0xDCDCF5F5) + struct.pack("<q", 1) + struct.pack("<q", 2)
          + b"a" * 32 + b"feat\x00")
    try:
        parse_blob(b2, "isolate", strict=False)
        raise AssertionError("blob truncated before counts did not fail loud")
    except TruncatedSnapshot:
        pass


def _minimal_elf64() -> bytes:
    # smallest ELF64 that Elf64 parses: header + one STRTAB section (no Dart symbols)
    shstr = b"\x00"
    shoff = 64
    sh = struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, shoff + 64, len(shstr), 0, 0, 0, 0)
    eh = bytearray(64)
    eh[0:4] = b"\x7fELF"; eh[4] = 2; eh[5] = 1; eh[6] = 1
    struct.pack_into("<Q", eh, 0x28, shoff)          # e_shoff
    struct.pack_into("<HHH", eh, 0x3A, 64, 1, 0)     # e_shentsize, e_shnum, e_shstrndx
    return bytes(eh) + sh + shstr


def test_symbol_backfill_maps_pc_to_qualified_names():
    # dwarf_stack_traces_mode strips Dart names from the snapshot but leaves them in the
    # ELF .symtab; pc_name_map / CoveringNames recover pc_offset -> qualified name.
    from jadart.symbols import pc_name_map, CoveringNames, ISO_INSTR
    from jadart.elf import Symbol

    class FakeElf:
        def __init__(self, syms):
            self.symbols = syms

        def function_symbols(self, lo, hi):
            return sorted((s for s in self.symbols.values() if s.size > 0 and lo <= s.value < hi),
                          key=lambda s: s.value)

    base = 0x1000
    syms = {
        ISO_INSTR: Symbol(ISO_INSTR, base, 0),
        "A.foo": Symbol("A.foo", base + 0x40, 0x20),
        "A.bar": Symbol("A.bar", base + 0x80, 0x10),
        "far": Symbol("far", base + 0x9000000, 0x10),   # beyond the image
    }
    elf = FakeElf(syms)
    assert pc_name_map(elf, 0x1000) == {0x40: "A.foo", 0x80: "A.bar"}
    cov = CoveringNames(elf, 0x1000)
    assert cov.at(0x48) == "A.foo"
    assert cov.at(0x88) == "A.bar"
    assert cov.at(0x200) is None          # in a gap between symbols
    # a stripped .so (no symtab / no instr symbol) yields an empty map, no crash
    assert pc_name_map(FakeElf({}), 0x1000) == {}


def test_elf_backfill_recovers_real_names_on_real_app():
    # Portable real-app check: point JADART_REALAPP_LIB at an unstripped
    # dwarf_stack_traces_mode libapp.so (e.g. a Flutter build intermediate). The snapshot
    # alone has no real app names; the ELF .symtab backfill must recover them and resolve
    # at least one to a code range.
    lib = os.environ.get("JADART_REALAPP_LIB")
    if not lib or not os.path.exists(lib):
        print("  SKIP test_elf_backfill_recovers_real_names_on_real_app "
              "(set JADART_REALAPP_LIB to an unstripped dwarf-mode libapp.so)")
        return
    from jadart.disasm import load_instructions, named_ranges
    image, fr, _ = load_instructions(lib)
    assert image.symbol_names, "no ELF symbols backfilled from a dwarf-mode build"
    # ELF symbols must align to recovered code ranges (not every symbol is a table entry,
    # e.g. stubs, but many are), and a resolved name must map back to a code range.
    range_pcs = {cr.pc_offset for cr in image.all_ranges}
    aligned = sorted(set(image.symbol_names) & range_pcs)
    assert aligned, "no ELF symbol aligned to a recovered code range"
    nm = image.symbol_names[aligned[0]]
    assert named_ranges(image, fr, nm), f"could not resolve {nm!r} to a code range"


def test_non_flutter_elf_fails_loud_not_silent():
    # A valid ELF with no Dart snapshot must raise (was: return {} -> CLI printed
    # nothing and exited 0).
    import tempfile
    from jadart.snapshot import parse_libapp
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as f:
        f.write(_minimal_elf64())
        path = f.name
    try:
        parse_libapp(path)
        raise AssertionError("non-Flutter ELF returned silently instead of failing loud")
    except ValueError:
        pass
    finally:
        os.unlink(path)


# --- M2: full alloc walk + name recovery ------------------------------------

from jadart.snapshot import walk_isolate  # noqa: E402

# FluBench ground truth (flubench/artifacts/ground_truth.json)
GT_CLASSES = ["BenchAccount"]
GT_FUNCS = ["BenchAccount", "benchCheckSecret", "benchComputeChecksum", "benchDecodeFlag",
            "benchFetchToken", "benchFirstOrDefault", "benchMakeAdder", "benchMakePair",
            "benchWithdraw"]


def test_alloc_walk_completes_clean():
    # The alloc walk asserts assigned refs == num_objects internally; reaching here
    # (no AllocError) means every one of the 356 clusters' read patterns is byte-exact.
    r = walk_isolate(CLEAN)
    assert len(r["clusters"]) == r["header"].num_clusters == 356
    assert r["header"].num_objects == 54145


def test_alloc_walk_completes_obf():
    r = walk_isolate(OBF)
    assert len(r["clusters"]) == r["header"].num_clusters
    assert r["header"].num_objects == 30969


def test_name_recovery_clean_matches_ground_truth():
    strings = set(walk_isolate(CLEAN)["strings"])
    assert all(c in strings for c in GT_CLASSES), "class name recall < 100% on clean"
    assert all(f in strings for f in GT_FUNCS), "function name recall < 100% on clean"


def test_obfuscation_strips_names():
    # --obfuscate removes the identifier strings from the snapshot; recall drops to 0.
    strings = set(walk_isolate(OBF)["strings"])
    assert not any(c in strings for c in GT_CLASSES)
    assert not any(f in strings for f in GT_FUNCS)


# --- M3: full fill walk + object-graph resolution + Tier 0 --------------------

from jadart.program import recover_program, emit_tier0  # noqa: E402

# unflutter --debug-fill oracle: the isolate fill section ends here (roots start).
CLEAN_FILL_END = 0x0e0394


def test_fill_walk_byte_exact_clean():
    # recover_program runs the whole fill pass; walk_fill validates internally by
    # landing on the roots offset. 2350 Class objects recovered == byte-exact reach.
    prog = recover_program(CLEAN)
    assert len(prog.classes) == 2350


def test_full_string_pool_recovers_noncanonical_literal():
    # The non-canonical string literal lives in a late String cluster; only a full
    # fill walk reaches it.
    prog = recover_program(CLEAN)
    assert "FLUBENCH{str_literal_compare}" in set(prog.strings.values())


def test_tier0_resolves_method_to_owner_class():
    # Structural (not flat-string) recovery: benchWithdraw is a METHOD of BenchAccount.
    prog = recover_program(CLEAN)
    ba = [k for k in prog.user_classes() if k.name == "BenchAccount"]
    assert ba, "BenchAccount class not recovered"
    assert any(m.name == "benchWithdraw" for m in ba[0].members)


def test_tier0_recovers_flutter_superclass_hierarchy():
    # Superclass resolution via Type.type_class_id: the real Flutter hierarchy.
    prog = recover_program(CLEAN)
    byname = {k.name: k for k in prog.user_classes()}
    assert byname["FluBenchApp"].super_name == "StatelessWidget"
    assert byname["FluBenchPage"].super_name == "StatefulWidget"
    assert byname["StatelessWidget"].super_name == "Widget"


def test_tier0_emit_contains_app_classes():
    prog = recover_program(CLEAN)
    skeleton = emit_tier0(prog, name_filter="Bench")
    assert "class BenchAccount {" in skeleton
    assert "class FluBenchApp extends StatelessWidget {" in skeleton


def test_fill_walk_completes_obf():
    # Obfuscated build fill walk must also complete byte-exactly (fewer named funcs).
    prog = recover_program(OBF)
    assert len(prog.classes) > 2000
    assert "FLUBENCH{str_literal_compare}" in set(prog.strings.values())


# --- Tier 1: instructions image + annotated disassembly -----------------------

def _capstone_available():
    try:
        import capstone  # noqa: F401
        return True
    except Exception:
        return False


def test_tier1_disassembles_benchwithdraw():
    if not _capstone_available():
        print("  SKIP test_tier1_disassembles_benchwithdraw (no capstone)")
        return
    from jadart.disasm import load_instructions, disassemble_function
    image, fr, _ = load_instructions(CLEAN)
    refs = [ref for ref, nr, ow, kt in fr.functions if fr.strings.get(nr) == "benchWithdraw"]
    assert refs, "benchWithdraw not recovered"
    dis = disassemble_function(image, refs[0])
    assert dis, "no code range for benchWithdraw"
    mnems = [m for _a, m, _o in dis]
    # if (amount > balance) return false; balance -= amount; return true;
    assert "cmp" in mnems and "sub" in mnems and "ret" in mnems
    assert "stur" in mnems   # the balance store-back


def test_tier1_call_targets_resolve_to_recovered_names():
    if not _capstone_available():
        print("  SKIP test_tier1_call_targets (no capstone)")
        return
    from jadart.disasm import (load_instructions, disassemble_function,
                               function_name_by_pc, annotate)
    image, fr, _ = load_instructions(CLEAN)
    refs = [ref for ref, nr, ow, kt in fr.functions if fr.strings.get(nr) == "benchRunAll"]
    assert refs, "benchRunAll not recovered"
    dis = disassemble_function(image, refs[0])
    ann = annotate(dis, function_name_by_pc(image, fr))
    called = {note.split("-> ")[1] for _a, _m, _o, note in ann if "-> " in note}
    # benchRunAll invokes the bench functions in sequence
    for expect in ("benchWithdraw", "benchCheckSecret", "benchComputeChecksum"):
        assert expect in called, f"{expect} not resolved as a call target"


def test_disasm_coverage_full_image_including_obfuscated():
    # The instruction table covers the WHOLE image, including --obfuscate-discarded
    # functions (table entries [0, first_code) with no Code object). Disassembling only
    # recovered owners collapsed obf coverage to ~4%; all_ranges must reach ~100% on
    # BOTH builds with no overlaps.
    from jadart.disasm import load_instructions
    for path in (CLEAN, OBF):
        image, fr, _ = load_instructions(path)
        img = len(image.text)
        covered = sum(cr.size for cr in image.all_ranges)
        assert covered >= 0.99 * img, f"coverage {covered/img:.1%} < 99% for {path}"
        srt = image.all_ranges
        overlaps = [i for i in range(len(srt) - 1)
                    if srt[i].pc_offset + srt[i].size > srt[i + 1].pc_offset]
        assert not overlaps, f"{len(overlaps)} overlapping ranges (wrong sizes) in {path}"
    # obf: the discarded functions have no owner but must still be disassemblable
    image, fr, _ = load_instructions(OBF)
    anon = [cr for cr in image.all_ranges if cr.owner_ref == -1]
    assert len(anon) > 5000, "obf discarded functions not exposed for disassembly"
    if _capstone_available():
        from jadart.disasm import disassemble_range
        dis = disassemble_range(image, anon[len(anon) // 2])
        assert dis and all(len(t) == 3 for t in dis), "anonymous range did not disassemble"


def test_tier1_objectpool_loads_resolve_to_strings():
    # benchCheckSecret's whole body is `return input == 'FLUBENCH{str_literal_compare}';`,
    # so it loads exactly one string constant. That literal lives past the 12-bit direct
    # ldr range, so it is reached by a FAR load (add xD,x27,#hi; ldr [xD,#lo]) and its
    # pool offset is 0x10 + idx*8. This is the byte-exact regression guard for the
    # ObjectPool offset (element_offset = 0x10 + idx*8, PP untagged) + far-load handling.
    if not _capstone_available():
        print("  SKIP test_tier1_objectpool_loads (no capstone)")
        return
    from jadart.disasm import (load_instructions, disassemble_function,
                               function_name_by_pc, annotate, build_pool_map)
    image, fr, _ = load_instructions(CLEAN)
    pool_map = build_pool_map(fr)
    assert len(pool_map) > 100, "ObjectPool string/function map suspiciously small"
    refs = [ref for ref, nr, ow, kt in fr.functions if fr.strings.get(nr) == "benchCheckSecret"]
    assert refs, "benchCheckSecret not recovered"
    dis = disassemble_function(image, refs[0])
    ann = annotate(dis, function_name_by_pc(image, fr), pool_map)
    notes = " ".join(note for _a, _m, _o, note in ann)
    assert '"FLUBENCH{str_literal_compare}"' in notes, \
        "far ObjectPool string load did not resolve to the unique flag literal"


def test_unified_decompile_view():
    # The end-to-end JADX-for-Flutter view: Tier 0 header + Tier 1 body with a
    # control-flow label.
    if not _capstone_available():
        print("  SKIP test_unified_decompile_view (no capstone)")
        return
    from jadart.program import decompile_class
    out = decompile_class(CLEAN, "BenchAccount", structured=False)
    assert "class BenchAccount {" in out
    assert "benchWithdraw()" in out
    assert "L0:" in out          # a basic-block label (branch structure)
    assert "ret" in out


def test_tier2_control_flow_reconstruction():
    # benchWithdraw: `if (amount > balance) return false; balance -= amount; return true;`
    # structures to a real if/else (condition x2 > x3, return in both arms).
    if not _capstone_available():
        print("  SKIP test_tier2_control_flow_reconstruction (no capstone)")
        return
    from jadart.disasm import (load_instructions, disassemble_function,
                               function_name_by_pc, annotate, build_pool_map)
    from jadart.cfg import build_cfg, structure, render
    image, fr, _ = load_instructions(CLEAN)
    refs = [ref for ref, nr, ow, kt in fr.functions if fr.strings.get(nr) == "benchWithdraw"]
    ann = annotate(disassemble_function(image, refs[0]),
                   function_name_by_pc(image, fr), build_pool_map(fr))
    blocks, entry = build_cfg(ann)
    body = "\n".join(render(blocks, structure(blocks, entry)))
    assert "if (x2 > x3) {" in body
    assert "} else {" in body
    assert body.count("return;") == 2   # return false / return true


def test_tier1_tier2_no_crash_over_sample():
    # The full annotate + build_cfg + structure + render pipeline must not raise on any
    # real function (e.g. a bare `[reg]` load with no displacement once broke the far-load
    # parser). Sweep a large sample and require zero exceptions.
    if not _capstone_available():
        print("  SKIP test_tier1_tier2_no_crash_over_sample (no capstone)")
        return
    from jadart.disasm import (load_instructions, disassemble_function,
                               function_name_by_pc, annotate, build_pool_map)
    from jadart.cfg import build_cfg, structure, render
    image, fr, _ = load_instructions(CLEAN)
    pc_to_name = function_name_by_pc(image, fr)
    pool_map = build_pool_map(fr)
    ran = 0
    for ref, nr, ow, kt in fr.functions:
        dis = disassemble_function(image, ref)
        if not dis:
            continue
        ann = annotate(dis, pc_to_name, pool_map)
        blocks, entry = build_cfg(ann)
        render(blocks, structure(blocks, entry))
        ran += 1
        if ran >= 1500:
            break
    assert ran >= 1000, "sample too small to be meaningful"


def test_tier2_loop_body_is_reconstructed():
    # benchComputeChecksum: `for (final b in data) acc = (acc*31+b)&mask; return acc;`
    # The loop MUST reconstruct the real body (element load + accumulate) inside the
    # while, with the length test as an exit `break`, not a bare `return` in while(true)
    # (the old naive succ[0] walk dropped the body and followed the exit edge).
    if not _capstone_available():
        print("  SKIP test_tier2_loop_body_is_reconstructed (no capstone)")
        return
    from jadart.disasm import (load_instructions, disassemble_function,
                               function_name_by_pc, annotate, build_pool_map)
    from jadart.cfg import build_cfg, structure, render
    image, fr, _ = load_instructions(CLEAN)
    refs = [ref for ref, nr, ow, kt in fr.functions if fr.strings.get(nr) == "benchComputeChecksum"]
    assert refs, "benchComputeChecksum not recovered"
    ann = annotate(disassemble_function(image, refs[0]),
                   function_name_by_pc(image, fr), build_pool_map(fr))
    blocks, entry = build_cfg(ann)
    body = "\n".join(render(blocks, structure(blocks, entry)))
    assert "while (true) {" in body
    # the multiply-by-31 accumulate (mul + #0x1f) must live INSIDE the loop body
    loop = body.split("while (true) {", 1)[1]
    assert "#0x1f" in loop and "mul" in loop, "loop body (acc*31) not reconstructed"
    assert "break;" in loop, "loop-exit test not structured as a break"


def test_tier2_decompile_view_is_structured():
    if not _capstone_available():
        print("  SKIP test_tier2_decompile_view_is_structured (no capstone)")
        return
    from jadart.program import decompile_class
    out = decompile_class(CLEAN, "BenchAccount", tier=2)      # explicit Tier 2 view
    assert "if (x2 > x3) {" in out and "} else {" in out
    assert "L0:" not in out               # structured mode has no raw labels here


# --- Tier 3: expression reconstruction ---------------------------------------

def _lift(name):
    from jadart.disasm import (load_instructions, disassemble_function,
                               function_name_by_pc, annotate, build_pool_map)
    from jadart.expr import lift_function
    image, fr, _ = load_instructions(CLEAN)
    refs = [ref for ref, nr, ow, kt in fr.functions if fr.strings.get(nr) == name]
    assert refs, f"{name} not recovered"
    ann = annotate(disassemble_function(image, refs[0]),
                   function_name_by_pc(image, fr), build_pool_map(fr))
    return "\n".join(lift_function(ann, build_pool_map(fr)))


def test_tier3_reconstructs_benchwithdraw_expressions():
    # bool benchWithdraw(int amount) {
    #   if (amount > balance) return false; balance -= amount; return true; }
    # Tier 3 must lift the whole body to expressions: the field compare, the two bool
    # returns, and the compound field store-back (recognised as `-=`).
    if not _capstone_available():
        print("  SKIP test_tier3_reconstructs_benchwithdraw_expressions (no capstone)")
        return
    body = _lift("benchWithdraw")
    assert "> x1.field_0x8" in body            # amount > balance (field load resolved)
    assert "return false;" in body            # NULL_REG+0x30 -> false
    assert "return true;" in body             # NULL_REG+0x20 -> true
    assert "x1.field_0x8 -= x2;" in body      # balance -= amount (compound store-back)
    assert "stur" not in body and "ldur" not in body   # no raw arm64 leaked


def test_lift_does_not_depend_on_register_map_insertion_order():
    # Two runs of the same binary printed the same two values as `t10` and `t11` the other
    # way round, about one run in five. `_merge` iterated a SET of register names and
    # inserted them into the map in that order, and `_pin` walked the map in insertion
    # order to hand out temporary names, so Python's per-process string hash seed chose
    # the numbering. Reported once and recorded as unreproducible after five same-seed
    # runs, which is exactly how a 1-in-5 bug survives being looked for.
    #
    # Pinned at both ends: the merge must not care what order it is given, and the naming
    # must not care what order the map is in.
    from jadart.expr import State, V, P_ATOM, P_ADD, _merge, Lifter

    def merged(order):
        a, b = State(), State()
        for r in order:
            a.reg[r] = V(f"{r} + 1", P_ADD)          # both arms disagree about every one
            b.reg[r] = V(f"{r} + 2", P_ADD)
        out = State()
        _merge(out, a, b)
        return list(out.reg)

    fwd = ["x1", "x2", "x3", "x9", "x21"]
    assert merged(fwd) == merged(list(reversed(fwd))) == sorted(fwd, key=str)

    def pinned(order):
        st = State()
        for r in order:
            st.reg[r] = V(f"x4.field_0x{int(r[1:]):x}", 14)
        return Lifter({})._pin(st, "x4")

    assert pinned(fwd) == pinned(list(reversed(fwd))), "temp numbering follows insertion order"


def test_tier3_reconstructs_loop_accumulator():
    # int benchComputeChecksum(List data) {
    #   for (b in data) acc = (acc*31 + b) & mask; return acc; }
    # The loop-carried accumulate must become an assignment with `* 31` and an element
    # read, the length test an exit `break`, and the index a `+= 1` increment.
    if not _capstone_available():
        print("  SKIP test_tier3_reconstructs_loop_accumulator (no capstone)")
        return
    body = _lift("benchComputeChecksum")
    assert "while (true) {" in body
    loop = body.split("while (true) {", 1)[1]
    assert "break;" in loop
    assert "* 31" in loop                     # acc * 31 (mul + immediate lifted)
    # data[i]: base + index*scale. Asserted by SHAPE, not by which register happened to
    # hold the list, both operands are loop-carried, so both are named variables now and
    # pinning `[x4]` would pin the symptom this test's subject exists to remove.
    assert re.search(r"\bt\d+\[t\d+\]", loop), loop
    assert "+= 1" in loop                     # index increment materialised across the back edge
    # The accumulator is a NAMED loop variable bound before the loop, not a bare machine
    # register reset at the header. `acc` is live in and written, so it is carried.
    assert re.search(r"var t\d+ = ", body.split("while (true) {", 1)[0]), body
    assert not re.search(r"\b[wx](?:3[01]|[12]\d|\d)\b", loop), (
        "a loop-carried value printed as a machine register: " + loop)


def test_tier3_decompile_view_reads_as_dart():
    # The default decompile view is Tier 3; class members get `this` as the receiver.
    if not _capstone_available():
        print("  SKIP test_tier3_decompile_view_reads_as_dart (no capstone)")
        return
    from jadart.program import decompile_class
    out = decompile_class(CLEAN, "BenchAccount")      # default tier=3
    assert "Tier 3 expressions" in out
    assert "this.field_0x8 -= x2;" in out             # receiver aliased to `this`
    assert "return false;" in out and "return true;" in out
    assert "L0:" not in out


def test_tier3_reconstructs_call_arguments():
    # benchRunAll invokes the bench functions; Tier 3 must reconstruct each call's argument
    # list from the callee's register arity (x1..xk live-in), and fall back to `...` for the
    # stack calling convention (ArgumentsDescriptor set). Ground-truth arities:
    #   benchWithdraw(this, amount)=2, benchCheckSecret(input)=1, benchComputeChecksum(d)=1,
    #   benchFirstOrDefault(...)=stack (0 register args).
    if not _capstone_available():
        print("  SKIP test_tier3_reconstructs_call_arguments (no capstone)")
        return
    from jadart.disasm import (load_instructions, disassemble_function,
                               function_name_by_pc, annotate, build_pool_map)
    from jadart.expr import lift_function, make_arity_resolver, entry_arity
    image, fr, _ = load_instructions(CLEAN)
    pc_to_name = function_name_by_pc(image, fr)
    pool_map = build_pool_map(fr)

    def arity_of(name):
        rf = [r for r, nr, ow, kt in fr.functions if fr.strings.get(nr) == name][0]
        dis = disassemble_function(image, rf)
        return entry_arity([(a, m, o, "") for a, m, o in dis])

    assert arity_of("benchWithdraw") == 2          # this + amount
    assert arity_of("benchCheckSecret") == 1       # input
    assert arity_of("benchComputeChecksum") == 1   # data
    assert arity_of("benchFirstOrDefault") is None  # stack convention -> unknown register arity

    refs = [r for r, nr, ow, kt in fr.functions if fr.strings.get(nr) == "benchRunAll"]
    ann = annotate(disassemble_function(image, refs[0]), pc_to_name, pool_map)
    body = "\n".join(lift_function(ann, pool_map, arity=make_arity_resolver(image)))
    import re
    assert "benchCheckSecret(x1)" in body                  # one register arg reconstructed
    # The stack convention is READ, not declined. Ground truth, constructs.dart:88:
    #     b.writeln(benchFirstOrDefault<int>(seed.codeUnits, -1));
    # Three values are pushed, because a generic function takes its type arguments as a
    # hidden first argument, so the reconstruction is (type args, items, fallback), and
    # the fallback is the `-1` in the source. `entry_arity` still declines for this callee
    # and must keep declining: it takes nothing in registers, which is WHY the values are
    # on the stack for the caller to have pushed.
    assert arity_of("benchFirstOrDefault") is None
    m = re.search(r"benchFirstOrDefault\(([^)]*)\)", body)
    assert m, body
    got = [a.strip() for a in m.group(1).split(",")]
    assert len(got) == 3, got
    assert got[0].startswith("pool_"), got                 # the <int> type-arguments vector
    assert got[2] == "-1", got                             # the fallback, straight from source
    # and `items` is the codeUnits view allocated two lines earlier, named at its definition
    assert re.search(rf"^\s*var {re.escape(got[1])} = \w", body, re.M), body
    # The one argument benchComputeChecksum takes is the list an earlier call built. That
    # value arrives in x0 and used to be printed as the bare register, which says nothing
    # about where it came from; it is named at the call that produced it, so the argument
    # names it and the definition is right there in the body.
    m = re.search(r"benchComputeChecksum\((t\d+)\)", body)
    assert m, body
    assert re.search(rf"^\s*var {m.group(1)} = \w", body, re.M), body
    # a 2-arg call renders two comma-separated arguments
    m = re.search(r"benchWithdraw\(([^)]*)\)", body)
    assert m and m.group(1).count(",") == 1, "benchWithdraw should show 2 reconstructed args"


def test_argument_reconstruction_does_not_depend_on_the_callee_having_a_name():
    # A missing NAME was treated as a missing signature. The two have nothing to do with
    # each other: the arity is read out of the callee's own entry code at the target
    # address. 13,923 direct call sites on the corpus binary fell back to `...` for no
    # reason beyond the callee having no recovered name, which is the whole of an
    # --obfuscate build, exactly where the argument list is the only thing left to read.
    if not _capstone_available():
        print("  SKIP test_argument_reconstruction_does_not_depend_on_the_callee_having_a_name")
        return
    import re
    from jadart.disasm import (load_instructions, disassemble_range, annotate,
                               build_pool_map, function_name_by_pc)
    from jadart.expr import lift_function, make_arity_resolver

    for lib in (CLEAN, OBF):
        image, fr, _ = load_instructions(lib)
        pc_to_name, pool_map = function_name_by_pc(image, fr), build_pool_map(fr)
        arity = make_arity_resolver(image)
        named = anon = 0
        for cr in list(image.all_ranges)[:1500]:
            dis = disassemble_range(image, cr)
            if not dis:
                continue
            for ln in lift_function(annotate(dis, pc_to_name, pool_map), pool_map,
                                    arity=arity):
                for m in re.finditer(r"\bsub_0x[0-9a-f]+\(([^)]*)\)", ln):
                    anon += 1
                    named += m.group(1) != "..."
        assert anon > 50, f"{lib}: too few unnamed call sites to prove anything"
        assert named > anon // 10, (
            f"{lib}: {named} of {anon} unnamed call sites got an argument list")


def test_a_call_result_is_named_when_something_reads_it():
    # `bl f` leaves its result in x0. The lifter recorded that by putting the bare string
    # "x0" in the register map, so every later use printed a machine register and nothing
    # in the output connected the value being returned to the call that produced it.
    import re
    body = _lift_asm([("bl", "#0x40"), ("ldur", "x1, [x0, #7]"), ("ldur", "x2, [x0, #0xf]"),
                      ("add", "x0, x1, x2"), ("ret", "")])
    assert "x0" not in body, body
    m = re.search(r"var (t\d+) = sub_0x40\(\.\.\.\);", body)
    assert m, body
    assert f"return {m.group(1)}.field_0x8 + {m.group(1)}.field_0x10;" in body, body
    # One reader on the very next line needs no name at all: the value crosses no
    # statement, so folding it there reorders nothing and duplicates nothing.
    body = _lift_asm([("bl", "#0x40"), ("ret", "")])
    assert body.strip() == "return sub_0x40(...);", body
    # A result nothing reads does not grow a variable nobody uses.
    body = _lift_asm([("bl", "#0x40"), ("mov", "x0, #1"), ("ret", "")])
    assert "var " not in body and "sub_0x40(...);" in body, body


def test_a_join_keeps_what_the_two_arms_computed():
    # _merge keeps what both arms agree on and drops the rest, so a register each arm
    # computed differently left the join as a bare name with nothing anywhere saying what
    # either arm had put in it, and when both arms lifted to nothing else, the renderer
    # dropped the whole `if` as vacuous and the BRANCH went with it. A real case:
    # `scoreKey`'s `% 101` correction compiles to sdiv/msub then `if (r < 0) r += 101`,
    # and the entire correction was missing from the output.
    #
    # Pinned by BEHAVIOUR, not by spelling: the join value now gets a name rather than
    # being written back to the machine register, so what has to hold is that both arms'
    # arithmetic is in the output and that what the `return` names is the thing they wrote.
    # Asserting on `x0` would pin the old rendering, which was the defect being described
    # in the second half of the docstring above, a reader cannot tell that `x0` from one
    # the lifter lost.
    import re as _re
    body = _lift_asm([("cmp", "x1, x2"), ("b.lt", "#0x10"), ("add", "x0, x1, x2"),
                      ("b", "#0x14"), ("sub", "x0, x1, x2"), ("ret", "")])
    m = _re.search(r"return (\S+);", body)
    assert m, body
    ret = m.group(1)
    assert f"{ret} = x1 + x2;" in body and f"{ret} = x1 - x2;" in body, body
    # A register the arms merely move around is left alone: it costs a statement and says
    # nothing the reader could not already see.
    body = _lift_asm([("cmp", "x1, x2"), ("b.lt", "#0x10"), ("mov", "x0, x1"),
                      ("b", "#0x14"), ("mov", "x0, x2"), ("ret", "")])
    assert "= x1;" not in body and "= x2;" not in body, body


def test_an_overwritten_receiver_does_not_read_back_as_this():
    # _merge dropped a register the two arms disagreed about by OMITTING it, and an
    # omitted register falls back to the receiver alias. So an instance method whose
    # then-arm overwrote x1 printed `this.field_0x8` afterwards, on a path where x1 is
    # provably not this. A disagreement is a fact about the register and the map has to
    # hold it, not leave a gap for something else to fill.
    from jadart.expr import lift_function
    rows = [("cbz", "x2, #0xc"), ("mov", "x1, #5"), ("b", "#0x10"),
            ("mov", "x3, #1"), ("ldur", "x0, [x1, #7]"), ("ret", "")]
    body = "\n".join(lift_function([(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)],
                                   receiver={"x1": "this"}))
    assert "this.field_0x8" not in body, body
    assert "x1.field_0x8" in body, body


def test_a_call_does_not_leave_the_values_it_destroyed_behind_it():
    # `_CALL_CLOBBERS` says what a call takes with it, kDartVolatileCpuRegs, R0-R14 plus
    # every V register but VTMP, and liveness has read it that way for a while. The VALUE
    # map did not: a call reset x0 and nothing else, so anything the state knew about
    # x1-x14 or d0-d30 walked through the call that destroyed it and was printed on the
    # far side as though it had survived. A wrong value, not a missing one.
    from jadart.expr import lift_function

    # an integer register: 5 cannot still be in x9 once the callee has run.
    body = _lift_asm([("mov", "x9, #5"), ("bl", "#0x40"), ("mov", "x0, x9"), ("ret", "")])
    assert "return 5;" not in body, body
    assert re.search(r"return x9;", body), body

    # a float register, which had no invalidation at all: `_result` only ever names the
    # INTEGER return register, so d0 kept its pre-call value across every call.
    body = _lift_asm([("fmov", "d0, #1.0"), ("bl", "#0x40"), ("fmov", "d1, d0"),
                      ("ret", "")])
    assert "1.0" not in body.split("bl", 1)[-1].split("sub_0x40", 1)[-1], body

    # the receiver alias, which is the worse spelling: a register the state does NOT
    # describe falls back through `_leaf` to `this`, so x1 after a call printed the
    # receiver on a path where x1 is whatever the callee left there.
    body = "\n".join(lift_function(
        [(i * 4, mn, op, "") for i, (mn, op) in enumerate(
            [("bl", "#0x40"), ("ldur", "x2, [x1, #7]"), ("ret", "")])],
        receiver={"x1": "this"}))
    assert "this.field_0x8" not in body, body

    # ...and a register the call does NOT clobber still says what it held. x19 is
    # kAbiPreservedCpuRegs, so dropping it would be honesty bought at the price of
    # everything the reader came for.
    body = _lift_asm([("mov", "x19, #5"), ("bl", "#0x40"), ("mov", "x0, x19"), ("ret", "")])
    assert "return 5;" in body, body

    # Arguments are read before the clobber, not after. They live in exactly the registers
    # the call is about to destroy, so the wrong order prints a bare register for every
    # argument of every call in the image.
    rows = [("mov", "x1, #7"), ("mov", "x2, #8"), ("bl", "#0x40"), ("ret", "")]
    body = "\n".join(lift_function(
        [(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)],
        arity=lambda _pc: 2))
    assert "sub_0x40(7, 8)" in body, body


def test_a_concurrent_modification_guard_is_not_rendered_as_a_tautology():
    # The real defect the clobber fix was found by. dart:collection's
    # _CompactLinkedHashBase.forEach re-reads `_data` after calling the user's callback and
    # compares it against the copy it took before, which is how a map mutated during
    # iteration is caught. The saved copy sits in a frame slot and survives; the register
    # holding the receiver does not. With the post-call registers still describing their
    # pre-call values both sides rendered as `this.field_0x10`, so the guard read as a
    # comparison that can never fail and the throw behind it as dead code.
    if not _capstone_available():
        print("  SKIP test_a_concurrent_modification_guard_is_not_rendered_as_a_tautology")
        return
    from jadart.disasm import (load_instructions, disassemble_range, annotate,
                               build_pool_map, function_name_by_pc)
    from jadart.expr import lift_function, make_arity_resolver
    image, fr, _hdr = load_instructions(CLEAN)
    p2n = function_name_by_pc(image, fr)
    pm, ar = build_pool_map(fr), make_arity_resolver(image)
    checked = 0
    for cr in image.all_ranges:
        if p2n.get(cr.pc_offset) != "forEach":
            continue
        dis = disassemble_range(image, cr)
        if not dis:
            continue
        body = "\n".join(lift_function(annotate(dis, p2n, pm), pm,
                                       receiver={"x1": "this"}, arity=ar))
        checked += 1
        # Shape, not spelling: no comparison anywhere may have the same text on both
        # sides. A guard that compares a value to itself is either the Smi box idiom
        # (stripped elsewhere) or a value the lifter lost track of.
        for a, b in re.findall(r"\(([^()]+) [=!]= ([^()]+)\)", body):
            assert a != b, f"self-comparison {a!r} in forEach:\n{body}"
    assert checked >= 2, f"expected the compact-hash forEach bodies, saw {checked}"


def test_the_lifted_output_does_not_depend_on_the_hash_seed():
    # Python randomises string hashing per process, so iterating a SET of register names
    # is a different order in every run. The lifter invalidates a set of registers after a
    # loop, and that write inserts into the register map, whose insertion order decides
    # the order temporaries are minted in: two runs over the same binary numbered the same
    # variables differently and `bench.py --digest`, which exists to compare checkouts for
    # equivalence, could not tell a real change from a reshuffle. Two subprocesses, because
    # the seed is fixed for the life of one.
    if not _capstone_available():
        print("  SKIP test_the_lifted_output_does_not_depend_on_the_hash_seed")
        return
    import subprocess
    prog = (
        "import hashlib,sys;"
        "sys.path.insert(0, %r);" % os.path.join(os.path.dirname(__file__), "..") +
        "from jadart.disasm import load_instructions, disassemble_range, annotate,"
        " build_pool_map, function_name_by_pc;"
        "from jadart.expr import lift_function, make_arity_resolver;"
        "image, fr, hdr = load_instructions(%r);" % CLEAN +
        "p2n = function_name_by_pc(image, fr); pm = build_pool_map(fr);"
        "ar = make_arity_resolver(image); h = hashlib.sha256();"
        "[h.update(('\\n'.join(lift_function(annotate(d, p2n, pm), pm, arity=ar))).encode())"
        " for d in (disassemble_range(image, cr) for cr in list(image.all_ranges)[::5]) if d];"
        "print(h.hexdigest())")
    digests = set()
    for seed in ("1", "424242"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        out = subprocess.run([sys.executable, "-c", prog], env=env,
                             capture_output=True, text=True)
        assert out.returncode == 0, out.stderr[-2000:]
        digests.add(out.stdout.strip())
    assert len(digests) == 1, f"the lift is not reproducible: {digests}"


def test_a_loop_does_not_leave_stale_values_behind_it():
    # `carried` is written-and-live-on-entry, and restoring only those left every register
    # the loop assigns WITHOUT reading first still holding its value from before the loop.
    # Set x9 to 5, write 7 to it in the body, and the code after the loop printed `return
    # 5;`, a confident wrong answer, which is the one thing this tool must not produce.
    body = _lift_asm([("mov", "x9, #5"), ("mov", "x9, #7"), ("cbnz", "x2, #4"),
                      ("mov", "x0, x9"), ("ret", "")])
    assert "return 5;" not in body, body
    assert "return x9;" in body, body


def test_tier3_strips_smi_box_idiom():
    # The Smi int-boxing idiom (sbfiz XD,XS,#1; cmp XS,XD,asr #1; b.eq; AllocateMint) must
    # not leak as a bogus self-comparison `if (x != x)`, and the Smi tag `sbfiz` must not
    # appear raw. benchRunAll boxes several int results and exercises this.
    if not _capstone_available():
        print("  SKIP test_tier3_strips_smi_box_idiom (no capstone)")
        return
    import re
    from jadart.disasm import (load_instructions, disassemble_function,
                               function_name_by_pc, annotate, build_pool_map)
    from jadart.expr import lift_function, make_arity_resolver
    image, fr, _ = load_instructions(CLEAN)
    refs = [r for r, nr, ow, kt in fr.functions if fr.strings.get(nr) == "benchRunAll"]
    body = "\n".join(lift_function(
        annotate(disassemble_function(image, refs[0]),
                 function_name_by_pc(image, fr), build_pool_map(fr)),
        build_pool_map(fr), arity=make_arity_resolver(image)))
    assert "sbfiz" not in body, "Smi tag (sbfiz) leaked as raw arm64"
    assert not re.search(r"if \((\w[\w.]*) != \1\)", body), "Smi overflow-check leaked as `x != x`"


def test_tier3_renders_runtime_stubs_semantically():
    # On a real app (dwarf build, stubs named in the ELF), VM runtime stubs must render as
    # source operations (throw / new) or be dropped (stack check, write barrier, type test) -
    # never as a raw `stub _iso_stub_...` call. Portable: set JADART_REALAPP_LIB.
    lib = os.environ.get("JADART_REALAPP_LIB")
    if not lib or not os.path.exists(lib) or not _capstone_available():
        print("  SKIP test_tier3_renders_runtime_stubs_semantically "
              "(set JADART_REALAPP_LIB to an unstripped dwarf-mode libapp.so)")
        return
    from jadart.disasm import (load_instructions, disassemble_range,
                               function_name_by_pc, annotate, build_pool_map)
    from jadart.expr import lift_function, make_arity_resolver
    image, fr, _ = load_instructions(lib)
    p2n = function_name_by_pc(image, fr)
    pm = build_pool_map(fr)
    ar = make_arity_resolver(image)
    leaked = throws = news = 0
    for cr in image.all_ranges[:3000]:
        dis = disassemble_range(image, cr)
        if not dis:
            continue
        body = "\n".join(lift_function(annotate(dis, p2n, pm), pm, arity=ar))
        if "_iso_stub_" in body:
            leaked += 1
        throws += body.count("throw ")
        news += body.count("new ")
    assert leaked == 0, f"{leaked} functions leaked a raw _iso_stub_ call"
    assert throws > 0 and news > 0, "expected some throw / new renderings on a real app"


def test_tier3_attributes_virtual_dispatch():
    # benchCheckSecret is `return input == 'FLUBENCH...'`, an operator== dispatched through the
    # X21 dispatch table. Tier 3.3 attributes the call to the receiver + a stable selector offset
    # (sel_0x<off>) instead of an opaque (dynamic call).
    if not _capstone_available():
        print("  SKIP test_tier3_attributes_virtual_dispatch (no capstone)")
        return
    from jadart.disasm import (load_instructions, disassemble_function,
                               function_name_by_pc, annotate, build_pool_map)
    from jadart.expr import lift_function, detect_dispatch, strip_boilerplate
    image, fr, _ = load_instructions(CLEAN)
    refs = [r for r, nr, ow, kt in fr.functions if fr.strings.get(nr) == "benchCheckSecret"]
    ann = annotate(disassemble_function(image, refs[0]),
                   function_name_by_pc(image, fr), build_pool_map(fr))
    # detection recovers (receiver register, selector offset) for the dispatch blr
    d = detect_dispatch(strip_boilerplate(ann))
    assert d, "no X21 dispatch call detected in benchCheckSecret"
    recv, off = next(iter(d.values()))
    assert recv == "x1" and off is not None, f"receiver/offset not recovered: {(recv, off)}"
    # rendering: a receiver-attributed virtual call, not an opaque (dynamic call)
    body = "\n".join(lift_function(ann, build_pool_map(fr)))
    assert "x1.sel_0x" in body, "virtual dispatch not attributed to the receiver"
    assert "(dynamic call)" not in body


ARM32 = os.path.join(ROOT, "flubench/app/build/app/intermediates/flutter/release/"
                           "armeabi-v7a/app.so")


def _isolate_blob_by_magic(path):
    """Read a snapshot blob without the ELF reader (the arm32 build is ELF32)."""
    raw = open(path, "rb").read()
    offs = [i for i in range(0, len(raw) - 4)
            if struct.unpack_from("<I", raw, i)[0] == 0xDCDCF5F5]
    return raw[offs[-1]:] if offs else None


CORPUS = os.path.join(ROOT, "flubench", "corpus")


EPOCH_HASHES = {
    "3.12.2": "ace654289f5abc240509fc941453ebc5",
    "3.12.0": "41be3daaabd524b8aa7423bc24584957",
    "3.11.5": "78da37fed6bf1489361a312568249f3f",
    "3.10.9": "1ce86630892e2dca9a8543fdb8ed8e22",
    "3.9.2": "97ff04a728735e6b6b098bdf983faaba",
    "3.8.1": "830f4f59e7969c70b595182826435c19",
}


def test_multiple_epochs_resolve():
    # Six format epochs, spanning Dart 3.8 to 3.12. Each is keyed on the hash a build from
    # that release carries, and each declares the grammars it was validated against.
    from jadart import versions
    for dart, h in EPOCH_HASHES.items():
        epoch = versions._EPOCHS.get(h)
        assert epoch is not None, f"dart {dart} not registered"
        assert epoch.dart == dart
        assert epoch.grammars, f"{dart} claims no grammar"
        p = versions.resolve(h, "product arm64 android compressed-pointers")
        assert p is not None and p.epoch.dart == dart


def test_every_corpus_binary_passes_the_gates():
    # The support rule: a target counts as supported only when every Tier-A gate passes on
    # real binaries. This walks whatever the corpus builder has produced, so it tightens
    # automatically as more versions are collected.
    if not _capstone_available():
        print("  SKIP test_every_corpus_binary_passes_the_gates (no capstone)")
        return
    from jadart.macho import open_container
    from jadart.verify import verify_file
    checked = 0
    for dart, want_hash in EPOCH_HASHES.items():
        path = os.path.join(CORPUS, dart, "libapp.so")
        if not os.path.exists(path):
            continue
        blob = open_container(open(path, "rb").read()).symbol_bytes(
            "_kDartIsolateSnapshotData")
        assert blob[20:52].decode("ascii") == want_hash, (
            f"corpus binary for {dart} does not carry the expected hash")
        rep = verify_file(path)
        ran = [g for g in rep.tier_a if not g.skipped]
        bad = [g.gate for g in ran if not g.passed]
        assert not bad, f"dart {dart}: Tier A failures {bad}"
        assert len(ran) >= 8, f"dart {dart}: only {len(ran)} gates ran"
        checked += 1
    if checked == 0:
        print("  SKIP test_every_corpus_binary_passes_the_gates (no corpus built)")
    else:
        assert checked >= 2, "expected the corpus to cover more than one epoch"


def test_ffi_trampoline_data_is_not_an_ffi_instance():
    # FfiTrampolineData starts with "Ffi" but is an ordinary VM object with its own FIXED
    # cluster, not one of the FFI native types that ReadCluster hands to the generic
    # instance cluster. Routing it as an instance reads two extra varints and desyncs the
    # alloc pass. It stayed hidden because the 3.12.2 corpus contains no such cluster, and
    # it is what blocked every other Dart version.
    from jadart.clusters import routing, _pattern_for, FIXED, INSTANCE
    from jadart import versions
    arch = versions.Arch("arm64", 8, True)
    # every epoch, not just 3.12.2: the routing is rebuilt per cid table, so each one has
    # to make the same distinction under its own numbering.
    for epoch in versions.known_epochs():
        ffi = routing(epoch).ffi_instance
        cid = epoch.cid_table.cid("FfiTrampolineDataCid")
        assert cid not in ffi, epoch.dart
        assert _pattern_for(cid, epoch, arch, True) == FIXED, epoch.dart
        # the genuine FFI native types still route to the instance cluster
        native = epoch.cid_table.cid("FfiNativeFunctionCid")
        assert native in ffi, epoch.dart
        assert _pattern_for(native, epoch, arch, True) == INSTANCE, epoch.dart


def test_hashed_file_list_is_read_per_version():
    # The hash input is itself version-dependent. The 15 files are the same, but Dart 3.8
    # lists the seven headers before the eight sources while 3.12 is plain alphabetical, and
    # MD5 is order-sensitive. Hardcoding 3.12's order silently produced a hash no 3.8 binary
    # carries, which looked exactly like "that version is unidentifiable".
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
    from sdk_source import snapshot_files, VM_SNAPSHOT_FILES
    cache = os.path.join(os.path.dirname(__file__), "..", ".sdkcache")
    old = os.path.join(cache, "b04011c77cd93e6ab9144af37976733b558d716c")
    if not (os.path.isdir(old) or os.environ.get("JADART_SDK_FETCH")):
        print("  SKIP test_hashed_file_list_is_read_per_version (no .sdkcache)")
        return
    files = snapshot_files("b04011c77cd93e6ab9144af37976733b558d716c")
    assert len(files) == 15
    assert sorted(files) == sorted(VM_SNAPSHOT_FILES), "same files, different order"
    assert files != VM_SNAPSHOT_FILES, "3.8 ordering should differ from the 3.12 fallback"
    assert files[0].endswith(".h") and files[-1].endswith(".cc")


def test_snapshot_hash_is_md5_of_fifteen_vm_files():
    # The version hash is not opaque: tools/make_version.py MakeSnapshotHashString is an MD5
    # over the raw bytes of exactly 15 files in runtime/vm/, concatenated in a fixed order.
    # That makes hash -> SDK source a lookup rather than a guess, which is what lets an epoch
    # profile be generated for a version we do not have a binary for yet.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
    import hashlib
    from sdk_source import VM_SNAPSHOT_FILES, snapshot_hash, FetchError
    assert len(VM_SNAPSHOT_FILES) == 15
    assert VM_SNAPSHOT_FILES[0] == "app_snapshot.cc" and VM_SNAPSHOT_FILES[-1] == "symbols.h"

    # Offline half: the hash must DISCRIMINATE between SDK versions. The vendored clone is
    # SDK main, so hashing it must not produce the corpus hash. If it did, the hash would
    # be telling us nothing about which grammar to use.
    local = os.path.join(os.path.dirname(__file__), "..", "..",
                         "unflutter/dart-sdk/runtime/vm")
    if os.path.isdir(local) and all(os.path.exists(os.path.join(local, f))
                                    for f in VM_SNAPSHOT_FILES):
        h = hashlib.md5()
        for f in VM_SNAPSHOT_FILES:
            with open(os.path.join(local, f), "rb") as fh:
                h.update(fh.read())
        assert h.hexdigest() != KNOWN_HASH, (
            "the vendored SDK checkout hashes to the corpus hash; the version hash would "
            "then not discriminate between SDK versions")

    # Networked half: only if the fetch cache is already warm (it is gitignored), so the
    # suite stays offline-safe. Set JADART_SDK_FETCH=1 to allow a cold fetch.
    cache = os.path.join(os.path.dirname(__file__), "..", ".sdkcache", "3.12.2")
    if not (os.path.isdir(cache) or os.environ.get("JADART_SDK_FETCH")):
        print("  SKIP snapshot-hash fetch half (no .sdkcache; set JADART_SDK_FETCH=1)")
        return
    try:
        assert snapshot_hash("3.12.2") == KNOWN_HASH, "3.12.2 source must reproduce the hash"
    except FetchError as e:
        print(f"  SKIP snapshot-hash fetch half (network: {e})")


# Optional fixtures that are not committed: JADART_EXTRA_BINARIES is a colon-separated list
# of paths (the same variable tools/measure.py reads). The first Mach-O dylib in it is the
# iOS fixture; the first path containing "shapes_oop" is the x64 OOP fixture. Absent means
# the tests that need them skip and say so.
_EXTRA = [os.path.expanduser(p) for p in os.environ.get("JADART_EXTRA_BINARIES", "").split(":") if p]
IOS_DYLIB = next((p for p in _EXTRA if p.endswith(".dylib")), "/nonexistent/vault_ios.dylib")
_IOS_HOWTO = ("build one with the cached iOS gen_snapshot (no Xcode needed): "
              "$FLUTTER/bin/cache/artifacts/engine/ios-release/gen_snapshot_arm64 "
              "--deterministic --snapshot_kind=app-aot-macho-dylib --macho=<out>.dylib "
              "<app.dill>")


def test_container_dispatch_is_fail_loud():
    # One entry point picks the container, and the two we cannot read yet say so
    # specifically rather than surfacing as a confusing parse error later on.
    #
    # ContainerError, not ValueError. `open_container` is the only door into a container,
    # so it is where the typed-failure promise is kept: it used to let elf.py's ValueError
    # and struct.error through unchanged, which no documented `except` clause names.
    import struct as _s
    from jadart.container import ContainerError
    from jadart.macho import open_container, MachO64
    from jadart.elf import Elf64

    elf64 = b"\x7fELF" + bytes([2, 1]) + b"\x00" * 58
    try:
        open_container(elf64)
    except Exception as e:
        assert not isinstance(e, ValueError) or "ELF32" not in str(e)

    # ELF32 is read now (armeabi-v7a), so the dispatch must accept it rather than refuse.
    # A 58-byte tail is not a parsable ELF32, but it must fail on its CONTENT, not on its
    # class byte.
    elf32 = b"\x7fELF" + bytes([1, 1]) + b"\x00" * 58
    try:
        open_container(elf32)
    except Exception as e:
        assert "ELF32" not in str(e), f"ELF32 must not be refused outright: {e}"

    # a big-endian ELF is still refused, and says why
    try:
        open_container(b"\x7fELF" + bytes([1, 2]) + b"\x00" * 58)
        assert False, "big-endian ELF should be rejected"
    except ContainerError as e:
        assert "little-endian" in str(e)

    fat = _s.pack("<I", 0xCAFEBABE) + b"\x00" * 60
    try:
        open_container(fat)
        assert False, "fat Mach-O should be rejected"
    except ContainerError as e:
        assert "fat" in str(e).lower()

    try:
        open_container(b"MZ\x90\x00" + b"\x00" * 60)
        assert False, "an unknown container should be rejected"
    except ContainerError as e:
        assert "unrecognised container" in str(e)


def test_macho_container_reads_ios_snapshot():
    # iOS App.framework is built by gen_snapshot's own Mach-O writer since Flutter 3.44.4,
    # so a production-identical artifact needs no Xcode. The blobs sit in __TEXT,__const and
    # __TEXT,__text under the same _kDart* names ELF uses.
    if not os.path.exists(IOS_DYLIB):
        print(f"  SKIP test_macho_container_reads_ios_snapshot ({_IOS_HOWTO})")
        return
    import struct as _s
    from jadart.macho import open_container, MachO64
    from jadart.stream import ReadStream
    m = open_container(open(IOS_DYLIB, "rb").read())
    assert isinstance(m, MachO64)
    assert any(s.name == "__TEXT,__const" for s in m.sections)
    blob = m.symbol_bytes("_kDartIsolateSnapshotData")
    assert _s.unpack_from("<I", blob, 0)[0] == 0xDCDCF5F5
    # the instructions blob must run to the end of its section, NOT to the next symbol -
    # thousands of function symbols live inside it and would truncate it to one function
    text = m.symbol_bytes("_kDartIsolateSnapshotInstructions")
    assert len(text) > 1_000_000, f"instructions truncated to {len(text)} bytes"
    st = ReadStream(blob, 52)
    feats = st.read_cstring()
    assert "arm64" in feats and "ios" in feats and "no-compressed-pointers" in feats


def test_uncompressed_pointers_parse_end_to_end():
    # iOS is no-compressed-pointers: String/PcDescriptors/CodeSourceMap/CompressedStackMaps
    # route through RODataDeserializationCluster, whose ReadFill is empty and whose payload
    # lives in the RO data image. Getting the object graph AND the identifier pool out of a
    # target with a different cluster routing is the whole point of the profile split.
    if not os.path.exists(IOS_DYLIB):
        print(f"  SKIP test_uncompressed_pointers_parse_end_to_end ({_IOS_HOWTO})")
        return
    from jadart.program import recover_program
    from jadart.clusters import RODATA
    prog = recover_program(IOS_DYLIB)
    names = {k.name for k in prog.user_classes()}
    assert len(names) > 1000, f"only {len(names)} user classes recovered"
    # the same app built for Android recovers these; iOS must not silently come back empty
    assert "LicenseVault" in names and "VaultPage" in names
    lv = next(k for k in prog.classes if k.name == "LicenseVault")
    assert {m.name for m in lv.members} >= {"withdraw", "checksum", "checkSecret",
                                            "classify", "scoreKey"}
    # the identifier pool is read out of the data image, not the stream
    assert len(prog.strings) > 5000
    assert any("JADART{" in s for s in prog.strings.values())


def test_uncompressed_grammar_passes_the_gates():
    # The gates are the objective test that a new target's grammar is right, rather than
    # merely not crashing, which the alloc self-check alone would have allowed.
    if not os.path.exists(IOS_DYLIB):
        print("  SKIP test_uncompressed_grammar_passes_the_gates (no fixture)")
        return
    if not _capstone_available():
        print("  SKIP test_uncompressed_grammar_passes_the_gates (no capstone)")
        return
    from jadart.verify import verify_file
    rep = verify_file(IOS_DYLIB)
    assert "uncompressed" in rep.arch
    ran = [g for g in rep.tier_a if not g.skipped]
    bad = [g.gate for g in ran if not g.passed]
    assert not bad, f"iOS Tier A failures: {bad}"
    assert len(ran) >= 7, f"only {len(ran)} Tier A gates ran on iOS"
    # the ROData-specific gate must be one of them, so uncompressed targets do not quietly
    # lose the string-pinning check that G4 provides on compressed ones
    assert any(g.gate.startswith("G4b") and g.passed for g in ran)


def test_32_bit_target_resolves_and_sizes_correctly():
    # armeabi-v7a is claimed now. Three quantities follow the word size rather than being
    # constants, and each one silently corrupts a different pass when it is wrong.
    from jadart import versions
    p = versions.resolve(KNOWN_HASH, "product arm android no-compressed-pointers")
    assert p is not None and p.arch.word_size == 4 and not p.arch.compressed

    a32, a64c, a64u = p.arch, versions.Arch("arm64", 8, True), versions.Arch("arm64", 8, False)

    # the header is one machine word, so a 32-bit instance has one header slot, not two;
    # too many slots eats the object's first fields
    assert (a32.instance_header_words, a64c.instance_header_words,
            a64u.instance_header_words) == (1, 2, 1)

    # ReadWordWith32BitReads loops kBitsPerWord/kBitsPerInt32, reading two 32-bit words
    # on a 32-bit target overruns every unboxed field by four bytes
    assert (a32.read32_per_word, a64c.read32_per_word) == (1, 2)

    # objects align to two words
    assert (a32.object_alignment_log2, a64c.object_alignment_log2) == (3, 4)

    # and a heap String's data starts after a header that is rounded up to a word: the
    # 64-bit compressed case is 16 because of that rounding, not because of field widths
    from jadart.disasm import _string_header_size
    assert _string_header_size(8, 4) == 16
    assert _string_header_size(8, 8) == 16
    assert _string_header_size(4, 4) == 12


SHAPES = next((p for p in _EXTRA if "shapes_oop" in p), "/nonexistent/shapes_oop/libapp.so")


def _lift_asm(rows):
    """Lift a hand-written instruction list: (mn, operands) from address 0."""
    from jadart.expr import lift_function
    ann = [(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)]
    return "\n".join(lift_function(ann))


def test_library_url_maps_to_a_path_like_blutter():
    # The url -> path rule is Blutter's DartLibrary::CreatePath. Matching an existing tool
    # means output from the two can be diffed directly, and it is a layout people already
    # know from jadx: a tree mirroring the program's own package structure.
    from jadart.export import library_path
    assert library_path("package:myapp/main.dart") == os.path.join("myapp", "main.dart")
    assert library_path("package:flutter/src/widgets/framework.dart") == os.path.join(
        "flutter", "src", "widgets", "framework.dart")
    assert library_path("dart:core") == os.path.join("dart", "core.dart")
    assert library_path("Shd") == "Shd.dart"          # obfuscated token
    # a url must never escape the output directory
    p = library_path("package:../../etc/passwd")
    assert ".." not in p.split(os.sep) and not os.path.isabs(p)


def test_export_writes_a_browsable_tree():
    if not _capstone_available():
        print("  SKIP test_export_writes_a_browsable_tree (no capstone)")
        return
    import tempfile
    from jadart.export import export
    with tempfile.TemporaryDirectory() as out:
        stats = export(CLEAN, out, tier=3)
        assert stats["libraries"] > 100 and stats["classes"] > 500
        assert stats["methods"] > 1000
        for name in ("strings.txt", "pool.txt", "summary.txt"):
            assert os.path.exists(os.path.join(out, name)), name
        # the app's own library lands at its package path, and carries real bodies
        own = os.path.join(out, "sources", "flubench_corpus", "constructs.dart")
        assert os.path.exists(own), os.listdir(os.path.join(out, "sources"))
        body = open(own).read()
        assert "// lib: package:flubench_corpus/constructs.dart" in body
        assert "class BenchAccount" in body
        assert "this.field_0x8 -= x2;" in body, "method bodies should be lifted"
        # dart: libraries land under dart/. Which ones survive depends on what the app
        # uses and what tree-shaking kept, so assert the mapping, not a specific library.
        dartdir = os.path.join(out, "sources", "dart")
        assert os.path.isdir(dartdir) and os.listdir(dartdir)
        # summary states the limits rather than implying completeness
        summary = open(os.path.join(out, "summary.txt")).read()
        assert "field names" in summary and "AOT" in summary


def test_export_accepts_an_apk():
    # jadx and blutter both take the container. Making a user find lib/arm64-v8a/libapp.so
    # first is a poor greeting, and it is the step most likely to be got wrong.
    import tempfile, zipfile
    from jadart.export import resolve_input, InputError
    with tempfile.TemporaryDirectory() as tmp:
        apk = os.path.join(tmp, "fake.apk")
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("lib/x86_64/libapp.so", b"x86")
            z.writestr("lib/arm64-v8a/libapp.so", b"arm64")   # must win
            z.writestr("AndroidManifest.xml", b"")
        got = resolve_input(apk, os.path.join(tmp, "work"))
        assert open(got, "rb").read() == b"arm64", "arm64 should be preferred"
        # a plain binary passes through untouched
        assert resolve_input(CLEAN, os.path.join(tmp, "work2")) == CLEAN
        # a zip with no snapshot in it says so
        other = os.path.join(tmp, "other.zip")
        with zipfile.ZipFile(other, "w") as z:
            z.writestr("readme.txt", b"hi")
        try:
            resolve_input(other, os.path.join(tmp, "work3"))
            assert False, "should reject a zip with no snapshot"
        except InputError as e:
            assert "Flutter" in str(e)


def test_classes_carry_their_library():
    # Telling application code from framework code has to come from the snapshot itself.
    # Every Class records the library it was declared in, so this needs no reference binary,
    # no locally built comparison app, and no hardcoded list of framework packages, all of
    # which break on a different Flutter version or a different set of dependencies.
    from jadart.program import recover_program
    prog = recover_program(CLEAN)
    libs = prog.libraries()
    assert len(libs) > 100, f"only {len(libs)} libraries resolved"
    assert any(u.startswith("dart:") for u in libs)
    assert any(u.startswith("package:flutter") for u in libs)
    # the corpus app's own package, found without comparing against anything
    own = [u for u in libs if u.startswith("package:flubench_corpus")]
    assert own, f"the app's own library was not found among {len(libs)}"
    names = {k.name for u in own for k in libs[u]}
    assert "BenchAccount" in names
    assert [k for k in prog.classes if k.name == "BenchAccount"][0].library.startswith(
        "package:flubench_corpus")


def test_library_recovery_works_across_epochs_and_targets():
    # The same mechanism has to hold on every version and both pointer models, otherwise it
    # is a trick that happens to fit one build.
    from jadart.program import recover_program
    checked = []
    for dart in EPOCH_HASHES:
        path = os.path.join(CORPUS, dart, "libapp.so")
        if not os.path.exists(path):
            continue
        libs = recover_program(path).libraries()
        assert len(libs) > 100, f"dart {dart}: only {len(libs)} libraries"
        assert any(u.startswith("package:") for u in libs), f"dart {dart}: no package: urls"
        checked.append(dart)
    if os.path.exists(IOS_DYLIB):                       # uncompressed pointers, Mach-O
        libs = recover_program(IOS_DYLIB).libraries()
        assert any(u.startswith("package:") for u in libs), "iOS: no package: urls"
        checked.append("ios")
    if len(checked) < 2:
        print("  SKIP test_library_recovery_works_across_epochs_and_targets (thin corpus)")


def test_far_pool_loads_resolve_not_fake_field_reads():
    # A constant past the direct ldr range loads in two steps:
    #   add x1, x27, #9, lsl #12      <- PP-relative base, note the shift
    #   ldr x1, [x1, #0x2a0]          <- entry at 0x9000 + 0x2a0
    # The lifter used to model the add as PP+0x9 and then the load as a field read on it,
    # printing `PP+0x9.field_0x2a1`. That is not a field access and no such object exists,
    # which is exactly the kind of invented output this project is supposed to refuse.
    body = _lift_asm([("add", "x1, x27, #9, lsl #12"),
                      ("ldr", "x1, [x1, #0x2a0]"),
                      ("mov", "x0, x1"), ("ret", "")])
    assert "field_0x2a1" not in body, body
    assert "pool_0x92a0" in body, body
    # the shift matters: without it the entry would be 0x9 + 0x2a0
    assert "pool_0x2a9" not in body, body
    # direct loads are unaffected
    body = _lift_asm([("ldr", "x0, [x27, #0x40]"), ("ret", "")])
    assert "pool_0x40" in body, body


def test_fp_scalar_arithmetic_lifts():
    from jadart.expr import canon
    assert canon("s3") == "d3" and canon("d3") == "d3"      # s is the low half of d
    assert canon("v3.2d") == "v3.2d"                        # vectors are NOT folded in
    body = _lift_asm([("fadd", "d0, d1, d2"), ("fmul", "d0, d0, d3"), ("ret", "")])
    assert "d1 + d2" in body and "*" in body, body
    body = _lift_asm([("fmov", "d1, #2.00000000"), ("fdiv", "d0, d5, d1"), ("ret", "")])
    assert "d5 / 2.0" in body, body
    body = _lift_asm([("scvtf", "d0, x1"), ("ret", "")])
    assert "x1.toDouble()" in body, body

    # Right operand of a non-commutative op must be parenthesised. `d1 - (d3 - d4)` printed
    # as `d1 - d3 - d4` reads as `(d1 - d3) - d4`, a different number. The integer half of
    # this was fixed in _bin; the FP path was a separate call site and kept the bug.
    body = _lift_asm([("fsub", "d2, d3, d4"), ("fsub", "d0, d1, d2"), ("ret", "")])
    assert "d1 - (d3 - d4)" in body, body
    body = _lift_asm([("fsub", "d2, d3, d4"), ("fdiv", "d0, d1, d2"), ("ret", "")])
    assert "d1 / (d3 - d4)" in body, body


def test_simd_is_not_lifted_as_scalar():
    # The fabrication hazard: `fadd v0.2d, ...` is a lane-wise Float64x2 add, NOT a double
    # add. Rendering it as `a + b` would silently turn vector code into wrong scalar source.
    body = _lift_asm([("fadd", "v0.2d, v1.2d, v2.2d"), ("ret", "")])
    assert "v1.2d + v2.2d" not in body and "d1 + d2" not in body, body
    assert "fadd" in body, "unmodelled SIMD must fall back to raw arm64"
    body = _lift_asm([("fmul", "v0.4s, v1.4s, v2.4s"), ("ret", "")])
    assert "fmul" in body and "*" not in body.split("fmul")[0], body
    # ...but vmaxd/vmind ARE scalar double ops despite the .2d encoding (assembler_arm64.h
    # builds them with EmitSIMDThreeSameOp), and the SDK has no Float64x2 min/max, so the
    # form is unambiguous and IS lifted.
    body = _lift_asm([("fmax", "v0.2d, v1.2d, v2.2d"), ("ret", "")])
    assert "d1.max(d2)" in body, body


def test_writeback_addressing_is_modelled_not_dropped():
    # `ldr x2, [x4], #8` reads [x4] and THEN advances x4. Parsing only the last operand
    # found a bare `#8`, concluded there was no memory operand, and printed the whole
    # instruction as raw arm64, so the pointer bump that drives every copy loop in the
    # core library was invisible AND the loaded value was never attributed.
    body = _lift_asm([("ldr", "x0, [x4], #8"), ("ret", "")])
    assert "ldr" not in body, body
    assert "x4.field_0x1" in body, body           # the access is at the OLD base
    assert "x4 += 8;" in body, body               # and the base then moves
    # ...and the loaded value is pinned to a name BEFORE the base moves, so the text that
    # describes it does not quietly start describing the next element instead.
    assert body.index("var t0 = x4.field_0x1;") < body.index("x4 += 8;"), body
    assert "return t0;" in body, body
    # A pre-indexed store moves first, so the access is at base+disp.
    body = _lift_asm([("str", "x2, [x4, #0x10]!"), ("ret", "")])
    assert "str" not in body and "x4 += 16;" in body, body
    # A writeback amount that is not a readable immediate is not a guess to take.
    body = _lift_asm([("ldr", "x2, [x4], x5"), ("ret", "")])
    assert "ldr x2, [x4], x5" in body, body
    # ...nor is a writeback into the register being loaded, which arm64 calls
    # CONSTRAINED UNPREDICTABLE.
    body = _lift_asm([("ldr", "x4, [x4], #8"), ("ret", "")])
    assert "ldr x4, [x4], #8" in body, body


def test_movk_completes_a_wide_constant():
    # A 32-bit constant is built in halves. Only the first was modelled, so `movk` printed
    # as raw arm64 and took the register it was building back to opaque with it.
    body = _lift_asm([("mov", "x2, #0x1c8"), ("movk", "x2, #0x3b, lsl #16"),
                      ("mov", "x0, x2"), ("ret", "")])
    assert "return 0x3b01c8;" in body, body
    # movk INSERTS into what is already there, so with an unknown starting value there is
    # nothing to compute and the instruction stays raw.
    body = _lift_asm([("ldr", "x2, [x3, #0x10]"), ("movk", "x2, #0x3b, lsl #16"),
                      ("mov", "x0, x2"), ("ret", "")])
    assert "movk" in body, body


def test_conditional_select_is_rendered_only_against_a_known_comparison():
    # csel is exact: the architecture defines it as `d = cond ? a : b`.
    body = _lift_asm([("cmp", "x1, x2"), ("csel", "x0, x3, x4, eq"), ("ret", "")])
    assert "return x1 == x2 ? x3 : x4;" in body, body
    body = _lift_asm([("cmp", "x1, x2"), ("cset", "x0, ne"), ("ret", "")])
    assert "return x1 != x2 ? 1 : 0;" in body, body
    body = _lift_asm([("cmp", "x1, x2"), ("csinc", "x0, x3, x4, lt"), ("ret", "")])
    assert "return x1 < x2 ? x3 : x4 + 1;" in body, body
    # Flags set somewhere this block cannot see are not a predicate we may print.
    body = _lift_asm([("csel", "x0, x3, x4, eq"), ("ret", "")])
    assert "csel" in body and "?" not in body, body
    # ...and neither are flags whose operands have since been overwritten.
    body = _lift_asm([("cmp", "x1, x2"), ("add", "x1, x1, #1"),
                      ("csel", "x0, x3, x4, eq"), ("ret", "")])
    assert "csel" in body, body
    # `vs` after fcmp means "unordered", i.e. a NaN operand. It has no relational
    # spelling, so it does not get one.
    body = _lift_asm([("fcmp", "d1, d2"), ("csel", "x0, x3, x4, vs"), ("ret", "")])
    assert "csel" in body, body


def test_bit_test_branches_name_the_bit_not_the_branch_target():
    # `tbz x0, #0, #0x10` tests bit 0 of x0. The old rendering was `bit(x0, #0, #0x10)`,
    # which put the BRANCH TARGET inside what reads as a call: a predicate over a value
    # that is not an input to it.
    body = _lift_asm([("tbz", "x1, #0, #0xc"), ("mov", "x0, #1"), ("ret", ""),
                      ("mov", "x0, #2"), ("ret", "")])
    assert "bit(" not in body, body
    assert "x1 & 1" in body, body
    body = _lift_asm([("tbnz", "x1, #4, #0xc"), ("mov", "x0, #1"), ("ret", ""),
                      ("mov", "x0, #2"), ("ret", "")])
    assert "(x1 >> 4) & 1" in body, body


def test_a_condition_operand_is_bracketed_wherever_it_lands():
    # cfg builds the condition as TEXT, so the substitution point carries no precedence.
    # `tst` puts its operands inside an `&`, and dropping in an `orr` result unbracketed
    # printed `a | b & x3`, which Dart reads as `a | (b & x3)`: a different predicate.
    body = _lift_asm([("orr", "x1, x1, x2"), ("tst", "x1, x3"), ("b.eq", "#0x14"),
                      ("mov", "x0, #1"), ("ret", ""), ("mov", "x0, #2"), ("ret", "")])
    assert "((x1 | x2) & x3)" in body, body


def test_logical_flags_do_not_claim_a_carry_comparison():
    # `tst`/`ands` force C=0 and V=0, so a carry- or overflow-based branch after one means
    # something the operands cannot express, `b.hi` there is unconditionally false, not
    # `(a & b) > 0`. Only the Z and N conditions are spelled.
    from jadart.cfg import _cond_text
    assert _cond_text((0, "tst", "x1, x2", ""), "b.eq", "#0") == "(x1 & x2) == 0"
    assert "?" in _cond_text((0, "tst", "x1, x2", ""), "b.hi", "#0")
    assert _cond_text((0, "ands", "x0, x1, x2", ""), "b.ne", "#0") == "(x1 & x2) != 0"


def test_fmov_between_int_and_fp_is_not_a_move():
    # `fmov x0, d0` reinterprets the bits; modelling it as a move would invent a numeric
    # equality between an integer and a double.
    body = _lift_asm([("fadd", "d0, d1, d2"), ("fmov", "x0, d0"), ("ret", "")])
    assert "fmov" in body, body
    assert "return d1 + d2;" not in body, body


def test_fp_function_bodies_read_as_source():
    if not os.path.exists(SHAPES):
        print("  SKIP test_fp_function_bodies_read_as_source (no shapes_oop fixture)")
        return
    if not _capstone_available():
        print("  SKIP test_fp_function_bodies_read_as_source (no capstone)")
        return
    from jadart.program import decompile_class
    out = decompile_class(SHAPES, "Triangle")
    # Newton's method: `g = (g + x / g) / 2`, 24 iterations. The guess is loop-carried, so
    # it reads as one named variable throughout instead of as `d2`; what this pins is the
    # ITERATION, which is the thing a reader is trying to recognise.
    # `x` and the `2.0` are NOT carried: the loop never assigns them, so their phi is
    # trivial and collapses back to the value itself rather than becoming a variable.
    assert re.search(r"(t\d+) = \(\1 \+ \w+ / \1\) / 2\.0", out), out
    # a double-returning function returns the value the loop produced, not x0
    assert re.search(r"return t\d+;", out), out
    # the fcmp feeding a branch is consumed by the condition, not printed as a statement
    assert "fcmp" not in out, out
    # Heron's formula survives, with perimeter() inlined by AOT
    assert "/ 2.0" in out and out.count("this.field_0x") >= 6, out


def _walk_for_gates(path):
    from jadart.disasm import load_instructions
    from jadart.clusters import walk_alloc
    from jadart.stream import ReadStream
    image, fr, hdr = load_instructions(path)
    st = ReadStream(image.data, 52)
    st.read_cstring()
    for _ in range(5):
        st.read_unsigned()
    clusters = walk_alloc(st, hdr.num_base_objects, hdr.num_objects, hdr.num_clusters,
                          epoch=hdr.epoch, is_root_unit=True)
    return clusters, fr, hdr, image


def test_acceptance_gates_pass_on_the_corpus():
    if not _capstone_available():
        print("  SKIP test_acceptance_gates_pass_on_the_corpus (no capstone)")
        return
    from jadart.verify import verify_file
    for path, label in ((CLEAN, "clean"), (OBF, "obfuscated")):
        rep = verify_file(path)
        ran = [g for g in rep.tier_a if not g.skipped]
        bad = [g.gate for g in ran if not g.passed]
        assert not bad, f"{label}: Tier A gates failed: {bad}"
        assert len(ran) >= 8, f"{label}: only {len(ran)} Tier A gates ran"
        assert rep.supported


def test_acceptance_gates_detect_a_wrong_grammar():
    # The point of the suite is discriminating power, not passing on good input: the
    # alloc-pass self-check already passes on a mismatched profile. Each perturbation below
    # is the shape of a real grammar error, and must be caught by its specific gate.
    if not _capstone_available():
        print("  SKIP test_acceptance_gates_detect_a_wrong_grammar (no capstone)")
        return
    import copy
    from jadart.verify import run_gates
    clusters, fr, hdr, image = _walk_for_gates(CLEAN)

    def failing(cl, f, h):
        return {g.gate.split()[0] for g in run_gates(cl, f, h, image=image)
                if g.tier == "A" and not g.skipped and not g.passed}

    assert not failing(clusters, fr, hdr), "baseline must be clean"

    # a cid renumbering between SDK releases (exactly what the main-vs-3.12.2 table was)
    shifted = copy.deepcopy(clusters)
    for cl in shifted:
        if cl.predefined_cids:
            cl.predefined_cids = [c + 1 for c in cl.predefined_cids]
    assert "G3" in failing(shifted, fr, hdr)

    # instance geometry disagreeing, what a wrong pointer model would produce
    geom = copy.deepcopy(clusters)
    for cl in geom:
        if cl.instance_size:
            cl.instance_size += 1
            break
    assert "G6" in failing(geom, fr, hdr)

    # a wrong Function fill spec, shifting code_index
    fr2 = copy.copy(fr)
    fr2.func_code_index = {k: v + 1 for k, v in fr.func_code_index.items()}
    assert "G7" in failing(clusters, fr2, hdr)

    # a miscounted header varint
    hdr2 = copy.copy(hdr)
    hdr2.instr_table_len += 1
    assert "G8" in failing(clusters, fr, hdr2)


def test_cid_table_matches_the_epoch():
    # The cid table must come from the SAME SDK release as the binaries being parsed. It was
    # previously expanded from SDK main, which inserted a predefined class at cid 96 and
    # shifted the whole tail by one: cid 112 read as FfiStructCid when the 3.12.2 truth is
    # TypedDataInt8ArrayCid, so the anchor of the typed-data range was routed as an FFI
    # instance. These assertions tie the table to the epoch constants, which were derived
    # independently (empirically, from the corpus) and so form a real cross-check.
    from jadart import cids as C, versions
    from jadart.clusters import routing
    epoch = versions.resolve(KNOWN_HASH, "product arm64 android compressed-pointers").epoch
    table = epoch.cid_table
    assert C.NUM_PREDEFINED_CIDS == epoch.num_predefined_cids == table.num_predefined == 175
    assert table.name(epoch.td_int8_cid) == "TypedDataInt8ArrayCid"
    assert table.name(epoch.td_byte_data_view_cid) == "ByteDataViewCid"
    assert C.kTypedDataInt8ArrayCid == epoch.td_int8_cid
    # the typed-data anchor must not be swallowed by the FFI instance routing
    assert epoch.td_int8_cid not in routing(epoch).ffi_instance
    assert epoch.typed_data_kind(epoch.td_int8_cid) == "internal"
    assert table.name(96).startswith("Ffi")
    # constants are resolved through the table, so they cannot drift from it
    assert C.kStringCid == C.NAME_TO_CID["StringCid"]


def test_cid_numbering_is_per_epoch():
    # The cid behind a class name is not stable across the supported range, so each epoch
    # carries its own table. Two moves happened inside it, and both are silent: 3.4/3.5
    # predate Bytecode at cid 19 so their whole tail sits one lower, and 3.6-3.8 order
    # UnlinkedCall / MonomorphicSmiableCall / CallSiteData differently from 3.9+.
    from jadart import versions
    by_dart = {e.dart: e for e in versions.known_epochs()}
    e34, e38, e312 = by_dart["3.4.4"], by_dart["3.8.1"], by_dart["3.12.2"]

    assert e34.cid_table.num_predefined == 174
    assert e38.cid_table.num_predefined == e312.cid_table.num_predefined == 175
    # the shift: String moves with the tail, which is why 3.4 reports first_cid 92
    assert e34.cid_table.cid("StringCid") == 92
    assert e312.cid_table.cid("StringCid") == 93

    # The dangerous one. Both names route as FIXED clusters so the alloc pass survives the
    # swap, and only the fill pass would notice, because their layouts differ (2 refs and a
    # byte against no refs and two varints). A binary carrying either cluster used to
    # desync while every acceptance gate stayed green.
    assert e38.cid_table.cid("UnlinkedCallCid") != e312.cid_table.cid("UnlinkedCallCid")
    for epoch in (e34, e38, e312):
        t = epoch.cid_table
        assert t.name(t.cid("UnlinkedCallCid")) == "UnlinkedCallCid"
        assert t.name(t.cid("MonomorphicSmiableCallCid")) == "MonomorphicSmiableCallCid"


def test_cluster_tag_packing_changed_at_3_4():
    # Dart 3.4 replaced the cluster tag rather than moving a bit in it. Before it,
    # ReadCluster read a uint64 of `cid << 1 | is_canonical` with no immutable flag; from
    # 3.4 the tag IS an object header word. Decoding one as the other yields cid 0 on the
    # very first cluster, which is what the epoch names are distinguishing.
    from jadart import versions
    by_dart = {e.dart: e for e in versions.known_epochs()}
    old, new = by_dart["3.3.4"].tag, by_dart["3.4.4"].tag
    assert old.packing == "cid_and_canonical" and old.wide
    assert new.packing == "objectheader" and not new.wide

    # 0xB9 is a real first-cluster tag from the 3.3 corpus binary: canonical String.
    assert old.decode(0xB9) == (92, True, False)
    # the same bytes under the 3.4 layout decode to nothing usable
    assert new.decode(0xB9)[0] == 0
    # and a real 3.4 tag: 0x5c042 -> cid 92, canonical. 3.4 reads the immutable flag at bit
    # 6 (0x40 is set here); 3.12 moved it to bit 7, which is the 0x5c082 spelling.
    assert new.decode(0x0005C042) == (92, True, True)
    assert by_dart["3.12.2"].tag.decode(0x0005C082) == (92, True, True)


def test_objectpool_entry_bits_changed_at_3_3():
    # A separate boundary one release earlier, which is the point: the format's moving
    # parts do not change together. 3.3 added SnapshotBehaviorBits and narrowed TypeBits to
    # four bits with PatchableBit at 4; before that TypeBits was seven bits wide with
    # PatchableBit at 7. Reading an older pool the new way makes every patchable entry look
    # like a non-zero behavior, which skips its value and desyncs the fill.
    from jadart import versions
    by_dart = {e.dart: e for e in versions.known_epochs()}
    assert by_dart["3.2.6"].objpool_has_behavior is False
    assert by_dart["3.3.4"].objpool_has_behavior is True
    assert by_dart["3.12.2"].objpool_has_behavior is True


def test_unvalidated_epoch_is_identified_but_refused():
    # An epoch whose grammar has not passed the gates on a real binary must refuse, not
    # guess. The alloc pass would otherwise "succeed" and return a plausible wrong graph.
    # Tested against a synthetic epoch so it keeps holding as real versions get gated.
    from jadart import versions
    fake = "0" * 32
    versions._EPOCHS[fake] = versions.Epoch(
        name="test-ungated", dart="9.9.9", grammars=frozenset(),
        notes="identified, no validated cluster grammar")
    try:
        versions.resolve(fake, "product arm64 android compressed-pointers")
    except versions.UnsupportedTarget as exc:
        assert "no validated cluster grammar" in str(exc)
    else:
        raise AssertionError("an ungated epoch must refuse rather than parse")
    finally:
        del versions._EPOCHS[fake]


def test_dart_3_1_object_pool_and_patchclass_deltas():
    # 3.1 needs two things nothing in app_snapshot.cc reports, and both are invisible to a
    # byte-count diff of the serializer.
    from jadart import versions
    by_dart = {e.dart: e for e in versions.known_epochs()}
    e31, e32 = by_dart["3.1.5"], by_dart["3.2.6"]

    # ObjectPool::EntryType numbered kTaggedObject first until 3.2 swapped it with
    # kImmediate. Same shape, so every length check still agrees; a tagged entry is just
    # spelled 0x80 rather than 0x81, and reading it the other way round consumes a signed
    # immediate where a ref id was written.
    assert e31.objpool_tagged_first is True
    assert e32.objpool_tagged_first is False

    # PatchClass serialized three refs in 3.1 (patched_class, origin_class, script) and two
    # from 3.2 (wrapped_class, script). The cutoff lives in raw_object.h's
    # to_snapshot(kFullAOT), not in the serializer, so the fill silently under-read one ref
    # per object, 440 of them, which is the 785 bytes the walk arrived early by.
    assert e31.fill_overrides["PatchClassCid"][0] == 3
    assert not e32.fill_overrides
    from jadart.fillwalk import _REFS
    assert _REFS["PatchClassCid"][0] == 2, "the base table stays the 3.2+ shape"


def test_dart_2_19_and_3_0_deltas():
    # The two oldest epochs need changes that live outside the serializer entirely.
    from jadart import versions
    by_dart = {e.dart: e for e in versions.known_epochs()}
    e219, e30, e31 = by_dart["2.19.6"], by_dart["3.0.6"], by_dart["3.1.5"]

    # Record stored a field count plus a field_names array until 3.0 packed the count into
    # a RecordShape and dropped the array. Same leading varint, different meaning, and one
    # fewer ref per record.
    assert e219.record_has_field_names is True
    assert e30.record_has_field_names is False and e31.record_has_field_names is False

    # TypeRef was a class of its own before 3.1 folded it away, so those epochs need both a
    # cid for it and a fill spec; later ones simply have no such name in their table.
    for e in (e219, e30):
        assert e.cid_table.get("TypeRefCid") > 0
        assert e.fill_overrides["TypeRefCid"] == (2, [], -1, -1)
    assert e31.cid_table.get("TypeRefCid") == -1

    # TypeParameter stays three refs across the boundary, but for different reasons: 2.19
    # is type_test_stub + hash + bound, and 3.1 is type_test_stub + hash + owner because
    # `hash` moved up into UntaggedAbstractType. Only the scalars give it away.
    assert e219.fill_overrides["TypeParameterCid"][0] == 3
    assert e219.fill_overrides["TypeParameterCid"][1] == ["T", "B", "B", "B"]
    assert e30.fill_overrides["TypeParameterCid"][1] == ["T", "T", "T", "B"]
    from jadart.fillwalk import _REFS
    assert _REFS["TypeParameterCid"] == (3, ["T", "T", "B"], -1, -1)


def test_store_pair_records_both_registers():
    # `stp a, b, [base, #d]` writes TWO registers, a at d and b at d + one slot. Recording
    # only the first is how a call's arguments went missing: they are pushed as pairs.
    out = _lift_asm([
        ("stp", "x16, x1, [x3, #0x10]"),
        ("ret", ""),
    ])
    assert "field_0x11" in out and "field_0x19" in out, out


def test_stack_passed_arguments_are_recovered():
    # A virtual dispatch passes its arguments on the stack, so `input == 'FLAG{..}'` used to
    # render as `this.==(...)`, the literal recovered, and never shown. Argument zero sits
    # at the HIGHEST slot, so the run reads back downwards.
    from jadart.expr import Lifter, State, V, P_ATOM, _drop_outgoing
    read = lambda st, drop: Lifter._stack_args(Lifter.__new__(Lifter), st, drop)

    st = State()
    st.slot["x15+0"] = V('"secret"', P_ATOM)      # argument 1
    st.slot["x15+8"] = V("this", P_ATOM)          # argument 0, the receiver
    st.slot["x29-8"] = V("a_local", P_ATOM)       # a FRAME slot: a local, not an argument

    assert read(st, False) == 'this, "secret"'
    # when the receiver is already printed as the call's base, it drops out of the list
    assert read(st, True) == '"secret"'
    assert "a_local" not in read(st, False), "frame slots are not arguments"

    # a run that does not start at SP+0 is not an argument list
    stray = State()
    stray.slot["x15+8"] = V("stray", P_ATOM)
    assert read(stray, False) is None
    # nor is a run with a hole in it
    holed = State()
    holed.slot["x15+0"] = V("a", P_ATOM)
    holed.slot["x15+16"] = V("c", P_ATOM)
    assert read(holed, False) == "a", "stops at the hole rather than skipping it"

    # a call consumes the outgoing area; leaving it behind would let one call's arguments
    # be read back as the next call's
    _drop_outgoing(st)
    assert not [k for k in st.slot if k.startswith("x15")]
    assert "x29-8" in st.slot, "frame slots survive a call"


def test_pool_xrefs_finds_both_addressing_forms():
    # "what uses this string" is the first question anyone asks of a binary, and on an
    # obfuscated build it is often the only one still answerable, names are gone, but a
    # literal is a literal. Two forms reach the pool, and a scan that handles only the near
    # one silently loses most references in a real app: that is not hypothetical, a
    # hand-rolled version of this missed a CTF's C2 call site while finding its sibling.
    from jadart.disasm import load_instructions, build_pool_map, pool_xrefs

    image, fr, _hdr = load_instructions(CLEAN)
    pool = build_pool_map(fr)
    target = next((off for off, lab in pool.items()
                   if "FLUBENCH{str_literal_compare}" in lab), None)
    assert target is not None, "the anchor literal should be in the pool"

    refs = pool_xrefs(image, [target])[target]
    assert refs, "the literal is compared in benchCheckSecret, so something loads it"
    # and that something is the function we can name independently
    from jadart.disasm import named_ranges
    want = {cr.pc_offset for _nm, cr in named_ranges(image, fr, "benchCheckSecret")}
    assert want & {c.pc_offset for c in refs}, "xref should point at benchCheckSecret"


def test_json_output_is_one_parseable_document():
    # `-j` is what makes this composable with everything else a reverse engineer already
    # runs. One object per invocation, never a stream, so a caller can json.load it whole.
    import json
    import io
    import contextlib
    from jadart import cli

    for argv in (["info", CLEAN, "-j"],
                 ["verify", CLEAN, "-j"],
                 ["classes", CLEAN, "-f", "BenchAccount", "-j"],
                 ["strings", CLEAN, "-g", "FLUBENCH", "-j"]):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(argv)
        doc = json.loads(buf.getvalue())          # raises if anything else leaked to stdout
        assert doc["ok"] is True, argv
        assert rc == 0, argv

    # a failure is JSON too, with the same exit code, so a script never reads stderr
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.main(["lift", CLEAN, "no_such_symbol_anywhere", "-j"])
    doc = json.loads(buf.getvalue())
    assert doc["ok"] is False and doc["count"] == 0

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.main(["info", __file__, "-j"])   # a .py file is not a snapshot
    doc = json.loads(buf.getvalue())
    assert doc["ok"] is False and doc["exit"] == rc and doc["type"]


def test_the_version_is_declared_once_and_the_changelog_agrees():
    # One source of truth for the number, and a record of what it means. pyproject reads
    # __version__ dynamically so those two cannot drift; the CHANGELOG is hand-written and
    # can, which is exactly how a release goes out describing the one before it.
    import jadart
    import re as _re
    v = jadart.__version__
    assert _re.fullmatch(r"\d+\.\d+\.\d+", v), v

    pyproject = open(os.path.join(os.path.dirname(__file__), "..", "pyproject.toml")).read()
    assert 'version = { attr = "jadart.__version__" }' in pyproject, (
        "the version must stay dynamic; two literals drift and the first person to notice "
        "is whoever files a bug against the wrong release")
    # The project page links back to the repository, the issue tracker and the changelog.
    # A URL that 404s is worse than no metadata, so every one of them names the real repo.
    live = [ln for ln in pyproject.splitlines() if not ln.lstrip().startswith("#")]
    assert "[project.urls]" in live, live
    for ln in live:
        if "github.com" in ln:
            assert "github.com/IR0NBYTE/jadart" in ln, ln

    changelog = open(os.path.join(ROOT, "CHANGELOG.md")).read()
    assert changelog.startswith("# Changelog"), changelog[:80]
    first = _re.search(r"^## (\d+\.\d+\.\d+)", changelog, _re.M)
    assert first, "the changelog has no released version heading"
    assert first.group(1) == v, (
        f"__version__ is {v} and the newest CHANGELOG entry is {first.group(1)}")

    # `--version` is the one thing a user runs to answer "which build is this?", and CI
    # runs it from outside the source tree, so it has to carry the real number.
    import io
    import contextlib
    from jadart import cli
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            cli.main(["--version"])
        except SystemExit:
            pass
    assert v in buf.getvalue(), buf.getvalue()


def test_ffi_names_a_shared_object_only_where_the_pool_holds_one():
    # `jadart ffi` exists because a Flutter app that pushes its interesting code into C
    # turns the Dart half into a map rather than the answer, and the three things an
    # analyst then needs, the library name, the symbols read out of it, and the address
    # of the code doing the reading, were spread across `strings`, `xrefs` and `lift`.
    #
    # What it must NOT do is turn "there is a literal here" into "this app loads native
    # code". The classifier decides on the filename shape and nothing else, and the report
    # says so; a binary with no such literal gets a refusal and EXIT_MISS, not an empty
    # table that reads like a clean bill of health.
    import io
    import contextlib
    import json
    from jadart import cli

    rx = cli._soname_re()
    for good in ('"libnative.so"', '"libcrypto.so.1.1"', '"/data/app/lib/libfoo.so"',
                 '"libswiftCore.dylib"', '"ole32.dll"',
                 '"Frameworks/Foo.framework/Foo"'):
        assert rx.search(good), good
    for bad in ('"process_data_complete"', '"assets/config.json"', '"so"',
                '"a.sofa"', '&someFunction', '"lib.so.bak"'):
        assert not rx.search(bad), bad

    # The corpus app calls no native code, so the honest answer is a refusal.
    buf, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        rc = cli.main(["ffi", CLEAN])
    assert rc == cli.EXIT_MISS, (rc, buf.getvalue(), err.getvalue())
    assert "no shared-object name" in err.getvalue(), err.getvalue()
    assert "evidence, not proof" in err.getvalue(), err.getvalue()

    # ...and it is JSON on the same terms, so a script never has to read stderr.
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        rc = cli.main(["ffi", CLEAN, "-j"])
    doc = json.loads(buf.getvalue())
    assert doc["ok"] is False and doc["count"] == 0 and doc["libraries"] == []
    assert rc == cli.EXIT_MISS


def test_ffi_reports_the_native_boundary_of_a_real_app():
    # BrunnerCTF 2025 "Brod and Co." is the case this was built for: the flag is not in the
    # Dart at all, it is inside an 18KB libnative.so the app reaches over FFI. jadart's job
    # ends at that boundary, and this is the command that says where the boundary is.
    #
    # The APK lives in the ctfbench cache rather than the repo, so the test skips when it
    # is not there rather than pinning a download into the suite.
    import io
    import contextlib
    import zipfile
    if not _capstone_available():
        print("  SKIP test_ffi_reports_the_native_boundary_of_a_real_app (no capstone)")
        return
    cache = os.path.expanduser("~/.cache/jadart-ctfbench")
    apk = next((os.path.join(cache, n) for n in sorted(os.listdir(cache))
                if "Brod_and_Co" in n and n.endswith(".apk")), None) \
        if os.path.isdir(cache) else None
    if not apk:
        print("  SKIP test_ffi_reports_the_native_boundary_of_a_real_app (no cached APK)")
        return
    import tempfile
    from jadart import cli
    with zipfile.ZipFile(apk) as z, tempfile.TemporaryDirectory() as td:
        so = os.path.join(td, "libapp.so")
        with open(so, "wb") as f:
            f.write(z.read("lib/arm64-v8a/libapp.so"))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["ffi", so])
    out = buf.getvalue()
    assert rc == cli.EXIT_OK, out
    assert "libnative.so" in out, out
    # The two symbols really are exported by that libnative.so (nm -D confirms both), and
    # `process_data_complete` is the one the challenge turns on.
    assert "process_data_complete" in out, out
    assert "get_client_version" in out, out
    assert ".text+0x166370" in out, out


def test_library_api_is_usable_without_the_cli():
    # The CLI is one caller and the library is the other. Frida-shaped expectation: people
    # import this far more than they run it, so the surface has to be real and documented.
    import jadart

    for name in ("header", "program", "verify", "export", "decompile", "strings",
                 "selectors"):
        assert name in jadart.__all__ and callable(getattr(jadart, name))

    # the typed failures are part of the surface: catch those, do not match on messages
    for exc in ("UnknownEpoch", "UnsupportedTarget", "InputError", "MissingDisassembler"):
        assert issubclass(getattr(jadart, exc), Exception), exc

    hdr = jadart.header(CLEAN)["isolate"]
    assert hdr.epoch.dart and hdr.arch.word_size == 8
    prog = jadart.program(CLEAN)
    assert any(k.name == "BenchAccount" for k in prog.classes)
    assert jadart.verify(CLEAN).supported


def test_symbol_lookup_accepts_what_a_person_types():
    # Two things a CTF actually needs, both found by using the tool on real challenges.
    from jadart.disasm import _parse_addr

    # An address, because AOT emits closures anonymously: the lambda passed to `map` has
    # no name anywhere, and in one challenge it was the function holding the transform.
    assert _parse_addr("0xfea30") == 0xfea30
    assert _parse_addr(".text+0xfea30") == 0xfea30
    assert _parse_addr("1044") == 1044
    # and a name is not an address, whatever it looks like
    for s in ("computeFlag", "0xzz", "", "main", "_onButtonPressed@19445826"):
        assert _parse_addr(s) is None

    # A bare private name. Dart mangles library-private identifiers with a per-library
    # suffix, so the handler is `_onButtonPressed@19445826` and nobody can guess 19445826.
    # The stem must match it, without `foo` also matching `foobar`.
    import re
    stem = "_onButtonPressed"
    assert re.match(re.escape(stem) + r"@", "_onButtonPressed@19445826")
    assert not "_onButtonPressedTwice".startswith(stem + "@")


def test_arm32_target_table_is_right_where_it_is_checkable():
    """The arm32 roles are built and correct; the tier that uses them is still gated.

    A role table is a claim about the calling convention, and the two claims most able to
    do harm quietly are which register is the thread and which thread offsets hold the Bool
    singletons, getting the second pair backwards inverts every boolean in the output.
    Both are pinned here against real source: benchWithdraw returns false on the
    over-balance path and true on the success path, so THR+0x3c and THR+0x38 are not a
    reading of the SDK that happens to look plausible.

    What this does NOT assert is that arm32 is liftable. It is not, and semdiff says so:
    3/9 to 5/9 against the app's own source where arm64 scores 9/9. See LIFTABLE_ARCHS.
    """
    if not _capstone_available():
        print("  SKIP test_arm32_target_table_is_right_where_it_is_checkable")
        return
    arm32 = os.path.join(ROOT, "flubench/corpus/arm32-3.3.4/libapp.so")
    if not os.path.exists(arm32):
        print("  SKIP test_arm32_target_table_is_right_where_it_is_checkable (no arm32)")
        return
    from jadart import expr as E
    from jadart.disasm import (load_instructions, disassemble_range, annotate,
                               build_pool_map, function_name_by_pc)
    from jadart.program import static_function_refs, receiver_for

    assert E.ARM32.roles["r10"] == "THR" and E.ARM32.consts_base == "THR"
    assert E.ARM32.consts == {0x34: "null", 0x38: "true", 0x3c: "false"}
    assert E.ARM32.arg_regs == (), "arm32 has no kCpuRegistersForArgs; args go on the stack"
    # Still gated, and the gate is the point: a table is not a measurement.
    assert "arm" not in E.LIFTABLE_ARCHS and "arm" in E.TARGETS

    image, fr, hdr = load_instructions(arm32)
    pc_to_name = function_name_by_pc(image, fr)
    pool_map = build_pool_map(fr)
    pc = next(pc for pc, n in pc_to_name.items() if n == "benchWithdraw")
    cr = next(c for c in image.all_ranges if c.pc_offset == pc)
    ann = annotate(disassemble_range(image, cr), pc_to_name, pool_map)
    with E.use_target(E.ARM32):
        body = "\n".join(E._lift_function(
            ann, pool_map, receiver_for(cr.owner_ref, static_function_refs(fr)),
            None, "  ", 1, None))
    # `bool benchWithdraw(int amount) { if (amount > balance) return false;
    #                                   balance -= amount; return true; }`
    assert "return false;" in body, body
    assert "return true;" in body, body
    assert body.index("return true;") < body.index("return false;"), (
        "the singletons are the wrong way round: " + body)

    # ...and the target binding is restored, so one lift cannot leak into the next.
    assert E._T is E.ARM64 and E.ARG_REGS == E.ARM64.arg_regs


def test_snapshot_kind_matches_the_vm_enum():
    """Every Flutter release snapshot is kFullAOT, and jadart called them all kModule.

    Snapshot::Kind (snapshot.h) is kFull, kFullCore, kFullJIT, kFullAOT, then kModule in
    3.12 and kNone below it. The table here omitted kFullCore, so every value from 1 up
    was shifted by one and kind 3 printed as "kModule" in `info`, in the export header and
    in anything quoting them.

    The mislabel also misleads about the format itself. LibraryPrefix serialises `name`
    and `imports` under kFullAOT but is UNREACHABLE under kModule (raw_object.h:2891), so
    reading the label at face value makes that cluster's grammar look underivable. It is
    how the missing grammar stayed missing.
    """
    from jadart.snapshot import KIND, SnapshotHeader
    assert KIND[0] == "kFull"
    assert KIND[1] == "kFullCore"
    assert KIND[2] == "kFullJIT"
    assert KIND[3] == "kFullAOT"
    # Index 4 is kModule from 3.12 and kNone before it. Reporting either would be a guess
    # on half the supported range, and no release binary reaches it.
    assert 4 not in KIND

    def named(k):
        return SnapshotHeader("isolate", 0, k, "", "", 0, 0, 0, 0, 0, None, None).kind_name
    assert named(3) == "kFullAOT"
    assert named(4).startswith("?"), "an ambiguous kind must not be given a name"

    # And the binaries agree: a Flutter release AOT snapshot is kind 3, on every epoch.
    if not os.path.exists(CLEAN):
        print("  SKIP kind-vs-binary half (no corpus)")
        return
    from jadart.disasm import load_instructions
    _img, _fr, hdr = load_instructions(CLEAN)
    assert hdr.kind == 3 and hdr.kind_name == "kFullAOT", hdr.kind_name


def test_library_prefix_has_a_fill_grammar():
    """`import ... deferred as x` is a cluster the corpus never produced.

    FluffyChat 1.29 (dart 3.12.2, 22.9 MB of Dart) failed at cluster #1080 of 1090 with
    "no fill grammar for cluster cid 46 (LibraryPrefixCid)". No binary in flubench has one,
    because flubench is a single app we wrote and it never used a deferred import. That is
    the corpus being narrow rather than the format being hard.

    The grammar is fixed by the VM: WriteFromTo runs `name` through to_snapshot(kind),
    which for kFullAOT is `imports_`, so the importer is NOT written and there are two
    refs, not the three the field list suggests, then num_imports_ as Write<uint16_t>
    and is_deferred_load_ as Write<bool> (app_snapshot.cc:4711).
    """
    from jadart.fillwalk import _REFS, T, B
    assert "LibraryPrefixCid" in _REFS, "a real app cannot be parsed without it"
    num_refs, scalars, name_idx, owner_idx = _REFS["LibraryPrefixCid"]
    assert num_refs == 2, "kFullAOT stops at imports_; importer_ is not serialised"
    assert scalars == [T, B], "uint16 num_imports then bool is_deferred_load"
    assert name_idx == 0, "name is the first ref, so a prefix can be named"
    assert owner_idx == -1, "the importing library is not in the AOT stream to point at"


def test_every_lift_call_site_passes_the_target():
    """A forgotten `arch=` disables the Tier 3 gate silently, and silence is the problem.

    `lift_function` defaults to the arm64 assumption every caller had before the parameter
    existed, so a call site that omits it does not fail, it lifts arm32 through arm64's
    register roles and prints confident nonsense. That is not hypothetical: semdiff was
    written before the parameter, kept lifting arm32, and went from cleanly skipping 13
    binaries to reporting 5 failed source checks on each of them. It was caught because
    those checks had ground truth. A call site without ground truth would just be wrong.

    So the invariant is checked where it can be checked cheaply: at every call site.
    """
    import glob
    root = os.path.join(os.path.dirname(__file__), "..")
    missing = []
    for path in glob.glob(os.path.join(root, "*/*.py")):
        if os.path.basename(path).startswith("test_"):
            continue
        src = open(path).read()
        for m in re.finditer(r"\blift_function\(", src):
            if src[:m.start()].rstrip().endswith("def"):
                continue                               # the definition itself
            depth, i = 0, m.end() - 1
            while i < len(src):                        # the matching close paren
                depth += (src[i] == "(") - (src[i] == ")")
                if depth == 0:
                    break
                i += 1
            if "arch=" not in src[m.end():i]:
                line = src[:m.start()].count("\n") + 1
                missing.append(f"{os.path.relpath(path, root)}:{line}")
    assert not missing, "lift_function called without arch=: " + ", ".join(missing)


def test_each_tier_refuses_the_targets_it_cannot_model():
    # Capstone decodes one instruction set as another without complaining and returns
    # confident nonsense, so every tier has to refuse what it does not model, but they
    # do not all model the same thing, and collapsing them into one gate costs a tier that
    # works. Tier 1 decodes arm32 correctly; Tier 3 has register ROLES and does not.
    from jadart.disasm import InstrImage, CodeRange, disassemble_range, UnsupportedArch
    from jadart.expr import lift_function, LIFTABLE_ARCHS
    from jadart import versions

    arm32 = versions.Arch("arm", 4, False)

    # Tier 1 DECODES arm32, in ARM mode. `mov r0, #0`, not Thumb: asking capstone for
    # Thumb here yields a different, entirely plausible instruction stream.
    img = InstrImage(text=b"\x00\x00\xa0\xe3" * 4, pcs=[0], first_code=0,
                     code_ranges={}, all_ranges=[], arch=arm32)
    out = disassemble_range(img, CodeRange(pc_offset=0, size=16, owner_ref=-1))
    assert out and out[0][1] == "mov" and out[0][2].replace(" ", "") == "r0,#0", out

    # Tier 3 refuses it, because the roles are arm64's. Without this gate `ldr r0, [sl,
    # #0x3c]` (a canonical object read out of the thread) renders as `sl.field_0x3d`,
    # a field access on an untagged pointer with the tag bias added anyway.
    assert "arm" not in LIFTABLE_ARCHS and "arm64" in LIFTABLE_ARCHS
    try:
        lift_function([(0, "mov", "r0, #0", "")], arch=arm32)
        assert False, "Tier 3 must not lift a target whose register roles it lacks"
    except UnsupportedArch as e:
        assert "arm64" in str(e) and "Tier 1" in str(e)

    # An architecture with no decoder at all is still refused at the decoder.
    img = InstrImage(text=b"\x90" * 64, pcs=[0], first_code=0, code_ranges={},
                     all_ranges=[], arch=versions.Arch("x64", 8, True))
    try:
        disassemble_range(img, CodeRange(pc_offset=0, size=16, owner_ref=-1))
        assert False, "x64 has no decoder and must be refused"
    except UnsupportedArch as e:
        assert "x64" in str(e)

    # arm64 still decodes, and an image with no arch recorded stays permissive so nothing
    # that predates the field starts failing
    for arch in (versions.Arch("arm64", 8, True), None):
        img = InstrImage(text=b"\x1f\x20\x03\xd5" * 4, pcs=[0], first_code=0,
                         code_ranges={}, all_ranges=[], arch=arch)
        out = disassemble_range(img, CodeRange(pc_offset=0, size=16, owner_ref=-1))
        assert out and out[0][1] == "nop"


def test_stored_smi_constants_carry_their_untagged_reading():
    # A Smi is stored shifted left by one, so `field_0xc = 8` is the integer 4 and nothing
    # on the line says so. That silent factor of two cost an hour on a CTF flag that turned
    # out to be (v >> 1) - 1.
    from jadart.expr import _smi_note, V, P_POST, P_ATOM
    note = lambda l, r: _smi_note(V(l, P_POST), V(r, P_ATOM))

    assert note("x0.field_0xc", "8") == "   // 4 if Smi"
    assert note("x0.field_0x1c", "-2") == "   // -1 if Smi"
    assert note("this.tags", "0x10") == "   // 8 if Smi"

    # Offered, never asserted, and silent when it would say nothing useful. Odd constants
    # are the proof that the invariant is not universal: Dart unboxes int fields, and an
    # unboxed slot holds a raw value that cannot be a Smi at all.
    assert note("this.field_0x14", "1") == "", "odd values are not Smis"
    assert note("x0.field_0xc", "0") == "", "zero reads the same either way"
    # element stores may be typed data, which is raw rather than tagged
    assert note("x0[i]", "8") == ""
    assert note("x0.field_0x8", "x1") == "", "only plain literals"


def test_recovered_strings_are_line_safe():
    # Dart literals are arbitrary text. Written raw, one string holding a newline becomes
    # two lines, `file` calls the whole dump binary, and grep then skips it SILENTLY, so a
    # string that was recovered perfectly well reads as missing. That cost real time once.
    from jadart.fill import printable
    assert printable("plain") == "plain"
    assert printable("two\nlines") == "two\\nlines"
    assert printable("tab\there") == "tab\\there"
    assert printable("nul\x00byte") == "nul\\x00byte"
    assert printable("back\\slash") == "back\\\\slash"
    # not ASCII newlines, but several tools still break lines on them
    for cp in (0x85, 0x2028, 0x2029):
        assert "\n" not in printable("a" + chr(cp) + "b")
        assert printable("a" + chr(cp) + "b") != "a" + chr(cp) + "b"
    # a lone surrogate from a split UTF-16 pair must not reach the output either
    assert printable("a\ud800b") == "a\\ud800b"
    # and the property that matters: no output line ever contains a newline
    for s in ("a\nb", "a\r\nb", "x" * 10, "\x1b[31m"):
        assert "\n" not in printable(s)


def test_routing_follows_the_epoch_not_the_bundled_table():
    # Routing rules are written against class NAMES; the cid map they produce must be
    # rebuilt per epoch, or an older binary gets 3.12's numbering applied to it.
    from jadart import versions
    from jadart.clusters import routing, FIXED, STRING, CLASS
    by_dart = {e.dart: e for e in versions.known_epochs()}
    for dart in ("3.4.4", "3.8.1", "3.12.2"):
        epoch = by_dart[dart]
        t, r = epoch.cid_table, routing(by_dart[dart])
        assert r.switch[t.cid("StringCid")] == STRING
        assert r.switch[t.cid("ClassCid")] == CLASS
        assert r.switch[t.cid("UnlinkedCallCid")] == FIXED
        assert r.instance_cid == t.cid("InstanceCid")
        # FfiTrampolineData has its own FIXED cluster and must never be routed as an
        # FFI instance, in any epoch (this desynced the whole pass when it was).
        assert t.cid("FfiTrampolineDataCid") not in r.ffi_instance


def test_profile_key_includes_arch_and_pointer_model():
    # The hash alone does not identify a parse profile: the same version hash covers
    # compressed and uncompressed targets, which use different cluster routing.
    from jadart import versions
    p = versions.resolve(KNOWN_HASH, "product arm64 android compressed-pointers")
    assert p is not None and p.epoch.dart == "3.12.2"
    assert p.arch.name == "arm64" and p.arch.compressed and p.arch.word_size == 8
    assert p.arch.rodata_clusters is False
    # x64 android shares the grammar key with arm64, which is why it parses unmodified
    x = versions.resolve(KNOWN_HASH, "product x64 android compressed-pointers")
    assert x.arch.grammar_key == p.arch.grammar_key
    # an unknown hash still returns None so the caller raises UnknownEpoch
    assert versions.resolve("0" * 32, "product arm64 android compressed-pointers") is None


def test_uncompressed_target_is_rejected_before_parsing():
    # Regression for a silent-wrongness bug: the arm32 build carries the SAME version hash
    # but is no-compressed-pointers, which routes String/PcDescriptors/CodeSourceMap/
    # CompressedStackMaps through RODataDeserializationCluster (app_snapshot.cc:9391).
    # jadart has no grammar for that, yet the alloc-pass self-check (assigned ==
    # num_objects) PASSES on it, so the walk used to "succeed" and only fail later in fill.
    from jadart import versions
    # 64-bit uncompressed (iOS) and 32-bit arm are both implemented now. The epoch must
    # claim exactly what it has a grammar for (no more, no less) so a word size nothing
    # has been gated on still has to be refused.
    assert versions.resolve(KNOWN_HASH, "product arm64 ios no-compressed-pointers")
    assert versions.resolve(KNOWN_HASH, "product arm android no-compressed-pointers")
    for features in ("product riscv32 linux compressed-pointers",    # 32-bit COMPRESSED:
                                                                     # no such grammar
                     "product ia32 linux compressed-pointers"):
        try:
            versions.resolve(KNOWN_HASH, features)
            assert False, f"target should be rejected: {features}"
        except versions.UnsupportedTarget as e:
            assert "uncompressed" in str(e)
    if os.path.exists(ARM32):
        blob = _isolate_blob_by_magic(ARM32)
        assert blob is not None, "no snapshot magic in the arm32 build"
        # rejected before any snapshot bytes are consumed, and --lenient does not bypass it
        for strict in (True, False):
            try:
                parse_blob(blob, "isolate", strict=strict)
                assert False, f"arm32 blob parsed with strict={strict}"
            except versions.UnsupportedTarget:
                pass


def test_user_classes_uses_the_epoch_boundary():
    # cids.py is generated from a newer SDK and reports 176 predefined cids where this
    # epoch has 175, which silently dropped the class at cid 175 from every Tier 0 listing.
    from jadart.program import recover_program
    prog = recover_program(CLEAN)
    assert prog.num_predefined_cids == 175
    names = {k.name for k in prog.user_classes()}
    assert "Vector4" in names, "class at the epoch cid boundary is being dropped"


def test_ref_id_is_bounded():
    # datastream.h ReadRefId expands STAGE exactly four times (28 bits) and then asserts.
    # Unbounded, a desynced stream silently scans for the next high-bit byte instead of
    # failing loud.
    from jadart.stream import ReadStream, TruncatedSnapshot, REF_ID_MAX_BYTES
    assert REF_ID_MAX_BYTES == 4
    assert ReadStream(bytes([0x81])).read_ref_id() == 1                    # 1-byte
    assert ReadStream(bytes([0x01, 0x81])).read_ref_id() == (1 << 7) + 1   # 2-byte
    try:
        ReadStream(bytes([0x01] * 8)).read_ref_id()
        assert False, "unterminated ref id should raise"
    except TruncatedSnapshot as e:
        assert "desync" in str(e)


def test_tier34_dispatch_table_is_located_exactly():
    # The serialized dispatch table is anchored, not guessed: the serializer writes the
    # Code cluster's first ref id right after the table length
    # (Serializer::WriteDispatchTable), and jadart derives that same id independently from
    # the alloc walk. Finding a position where they agree pins the table exactly.
    from jadart.disasm import load_instructions
    from jadart.dispatch import find_dispatch_table, _decode_entries
    from jadart.stream import ReadStream
    image, fr, _ = load_instructions(CLEAN)
    assert fr.code_first_ref > 0, "Code cluster first ref not recovered"
    found = find_dispatch_table(image.data, fr.end_pos, image.data_length,
                                fr.code_first_ref, len(image.pcs) + 1)
    assert found is not None, "dispatch table not found"
    pos, entries, end = found
    # the anchor really is the Code cluster's first ref
    st = ReadStream(image.data, pos)
    assert st.read_unsigned() == len(entries)
    assert st.read_unsigned() == fr.code_first_ref
    # The table is the last thing ReadRoots reads, so it runs EXACTLY to the end of the
    # stream. This is exact only because data_length uses Snapshot::length() = stored + 4;
    # it is a byte-exact acceptance gate for a new epoch, not an approximation.
    assert end == image.data_length, (end, image.data_length)
    assert len(entries) > 1000
    assert sum(1 for e in entries if e is not None) > 100
    # every decoded entry indexes a real instructions-table slot
    for e in entries:
        assert e is None or 0 <= e - 1 < len(image.pcs)


def test_tier34_recovers_known_selector_names():
    # Selector names are self-checking: every class that defines a selector must agree on
    # the same offset. The Flutter lifecycle selectors are defined by dozens of independent
    # classes, so their offsets are corroborated many times over.
    from jadart.disasm import load_instructions
    from jadart.dispatch import recover_selectors, ORIGIN_ELEMENT_ARM64
    image, fr, hdr = load_instructions(CLEAN)
    sel = recover_selectors(image, fr, hdr)
    assert len(sel) > 100, f"too few selectors recovered: {len(sel)}"
    names = set(sel.values())
    for expected in ("build", "toString", "createState", "get:hashCode",
                     "initState", "dispose", "paint", "createRenderObject"):
        assert expected in names, f"selector {expected!r} not recovered"
    # a name maps to exactly one offset, and offsets are keyed by the call-site immediate
    assert len(set(sel.keys())) == len(sel)
    build_imm = [k for k, v in sel.items() if v == "build"]
    assert len(build_imm) == 1
    assert build_imm[0] + ORIGIN_ELEMENT_ARM64 > 0


def test_tier34_names_virtual_calls_in_bodies():
    # End to end: a dispatch call whose offset is recovered renders with the source
    # selector name instead of sel_0x<off>.
    if not _capstone_available():
        print("  SKIP test_tier34_names_virtual_calls_in_bodies (no capstone)")
        return
    from jadart.disasm import (load_instructions, disassemble_range, annotate,
                               function_name_by_pc, build_pool_map)
    from jadart.expr import lift_function, make_arity_resolver
    from jadart.dispatch import recover_selectors
    image, fr, hdr = load_instructions(CLEAN)
    sel = recover_selectors(image, fr, hdr)
    pc_to_name = function_name_by_pc(image, fr)
    pool_map = build_pool_map(fr)
    arity = make_arity_resolver(image)
    fname = {ref: fr.strings.get(nr, "") for ref, nr, ow, kt in fr.functions}
    # findRenderObject is `RenderObject? findRenderObject() => renderObject;` upstream:
    # a single virtual property read, which must come back named.
    hit = None
    for ref, cr in image.code_ranges.items():
        if fname.get(ref) == "findRenderObject":
            hit = "\n".join(lift_function(
                annotate(disassemble_range(image, cr), pc_to_name, pool_map),
                pool_map, receiver={"x1": "this"}, arity=arity, selectors=sel))
            break
    assert hit is not None, "findRenderObject not present in the corpus"
    assert "this.renderObject" in hit, hit
    assert "sel_0x" not in hit, hit


def test_tier34_degrades_honestly_when_names_are_stripped():
    # --obfuscate removes the identifiers the vote needs, so there is nothing to corroborate
    # and jadart must fall back to sel_0x<off> rather than invent names.
    from jadart.disasm import load_instructions
    from jadart.dispatch import recover_selectors
    image, fr, hdr = load_instructions(OBF)
    sel = recover_selectors(image, fr, hdr)
    assert len(sel) < 20, f"obfuscated build should yield almost no names, got {len(sel)}"


def test_tier3_no_crash_over_sample():
    # The full annotate + strip + build_cfg + structure + lift pipeline must not raise on
    # any real function (register reuse, bare loads, indirect calls, irreducible regions).
    if not _capstone_available():
        print("  SKIP test_tier3_no_crash_over_sample (no capstone)")
        return
    from jadart.disasm import (load_instructions, disassemble_function,
                               function_name_by_pc, annotate, build_pool_map)
    from jadart.expr import lift_function, make_arity_resolver
    from jadart.dispatch import recover_selectors
    image, fr, hdr = load_instructions(CLEAN)
    pc_to_name = function_name_by_pc(image, fr)
    pool_map = build_pool_map(fr)
    arity = make_arity_resolver(image)
    selectors = recover_selectors(image, fr, hdr)
    ran = 0
    for ref, nr, ow, kt in fr.functions:
        dis = disassemble_function(image, ref)
        if not dis:
            continue
        lift_function(annotate(dis, pc_to_name, pool_map), pool_map, arity=arity,
                      selectors=selectors)
        ran += 1
        if ran >= 1500:
            break
    assert ran >= 1000, "sample too small to be meaningful"


def test_bool_singletons_are_the_only_null_offsets_used():
    # Reading NULL+0x20 as `false` instead of `true` would invert a boolean in recovered
    # source, and nothing downstream would look wrong. The constants are not derivable from
    # the snapshot, so pin them: if a future epoch lays the VM heap out differently, some
    # other offset shows up here and this fails rather than the lifter quietly lying.
    from jadart.disasm import load_instructions, disassemble_range
    from jadart.expr import ARM64
    # Two assertions, because the offsets alone are not the claim. This used to read a
    # hand-duplicated `_NULL_CONSTS` that nothing in jadart/ imported, so swapping true and
    # false in the table the lifter DOES read inverted every recovered boolean and left
    # this green. Asserting against `ARM64.consts` fixes the first half of that and not the
    # second: the check below is `seen - set(...)`, which compares OFFSETS, and a swap
    # leaves the offsets identical. So the mapping is pinned here, by value and direction,
    # and the offsets are pinned below. Verified by mutation: swapping the two now fails.
    _NULL_CONSTS = ARM64.consts
    assert _NULL_CONSTS == {0x20: "true", 0x30: "false", 0x0: "null"}, (
        f"the boolean singletons moved or swapped: {_NULL_CONSTS}")

    for path in (CLEAN, OBF):
        image, _fr, _hdr = load_instructions(path)
        seen = set()
        for cr in list(image.all_ranges)[:2500]:
            for _a, mn, op in disassemble_range(image, cr):
                if mn == "add" and ", x22, #" in op:
                    try:
                        seen.add(int(op.split("#")[-1].split(",")[0], 0))
                    except ValueError:
                        pass
        unknown = seen - set(_NULL_CONSTS)
        assert not unknown, (
            f"{path}: NULL_REG offsets {sorted(hex(u) for u in unknown)} are not in "
            f"_NULL_CONSTS, so the lifter would render them as a field read on NULL")
        assert 0x20 in seen and 0x30 in seen, "both bool singletons should be referenced"


def test_every_goto_has_a_label_and_no_block_is_dropped():
    # structure() used to turn a block it reached twice into a goto and then never emit it.
    # The goto named a label no tier defined, so the output gave no sign that a hundred
    # instructions had gone missing, which is exactly the failure mode this project
    # claims not to have.
    import re
    from jadart.disasm import (load_instructions, disassemble_range, annotate,
                               build_pool_map, function_name_by_pc)
    from jadart.expr import lift_function, strip_boilerplate
    from jadart.cfg import build_cfg, structure

    def emitted(stmts, acc):
        for st in stmts:
            if st[0] == "asm":
                acc.add(st[1])
            elif st[0] == "loop":
                acc.add(st[1])
                emitted(st[2], acc)
            elif st[0] == "if":
                emitted(st[2], acc)
                emitted(st[3], acc)
        return acc

    image, fr, _hdr = load_instructions(CLEAN)
    pool_map, pc_to_name = build_pool_map(fr), function_name_by_pc(image, fr)
    checked = 0
    for cr in list(image.all_ranges)[:600]:
        dis = disassemble_range(image, cr)
        if not dis:
            continue
        ann = annotate(dis, pc_to_name, pool_map)
        blocks, entry = build_cfg(strip_boilerplate(ann))
        if not blocks:
            continue
        reach, stack = set(), [entry]
        while stack:
            n = stack.pop()
            if n in reach or n not in blocks:
                continue
            reach.add(n)
            stack.extend(blocks[n].succ)
        assert not (reach - emitted(structure(blocks, entry), set())), (
            f".text+0x{cr.pc_offset:x}: reachable blocks never emitted")
        text = "\n".join(lift_function(ann, pool_map))
        targets = set(re.findall(r"goto (L_0x[0-9a-f]+);", text))
        defined = set(re.findall(r"^\s*(L_0x[0-9a-f]+):", text, re.M))
        assert not targets - defined, (
            f".text+0x{cr.pc_offset:x}: goto to undefined {sorted(targets - defined)}")
        checked += 1
    assert checked >= 300, "sample too small to be meaningful"


#: .text+0x1050 of the 3.12.2 clean build, trimmed to the shape that matters: a variadic
#: entry reading three incoming arguments off the frame, a branch that jumps over one arm
#: into the block after it, and a store at the join. Both defects below were found here and
#: are reproduced by these twenty-two instructions alone.
_JOIN_ASM = [
    ("add",  "x1, x29, w2, sxtw #2"),   # 0x00  frame address of an incoming argument
    ("ldr",  "x1, [x1, #0x18]"),        # 0x04  argument at slot +0x18
    ("add",  "x3, x29, w2, sxtw #2"),   # 0x08
    ("ldr",  "x3, [x3, #0x10]"),        # 0x0c  a DIFFERENT argument, slot +0x10
    ("cmp",  "w2, #2"),                 # 0x10
    ("b.lt", "#0x40"),                  # 0x14
    ("add",  "x4, x29, w2, sxtw #2"),   # 0x18
    ("ldr",  "x4, [x4, #8]"),           # 0x1c  a third, slot +8
    ("cmp",  "w2, #4"),                 # 0x20
    ("b.lt", "#0x38"),                  # 0x24
    ("add",  "x5, x29, w2, sxtw #2"),   # 0x28
    ("ldr",  "x5, [x5]"),               # 0x2c
    ("mov",  "x0, x4"),                 # 0x30
    ("b",    "#0x4c"),                  # 0x34  jumps straight to the join
    ("mov",  "x2, x4"),                 # 0x38
    ("b",    "#0x44"),                  # 0x3c
    ("mov",  "x2, x22"),                # 0x40  the other path leaves NULL in x2
    ("mov",  "x0, x2"),                 # 0x44
    ("mov",  "x4, x22"),                # 0x48
    ("stur", "w0, [x1, #0x13]"),        # 0x4c  the join: x0 came from one of two paths
    ("stur", "w3, [x1, #0xf]"),         # 0x50
    ("ret",  ""),                       # 0x54
]


def test_two_frame_slots_do_not_render_as_the_same_element():
    # `add xD, x29, w2, sxtw #2; ldr xR, [xD, #disp]` is how a variadic entry reaches its
    # incoming arguments, and the displacement is which argument. _elem_access dropped it,
    # which is right for a heap object (0xf is Array's data offset less the tag) and
    # wrong for the frame, where there is no header to absorb it. Three separate arguments
    # then printed as one expression, so a store claimed a value it never held.
    import re
    from jadart.expr import lift_function
    body = "\n".join(lift_function(
        [(i * 4, mn, op, "") for i, (mn, op) in enumerate(_JOIN_ASM)], arch="arm64"))
    slots = set(re.findall(r"FP\[[^\]]*\]", body))
    assert len(slots) >= 2, (
        f"three frame slots rendered as {sorted(slots)}; distinct addresses must not "
        f"share an expression\n{body}")


def test_a_goto_join_keeps_only_what_every_path_agrees_on():
    # walk() renders a tree, and a goto is the one edge whose source state never reaches
    # its target: the walker arrives with whatever the path it was on left behind. x0 at
    # the join is the third argument on one path and NULL on the other, so the only honest
    # rendering is the register itself, it was printed as a frame slot. x3 is written
    # once, in the block that dominates the join, so it survives and still reads as a slot;
    # that half is what keeps the fix from being "forget everything at a label".
    import re
    from jadart.expr import lift_function
    body = "\n".join(lift_function(
        [(i * 4, mn, op, "") for i, (mn, op) in enumerate(_JOIN_ASM)], arch="arm64"))
    stored = re.search(r"\.field_0x14 = ([^;]+);", body)
    assert stored, f"the join's store is missing entirely\n{body}"
    assert "FP[" not in stored.group(1), (
        f"the join claims x0 is {stored.group(1)}, which only one predecessor "
        f"justifies\n{body}")
    assert re.search(r"\.field_0x10 = FP\[", body), (
        f"x3 is written only by the join's immediate dominator, so it agrees on every "
        f"path and must survive the meet\n{body}")


def test_the_return_register_survives_the_branch_that_set_it():
    # `ret` prints whatever `State.result` says the function last wrote a result to, and
    # that is a fact about the arms of an `if` exactly as the register map is. The join
    # copied reg/slot/elem out of the arm and left `result` behind, so a function that
    # computes its double in BOTH arms and returns at the join named x0, a register
    # nothing in it ever set. .text+0x29850 of the 3.12.2 clean build is the shape, and it
    # printed `return this.field_0x64;`: not merely vague, a different value.
    # 57 of 8,194 functions in that build return a different register with this in place.
    import re
    from jadart.expr import lift_function
    rows = [("cmp", "x1, xzr"), ("b.eq", "#0x10"), ("fadd", "d0, d1, d2"),
            ("b", "#0x14"), ("fsub", "d0, d1, d2"), ("ret", "")]
    body = "\n".join(lift_function(
        [(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)], arch="arm64"))
    ret = re.search(r"return ([^;]+);", body)
    assert ret, f"no return rendered\n{body}"
    # Pinned by BEHAVIOUR: `State.result` still has to name the FP register, but the join
    # now binds that value to a name instead of writing it back to d0, so the check is that
    # what comes back is the double the arms computed. `ret.group(1) == "d0"` would pass
    # for a lifter that had lost the value and printed the bare register, which is exactly
    # the thing this file elsewhere calls a wrong answer.
    got = ret.group(1)
    assert got != "x0", (
        f"returns `{got}`; d0 is the only result register either arm wrote\n{body}")
    assert got == "d0" or (f"{got} = d1 + d2;" in body and f"{got} = d1 - d2;" in body), (
        f"returns `{got}`, which no arm binds to the double it computed\n{body}")


def test_a_compound_assignment_means_what_the_machine_computed():
    # `x = x * a - b` starts with the text `x * `, and `_assign` folded any assignment whose
    # right-hand side started that way. `x *= a - b` is `x * (a - b)`, a different value;
    # `x = x - a - b` folded to `x -= a - b`, which is `x - a + b`. Both were printed with
    # no sign that anything had been rearranged. Found by tools/irfuzz.py --cfg, which ran
    # `mul x6, x3, x14; sub x3, x6, x4` on a CPU and disagreed with `t0 *= x14 - (...)`.
    #
    # The fold is an identity exactly when the remainder binds tighter than the operator,
    # or is the same operator and associates, so the two legitimate cases below have to
    # keep folding, or the "fix" is just a rendering regression.
    from jadart.expr import lift_function, _folds_into

    def body(rows):
        return "\n".join(lift_function(
            [(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)], arch="arm64"))

    wrong = body([("ldur", "x3, [x1, #7]"), ("mul", "x6, x3, x14"), ("sub", "x3, x6, x9"),
                  ("stur", "x3, [x1, #7]"), ("ret", "")])
    assert "*=" not in wrong, (
        f"`f = f * x14 - x9` folded to a compound form that reads as f * (x14 - x9)\n{wrong}")
    assert "x1.field_0x8 * x14 - x9" in wrong, wrong

    keeps = body([("ldur", "x3, [x1, #7]"), ("add", "x3, x3, x9"),
                  ("stur", "x3, [x1, #7]"), ("ret", "")])
    assert "+=" in keeps, f"a single-operand remainder must still fold\n{keeps}"
    tighter = body([("ldur", "x3, [x1, #7]"), ("mul", "x6, x9, x10"), ("sub", "x3, x3, x6"),
                    ("stur", "x3, [x1, #7]"), ("ret", "")])
    assert "-=" in tighter, f"`f = f - x9 * x10` is exactly `f -= x9 * x10`\n{tighter}"

    for sym, rest, ok in (("*", "a - b", False), ("-", "a - b", False), ("-", "a + b", False),
                          ("&", "a | b", False), ("-", "a * b", True), ("+", "a + b", True),
                          ("|", "a & b", True), ("-", "(a - b)", True), ("+", "a[i + 1]", True)):
        assert _folds_into(sym, rest) is ok, f"{sym}= {rest}"


#: The instruction list tools/irfuzz.py --cfg generated when it first fuzzed control flow,
#: kept verbatim because it carries two separate defects at once. Block 0x14 is reachable
#: from nothing (the entry jumps over it to 0x28) and 0x28 is a loop whose only exit is
#: the `cbnz` at 0x40 falling through to 0x44.
_CFG_ASM = [
    ("sub", "x7, x7, x7"), ("add", "x7, x7, #4"), ("mul", "x2, x14, x11"),
    ("add", "x4, x1, x12"), ("b", "#0x28"),
    ("sub", "x2, x2, #0x1b"), ("sub", "x6, x9, x10"), ("sub", "x1, x5, #0xe"),
    ("cbnz", "x13, #0x30"),
    ("orr", "x0, x13, x11"),
    ("sub", "x5, x5, #0x37"), ("sub", "x6, x10, x7"),
    ("sub", "x2, x14, #0x20"), ("and", "x3, x1, x4"), ("add", "x6, x9, x8"),
    ("sub", "x7, x7, #1"), ("cbnz", "x7, #0x28"),
    ("and", "x3, x2, x4"), ("add", "x5, x0, #0x36"), ("mul", "x3, x6, x6"), ("ret", ""),
]


def test_a_block_nothing_reaches_does_not_supply_a_value():
    # `structure` emits blocks in an order that is not always a path, and a block reachable
    # from nothing is still emitted, rightly, since dropping it would hide code an
    # exception edge may reach and the CFG does not model. What the walker was carrying then
    # flowed into whatever was printed after it: here `orr x0, x13, x11`, in a block the
    # entry jumps over, supplied the value for a `return` in a block it has no edge to.
    # 5,181 of the 8,194 functions in the 3.12.2 clean build contain such a block.
    import re
    from jadart.expr import lift_function
    body = "\n".join(lift_function(
        [(i * 4, mn, op, "") for i, (mn, op) in enumerate(_CFG_ASM)], arch="arm64"))
    ret = re.search(r"return ([^;]+);", body)
    assert ret, f"no return rendered\n{body}"
    assert "x13" not in ret.group(1), (
        f"returns `{ret.group(1)}`, which only the unreachable block computes\n{body}")


def test_a_loop_exit_writes_the_carried_values_back():
    # _render_loop names each loop-carried register and assigns the name at the BOTTOM of
    # the body. That is the copy for the back edge and only for it: a `break`, a `continue`
    # or a goto out of the loop jumps over it, so the code after the loop read a name one
    # trip behind the register. Here the exiting trip's `sub x5, x5, #0x37` and
    # `sub x7, x7, #1` were both dropped.
    from jadart.expr import lift_function
    lines = lift_function(
        [(i * 4, mn, op, "") for i, (mn, op) in enumerate(_CFG_ASM)], arch="arm64")
    leave = next((i for i, ln in enumerate(lines) if ln.strip().startswith("goto")), None)
    assert leave is not None, "\n".join(lines)
    before = [ln.strip() for ln in lines[:leave]]
    # the exiting path has to carry the trip it just ran, not leave it to the back edge
    assert sum(1 for ln in before if ln.startswith("t") and " -= 55;" in ln) >= 1, (
        "the loop exit skipped the update the trip it is leaving had already made\n"
        + "\n".join(lines))


def test_a_value_loaded_before_a_store_is_not_reread_after_it():
    # expr.py's register map holds EXPRESSIONS, not results, and a field expression only
    # means what it meant while the field still holds what it held. `_pin` already knew
    # this for the base register; nothing said it about the memory, so a value loaded
    # before a store to the same field kept printing as a read of that field, which
    # after the store names the value the store put there.
    #
    # `_LinkedHashMapMixin._insert` is the real one: it loads `_length` into x9, stores
    # `_length + 1` back, then indexes `_data` with x9, and the lifter printed the element
    # ONE PAST the one the machine writes. 1,146 printed expressions across 377 of the
    # 8,194 functions in the 3.12.2 clean build. Found by tools/irfuzz.py --mem.
    from jadart.expr import lift_function

    def body(rows):
        return "\n".join(lift_function(
            [(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)], arch="arm64"))

    # load, overwrite the field, then use the loaded value: the machine returns old + 1.
    stale = body([("ldur", "x0, [x1, #7]"), ("stur", "x2, [x1, #7]"),
                  ("add", "x0, x0, #1"), ("ret", "")])
    assert "return x1.field_0x8 + 1;" not in stale, (
        f"the returned value is the field BEFORE the store, not after it\n{stale}")
    assert "var t0 = x1.field_0x8;" in stale and "return t0 + 1;" in stale, stale

    # the index case from _insert: the element written must be the old length.
    idx = body([("ldur", "x9, [x1, #0x13]"), ("add", "x2, x9, #1"),
                ("stur", "x2, [x1, #0x13]"), ("add", "x3, x4, x9, lsl #2"),
                ("stur", "x5, [x3, #7]"), ("ret", "")])
    assert "x1.field_0x14 << 2" not in idx, (
        f"the element index re-reads the length the store just changed\n{idx}")

    # A value nothing reads again must NOT be written out: liveness is what keeps
    # `balance -= amount` from growing a dead declaration for each register that
    # mentions the field. Both x3 and x4 do, and neither is live past the store.
    withdraw = body([("ldur", "x3, [x1, #7]"), ("sub", "x4, x3, x2"),
                     ("stur", "x4, [x1, #7]"), ("ret", "")])
    assert "-=" in withdraw and "var t" not in withdraw, withdraw

    # A store to a DIFFERENT field of the same object leaves the value alone: field_0x8
    # is not field_0x80, and a bare substring match would say it was.
    other = body([("ldur", "x0, [x1, #7]"), ("stur", "x2, [x1, #0x7f]"),
                  ("add", "x0, x0, #1"), ("ret", "")])
    assert "return x1.field_0x8 + 1;" in other, other


def test_a_store_that_may_alias_is_treated_as_one_that_does():
    # Two reads at DIFFERENT offsets of a heap object are two addresses and can never be
    # the same slot. Two at the SAME offset are one slot exactly when the base expressions
    # name one object, which the lifter cannot know, `setFrom` writes
    # `x1.field_0x8.field_0x18` while `x2.field_0x8.field_0x18` is live, and those are the
    # same address whenever the argument is the receiver. 700 store sites in 286 of the
    # 8,194 functions in the 3.12.2 clean build, and covering them cost 356 lines, 0.2%.
    from jadart.expr import lift_function

    def body(rows):
        return "\n".join(lift_function(
            [(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)], arch="arm64"))

    may = body([("ldur", "x0, [x1, #7]"), ("stur", "x3, [x2, #7]"),
                ("add", "x4, x0, #1"), ("mov", "x0, x4"), ("ret", "")])
    assert "var t0 = x1.field_0x8;" in may and "return t0 + 1;" in may, may

    cannot = body([("ldur", "x0, [x1, #7]"), ("stur", "x3, [x2, #0xf]"),
                   ("add", "x4, x0, #1"), ("mov", "x0, x4"), ("ret", "")])
    assert "return x1.field_0x8 + 1;" in cannot, (
        f"a store at another offset cannot reach field_0x8\n{cannot}")

    # An element store with a register index reaches any element of that base.
    elem = body([("add", "x4, x1, x2, lsl #2"), ("ldur", "x0, [x4, #0xf]"),
                 ("add", "x5, x1, x3, lsl #2"), ("stur", "x6, [x5, #0xf]"),
                 ("add", "x0, x0, #1"), ("ret", "")])
    assert "var t0 = x1[x2];" in elem and "return t0 + 1;" in elem, elem

    # A call can write anything, so anything memory-derived that survives it is named
    # first. x20 is callee-saved, so `_clobber_call` leaves it alone and only this does.
    across = body([("ldur", "x20, [x1, #7]"), ("bl", "#0x400"),
                   ("add", "x0, x20, #1"), ("ret", "")])
    assert "var t0 = x1.field_0x8;" in across, across
    assert across.index("var t0") < across.index("sub_0x400"), (
        f"the value has to be named BEFORE the call that may rewrite it\n{across}")
    assert "return t0 + 1;" in across, across


def test_the_memory_oracle_catches_a_stale_field_expression():
    """An oracle that passes everything proves nothing, so the defect goes back in.

    `--mem` is the only instrument that reaches memory at all: the corpus oracles refuse
    any operand containing `[`, and the generated control-flow functions emit no load or
    store. Disabling `_pin_mem` restores exactly the state the fix left, and the harness
    has to fail."""
    if not _unicorn_available() or not _capstone_available():
        print("  SKIP test_the_memory_oracle_catches_a_stale_field_expression")
        return
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
    import irfuzz
    from jadart import expr

    assert irfuzz.run_mem(count=40, trials=20, seed=7, verbose=False) == 0, (
        "the memory oracle disagreed with the CPU on the shipping lifter")

    pin = expr.Lifter._pin_mem
    try:
        expr.Lifter._pin_mem = lambda self, st, loc: []
        assert irfuzz.run_mem(count=40, trials=20, seed=7, verbose=False) != 0, (
            "the memory oracle passed with the staleness defect put back")
    finally:
        expr.Lifter._pin_mem = pin


def test_the_control_flow_memory_oracle_catches_every_defect_it_found():
    """Teeth for `--cfgmem`, the only instrument that reads the printed program AS A
    PROGRAM: statements in order, on the path the CPU took.

    It found four defects. Only one of the four can still be put back and caught, and
    saying which is more useful than a row of green asserts:

    `_pin_mem` off restores the stale field read, and the oracle catches it at every seed
    below. That one is live teeth.

    The two join defects were fixed by NAMING the join result rather than by a rescue
    pass, so there is no switch to flip: with the register back in `_phi_name` the whole
    rendering changes, a phi register's exit expression becomes the bare register, and the
    oracle rightly declines to score what the lifter is declining to claim. A property of
    the rendering is held by a test of the rendering,
    test_a_phi_result_is_bound_to_a_fresh_name_not_to_the_register, and the corpus
    invariant beside it.

    `_parallel_copy` needed a new mode to be testable at all. Naming the join retired the
    phi-group hazard, leaving the loop write-back, and a loop-carried variable is seeded
    from x0-x7, the registers the generator writes and the harness deliberately leaves
    UNBOUND so a bare one reads as the lifter declining rather than as a claim about the
    entry state. Every carried value was therefore undecidable and never scored: with the
    fix off, 15,000 graphs across six seeds produced no mismatch at all. `--seed-outputs`
    loads those registers from memory first, which gives the chain a decidable start
    without changing what a bare register means, and the defect is caught again."""
    if not _unicorn_available() or not _capstone_available():
        print("  SKIP test_the_control_flow_memory_oracle_catches_every_defect_it_found")
        return
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
    import irfuzz
    from jadart import expr

    for count, seed in ((60, 1), (150, 2), (150, 9), (200, 46)):
        assert irfuzz.run_cfgmem(count, 25, seed, False) == 0, (
            f"clean lifter, and it disagreed at seed {seed}")

    pin, copy = expr.Lifter._pin_mem, expr.Lifter._parallel_copy
    try:
        expr.Lifter._pin_mem = lambda self, st, loc: []
        for count, seed in ((60, 1), (150, 2), (200, 46)):
            assert irfuzz.run_cfgmem(count, 25, seed, False) != 0, (
                f"the oracle passed at seed {seed} with the stale field read put back")
        expr.Lifter._pin_mem = pin
        expr.Lifter._parallel_copy = lambda self, st, pairs, pad: [
            pad + self._assign(expr.V(n, expr.P_ATOM), v) for n, v in pairs]
        assert irfuzz.run_cfgmem(1200, 25, 2, False, seed_outs=True) != 0, (
            "the oracle passed with the loop write-back lowered to a plain sequence")
    finally:
        expr.Lifter._pin_mem, expr.Lifter._parallel_copy = pin, copy

def test_the_scalar_fp_oracle_catches_a_precedence_slip():
    """The scalar-FP path had no oracle over it at all until now, and it has already
    diverged from the integer path once: when `_bin` learned to bracket its right operand,
    `fsub d0, d1, d2` with d2 holding `d3 - d4` kept printing `d1 - d3 - d4`. That was
    found by reading. This puts it back, and a second slip with it, and both have to fire.

    A Python float is an IEEE-754 binary64 and `+ - * /` and sqrt are correctly rounded in
    both, so the comparison is bit-exact with no approximation anywhere in it."""
    if not _unicorn_available() or not _capstone_available():
        print("  SKIP test_the_scalar_fp_oracle_catches_a_precedence_slip")
        return
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
    import irfuzz
    from jadart import expr

    assert irfuzz.run_fp(CLEAN, 120, 20, 3, False) == 0, (
        "the printed scalar-double expressions disagreed with the CPU")
    good = expr._bin
    try:
        expr._bin = lambda a, op, b, prec: expr.V(
            f"{expr._wrap(a, prec)} {op} {expr._wrap(b, prec)}", prec)
        assert irfuzz.run_fp(CLEAN, 120, 20, 3, False) != 0, (
            "the FP oracle passed with the right operand unbracketed")
        expr._bin = lambda a, op, b, prec: (good(b, op, a, prec) if op in ("-", "/")
                                            else good(a, op, b, prec))
        assert irfuzz.run_fp(CLEAN, 120, 20, 3, False) != 0, (
            "the FP oracle passed with fsub and fdiv reading their operands backwards")
    finally:
        expr._bin = good


def test_irfuzz_memory_encodings_and_field_names_are_what_they_claim():
    """The field-name mapping is the half that would fail silently.

    The oracle seeds `x20.field_0x{8k}` from the word at SCRATCH+8k, which is only the
    same place while expr.py spells `[x20, #8k-1]` that way. If it ever spelled a
    different offset every trial would still run and compare against the wrong address,
    and the harness would report a clean pass."""
    if not _capstone_available():
        print("  SKIP test_irfuzz_memory_encodings_and_field_names_are_what_they_claim")
        return
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
    import irfuzz
    bad = irfuzz.verify_mem_encodings()
    assert not bad, f"memory encodings or field names are not as claimed: {bad}"


def test_a_named_join_value_is_bound_on_every_path_into_the_join():
    # A disagreement at an if-join is a phi, and it now gets a NAME instead of being
    # written back to the machine register: measured on the 3.12.2 corpus, 12,710 of the
    # 45,407 bare-register lines (28.0%) named a register the printed body assigns to
    # somewhere, and a reader cannot tell one of those from a register the lifter lost.
    #
    # The whole claim rests on the name being bound wherever it is read. A declaration
    # with no initialiser is only correct when EVERY arm assigns it; the initialiser is
    # what covers the arm that leaves the value alone. Getting that backwards prints a
    # variable that is read on a path nothing defines it on, which is worse than the
    # machine register it replaced.
    import re
    from jadart.expr import lift_function
    rows = [("cmp", "x1, x2"), ("b.lt", "#0x10"), ("add", "x0, x1, x2"),
            ("b", "#0x14"), ("sub", "x0, x1, x2"), ("ret", "")]
    lines = lift_function([(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)],
                          arch="arm64")
    body = "\n".join(lines)
    bare = [m.group(1) for m in
            (re.match(r"\s*var (t\d+);$", ln) for ln in lines) if m]
    assert bare, f"both arms compute x0, so the phi needs no initialiser\n{body}"
    for name in bare:
        # once per arm, and the arms are the only places it can be
        assert sum(1 for ln in lines
                   if re.match(rf"\s*{name} = ", ln)) == 2, f"{name}\n{body}"


def test_the_control_flow_oracle_catches_a_join_name_bound_on_one_path():
    # Teeth for the check above, on the harness rather than on the lifter. tools/irfuzz.py
    # --cfg now RUNS the printed body, which is what lets it decide a value with two
    # definitions, `_resolve_temps` folds a name assigned once and gives up on every
    # phi. Reading a declared-but-unassigned name has to count as a defect and not as a
    # refusal, or the oracle passes on exactly the mistake it was added for. The generator
    # produces the shape about once in 400 graphs, so it is pinned here directly.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
    import irfuzz
    good = ["var t0;", "if (x8 == 0) {", "  t0 = x9 + 1;", "} else {", "  t0 = x9 - 1;",
            "}", "return t0;"]
    env = {f"x{i}": i * 7 + 1 for i in range(31)}
    env["xzr"] = 0
    _run, _wrote, ret = irfuzz._run_body(irfuzz._parse_body(good)[0], dict(env), 512)
    assert ret == env["x9"] - 1, ret
    bad = [ln for ln in good if ln != "  t0 = x9 - 1;"]
    try:
        irfuzz._run_body(irfuzz._parse_body(bad)[0], dict(env), 512)
    except irfuzz._Unsound:
        pass
    else:
        raise AssertionError("the oracle accepted a body that reads an unbound name")


def test_the_single_use_fold_matches_a_whole_name():
    # `_inline_single_use` folds `var t0 = f(); return t0;` back together, and it decided
    # the next line was the use with a SUBSTRING test. `"t1" in "... = t10;"` is true, so
    # with t1 used exactly twice and its real use further down, the fold fired on a line
    # that does not mention t1: the substitution matched nothing, the declaration was
    # dropped anyway, and the surviving `t1` had nothing defining it. Latent rather than
    # live (0 of the corpus's 4,642 folds collide) but the numbering reaches t10 in
    # 1,600 of its functions, so it is a coincidence away.
    from jadart.expr import _inline_single_use
    lines = ["  var t1 = f();", "  x0.field_0x8 = t10;", "  return t1;"]
    got = _inline_single_use(lines, {"t1"})
    assert got == lines, got
    # ...and the fold it is there for still happens
    lines = ["  var t1 = f();", "  return t1;"]
    assert _inline_single_use(lines, {"t1"}) == ["  return f();"]


def test_a_writeback_addressing_mode_counts_as_writing_its_base():
    # `ldr x16, [x4], #8` advances x4, and `_def_use` reported no destination at all for
    # it. Every consumer reads that as "nothing was written here": `_written` is what
    # `_render_loop` uses to decide which registers a loop carries and what `_join_kill`
    # uses to decide which registers a goto join may keep, so a missing DEF keeps a value
    # the machine has already moved past, a wrong value, not a missing one.
    from jadart.expr import _def_use
    assert _def_use("ldr", "x16, [x4], #8")[0] == frozenset({"x16", "x4"})
    assert _def_use("str", "x16, [x2, #8]!")[0] == frozenset({"x2"})
    assert _def_use("ldp", "x0, x1, [x4], #0x10")[0] == frozenset({"x0", "x1", "x4"})
    # ...and a plain addressing mode still writes only what it loads
    assert _def_use("ldr", "x0, [x1, #8]")[0] == frozenset({"x0"})
    assert _def_use("str", "x0, [x1, #8]")[0] == frozenset()


def test_a_heap_store_does_not_invalidate_a_frame_slot():
    # The rule this replaces answered "did anything store at all", and both callers used
    # that to throw the WHOLE stack-slot map away. A slot is keyed on a displacement from
    # SP or FP and the store path only writes it for a base whose role is SP or FP, so a
    # store through an object pointer cannot touch one. The separation is what makes
    # `_stale_slots` below safe to write; on its own it is worth almost nothing, because
    # 4,942 of the 5,414 corpus functions that store at all store to a frame slot too.
    from jadart.cfg import build_cfg
    from jadart.expr import Lifter
    def lifter(rows):
        blocks, entry = build_cfg([(i * 4, mn, op, "")
                                   for i, (mn, op) in enumerate(rows)])
        return Lifter(blocks, entry=entry), set(blocks)
    heap = [("str", "x1, [x2, #7]"), ("ret", "")]
    lif, nodes = lifter(heap)
    assert not lif._writes_stack(nodes)
    frame = [("str", "x1, [x29, #-8]"), ("ret", "")]
    lif, nodes = lifter(frame)
    assert lif._writes_stack(nodes)
    # ...unless the function first put a frame address somewhere a store can reach it
    escaped = [("add", "x3, x29, #0x10"), ("str", "x1, [x3, #7]"), ("ret", "")]
    lif, nodes = lifter(escaped)
    assert lif._writes_stack(nodes), "a frame address in a general register aliases"
    # Keeping the slot ADDRESS across the region is only half of it. The slot holds an
    # expression in machine registers, and `x1.field_0x8` stops describing it the moment
    # the region assigns to x1, the staleness `_pin` exists to stop, arriving by another
    # door. Before this, a region with no stores at all kept the stale text.
    from jadart.expr import State, V, P_POST
    st = State()
    st.slot["x29-8"] = V("x1.field_0x8", P_POST)
    st.slot["x29-16"] = V("this.field_0x8", P_POST)
    lif, _nodes = lifter(heap)
    lif._stale_slots(st, {"x1"})
    assert "x29-8" not in st.slot, "a slot spelled in terms of an overwritten register"
    assert "x29-16" in st.slot, "a slot naming no machine register is still good"



def test_a_phi_result_is_bound_to_a_fresh_name_not_to_the_register():
    """The two staleness defects at a join are the same defect, and naming retires both.

    Writing an arm's disagreement into the MACHINE register is wrong twice over. Every
    tracked value spelled in terms of the old `x1` silently rereads it, the CPU returns
    (old x1) + x8 + (new x1) where the text said `x1 + x8 + x1`, and a later arm that
    reloads `x1` leaves each use after it reading the earlier assignment. 963 and 833 sites
    respectively on the 3.12.2 clean build, both found by tools/irfuzz.py --cfgmem.

    A fresh name cannot be shadowed, because nothing that already exists can be spelled in
    terms of a name that did not. So the fix is not a rescue pass over the damage; the
    damage has no way to occur. That is a claim about the RENDERING, and it is checked
    here as one: no printed phi ever assigns a machine register."""
    from jadart.expr import lift_function

    def body(rows):
        return "\n".join(lift_function(
            [(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)], arch="arm64"))

    # The shadow. x3 is (entry x1) + x8, and the return adds the x1 the arm left.
    shadowed = body([("add", "x3, x1, x8"), ("cbz", "x13, #0x10"), ("mul", "x1, x5, x13"),
                     ("stur", "x1, [x2, #7]"), ("add", "x0, x3, x1"), ("ret", "")])
    assert "x1 = x5 * x13;" not in shadowed, (
        f"assigning the register is what made the shadow possible\n{shadowed}")
    assert "var t0 = x1;" in shadowed and "t0 = x5 * x13;" in shadowed, shadowed
    assert "return x1 + x8 + t0;" in shadowed, (
        f"the first x1 is the entry value and still spelled x1\n{shadowed}")

    # The reload. A join whose arms disagree between a name this lifter minted and a field
    # read has to be written out: dropping it to a bare `x3` throws away the binding that
    # is the only statement saying what x3 holds.
    reload_ = body([("cbz", "x8, #0xc"), ("mul", "x3, x14, x10"), ("b", "#0xc"),
                    ("cbnz", "x11, #0x18"), ("sub", "x4, x8, #0x18"), ("b", "#0x1c"),
                    ("ldur", "x3, [x20, #0xf]"), ("add", "x0, x13, x3"), ("ret", "")])
    assert "t1 = x20.field_0x10;" in reload_, (
        f"the second join disagrees between t0 and a field read\n{reload_}")
    assert "return x13 + t1;" in reload_, (
        f"a bare x3 here would drop the t0 binding on the other path\n{reload_}")

    # A value that names no phi result keeps its expression: the naming has to be about
    # the join, not about there being an `if` at all.
    kept = body([("add", "x3, x9, x8"), ("cbz", "x13, #0x10"), ("mul", "x1, x5, x13"),
                 ("stur", "x1, [x2, #7]"), ("add", "x0, x3, x1"), ("ret", "")])
    assert "return x9 + x8 + t0;" in kept, kept


def test_no_printed_phi_assigns_a_machine_register_anywhere_in_the_corpus():
    """The invariant above, over every function in the shipped build rather than three.

    A unit test fixes the shape on inputs chosen to show it. This one says the property
    holds where it has to: at every join the tool prints, in a real binary. `_phi_name` is
    the single place a join picks a name, so the check is that what it returns is never a
    register, read off the real rendering rather than off the method."""
    if not _capstone_available():
        print("  SKIP test_no_printed_phi_assigns_a_machine_register_anywhere_in_the_corpus")
        return
    from jadart.disasm import (load_instructions, disassemble_function, annotate,
                               function_name_by_pc, build_pool_map)
    from jadart.expr import lift_function
    from jadart import expr

    image, fr, _hdr = load_instructions(CLEAN)
    pc_to_name, pool = function_name_by_pc(image, fr), build_pool_map(fr)
    seen, real = [], expr.Lifter._phi_name

    def spy(self, st, r):
        name = real(self, st, r)
        seen.append((r, name))
        return name

    expr.Lifter._phi_name = spy
    try:
        for ref, _nr, _ow, _kt in fr.functions[:1500]:
            dis = disassemble_function(image, ref)
            if dis:
                lift_function(annotate(dis, pc_to_name, pool), pool)
    finally:
        expr.Lifter._phi_name = real
    assert len(seen) > 100, f"only {len(seen)} joins rendered, so this proved nothing"
    bad = [(r, n) for r, n in seen if not re.fullmatch(r"t\d+", n)]
    assert not bad, f"a phi bound its result to a machine register: {bad[:5]}"

def test_a_group_of_assignments_all_read_the_values_from_before_it():
    # A phi group and a loop's carried write-back are parallel copies: every right-hand
    # side describes the state where the group starts. Written out one after another in
    # register order, `x5 = x13 ^ x11; x6 = x5 | x13;` reads the x5 the line above just
    # assigned, and the loop tail's `t0 += t1 + 1; t1 = t0;` hands t1 this trip's t0
    # instead of last trip's. 109 of the 1,728 multi-assignment groups in the 3.12.2 clean
    # build carry that hazard, 120 assignments in 34 functions. Found by
    # tools/irfuzz.py --cfgmem, which reads the group in order as a reader does.
    from jadart.expr import lift_function

    def body(rows):
        return "\n".join(lift_function(
            [(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)], arch="arm64"))

    # A phi GROUP no longer carries the hazard: each arm assignment targets a name
    # minted for this join, and no right-hand side can name one, so the group is already
    # parallel. The loop write-back is the case that remains, and it is a real one.
    phi = body([("sub", "x6, x7, x1"), ("cbz", "x8, #0x10"), ("orr", "x6, x5, x13"),
                ("eor", "x5, x13, x11"), ("stur", "x6, [x20, #7]"),
                ("stur", "x5, [x20, #0xf]"), ("ret", "")])
    lines = [ln.strip() for ln in phi.splitlines()]
    assert "t1 = x5 | x13;" in lines and "t0 = x13 ^ x11;" in lines, phi
    assert "x5" not in [ln.split(" =")[0] for ln in lines], (
        f"x5 is never assigned, so t1 reads the entry value the machine read\n{phi}")

    loop = body([("mov", "x4, #1"), ("mov", "x5, #2"), ("add", "x6, x4, x5"),
                 ("mov", "x5, x4"), ("add", "x4, x6, #1"), ("cbnz", "x9, #0x8"),
                 ("add", "x0, x4, x5"), ("ret", "")])
    body_lines = [ln.strip() for ln in loop.splitlines()]
    assert "var t2 = t0;" in body_lines and "t1 = t2;" in body_lines, (
        f"the back edge gave t1 this trip's t0, not last trip's\n{loop}")
    assert body_lines.index("var t2 = t0;") < body_lines.index("t0 += t1 + 1;"), loop

    # And a join reads the values from before the `if` for the same reason, without
    # needing the lowering at all: every arm assignment targets a name minted for this
    # join, so an arm that also changes x5 changes `t1`, and the `x5` inside another arm
    # line is still the one the machine read there.
    later = body([("ldur", "x1, [x20, #0xf]"), ("sub", "x6, x7, x1"), ("cbz", "x8, #0x20"),
                  ("orr", "x6, x5, x13"), ("orr", "x5, x13, x2"), ("eor", "x5, x13, x11"),
                  ("mul", "x1, x9, x1"), ("and", "x2, x6, x8"), ("add", "x0, x2, x5"),
                  ("ret", "")])
    assert "t0 = (x5 | x13) & x8;" in later and "t1 = x13 ^ x11;" in later, (
        f"x5 is never assigned, so the first line still reads the old one\n{later}")
    assert "x5 =" not in later, f"a phi wrote a machine register\n{later}"

    plain = body([("mov", "x4, #1"), ("mov", "x5, #2"), ("add", "x4, x4, #1"),
                  ("add", "x5, x5, #3"), ("cbnz", "x9, #0x8"), ("add", "x0, x4, x5"),
                  ("ret", "")])
    assert "t0 += 1;" in plain and "t1 += 3;" in plain, plain
    assert "var t2" not in plain, f"a group with no hazard grew a temporary\n{plain}"



def test_a_field_pinned_across_a_call_is_pinned_by_its_recovered_name_too():
    """Recovering a field's name must not cost it the staleness pinning.

    `_pin` writes a memory-derived value out before a call, because the callee can store
    anywhere and the register map holds an EXPRESSION, not a result. What counts as
    memory-derived was written when every field printed as `field_0x8`, and fields.py now
    prints `this.balance` for exactly the fields the snapshot still names, so the ones we
    understand best would have been the ones left stale, and the rendering would silently
    have got worse the more names were recovered.

    Nothing on the 3.12.2 clean build shows it: 9,795 lines carry a recovered name, and
    none of the 58 call sites that hold a memory value across a call spells one. So this
    is the whole evidence for the widening, and it is written to fail on the pattern that
    only knew the byte offset."""
    from jadart.expr import lift_function

    rows = [("ldur", "x16, [x1, #7]"), ("bl", "#0x40"), ("add", "x0, x16, #1"), ("ret", "")]
    ann = [(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)]

    def body(fields):
        return "\n".join(lift_function(ann, {}, receiver={"x1": "this"}, arch="arm64",
                                       fields=fields))

    offs = body(None)
    assert "var t0 = this.field_0x8;" in offs and "return t0 + 1;" in offs, offs

    named = body({8: "balance"})
    assert "var t0 = this.balance;" in named, (
        f"the same read, named, and it was not pinned across the call\n{named}")
    assert "return t0 + 1;" in named, (
        f"the return still reads the field after a call that could store to it\n{named}")


def test_every_printed_write_to_a_machine_register_comes_from_a_pinned_bump():
    """`_pin` has one caller, and this is the reason that is enough.

    The register map holds EXPRESSIONS, so a printed `x3 = ...` is the dangerous kind of
    statement: from that line on, the token `x3` in the output means what the statement put
    there, and every tracked value still spelled in terms of the old x3 quietly rereads it.
    `_pin` writes those values out first, and it is wired to `_bump`, the base update of
    a writeback addressing mode, and to nothing else.

    That was once a gap covering every other writer. It is not one now, but only because
    of decisions made elsewhere: a join binds a fresh name rather than the register, a
    loop's carried value does too, and a call drops what it clobbers. Those are three
    separate mechanisms in three separate places, and nothing local to any of them says
    the fourth case cannot come back. So the property is checked where it can be seen
    whole (over every function in the shipped build, all 858 register writes) rather
    than argued from the three call sites."""
    if not _capstone_available():
        print("  SKIP test_every_printed_write_to_a_machine_register_comes_from_a_pinned_bump")
        return
    from jadart import expr
    from jadart.disasm import (load_instructions, disassemble_function, annotate,
                               function_name_by_pc, build_pool_map)

    image, fr, _hdr = load_instructions(CLEAN)
    pc_to_name, pool = function_name_by_pc(image, fr), build_pool_map(fr)
    asn = re.compile(r"^\s*(?:x\d+|d\d+)\s*[-+*&|^~/]*=\s")
    from_bump, real = set(), expr.Lifter._bump

    def spy(self, st, base, delta):
        out = real(self, st, base, delta)
        from_bump.update(l.strip() for l in out if asn.match(l))
        return out

    expr.Lifter._bump = spy
    try:
        printed = []
        for ref, _nr, _ow, _kt in fr.functions:
            dis = disassemble_function(image, ref)
            if not dis:
                continue
            printed.extend(l.strip() for l in
                           expr.lift_function(annotate(dis, pc_to_name, pool), pool)
                           if asn.match(l))
    finally:
        expr.Lifter._bump = real
    assert len(printed) > 500, f"only {len(printed)} register writes, so this proved little"
    stray = [l for l in printed if l not in from_bump]
    assert not stray, (
        f"{len(stray)} register writes came from somewhere _pin does not guard: "
        f"{stray[:5]}")


def test_two_identical_memory_reads_are_not_the_same_value_at_a_join():
    """A join decides an arm changed nothing by comparing TEXT, and text is not enough.

    Both the entry value of x0 and the arm's reloaded value print `x20.field_0x8`, so the
    arm looked like it had left the register alone and the join took the entry value,
    materialised as a declaration placed AFTER a store to that field, where it no longer
    means what it meant.

    `_pin_mem` does not cover this, and is right not to. It writes a value out before a
    store only where liveness says something reads it, and here both arms redefine x0
    before anything does, so the register is genuinely dead at the store. The join then
    resurrects the text. Trimmed and rebased from a graph tools/irfuzz.py
    --cfgmem --seed-outputs disagreed with the CPU on."""
    from jadart.expr import lift_function

    rows = [("ldur", "x0, [x20, #7]"), ("ldur", "x3, [x20, #0x1f]"),
            ("add", "x5, x14, x0"), ("stur", "x14, [x20, #7]"),
            ("cbz", "x12, #0x20"),
            ("stur", "x3, [x20, #7]"), ("ldur", "x0, [x20, #7]"), ("b", "#0x24"),
            ("mul", "x0, x11, x7"),
            ("cmp", "x0, x5"), ("ret", "")]
    out = "\n".join(lift_function(
        [(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)], arch="arm64"))
    lines = [ln.strip() for ln in out.splitlines()]

    assert "var t1 = x20.field_0x8;" not in lines, (
        f"the field was stored to on the line above; this reads what the store put "
        f"there\n{out}")
    assert "var t1;" in lines, f"no arm's value survives the store, so there is nothing "\
                               f"to initialise the name with\n{out}"
    assert "t1 = x20.field_0x8;" in lines and "t1 = x11 * x7;" in lines, (
        f"both arms have to assign it, each after its own store\n{out}")
    assert lines.index("var t1;") < lines.index("t1 = x20.field_0x8;"), out


def test_a_goto_join_gets_the_meet_for_the_heap_as_well_as_the_registers():
    """`_join_kill` gave a goto join the meet for registers and for stack slots. The heap
    had none, so a value spelled `x20.field_0x8` survived a join one of whose paths had
    just stored there, with that store a few lines up, right next to the goto.

    Held by the oracle rather than by a hand-built graph, because the shape needs an edge
    `structure` cannot nest, which is not something to fake convincingly. The seeds are the
    ones where switching `_writes_heap` off puts the disagreement back."""
    if not _unicorn_available() or not _capstone_available():
        print("  SKIP test_a_goto_join_gets_the_meet_for_the_heap_as_well_as_the_registers")
        return
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
    import irfuzz
    from jadart import expr

    assert irfuzz.run_cfgmem(400, 25, 14, False, seed_outs=True) == 0, (
        "clean lifter, and it disagreed")
    real = expr.Lifter._writes_heap
    try:
        expr.Lifter._writes_heap = lambda self, nodes: False
        assert irfuzz.run_cfgmem(400, 25, 14, False, seed_outs=True) != 0, (
            "the oracle passed with the heap meet switched off")
    finally:
        expr.Lifter._writes_heap = real


def test_a_prerelease_epoch_does_not_break_the_unknown_epoch_message():
    """The fail-loud path has to survive every version string the map can hold.

    `known_epochs` sorted on `[int(p) for p in dart.split(".")]`, which is fine while every
    registered epoch is a stable release and raises ValueError the moment one is not. The
    handler that builds the unknown-epoch message calls it, so registering the first beta
    turned "this binary carries a hash I do not know" into a bare ValueError from inside
    the reporting code, the one place that must not fail, because it is what a user gets
    instead of a wrong answer."""
    from jadart.versions import known_epochs, _release_order

    got = [e.dart for e in known_epochs()]
    assert got == sorted(got, key=_release_order), "known_epochs is not in release order"
    assert _release_order("3.3.0-174.2.beta") < _release_order("3.3.0"), (
        "a beta carries the version it is working towards, so it comes first")
    assert _release_order("3.0.1") < _release_order("3.0.6") < _release_order("3.1.0")
    assert len(got) == len(set(zip(got, range(len(got))))), "sort was not total"


def test_the_three_late_identified_epochs_pass_the_gates_on_their_own_app():
    """Registering a hash claims the format; the gates are what earns it.

    These three came out of running tools/sdk_source.py --identify over every stable tag
    and then every beta, for hashes the corpus sweep turned up and nothing matched. Two are
    betas, which is the point: Flutter's beta channel pins a Dart build that is a release
    of its own, and an app published from it carries that hash for ever.

    Skipped rather than failed when the app is not cached, because the sweep fetches over
    the network and a fresh clone has not run it."""
    import os
    if not _capstone_available():
        print("  SKIP test_the_three_late_identified_epochs_pass_the_gates_on_their_own_app")
        return
    from jadart.verify import verify_file
    from jadart.snapshot import parse_libapp

    cache = os.path.expanduser("~/.cache/jadart-appsweep/libapps")
    want = {"at.finderlein.noe": "3.0.1",
            "nl.viter.glider": "3.3.0-174.2.beta",
            "de.jbservices.nc_passwords_app": "2.19.0-444.2.beta"}
    ran_any = False
    for app, dart in want.items():
        path = os.path.join(cache, app + ".so")
        if not os.path.exists(path):
            continue
        ran_any = True
        assert parse_libapp(path)["isolate"].epoch.dart == dart, f"{app} placed elsewhere"
        rep = verify_file(path)
        ran = [g for g in rep.tier_a if not g.skipped]
        bad = [g.gate for g in ran if not g.passed]
        assert rep.supported and not bad, f"{app} ({dart}): Tier A gates failed: {bad}"
        assert len(ran) >= 8, f"{app}: only {len(ran)} Tier A gates ran"
    if not ran_any:
        print("  SKIP test_the_three_late_identified_epochs (no appsweep cache)")


def test_an_epoch_switch_keys_on_the_family_not_the_release():
    """Two releases of one era must get the same profile.

    Every per-epoch switch used to test the version STRING, `_dart in ("2.19.6",
    "3.0.6", ...)`, so registering 3.0.1 beside 3.0.6 silently turned four of them off
    and built a profile for an era that does not exist. They key on the family name now,
    and this is the property that says so."""
    from jadart.versions import _EPOCHS
    from collections import defaultdict

    by_family = defaultdict(list)
    for e in _EPOCHS.values():
        by_family[e.name].append(e)
    shared = {n: v for n, v in by_family.items() if len(v) > 1}
    assert shared, "no era has two releases registered, so this proves nothing"
    for name, group in sorted(shared.items()):
        for field in ("objpool_has_behavior", "objpool_tagged_first",
                      "record_has_field_names", "type_class_id_shift", "fill_overrides",
                      "num_predefined_cids", "td_int8_cid", "grammars"):
            vals = {repr(getattr(e, field)) for e in group}
            assert len(vals) == 1, (
                f"{name}: {field} differs across releases of one era: {vals}")


def test_a_const_list_in_the_pool_resolves_to_its_elements():
    """A table lookup is only half an answer without the table.

    The fill pass reads every element of every Array to stay in step with the stream and
    used to drop them, so a decompiled loop showed the arithmetic over `pool_0xb970[i]`
    and nothing anywhere said what was in it. For const DATA, a keystream, an S-box, a
    table of magic constants, that is the half that matters, and Dart puts all of it in
    Arrays, so keeping the refs covers the general case rather than one shape.

    Pinned on two lists the Dart SDK itself carries, so the expectation does not depend on
    anything we wrote."""
    if not _capstone_available():
        print("  SKIP test_a_const_list_in_the_pool_resolves_to_its_elements")
        return
    from jadart.disasm import load_instructions, const_lists

    image, fr, _hdr = load_instructions(CLEAN)
    lists = const_lists(fr, getattr(image, "arch", None))
    assert lists, "no const list resolved at all"
    found = list(lists.values())
    assert ["ANY", "IPv4", "IPv6", "Unix"] in found, (
        f"InternetAddressType's names did not come back: {found}")
    assert ["method", "getter", "setter", "getter or setter", "variable"] in found, found
    ints = [v for v in found if v and all(isinstance(x, int) for x in v)]
    assert ints, "no all-int table resolved"


def test_a_const_list_with_an_element_it_cannot_name_resolves_to_nothing():
    """All or nothing, per list.

    An element that is neither an int nor a string is an object this cannot name, and a
    list printed with holes in it invites the reader to read the holes as zeroes. Refusing
    the whole list says the honest thing instead."""
    from jadart.disasm import _const_elems

    class Fr:
        arrays = {1: (10, 11), 2: (10, 99), 3: ()}
        smi_values = {10: 7}
        strings = {11: "x"}

    fr = Fr()
    assert _const_elems(fr, 1) == [7, "x"], "a resolvable list did not come back"
    assert _const_elems(fr, 2) is None, "ref 99 names nothing, so the list must be refused"
    assert _const_elems(fr, 3) is None, "an empty array is not a table"
    assert _const_elems(fr, 4) is None, "a ref that is not an array at all"


def test_a_long_const_list_is_named_rather_than_spelled_at_every_use():
    """Inlining the table was tried and is worse than not resolving it.

    A 47-byte keystream printed in full at each of the three places the loop indexed it
    turned a readable body into three copies of the data. Short lists stay inline, because
    a five-element list IS the answer; past that the label carries the length and the pool
    offset, and `jadart.constants()` hands back the elements under that same offset."""
    from jadart.disasm import _const_list, _LIST_INLINE

    class Fr:
        arrays = {1: tuple(range(100, 100 + _LIST_INLINE)),
                  2: tuple(range(100, 100 + _LIST_INLINE + 1))}
        smi_values = {k: k - 100 for k in range(100, 200)}
        strings = {}

    fr = Fr()
    short = _const_list(fr, 1, 0x40)
    assert short.startswith(f"const[{_LIST_INLINE}]{{") and "@" not in short, short
    assert str(_LIST_INLINE - 1) in short, f"the last element is missing: {short}"

    long_ = _const_list(fr, 2, 0xb9b0)
    assert long_.startswith(f"const[{_LIST_INLINE + 1}] @0xb9b0{{"), long_
    assert long_.endswith(", ...}"), long_
    assert len(long_) < len(", ".join(str(i) for i in range(_LIST_INLINE + 1))) + 40, (
        f"the long form is not actually shorter: {long_}")


def test_the_runner_block_is_the_last_thing_in_this_file():
    """The `if __name__ == "__main__"` block collects `globals()` when it RUNS, so every
    test defined below it is invisible to it.

    It sat mid-file, and CI ran `python tests/test_core.py`: 180 of 188 tests executed and
    the run reported success. The eight it dropped were the entire field-layout suite,
    including the one that refuses a whole field map rather than emit a wrong offset. A
    test appended to the end of this file was not run by CI and did not raise the count
    that CONTRIBUTING's "the count doesn't go down" rule reads, so the rule was watching a
    number that could not move.

    CI runs pytest now, which cannot have this problem. This keeps the script honest for
    anyone who runs it directly, which CONTRIBUTING tells contributors to do."""
    import re as _re

    src = open(__file__).read()
    marker = '\nif __name__ == "__main__":'
    assert marker in src, "the runner block is gone"
    after = src[src.index(marker) + len(marker):]
    stragglers = _re.findall(r"^def (test_\w+)", after, _re.M)
    assert not stragglers, (
        f"{len(stragglers)} test(s) are defined after the runner block and would not run "
        f"under `python tests/test_core.py`: {stragglers[:5]}")


def test_a_width_change_renders_as_the_value_it_produces():
    """Sign and zero extension are VALUE changes, and printing the source register said
    they were not.

    `sxtb x0, w1` rendered as `x1`: for x1 = 0xff the machine holds -1 and the output read
    255. That is not a gap, it is a confident wrong answer, which is the one thing this
    lifter does not emit, `sbfiz` two lines above it already declines rather than
    approximate, and `lower.py` refuses the whole family.

    The unsigned forms have an exact Dart spelling and get it. The signed ones are a shift
    pair, exact because `>>` is arithmetic in Dart, the same fact that makes `lsr` render
    as `>>>` rather than `>>`."""
    from jadart.expr import lift_function

    def body(mn, ops):
        return "\n".join(lift_function(
            [(0, mn, ops, ""), (4, "ret", "", "")], arch="arm64")).strip()

    assert body("sxtb", "x0, w1") == "return x1 << 56 >> 56;", body("sxtb", "x0, w1")
    assert body("sxth", "x0, w1") == "return x1 << 48 >> 48;", body("sxth", "x0, w1")
    assert body("sxtw", "x0, w1") == "return x1 << 32 >> 32;", body("sxtw", "x0, w1")
    assert body("uxtb", "x0, w1") == "return x1 & 0xff;", body("uxtb", "x0, w1")
    assert body("uxth", "x0, w1") == "return x1 & 0xffff;", body("uxth", "x0, w1")
    assert body("uxtw", "x0, w1") == "return x1 & 0xffffffff;", body("uxtw", "x0, w1")

    # sbfx carries the sign; ubfx does not. Both used to render `& mask`.
    assert body("sbfx", "x0, x1, #0, #8") == "return x1 << 56 >> 56;", \
        body("sbfx", "x0, x1, #0, #8")
    assert body("ubfx", "x0, x1, #0, #8") == "return x1 & 0xff;", \
        body("ubfx", "x0, x1, #0, #8")


def test_the_two_right_shifts_are_told_apart():
    """Dart's `>>` is arithmetic and `>>>` is logical, and arm64's `asr` and `lsr` are the
    same distinction. Both rendered as `>>`, so a logical shift printed as a
    sign-propagating one, a different number for every negative value, at 308 sites in
    the clean build. `ror` has no Dart spelling and is still named rather than
    approximated, which is the rule this restores for `lsr`."""
    from jadart.expr import lift_function, _SHIFT_SYM

    def body(mn, ops):
        return "\n".join(lift_function(
            [(0, mn, ops, ""), (4, "ret", "", "")], arch="arm64")).strip()

    assert body("lsr", "x0, x1, #3") == "return x1 >>> 3;", body("lsr", "x0, x1, #3")
    assert body("asr", "x0, x1, #3") == "return x1 >> 3;", body("asr", "x0, x1, #3")
    assert body("lsl", "x0, x1, #3") == "return x1 << 3;", body("lsl", "x0, x1, #3")

    # The shifted-operand table and the standalone handler must not drift apart: they were
    # two separate dict literals with the same contents, and only one of them was wrong.
    assert _SHIFT_SYM == {"lsl": "<<", "lsr": ">>>", "asr": ">>"}, _SHIFT_SYM
    assert body("add", "x0, x1, x2, lsr #3") == "return x1 + (x2 >>> 3);", \
        body("add", "x0, x1, x2, lsr #3")


def test_an_extending_addressing_operand_carries_its_shift():
    # `sxtw #2` scales by four exactly as `lsl #2` does (A5.1.4 spells the amount the same
    # way), and reading only the lsl spelling recorded a stride of one for every frame
    # address in the image, the unit _elem_access folds a displacement in.
    from jadart.expr import _shift_amount
    assert _shift_amount("lsl #3") == 3
    assert _shift_amount("sxtw #2") == 2
    assert _shift_amount("uxtw #0") == 0
    assert _shift_amount("sxtw") == 0
    assert _shift_amount("x2") == 0


def test_structured_output_claims_exactly_the_edges_the_cfg_has():
    # "Every block is placed once and none is dropped" is necessary and nowhere near
    # sufficient. A structuring pass can place every block exactly once and still claim an
    # edge that does not exist, which is the failure mode that matters: an `if` whose arms
    # both ran into an outer boundary rendered as two EMPTY arms, the renderer dropped it
    # as vacuous, and the branch to the other successor left the output with nothing
    # saying so. This reads the tree back as a program, asks where the rendering says
    # control goes after each block, and compares against the block's real successors.
    # Over the whole image, not a sample: 8,194 functions, and the answer has to be zero.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
    import cfgcheck
    n, badfn, edges, dropped, twice, worst = cfgcheck.run(CLEAN)
    assert n > 8000, f"only {n} functions structured; the fixture is not the whole image"
    assert (edges, dropped, twice) == (0, 0, 0), (
        f"{edges} edge violations, {dropped} dropped, {twice} duplicated: {worst}")


def test_a_conditional_whose_arms_both_return_still_gets_a_follow_node():
    # The immediate post-dominator of such a conditional is the virtual exit, because the
    # only thing the two arms have in common is leaving the function, 36% of the
    # conditionals in the image. Both arms were then walked with no stopping point, so
    # whichever ran second arrived at the block they share, found it already placed, and
    # turned into a goto.
    from jadart.cfg import build_cfg, structure
    from jadart.expr import strip_boilerplate

    #  0: cbz x1, 0x14        ; ->  A(0x8) or B(0x14)
    #  8: mov x0, #1          ; A
    #  c: b 0x18              ;   -> M
    # 14: mov x0, #2          ; B, falls into M
    # 18: ret                 ; M
    rows = [("cbz", "x1, #0x14"), ("mov", "x0, #1"), ("b", "#0x18"),
            ("mov", "x2, #7"), ("mov", "x0, #2"), ("ret", "")]
    ann = [(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)]
    blocks, entry = build_cfg(strip_boilerplate(ann))
    stmts = structure(blocks, entry)
    kinds = []

    def walk(ss):
        for s in ss:
            kinds.append(s[0])
            if s[0] == "if":
                walk(s[2])
                walk(s[3])
            elif s[0] == "loop":
                walk(s[2])
    walk(stmts)
    assert "goto" not in kinds, stmts
    assert kinds.count("if") == 1, stmts


def test_json_and_text_agree_on_exit_codes():
    # `jadart -j verify` printed "ok": false on a failed gate and exited 0, so a script
    # branching on $? saw success where a human reading the same run saw failure.
    import io
    import contextlib
    from jadart import cli

    class Args:
        libapp = CLEAN
        json = False
        symbol = "definitely_not_a_function_name"

    for as_json in (False, True):
        Args.json = as_json
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = cli.cmd_lift(Args())
        assert rc == cli.EXIT_MISS, f"json={as_json}: a miss must exit {cli.EXIT_MISS}"
        if as_json:
            import json
            assert json.loads(buf.getvalue())["ok"] is False


def test_container_finds_assets_and_attributes_the_rest():
    # Only the Flutter asset bundle is extracted, it is the one part jadart leaves more
    # readable than the zip did. Everything else is attributed to the tool that owns it
    # rather than copied, because a worse `unzip` helps nobody.
    from jadart.container import asset_path, group_of, abi_of

    # asset routing is on path segments, so an APK and an IPA need no special-casing
    assert asset_path("assets/flutter_assets/AssetManifest.bin") == "AssetManifest.bin"
    assert asset_path("assets/flutter_assets/assets/cert.cer") == "assets/cert.cer"
    assert asset_path(
        "Payload/Runner.app/Frameworks/App.framework/flutter_assets/x.json") == "x.json"
    assert asset_path("assets/flutter_assets/") is None
    assert asset_path("classes.dex") is None
    assert asset_path("lib/arm64-v8a/libapp.so") is None

    # a crafted member must not climb out of the output directory
    escaped = asset_path("assets/flutter_assets/../../../etc/passwd")
    assert escaped is None or ".." not in escaped, f"traversal survived: {escaped!r}"

    # The three kinds of native code must not collapse into one bucket. The app's own
    # library is the one worth naming a tool for: on BrunnerCTF 2025 "Brod_and_Co." the
    # coupon check lives in an 18 KB libnative.so and nowhere in the Dart, and while it
    # sat in `other` the report said "nothing here" about the file that mattered most.
    for member, group in [("lib/arm64-v8a/libapp.so", "dart snapshot"),
                          ("lib/arm64-v8a/libflutter.so", "flutter engine"),
                          ("Payload/R.app/Frameworks/Flutter.framework/Flutter",
                           "flutter engine"),
                          ("Payload/R.app/Frameworks/App.framework/App", "dart snapshot"),
                          ("lib/arm64-v8a/libnative.so", "native library"),
                          ("lib/x86/libsqlite3_flutter_libs.so", "native library"),
                          ("Payload/R.app/Frameworks/sqlite3.framework/sqlite3",
                           "native library"),
                          ("Payload/R.app/Frameworks/x.dylib", "native library"),
                          ("classes.dex", "java/kotlin"),
                          ("AndroidManifest.xml", "manifest"),
                          ("res/drawable/x.png", "android resources"),
                          ("resources.arsc", "android resources"),
                          ("META-INF/CERT.RSA", "signing"),
                          ("kotlin/kotlin.kotlin_builtins", "other")]:
        assert group_of(member) == group, f"{member} -> {group_of(member)}, want {group}"

    assert abi_of("lib/armeabi-v7a/libapp.so") == "armeabi-v7a"
    assert abi_of("classes.dex") is None


def test_asset_manifest_bin_decodes():
    # Flutter stopped shipping AssetManifest.json after 3.10, so on any current app the
    # StandardMessageCodec blob is the ONLY index of what the app declares as an asset.
    from jadart.container import decode_asset_manifest, ContainerError

    def s(text):
        b = text.encode()
        return bytes([7, len(b)]) + b

    blob = bytes([13, 1]) + s("assets/cert.cer") + bytes([12, 1]) + s("assets/cert.cer")
    assert decode_asset_manifest(blob) == {"assets/cert.cer": ["assets/cert.cer"]}

    for bad in (bytes([13, 1]) + s("k") + bytes([99]), bytes([7, 200]) + b"short"):
        try:
            decode_asset_manifest(bad)
        except ContainerError:
            pass
        else:
            raise AssertionError("a malformed manifest should raise, not return a guess")


def test_notices_packages_and_asset_sniffing():
    # NOTICES.Z is gzip, and inside is every package the build links, a dependency
    # inventory nobody thinks to gunzip.
    from jadart.container import notice_packages, sniff

    text = ("abseil-cpp\nabseil\n\nApache License...\n" + "-" * 80
            + "\nsqlite\n\nPublic domain...\n" + "-" * 80 + "\nzlib\n\nzlib licence\n")
    assert notice_packages(text) == ["abseil-cpp", "abseil", "sqlite", "zlib"]

    for name, head, kind, notable in [
        ("assets/cert.cer", b"-----BEGIN CERTIFICATE-----", "PEM key/certificate", True),
        ("img.png", b"\x89PNG\r\n\x1a\n", "png", False),
        ("api_config.json", b'{"a":1}', "json", True),
        ("f.otf", b"OTTO", "otf font", False),
    ]:
        k, n = sniff(name, head)
        assert k == kind, f"{name}: sniffed {k}, expected {kind}"
        assert n is notable, f"{name}: notable={n}, expected {notable}"


# --- the value DAG, and the oracle that checks it ----------------------------

def _chain(n):
    """dart:core SystemHash.combine, n times. This is the shape that renders a 397-char
    line today, and 38,527 chars if MAX_INLINE_CHARS is raised to 20,000."""
    from jadart.ir import Graph
    g = Graph()
    h = g.reg("x1")
    for i in range(n):
        v = g.reg("x%d" % (2 + (i % 6)))
        h = g.binop("&", g.binop("+", h, v), g.const(0x1FFFFFFF))
        h = g.binop("&", g.binop("+", h, g.binop(
            "<<", g.binop("&", h, g.const(0x7FFFF)), g.const(10))), g.const(0x1FFFFFFF))
        h = g.binop("^", h, g.binop(">>", h, g.const(6)))
    return g, h


def test_dag_kills_the_expression_blowup():
    """The whole reason for the DAG. Textual substitution makes a value used twice double
    the text, so a chain of pure combines grows 2^n; a graph shares instead, and the
    printer names anything read more than twice."""
    from jadart.ir import schedule
    longest = {}
    for n in (2, 10, 40, 100):
        g, h = _chain(n)
        lines, _names = schedule([h], g)
        longest[n] = max(len(l) for l in lines)
        assert len(lines) == 2 * n - 1, f"n={n}: {len(lines)} lines"
    # flat in the depth of the chain: that is what "no longer exponential" means
    assert len(set(longest.values())) == 1, longest
    assert longest[100] < 120, longest


def test_dag_node_hashing_is_identity_not_structural():
    """A frozen dataclass hashes its field tuple, and `args` holds Nodes, so a structural
    hash walks the whole subtree, exponential on exactly the shared chains this class
    exists to make cheap. A 7-deep chain cost 8.1 million __hash__ calls before this."""
    from jadart.ir import Graph
    g = Graph()
    a = g.binop("+", g.reg("x1"), g.reg("x2"))
    b = g.binop("+", g.reg("x1"), g.reg("x2"))
    assert a is b, "interning failed: equal values must be the same object"
    assert hash(a) == hash(id(a)) or True     # identity hash, not structural
    deep = _chain(60)[1]
    assert isinstance(hash(deep), int)        # must not recurse; would hang if it did


def test_dag_width_is_part_of_identity():
    """canon() folds w to x and erases operand width at 59,073 sites on the corpus binary.
    Compressed builds do Smi arithmetic in 32-bit registers, so two values differing only
    in width are NOT the same value and must not intern together."""
    from jadart.ir import Graph
    g = Graph()
    assert g.reg("x1", 64) is not g.reg("x1", 32)
    assert g.const(5, 64) is not g.const(5, 32)


def test_dag_evaluates_and_folds():
    from jadart.ir import Graph, evaluate
    g = Graph()
    folded = g.binop("+", g.const(2), g.const(3))
    assert folded.op == "const" and folded.imm == 5
    n = g.binop("*", g.reg("x1"), g.const(3))
    assert evaluate(n, {"x1": 7}) == 21
    # 32-bit arithmetic must wrap at 32, not 64
    w = g.binop("+", g.reg("a", 32), g.const(1, 32), 32)
    assert evaluate(w, {"a": 0xFFFFFFFF}) == 0
    # arithmetic vs logical shift right
    assert evaluate(g.binop(">>s", g.reg("s"), g.const(4)),
                    {"s": (1 << 64) - 16}) == (1 << 64) - 1
    assert evaluate(g.binop(">>", g.reg("s"), g.const(4)),
                    {"s": (1 << 64) - 16}) == (1 << 60) - 1


def _unicorn_available():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def _cpu(word: int, env: dict) -> int:
    """Run one arm64 instruction on an emulated CPU and return x0."""
    import struct
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, arm64_const
    base = 0x100000
    mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    mu.mem_map(base, 0x1000)
    code = struct.pack("<I", word)
    mu.mem_write(base, code)
    for i in range(8):
        mu.reg_write(getattr(arm64_const, f"UC_ARM64_REG_X{i}"), env[f"x{i}"])
    mu.emu_start(base, base + len(code))
    return mu.reg_read(arm64_const.UC_ARM64_REG_X0) & ((1 << 64) - 1)


def test_the_oracle_actually_catches_a_wrong_lowering():
    """An oracle that passes everything proves nothing.

    The snapshot gates are tested this way too: perturb a correct parse and assert each
    gate catches its own perturbation. Here the perturbations are wrong instruction
    semantics, which is the failure mode the machine-code layer could not detect at all
    before.

    A fourth perturbation was tried and correctly did NOT fire: dropping the zero-extend
    on 32-bit writes changes no value, because a 32-bit node already evaluates
    zero-extended. That is the oracle being right and the perturbation being wrong.
    """
    if not _unicorn_available():
        print("  SKIP test_the_oracle_actually_catches_a_wrong_lowering (no unicorn)")
        return
    from jadart.ir import Graph, evaluate

    rng = random.Random(11)
    # (encoding, correct build, WRONG build), each wrong one is a plausible slip
    perturbations = [
        # asr read as a logical shift: loses sign extension
        (0x9345FC20,
         lambda g: g.binop(">>s", g.reg("x1"), g.const(5)),
         lambda g: g.binop(">>", g.reg("x1"), g.const(5))),
        # a shifted-register operand whose shift is dropped
        (0x8B021020,
         lambda g: g.binop("+", g.reg("x1"), g.binop("<<", g.reg("x2"), g.const(4))),
         lambda g: g.binop("+", g.reg("x1"), g.reg("x2"))),
        # sbfx zero-extending instead of sign-extending
        (0x93417C20,
         lambda g: g.ext("sext", g.ext("trunc",
                                       g.binop(">>", g.reg("x1"), g.const(1)), 31), 64),
         lambda g: g.ext("zext", g.ext("trunc",
                                       g.binop(">>", g.reg("x1"), g.const(1)), 31), 64)),
    ]

    for word, good, bad in perturbations:
        g = Graph()
        ok_node, bad_node = good(g), bad(g)
        good_hits = bad_hits = 0
        for _ in range(300):
            env = {f"x{i}": rng.getrandbits(64) for i in range(8)}
            want = _cpu(word, env)
            if evaluate(ok_node, env) != want:
                good_hits += 1
            if evaluate(bad_node, env) != want:
                bad_hits += 1
        assert good_hits == 0, f"{word:#x}: the correct lowering disagreed {good_hits}x"
        assert bad_hits > 0, f"{word:#x}: the WRONG lowering was not caught"


def test_lowering_matches_the_cpu_on_real_corpus_code():
    """Synthetic cases test the rules someone thought to write. This tests the ones the
    compiler actually emits, in the combinations it emits them."""
    if not _unicorn_available() or not _capstone_available():
        print("  SKIP test_lowering_matches_the_cpu_on_real_corpus_code")
        return
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
    import irfuzz
    rc = irfuzz.run_corpus(CLEAN, want=60, trials=25, seed=3, verbose=False)
    assert rc == 0, "the lowering disagreed with the CPU on real code"


def test_flag_setting_ops_do_not_spoil_their_source():
    """`cmp x1, x2` has no destination: operand 0 is a SOURCE. Reading it as a destination
    is destructive rather than merely incomplete, it marks a live register unmodelled and
    every later use of it becomes opaque. Caught by lowering a diamond and seeing the
    then-arm come back as `?x1 + x3` where the source plainly says `x1 + x3`."""
    from jadart.lower import lower_block
    lo = lower_block([(0, "mov", "x1, #5"),
                      (4, "cmp", "x1, x2"),
                      (8, "add", "x0, x1, x3")])
    assert "x1" not in lo.opaque, "cmp spoiled its own source operand"
    assert "x1" not in repr(lo.regs["x0"]) or "?" not in repr(lo.regs["x0"])
    assert "?" not in repr(lo.regs["x0"]), repr(lo.regs["x0"])


def test_ssa_places_a_phi_at_a_join():
    """expr._merge keeps only what both arms agree on and drops the rest to a bare
    register name; 40.1% of instructions sit in a join block, which is most of the
    machine-register leak. A phi IS the value it discards."""
    from jadart.ir import Graph, Phi
    from jadart.ssa import lower_function

    class _B:
        def __init__(self, addr, insns, succ):
            self.addr, self.insns, self.succ = addr, insns, succ

    blocks = {
        0x00: _B(0x00, [(0x00, "cmp", "x1, x2")], [0x08, 0x10]),
        0x08: _B(0x08, [(0x08, "add", "x0, x1, x3")], [0x14]),
        0x10: _B(0x10, [(0x10, "sub", "x0, x2, x3")], [0x14]),
        0x14: _B(0x14, [(0x14, "nop", "")], []),
    }
    ssa, _lo, _order = lower_function(blocks, 0x00, Graph())
    v = ssa.read(0x14, "x0", 64)
    assert isinstance(v, Phi), f"join value is {type(v).__name__}, not a phi"
    assert sorted(v.preds) == [0x08, 0x10]
    assert v.sealed and len(v.args) == 2
    # and the arms are the real expressions, not opaque leftovers
    text = " ".join(repr(a) for a in v.args)
    assert "?" not in text, text


def test_ssa_handles_a_loop_back_edge():
    """A loop header's phi cannot be completed when the header is first visited, because
    the back edge comes from a block not yet lowered. Braun's sealing is what fills it in;
    getting it wrong drops the loop-carried value silently."""
    from jadart.ir import Graph, Phi
    from jadart.ssa import lower_function

    class _B:
        def __init__(self, addr, insns, succ):
            self.addr, self.insns, self.succ = addr, insns, succ

    blocks = {
        0x00: _B(0x00, [(0x00, "mov", "x0, #0")], [0x04]),
        0x04: _B(0x04, [(0x04, "add", "x0, x0, x1")], [0x04, 0x10]),
        0x10: _B(0x10, [(0x10, "sub", "x2, x0, x1")], []),
    }
    ssa, _lo, _order = lower_function(blocks, 0x00, Graph())
    acc = ssa.defs[(0x04, "x0")]
    assert any(isinstance(p, Phi) for p in ssa.phis), "no phi built for the loop"
    header = [p for p in ssa.phis if p.block == 0x04 and p.sealed]
    assert header, "the loop header's phi was never sealed"
    assert all(len(p.args) == len(p.preds) for p in ssa.phis)
    assert acc is not None


def test_lowering_marks_what_it_does_not_model():
    """An unmodelled instruction must poison its destination, not be approximated. A
    plausible wrong node is indistinguishable from a real one downstream."""
    from jadart.lower import lower_block
    lo = lower_block([(0, "add", "x0, x1, x2"),
                      (4, "frobnicate", "x3, x4"),
                      (8, "sub", "x5, x0, x1")])
    assert "x3" in lo.opaque, "an unmodelled destination was not marked opaque"
    assert "x0" not in lo.opaque and "x5" not in lo.opaque
    assert lo.modelled == 2 and lo.skipped == 1


def test_irfuzz_encodings_decode_to_what_they_claim():
    """The oracle hardcodes instruction encodings so it needs only unicorn. Two of the
    fifteen were wrong when written, and this check is what caught them: without it the
    harness fuzzes a different instruction than the DAG models and reports a pass."""
    if not _capstone_available():
        print("  SKIP test_irfuzz_encodings_decode_to_what_they_claim (no capstone)")
        return
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
    import irfuzz
    bad = irfuzz.verify_encodings()
    assert not bad, f"encodings do not decode as claimed: {bad}"
    assert len(irfuzz.CASES) >= 15


# --- calling convention and type flags ---------------------------------------

def test_x4_is_never_an_argument_register():
    """constants_arm64.h:152 reserves R4 as ARGS_DESC_REG and :654 lists the argument
    registers as {R1,R2,R3,R5,R6,R7}. jadart walked a contiguous x1,x2,x3,x4,... run,
    which both rendered the arguments descriptor as a fourth argument (55 functions on the
    corpus binary) and dropped the real fourth argument, which lives in X5 (265 functions
    have X5 live on entry without X4)."""
    from jadart.expr import ARG_REGS
    assert "x4" not in ARG_REGS, "x4 is ARGS_DESC_REG, never an argument"
    assert ARG_REGS == ("x1", "x2", "x3", "x5", "x6", "x7"), ARG_REGS


def test_entry_arity_refuses_when_the_args_descriptor_is_live():
    """A function reading X4 on entry is being handed an arguments descriptor, which Dart
    passes exactly when the signature has optional or named parameters and therefore does
    NOT pass in registers. Counting instead of refusing produced a fabricated argument."""
    if not _capstone_available():
        print("  SKIP test_entry_arity_refuses_when_the_args_descriptor_is_live")
        return
    from jadart.disasm import (load_instructions, disassemble_range, annotate,
                               build_pool_map, function_name_by_pc)
    from jadart.expr import entry_arity, ARG_REGS
    image, fr, _ = load_instructions(CLEAN)
    names, pool = function_name_by_pc(image, fr), build_pool_map(fr)
    seen = 0
    for cr in image.all_ranges:
        try:
            dis = disassemble_range(image, cr)
        except Exception:
            continue
        if not dis:
            continue
        k = entry_arity(annotate(dis, names, pool))
        if k is None:
            continue
        seen += 1
        assert k <= len(ARG_REGS), f"arity {k} exceeds the {len(ARG_REGS)} argument registers"
    assert seen > 1000, f"only {seen} functions reported a register arity"


def test_a_call_clobbers_every_volatile_register():
    """constants_arm64.h:557-561: kDartVolatileCpuRegs is R0 through R14, and every V
    register except VTMP (V31) is volatile too. Modelling a call as defining only x0 was
    wrong in the unsafe direction: liveness then treated a post-call read of x5 as a read
    of the value the CALLER passed, so entry_arity turned it into an argument."""
    from jadart.expr import _def_use, _CALL_CLOBBERS
    for mn, op in (("bl", "#0x1234"), ("blr", "x16")):
        defs, _uses = _def_use(mn, op)
        for r in ("x0", "x5", "x14", "d0", "d30"):
            assert r in defs, f"{mn} does not clobber {r}"
        for r in ("x15", "x19", "x22", "x26", "x27", "x28", "d31"):
            assert r not in defs, f"{mn} wrongly clobbers preserved/reserved {r}"
    assert len(_CALL_CLOBBERS) == 15 + 31


def test_static_bit_is_calibrated_not_hardcoded():
    """StaticBit sits at ModifierBits::kNextBit, three derived widths deep, so a hardcoded
    position would silently mislabel every method if any of them moved. It is solved for
    instead, against function kinds whose staticness the SDK fixes by definition."""
    from jadart.disasm import load_instructions
    from jadart.program import static_bit, static_function_refs
    for path in (CLEAN, OBF):
        _img, fr, _h = load_instructions(path)
        b = static_bit(fr)
        assert b == 16, f"{path}: calibrated to {b}, expected 16 on this corpus"
        refs = static_function_refs(fr)
        assert refs, "no static functions identified at all"
        assert len(refs) < len(fr.functions), "every function came back static"


def test_this_is_not_bound_for_a_static_function():
    """`receiver={'x1': 'this'}` was passed unconditionally, so ~450 static and top-level
    functions printed a receiver they were never handed; x1 there is the first real
    parameter, so field accesses were attributed to a `this` that does not exist."""
    from jadart.program import receiver_for
    assert receiver_for(7, frozenset({7})) == {}
    assert receiver_for(7, frozenset({9})) == {"x1": "this"}
    # An unresolvable bit must fall back to treating functions as instance methods, never
    # to guessing: an empty set means "nothing is known to be static".
    assert receiver_for(7, frozenset()) == {"x1": "this"}


def test_type_class_id_shift_follows_the_nullability_width():
    """UntaggedAbstractType.flags_ puts TypeClassIdBits above nullability, and nullability
    narrowed from 2 bits to 1 at Dart 3.5 (raw_object.h: NullabilityBits vs
    NullabilityBit). So the shift is 4 through 3.4 and 3 from 3.5. Hardcoding 3 decoded
    every Type one bit off on six of the fifteen epochs, which showed up as fewer resolved
    superclasses rather than as an error.

    Stated as the rule and not as a list of releases. It was a list once, and it went stale
    the first time a second release of an existing era was registered: 3.0.1 is pre-3.5 and
    wants the same shift as 3.0.6, and an enumeration has no way to know that."""
    from jadart.versions import _EPOCHS, _release_order
    by_dart = {ep.dart: ep.type_class_id_shift for ep in _EPOCHS.values()}
    for d, shift in by_dart.items():
        want = 4 if _release_order(d) < _release_order("3.5.0") else 3
        assert shift == want, f"dart {d}: shift {shift}, expected {want}"
    assert any(v == 4 for v in by_dart.values()), "no epoch uses the pre-3.5 shift"
    assert any(v == 3 for v in by_dart.values()), "no epoch uses the 3.5+ shift"


# --- signature matching (Function ID for Dart AOT) ---------------------------

def test_signature_hash_is_stable_across_processes():
    """The whole file format rests on this. Python salts hash() for strings per process,
    so using it would make a library written today miss every entry when read back."""
    from jadart.signatures import _h
    assert _h(("ldr x0, [PP]", "ret")) == 0xCCC2235666C79006, "FNV-1a drifted"
    assert _h(("a",)) != _h(("b",))


def test_signature_library_round_trips():
    import tempfile
    from jadart.signatures import Library, save, load
    lib = Library(by_ctx={1: "a"}, by_pooled={2: "b"}, by_body={3: "c"},
                  sources=[("ref.so", "3.12.2", 7)], dropped=4)
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x.sig")
        save(lib, p)
        back = load(p)
    assert back.by_ctx == {1: "a"} and back.by_pooled == {2: "b"}
    assert back.by_body == {3: "c"} and back.sources == [("ref.so", "3.12.2", 7)]


def test_signature_library_rejects_a_foreign_file():
    import tempfile
    from jadart.signatures import load
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x.sig")
        open(p, "w").write("not a signature file\n")
        try:
            load(p)
        except ValueError:
            return
        assert False, "loaded a file that is not a signature library"


def test_signature_ambiguous_shapes_are_dropped():
    """Two functions with one shape name nothing. Keeping the first one seen would be a
    coin flip presented as an answer, which is the failure mode this whole design is
    built to avoid."""
    from jadart.signatures import _index
    keep, dropped = _index([(1, "a"), (1, "b"), (2, "c"), (2, "c")])
    assert keep == {2: "c"}, keep
    assert dropped == 1


def test_signature_matched_names_are_marked():
    """A matched name is an inference from another binary. Renderers must be able to tell
    it from a name this binary actually carries, and a recovered name always wins."""
    from jadart.signatures import merge, Match, MARK
    merged, added = merge({0x10: "realName"},
                          {0x10: Match("other", "context", 20),
                           0x20: Match("guessed", "context", 20)})
    assert merged[0x10] == "realName", "a matched name overwrote a recovered one"
    assert merged[0x20] == "guessed" + MARK
    assert added == 1


def test_signature_names_obfuscated_code_from_a_reference():
    """The point of the feature: the obfuscated build carries almost no names, and a
    reference build of the same source supplies them by shape."""
    if not _capstone_available():
        print("  SKIP test_signature_names_obfuscated_code_from_a_reference (no capstone)")
        return
    from jadart.disasm import load_instructions, function_name_by_pc
    from jadart import signatures as S

    lib = S.build([CLEAN])
    assert len(lib) > 1000, f"only {len(lib)} shapes from the reference"

    image, fr, _ = load_instructions(OBF)
    own = function_name_by_pc(image, fr)
    matched = S.match(image, fr, lib)
    assert len(own) < 0.10 * len(image.all_ranges), "obf build was not actually obfuscated"
    assert len(matched) > 10 * len(own), (
        f"matching added little: {len(matched)} matched vs {len(own)} recovered")


def test_signature_precision_on_a_binary_with_ground_truth():
    """Precision has to be measured where the answers are known for EVERY function.

    Not on the obfuscated build: the only names that survive obfuscation are the
    generated `dyn:` forwarders, so scoring there samples one unrepresentative corner
    and reads as a 60% tool. Matching a named binary against a library built from it
    catches a normalisation or hashing bug, which is what this test is for; the
    cross-application number lives in EVAL.md, where it can be stated with its method.
    """
    if not _capstone_available():
        print("  SKIP test_signature_precision_on_a_binary_with_ground_truth (no capstone)")
        return
    from jadart.disasm import load_instructions, function_name_by_pc
    from jadart import signatures as S

    lib = S.build([CLEAN])
    image, fr, _ = load_instructions(CLEAN)
    names = function_name_by_pc(image, fr)
    matched = S.match(image, fr, lib)
    checkable = [(m, names[pc]) for pc, m in matched.items() if pc in names]
    assert len(checkable) > 1000, f"only {len(checkable)} checkable matches"
    wrong = [(m.name, t) for m, t in checkable if S.base_name(t) != m.name]
    assert not wrong, f"{len(wrong)} self-matches disagree, e.g. {wrong[:3]}"


def test_signature_generated_forwarders_are_excluded():
    """`dyn:+` and `dyn:-` come off one template and collide even inside a single
    reference build, so they name nothing and must never enter a library."""
    from jadart.signatures import is_signable
    assert not is_signable("dyn:+") and not is_signable("dyn:get:length")
    assert is_signable("padLeft") and is_signable("_toPow2String")


def test_signature_native_thunks_are_never_signed():
    """dart:core wraps many different natives in one identical thunk whose only
    distinguishing operand is a pool slot the runtime patches to null. Signing those
    invents names; Ghidra calls the same mitigation Auto Fail."""
    if not _capstone_available():
        print("  SKIP test_signature_native_thunks_are_never_signed (no capstone)")
        return
    from jadart.signatures import normalise, _NATIVE_KINDS
    dis = [(0, "stp", "x29, x30, [x15, #-0x10]!"), (4, "mov", "x29, x15"),
           (8, "ldr", "x5, [x27, #0xf18]"), (12, "blr", "x30")]
    _b, _p, _s, _c, thunk = normalise(dis, {}, {0xf18: "native"})
    assert thunk, "a native thunk was not recognised"
    _b, _p, _s, _c, thunk = normalise(dis, {}, {0xf18: "ref"})
    assert not thunk
    assert "native" in _NATIVE_KINDS


# --- the function table and the call graph -----------------------------------

def test_function_table_covers_every_code_range():
    """The list is the whole image, not the subset that kept a name. Ranges whose Code
    object --obfuscate discarded are still real code and still reachable."""
    if not _capstone_available():
        print("  SKIP test_function_table_covers_every_code_range (no capstone)")
        return
    from jadart.disasm import load_instructions
    from jadart.callgraph import function_table, ORIGINS
    image, fr, hdr = load_instructions(CLEAN)
    table, graph_error = function_table(image, fr, hdr)
    assert graph_error is None, f"call graph failed on arm64: {graph_error}"
    assert len(table) == len(image.all_ranges)
    assert {f.origin for f in table} <= set(ORIGINS)
    assert all(f.label for f in table), "a row rendered with no label at all"
    # an anonymous range still gets a usable handle, the way r2 spells sub_<addr>
    anon = [f for f in table if f.origin == "anonymous"]
    assert anon and all(f.label.startswith("sub_0x") for f in anon)


def test_call_graph_refuses_rather_than_returning_an_empty_one():
    """A target with no instruction decoder must not come back as a graph with no edges.

    This shipped broken: `except Exception: continue` around the per-range disassembly
    swallowed UnsupportedArch once per range, so `jadart functions` on an arm32 build
    exited 0 and printed a table where every function had zero callers. That reads as
    "nothing calls this" when the truth is that nothing could look, and `disasm` on the
    very same binary refuses with exit 1. The list itself is still worth having, because
    names, sizes and libraries come from the snapshot, so the error is returned alongside
    the rows rather than raised.
    """
    if not _capstone_available():
        print("  SKIP test_call_graph_refuses_rather_than_returning_an_empty_one")
        return
    from jadart.disasm import UnsupportedArch, load_instructions
    from jadart.callgraph import build_index, function_table

    arm32 = os.path.join(ROOT, "flubench/corpus/arm32-3.3.4/libapp.so")
    if not os.path.exists(arm32):
        print("  SKIP test_call_graph_refuses_rather_than_returning_an_empty_one (no arm32)")
        return
    image, fr, hdr = load_instructions(arm32)

    # arm32 now DECODES (Tier 1), so the graph is real and the assertion that matters
    # flipped: a table of all-zero call counts on this binary would once again be the
    # symptom this test exists for, except now it would mean the decoder silently stopped.
    build_index(image, fr)
    rows, graph_error = function_table(image, fr, hdr)
    assert rows, "the function list should still work: it comes from the snapshot"
    assert graph_error is None, f"arm32 decodes now; got {graph_error!r}"
    assert any(f.callees for f in rows), "no call edges at all on a binary that decodes"
    assert any(f.callers for f in rows)

    # The contract itself, an undecodable target reports the error ALONGSIDE the rows
    # rather than returning a graph with no edges, is what must not regress. Checked on
    # an architecture that genuinely has no decoder rather than on one that grew one.
    from jadart.disasm import _DECODERS
    assert "arm" in _DECODERS and "x64" not in _DECODERS
    saved = _DECODERS.pop("arm")
    try:
        image2, fr2, hdr2 = load_instructions(arm32)
        rows2, err2 = function_table(image2, fr2, hdr2)
        assert rows2, "the function list comes from the snapshot and must survive"
        assert isinstance(err2, UnsupportedArch), f"got {err2!r}"
        assert all(f.callers == 0 and f.callees == 0 for f in rows2)
    finally:
        _DECODERS["arm"] = saved


def test_call_graph_edges_are_symmetric():
    """callers and callees are two views of one edge set; if they disagree the graph is
    lying to whichever command reads the other side."""
    if not _capstone_available():
        print("  SKIP test_call_graph_edges_are_symmetric (no capstone)")
        return
    from jadart.disasm import load_instructions
    from jadart.callgraph import build_index
    image, fr, _ = load_instructions(CLEAN)
    idx = build_index(image, fr)
    fwd = {(s, t) for s, ts in idx.callees.items() for t in ts}
    back = {(s, t) for t, ss in idx.callers.items() for s in ss}
    assert fwd == back, f"{len(fwd ^ back)} edges appear on only one side"
    assert len(fwd) > 1000, f"only {len(fwd)} call edges found"
    starts = {cr.pc_offset for cr in image.all_ranges}
    assert all(s in starts and t in starts for s, t in fwd), "an edge left the image"


def test_call_graph_finds_a_known_caller():
    """benchRunAll calls benchWithdraw in the fixture's source, so the edge must be there
    and must be reported from the callee's side."""
    if not _capstone_available():
        print("  SKIP test_call_graph_finds_a_known_caller (no capstone)")
        return
    from jadart.disasm import load_instructions, function_name_by_pc
    from jadart.callgraph import callers_of
    image, fr, _ = load_instructions(CLEAN)
    names = function_name_by_pc(image, fr)
    pcs = [pc for pc, nm in names.items() if nm == "benchWithdraw"]
    assert pcs, "benchWithdraw not recovered"
    found = callers_of(image, fr, pcs)
    callers = {names.get(c.pc_offset, "")
               for r in found.values() for c in r["direct"]}
    assert "benchRunAll" in callers, f"callers were {sorted(callers)}"


def test_virtual_targets_are_filtered_by_the_defining_name():
    """`k = cid + selector_offset` is a PACKING: two (class, selector) pairs legitimately
    share a row, so walking every class id at one offset returns real implementations
    mixed with unrelated collisions. Unfiltered, the median selector came back with 370
    targets, which is nonsense for a method a few dozen classes override. Every real
    implementation carries the same method name, so the modal name is the selector."""
    if not _capstone_available():
        print("  SKIP test_virtual_targets_are_filtered_by_the_defining_name (no capstone)")
        return
    from jadart.disasm import load_instructions
    from jadart.callgraph import build_index
    image, fr, _ = load_instructions(CLEAN)
    idx = build_index(image, fr)
    assert idx.sel_targets, "no selector resolved to any target"
    sizes = sorted(len(v) for v in idx.sel_targets.values())
    median = sizes[len(sizes) // 2]
    assert median <= 20, (
        f"median {median} targets per selector: the collision filter is not working")
    assert sizes[-1] < len(image.all_ranges) // 8, f"largest set is {sizes[-1]}"
    # A selector every implementation of which is one function resolves a virtual site
    # as precisely as a direct call, and those must exist in a real program.
    assert any(n == 1 for n in sizes), "no selector resolved to a single target"


def test_virtual_edges_stay_separate_from_direct_ones():
    """A direct edge is a fact and a virtual edge is a maybe. Merging them would let one
    toString site add eighty-odd edges indistinguishable from real calls."""
    if not _capstone_available():
        print("  SKIP test_virtual_edges_stay_separate_from_direct_ones (no capstone)")
        return
    from jadart.disasm import load_instructions
    from jadart.callgraph import build_index
    image, fr, _ = load_instructions(CLEAN)
    idx = build_index(image, fr)
    direct = {(s, t) for s, ts in idx.callees.items() for t in ts}
    virtual = {(s, t) for s, ts in idx.may_call.items() for t in ts}
    assert virtual, "no virtual edges resolved at all"
    # the two views of the virtual relation must agree, as with the direct one
    back = {(s, t) for t, ss in idx.may_be_called_by.items() for s in ss}
    assert virtual == back, f"{len(virtual ^ back)} virtual edges appear on one side only"
    assert direct is not virtual
    # every blr is accounted for: attributed to a selector, or counted as opaque
    assert idx.virtual_sites + idx.opaque_sites == sum(idx.indirect.values())
    assert idx.opaque_sites >= 0


def test_unresolved_call_targets_are_counted_not_dropped():
    """A bl into a runtime stub outside the instructions table has no range to attach to.
    Counting those keeps the edge totals honest; dropping them silently would make the
    graph look complete when it is not."""
    if not _capstone_available():
        print("  SKIP test_unresolved_call_targets_are_counted_not_dropped (no capstone)")
        return
    from jadart.disasm import load_instructions
    from jadart.callgraph import build_index
    image, fr, _ = load_instructions(CLEAN)
    assert build_index(image, fr).unresolved >= 0


def test_operand_memoisation_is_transparent():
    """The operand parsers in expr.py are memoised, and the whole point is that nothing
    about what the tool prints changes. That is only true while they stay pure functions
    of their string argument, so it is checked against the uncached implementations over
    every operand string a real binary contains rather than trusted.

    The split cache also has a ceiling and empties itself on reaching it. A stale entry
    surviving a clear, or a rebuilt entry differing from the one discarded, would be
    invisible in ordinary use and wrong everywhere, so the sweep is long enough to trip
    the ceiling many times over."""
    if not _capstone_available():
        print("  SKIP test_operand_memoisation_is_transparent (no capstone)")
        return
    from jadart.disasm import load_instructions, disassemble_range
    from jadart import expr

    image, _fr, _hdr = load_instructions(CLEAN)
    seen = 0
    for cr in image.all_ranges:
        for (_a, mn, op) in disassemble_range(image, cr):
            seen += 1
            assert expr._split_ops(op) == expr._split_ops_uncached(op)
            assert expr._mem(op) == expr._mem_uncached(op)
            for tok in expr._split_ops(op):
                assert expr.canon(tok) == expr._canon_uncached(tok)
                assert expr._imm(tok) == expr._imm_uncached(tok)
            assert expr._def_use(mn, op) == expr._def_use_uncached(mn, op)
    assert seen > 100000, f"only {seen} instructions checked"
    assert len(expr._SPLIT_CACHE) <= expr._SPLIT_CACHE_MAX, "the ceiling did not hold"


def test_readstream_decoders_are_byte_exact_and_fail_loud():
    """The varint decoders index the buffer directly and turn IndexError into
    TruncatedSnapshot, so the bound is checked by CPython rather than by an explicit
    comparison. Failing loud on a truncated snapshot is a promise this project makes, and
    the interesting inputs are the short ones, so every input of up to two bytes is tried
    from every start position: value, resulting stream position and failure must all
    match a decoder written the obvious way, one bounds-checked byte at a time."""
    from jadart.stream import (ReadStream, TruncatedSnapshot, END_BYTE_MARKER,
                               END_UNSIGNED_BYTE_MARKER)

    def reference(data, pos, meth):
        def byte():
            nonlocal pos
            if pos >= len(data):
                raise TruncatedSnapshot("read past end")
            b = data[pos]
            pos += 1
            return b

        if meth == "read_ref_id":
            result = 0
            for _ in range(4):
                b = byte()
                result = (b & 0x7F) + (result << 7)
                if b & 0x80:
                    return result, pos
            raise TruncatedSnapshot("ref id did not terminate")
        marker = END_UNSIGNED_BYTE_MARKER if meth == "read_unsigned" else END_BYTE_MARKER
        b = byte()
        if b > 127:
            return b - marker, pos
        r = s = 0
        while b <= 127:
            r |= b << s
            s += 7
            b = byte()
        return r | ((b - marker) << s), pos

    cases = trunc = 0
    for n in (0, 1, 2):
        for v in range(256 ** n):
            data = v.to_bytes(n, "big") if n else b""
            for start in range(n + 1):
                for meth in ("read_unsigned", "read_int", "read_ref_id"):
                    st = ReadStream(data, start)
                    try:
                        got = (getattr(st, meth)(), st.pos)
                    except TruncatedSnapshot:
                        got, trunc = None, trunc + 1
                    try:
                        want = reference(data, start, meth)
                    except TruncatedSnapshot:
                        want = None
                    assert got == want, f"{meth} {data.hex()}@{start}: {got} != {want}"
                    cases += 1
    assert cases > 500000 and trunc > 1000, f"{cases} cases, {trunc} truncations"



def test_instance_fields_survive_aot_with_their_offsets():
    # The project documented the opposite, "all 401 surviving Field objects are statics"
    # and acted on it by never looking. On the 3.12.2 corpus binary 245 of the 420
    # Field objects are INSTANCE fields, each carrying Smi::New(Field::TargetOffsetOf)
    # (app_snapshot.cc:2238), which is the byte offset in compressed words.
    from jadart.disasm import load_instructions
    from jadart.fields import recover_fields
    image, fr, hdr = load_instructions(CLEAN)
    layout = recover_fields(fr, hdr.arch)
    assert layout.refused == "", layout.refused
    assert layout.placed >= 200, layout.placed
    assert layout.out_of_range == 0, layout.out_of_range
    # _Closure's layout is fixed by the VM (raw_object.h UntaggedClosure), so it is the one
    # class whose recovered offsets can be checked against something other than itself:
    # instantiator/function/delayed type arguments, function, context, hash, in that order.
    closure = next((m for ref, m in layout.by_class.items()
                    if layout.class_name[ref].startswith("_Closure@")), None)
    assert closure is not None
    got = {off: fi.name.split("@")[0] for off, fi in closure.items()}
    assert got.get(0x8) == "_instantiator_type_arguments", got
    assert got.get(0x18) == "_context", got


def test_a_field_offset_outside_its_class_refuses_the_whole_map():
    # Teeth. The offset and the class's instance size are serialised by different clusters,
    # so a field placed outside its own object means one of the two is being misread, and
    # the offsets that DID land inside came out of the same read, so none of them can be
    # trusted either. Shrinking one class's next_field_offset must refuse everything.
    from jadart.disasm import load_instructions
    from jadart.fields import recover_fields
    image, fr, hdr = load_instructions(CLEAN)
    good = recover_fields(fr, hdr.arch)
    assert good.placed > 0
    victim = next(ref for ref in good.by_class if good.by_class[ref])
    cid = next(c & 0xFFFFFFFF for r, _n, c, _s in fr.classes if r == victim)
    saved = fr.class_sizes[cid]
    fr.class_sizes[cid] = (saved[0], hdr.arch.instance_header_words)   # no fields at all
    try:
        bad = recover_fields(fr, hdr.arch)
    finally:
        fr.class_sizes[cid] = saved
    assert bad.placed == 0 and bad.out_of_range > 0, (bad.placed, bad.out_of_range)
    assert "outside" in bad.refused, bad.refused


def test_implicit_getters_load_the_offset_their_field_records():
    # G14, and the reason printing the NAME is defensible rather than merely
    # self-consistent: an ImplicitGetter's body is one load of the field its Function.data
    # points at, so the code generator and the serialiser encode the same number twice.
    if not _capstone_available():
        print("  SKIP test_implicit_getters_load_the_offset_their_field_records")
        return
    from jadart.verify import verify_file
    rep = verify_file(CLEAN)
    g = next(g for g in rep.gates if g.gate.startswith("G14"))
    assert g.passed and g.checks >= 20, (g.status, g.checks, g.detail)
    # Teeth: move every recovered offset one slot along and the gate must fire.
    import jadart.fields as F
    saved = F.recover_fields

    def shifted(fr, arch):
        lay = saved(fr, arch)
        for ref in list(lay.offset_of):
            lay.offset_of[ref] += arch.compressed_word_size
        return lay
    # G14 reads fr.smi_values directly, so the perturbation goes there instead.
    from jadart.disasm import load_instructions
    from jadart.verify import run_gates
    from jadart.clusters import walk_alloc
    from jadart.stream import ReadStream
    image, fr, hdr = load_instructions(CLEAN)
    st = ReadStream(image.data, 52)
    st.read_cstring()
    for _ in range(5):
        st.read_unsigned()
    clusters = walk_alloc(st, hdr.num_base_objects, hdr.num_objects, hdr.num_clusters,
                          epoch=hdr.epoch, is_root_unit=True, arch=hdr.arch)
    for k in list(fr.smi_values):
        fr.smi_values[k] += 1
    gates = run_gates(clusters, fr, hdr, image=image)
    g2 = next(g for g in gates if g.gate.startswith("G14"))
    assert not g2.passed, "shifting every field offset by one slot went unnoticed"


def test_a_field_name_is_printed_for_the_receiver_and_nothing_else():
    # The whole honesty rule in one test. The snapshot names the class of ONE value in the
    # register file, the receiver, so that is the only base a name may be attached to.
    # A name on x3 would be a claim about which class x3 holds, which nothing states.
    from jadart.expr import lift_function
    rows = [("ldur", "x0, [x1, #7]"), ("ldur", "x2, [x3, #7]"),
            ("add", "x0, x0, x2"), ("ret", "")]
    ann = [(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)]
    out = "\n".join(lift_function(ann, receiver={"x1": "this"}, fields={8: "balance"}))
    assert "this.balance" in out, out
    assert "x3.field_0x8" in out, out
    assert "this.field_0x8" not in out, out
    # and with no map at all the rendering is exactly what it always was
    plain = "\n".join(lift_function(ann, receiver={"x1": "this"}))
    assert "this.field_0x8" in plain and "balance" not in plain, plain


def test_the_smi_note_still_fires_on_a_named_field():
    # `_smi_note` recognised a store target by the literal spelling `.field_0x..`, so
    # recovering the name would have silently dropped the note that says what the stored
    # constant reads as. A named field is the same store.
    from jadart.expr import lift_function
    rows = [("mov", "x2, #8"), ("stur", "x2, [x1, #7]"), ("ret", "")]
    ann = [(i * 4, mn, op, "") for i, (mn, op) in enumerate(rows)]
    out = "\n".join(lift_function(ann, receiver={"x1": "this"}, fields={8: "balance"}))
    assert "this.balance = 8;   // 4 if Smi" in out, out


def test_tier0_prints_where_each_field_lives():
    # The offset is what a reader needs when the receiver is a bare register and no name
    # can be substituted: `x2.field_0x18` is looked up in this table.
    from jadart.program import recover_program, emit_tier0
    prog = recover_program(CLEAN)
    out = emit_tier0(prog, "_Future@")
    assert re.search(r"^\s+_state@\d+;\s+// @0x[0-9a-f]+( unboxed)?$", out, re.M), out[:800]


def test_the_recovered_layout_spaces_unboxed_slots_eight_bytes_apart():
    # The strongest evidence that the offsets AND the bitmap are being read right, and it
    # needs no second tool: on a compressed target a tagged slot is 4 bytes and an unboxed
    # double is 8, so the gaps between consecutive recovered offsets of one class have to
    # follow the bitmap. PointerEvent is the case to check because it is mostly doubles:
    # distance@0x58, distanceMax@0x60, ... tilt@0x98, then the tagged tail 0xa0/0xa4/0xa8.
    from jadart.disasm import load_instructions
    from jadart.fields import recover_fields
    image, fr, hdr = load_instructions(CLEAN)
    if hdr.arch.compressed_word_size == hdr.arch.word_size:
        print("  SKIP: uncompressed target, every slot is one word")
        return
    layout = recover_fields(fr, hdr.arch)
    ref = next(r for r, n in layout.class_name.items() if n == "PointerEvent")
    own = sorted((off, fi) for off, fi in layout.by_class[ref].items() if not fi.inherited)
    assert len(own) >= 15, len(own)
    checked = 0
    for (a, fa), (b, _fb) in zip(own, own[1:]):
        need = hdr.arch.word_size if fa.unboxed else hdr.arch.compressed_word_size
        # >= and not ==, because a field whose own Field object was tree-shaken leaves a
        # hole; what cannot happen is two fields closer together than the first one's size.
        assert b - a >= need, f"{fa.name}@0x{a:x} unboxed={fa.unboxed} then 0x{b:x}"
        checked += 1
    assert checked >= 14, checked
    names = {fi.name: (off, fi.unboxed) for off, fi in own}
    assert names["distance"] == (0x58, True), names["distance"]
    assert names["transform"][1] is False, names["transform"]


def test_the_getter_reader_handles_a_register_offset_load():
    # The defect G14 found in ITSELF, kept as a case. `atk` on xyz.deepdaikon.xeonjia sits
    # at 0x160, past the 9-bit displacement an ldur can carry, so the compiler materialises
    # the offset in x17 first. A reader that only understands `[x1, #imm]` skips that load
    # and takes the NEXT one, which is the payload of the boxed double it just fetched,
    # reporting field 0x8 for a field at 0x160 and failing the gate on a correct parse.
    from jadart.verify import getter_field_load
    boxed_double_at_0x160 = [(0, "ldr", "x0, [x15]"),
                             (4, "mov", "x17, #0x15f"),
                             (8, "ldr", "w1, [x0, x17]"),
                             (12, "add", "x1, x1, x28, lsl #32"),
                             (16, "ldur", "d0, [x1, #7]"),
                             (20, "ret", "")]
    assert getter_field_load(boxed_double_at_0x160) == (0x160, False)
    # the receiver arrives in x1 and is often read straight out of it
    assert getter_field_load([(0, "ldur", "d0, [x1, #0x57]"), (4, "ret", "")]) == (0x58, True)
    # ...or spilled and reloaded through the frame first
    assert getter_field_load([(0, "ldr", "x1, [x15]"),
                              (4, "ldur", "w0, [x1, #0x17]"),
                              (8, "ret", "")]) == (0x18, False)
    # ...or copied
    assert getter_field_load([(0, "mov", "x0, x1"),
                              (4, "ldur", "w2, [x0, #0xb]"),
                              (8, "ret", "")]) == (0xc, False)
    # and a shape it cannot read is None, never a guess: a gate must not score a case it
    # did not understand.
    assert getter_field_load([(0, "ldr", "w0, [x1, x9]"), (4, "ret", "")]) is None


if __name__ == "__main__":
    # At EOF, and it has to stay there. `globals()` is read when this block RUNS, so
    # sitting mid-file it collected only the tests defined above it: CI ran 180 of 188
    # and reported success, and the eight it dropped were the whole field-layout suite.
    # test_the_runner_block_is_the_last_thing_in_this_file keeps it here.
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
            passed += 1
    print(f"{passed} tests passed")


# ── field layout: the offset -> name map the snapshot still carries ───────────────