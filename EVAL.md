# Phase 1: systematic evaluation

Comparing the existing Flutter RE tools on a controlled corpus (FluBench), to
map the capability frontier and build the failure taxonomy that tells us where
the new framework's technique must live.

## Method

FluBench (flubench/) compiles a labeled construct app; the declared symbols and
string literals are exact ground truth. score.py measures recall. The corpus is
optimizer-resistant (@pragma never-inline + runtime-seeded inputs) so we measure
the tool, not the AOT optimizer (see FINDINGS.md, Phase 0).

## Tool comparison (on the Dart 3.12.2 arm64 corpus)

The comparison below is run on one epoch so the tools are measured against the same bytes;
Jadart's own coverage is eighteen epochs and four targets, measured further down.

| tool | build | classes | functions | strings | decompiles? | offline | version-ID |
|------|-------|---------|-----------|---------|-------------|---------|-----------|
| unflutter | clean | 100% | 100% | 100% | no (asm) | yes | silent-fallback |
| unflutter | obf | 0% | 0% | 100% | no (asm) | yes | silent-fallback |
| Jadart (M2) | clean | 100% | 100% | 100% | not yet | yes | fail-loud |
| Jadart (M2) | obf | 0% | 0% | 100% | not yet | yes | fail-loud |
| Jadart (M3) | clean | 100% | 100% | 100% | Tier 0 skeleton | yes | fail-loud |
| Jadart (M3) | obf | 0% | 0% | 100% | Tier 0 skeleton | yes | fail-loud |
| Jadart (T1) | clean | 100% | 100% | 100% | Tier0 + annotated asm | yes | fail-loud |
| Jadart (unified) | clean | 100% | 100% | 100% | per-class decompile view | yes | fail-loud |
| Jadart (T2) | clean | 100% | 100% | 100% | structured pseudo-Dart (if/else/loop) | yes | fail-loud |
| Jadart (T3) | clean | 100% | 100% | 100% | pseudo-Dart **expressions** (field/arith/call/return) | yes | fail-loud |
| Jadart (T3.4) | clean | 100% | 100% | 100% | expressions + **named virtual calls** (`this.renderObject`) | yes | fail-loud |
| Blutter | - | pending (WP-5) | | | no (asm) | yes | per-version SDK |
| Ghidra+scripts | - | pending | | | pseudocode (C) | yes | manual |

M3 note: Jadart is now the ONLY tool in this table that emits structured Dart (a Tier 0
class/method skeleton), not assembly or C-pseudocode. It walks the whole fill pass
byte-exactly and resolves the object graph, so it recovers not just a flat name list but the
structure: `benchWithdraw` is placed inside `class BenchAccount`, 1842 named classes with
their methods. This is the headline decompiler gap (failure taxonomy item 4) being closed at
Tier 0. Reproduce (from framework/): `python3 -m jadart.cli <libapp.so> --tier0 --filter Bench`.

Reading:
- unflutter clean recovery is near-perfect even though it cannot positively
  identify Dart 3.12.2. Obfuscation zeroes name recovery (identifiers are
  stripped from the snapshot; ~43% of objects removed, measured via Jadart),
  while string literals survive (--obfuscate does not encrypt them).
- Jadart (M2) now EQUALS unflutter's name recall (clean 100/100/100, obf 0/0/100)
  from a scratch, version-robust parser, and does it fail-loud instead of by
  silent-fallback. It walks the whole alloc pass byte-exactly (lands on num_objects)
  and reads the canonical String cluster to recover the identifier pool. Reproduce:
  `python3 flubench/score.py --truth flubench/artifacts/ground_truth.json --jadart-lib
  flubench/artifacts/clean/lib/arm64-v8a/libapp.so --label clean`.
- Key eval finding: parsing the 3.12.2 binary against the main (3.13-dev) SDK source
  exposed three format drifts (Closure alloc, Class alloc, cid numbering). Jadart
  handles them per-epoch; unflutter absorbs the same drift silently by falling back to
  its newest hand-coded profile. This is direct evidence for the version-robustness gap
  (failure taxonomy item 2) and that a per-epoch parameterization closes it.

## Test-phase hardening (Tier 1/2)

An adversarial test phase found and fixed three correctness bugs in the Tier 1/2
disassembly and structuring stages. All are now covered by regression tests
(framework/tests/test_core.py):

1. ObjectPool annotation offset. PP (X27) is untagged on arm64 and pool entry idx
   sits at byte offset `0x10 + idx*8` (ObjectPool_elements_start_offset=0x10,
   element_size=8, from runtime_offsets_extracted.h). The annotator keyed entries at
   `idx*8`, a 16-byte (2-slot) shift that mislabelled constants. Confirmed against a
   unique-string anchor: benchCheckSecret's only string constant is
   `FLUBENCH{str_literal_compare}`, which resolves correctly only under `(off-0x10)/8`.
   unflutter shares the same off-by-2 in its pool annotation (harmless for its name
   recovery, which does not use pool offsets).
2. Far pool loads. Constants past the 12-bit scaled-ldr range (~0x7ff8) are loaded as
   `add xD, x27, #hi; ldr xN, [xD, #lo]`. These were unhandled, so every string in the
   high pool (e.g. the flag literal above) went unresolved. The annotator now tracks the
   add base and resolves the combined offset.
3. Loop-body reconstruction. The old loop walker followed `succ[0]` linearly, taking the
   branch-taken/exit edges and emitting a bare `return` inside `while(true)` with the body
   dropped. Loops are now structured through the same recursive if/else machinery bounded
   to the natural-loop node set, so benchComputeChecksum's `for` body (element load +
   `acc = acc*31 + b`) reconstructs inside the loop with the length test as a `break`.

Coverage: fixing the instruction-table walk to size functions by the next table entry
(across all entries, not just recovered owners) and to expose every table entry raised
obfuscated-build disassembly coverage from 4% to 100% of the instruction image. The
discarded functions under --obfuscate keep their instructions (table entries
[0, first_entry_with_code)); only their names are gone.

Robustness: truncated/malformed snapshots now raise TruncatedSnapshot instead of a bare
IndexError; a non-Flutter ELF fails loud (was a silent exit 0); the default CLI path and
the --decompile not-found path report cleanly with non-zero exit codes.

## Tier 3: expression reconstruction (closes failure-taxonomy item 4)

Tier 2 recovers control flow but leaves each block as annotated arm64. Tier 3 lifts those
instructions into pseudo-Dart *expressions* by abstract interpretation over the register
file (jadart/expr.py): a register->expression map is threaded through the structured
statement tree, forked at branches and merged after them, with loop-carried variables
materialised via a liveness pass. This is the headline decompiler gap, no other Flutter RE
tool emits expressions; they stop at assembly (unflutter, Blutter) or C-pseudocode (Ghidra).

What it models: object field load/store (`this.field_0x8`), arithmetic (`+ - * & | ^` and
shifts, with 32-bit masks and Smi untag shown), integer/`bool`/`null` constants (the latter
via `NULL_REG + 0x20/0x30`), array element access (`base[index]` recovered from
`add base, idx, lsl #s`), compressed-pointer decompression, named direct calls, and
`return <expr>` - plus compound assignment recognition (`balance -= amount`). Compiler
boilerplate is stripped so it never reaches output: the frame prologue/epilogue, the thread
stack-overflow check (and its now-unreachable slow path), and the pointer write barrier
(`tst TMP, x28, lsr #32; b.cc; bl <stub>`, unambiguous because x28/HEAP_BASE is reserved).
Anything not modelled is emitted verbatim as its arm64 line, so nothing is fabricated.

Result on the FluBench ground truth (`benchWithdraw`, source
`if (amount > balance) return false; balance -= amount; return true;`):

```
if (x2 > this.field_0x8) {
  return false;
} else {
  this.field_0x8 -= x2;
  return true;
}
```

and the `benchComputeChecksum` accumulator loop reconstructs the length test as an exit
`break`, the element read as `x2[x4]`, the accumulate as `x0 = (x0 & 0xffffffff) * 31 +
(x2[x4] & 0xffffffff) & 0xffffffff`, and the index as `x4 += 1`.

Robustness / honesty: the full annotate -> strip -> CFG -> structure -> lift pipeline runs
with **zero exceptions over 9000 code ranges** across the clean build, the obfuscated build,
and a real third-party app (flagcheck). On real Flutter framework code it was never tuned
for, it produces readable bodies, e.g. `AnimationController._checkStatusChanged` comes back
as `if (_lastReportedStatus != _status) { _lastReportedStatus = _status;
notifyStatusListeners(...); }` (register/offset names, boilerplate stripped).

Virtual-dispatch attribution (Tier 3.3): a call through the X21 dispatch table (Dart's
class-id-indexed virtual/interface dispatch) renders as `receiver.sel_0x<off>(...)` instead of
an opaque `(dynamic call)`. The lifter traces the class-id load (`ubfx cid,[recv,#-1]`), the
per-selector offset added to it, and the `[x21, idx]` table load back to the receiver register
and the offset; the offset is stable program-wide, so it identifies the selector. Over the
corpus ~74% of dispatch sites recover both the receiver and the offset.

## Tier 3.4: virtual-call selector NAMES (a capability no public tool has)

Tier 3.3 leaves a virtual call as `x1.sel_0x4778(...)`: the right receiver and a stable
selector id, but not a name. Every other tool stops in the same place, including the strongest
one, Blutter recompiles the exact Dart SDK and still prints `r0 = GDT[cid_x0 + 0x4778]()`
(`blutter/src/il.h`). Tier 3.4 closes it by parsing the serialized global dispatch table, which
no tool had decoded.

**Locating the table is exact, not a search.** It is written last in the isolate stream, after
the fill pass and the roots, so its start is not at a fixed offset and the intervening roots
are variable-length varints. But the serializer emits the Code cluster's first ref id right
after the table length (`Serializer::WriteDispatchTable`), and Jadart already derives that same
number independently from the alloc walk. Scanning the post-fill region for the position where
the two agree pins the table exactly: on the corpus it resolves to offset `0xe086f`, length
29190, with `first_code_id = 19341` matching the Code cluster's `start_ref = 19341`, and the
decode consumes the stream to its end.

**The slot -> function link already existed.** Dispatch entries encode a `code_index`, and the
same index space is used by every Function's serialized `code_index`; per
`GetCodeAndEntryPointByIndex`, `instructions-table slot = code_index - 1` in both the discarded
and the Code-cluster case. That is exactly the slot Jadart maps to an owning function, so a
table row names a concrete function rather than a bare address.

**Naming, and how it self-checks.** The dispatch register points at `&array[kOriginElement]`
(4096 on ARM64), so a row for class `cid` sits at `k = cid + selector_offset` and a call site's
immediate is `selector_offset - kOriginElement`. A method defined in class C necessarily
occupies C's own row, giving `selector_offset = k - cid(C)`; every class defining the same
selector must independently produce the same number. That redundancy is the check. On the
corpus `get:hashCode` is corroborated by 127 distinct defining classes, `toString` by 67,
`build` by 48, `createState` by 46, `createRenderObject` by 42, `dispose` by 40 - the entire
Flutter widget lifecycle, each at its own offset. A name is emitted only with >= 2 agreeing
classes, and an offset claimed by two names is dropped.

Measured (clean build, 0 exceptions): 168 selectors recovered; of the 1108 dispatch sites
whose offset is recovered, 318 get a source name (28.7%). It was 209 and 40.2% until the
vote was required to be untied: `Counter.most_common` had been breaking a tie by insertion
order, so 144 names rested on which candidate happened to be counted first. Those now stay
`sel_0x<off>`, which is the honest rendering. `findRenderObject` lifts to
`x0 = this.renderObject; return x0;`, matching the upstream
`RenderObject? findRenderObject() => renderObject;`. Property selectors render as accessors
(`x0 = this.renderObject;`) rather than calls.

Two honest limits, both measured rather than assumed. `--obfuscate` builds yield ~1 selector:
the vote needs identifiers, and obfuscation removes them, so Jadart keeps `sel_0x<off>` instead
of inventing names. `dwarf_stack_traces_mode` builds also yield ~1: there the ELF `.symtab`
still has the real `Class.method` names (and Jadart uses them for the vote), but only 245 of
2175 Functions retain the snapshot `Code` -> owner-`Class` link the offset arithmetic needs, so
there are too few anchors to corroborate. Both degrade to the Tier 3.3 rendering, never to a
guess. Reproduce with `python3 -m jadart.cli <libapp.so> --selectors`.

Call-argument reconstruction (Tier 3.1): a direct call renders its arguments (`foo(x0, x3)`)
by resolving the callee's register arity, the count of contiguous x1..xk that are live on
entry (read before written), and reading those registers' expressions at the call site. The
Dart AOT stack calling convention (marked by an ArgumentsDescriptor load into R4) and runtime
stubs fall back to `...`, and an argument is only shown when the caller established it locally,
so every rendered argument is a real incoming argument (it never over-counts; float/optional
args passed in V-registers are simply omitted). On FluBench, `benchRunAll` reconstructs
`benchWithdraw(x0, x3)` (2 args), `benchComputeChecksum(<list>)` (1), and correctly leaves the
stack-convention `benchFirstOrDefault(...)` unreconstructed.

Semantic runtime operations (Tier 3.2): a `bl` to a VM stub is compiler machinery, not a
source call, so Jadart renders the ones with source meaning and drops the rest. Throw stubs
become `throw <x0>` / `rethrow`, the shared error stubs become `throw NullCastError()` /
`throw RangeError()` / `throw LateInitializationError()`, and allocation stubs become
`x0 = new List()` / `new int()` / `new <Type>()`; the pure machinery (stack-overflow check,
object/array write barrier, type-test, lazy-field init, Smi int-boxing, the `brk` trap after
a noreturn) is dropped. The Smi box-or-tag idiom (`sbfiz; cmp ..., asr #1; b.eq; AllocateMint`)
is collapsed to its integer value so it no longer surfaces as a bogus `if (x != x)`. On the
flagcheck app this turns `AnimationController._checkStatusChanged`'s late-init guard into a
clean `else { throw LateInitializationError(); }` and `Base64Codec._checkPadding`'s error
path into `new List(); ... throw x0;` with the padding message literals intact.

Field names are recovered where the snapshot still carries them, and only there. This
paragraph used to end "Field NAMES are unrecoverable", which was a generalisation from the
first part of the measurement to a claim the rest of it does not support.

Still true, and still measured: across all **2350 classes the `offset_in_words_to_field`
table is empty**, only 420 of the program's several-thousand fields keep a `Field` object
at all, and `balance` (BenchAccount's field) is absent from the entire string pool, so that
field renders `this.field_0x8` and always will.

Not true: that the 420 are all statics. **245 of them are instance fields**, each carrying
`Smi::New(Field::TargetOffsetOf(field))` - its own byte offset in compressed words
(app_snapshot.cc:2238). Across the 44 cached third-party apps it is **36,555 instance
fields of 59,160**, and **32,205 of 32,205** place inside their owner class's declared
`instance_size` with none outside. Those are printed by name on `this`, and by offset
everywhere else, because `this` is the only value whose class the snapshot states.

Measured reach on the lifted output, corpus binary: **1,364 of 11,177** `this.field_0x`
occurrences become names (12.2%), clearing **1,273 of 10,134** lines that carried one
(12.6%); over all lifted lines the byte-offset symptom goes 42,278 -> 41,617 (27.8% ->
27.4%). On real apps: hacki 6,201 of 36,239 this-lines (17.1%), com.k.todo 4,246 of 23,573
(18.0%). Three byte-exact gates decide whether the map is safe to print, G12 (offset
inside `instance_size`), G14 (offset against the displacement an implicit getter compiled
to), G15 (the unboxed-fields bitmap against that getter's register width), and all three
report 0 disagreements on all 33 corpus binaries and 44 real apps.

(Virtual-dispatch selector names, once listed here as the remaining achievable refinement,
are now recovered, see Tier 3.4 above.)

## End-to-end on a real app (dwarf_stack_traces_mode)

Running Jadart on a real, separate Flutter app (a "flagcheck" flag-checker, not FluBench)
surfaced the dominant real-world configuration: a default `flutter build --release` sets
dwarf_stack_traces_mode, which STRIPS the Dart class/method/field names out of the snapshot
(snapshot-only recovery then yields short hash tokens like AB, Aba) and emits them instead
into the ELF .symtab / DWARF as qualified `Class.method` symbols for offline stack-trace
symbolication. FluBench's clean build happens to be built with no-dwarf_stack_traces_mode,
which is why its snapshot keeps names; most shipped apps will not.

Jadart handles this with an ELF-symbol backfill (jadart/symbols.py): map each recovered
code range's pc_offset back to the covering .symtab symbol. On the real app this recovered
9666 real function names that the snapshot no longer held, on top of the 7225 string
literals recovered from the snapshot (which include the app's hardcoded flag), with full
100% disassembly coverage (11052 ranges). The hardcoded flag is localized to its exact load
site through a far pool load (the test-phase fix above), and `--disasm
_FlagCheckPageState._checkFlag` resolves the real name to its code. The backfill needs a
.so that still carries a symbol table (an unstripped build intermediate, a debug .so, or a
matching --split-debug-info file); a fully stripped shipped .so loses the names for every
tool. Reproduce against any such .so: `JADART_REALAPP_LIB=<libapp.so> python3
framework/tests/test_core.py`.

## Target resolution: closing a hole in our own fail-loud claim

Fail-loud on an unknown *version* is not enough, because the version hash does not identify
the parse profile. Part of the cluster grammar is chosen by a build flag: `ReadCluster` gates
on `#if !defined(DART_COMPRESSED_POINTERS)` (app_snapshot.cc:9391) and routes String,
PcDescriptors, CodeSourceMap and CompressedStackMaps to `RODataDeserializationCluster`, whose
`ReadFill` is empty and whose payload lives in the data image rather than the stream.

Measured on this corpus: the arm64, x64 and arm32 builds of one app all carry the identical
hash `ace654289f5abc240509fc941453ebc5`, but arm32 is `no-compressed-pointers`. Jadart used to
resolve it to the compressed profile and walk 437 clusters with the alloc-pass self-check
(`assigned == num_objects`) **passing**, because the ROData alloc pattern also reads exactly
one varint per object; it only failed later, in the fill pass. That is a silent-wrongness
window inside the project's headline correctness gate.

The profile key is now `(hash, architecture, pointer model)`. An unimplemented target raises
`UnsupportedTarget` naming the offending token, before any snapshot byte is consumed, and
`--lenient` does not bypass it: lenient means "this version is unknown, try anyway", whereas a
known version on an unimplemented pointer model is a grammar we know to be wrong. arm64 and
x64 share a grammar key, which is why the snapshot layer already parses x86_64 unmodified.

Two related defects found in the same audit and fixed: `user_classes()` used the bundled cid
table's boundary (176) instead of the epoch's (175), silently dropping the class at cid 175
(`Vector4`) from every Tier 0 listing; and `ReadRefId` was an unbounded loop, where
datastream.h expands its `STAGE` macro exactly four times (28 bits) and then asserts, so a
desynced stream scanned for the next high-bit byte instead of failing loud.

## Acceptance gates: what "supported" is allowed to mean

`assigned == num_objects` is necessary but not sufficient - it passes on a build whose
pointer model we have no grammar for, because the wrong grammar reads the same *number* of
varints. So "it parsed" cannot be the evidence for claiming a new epoch or target.

What makes a stronger claim possible is that the snapshot encodes several values twice, in
independently-derived places, so agreement cannot survive a misparse. `jadart --verify`
(jadart/verify.py) checks them:

| gate | invariant | on the clean corpus |
|------|-----------|---------------------|
| G3 | CLASS alloc cid list == the Class fill pass's own `class_id`s | 119 predefined, exact |
| G4 | String alloc lengths == the lengths the fill pass re-reads | 9013 strings; pins the alloc->fill boundary to the byte |
| G4b | ROData string objects sit at monotonic offsets and carry string tags | uncompressed targets only, where the pool is not in the stream at all |
| G5 | every ref id lies in `[0, num_objects]` | 20484 checks |
| G6 | INSTANCE alloc `(nfo, size)` == that cid's Class fill fields | 319 clusters |
| G7 | `Function.code_index - 1` == its Code's instructions-table slot | 6849 checks (87% of functions); 238 / 15% on `--obfuscate`, and the ratio is reported |
| G8 | header `instr_table_len` == `rodata.length - first_entry_with_code` | validates 5 header varints + data-image alignment at once |
| G10 | canonical-set `table_length - 2` is a power of two, gaps fit | 6 sets |
| G11 | dispatch table found by its `code_first_ref` anchor and ending *exactly* at the stream end | 29190 entries |

G4 and G4b are a complementary pair, and exactly one of them applies to any given build: a
compressed target keeps its string pool in the stream, an uncompressed one keeps it in the
RO data image and its `ReadFill` is empty. So there are nine Tier-A gates defined and eight
that can run, whichever target you point at, and the string check, the one that pins the
alloc-to-fill boundary, is never the one missing.

The gates are chosen for discriminating power, and that is tested rather than assumed: the
suite perturbs a correct parse in four ways that mimic real grammar errors, a cid
renumbering, an instance-geometry disagreement, a shifted Function fill spec, a miscounted
header varint, and asserts that each is caught by its specific gate.

Measured: **every applicable Tier-A gate (9 to 11 of the 12, by target) on all 33 binaries in this checkout** - fifteen
Dart releases from 2.19.6 to 3.12.2, a 32-bit build of thirteen of them, the clean and
`--obfuscate` FluBench builds, three independently written apps, and an iOS Mach-O dylib.
Two third-party CTF binaries nobody here compiled also pass, and are not counted above
because they are not part of the checkout.

Regenerate this rather than trusting it: `python3 tools/measure.py` prints the tables from
the corpus actually on disk, and `--check` fails if this file has drifted from them. The
numbers here were hand-maintained once, which is exactly how they came to claim eight gates
on five binaries long after there were nine on thirty-three.

A separate Tier B reports plausibility checks (tag decoding, instructions-table
monotonicity) that can pass on a wrong parse and therefore never gate. One candidate was
tested and **rejected**: "the fill pass lands exactly at the roots offset" is not
self-checkable, because `ReadRefId` is high-bit-terminated and self-resynchronising -
perturbing the boundary by -8..+8 bytes still decodes cleanly. G4 and G11 pin that boundary
properly instead.

Rule adopted: a target counts as SUPPORTED only when every Tier-A gate passes on at least
three independent binaries built with that SDK, including one `--obfuscate` build. One
binary is a hypothesis, not support.

## How far does one format profile reach?

A per-epoch parser is only worth building if an epoch covers more than one release, and that
is measurable without building anything. The snapshot version hash is an MD5 over 15 files in
`runtime/vm` (`tools/make_version.py`), so `tools/sdk_source.py` can compute the hash any SDK
tag *would* produce by fetching those files over HTTP, about 2.5 MiB per version, no clone
and no VM build.

Measured across the Dart releases Flutter stable has shipped:

Fifteen epochs are registered and gated, from Dart 2.19.6 to 3.12.2. The full table with
hashes is `jadart --version`, or `python3 tools/measure.py`; the shape of it is what matters
here:

| Dart | epoch family | note |
|------|--------------|------|
| 2.19, 3.0 | `cidcanonical-*` | pre-object-header cluster tag; Record still carries a field-names array |
| 3.1 - 3.3 | `cidcanonical-*` | same tag, three different cid tables |
| 3.4 - 3.12 | `objectheader-*` | the cluster tag becomes an object header word at 3.4 |

Three things follow. A profile usually covers a whole minor line, every 3.11 and every 3.10
release shares one hash, so one profile serves ten releases. That is a measurement, not a
rule: 3.12.0 and 3.12.2 have *different* hashes, so a patch release did touch the
serialization sources. And it gets finer going back - 3.0.0 and 3.0.7 diverge too, so a
tool that assumed "one profile per minor version" would be wrong in both directions, which
is exactly the sort of assumption a hash comparison removes.

The reach is also better than the epoch count suggests. Diffing the AOT-live `ReadAlloc` and
`ReadFill` bodies across all fifteen turned up six format changes in total, and **only one of
them alters how many bytes a cluster reads**. The rest move a serialization cutoff in
`raw_object.h`, repack a bitfield, or renumber an enum - none of which a byte-count diff can
see, and all of which produce a plausible wrong parse rather than a failure. That is the
argument for the gates in one sentence.

It also makes the corpus tractable: one build per distinct hash, not one per release.
`framework/tools/build_corpus.py --plan` prints the table above and marks which are built.

### The Android toolchain is the fragile part, not the Dart one

The obvious way to build the corpus, run `flutter build apk` under each pinned SDK, fails
quickly, and not for any reason to do with Dart. Flutter 3.41.9 dies in the Kotlin DSL with
`Unresolved reference 'jvmTarget'`, because the app's Gradle config was authored against a
newer AGP. Chasing that per version means pinning a JDK and an AGP for each stable, which is
what makes a version sweep sound like a week of work.

None of it is necessary. `flutter build apk` internally compiles Dart to kernel and then runs
`gen_snapshot`, and both tools ship inside every SDK, so driving those two steps directly
produces the same `libapp.so` with no Android toolchain involved:

```
dartaotruntime <engine>/frontend_server_aot.dart.snapshot \
  --sdk-root <engine>/common/flutter_patched_sdk_product/ \
  --target=flutter --aot --tfa --packages .dart_tool/package_config.json \
  --output-dill app.dill lib/main.dart
<engine>/android-arm64-release/<host>/gen_snapshot \
  --deterministic --snapshot_kind=app-aot-elf --elf=libapp.so app.dill
```

That is the same shape as the iOS fixture recipe (gen_snapshot's Mach-O writer), and it
generalises: the corpus depends only on the Dart toolchain inside each SDK, which is exactly
the thing whose format we are trying to characterise.

The check that ties it together: a binary built this way with Flutter 3.41.9 carries version
hash `78da37fed6bf1489361a312568249f3f`, byte-identical to the hash computed over HTTP from
the Dart 3.11.5 tag *before that SDK was installed*. Across every corpus build the predicted
and observed hashes agree **15/15**, so the hash really does identify the format sources, and
a version can be identified before any binary of it exists.

### The desync was ours, not Dart's

With five binaries spanning Dart 3.9.2 to 3.12.2, the honest result splits in two.

**Identification generalises.** `tools/gen_epoch.py` derives an epoch from a release's own
`class_id.h` by preprocessing the `ClassId` enum, and that had to survive real drift to work:
3.12 builds the enum from a single `CLASS_ID_LIST` macro, while 3.11 and earlier write the
body inline with per-family `DEFINE_OBJECT_KIND` blocks and have no `CLASS_ID_LIST` at all.
Expanding the enum itself rather than one macro handles both. Run against 3.12.2 it
reproduces the committed table exactly (175 cids, 0 disagreements).

**The grammar did not drift at all.** Extracting all 53 `ReadAlloc` bodies from both
releases and diffing them pairwise shows exactly one difference, in `MintDeserializationCluster`,
and it is an extra `is_deeply_immutable` argument to `InitializeHeader`: a runtime object-header
flag that reads no bytes. `Deserializer::ReadCluster`'s routing is unchanged apart from renaming
`ImmutableBit` to `DeeplyImmutableBit`. The alloc grammar for Dart 3.11.5 and 3.12.2 is
byte-identical.

The desync was a latent bug in jadart. `_FFI_INSTANCE` was built by matching the "Ffi" name
prefix, on the reasoning that FFI native types have no cluster of their own and get handed to
the generic instance cluster. But `FfiTrampolineData` also starts with "Ffi" and is an ordinary
VM object with its own FIXED cluster. Routing it as an instance reads two extra varints
(`next_field_offset` and `instance_size`) and desyncs everything after it.

It stayed invisible for one reason: the 3.12.2 corpus app contains no `FfiTrampolineData`
cluster. Every other binary does. So a bug in the grammar of what was then the only supported
epoch was masked by the only epoch it was tested on, and it presented as "the format drifted"
on every other version. Fixing the routing and adding the missing `FfiTrampolineData` fill spec (4 refs from
`ReadFromTo`, then `Read<int32_t>` and `Read<uint8_t>`, identical in both releases) was the
entire change.

One concrete drift did fall out of the comparison, previously suspected but unconfirmed: the
object header's **immutable bit moved from 6 to 7**. A canonical String cluster tag reads
`0x5d042` on 3.11.5 and `0x5d082` on 3.12.2. `ClassIdTag` itself is unchanged
(`BitField<..., SizeTagBits::kNextBit, 20>` in both), which is why the cid still decodes.

So the three other epochs are listed in `versions.py` as **identified but unsupported**, with
an empty grammar set. Jadart reports "dart 3.11.5, identified, no validated cluster grammar"
instead of "unknown version" - more useful, and still a refusal. Supporting one is now a
bounded task rather than an open question: derive that release's per-cluster ReadAlloc deltas
and confirm them with `--verify` against the corpus binary that already exists.

## Third-party evidence: 48 real apps nobody here compiled

Everything above this section is measured on flubench, which is fifteen epochs of ONE app,
the one we wrote. That is a controlled corpus and it is why the gates are byte-exact, but
it can only exercise Dart features we thought to put in the app. It cannot fail in a way we
did not imagine.

`tools/appsweep.py` widens the evidence to F-Droid. It range-reads each APK's zip central
directory to find `lib/arm64-v8a/libapp.so` without downloading the APK, then range-fetches
just that member. 700 probes found 174 Flutter apps in about eight minutes; 48 snapshots
cost roughly 200 MB of transfer instead of the 3 GB the APKs would have.

| | |
|---|---|
| real apps swept | 48 |
| pass all 8 Tier-A gates | **44** |
| refused: version hash not in the registry | 4 |
| missing cluster grammars | **0** (after LibraryPrefix) |
| epochs exercised by third-party code | **13 of 15** |
| cfgcheck edge violations, 37 apps lifted | **0** |

Epoch spread: 2.19.6, 3.2.6, 3.3.4, 3.4.4, 3.5.4 x3, 3.6.2 x4, 3.7.2 x2, 3.8.1, 3.9.2 x3,
3.10.9 x2, 3.11.5 x7, 3.12.0, 3.12.2 x17.

**What this found.** One missing cluster grammar, `LibraryPrefixCid`, `import ... deferred
as`, which flubench never used because we never wrote one. FluffyChat 1.29 died on it at
cluster #1080 of 1090. Everything else parsed with the grammar already present, which says
the format coverage was genuinely wider than one app could demonstrate.

**What it did not find, and the honest reading.** Zero further grammar gaps across 47 apps
and 16 epochs. Four apps could not be placed at first, and the note here used to say their
hashes matched no stable release from 2.19.0 through 3.13.1 nor any recent beta. That was
not a fact about the hashes, it was the reach of the search: running `sdk_source.py
--identify` over ALL 46 stable 2.x tags, ALL 76 stable 3.x tags and then ALL 101 beta tags
places three of the four. One is a stable patch release the earlier sweep had skipped
(3.0.1), and two are betas, 2.19.0-444.2.beta and 3.3.0-174.2.beta. All three pass every
Tier-A gate on the app that carries them, which is what earns a profile here.

The remaining one is bracketed rather than guessed. Its features string has `no-msan`,
which dart.cc gained at 3.5.0, and no `shared_data`, which it gained at 3.9.0, so the build
is a 3.5.x-3.8.x dev revision; every stable and every beta in that window reproduces a
different hash, which leaves 1,601 dev tags at a 2.5 MiB fetch each. Registered in
`_UNIDENTIFIED` with that bracket so the next attempt starts from it.

What survives of the original reading is the shape, at a twentieth of the size: a registry
enumerated from stable releases alone has holes, because a Flutter beta pins a Dart build
that is a release of its own and an app published from it carries that hash for ever. One
app in 48 rather than four. Refusing it by name, with the `--identify` line that would
place it, is still the correct behaviour rather than a gap to close by guessing.

## Failure taxonomy (the gaps a new tool must cover)

1. Version-ID: silent fallback (unflutter) -> confidently-wrong output or
   mid-parse crash (its issue #1). FIX: fail loud on unknown epoch (Jadart does).
2. Version reach: unflutter hand-codes each format (caps documented at 3.10.7;
   3.11/3.12 only for exact hashes); Blutter recompiles the SDK per version.
   FIX: version-parameterized grammar with auto-generated cid/field skeletons
   (DESIGN.md section 7).
3. Obfuscation: names are gone from the snapshot; no tool recovers them (only
   string xrefs survive to locate a function). Semantic renaming is open (could
   use cross-build diffing or an offline LLM; a research bet).
4. Decompilation: every tool stops at (annotated) assembly or Ghidra-C; none
   emit Dart or structured pseudo-Dart. This is the headline gap (C4). CLOSED by
   Jadart Tier 2 (control flow) + Tier 3 (expressions): `libapp.so` -> named
   pseudo-Dart statements. Tier 3.4 additionally names virtual calls from the
   serialized dispatch table, which not even Blutter decodes. Field names remain
   impossible (AOT strips them); that is a property of the format, not a tool gap.
5. Scope: Blutter is Android-arm64 only; iOS is unsupported across the board. CLOSED for
   the snapshot layer by Jadart: Mach-O containers are read, and the uncompressed-pointer
   grammar iOS uses (RODataDeserializationCluster, identifier pool in the RO data image) is
   implemented and passes 8/8 gates. The corpus objection turned out to be false, since
   Flutter 3.44.4 gen_snapshot writes App.framework itself, so a production-identical iOS
   artifact builds from the cached ios-release gen_snapshot with no Xcode at all.
6. Split snapshots / deferred units: not covered here yet; add to the corpus.

## Pending

- A Blutter backend and a setup-cost writeup, to fill the Blutter rows above.
- A multi-Dart-version sweep of the other tools, to fill the version-robustness axis.
  Running unflutter across the corpus is also what measures its silent fallback.
- A Ghidra-plus-scripts backend, for the pseudocode column.

Each of these is scoped in [CONTRIBUTING.md](CONTRIBUTING.md) and needs no Jadart internals.

## How to reproduce

```bash
bash flubench/run.sh                    # unflutter rows
cd framework && python3 -m pytest tests -q   # jadart core validation
```
