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
| Jadart (T3.4) | clean | 100% | 100% | 100% | expressions + **named virtual calls** (`x2.addListener(...)`) | yes | fail-loud |
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
corpus ~74% of dispatch sites recover both the receiver and the offset, and 2,580 of the
clean fixture's 3,333 (77.4%).

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
immediate is `selector_offset - kOriginElement`. A method defined in a concrete class C
occupies C's own row, giving `selector_offset = k - cid(C)`; every class defining the same
selector must independently produce the same number. That redundancy is the check. On the
corpus `get:hashCode` is corroborated by 127 distinct defining classes, `toString` by 67,
`build` by 48, `createState` by 46, `createRenderObject` by 42, `dispose` by 40 - the entire
Flutter widget lifecycle, each at its own offset. A name is emitted only with >= 2 agreeing
classes, and an offset claimed by two names is dropped.

An offset is not always one selector's. The table is packed by row displacement, so two
selectors whose classes never meet can take the same offset, and the immediate at a call
site does not say which of them it calls. A function defined in class C fills its
selector's cell in the row of every concrete class at or below C that inherits it, and no
other (an abstract class has no row), so its offset is the one at which all of those
classes have it. An offset is named only where every function placed there spells the one
selector, a function with no name counting as another one unless a class above it defines
the selector, and where no function that fits more than one offset fits it unless its own
selector's vote places it elsewhere: `findRenderObject`'s `renderObject` shares its offset
with `handleTapUp`, `encodeMethodCall` and `get:notify` and prints `sel_0x<off>`, and the
offset `perform` had, where 122 calls of `.length` printed `.perform()`, holds nine
functions with no name, iterables' `length` getters among them. A sharer can also be
invisible to all that, a getter whose code is a `return false` some other function owns:
the clean build's `.textScaleFactor`, a double getter, was printed for a call whose result
is tested as a bool (#128). So where a selector's implementations return a double in d0
and a call site reads its result from x0, the call is not given the name.

Measured (clean build, 0 exceptions): 133 selectors recovered; of the 2,580 dispatch sites
whose offset is recovered, 607 have a named offset (23.5%), counted over every function's
`detect_dispatch` sites; the x0 check leaves 2 of them unnamed. By that count it was 974
(37.8%) with the 168 names the vote alone accepts; the 318 of 1,108 given here before were
counted with an older lifter. The vote has to be untied as well: `Counter.most_common` had
been breaking a tie by insertion order, so 144 names rested on which candidate happened to
be counted first. Those stay `sel_0x<off>`, which is the honest rendering. Property
selectors render as accessors (`x0 = this.foo;`) rather than calls.

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
`instance_size` with none outside. Those are printed by name wherever the base's
class is stated. That was `this` alone until a class's own allocation stub was read as the
statement of what a `bl` allocates, and until a surviving accessor was read as the name of
the slot its whole body touches (both #240): on the clean fixture the three channels clear
1,793 of the 55,089 lines that would otherwise carry a byte offset, 1,734 of them on
`this`.

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
site through a far pool load (the test-phase fix above), and
`--disasm _FlagCheckPageState._checkFlag` resolves the real name to its code. The backfill needs a
.so that still carries a symbol table (an unstripped build intermediate, a debug .so, or a
matching --split-debug-info file); a fully stripped shipped .so loses the names for every
tool. Reproduce against any such .so:
`JADART_REALAPP_LIB=<libapp.so> python3 framework/tests/test_core.py`.

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

## The field in November 2026, re-measured on the same bytes

The table at the top of this file was run in Phase 0. Three things about it have
expired, and one of them is the tool every row was scored against.

**unflutter's upstream is gone.** `zboralski/unflutter`, the Go snapshot analyzer those
rows were measured against, has been removed by its author. A community continuation
sits at `KristijanZic/unflutter`, and the maintained successor is `BroNils/aotopsy`, a
fork that adds x86_64, a decompiler, whole-program type inference and Frida export. The
unflutter rows stay as a record of what was measured then, because they cannot be re-run
from the source they were measured against.

**Two tools emit pseudo-Dart now.** Taxonomy item 4 below said every tool stops at
annotated assembly or Ghidra C. That was true when it was written and is false now:
AOTopsy writes a `.dart` file per function, and `caverav/flutterdec` (Rust,
0.1.0-alpha.2) writes `.dartpseudo`. The claim that survives measurement is narrower and
it is the one below about selector names.

**Blutter is unchanged in shape:** Android arm64 only, and a per-version Dart SDK
compile.

### AOTopsy, head to head on the committed fixtures

Built from `main` on 2026-11-06 with `go build ./cmd/aotopsy`, which takes 3.2 s and
needs nothing but a Go toolchain, then run on the same two fixtures jadart is measured
on. Every number below is from one run of each tool over every code range of the clean
fixture.

| axis | jadart 1.3.0 | AOTopsy |
|---|---|---|
| wall clock, whole image | 5.75 s `lift`, 4.55 s `export` | 12.8 s analyze, 21.0 s with `--decompile` |
| code ranges rendered | 8,194 | 8,194 |
| lines of pseudocode | 185,227 | 261,039 |
| field accesses printed | 71,036, of which 2,693 by name | 71,068, of which 0 by name |
| named (class, offset) pairs in the field map | 2,019 over 504 classes | 1,987 instance slots over 1,917 classes |
| dispatch sites | 3,333, 2,580 with receiver and offset (77.4%) | 3,425, 2,319 with an offset (67.7%) |
| dispatch sites given a SOURCE NAME | 607, from 133 decoded selectors | 0 |
| allocations naming their class | 3,848 of 4,425 `new` sites | 0 of 918 `AllocateObject` sites |
| `goto` lines | 5,493 (3.0%) in 1,414 of 8,194 functions | 31,500 (12.1%) |
| code the renderer leaves out | none, and `tools/cfgcheck.py` checks every rendered edge against the CFG for every block in the image | 5,223 `code omitted by the structured walk` notes, 8,322 orphan-block notes |
| iOS / Mach-O | parses an App.framework dylib: 2,248 classes, 8,153 members, 11,169 strings, and lifts its bodies | `error: open: elfx: not an ELF file`, exit 1 |
| exceptions over both fixtures | 0 over 16,382 ranges | 0 over 16,382 ranges |

Field accesses are counted with the same regex on both sides, over the lifted body of
every range. That the two totals land within 32 of each other on 71,000 accesses is the
check that they are looking at the same thing.

### What that looks like on a function whose source is public

`vault_logic`'s `LicenseVault` is an app with the Dart source in the repository, so the
three bodies below have a right answer rather than a plausible one.

`withdraw`, source `if (amount > balance) return false; balance -= amount; return
true;`. Both tools get it right, and AOTopsy reads better: it puts the positive branch
first, it prints 250 in decimal, and it names the incoming argument. jadart prints `if
(this.field_0x8 < 0xfa)` with the inverted test and the hex literal, though it does name
the receiver `this` where AOTopsy calls it `accumulator`.

`classify`, a four-way comparison chain returning string literals. Both correct. AOTopsy
prints the bounds as 40 and 80, jadart as 0x28 and 0x50.

`checksum`, source `acc = (acc * 31 + b) & 0xffffffff` over a list. jadart recovers the
loop and the accumulator:

```
var t0 = x1.field_0xc;
var t1 = 0;
var t4 = t0.field_0x8 >> 1;
var t5 = 0;
while (true) {
  if (t5 >= t4) break;
  t1 = ((t1 & 0xffffffff) * 31 + (t0[t5] & 0xffffffff)).toUnsigned(32) & 0xffffffff;
  t5 += 1;
}
return t1;
```

AOTopsy returns 0 from the first comparison, loses the accumulator, the multiply, the
mask and the element read, and marks the rest omitted:

```
while (true) {
  block_2:;
  if (0 >= arg2) { return 0; }
  else if (classId(arg1.f11) << 1 != 188) { block_6:; continue; }
  else { goto block_6; }
}
// --- code omitted by the structured walk, shown verbatim ---
```

That is the shape of the whole comparison. AOTopsy renders a body more pleasantly where
it renders one; jadart recovers more of what the body does.

### The real-app result, which goes the other way

The fixtures above are one app we wrote. FluffyChat's current F-Droid build
(`chat.fluffy.fluffychat`, a 26.1 MB `libapp.so` pulled by `tools/appsweep.py`) is an app
neither tool was tuned on, and it is Dart 3.13.0. AOTopsy parses it: 88,618 functions,
10,679 classes, 12 s. jadart refuses it. The refusal is correct rather than a bug, since
3.13 is past the newest registered epoch, but on the version-reach axis the competitor is
ahead today for anything built with the current Flutter stable.

Two separate things stop us and both are bounded. The epoch is unregistered (hash
`0451907c2eaa8467e848c0067bfe8ed4`). And 3.13 changed the container: that build exports
`_kDartSnapshotData` and `_kDartSnapshotText`, where every earlier release exported
`_kDartVmSnapshotData`, `_kDartIsolateSnapshotData` and their instruction pairs, and the
`.so` has no `.symtab` at all, only those three in `.dynsym`. `jadart info` survives it
because it falls through to the magic scan and reports the unknown epoch by name, while
`verify`, `classes`, `decompile` and `export` ask for `_kDartIsolateSnapshotData` directly
and refuse with `no symbol '_kDartIsolateSnapshotData' in this ELF. If this is a Flutter
app, the snapshot is in libapp.so, not here`, which is the wrong reason for a file that is
libapp.so.

Seven snapshots were pulled for this section with `tools/appsweep.py`, out of 199 Flutter
apps a partial probe of F-Droid's largest packages turned up. jadart identifies six of the
seven and refuses only FluffyChat; AOTopsy identifies all seven. Where both identify a
build they agree on the era and differ on the label: we name the stable release we
registered the hash under (3.11.5, 3.5.4, 3.3.4, 2.19.6), AOTopsy names the era (3.11.0,
3.5.0, 3.3.0, 2.19.0). Neither is wrong, because one format hash covers several patch
releases.

On the six it reads, jadart's acceptance gates pass on every one: Tier A 11 of 11 and
Tier B 3 of 3 on each, between 120,163 and 364,740 byte-exact checks per app and 1,257,569
in total, with no failures. These are apps nobody here compiled, across five Dart
versions.

The output comparison also holds away from our own fixture. On `kzs.th000.tsdm_client`
(Dart 3.11.5, 16 MB, 48,906 functions), the two tools agree on the shape of the image and
split the same way they do on FluBench:

| axis | jadart | AOTopsy |
|---|---|---|
| lines, whole image | 857,974 in 98 s | 1,306,702 in 143 s |
| lines carrying an unnamed value | 66,037 (7.7%) | 429,316 (32.9%) |
| lines carrying an unnamed field | 274,186 (32.0%) | 246,001 (18.8%), none named |
| `goto` lines | 18,951 (2.2%), in 10.7% of functions | 145,533 (11.1%) |
| dispatch sites | 16,630, 8,073 with receiver and offset (48.5%) | 16,961, 6,455 with an offset (38.1%) |
| dispatch sites named | 1,524, from 893 decoded selectors | 0 |
| code left out of the rendering | none | 27,525 notes |

### Refusal behaviour, which is the axis this file was started for

Five malformed inputs built from the clean fixture (truncated at half, truncated after
the header, 256 KiB of the payload XOR 0xff, empty, ELF header only): both tools refuse
all five, neither crashes and neither hangs. jadart exits 2 with a typed message,
AOTopsy exits 1 with an error. The DoS and untyped-failure half of the threat model is a
draw.

An unregistered version hash is not. Relabel the clean fixture with a hash no registry
holds and jadart refuses before parsing, naming the hash, the span it supports and the
command that would place the build (exit 2). AOTopsy picks a grammar anyway and dies
inside the fill pass, `cluster 332 (String CID 93): string 17/23 data: stream:
unexpected end of data` (exit 1), on bytes that are in fact Dart 3.12.2: the fallback it
chose does not fit the file it was handed. `aotopsy doctor` on the same file prints
`Support: OK` with an empty Dart version, which is the one answer in this comparison
that is actively misleading. Neither tool emits a fabricated object graph, so the
outcome is the same and the difference is the quality of the refusal.

Relabel it as a different grammar era instead (3.12.2 bytes carrying the 2.19.6 hash)
and both refuse with the offending cluster named: jadart `no alloc pattern for cid 2
(FreeListElement) under epoch cidcanonical-2.19`, AOTopsy `cluster 34 (CID 2): unknown
fill kind 21`. Relabel it within an era (the 3.10 hash) and both parse, both report the
version the label claims, and jadart's gates pass 11 of 11 Tier A and 3 of 3 Tier B over
66,323 checks. That is the honest result rather than a miss: the version label is read
from the file, and where two epochs share a grammar for the clusters an app uses,
nothing in the bytes contradicts it.

One defect to report upstream: AOTopsy's pseudocode prints the raw tagged displacement
as its field token, so `balance`, which its own `classes.jsonl` records at byte offset
8, prints as `.f7`, and an array's first element at offset 16 prints as `.f15`. The two
outputs cannot be cross-referenced without knowing to add one.

### What AOTopsy has that jadart does not

x86_64 decompilation, a claimed span of Dart 2.10 through 3.13 against our 18 epochs
from 2.19, IDA, Ghidra, Frida, SARIF and DOT export, behavioural keyword classification,
a function-fingerprint dictionary for unnamed code, and an import path for darter's
output on older versions. Its name-recovery agreement against each build's own ELF
`.symtab` is reported as 90.2% over 44 ground-truth builds, which is a measurement
jadart does not have an equivalent of.

Three things in its renderer are better than ours and are worth taking: an incoming
argument prints as `arg0` where we print `x2`, a comparison against an untagged constant
prints in decimal where we print hex, and the positive arm of a two-way branch comes
first. None of them changes what is recovered; all three change how much of it a reader
can hold.

### flutterdec, read rather than run

`caverav/flutterdec` (Rust, 7 crates, 123 dependencies, 0.1.0-alpha.2) advertises
readable pseudo-Dart with named Flutter selectors for Android arm64. The naming is not a
dispatch table decode: `crates/flutterdec-decompiler/src/helpers/selector_table/` holds
329 lines of hardcoded selector tables (`FLUTTER_SELECTORS`, `DART_CORE_SELECTORS` and
four more), and `classify_standard_selector` normalises a string it already has and
looks it up in them. It can therefore label a call whose name is already present as a
string and cannot name a selector that is not in its tables. It was not built or run
here, because a Rust toolchain is a 1.5 GB llvm download on this host; what is stated
above is from its source.

### Blutter, and what it costs to get an answer out of it

Not run. The setup, measured from its README and `blutter.py` rather than guessed: a
C++20 compiler (g++ 13 or clang 16 and up), `cmake`, `ninja`, `pkg-config`, `icu4c`,
`capstone`, `pyelftools` and `requests`, and then, for any Dart version whose `blutter`
executable is not already built, an automatic checkout and compile of the matching Dart
SDK. It also needs `libflutter.so` next to `libapp.so`, because that is where it reads
the version from; a bare snapshot needs `--dart-version <version>_<os>_<arch>` supplied
by hand. Our fixtures ship `libapp.so` alone, which is the common case for an iOS build,
a split APK, or a snapshot pulled out of an archive, and it is the case Blutter cannot
start from unaided.

### How to reproduce this section

```bash
git clone --depth 1 https://github.com/BroNils/aotopsy && cd aotopsy
go build ./cmd/aotopsy
LIB=<jadart>/flubench/artifacts/clean/lib/arm64-v8a/libapp.so
./aotopsy $LIB --out /tmp/aot --decompile --all -q
find /tmp/aot/dart -name '*.dart' -exec cat {} + | grep -c 'dispatchCall(selector:'
cd <jadart> && .venv/bin/jadart lift $LIB benchComputeChecksum
.venv/bin/python framework/tools/quality.py $LIB
```

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
4. Decompilation: in Phase 0 every tool stopped at (annotated) assembly or
   Ghidra-C. That is no longer the field: AOTopsy and flutterdec both emit
   pseudo-Dart as of 2026 (see the section above, which measures AOTopsy's against
   ours on the same bytes). What no tool does is resolve a virtual call to its
   source selector name out of the serialized dispatch table: AOTopsy recovers the
   offset for 2,319 of 3,425 sites and names none, flutterdec matches known names
   from a hardcoded table, Blutter prints `GDT[cid_x0 + 0x4778]()`. Field names are
   not impossible either, as this file said: 2,693 of the clean fixture's 71,036
   field accesses are printed by name from three channels (#240).
5. Scope: Blutter is Android-arm64 only, AOTopsy is ELF only and refuses an iOS
   dylib, flutterdec is Android arm64 only, so iOS is unsupported elsewhere. CLOSED for
   the snapshot layer by Jadart: Mach-O containers are read, and the uncompressed-pointer
   grammar iOS uses (RODataDeserializationCluster, identifier pool in the RO data image) is
   implemented and passes 8/8 gates. The corpus objection turned out to be false, since
   Flutter 3.44.4 gen_snapshot writes App.framework itself, so a production-identical iOS
   artifact builds from the cached ios-release gen_snapshot with no Xcode at all.
6. Split snapshots / deferred units: not covered here yet; add to the corpus.

## Pending

- A Blutter run, to fill the Blutter rows above. Its setup cost is measured in the
  section above; what is missing is the output.
- A multi-Dart-version sweep of the other tools, to fill the version-robustness axis.
  AOTopsy claims 2.10 through 3.13 over 93 sample builds; only its 3.12 behaviour is
  measured here.
- A Ghidra-plus-scripts backend, for the pseudocode column.
- A real-app comparison. Both tools agree closely on the committed fixtures, which are
  one app we wrote; the apps in `tools/appsweep.py`'s F-Droid set are the ones neither
  tool was tuned on.

Each of these is scoped in [CONTRIBUTING.md](CONTRIBUTING.md) and needs no Jadart internals.

## How to reproduce

```bash
bash flubench/run.sh                    # unflutter rows
cd framework && python3 -m pytest tests -q   # jadart core validation
```
