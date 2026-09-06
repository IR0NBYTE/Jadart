# Flutter/Dart RE research: baseline findings

**This is the survey that came BEFORE the framework, kept as written.** It records what
the off-the-shelf offline toolchain could do against Dart 3.12.2 in August 2026, which is
the baseline `framework/` was built to beat. Two things have moved since and are marked
inline: capstone is installed and is what the framework runs on, and several of the open
questions below are answered in EVAL.md. Blutter and Ghidra are still not usable here, so
nothing in this repo compares itself against them.


Goal: map what the offline reverse-engineering toolchain can and cannot do against
modern Flutter (Dart AOT) apps, and find where the real limits are. Everything here
runs locally, no cloud, no paid API.

## Test target

`flagcheck`, a locally built app on Flutter 3.44.4 / Dart 3.12.2.
A single screen: text field + button + `if (input == 'YINKO{fl4gs_1n_d4rt_aot}')`.
Two APKs built for comparison:

- clean: `flutter build apk --release`
- obfuscated: `flutter build apk --release --obfuscate --split-debug-info=build/symbols`

Snapshot build-id (both): `ace654289f5abc240509fc941453ebc5`. Flag string lives at
`.rodata:0x23893` inside `_kDartIsolateSnapshotData`; compare logic lives in
`_kDartIsolateSnapshotInstructions` (.text).

## Environment

- Flutter 3.44.4, Dart 3.12.2, Android SDK (platforms 34/35/36), JBR 21 (NOT JDK 25).
- radare2 / rabin2, jadx, apktool, frida (python), nm/objdump/strings: installed.
- Go 1.25.4: installed. unflutter: built from source in this workspace.
- Blutter: cloned, NOT built (no compiled binary, no Dart SDK). Ghidra: NOT
  installed. capstone (python): **installed since**, along with unicorn, the
  framework's disassembly and its differential oracles both rest on them.
- Xcode / CocoaPods: absent, so iOS is out of scope on this machine.

## Tool results vs Dart 3.12.2

| Tool | Result | Limitation |
|---|---|---|
| strings | flag literal recovered instantly, clean AND obfuscated | strings only; no logic or structure |
| radare2 raw | disassembles ARM64; IDs lang=dart; sees the 5 snapshot blobs | no function boundaries/names; lands on the snapshot header as "invalid"; no Dart-ABI awareness |
| unflutter | parsed 3.12.2: 11058 funcs, 2321 classes, 95.3% call resolution, string xrefs; clean build recovered `_FlagCheckPageState._checkFlag` by name + annotated the flag in the pool | see notes below |
| Blutter | not tested | needs a compiled Dart 3.12.2 SDK; heavy on macOS with no Xcode CLT |
| Ghidra + unflutter scripts | not tested | Ghidra not installed; would add C-like pseudocode via the `__dartcall` convention |

## Key result: obfuscation vs unflutter

- Clean build: readable names recovered (`FlagCheckPage`, `_checkFlag`). Read the check directly.
- Obfuscated build: those names are stripped; the same functions come out as
  `stub_6e444` / `stub_116b28`. The string cross-reference still survives, so unflutter
  pinpoints exactly which anonymous functions load the flag. The crack path holds:
  find the string, find its xref, that is the check. You lose the name, not the location.

Practical takeaway: `--obfuscate` renames identifiers but does NOT encrypt string
literals, so for any crackme that stores its secret as a literal, the offline toolchain
solves it trivially (strings alone, or unflutter to locate the check).

## unflutter limitations logged

1. No positive version identification for Dart 3.12.2. It printed no "Dart SDK" banner
   and `dart_meta.json` carries no build-id/version; it silently fell back to its
   newest-known model (3.4.3-3.10.7 ObjectHeader tag style). Correct here (verified
   against the clean build), but an unverified fidelity risk for other 3.11/3.12 apps.
2. Obfuscated identifier names are unrecoverable (they are gone from the snapshot).
3. Output is annotated assembly, not decompiled Dart. Runtime-stub calls (string
   equality, etc.) show as raw BL offsets, so reading the actual comparison still means
   reading Dart-ABI assembly (X26 thread ptr, X27 pool, X28 heap base, compressed ptrs).
4. Needs Graphviz for SVG render (not installed; JSON/DOT still produced).

## Open questions for the project

Four of these are answered, and the answers live in EVAL.md and framework/README.md
rather than here: version identification across releases (fifteen format epochs keyed on
version hash, architecture and pointer model, so a release with no registered grammar
fails loudly instead of being guessed at), fidelity across versions jadart cannot
positively ID (the acceptance gates run on 33 binaries over 13 epochs, including real
F-Droid apps), whether annotated assembly can become readable Dart (Tier 3 does, at 23.6%
bare registers on the clean build), and whether obfuscated builds keep their structure
(they do; the names are gone, the call graph and string xrefs are not).

The rest stand, and two of them cannot be answered on this machine at all:


- unflutter fidelity across Dart versions it cannot positively ID. Build the same app on
  Dart 3.8 / 3.10 / 3.11 / 3.12 and diff name-recovery and xref correctness.
- Blutter on macOS: is the SDK-build feasible without Xcode CLT, and does it beat
  unflutter on obfuscated builds (object-pool fidelity, Frida hook generation)?
- Does Ghidra + unflutter's `__dartcall` convention turn the recovered `stub_*` functions
  into readable pseudocode for the comparison?
- Hardened targets: rebuild the flag check to defeat strings (SHA-256 compare, runtime
  XOR-decrypt, char-by-char). Where does the static offline path break, and does dynamic
  Frida (hook the compare on an AVD) or a local-LLM asm summarizer (r2ai + Ollama) close
  the gap?
- Anti-RE: add root/Frida detection and measure how much of the toolchain still works.

## Experiment matrix (to run)

- Dart version: 3.8, 3.10, 3.11, 3.12
- Obfuscation: off, `--obfuscate`, `--obfuscate --split-debug-info`
- Flag storage: literal, hash-compare, runtime-decrypt, char-by-char computed
- Tools: strings, radare2, Ghidra(+unflutter), unflutter, Blutter, Frida (dynamic), r2ai+Ollama
- Metrics: name-recovery %, can-you-find-the-check (Y/N), offline-only (Y/N), version
  robustness, analyst effort.

## Phase 0 (FluBench) baseline

Harness built (flubench/): a labeled construct app (8 constructs), a source->ground-truth
extractor, and a scorer that runs a tool and measures symbol recall. First tool scored:
unflutter, Dart 3.12.2, arm64.

Scorecard (recall vs ground truth):

| build | classes | functions | strings |
|-------|---------|-----------|---------|
| clean | 1/1 (100%) | 9/9 (100%) | 1/1 (100%) |
| obfuscated | 0/1 (0%) | 0/9 (0%) | 1/1 (100%) |

Reading: on a clean build unflutter recovers everything (names, class, string literal),
near-perfect fidelity even though it cannot positively identify Dart 3.12.2. Obfuscation
zeroes name recovery (identifiers are stripped from the snapshot) while string literals
survive (--obfuscate does not encrypt them).

Two methodology findings from Phase 0 (both were bugs that made the FIRST run meaningless,
and both generalize to every future construct):

1. The corpus must be optimizer-resistant. The first corpus passed constant arguments, so
   AOT constant-folded literals and inlined whole functions away; `strings libapp.so` had 0
   hits for those literals. It was measuring the optimizer, not the tool. Fix: every
   construct gets @pragma('vm:never-inline') and inputs are threaded from a runtime seed
   the compiler cannot fold.
2. Ground-truth extraction must exclude non-data string literals. The extractor first mined
   import URIs (dart:convert) and @pragma annotation args (vm:never-inline) as "strings",
   polluting the string metric. Fix: strip import/export/part directives and @pragma(...)
   before mining literals.

Both rules are now enforced in flubench/ and documented in flubench/README.md. This is the
value of Phase 0: establish a measurement you can trust before comparing tools.

Next: add a Blutter backend to the scorer, sweep Dart versions (FVM), and add Tier 1+ body
fidelity (compile-and-diff) so the benchmark grades decompilation, not just name recall.

## Phase 2 (jadart parser core) baseline

Built framework/jadart, a dependency-free byte-exact snapshot parser (header, version epoch,
counts, cluster tags), validated against the Dart 3.12.2 build (6 passing tests):

- Version hash extracted exactly (ace654289f5abc240509fc941453ebc5).
- The base-objects invariant holds: isolate.num_base_objects (1081) == vm.num_objects (1081),
  because the isolate snapshot's base refs are the VM snapshot's objects. Strong correctness
  signal that both count blocks parsed.
- Isolate snapshot: 54145 objects, 356 clusters; first cluster cid decodes to 93 (sane
  predefined range), confirming the tag-bit layout (cid = bits 12-31).
- Fail-loud: an unknown (hash, features) epoch raises rather than guessing. This is the
  headline correctness fix over unflutter's silent fallback.

New measured finding (via jadart): obfuscation removes ~43% of snapshot objects
(clean 54145 -> obf 30969, delta 23176) at nearly constant cluster count (356 -> 355). Those
23k objects are the stripped name strings. This is the quantified reason name recovery drops
to 0% under --obfuscate: the identifiers are not merely hidden, they are absent from the
binary. String literals remain (they are separate constant objects, not identifiers).

## Phase 2 M2 (full alloc walk + name recovery)

jadart now walks the ENTIRE alloc pass and recovers names, not just counts. It lands exactly on
num_objects (54145 clean, 30969 obf), reading all 356 (clean) / 355 (obf) clusters byte-exactly,
a strong self-check: any wrong per-cluster read pattern desyncs the varint stream and misses the
count. It then reads the canonical String cluster's fill for the interned identifier pool.

Name recall vs FluBench ground truth (equal to unflutter, the prior best):
- clean: classes 1/1 (100%), functions 9/9 (100%), strings 1/1 (100%). Also recovered
  _FluBenchPageState, benchRunAll, and the source URI package:flubench_corpus/constructs.dart.
- obf:   classes 0/1, functions 0/9, strings 1/1 (the literal survives; identifiers are gone).
Recovered identifier pool: 8990 canonical strings clean, 6025 obf (the ~2965 difference is the
stripped identifier names). Reproduce: `python3 flubench/score.py --truth
flubench/artifacts/ground_truth.json --jadart-lib <libapp.so>`.

Version-drift found and fixed (the C3 version-robustness thesis, demonstrated): the SDK source is
checked out at main (3.13-dev), one version ahead of the 3.12.2 binary. Three format drifts had to
be handled per-epoch, each confirmed against the binary and cross-checked with unflutter's
version-parameterized model:
1. Closure alloc is FIXED in 3.12 (count only); main added a per-object `length` (inline captured
   context) in 3.13. Reading it as variable injected ~1.2M bogus "lengths" and desynced.
2. Class alloc reads predefined_count + predefined x ReadCid(int32) + new_count; main refactored
   this to a plain fixed count. Reading it as fixed under-consumed and dropped the tail clusters.
3. cid numbering shifted: 3.12 has TypedDataInt8Array=112 and NumPredefinedCids=175; main (with 2
   more predefined classes) has them higher, so main's table put FfiStruct at cid 112. Detecting
   typed-data by the main-derived NAME misrouted the last typed-data clusters; keying it to the
   epoch's numeric range fixed it.
All three now live in versions.py as epoch parameters; unknown epochs still fail loud. The cid
table itself is generated mechanically by expanding class_id.h's CLASS_ID_LIST with the C
preprocessor (the same X-macro the VM uses), so a new epoch's low-cid table is a re-run, not
hand-coding.

## Phase 2 M3 (full fill walk -> object graph -> Tier 0 skeleton)

jadart now walks the ENTIRE fill pass, not just the first String cluster. The fill pass runs
every cluster's per-object field data in alloc order; the walker consumes all 356 clusters
byte-exactly and lands on the roots at 0x0e0394 (clean), validated cluster-by-cluster against
unflutter's `--debug-fill` per-cluster offsets. It recovers the full object graph:
- clean: 9013 strings, 7892 functions (name + owner refs), 2350 classes (name refs + cids).
- obf:   6048 strings, 1602 functions, 2298 classes (fewer named funcs; obfuscation strips them).
The non-canonical string literal FLUBENCH{str_literal_compare} now resolves from the full pool.

Resolving the refs gives STRUCTURE, not a flat name list: benchWithdraw is recovered as a
method of class BenchAccount (its Function.owner ref points at the BenchAccount Class object).
`jadart --tier0` emits skeleton Dart - class headers with method signatures - for 1842 named
classes. This is the Tier 0 "JADX moment" (contribution C4); no other Flutter RE tool emits a
structured class/method tree.

Tier 0 enrichment (superclass + member kinds), all from the same fill walk:
- Superclass (`extends`): Class fill ref[9] is super_type (a Type); resolving Type ->
  type_class_id -> Class name recovers the real hierarchy. type_class_id is packed in the
  Type flags word as (flags >> 3) & 0xFFFFF (raw_object.h UntaggedType: NullabilityBit[0,1),
  TypeStateBits[1,3), TypeClassIdBits[3,23)). Verified: FluBenchApp extends StatelessWidget,
  FluBenchPage extends StatefulWidget, StatelessWidget extends Widget, and mixin applications
  like State extends _MixinApplication0&Object&Diagnosticable come out correctly.
- Member kinds: the Function kind_tag (last fill scalar) low 5 bits give the FunctionKind;
  jadart labels constructors (402), getters (747), setters (145) vs plain methods (4121).
- Fields: 332 Field objects survive; most instance fields are tree-shaken by AOT into direct
  offsets (no Field object), so a trivial class like BenchAccount shows its methods but not its
  `owner`/`balance` fields. That is a real AOT recovery limit, not a parser gap.
Example output: `class RenderBox extends RenderObject { RenderBox(); get constraints; get size;
hitTest(); globalToLocal(); ... }`.

## Phase 3 Tier 1 (instructions image + annotated disassembly)

jadart now ties a recovered Function to its actual machine code and disassembles it. The Code
fill captures each code's instructions-table index + owner Function; the InstructionsTable rodata
(a OneByteString in the isolate data image at roundUp(header.length, 64) + instr_table_rodata_offset,
16-byte header then {canon, length, first_entry_with_code, pad} then length x {pc_offset, stackmap}
entries) maps index -> pc_offset in the instructions image. Slicing [pc_offset, next_pc_offset) and
disassembling with capstone (arm64) recovers the method body.

Proof (benchWithdraw, `if (amount > balance) return false; balance -= amount; return true;`):
  ldur x3, [x1, #7]   ; load balance (tagged field at offset 0)
  cmp  x2, x3 ; b.le  ; amount vs balance
  add x0,x22,#0x30 ; ret   ; return false
  sub  x4, x3, x2 ; stur x4, [x1, #7]  ; balance -= amount, store
  add x0,x22,#0x20 ; ret   ; return true
Byte-accurate and semantically exact.

Call-target annotation is the "beats every current tool" step. A pc_offset -> function-name map
(from the code ranges + recovered Function names) resolves direct BL targets. benchRunAll's body
annotates to a readable call graph: `bl -> benchCheckSecret`, `-> benchComputeChecksum`,
`-> benchMakeAdder`, `-> benchFirstOrDefault`, `-> benchWithdraw`, each followed by `-> writeln` -
exactly the source.

ObjectPool load annotation completes it. The pool is loaded into PP (X27); `ldr xN, [x27, #off]`
reads pool entry off//8 (formula confirmed statistically over ~900 loads and by semantic sanity).
Entries that are refs to a String or Function get labelled, so pool loads annotate with the actual
referenced constant: in benchRunAll, `ldr x1, [x27, #0x810]  ; = "charCodes"` (near the string
processing) and `ldr x1, [x27, #0x1238]  ; = "Invalid MIME type"` (next to the base64 encode /
benchDecodeFlag), contextually exact. So a recovered method now reads as annotated arm64 with
BOTH named call targets and named string/const references. unflutter and the others stop at raw
`bl #offset` / `ldr [x27,#off]`; jadart names both. `jadart --disasm <func>` prints the listing.

## Phase 3 Tier 2 (control-flow reconstruction)

A CFG builder (basic blocks split at branch targets / after terminators; calls fall through) plus
a structuring pass (Cooper-Harvey-Kennedy dominators + post-dominators: back edges -> while, merge
points -> if/else) turn a method's annotated disasm into nested pseudo-Dart. benchWithdraw
(`if (amount > balance) return false; balance -= amount; return true;`) reconstructs exactly:
  ldur x3, [x1, #7]      // load balance (x3), amount is x2
  cmp x2, x3
  if (x2 > x3) { ...; return; }                       // if (amount > balance) return false
  else { sub x4, x3, x2; stur x4, [x1, #7]; return; } // balance -= amount; return true
The if-condition is the negation of the branch-taken condition (the then-branch is the fallthrough).
Loops are detected (benchComputeChecksum -> while) and rendered; nested/complex loop BODIES and full
expression lifting (register->value naming) are best-effort, the honest Tier 2/3 frontier. Irreducible
regions fall back to `goto` (never wrong). `--decompile <Class>` uses the structured renderer by
default. 22 tests pass (Tier 2 tests capstone-gated). This is structured pseudo-Dart from a stripped
AOT binary, the C4 decompiler contribution reaching Tier 2 on the common control-flow shapes.

Key fill-grammar facts for the 3.9-3.12 AOT PRODUCT / compressed-pointers profile (ported from
unflutter fill.go/fillspec.go, cross-checked with app_snapshot.cc/raw_object.h, validated by
the byte-exact oracle):
- Fill refs use ReadRefId (big-endian) for Dart >= 2.18 (NOT ReadUnsigned). Getting this codec
  wrong desyncs the entire fill pass; it is the single most important fill detail.
- Class fill: 13 refs (name = ref 0) + class_id + 3 int32 sizes + 2 int16 counts + state_bits +
  a conditional unboxed-fields bitmap (read for predefined classes or non-top-level cids).
- Function fill: 4 refs (name=0, owner=1, signature=2, data=3) + code_index(unsigned) + kind_tag.
- Instance fill (319 of 356 clusters - the bulk): one unboxed bitmap, then per object
  (next_field_offset_in_words - 2) fields, each a ref unless the bitmap marks it unboxed
  (then 2x uint32). next_field_offset comes from the alloc phase.
- Code fill (8194 objects): per main code a payload_info + 6 refs (owner = ref 0); discarded
  codes (state_bits bit 3, captured in alloc) read only compressed_stackmaps.

## Known limit: an irreducible loop is lifted with values it cannot justify

`tools/irfuzz.py --cfg` generates functions and checks what the lifter PRINTS against a real
CPU. It is deliberately restricted to reducible loops, the header dominates its latch,
and this is the reason.

Lift a two-entry loop, where the entry block jumps over the header into the body and the
back edge re-enters at the header, and the walker prints a register value that only one of
the two entries justifies. Reproduction, from the generator (the back edge at 0x3c targets
0x14, which the entry at 0x10 jumps over):

```
0x00  sub x7, x7, x7      0x20  add x2, x3, x13      0x38  sub x7, x7, #1
0x04  add x7, x7, #3      0x24  eor x6, x4, x6       0x3c  cbnz x7, #0x14
0x08  add x5, x9, x8      0x28  cbz x9, #0x4c        0x40  mul x2, x2, x1
0x0c  and x3, x10, x4     0x2c  sub x6, x1, #0x3c    0x44  and x2, x4, x7
0x10  b   #0x20           0x30  add x0, x0, #5       0x48  mul x6, x2, x6
0x14  add x5, x1, #0x26   0x34  add x6, x12, x1      0x4c  add x0, x5, #0x39
0x18  sub x5, x3, #3                                 0x50  ret
0x1c  cbnz x9, #0x4c
```

x5 is `x9 + x8` on the first trip and `x3 - 3` on every later one; the lift says `x9 + x8`.

Why it is a limit rather than a defect worth a fix today: Dart has no `goto`, its front end
cannot emit an irreducible loop, and no loop in any of the 33 corpus and CTF binaries is
one. Every loop `structure` meets in real input has a single entry, which is the assumption
the loop rendering is built on. The generator therefore produces what the tool actually
sees; fuzzing input the tool cannot receive would only stop the oracle being run.

What would fix it: node splitting before structuring, or refusing to render a loop whose
header has a predecessor outside the loop and falling back to `goto` for the whole region.
The second is a few lines and costs nothing on real input, and it is the honest one.

## Memory was excluded from every oracle, and four wrong-value defects were living there

`tools/irfuzz.py` had four oracles and all of them reported clean. Three exclusions were
stated in its own docstring, and each one is a place a defect can live undetected: the
deliberate reinterpretations, floating point, and **memory and calls**. The reason given
for the last was that a real Dart function with several blocks also calls out, so there is
nothing left to compare, true of CORPUS code, and not an argument about generated code.
A generated function can load and store without calling anything, and the emulator has an
answer for every byte.

`--mem` and `--cfgmem` do that. The thing that makes them work is that the printed text is
INTERPRETED as a program, declarations and assignments executed in order, on the path
the CPU took, with the statement tree linearised so a `goto` is a program counter rather
than a case to skip, instead of being folded into one expression. Folding a
`var t0 = this.field_0x8;` past a store to that field is the defect, not a way to look
for it.

### 1. A value loaded before a store to the same field kept reading that field

`expr.py`'s register map holds EXPRESSIONS, not values, so `x1.field_0x8` in the map is an
instruction to read that field, not the number it held when the load ran. `_pin` already
knew this for the base register, `ldr x16, [x4], #8` has to be written out before x4
advances, and nothing said it about the memory.

`_LinkedHashMapMixin._insert` is the one that shows what it costs. It loads `_length` into
x9, stores `_length + 1` back, then indexes `_data` with x9:

```
0x1d70  ldur w1, [x4, #0x13]     0x1de4  add   x2, x9, #1
0x1d80  sbfx x9, x1, #1, #0x1f   0x1dfc  stur  w0, [x3, #0x13]     <- _length = n + 1
                                 0x1e18  add   x25, x1, x9, lsl #2 <- indexes with the OLD n
```

printed, before:

```
this.field_0x14 = (this.field_0x14 >> 1) + 1;
(this.field_0x10 + (this.field_0x14 >> 1 << 2) + 15).field_0x1 = x2;   <- element n+1
this.field_0x14 = (this.field_0x14 >> 1) + 1 + 1;                      <- n+3, not n+2
```

and after:

```
var t1 = this.field_0x14 >> 1;
this.field_0x14 = (this.field_0x14 >> 1) + 1;
(this.field_0x10 + (t1 << 2) + 15).field_0x1 = x2;                     <- element n
```

**1,146 printed expressions across 377 of the 8,194 functions** in the 3.12.2 clean build.
Fixed by `Lifter._pin_mem`, which names every LIVE tracked value that reads the location
before the store. Liveness is not an optimisation there: `balance -= amount` mentions the
field in both the loaded register and the computed one, and pinning unconditionally puts
two dead declarations in front of every compound assignment.

Three sources of the same staleness were then measured and closed with it:

- **may-alias.** Two reads at different offsets of an object are two addresses and can
  never be one slot; two at the same offset are one slot exactly when the base expressions
  name one object, which the lifter cannot know. `setFrom` writes `x1.field_0x8.field_0x18`
  with `x2.field_0x8.field_0x18` live. 700 store sites, 286 functions, 356 lines.
- **element stores.** A store through a computed index reaches any element of that base.
  39 sites, 20 functions.
- **calls.** `_clobber_call` covers the registers the ABI destroys; the callee-saved ones
  keep their expressions, and a callee may have written the field one of them reads. 58
  call sites, 47 functions, closed by `_pin_call`.

### 2. A join's phi assignment redefined a register that live expressions still named

`_phi` writes an arm's disagreement out as a statement, `x1 = x5 * x13;`. From the join
onwards the token `x1` in the printed source means what that statement put there, and
every tracked value spelled in terms of the old x1 reads as the new one:

```
add x3, x1, x8          if (x13 != 0) { x1 = x5 * x13; }
cbz x13, ...            return x1 + x8 + x1;          <- both x1 are the new one
mul x1, x5, x13
add x0, x3, x1          the machine returns (old x1) + x8 + (new x1)
```

**963 of the 3,685 phi assignments in the clean build shadow a live value, in 230
functions.** Fixed by `Lifter._shadow`: a value already present in the pre-`if` state is
given a name there, which is sound because the declaration then sits where the expression
was formed; a value the arms merely happened to compute identically is dropped to the bare
register instead, because an arm may have clobbered a register inside it first.

`--cfg`, the existing control-flow oracle, cannot see this one by construction: it declines
to score any final expression that mentions an output register. `--cfgmem` scores them,
because a register a printed statement BOUND is a claim, and the ones nothing bound decline
by themselves, x0-x7 are simply left unbound in the evaluator.

### 3. A group of assignments read the values the group itself had just written

A phi group and a loop's carried write-back are both parallel copies: every right-hand
side describes the state at the point the group starts. Written out one after another in
register order they do not, and each one reads whatever the lines above it left:

```
0x10  orr x6, x5, x13     if (x8 != 0) {
0x18  orr x5, x13, x2       x5 = x13 ^ x11;
0x24  eor x5, x13, x11      x6 = x5 | x13;     <- the x5 the line above just assigned
```

and the loop tail has the same shape, `t0 += t1 + 1; t1 = t0;`, which hands t1 this trip's
t0 instead of last trip's. **109 of the 1,728 multi-assignment groups in the clean build
carry the hazard, 120 assignments in 34 functions.**

Fixed by `Lifter._parallel_copy`, shared by `_phi`, the loop tail and `_carry_out`. It is
minimal rather than nervous: the group is emitted in a fixed order, so a right-hand side
naming a member assigned LATER still reads the old value and needs nothing, and only one
naming a member assigned EARLIER is captured in a temporary first. 1,619 of the 1,728
groups have no hazard at all and print exactly as they did.

### 4. A join left a register bare after the body had already assigned it

`_phi` declines to write out a disagreement where each arm has nothing better than a name
or a field read: "a value the reader can still see coming". That rests on the bare register
meaning nothing to the reader, and it stops being true the moment an earlier phi has
written that register out as a statement. `x3` then names what that statement put there,
and an arm which quietly reloads x3, a load emits no line, so the arm renders empty and
the whole `else` is dropped, leaves every later use reading the older assignment:

```
cbz  x8, L1               if (x8 != 0) {
mul  x3, x14, x10           x3 = x14 * x10;
L1: cbnz x11, L2          }
...                       return x13 + x3;      <- reads the product
L2: ldur x3, [x20, #0xf]                           the machine reloaded x3 from memory
    add  x0, x13, x3
```

**833 joins in 266 of the 8,194 functions.** Fixed by tracking `Lifter._phi_named`: once a
register has been assigned in the output, the skip no longer applies to it, because the
bare spelling is no longer neutral.

Found only after `--cfgmem`'s interpreter learned `goto`. The renderer emits one for an
edge it cannot nest, and an interpreter over a statement TREE has nowhere to jump to, so
those graphs were being skipped, about 7% of them, and exactly the shape the join defects
live in. Linearising the tree into a flat op list turns a label into an index and a `goto`
into a program counter, and the exclusion goes with it.

### Cost

+3,297 lines on the clean build, 151,995 -> 155,292, or 2.2%. Lines carrying a bare machine
register go from 45,407 to 47,359, 29.9% of the output to 30.5%; most of that is the phi
assignments themselves, which name a register on the left and are the whole point of the
fourth fix. 93 of the new lines are declarations nothing reads, on top of the 3,691 the
output already had.

### What is still not covered

- **stack slots across a call.** A slot holding a memory read has the same problem and no
  liveness to consult. Dropping them at every call was tried and measured: the outgoing
  area is what `_stack_args` reconstructs a stack-convention call's arguments from, so
  emptying it costs `benchDecodeFlag` the literal `semdiff` pins it on. Naming them instead
  is the fix, and it is not written.
- **a field store against a live element read of another object**, and the reverse. An
  element at a dynamic index could be any offset, so covering it would invalidate almost
  everything; the two are treated as disjoint.
- **arm32.** Everything here is arm64, which is what Tier 3 lifts. The pair-register model
  under `_T.pairs` is on the same store and load paths and is not fuzzed by any of this,
  because `LIFTABLE_ARCHS` does not include arm32 and the generator cannot emit for it.
- **calls, as values.** `--mem` and `--cfgmem` generate no `bl`, because a call's result
  and its effect on memory are not claims the lifter makes and there is nothing to
  compare. `_pin_call` is checked by a unit test rather than by an oracle.

## Scalar floating point had no oracle at all, and is clean

`expr_cases` throws away any run with an s/d/q/v operand, so the whole FP path in `expr.py`
had been checked by reading and by nothing else, and it had already diverged from the
integer path once. When `_bin` learned to bracket its right operand, the integer half was
fixed and the scalar-FP half, a separate call site, was not: `fsub d0, d1, d2` with d2
holding `d3 - d4` printed `d1 - d3 - d4`.

`tools/irfuzz.py --fp` takes the scalar-double runs the compiler really emits (the corpus
has 152 of length two, 52 of length three or more, up to one of 35), lifts them, and
evaluates the printed text against an emulated CPU. It needs no approximation anywhere: a
Python float IS an IEEE-754 binary64 and `+ - * /` and sqrt are correctly rounded in both,
so the two agree bit for bit or the rendering is wrong. Only division by zero and the
square root of a negative are skipped, and those are the evaluator's limits rather than the
tool's.

**Clean: 773,687 comparisons over the corpus binary and nine shipped apps, 0 mismatches.**
Teeth proved by reintroducing the historical defect (the right operand unbracketed) and a
second one (fsub and fdiv reading their operands backwards); both fire.

One thing the scan settled rather than fuzzed. `canon` folds the s view onto the d view the
way it folds w onto x, and for floating point those are not the same NUMBER, single
precision rounds differently, so `fadd s0, s1, s2` rendered as `d1 + d2` would be a wrong
value rather than a wide one. It is moot on real code: across the corpus binary and three
shipped apps the only s-register instruction the compiler emits is `fcvt`, and there is no
scalar single-precision arithmetic anywhere in them.
