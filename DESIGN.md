# Technical design: version-robust Dart AOT snapshot parser + recovery

Grounding for the framework's core. Source of truth: `dart-lang/sdk` @ `c6d9d592`
(main, 2026-07-04), cloned under `unflutter/dart-sdk/`. Line citations are to that
checkout. Items we could not confirm from source are marked UNVERIFIED.

## 1. Snapshot stream layout

```
[ magic 0xdcdcf5f5 (int32) | length (int64) | kind (int64) ]   20-byte header (snapshot.h:35-42)
[ 32-char version hash, raw ASCII, NOT null-terminated ]        WriteVersionAndFeatures (app_snapshot.cc:8867)
[ features string, null-terminated ]
[ num_base_objects | num_objects | num_clusters | instr_table_len | instr_table_rodata_offset ]  unsigned varints
[ cluster[0..N].alloc ]     WriteAlloc pass
[ cluster[0..N].fill  ]     WriteFill pass
[ roots ]
```
`kind` in {kFull, kFullJIT, kFullAOT, kModule} (snapshot.h:24). `length` excludes the 4
magic bytes. Release snapshots (what you RE) are NOT self-delimiting: the int32 ref-index
and section-marker words between clusters exist only in DEBUG builds (app_snapshot.cc:9064,
9089).

## 2. Two-phase (alloc/fill) model

Driver `Serializer::Serialize` (app_snapshot.cc:8927):
- Trace: `AddBaseObjects` registers implicit shared objects (null, true/false, sentinels,
  predefined classes) never written to the stream; `Push`/`Trace` reach fixed point.
- Bucket: `Trace` computes `(cid, is_canonical, is_deeply_immutable)` and routes each object
  into one of three per-cid cluster arrays (canonical / immutable / normal). Smis force to
  kMintCid; all string cids collapse to kStringCid.
- WriteAlloc (loop :9060): each cluster writes a 32-bit tag word
  (`ClassIdTag::encode(cid) | CanonicalBit | DeeplyImmutableBit`), object count (+ per-object
  length for variable-size), and `AssignRef` on each object -> dense incrementing ref ids in
  allocation order. No field bytes yet.
- WriteFill (loop :9086): each cluster writes scalars + reference fields. All ref ids exist,
  so forward refs are free.
- Roots last, then dispatch table.

Deserializer replay `Deserializer::Deserialize` (:9928): read counts, alloc ref array, for
each cluster ReadAlloc (tag word -> allocate -> AssignRef), then for each cluster ReadFill,
then ReadRoots, then PostLoad (canonicalization / rehash). ReadCluster (:9364) reads the
uint32 tag, decodes cid, dispatches.

A SerializationCluster (:158) is one bucket of same-cid objects; ~51 subclasses in this
checkout, each with a mirror DeserializationCluster.

## 3. The four images

ELF symbols `_kDart{Vm,Isolate}Snapshot{Data,Instructions}`:
- Data images = the clustered stream above (.rodata). VM data = VM-global/shared objects +
  predefined-class scaffolding. Isolate data = the app object graph (classes, functions,
  libraries, constants, closures, types).
- Instructions images = a separate machine-code text image built by ImageWriter, NOT in the
  clustered stream. Header is two words {ImageSize, InstructionsSectionOffset}; then payload,
  plus (AOT) BSS, GNU build-id, InstructionsTable. The stream references code only by offset
  (`WriteInstructions` :8669 packs `(unchecked_offset << 1) | HasMonomorphicEntry`).
  Code<->heap linkage at runtime is via the ObjectPool (register PP / R27 on ARM64).

This split is why disassembly and object recovery are two problems: the code lives in
.text (Instructions), the names/pool/classes live in .rodata (Data), joined by offsets +
the ObjectPool.

## 4. CID table (class_id.h)

`CLASS_ID_LIST` X-macro (class_id.h:302-327) expands into `enum ClassId` (:329). Wire-critical
numbering: kIllegalCid(0), internals, INSTANCE_SINGLETONS, Maps/Sets/Arrays/Strings, FFI,
TypedData (each base type x4), ... kNumPredefinedCids (the boundary).

Rules:
- Predefined cids are compile-time-fixed by the enum, with COMPILE_ASSERT contiguity.
- User classes get cids >= kNumPredefinedCids at AOT-compile time in registration order.
- Dispatch: `cid >= kNumPredefinedCids || cid == kInstanceCid` -> generic Instance cluster
  (field-driven, self-describing via the Class object). Every predefined cid -> its bespoke
  cluster via the switch in NewClusterForClass (:8151) / ReadCluster (:9364).

Version drift: the enum grows/reorders as features land (RecordType/Record in 3.0,
SuspendState for async ~2.19/3.0, WeakArray/Finalizer recently, the 4-variant typed-data
expansion). Because predefined cids are positional, the numeric cid->grammar map is
version-specific, but the CLASS_LIST macro structure is mechanically parseable per version.

## 5. Encoding (datastream.h)

- Object header tag (raw_object.h:185-313, 64-bit): bit1 Canonical, bit7 DeeplyImmutable,
  bits8-11 SizeTag (4b), bits12-31 ClassIdTag (20b). The cluster tag word reuses this layout.
  VERSION NOTE: ClassId is 20 bits now; older SDKs used 16; the immutable bits are recent, so
  SizeTag/ClassId positions shift across versions.
- References `WriteRefId`/`ReadRefId` (datastream.h:510/107): unsigned dense ids, big-endian
  7-bits/byte varint capped at 28 bits, high bit marks last byte. Internal id space is signed
  by meaning (0 unreachable, 1 first, -1 unallocated) but the WIRE encoding is unsigned.
  The historical "unsigned->signed wire ref" switch is UNVERIFIED from source; resolve via
  `git log -p datastream.h`.
- Scalars: `Write/Read` signed varint (:563/234) for tag word + signed scalars;
  `WriteUnsigned/ReadUnsigned` (:501/102) for counts/lengths; plus (S)LEB128 (:177-225) for
  specific payloads (instructions-table deltas).
- Pointer compression (Dart 2.15; Android64 via engine PR #28388): in-heap refs become 4-byte
  compressed pointers. Does NOT change stream varints, but DOES change instance field
  offsets/sizes in Data images AND disables RODataSerializationCluster (guarded
  `#if !defined(DART_COMPRESSED_POINTERS)`). So the same Dart version yields structurally
  different snapshots by build flag -> the features string must match, not just the hash.

## 6. Version hash

- 32-char lowercase-hex MD5 stored at stream offset 0x14 (raw, unterminated), then the
  null-terminated features string. Computed by tools/make_version.py MakeSnapshotHashString:
  `md5(cat(VM_SNAPSHOT_FILES))` over a fixed file list (app_snapshot, dart, dart_api_impl,
  datastream, image_snapshot, object, raw_object, snapshot, symbols).
- VM verification `VerifyVersion` (:9732) is an exact `strncmp(...,32)`; `VerifyFeatures`
  (:9767) exact-matches product/JIT/AOT/arch/OS/null-safety/compressed-pointers flags.
- No official hash->SDK-version table exists; community maps (nfalliere gist,
  hadysata/flutter-versions, darter info/versions.md) are reusable. The hash is a pure
  function of source bytes, so different versions with identical snapshot files collide, and
  the hash carries no arch/flags. DESIGN RULE: key the format description off BOTH the hash
  and the features flags, and treat the hash as a "format epoch" id, not a precise version.

## 7. Version-robustness: the hybrid design (the crux)

Stable across all versions (hard-code once): the 20-byte header + magic; the
hash-then-features layout; the three varint codecs; the framing (counts -> alloc pass ->
fill pass -> roots); cluster tag word = fake object header; dense incrementing ref ids; base
objects first; the `cid >= kNumPredefinedCids || cid == kInstanceCid` dispatch rule.

Drifts (must be version-parameterized): the cid table; the tag word bit layout (16->20 bit
ClassId, added immutable bits); the ~50 predefined-cluster field grammars.

Can the drifting parts be auto-derived? Partially. The realistic answer is a HYBRID:
1. Parse class_id.h per version -> cid table. Fully mechanical (X-macro). Do this.
2. Parse raw_object.h Untagged* field lists (COMPRESSED_POINTER_FIELD macros between from()
   and to()) -> the pointer-field skeleton many clusters walk via WriteFromTo. Feasible with
   effort, but incomplete: `to_snapshot(kind,...)` conditionally drops trailing fields per
   snapshot kind (AOT vs JIT), and non-pointer/unboxed fields (flags, packed_fields, lengths)
   are written by hand-written imperative code, not derivable from the struct.
3. The imperative WriteFill/ReadFill bodies are the hard blocker: bespoke control flow,
   bit-packing, per-kind conditionals, cross-object ordering (Code before Function). There is
   NO declarative schema in the SDK. This is exactly why Blutter compiles the SDK and why
   unflutter hand-codes each version.
4. Self-description helps for USER data: once ClassSerializationCluster is parsed, each Class
   object yields user-class name, superclass, field names, field offsets, so user instance
   clusters (the bulk of app data) decode generically from the snapshot itself. But the ~50
   predefined clusters must be modeled to bootstrap, and that part is not in the snapshot.
5. Differential inference across two known snapshots: only for tiny local deltas; defeated in
   general by positional untagged fields, variable-length encoding, canonical dedup/reorder,
   and no section markers in release builds.

Obstacles: (a) positional untagged fields (no in-band ids); (b) to_snapshot(kind) drops
fields conditionally; (c) canonical clusters add a CanonicalSet table + require PostLoad
rehash; (d) compressed-pointers changes sizes/offsets and toggles RO-data clusters; (e)
generated/templated field lists + hand-packed bitfields; (f) release streams not
self-delimiting.

RECOMMENDED ARCHITECTURE:
- A stable core: header/codecs/framing/cid-dispatch.
- A per-format-epoch grammar table for the ~50 predefined clusters, keyed by
  (version-hash, features-flags).
- Auto-generate the cid table + pointer-field skeletons from class_id.h / raw_object.h at
  that epoch.
- A small hand-maintained overlay for the imperative bits of each ReadFill.
- Because app_snapshot.cc changes rarely and locally, you update ONLY the clusters whose
  WriteFill diffed between two SDK tags. That is far cheaper than unflutter's full
  re-hand-coding and far more portable than Blutter's per-version SDK recompile.
- Fail loud, never silent: reject-or-degrade-with-warning on an unknown (hash, features),
  never confidently parse with a guessed profile. This is the single most important fix over
  unflutter (see below).

## 8. Why "fail loud" is the headline correctness fix

unflutter's unknown-hash path silently falls back to the 3.9.2 profile, then to
ProfileUnknown (default TaggedPointerShift:1, ObjectAlignment:8) rather than erroring. Its
README caps at 3.10.7; 3.11.0 and 3.12.0-dev were added Feb 2026 but ONLY for their exact
known build hashes, so any other 3.11/3.12 hash hits the silent fallback (this is what our
Dart 3.12.2 binary did: parsed, no version banner, no build-id in metadata). Its issue #1
shows the footgun as a mid-fill crash (a libapp.so mis-detected as 2.10.0 then
`fill: cluster 396 ... value too large`). Blutter avoids this by construction (it only runs
when it built the matching SDK) but pays the per-version SDK-compile cost, is Android arm64
only, and needs a Linux-ish toolchain. Our design takes neither horn: version-parameterized
grammar (portable, no SDK build) PLUS explicit epoch detection that refuses to guess.

## 9. Decompilation ceiling (what recovery can and cannot produce)

AOT path: Dart -> Kernel IL -> optimized IL -> ARM64 machine code; product build discards
the Kernel/AST.

Survives (recoverable -> a rich headers + annotated-disassembly view):
- library/class/function NAMES (String objects; kept for stack traces unless full obfuscate).
- class hierarchy (super, interfaces, mixins).
- field layout: names, offsets, declared types.
- function signatures/types (Type, FunctionType, TypeParameter, TypeArguments).
- code entry points (Code -> instruction offsets), PcDescriptors (PC->source-position ids),
  ExceptionHandlers.
- closures (ClosureData, captured Context).
- ObjectPool contents: string literals, selectors, constants, static call targets. The
  backbone for annotating disassembly.

Gone (unrecoverable): Dart source, comments, Kernel AST/IL, statement-level structure,
local variable names (LocalVarDescriptors stripped in release), expression trees.

Therefore the realistic best output is: complete class/method/type reconstruction (an
API/header dump), the static call graph (ObjectPool + direct calls), string/constant
recovery, and per-method ARM64 disassembly annotated with pool-object and function names,
PLUS Ghidra-quality pseudocode for method bodies. NOT original Dart source. The pseudocode
lift is generic machine-code->pseudocode, made trickier by Dart calling conventions (PP/R27
pool, tagged-Smi "x2" arithmetic, stub calls) but NOT blocked by missing metadata for
signatures, only for bodies.

Product implication for a "JADX for Flutter": JADX-quality output = the class/method/type
tree + xrefs + strings + annotated disasm, with pseudocode bodies as the stretch. That
skeleton alone already beats every current tool's usability, because none of them present a
navigable, decompiler-style class tree.

## 10. Implementation index (file:function anchors)

- header/magic/kind: snapshot.h:24-66
- version hash + file list: tools/make_version.py:20-45; version_in.cc
- version/features write+verify: app_snapshot.cc:8867, :9719-9811
- serialize driver + counts: app_snapshot.cc:8927, :9053-9107
- deserialize driver: :9928-10035
- cluster bases: :158, :217; roots :267, :277
- cid dispatch: NewClusterForClass :8151; ReadCluster :9364
- cluster tag word: WriteAndMeasureAlloc :915
- ref model: constants :285-306; AssignRef :7807/:724
- codecs: datastream.h WriteRefId/ReadRefId :510/:107, WriteUnsigned/ReadUnsigned :501/:102,
  Write/Read :563/:234, (S)LEB128 :177-225
- object header tag bits: raw_object.h:185-326
- cid table: class_id.h:26-334
- instructions image: image_snapshot.h:35-134; WriteInstructions app_snapshot.cc:8669;
  ReadInstructions :9817; RO-data cluster :3667

## 11. Decompiler target tiers (RE to Dart)

Original Dart source is unrecoverable (AOT discards the Kernel AST). The realistic target is
readable, typed, roughly-recompilable pseudo-Dart, staged in tiers so each ships:

- Tier 0 - Skeleton Dart. Emit real Dart declarations (classes, fields, method signatures,
  types) from recovered metadata. Near-perfect because the metadata survives. The JADX
  moment; beats every current tool on usability.
- Tier 1 - Control-flow + calls. Per method: structured pseudo-Dart with branches/loops and
  named calls + string/const ops. Readable, not always recompilable.
- Tier 2 - Expression-level bodies. Faithful statements; degrades on heavily optimized code
  (inlining, boxing, polymorphic inline caches).
- Tier 3 - Async/closure re-sugaring. Reconstruct async/await and closures from the
  SuspendState/Context state machines. Research frontier; paper-worthy alone.

Dart advantage over stripped-C decompilation: types, signatures, field names/offsets, class
hierarchy, selectors, and the ObjectPool all survive, so output is typed and named, not
anonymous. Hard parts: object-pool ABI (R27/PP), tagged-Smi x2 arithmetic, runtime stub
naming, optimizer effects, async state machines.

Two routes (composable): (a) pragmatic, lift into Ghidra with a Dart calling-convention +
type model, take its C-pseudocode, run a Dart-ization pass (fastest to Tier 1);
(b) the contribution, our own Dart-AOT IR + structured decompiler (cleaner typed
pseudo-Dart). Optional offline LLM-assist (local Ollama) drafts bodies, verified against
behavior (compile-and-diff / dynamic check), a research bet, held to "verify, don't trust."

Grading: FluBench scores each tier (Tier 0 skeleton recall vs ground truth; Tier 1+ body
fidelity via compile-and-diff or a manual rubric).

## 12. Signature matching (jadart/signatures.py)

The problem it solves is narrow and worth stating exactly. Name recovery reads names out
of the snapshot, and on an ordinary build that returns 72.5% of code ranges. Under
`--obfuscate` it returns 2.2%, and the missing 97.8% is not hidden anywhere in the file:
Dart's obfuscator renames dart:core and the framework along with the app, so the strings
`toRadixString` and `padLeft` do not exist in the binary. Parsing harder cannot help. The
names have to come from somewhere else, and the only honest somewhere is a reference build
of the same release, where the same library code carries its names.

**Borrowed from Ghidra's Function ID**, whose model fits this problem almost exactly:

- two hashes per function, one with operands masked (robust to layout changes) and one
  keeping the detail that separates near-identical variants;
- the call graph disambiguates the rest, since two functions with identical bodies calling
  different subfunctions are told apart by their callees;
- entries known to be undiscriminating are excluded outright (Auto Fail) rather than
  matched with low confidence;
- a minimum instruction count, with calls and branches scoring zero, because a body made
  of calls looks like every other body made of calls.

**Where the adaptation improves on a direct port.** Ghidra masks constant operands because
it has no way to say what a constant means. A Dart AOT function reaches its constants
through the object pool (`ldr xN, [x27, #off]`), and Jadart already resolves that offset to
the string or function it names. So where Ghidra keeps a masked immediate, this keeps the
*resolved referent*: `[PP:"time of request: "]`. String literals are untouched by
obfuscation, which makes them the strongest available signal on precisely the builds with
nothing else left. The pool also exposes an entry's kind (tagged ref, immediate, native,
empty), which is stable across builds and free to include.

The direct-call graph is thinner here than in native code, because a Dart call is often an
indirect jump through a pool entry rather than a `bl`, so the child relation carries less
weight than in Ghidra and the pool referents carry more.

**Three match levels**, reported rather than collapsed: `context` (shape, pool referents,
and callee shapes all agree), `pool` (shape and referents), `shape` (masked instructions
only). Measured against an application in no reference, with ground truth for every
function: 99.3% overall, 99.4% at `context`, which is where 97% of matches land. Precision
falls to 93.8% at `pool` and 96.8% at `shape`, which is the reason the level is part of
the result and not an implementation detail.

**Two exclusion classes, both found by measurement, not anticipated.** dart:core wraps many
different natives in one identical thunk whose only distinguishing operand is a pool slot
the runtime patches to null at load; signing those produced a confident wrong name for a
string operation on the first run. The `dyn:` invocation forwarders come off one template,
and `dyn:+` and `dyn:-` collide inside a single reference build. Both are refused a
signature.

**Provenance is not optional.** A matched name is an inference from a different binary and
ends in `~`; a name without the mark was read out of this one. A recovered name always
beats a matched one, even when they disagree, because the binary is evidence and the
library is not. This is the same discipline as `(...)` for unknown call arguments and
`field_0x8` for a field whose name did not survive: the tool may decline to know something,
but it may not present a guess as a fact. A field name IS read out of this binary where the
`Field` object survived (fields.py), so it carries no mark; what the tool declines to do is
attach it to a receiver whose class is not stated, which is why `x3.field_0x8` keeps its
offset even where some class has a field at 8.

## 13. The lifter's architectural ceiling, and the way past it

Tier 3 lifts by abstract interpretation over the register file with TEXTUAL substitution:
each register maps to a string, and using a register pastes its text. Everything below
follows from that one decision, and none of it is fixable inside it.

**Measured on the 3.12.2 corpus binary**, 8194 functions, 457,622 instructions:

| symptom | measured |
|---|---|
| lines containing a bare machine register (`x0`, `d2`) | 52,791 of 147,002 (**35.9%**) |
| fields rendered by byte offset | 36,312 (24.7%) |
| calls rendered `(...)` | 18,519 (12.6%) |
| `goto` | 9,916 (6.7%) |
| raw arm64 (unmodelled) | 3,462 (2.4%) |

Stable within a couple of points across all 14 arm64 corpus binaries, 2.19.6 to 3.12.2.
This is architecture, not epoch drift.

**WHERE THE BARE REGISTERS ACTUALLY COME FROM**, counted rather than assumed, because the
plan that followed from assuming was wrong. Attributing every bare-register READ on the
3.12.2 corpus to the point the register map lost the value:

| cause | share |
|---|---|
| the loop header and exit, `_render_loop` | **95.7%** |
| clobbered or reset elsewhere | 2.5% |
| never set: an entry argument or a call result | 1.8% |

Merges are not the problem. The plan on this page said the DAG's phi would move this
number, and phi-at-a-join is worth roughly two percent; the loop is worth all the rest,
because `_render_loop` forgot every loop-carried register at the header so the whole body
printed machine registers, and forgot everything the loop wrote on the way out.

A loop-carried value IS a phi, and a phi with one join has a name in the source. Binding it
before the loop, reading that name in the body and assigning back at the bottom took the
corpus from 29.6% to 27.2%, HiveHex from 31.2% to 29.7% and MasterBaker from 27.6% to
25.6%. The update at the tail was already being emitted; it was assigning to `x5`.

Braun's trivial-phi collapse is what keeps that from adding noise: `carried` is a syntactic
over-approximation (live-in AND written somewhere in the loop's blocks), so a register the
walk never actually reassigns is not carried at all, and its binding is dropped when the
entry value is an atom. Without that, Newton's method acquired `var t1 = 2.0;`.

**AND WHERE THEY COME FROM NOW**, measured again after call-argument recovery pushed the
number back up to 29.9% by EXPOSING registers that had been hidden inside `(...)`. Same
method, refined: `State.get` returns a tagged copy of the register name, the tag names the
exact site that put the bare name in the map, and the tag survives every textual
substitution into the printed line. Total tagged lines match the untagged `tools/quality.py`
run to within 7 of 45,407, so the attribution is the metric and not a model of it.

| cause | lines | share |
|---|---|---|
| never established: an entry ARGUMENT register (x1,x2,x3,x5,x6,x7) | 9,282 | 20.4% |
| a stack-slot reload the map had no value for | 11,389 | 25.1% |
| ...of which incoming STACK arguments, `[FP,#>=0x10]` | 5,020 | 11.1% |
| ...of which a spill slot this function does store to | 5,121 | 11.3% |
| a register the two arms of an `if` disagreed about (`_merge`) | 8,719 | 19.2% |
| the left-hand side of an assignment the lifter itself emitted | 4,176 | 9.2% |
| a `goto` join's kill set | 2,150 | 4.7% |
| a call clobber | 1,880 | 4.1% |
| a pointer bump, `_bump` | 1,218 | 2.7% |
| raw arm64, and the unmodelled-instruction fallthrough | 1,782 | 3.9% |
| everything else (2,726 of it a non-argument register never established) | 4,811 | 10.6% |

The loop header is gone from this table because it was fixed; nothing above it is a merge
in the old sense either. But the table still does not answer the question a reader asks,
which is narrower than "where did the value go": **when a line says `x2`, can I find out
what `x2` is by reading the rest of the function?** Splitting the same 45,407 lines by
whether the printed body assigns the register anywhere:

| | lines | share |
|---|---|---|
| every bare register on the line is assigned by the printed body | 12,710 | 28.0% |
| at least one is not | 32,697 | 72.0% |
| ...and the unassigned ones are entry ARGUMENT registers only | 17,492 | 38.5% |
| ...raw-arm64 destinations only | 2,020 | 4.4% |
| ...one or the other | 34 | 0.1% |
| ...something else, 8,522 lines of it `x0` | 13,151 | 29.0% |

Only the first band can be reduced without inventing anything, and it was made almost
entirely at the if-join. `_phi` already wrote both arms out; it assigned them to the MACHINE
REGISTER, so the join and everything after it still read `x0` and the reader could not tell
that `x0` from one the lifter had lost. Binding the join to a name instead, the same shape
`_render_loop` uses, declared before the `if` with the entry value where one arm leaves it
alone, takes the corpus from **29.9% to 26.0%**, and the first band with it, from 28.0% of
register lines to 6.2%. Real apps move the same way: immich 26.6% -> 22.9%, fluffychat
24.8% -> 21.3%, finamp 28.3% -> 24.3%, openwrtmanager 27.5% -> 23.6%, tsacdop 25.8% ->
21.7%. No other symptom moves against it (byte-offset fields go 27.8% -> 27.7%).

TWO THINGS MEASURED AND NOT SHIPPED, because a negative with a number is worth more than
an idea. Naming the join for a disagreement where BOTH arms are already atoms (a field read
or an existing name) drops the share to 22.1%, but only by adding 27,732 register-to-register
move statements: the absolute count of register lines goes UP, 39,543 to 39,774, and the
share falls because the denominator grew 18%. That is gaming the metric. And `_writes_stack`
the rule that a store through an object pointer cannot reach a frame slot, was
predicted from the attribution to be worth 2,758 lines and measured at 0, because 4,942 of
the 5,414 corpus functions that store at all (91.3%) store to a frame slot somewhere too,
so the region being asked about answers yes either way. It is kept because separating the
two questions is what makes `_stale_slots` safe, and that is a correctness fix: a region
with no frame store used to keep a slot whose TEXT named a register the region had since
overwritten, and 56 reload sites were reading one.

WHAT IS LEFT IS MOSTLY AN HONEST REFUSAL, and the largest single band of it is the entry
argument: 17,492 lines (38.5%) whose only bare registers are the ones the Dart AOT calling
convention passes arguments in, plus 5,020 more reading the incoming STACK argument area.
Ghidra would print `param_1` and Hex-Rays `a1` for those. Jadart does not, and the reason
is a fact about the format rather than a policy: AOT does not serialize positional
parameter names (the same tree-shaking that empties `offset_in_words_to_field`), so `arg1`
would be a POSITION dressed as a name. `entry_arity` does prove the count, so the option is
open; it is a naming convention to decide on, not a recovery to build.

**AND WHY A CALL PRINTED `(...)`**, counted the same way, because the docstring's list of
five reasons turned out to have exactly one live entry. Of 25,373 direct call sites on the
corpus (30,281 on HiveHex), the runtime-stub and ArgumentsDescriptor branches fire for none
of them; 30.1% (64.9%) reach `...` solely because `entry_arity` declined for the callee.

`entry_arity` declines for one reason: the callee reads its arguments off the STACK. That
is a statement that the caller pushed them, so the values are in the outgoing area at the
call. `_stack_args` has always known how to read that area, and `blr` has always called it
before `_drop_outgoing`. `bl` called it after, so the area it was handed had just been
emptied and every declining site measured as "no contiguous run from SP+0". Reading before
the drop recovers 2,404 of 7,627 declining sites on the corpus and 13,996 of 19,638 on
HiveHex, taking `(...)` from 7.1% to 5.5% and from 12.3% to 4.1%.

The cost is real and goes the other way: bare machine registers rise, 27.2% to 27.9% on the
corpus and 29.7% to 35.3% on HiveHex, because an argument that was hidden inside `(...)` is
often a register the caller never established. That is more information, not less, the
arity and the shape of the call are now visible where before there was one token, but the
two metrics move in opposite directions and neither alone says whether the output improved.

**WHERE IT STANDS AFTER THE THREE INVALIDATION FIXES**, because the same trade shows up
again and the second half of it is easy to read as a regression. Textual substitution is
only sound while the registers inside the text still hold what they held, and three writers
were violating that: a call, which destroys R0-R14 and every V register but VTMP; a `goto`
target, which is a join the structured walk does not know it is standing on; and any
instruction overwriting a register some other tracked value still names. Each was printing
a value the machine does not have.

| symptom | before | after |
|---|---|---|
| bare machine register, corpus / HiveHex / MasterBaker | 27.9% / 35.3% / 26.2% | 28.2% / 34.9% / 26.9% |
| byte-offset field | 28.9% / 30.3% / 30.6% | 27.8% / 29.0% / 29.7% |
| calls rendered `(...)` | 5.5% / 4.1% / 5.9% | 5.3% / 3.8% / 5.7% |

Bare registers move by less than a point in each direction, and the reason they do not move
more is liveness. A stale text can only mislead something that reads it, so a value dead
after the write that invalidates it is left alone, and a live one gets a name rather than
being dropped, 7,566 pins on the corpus binary across 1,600 of its 8,194 functions, 3,024
of them removed again by the pass that drops any nothing goes on to read, 4,542 surviving.
(Counted by instrumenting the two passes. The commit that introduced them said 4,415, which
was the export's line delta and not the same quantity.) Where a name cannot
carry the value across, the register is what prints, and that is the direction to be wrong
in: a bare `x9` says the lifter lost it, and `(x0 + 1)` under a visible `x0 = x3 + x4` says
something false.

**The blowup is latent, not fixed.** `MAX_INLINE_CHARS = 200` truncates an exponential; it
does not remove it. Raising the cap: at 2,000 the longest line is 3,647 chars, at 20,000 it
is 38,527, and the worst case traces to `SystemHash.hash20` every time. The 390 `var tN =`
spills it produces are unprincipled, in the exact sense that their boundary is a string
length rather than anything about the program.

**Why a graph fixes it, demonstrated rather than argued.** Hash-consing one block into an
interned value DAG and applying Ghidra's inline rule takes `hash20` from a 397-character
line to 45 lines whose longest is 62, and the result is recovered source: every mask and
shift matches `SystemHash.combine`/`finish` in dart:core.

**The rule both production decompilers converge on.** Ghidra marks each varnode `implied`
(inlined) or `explicit` (named) from SSA descendant counts, with `max_implied_ref = 2` and
`max_term_duplication = 2` (`architecture.cc`); three or more reads always becomes a named
local, and two reads become one if duplicating the expression would exceed two terms.
Hex-Rays reaches the same place from the other side: an operand may be a nested instruction
(`mop_d`), and whatever propagation could not fold is what `alloc_lvars` gives a name at
`MMAT_LVARS`.

So the question the printer must answer is **"how many places read this value?"**, and
`MAX_INLINE_CHARS` is a bad approximation of it for a structural reason: once the value is
a Python string, the question is unanswerable, and length is only measurable after the
duplication has already been paid for. The IR is not the deliverable. The IR is what makes
the printer able to ask.

**What Dart AOT makes easier than stripped C**, and it is a lot: class sizes bound field
offsets (so a wrong type refinement can be *rejected* by an `instance_size` check, which C
decompilers have no equivalent of); 2,841 measured cid comparisons are flow-sensitive
*proofs* of a receiver's class on one branch edge; selector names survive; ObjectPool
constants resolve; and the calling convention is a constant rather than something to infer.
The type model should therefore be two orthogonal lattices, not Ghidra's structural one: a
REPRESENTATION lattice (Tagged/Untagged/Double/Bool) that rewrites must respect, and a
NOMINAL cid lattice ordered by the recovered superclass chain that is only for display.
Conflating them is how a display improvement becomes a wrong rewrite.

**What it makes harder**: Smi arithmetic is invisible in the common case, because
`2a + 2b = 2(a+b)` means `BinarySmiOpInstr` emits a bare `add` on tagged values
(`il_arm64.cc`) and only multiplication carries an untag. A tag-elimination pass cannot
pattern-match shifts; it needs the representation lattice and must refuse where the state
is not proven on every reaching definition.

**THE ASSUMPTION THIS OVERTURNS.** The project has held that the machine-code layer has no
byte-exact oracle, and that this caps it structurally where the snapshot layer is not
capped. That is false, and it is the most consequential finding here. Randomized
differential execution against an emulator IS an oracle: evaluate a block's instructions
under reference arm64 semantics, evaluate the IR after all passes, compare the live-out
state bit-exactly on random inputs. It does not validate display decisions, and it cannot
validate Smi-tag elimination (which deliberately changes the value). But it validates every
semantics-preserving rule, which is exactly the category that is otherwise unfalsifiable
and where the silent-wrong-answer risk lives. Build it FIRST; the rest of the work is only
safe behind it.

STAGE 0 AND THE CORE OF STAGE 1 ARE NOW BUILT (`jadart/ir.py`, `tools/irfuzz.py`).
The oracle is real: 15 arm64 instructions, 3,000 random comparisons against a unicorn CPU,
0 mismatches. Its encodings are hardcoded so it needs only unicorn, and verified with
capstone before anything runs, which caught two of the fifteen being wrong on the first
write (`lsl w0,w1,#9` decoded as `ubfx`, `sbfx x0,x1,#1,#31` as `sxtw`); without that
check the harness would have fuzzed the wrong instruction and reported a pass. The DAG
removes the blowup as measured: a 100-deep combine chain renders 199 lines whose longest
is 99 characters, flat in the depth, against 397 characters at depth 20 today.

TWO TRAPS WORTH KEEPING WRITTEN DOWN, both found by measurement rather than foresight.
`term_count` has to SATURATE at a cap: the printed size of a shared chain is exponential
in its depth, so computing it exactly costs what printing it costs, which is the thing
being avoided. And `Node` must use IDENTITY hashing: a frozen dataclass derives __hash__
from its field tuple, `args` holds Nodes, so hashing one node walks its whole subtree and
a 7-deep chain cost 8.1 million __hash__ calls. Interning makes that unnecessary, since
equal values are the same object.

THE LOWERING IS BUILT AND CHECKED AGAINST REAL CODE (`jadart/lower.py`). arm64 goes into
the DAG for the pure-arithmetic subset, and the oracle now runs on instructions the
compiler actually emitted rather than fifteen someone thought to write. The default sweep,
`tools/irfuzz.py --corpus <binary>`, is 301 straight-line runs, 1,010 instructions, 65,800
register comparisons, 0 mismatches; `--runs 400` takes that to 401 / 1,339 / 86,800. Both
figures were quoted here at one point without the invocation that produces them, which is
the same doc drift `tools/measure.py --check` exists to catch and does not yet cover for
this file.

AND THE ORACLE IS TESTED FOR TEETH, which matters more than the zero. The snapshot gates
are validated by perturbing a correct parse and asserting each gate catches its own
perturbation; the same discipline applies here. Lowering `asr` as a logical shift, dropping
a shifted-register operand's shift, and zero-extending `sbfx` are each caught. A fourth
perturbation, dropping the zero-extend on 32-bit writes, correctly did NOT fire: a 32-bit
node already evaluates zero-extended, so that line changes no value on 5,000 random inputs.
The oracle was right and the perturbation was wrong, and the comment in `lower.py` that
oversold that line has been corrected to say so.

The rule that keeps this honest: an unmodelled instruction POISONS its destination rather
than being approximated. `Lowering.opaque` records which registers went that way, so the
fuzzer only checks what the lowering actually claims, and a caller can decline to reason
about the rest.

AND THE ORACLE WAS ON THE WRONG LIFTER, which is worth stating plainly because it is the
failure mode a green number hides. Everything above measures `ir.py`/`lower.py`. Nothing in
the CLI reaches them: `jadart lift` and `jadart export` go through `expr.py`, which imports
neither, so the code whose output a user acts on had no execution oracle at all while the
harness reported hundreds of thousands of clean comparisons. `tools/irfuzz.py` now runs a
SECOND pass that lifts real straight-line runs with `expr.py` and evaluates THE TEXT IT
PRINTED against the emulated CPU. On the corpus binary the default sweep adds 301
pure-arithmetic runs, 38,663 printed expressions evaluated, 2,337 refused as undecidable,
0 mismatches; `--runs 1500` takes that to 1,501 / 190,450 / 11,900.

Tested for teeth the same way as the first: reintroducing the `_bin` precedence defect
makes it print `x3 = 30 - x1 - 2` against a CPU that computed `30 - (x1 - 2)`, four higher,
and exit 1. It refuses rather than guesses wherever the printed text is deliberately
lossy, `>>` stands for both `lsr` and `asr`, `<` for both signednesses, and the Smi-tag
and pointer-decompression rewrites are excluded by construction, which is what keeps a
designed reinterpretation from arriving as a false defect and getting the oracle switched
off.

One defect of that same class was found while porting this, and NOT by it: the oracle skips
FP registers, so it cannot see the scalar-FP path, which builds its text at a separate call
site and so never got the `_bin` change. `fsub d0,d1,d2` with `d2` holding `d3 - d4` printed
`d1 - d3 - d4`. Fixed and pinned by a test, but the credit belongs to reading the fix's
neighbours, and the fact that a whole operand class sits outside the oracle stands.

The gap that remains: the DAG lifter, its SSA and its oracle are the better-built half and
still ship nothing. Until `expr.py` is replaced by them, "checked against a CPU" means the
text pass, and the text pass covers straight-line arithmetic only.

SSA IS BUILT (`jadart/ssa.py`), using Braun et al. (CC 2013) rather than Cytron: it
constructs on demand while lowering, which fits a lifter already walking blocks and already
threading a register map, and the measured CFGs make the asymptotic argument moot (median 5
blocks, p99 86). A phi is placed at every join, sealed once its predecessors are known, and
a trivial phi collapses so an unchanging loop-carried register does not become a variable
the source never had.

VALIDATED SO FAR, and the boundary is worth stating precisely. Phi PLACEMENT is checked:
at a diamond the join value is a phi with both arms as real expressions, and at a loop the
header's phi is sealed with its back edge filled. Phi RESOLUTION against a live CPU is
checked only for acyclic paths. Loops are NOT yet checked that way, for a structural
reason rather than an oversight: a flat `{block: predecessor}` map cannot describe a block
entered five times from different predecessors, so a loop phi needs evaluation indexed by
position in the trace, which is not built. Until it is, loop values are correct by
construction and by argument, not by measurement, and this paragraph says so.

A REAL DEFECT THE SSA WORK SURFACED. `cmp x1, x2` has no destination, operand 0 is a
SOURCE, and the lowering was reading it as one, marking a live register unmodelled and
turning every later use of it opaque. Found by lowering a diamond and seeing the then-arm
come back as `?x1 + x3` where the source plainly says `x1 + x3`. `_NO_DEST` now covers
cmp/cmn/tst/teq/fcmp/fcmpe/ccmp/ccmn. Destructive rather than merely incomplete, and the
sort of thing that only shows up when something downstream is finally looking.

Remaining stages, each independently shippable, roughly 12 engineer-weeks to the end:
oracle harness; per-block value DAG plus the explicit/implied printer; SSA with phi nodes
across the existing `cfg.py` blocks (40.1% of instructions sit in join blocks, and `_merge`
currently discards exactly the value a phi would carry); a rule pool with a capped fixed
point and a loud warning on non-convergence; flags as values; the representation lattice;
the nominal cid lattice. Stages 5 and 6 change what the tool CLAIMS TO KNOW and carry the
heaviest validation.

Three latent correctness issues the measurement surfaced, independent of readability:
`canon()` maps `w` to `x` and erases operand width at 59,073 sites (12.9%), which matters
because compressed builds do Smi arithmetic in 32-bit registers; SP is still written by
`and` (428 sites) and `mov` (630) after `strip_boilerplate`, which the stack-slot map
assumes cannot happen; and pre-index writeback pushes are all filed at displacement 0, so
two consecutive pushes may alias (2,260 sites, NOT yet demonstrated to produce wrong
output, so it stays on this list rather than in a fix).

INVESTIGATED AND NOT CONFIRMED, recorded so it is not re-reported as fact: `cfg.py` gives
a block ending in `br` no successors, and that was reported as silently truncating the CFG
at 433 jump tables so the affected functions "read as smaller than they are". Two things
argue against it. The `br` itself IS rendered, as a raw arm64 line, so the reader can see
control flow leaving. And measuring blocks that never reach the statement tree finds them
in 5,081 of the 7,761 functions that contain NO `br` at all, against 100 of the 433 that
do (a lower rate, not a higher one) because that measurement is dominated by the
stack-overflow slow paths `strip_boilerplate` disconnects on purpose. Recovering jump
table targets is still worth doing for switch reconstruction; it is not a silent-loss bug
on this evidence.

## Follow-ups (UNVERIFIED items to close)
- wire-ref signed/unsigned history: `git log -p runtime/vm/datastream.h` across tags.
- exact 2.18 / 3.4 stream deltas: diff app_snapshot.cc / class_id.h between those tags.
- build the (hash, features) -> (epoch) map from the community tables + our own compiles.
