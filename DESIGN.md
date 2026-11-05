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
That count of the stub branch was a property of the INPUT and not of the code, and #234
is why: with no stub named on a release build the branch could not fire anywhere. 16,438
of the clean fixture's 34,979 direct call sites (47.0%) are calls to a stub, and that is
where it fires now.

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

Three latent correctness issues the measurement surfaced, independent of readability. The
first is FIXED and the paragraph after this one says how: `canon()` maps `w` to `x` and
erases operand width at 59,073 sites (12.9%), which matters because compressed builds do
Smi arithmetic in 32-bit registers. Two remain: SP is still written by `and` (428 sites)
and `mov` (630) after `strip_boilerplate`, which the stack-slot map assumes cannot happen;
and pre-index writeback pushes are all filed at displacement 0, so two consecutive pushes
may alias (2,260 sites, NOT yet demonstrated to produce wrong output, so it stays on this
list rather than in a fix).

WHERE THE WIDTH WENT, since it was the first of the three to produce a measured wrong
value (#235). A 32-bit destination clears the top half of its register, `canon` folds
the two views onto one name, and the printed text of a 32-bit result was therefore the
text of a 64-bit one. 3,727 of the clean fixture's 457,622 instructions compute into a w
register, and the machine's value differs from the printed one wherever the result's bit
32 or above would be set. `_narrow` writes the truncation as `.toUnsigned(32)`, which
pairs with the `.toSigned(32)` an `asr` on a w register already printed; Hex-Rays and
Ghidra carry the same fact in a TYPE (`unsigned int`, `uint`) and Binary Ninja in the
register name, and this file has neither.

Two rules keep that from flooding the output. Reading the w view of a register takes the
low 32 bits, so `_leaf` hands a consumer the value as it was before the truncation
(`V.wide`) and the consumer truncates its own result instead: one `.toUnsigned(32)` at
the end of a chain of 32-bit operations rather than one on every step, which is where a
type-carrying decompiler puts its cast too. And `V.bits` carries a conservative upper
bound, so a result that provably has no bit above 31 is left alone: a mask that small, a
literal, a 32-bit shift right, a sum of two bytes. 638 truncations reach the clean
export, and not one `tools/quality.py` symptom moves on either fixture: the same 185,479
lines, 20,015 bare-register lines and 54,069 byte-offset fields.

The second half of that issue was the GATE. `tools/irfuzz.py` excluded every w operand
by construction, on the grounds that the fold was a display choice an oracle over 64-bit
registers should not adjudicate, so no gate in this repo could see the class at all.
Dropping the exclusion put 32 real mismatches on the clean fixture and 30 on obf in
front of the first run. Dropping it WITHOUT teaching the evaluator `toUnsigned` and
`toSigned` leaves 3,500 of the clean fixture's expressions undecidable and reports no
mismatches, which is what a hollow fix looks like; with both, the clean fixture's text
pass checks 255,731 printed expressions where main checks 250,770, and disagrees with the
CPU nowhere.

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

### Where a runtime stub's name comes from, on a build that has no symbol for one

Every stub-aware rule in the lifter keys off an `_iso_stub_<Base>Stub` NAME:
`_classify_stub` decides whether a `bl` is a throw, an allocation or machinery to drop,
`_noreturn` asks it whether a path ends there, `_call_args` falls back on it, and
`_pin_call` treats a named stub as giving every register back. The names had two
possible sources and a default `flutter build apk --release` has neither. A stub's
`Code` object is owned by no `Function`, so the snapshot's name table has nothing for
it, and the .so carries no symbol table at all. Both fixtures measured 0 stub names,
which made the whole taxonomy dead code on the build a user actually has: 16,438 of the
clean image's 34,979 direct call sites, 47.0%, were calls to a stub printed as
`sub_0x2d5d00(...)`, an ordinary Dart call that returns, where six of those targets end
in `blr x30; brk #0` and cannot (#234).

THE THIRD SOURCE IS THE SNAPSHOT ITSELF. After the fill pass an AOT program snapshot
writes its roots: the isolate `ObjectStore`'s pointer fields in declaration order, from
`from()` through `to_snapshot(kFullAOT)` (app_snapshot.cc,
`ProgramDeserializationRoots::ReadRoots`). The tail of that run is the stubs generated
code calls, each a `Code` whose instructions-table slot already maps to a pc, so the
root INDEX identifies the stub. The index means something only through the release's own
`OBJECT_STORE_FIELD_LIST`, which tools/gen_objstore.py expands the way gen_cids.py
expands the cid enum: ten distinct root runs cover the eighteen registered epochs, 244
roots at 3.12 and 224 at 2.19.

THE REASON IT IS A READING AND NOT A GUESS is that the binary confirms the table twice.
The layout states which roots are `Code`-typed and the reader checks every one of them
against the `Code` objects the fill pass recovered, all 244 of 244 agreeing on each
fixture; a field inserted ahead of the stub block in some release the table was not
generated from shifts every later index, and a shifted index lands a non-`Code` where a
`Code` is declared, so the whole map is dropped and nothing is named. Independently, the
root run has to END exactly where `dispatch.find_dispatch_table` anchors the dispatch
table from an unrelated invariant, which it does on all seven binaries measured (both
fixtures, three architectures, clean and obfuscated). A third check reads the TEXT: no
stub named as a throw contains a `ret`, and every stub named as an allocation can
return. The last two live in the tests rather than in the parse path, because they cost
a scan and a disassembly.

WHY NOT THE OTHER TWO CHANNELS. Recognising the prologue shape (the FLIRT and Ghidra
FunctionID approach) identifies a shared stub but not which one, and the fixture holds
the counterexample: `allocate_float64_array_stub` opens with the same `str x30, [x15,
#-8]!` spill-everything prologue as the six error stubs and it returns. Deciding only
the return discipline from the body (Ghidra's discovered non-returning functions, LLVM's
attribute inference, Binary Ninja's `can_return`) is sound and needs no table, and it is
kept here as the text check above, but it yields no source meaning: no `throw`, no
allocation type, and a call still prints as a call. Blutter reaches the same facts this
uses by compiling the matching Dart SDK per version; a generated table gets them without
a toolchain.

WHAT IT CHANGED, on the clean fixture's whole image: `(...)` calls 9,196 to 5,139, lines
188,930 to 184,380, byte-offset fields 55,572 to 55,181, and 1,705 `throw` plus 886
`new` renderings in the first 3,000 ranges where main had none of either. The obf
fixture moves by the same amounts. Bare machine registers rise, 20,460 to 20,618, and
that is the usual direction of this trade: a line that said `sub_0x2d5670(...)` carried
no register and said nothing either.

ONE LATENT DEFECT CAME WITH IT, and only naming could expose it. `_classify_stub`
grouped the stubs that hand a value back in x0 (`InitLate*`, `Await`, `InitAsync`,
`CloneContext`) with the ones that give every register back, and `_step` drops the call
for both. Dropping a call that RETURNS something leaves the stale x0 standing in for the
value, so a lazy-init getter whose `if` arm called `InitLateFinalInstanceField` came out
as `return x0;`, a whole body replaced by a bare register, thirteen times on the clean
fixture. They are rendered as the calls they are now, which is also what `_rv_call`
already assumed about them (#127).

TWO RESIDUALS, measured and not fixed here. 1,571 statements still print after a
`throw`, which is the dead phi write-back the issue names: `_ends_path` ends the block
for the graph while `_arrive`'s write-back still lands after it. And blocks whose only
statement is an assignment nothing reads went 1,398 to 1,575, one shape: a type-test
stub is dropped and the class-id load in front of it is left with no reader.

### The edge a call that cannot return used to have

Naming the stubs made the second half of #234 visible, and it is the one the issue is
titled for. `build_cfg` ends a block at a terminator, at a trap mnemonic (#57) or at an
address `exits` names, and a `bl` is none of those, so a call to a stub that throws kept
its fall-through edge. `FocusTraversalPolicy.next` is the shape that shows what that
costs: the compiler lays out three one-instruction blocks, each a `bl` to the
null-cast-error stub, so the arms of three null tests can branch into them, and the lift
rendered the last as `throw NullCastError(); goto L_0x12c928;`, a jump out of a throw,
while the two `if`s above it lost their else arms to the edge. The same edge fed joins:
a phi met a value from a path that never arrives, and 1,224 statements on the clean
fixture printed under a `throw`.

THE FIX IS THE ONE EVERY OTHER TOOL MAKES, at the IR and not at the printer. angr adds
an inferred return edge at a call and REMOVES it when the callee turns out not to
return, re-recovering the CFG and dropping what is no longer reachable. Ghidra clears
the fall-through of a non-returning call and its decompiler eliminates the unreachable
code. Hex-Rays marks the call `__noreturn` and the microcode drops the rest of the
block. LLVM puts `unreachable` after such a call and SimplifyCFG deletes what follows.
So the lift hands `build_cfg` the addresses nothing runs past (`_path_ends`, from
`_ends_path`, which already knew which callee throws), and those blocks end with no
successor exactly as a trap's does.

WHERE THIS DIFFERS FROM GHIDRA AND HEX-RAYS IS WHAT HAPPENS TO THE CODE AFTER THE CALL.
Both drop it, and both document the hazard that follows: a callee wrongly marked as
non-returning hides real source, which is why Ghidra has an `Eliminate unreachable code`
switch and Hex-Rays tells you to clear the `noret` flag. Here that code is placed as its
own labelled section, which is what #57 already does for the code after a trap, because
it can be a catch entry and the CFG does not model exception edges. Measured, not
argued: over the 16,382 ranges of the two fixtures, not one instruction that the
structurer placed before this change stopped being placed, and none appeared that was
not placed before. `cfgcheck` reports 0 edge violations and 0 dropped blocks on both.

TWO SMALLER RULES FOLLOW FROM THE SAME FACT. A block nothing runs past hands nothing to
the statement after it, so `_lift_block` reports it as not falling through; an `if` arm
that throws then contributes nothing to the join, which takes the surviving arm's state
exactly rather than meeting it with a path that never arrives. And `State.set`, which
mints a name for a value too long to inline, was the one minting site outside `_mint`,
so the hoist could not move its declaration to the top of the body; sharing those names
took the last reads of a closed declaration out of the output.

WHAT IT ADDS UP TO on the clean fixture, against main: statements under a `throw` 1,224
to 0, `goto`s 6,830 to 5,493 and the functions that emit one 1,649 to 1,414 (20.1% to
17.3%), the #198 wrong-reload residual 2,579 to 2,089, reads of a closed declaration 5
to 0, lines with a bare machine register 20,460 to 20,015, byte-offset fields 55,572 to
54,069, and 3,451 fewer lines in all. The obf fixture moves by the same amounts, and
tier 2's export is byte-identical, since only the lift hands over the addresses.

ONE RESIDUAL, measured and guarded rather than fixed. One range of each fixture reads a
name that no line of its body binds, because a walk the lifter discarded minted it and
the walk that shipped did not, so there is no assignment left to hoist to.
`_lift_function` declares it at the top, which is what an initialiser-less declaration
means everywhere else in the file, a value this lifter does not know. The leak itself, a
name escaping a trial walk, is worth its own issue.

### A block the entry cannot reach, and the two things it was allowed to decide

Both halves of #237 are the same fact: `structure` and `expr` ask questions of a block no
path from the entry reaches, and two of their answers were claims rather than refusals.

THE DEFINITION HAS TWO HALVES AND ONLY ONE WAS ASKED OF THE BODY. The natural loop of a
back edge n -> h is the set of nodes h dominates that can reach n without passing through
h. `loop_nodes` asked `dominates(header, n)` of its LATCHES and only the reaching half of
the body, and the two differ in exactly one place: a block the entry cannot reach is
dominated by nothing, so it answers the reaching half and no more. The backward walk from
the latch took one in, `loop_exit` counted its edge out of the node set as a vote for
where the loop goes, the votes tied at one apiece, and the lowest address won, so the
block printed after the loop was one no run enters, and the state the lines after the loop
are spelled from carried its writes. On a generated graph that state said `x2 = x9 + 27`
where the CPU leaves x2 at the value the function was called with.

WHERE THE OTHER TOOLS ARE. LLVM states the rule from the other end: for a basic block not
reachable from the entry the concept of loops is undefined, since dominance is undefined
as well, and its LoopInfo is built over the dominator tree, which holds no such block.
Hex-Rays deletes them outright (`mba_t::remove_empty_and_unreachable_blocks`), and
Ghidra's decompiler has an "Eliminate unreachable code" analysis option that is on by
default; turn it off and the code still does not appear in the decompiler, only in the
disassembler. Deleting makes the question moot, and jadart cannot: a catch entry is
exactly a block with no edge in, because the CFG does not model the exception edge, and
dropping it loses real code (#57, #234). So the block stays in the output and is refused
an answer instead, which is the same trade this file makes for a call that cannot return.

THE SECOND HALF IS WHAT THE SECTION HANDS DOWNWARD. Such a section is placed, and it FALLS
THROUGH into whatever the tree put below it. `_reenter` already says that a block emitted
after something that did not fall through takes the state its own predecessors justify,
and a fall-through out of a section nothing reaches is the case it did not cover: the
block below read what the section wrote, on a way in none of its predecessors takes. The
goto-join's meet (`_join_kill`) exists for exactly this and cannot see it, because the
narrowing it makes from the join's immediate dominator can never hold a block the entry
does not reach. The guard is `_reenter` again, asked on arrival rather than on re-entry.
A fall-through is the only way such a section hands a state anywhere, since every other
way out of one is a `goto`, and `_arrive` hands a state over only where the target has a
single predecessor, which is the section itself.

IT TAKES TWO QUESTIONS AND THE FIRST VERSION ASKED ONE, which is worth writing down
because the one it asked is the obvious one. A region nothing reaches is still a region:
its own flow is the only flow there is, so a join inside one, every way into which is
inside it too, has nothing to meet with and its state is as justified as that region gets.
Asking only whether the state came out of such a region wiped exactly that join in
`resolve` (`.text+0x1753f0`) on both fixtures, where both paths carry `x9 + 27` and the
store printed it, leaving `x8.field_0x1 = x2;`: a bare register no line of that body
binds, standing in for a value the output had, which is the shape this file calls a wrong
answer and not a vaguer one. Every firing the first version had on either fixture was that
case, all three of them. So the guard asks for a predecessor the entry CAN reach as well,
the way in the arriving state cannot speak for, and `_join_kill` keeps the ways in it can.

AND `_reenter` HAS TO SAY WHOSE STATE IT JUST INSTALLED, which is the other thing the
first version got wrong. It replaces the register map, the slot map and their records and
left `State.src` naming the block it had just disowned; `_lift_block` sets that at its
end, which was enough while `_reenter` only ran where nothing fell through and the block
was lifted straight after it. Read on a LIVE arrival, the stale source fired the guard a
second time: once at the loop statement, rightly, and again at the header's own block
inside `_render_loop`, after the loop had bound its carried registers to names, where the
reset took those names with it. A counter's declaration and both of its write-backs left
the loop, which could then not advance at all, with the `sub x7, x7, #1` that drives it
nowhere in the body. The call site also makes the `carried` exclusion the goto-join meet
makes four lines below it, where the reason is already written down: a loop header's
registers are bound by then, and killing them puts the machine register back into every
line of the body.

AND THE PHI RECORD IS ABOUT THE EDGE, which is the third thing the guard had to learn and
the one that cost a wrong value. `_join_write` runs on the same fall-through, right after
the guard, and records WHICH WAY IN wrote the join's shared name; the join binds the
register to that name only where every way in wrote it (#123). It read the writing edge
off `State.src`, which the guard had just replaced, so the record named the block being
entered instead of the edge, no set of edges could cover the predecessors, and the join
dropped to the bare machine register: on a loop that writes a register on two arms and
prints it on one, the join read `x2` where the machine has `x9 + 1`. The caller hands the
arriving edge over directly now, and `_reenter` says whose state it installed rather than
whose it replaced, which is the predecessor it took it from or nowhere at all.

WHAT THAT LEAVES IS A FIX WITH NO CORPUS WITNESS, stated plainly because the alternative
is to imply one. With both questions asked the guard fires nowhere on either fixture and
nowhere in 8,000 generated graphs: the shape needs a section whose address is below a join
that the main walk left for the sweep, and neither the corpus nor `_gen_nested` draws one.
A hand-built graph does, and the wrong value on it is real, so the gate is a test rather
than an oracle; teaching `tools/irfuzz.py` to generate a trap and a section after it is
the way to put this class under an oracle, and it is its own piece of work.

MEASURED, INCLUDING THE FIX THAT WAS NOT SHIPPED. 980 of the clean fixture's 1,154 loops
held a block the entry cannot reach, in 621 ranges, and not one of them picked a different
exit, so the corpus never showed the first half either: `tools/irfuzz.py --cfg --nested`
found it at 2 in about 36,000 generated graphs. Over both fixtures the printed output does
not move at all: the same 185,479 and 185,280 lines with every `tools/quality.py` symptom
unchanged, the clean export byte-identical, the same 435,854 and 435,633 instructions
placed over 8,194 and 8,188 ranges, and `pbfuzz --census` unchanged.

WHERE THE EXIT PICK DOES CHANGE, TIER 3 PRINTS LESS, and the gate that says "nothing is
dropped" cannot see it, which is worth being exact about. `cfgcheck` structures with
`orphans=True`; the lifter does not, so a block nothing reaches is placed for Tier 2 and
not for Tier 3 (#67). The old exit pick printed some of those blocks anyway, after the
loop, with no label and no note, as if they ran. Over 4,000 generated graphs, 6 now place
20 instructions fewer with `orphans=False`, every one of them in a block nothing reaches,
and 0 place fewer with `orphans=True`. The check for that is the placement comparison per
range, not `cfgcheck`: both fixtures place the same instructions as before, 435,854 and
435,633.

The first attempt at the second half widened `_join_kill` instead, so that a join forgot
whatever an unreachable ancestor writes whichever way the walk arrived; that is the static
reading of a meet, and it cost 1,488 bare-register lines on the clean fixture and 1,643 on
obf while fixing nothing the arrival guard does not.

ONE RESIDUAL, measured and not shipped. `_reenter` rebuilds the register map, the slot map
and their records from the predecessor it takes the state from, and leaves `State.lost`,
`opaque`, `lost_slot` and `views` as the path it is replacing left them. That was
invisible while it only ran where nothing fell through; it now also runs on a live
arrival, where a leftover `lost` or `opaque` does reach a printed line, since a store
through such a base is spelled as a freshly minted raw name (#208). Rebuilding the four
from the same predecessor takes one bare-register line off each fixture and adds one
byte-offset field, with the suite green. It is not here because the no-carry direction is
a real question and not an oversight: clearing them says nothing is lost, where the honest
reading of a block with no justified way in may be that everything is. That belongs with
#140 and #208.

### What a flag-setting instruction writes, and where its comparison can be read

Two halves of #239, and the same shape as the other tools' answer in both.

THE VALUE AND THE FLAGS ARE TWO DEFINITIONS OF ONE INSTRUCTION, and only the flags were
modelled. `subs x0, x1, x2` printed as arm64 where `sub x0, x1, x2` prints `x1 - x2`, the
only difference between them being the flag suffix, and the register it wrote read as
nothing after it: 262 raw lines on the clean fixture. Ghidra translates one machine
instruction to a sequence of p-code operations, each of which writes at most one varnode,
so the register result is its own operation and the flag bits are theirs. Binary Ninja
lifts the value as the ordinary definition and emits the flag IL beside it, only where a
consumer reads it. LLVM's AArch64 `SUBSWrr` writes its GPR and carries
`implicit-def $nzcv`, and where the value is unused the selector emits `$wzr = SUBSWrr`,
which is what `cmp` is. Here the value comes from the plain twin and the flags stay with
`_note_flags`, which is also LLVM's own rewrite in the other direction: its
`AArch64PostSelectOptimize` turns a flag-setting op back into the plain one when NZCV is
dead.

THE COMPARISON LIVES IN STATE, NOT IN A BLOCK. `_flag_cond` declined wherever the flags
were set anywhere but the block it was asked in, and that was 102 of its 106 declines on
the clean fixture. VEX keeps a thunk of the last flag-setting op and its operands in GUEST
STATE (`CC_OP`, `CC_DEP1`, `CC_DEP2`) and computes the condition where it is READ, so the
fact crosses an edge like any other value; Hex-Rays makes the condition its own
microinstruction over the two comparands, so it is an operand; Binary Ninja resolves a
flag use where the flags were set by one instruction that reaches the use, a unique
reaching definition rather than same-block adjacency. `self._flags` already IS that
thunk, mnemonic and operands and their rendered values, so the only thing missing was the
edge, and it is taken where the block has one predecessor, which is the one case with
nothing to meet.

THE VALUES ARE RE-READ AT THE USE rather than carried as text, which is the part #237 paid
for twice. The text a predecessor captured can name a temp it declared, and `structure`
prints blocks in an order that is not a path, so that name need not be in scope where the
condition is read. For a block with one way in the arriving state IS the predecessor's
exit state, so re-reading spells the same values in names that are in scope, and it is
exact because the thunk's own invalidation guarantees nothing after the comparison wrote
an operand of it. The exception is a comparison that overwrote an operand it compared,
`subs x1, x1, #8`, where the arriving state holds the new value and only the captured text
holds the old one (#116); that one declines.

MEASURED, AND THE CEILING IS A MEASUREMENT TOO. On the clean fixture raw arm64 goes
1,553 to 1,288, with `subs`, `ands` and `adds` gone from the histogram entirely, lines
carrying a bare machine register 20,015 to 19,446, 254 lines off the output, byte-offset
fields 13 fewer, and the #198 wrong-reload residual 2,089 to 2,086; the obf fixture
moves by the same amounts. The second half is worth 3 of the 78 raw selects, and the
other 99 declines are accounted for rather than assumed: 48 are joins, whose two ways in
would have to agree before anything could be spelled, 32 are the `subs x1, x1, #8` shape
above, 13 had their comparison dropped before the edge, and 4 are blocks nothing
reaches. The joins are the next step and the largest one.

AND THE GATE DID NOT EXIST, which is the part worth copying from #235. A flag-setting op
sits next to the branch that reads it and a branch ends a straight-line run, so
`expr_cases` draws 5 runs containing one out of 6,623 over the whole clean fixture, and
the default sweep of 2,001 runs reaches none of them: the class could not be adjudicated
at all. The forms are drawn in the generated graphs now, under `--flags` and in a pool
of their own, because every named case in the suite is a (seed, index) coordinate into a
generator stream and widening the shared pool moves all of them (#230, and two ablation
gates read as blind the moment it did). On those graphs the oracle goes from 300
register results run against a CPU to 17,800, and from 127,350 printed expressions to
246,750, with no disagreement on any seed.

ONE THING MEASURED AND NOT SHIPPED. The thunk is invalidated by a write to any register in
the comparison's operand list, which includes the DESTINATION: `subs x5, x1, x2` compares
x1 and x2, and a later write to the dead x5 cannot change what either says. Narrowing that
to the registers the captured values rest on renders 31 more selects, taking the raw count
to about 44, and costs 9 more #198 wrong reloads, 2,086 to 2,095. That is a trade across
two numbers the census deliberately keeps apart, so it belongs to its own change with its
own measurement rather than riding in here.

### A displacement below the base, and why it is not a field

#236. One number was carrying two facts: where the access is, and which field of the
object it lands in. Those two agree only at or above the base.

THE TAG IS NOT THE SAME THING AS A STEP BELOW THE BASE, and counting separates them.
`Lifter._byte_off` decides the bias from the base REGISTER's name, tagged unless the name
is an untagged role register, and for `[P, #-1]` that is exactly right: kHeapObjectTag is
1, so offset 0 of a tagged pointer sits one byte below the pointer, it is the object
header, and `.tags` is the text. 11,184 of the clean fixture's 11,695 accesses with a
negative displacement are that read. The other 511, over 60 of the 2,082 ranges that use
one at all, step BELOW the object: a pre-indexed backward copy (`_quickCopy` at 0x1aace0,
`ldr x16, [x1, #-8]!`, at -2, -4, -8 and -16) and a walk off one saved interior pointer at
-64 down to -176. Their biased offset came out negative and printed as one,
`t3.field_0x-3`, 236 lines of the clean export and 2 of the obf one. None of the 511 has
an untagged role base, so the old spelling's one genuine ambiguity never arose in
practice; it printed a field at a negative offset instead, which no object has.

THE OTHER TOOLS EITHER MOVE THE NEGATIVE PART INTO THE BASE OR REFUSE. Ghidra builds the
very same default name this output borrowed, `field_0x` plus hex, and guards it:
`PrintC::opPtrsub` reaches that `ostringstream` only past
`if (ct->getSize() <= suboff || suboff < 0) throw LowlevelError("PTRSUB out of bounds into
struct")`. Upstream of the printer, `TypeStruct::isOffsetValid` answers false for a
negative offset (`getSubType` finds no field, `getFieldIter` returning -1, and the
leftover lands in the `extra < 0` test), so `RulePtrsubUndo` rewrites the PTRSUB back to
an INT_ADD and the access prints as plain pointer arithmetic with a cast. Hex-Rays does
the rewrite this change does: applying a structure offset to a negative number "usually
converts the whole (var-num) expression into the CONTAINING_RECORD macro", which is the
base moved down by a member offset so the member can stay non-negative. Binary Ninja
cannot spell one at all, a structure member's offset being unsigned (`u64`).

THE FOLD IS EXACT WITHOUT THE REPRESENTATION LATTICE THIS SECTION ASKS FOR. `_rebase`
folds the RAW displacement, not the biased offset: the address is `base + disp` for a
tagged and an untagged base alike, and offset 1 is the read at the base expression, which
is the convention `_frame_read`, `_FRAME_TEXT_RE` and docs/usage.md already state for any
base that is not a bare role register. So `(t4 - 8).field_0x1` needs no bit on `V` saying
Tagged or Untagged, and it is the text the write-back prints on the next line, which is
the reader's own cross-check. What the lattice is still for is the OTHER half of #236, a
base register holding an untagged pointer the lifter LOADED rather than one of the role
registers it has a table for. 2,876 accesses on the clean fixture have a base the register
tables call tagged and an even displacement, so they print an ODD field offset, and
`THR.field_0x78.field_0x6a1` (114 of them) is +0x6a0 of the pointer in THR+0x78 with
nothing in the text saying to subtract one. That is a spelling question about a positive
offset and is left open; this change only stops the output naming offsets no object has.

MEASURED. Every negative spelling is gone from both exports, 236 lines to 0 on clean and 2
to 0 on obf, and nothing else in either export moves except one line that is added. That
line is #209's may-alias pin finally firing: `_pin_mem` takes the written selector with
`_FIELD_LHS`, which `.field_0x-7` never matched, so a store below the base never froze a
live read at the same offset through a different base. `tools/quality.py` reads the class
210 lines larger on each fixture for the same kind of reason, its `_FIELD_RE` cannot match
a negative number either, so the byte-offset-field symptom was understated, not absent.
`pbfuzz --census` does not move on either fixture, 2,086 wrong reads and 0 stale records,
and no irfuzz oracle reports a mismatch. The oracles cannot score this class directly:
`corpus_cases` and `expr_cases` drop any operand containing `[`, and the memory generator
draws only the displacements 7, 15, 23 and 31, so the gate for it is a test.
### 13.1 Which base may carry a field name, and the three candidate proofs

The byte-offset field is the largest single symptom in the output, 69,074 accesses over
all 8,194 ranges of the clean fixture and 70,764 over the 8,188 of the obf one, and
until #240 a name was printed off one base only: `this`, whose class `Function.owner`
states. Counted per site, that is where they are:

| where the access is | clean | obf |
|---|---|---|
| on the receiver, `this` | 9,943 | 12,512 |
| ...of which the field map has no entry for the offset | 9,770 | 12,274 |
| NOT on the receiver | 59,131 | 58,252 |

The second row is #240's population 1, a slot whose `Field` object was tree-shaken, and
nothing about the base is wrong there: the class is known and the name is gone. The
third is population 2, and naming any of it needs a source of the base's class that is
not a guess. Three were measured before anything was built, and only one of the three is
worth building.

**A generic allocation stub, which is worth nothing.** `expr._ALLOC_TYPE` maps the
object-store allocation stubs to a type for the `var t0 = new List(...)` spelling, so
the class of those results has been known since the stubs were named (#234). 2,536 field
accesses on each fixture are off one. **0 of them can be named**, on both fixtures, and
the reason is structural rather than incidental: that table names `List`, `Context`,
`Closure`, `double`, `Record` and the typed-data arrays, every one of them a VM
representation whose slots are native rather than Dart `Field` objects, so there is
nothing in the map to look up. A measured zero, and the first thing the attribution
said.

**A PER-CLASS allocation stub, which is the one that pays.** `Code::owner()` is the
Function, Class or AbstractType the code belongs to, and the VM makes a CLASS the owner
of exactly one kind of code: that class's allocation stub
(`StubCode::GetAllocationStubForClass`, `Class::allocation_stub_`). 921 of the 8,194
Code objects on each fixture are owned by a Class, called from 3,185 and 3,183 sites,
and the body of each is three or five instructions that load the new object's header
word into `AllocateObjectABI::kTagsReg` and tail-branch to the shared stub. Two
byte-exact agreements, neither of them a plausibility argument:

* bits 12..31 of that immediate are the class id, the field `detect_dispatch` already
  extracts with `ubfx cid, tags, #0xc, #0x14`, and they are the owner Class's own id on
  **921 of 921** stubs on both fixtures, 0 disagreements. One disagreement refuses the
  whole map, for the reason an out-of-range field offset does in `recover_fields`: all
  921 owners were read the same way.
* bits 8..11 hold instance_size / kObjectAlignment and match the Class cluster's
  instance size on **916 of 916** where four bits can hold it, 0 disagreements.

7,504 field accesses on the clean fixture and 7,515 on the obf one are off such a
result, of which the field map names **692** and **234**; 686 and 228 reach the output,
the rest sitting in values a later pass renames or folds. The others refuse: 611 on each
land inside `instance_size` but past `next_field_offset`, and 6,201 and 6,670 land on a
slot inside the object whose `Field` object was tree-shaken, which is population 1 again
under another base. **0 of the 7,504 and 0 of the 7,515 land OUTSIDE the owner's
instance size**, which is the test that decides whether the attribution is a proof: a
class misattributed to a stub would scatter accesses past the end of its object, and
7,504 independent displacements out of the compiled code agree with the geometry the
Class cluster records. One that did not would drop the whole attribution for that base,
and that guard fires 0 times on either fixture.

**A dominating cid comparison, which is the bigger idea and currently worth 17 names.**
Above, this page counts 2,841 cid comparisons as flow-sensitive proofs of a receiver's
class on one branch edge. Narrowing that to the ones that could carry a field name:
5,808 sites extract a cid from a tags word on the clean fixture, 1,631 of them compare
it against a single immediate and feed an eq/ne branch (1,630 on the obf one), 1,608 of
those name a class this snapshot has, and 388 name one with a field map. Walking the
proven edge straight-line until the receiver register is redefined finds **535** field
accesses off the proven receiver, of which the map names **17** (11 on the obf fixture).
The ceiling is the field map's coverage, not the class attribution, and the cost is a
flow-sensitive refinement the textual lifter has no place to put. The remaining 4,177
cid sites are RANGE checks, `sub x9, x9, #0x438; cmp x9, #0x5a; b.hi`, which prove a
contiguous span of the class hierarchy rather than one class; the common ancestor's map
is the honest thing to read there and it is not read today.

### 13.2 What marking a recovered name as INFERRED costs, and why nothing is marked

The rule this repo holds, that output must never state what the input does not prove, is
the mainstream convention stated more strictly than the tools state it, and the
convention is worth citing rather than reinventing.

The `field_0x` plus the hex offset is Ghidra's own spelling, synthesised in `printc.cc`
for an access a structure has no declared member at, and Ghidra's help documents that
spelling as an epistemic signal: "If the initial name looks like field_0x.., it may be
that the field offset was discovered by the Decompiler, and the field does not exist in
the structure definition." The decompiler core never invents a structure at all;
`RulePtrsubUndo` converts a field access back to integer addition when the type
information turns out not to support it, so the output degrades to `*(undefined4
*)(param_1 + 8)`. Automatic structure creation is a user-invoked Java action whose
results are marked three ways at once, by name (`astruct`), by category path
(`/auto_structs`) and by every member being `undefined*` and `field..._0x...`;
provenance is carried program-wide by `SourceType`, ordered `USER_DEFINED > IMPORTED >
ANALYSIS > DEFAULT`, and type propagation stops dead at a `typelock`. Conflicts resolve
most-specific-wins and residual disagreement becomes a cast or an inline `/* WARNING:
... */` comment, which is the one tool here that writes its doubt into the text.

Hex-Rays draws the same line in three states rather than two: `lvar_t::flags` carries
`CVAR_TYPE` ("the type is defined?") and `CVAR_UTYPE` ("user-defined type") separately,
so inferred and confirmed are distinguishable in the API, and `set_lvar_type`'s own
documentation says the type "is not considered as final by the decompiler and may be
modified later by the type derivation". With no type bound it prints the mechanism and
no name, `*(_DWORD *)(a1 + 1713)`, and its sized-unknown keywords (`_BYTE`, `_DWORD`,
`_QWORD`, `_OWORD`, `_UNKNOWN`) say the width and nothing else, which is why `_field`
cites `_OWORD` for the 16-byte spelling. Its structure proposal is a dialog the user
accepts, and its members are `dword18` and `gap1C`, offsets again. Once a type IS bound,
even one the decompiler guessed, member names print plainly and the only marking is
colour, gray for guessed against blue for definite.

Binary Ninja is the one mainstream tool that carries a numeric confidence,
`BNTypeWithConfidence` over five named levels (`BN_FULL_CONFIDENCE` 255,
`BN_DEBUGINFO_CONFIDENCE` 200, `BN_HEURISTIC_CONFIDENCE` 192, `BN_DEFAULT_CONFIDENCE`
96, `BN_MINIMUM_CONFIDENCE` 1, with 0 reserved for unknown), composed multiplicatively
and floored, and it reaches the rendered output only as a theme colour
(`uncertainColor`). Its auto-created members are `field_` plus the hex offset, and an
access with no member at all prints `var->__offset(0x28).d`, the offset and the width.
It is also the counterexample to the claim that nobody prints an unproven name:
`var_18_1->field_4` appears in HLIL off a machine-guessed structure with nothing in the
text to say so. angr's Typehoon does the same automatically, `v->field_8` off pure
inference. In both cases the name IS the offset, so no semantic claim is smuggled in,
which is the same answer as refusing.

The academic line is where the argument for refusing is made rather than assumed. TIE
(NDSS 2011) outputs an interval instead of a type, "an upper and lower bound on the type
for each variable", and says why: "outputting a range is much more general, and can make
explicit the uncertainty due to the nature of the problem." It takes the conservative
branch at the one place it could trade soundness for specificity ("TIE always applies
the former, since our goal is to always infer types conservatively"), and its two
scoring definitions are the formal version of this repo's rule: a correct-but-general
answer is conservative and scores a small lattice distance, while an incompatible one
fails conservativeness and scores the maximum. It also removes what it cannot support,
"If B of record types has fields of T, we remove the fields", and its judgement on the
alternative is blunt: "it appears that in many cases Hex-rays seems to be guessing
types". REWARDS annotates memory it never saw as `unused` and says its field symbols "do
not represent their symbolic names, which we do not know, but rather the type tags
derived for these fields". Howard puts the precondition in one line: "we cannot
recognize what is not there."

Two dissents are worth recording rather than hiding. OSPREY (S&P 2021) scores a `void *`
recovered for a `Socket *` as INCORRECT, not as conservative, which is the opposite of
REWARDS' and Howard's "correct or unused" grading; and DIRTY (USENIX Security 2022)
argues outright that a wrong-but-suggestive name helps, "the type suggested by DIRTY
(MpegEncContext_0 *) could still be quite useful to a reverse engineer, even if it is
inaccurate". DIRTY's own mitigation is the shape of an answer this project could take if
it ever wanted to print a probable class: a separate suggestion channel over the
decompiler's output, not a fact inside it.

So nothing is marked, because nothing unproven is printed. The three candidate sources
above are each a statement the snapshot makes, cross-checked against a second encoding
of the same number, and bounded by `instance_size` the way `recover_fields` bounds the
map. Where a name cannot be reached that way the byte offset stands, which is Ghidra's
documented spelling for exactly this, and the reader can see that it is opaque.

## Follow-ups (UNVERIFIED items to close)
- wire-ref signed/unsigned history: `git log -p runtime/vm/datastream.h` across tags.
- exact 2.18 / 3.4 stream deltas: diff app_snapshot.cc / class_id.h between those tags.
- build the (hash, features) -> (epoch) map from the community tables + our own compiles.
