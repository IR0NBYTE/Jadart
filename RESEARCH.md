# Research proposal: an open-source reverse-engineering framework for Flutter apps

**This is the proposal the project started from, kept as written.** The status log at the
end stops at the point the framework became the deliverable; the current state of the tool
is in the README, the measurements in EVAL.md, and the record of changes in CHANGELOG.md.
Where the two disagree, this file is the older one.

Working vision: the "JADX for Flutter". A single, version-robust, open tool that takes a
Flutter app and gives back readable, navigable Dart, the way JADX turns a DEX into
readable Java.

## 1. Problem and motivation

Flutter compiles Dart to a native AOT snapshot (`libapp.so`). Because the output is
machine code with no JVM bytecode and stripped symbols, teams ship banking, fintech,
health, and identity apps on Flutter on the assumption that AOT compilation hides their
client-side logic. That assumption is wrong but under-examined: the logic is recoverable,
yet the public toolchain to do it is fragmented, version-fragile, and stops at assembly.

This is a security problem on both sides. Defenders need to know what an attacker can
actually recover from a shipped Flutter binary (secrets, endpoints, anti-fraud logic,
crypto). Attackers and auditors need reliable tooling to do that recovery. Today neither
side has a JADX-class tool, so the real exposure of the Flutter ecosystem is unmeasured.

## 2. Thesis

JADX's value is not disassembly. It is DEX to readable Java, in one coherent tool, with
cross-references, search, and a UI. No Flutter tool does the equivalent. Every existing
tool stops earlier, at symbolicated or annotated assembly. The thesis of this project is
that snapshot to readable pseudo-Dart is achievable, and that a version-robust, unified
open-source framework built around it becomes the de facto standard the same way JADX did.

## 3. State of the art (to be expanded from the grounding research)

| Tool | Mechanism | Stops at | Key limitation |
|---|---|---|---|
| Blutter | embeds the Dart VM, deserializes via VM APIs, walks the heap | symbolicated assembly + object pool + Frida hooks | compiles a matching Dart SDK per target version; heavy, per-version brittle; Android arm64 only |
| unflutter | VM-free parse of the snapshot byte grammar | annotated assembly + xrefs | hand-codes each Dart format; documented to 3.10.7; silently falls back to newest-known model on unknown versions |
| Ghidra + scripts | generic decompiler + a Dart calling-convention spec | C-like pseudocode | not Dart-aware semantics; manual; heavyweight |
| reFlutter | patches the engine, repackages | runtime/traffic redirection | not static recovery |
| doldrums / darter | early pure-Python parsers | class/method dumps | dead, pinned to old Dart |
| JEB | commercial Dart AOT helper | assisted analysis | closed source |

Measured + source-confirmed facts (see FINDINGS.md and DESIGN.md):
- unflutter's unknown-hash path silently falls back to the 3.9.2 profile, then to a default
  ProfileUnknown, rather than erroring. Dart 3.11/3.12 are supported only for their exact
  known build hashes (added Feb 2026); any other hash silently mis-parses. Our Dart 3.12.2
  binary parsed with no version banner and no build-id in metadata: the silent fallback. Its
  own issue #1 shows the footgun as a mid-fill crash (a libapp.so mis-detected as 2.10.0).
- On the obfuscated build the names were gone (functions became `stub_<offset>`), but the
  flag string xref still located the check.
- Blutter avoids mis-parsing by construction (it only runs when it built the matching Dart
  SDK), but pays a per-version SDK-compile cost, is Android arm64 only, and needs a
  Linux-ish toolchain. Neither tool produces Dart or structured pseudocode; both stop at
  annotated assembly. JEB gets closest and still flags that it needs proper
  calling-convention modeling.

## 4. The gaps that define the contributions

1. Decompilation to readable pseudo-Dart, from names the binary itself carries.
   NOTE, 2026-08-09: this gap was originally written as "snapshot to readable pseudo-Dart
   does not exist anywhere", and that is no longer true. `flutterdec` (MIT, Rust, alpha,
   github.com/caverav/flutterdec) emits `.dartpseudo` from an ARM64 snapshot. What is
   still true is narrower and worth stating precisely: flutterdec's own name backend
   produces `sub_<addr>` placeholders and it takes real names from r2flutter or from a
   Blutter dump. Jadart recovers names, the class tree and virtual-call selectors from
   the snapshot itself, in one self-contained tool with no external symbol source and no
   SDK build. Claim that, not the vacated one.
2. Version brittleness. Blutter recompiles the SDK; unflutter hand-writes each format. A
   principled, version-robust approach (derive the CID table and cluster grammar from the
   Dart VM sources per version, or infer them differentially) would be new.
3. No benchmark. There is no standard corpus or metric to compare tools or prove
   "better". Building one is a citable contribution and de-risks the rest.
4. Fragmentation. Static (Blutter/unflutter), dynamic (Frida), and traffic (reFlutter)
   are separate tools with no shared model. A unified framework with a real Dart-AOT IR
   that analysis passes and a dynamic bridge sit on top of is the integration gap.

## 5. Research questions

- RQ1. What snapshot metadata survives AOT, and what is the theoretical ceiling of static
  recovery (names, class layout, entry points, closures) versus what is unrecoverable
  (statement structure, locals, expression trees)?
- RQ2. Can the clustered-snapshot grammar be auto-derived across Dart versions instead of
  hand-coded, so the parser stays current without per-version engineering?
- RQ3. How faithfully can machine code + snapshot metadata be lifted to a Dart-AOT IR and
  then to readable pseudo-Dart, given the Dart calling convention and object model?
- RQ4. How much does obfuscation (`--obfuscate`, `--split-debug-info`) actually remove,
  and can semantic naming be recovered (cross-build diffing, heuristics, offline LLM)?
- RQ5. Where do current tools fail on a controlled corpus, and what failure taxonomy does
  a new design have to cover?

## 6. Contributions

- C1. FluBench: the first standardized, versioned benchmark for Flutter RE.
- C2. A systematic evaluation of existing tools on FluBench, with a failure taxonomy.
- C3. A version-robust Dart-AOT snapshot parser and IR. Concrete approach (DESIGN.md): a
  stable core (header/codecs/framing/cid-dispatch) + a per-format-epoch grammar table for
  the ~50 predefined clusters keyed by (version-hash, features-flags), with the cid table and
  pointer-field skeletons auto-generated from class_id.h / raw_object.h and a small
  hand-maintained overlay for the imperative ReadFill bodies. Crucially it fails loud on an
  unknown epoch instead of guessing, fixing unflutter's silent-fallback class of bug. This
  sits between Blutter (per-version SDK recompile) and unflutter (full per-version
  hand-coding) and is cheaper and more portable than both.
- C4. A decompiler pass from that IR to readable pseudo-Dart, staged in tiers (DESIGN.md
  section 11): Tier 0 skeleton Dart (classes/fields/signatures, near-perfect from surviving
  metadata, the JADX moment), Tier 1 control-flow + named calls, Tier 2 expression-level
  bodies, Tier 3 async/closure re-sugaring (research frontier). Original Dart source is
  provably unrecoverable (AOT discards the Kernel AST); the target is typed, named,
  roughly-recompilable pseudo-Dart, which the surviving metadata makes far richer than
  generic stripped-C decompilation.
- C5. A unified, open-source framework integrating static, dynamic (Frida), and traffic,
  released the way JADX is.

## 7. Methodology and phases

- Phase 0 - FluBench. Build the corpus and harness. Same apps compiled across Dart
  versions (3.8 / 3.10 / 3.11 / 3.12) x {clean, --obfuscate, --obfuscate
  --split-debug-info} x language constructs (async/await, closures, generics, records,
  FFI, isolates, string handling, crypto). Ground truth from the --split-debug-info symbol
  maps. Deliver: corpus generator, ground-truth extractor, metric harness.
- Phase 1 - Systematic eval. Run Blutter, unflutter, Ghidra+scripts, (JEB if available)
  against FluBench. Publish the capability frontier and the failure taxonomy. This tells
  us exactly where the novel technique must live.
- Phase 2 - IR + version-robust parser. Design a Dart-AOT IR (models the calling
  convention, object model, dispatch, closures). Build the parser guided by RQ2.
- Phase 3 - Decompiler. IR to pseudo-Dart. The differentiator.
- Phase 4 - Unify. One tool/UI: static recovery + Frida dynamic bridge + traffic, with
  xrefs, search, and scripting.

## 8. FluBench specification (draft)

- Axes: Dart version, obfuscation mode, split-debug-info on/off, construct set, app size
  (micro / medium / real-world sample).
- Ground truth: symbol maps from --split-debug-info; known source for each construct.
- Metrics:
  - function recovery: fraction of real functions located, with correct boundaries.
  - name recovery: fraction with correct class/method names (clean and obfuscated).
  - xref accuracy: string and call cross-references vs ground truth.
  - decompilation fidelity: does the recovered pseudo-Dart reproduce the construct's
    behavior (compile-and-diff, or manual rubric).
  - version robustness: does the tool identify and correctly parse each version.
  - cost: wall-clock, setup burden, offline-only yes/no.

## 9. Risks and open problems

- Decompilation may hit a hard ceiling for some constructs (heavy async lowering,
  inlined generics). Mitigation: scope pseudo-Dart to control-flow + call recovery first,
  full expression reconstruction later.
- Version-robust parsing may still need per-version anchors (generated clusters,
  canonicalization). Mitigation: auto-derive what is derivable, keep a small versioned
  override layer.
- Legal/ethics: dual-use RE tooling. Scope to authorized analysis, defensive research,
  and an OWASP-MAS-style framing.

## 10. Team and workflow

- Interns can own FluBench corpus generation and the Phase 1 eval (parallelizable, safe,
  high learning value). Core team owns the IR, parser, and decompiler.
- Everything runs offline and free: Flutter SDK, Android SDK, radare2, Ghidra, unflutter,
  Blutter, Frida, jadx, and (optionally) a local Ollama model for LLM-assisted naming.
  No paid API or cloud dependency, by design.

## 11. Status

- Phase 0 DONE: FluBench harness (flubench/) with a validated baseline (unflutter clean
  100/100/100, obfuscated 0/0/100 on Dart 3.12.2). Methodology rules established
  (optimizer-resistant corpus; non-data strings excluded from ground truth).
- Phase 1 IN PROGRESS: EVAL.md holds the tool-comparison table + failure taxonomy; the
  unflutter baseline is measured. The Blutter and multi-version rows are open work, listed
  under Pending in EVAL.md.
- Phase 2 M1 DONE: framework/ (Jadart) is a dependency-free, byte-exact, fail-loud snapshot
  core. Validated against the Dart 3.12.2 build (exact version hash, the base-objects
  invariant, sane cid decode, fail-loud on unknown epoch). This already fixes unflutter's
  silent-fallback failure mode.
- Phase 2 M2 DONE (WP-1a/1b, WP-2): Jadart now walks the ENTIRE alloc pass over all 356
  isolate clusters and recovers names. The alloc walk lands exactly on num_objects (54145
  clean, 30969 obf) (a byte-exact self-check across every cluster) then reads the canonical
  String cluster's fill to recover the interned identifier pool. FluBench name recall:
  clean classes 1/1 (100%), functions 9/9 (100%), strings 1/1 (100%); obf 0/0/100%. This
  EQUALS unflutter's baseline, from a scratch, version-robust, fail-loud parser. 10 tests pass.
  The cid table is generated mechanically from class_id.h via the C preprocessor.
- Version-robustness demonstrated (the C3 thesis, in the wild): the SDK source is checked out
  at main (3.13-dev), one version ahead of the 3.12.2 binary. Three concrete format drifts had
  to be handled per-epoch, each confirmed against the binary and cross-checked with unflutter:
  (1) Closure alloc is FIXED in 3.12 (main added a per-object length in 3.13); (2) Class alloc
  reads predefined_count + per-class ReadCid + new_count (main refactored to a plain fixed
  count); (3) the cid numbering shifted (typed-data starts at 112 with NumPredefinedCids 175 in
  3.12, vs 176 in main). All three live in versions.py as epoch parameters; unknown epochs still
  fail loud. This is exactly the per-format-epoch overlay DESIGN.md section 7 proposed.
- Docs: FINDINGS.md (measurements), DESIGN.md (format + parser design + tiers, source-cited),
  EVAL.md (Phase 1 eval), framework/README.md.
- Phase 2 M3 DONE (WP-1c/1d, WP-3-partial, WP-4): Jadart now walks the ENTIRE fill pass and
  emits a Tier 0 skeleton. The fill walk consumes all 356 clusters' fill data byte-exactly
  (validated against unflutter's --debug-fill per-cluster offsets: it lands on the roots at
  0x0e0394 for clean), recovering the full object graph: 9013 strings, 7892 functions (with
  name + owner refs), 2350 classes (with name refs + class ids). Resolving those refs gives
  readable structure, e.g. benchWithdraw is correctly recovered as a METHOD of class
  BenchAccount (structural, not flat-string). `jadart --tier0` emits real skeleton Dart:
      class BenchAccount { benchWithdraw(); }
      class _FluBenchPageState@... { build(); ... }
  1842 named app/framework classes with their method signatures, a navigable class/method
  tree no other Flutter RE tool produces (the JADX moment, contribution C4 Tier 0). 16 tests
  pass. The fill grammar is the version-parameterized 3.9-3.12 profile (fill refs = ReadRefId
  for Dart >= 2.18; Class/Function/Instance/Code/ObjectPool/TypeArguments/etc. per-cluster).
  Tier 0 is enriched to a full header dump: the real superclass hierarchy (via Type ->
  type_class_id resolution: FluBenchApp extends StatelessWidget, RenderBox extends RenderObject)
  and member kinds (constructors/getters/setters vs methods, from the Function kind_tag). Fields
  are mostly tree-shaken by AOT into offsets (332 Field objects survive), a real recovery limit.
- Phase 3 Tier 1 STARTED (WP-3): Jadart now maps each recovered Function to its Code object's
  byte range in the instructions image (via the InstructionsTable rodata) and disassembles it
  with capstone (arm64), annotating direct BL call targets with the recovered callee names.
  Proof: benchWithdraw disassembles to exactly its source (`if (amount > balance) return false;
  balance -= amount; return true;` as ldur/cmp/b.le/ret + sub/stur/ret), and benchRunAll's calls
  resolve to `-> benchCheckSecret`, `-> benchComputeChecksum`, `-> benchWithdraw`, `-> writeln`,
  etc. - a recovered, named call graph. `jadart --disasm <func>` prints it. 18 tests pass. This
  is the "beats every current tool" step: unflutter et al. stop at raw `bl #offset`; Jadart names
  the callee. ObjectPool loads are also annotated now: `ldr xN, [x27, #off]` -> pool entry off//8
  -> the referenced String/Function, e.g. `ldr x1, [x27, #0x810]  ; = "charCodes"` and
  `; = "Invalid MIME type"` in benchRunAll (contextually exact). So a method reads as annotated
  arm64 with named calls AND named string/const references.
- Unified `--decompile <Class>` view (the JADX-for-Flutter deliverable): the Tier 0 class header
  (extends + members) with each method's Tier 1 body, annotated, basic-block-labelled arm64.
  Example (FluBenchApp.build): `class FluBenchApp extends StatelessWidget { build() { L0: bl ->
  ThemeData.; ldr x1,[x27,#..] = "FluBench"; ... = "applyElevationOverlayColor"; L1: ... } }` -
  control-flow labels, named calls, named string constants, all in one navigable view. 20 tests pass.
  Jadart now runs end to end: stripped libapp.so -> object graph -> Tier 0 skeleton -> Tier 1
  annotated bodies -> a JADX-style per-class decompile view. This is the MVP of the project vision.
- Phase 3 Tier 2 STARTED (control-flow reconstruction): a CFG builder (basic blocks + edges) plus a
  post-dominator-based structuring pass recover if/else and while-loops from the disassembly and
  render them as nested pseudo-Dart, with the Tier 1 call/string annotations inline. benchWithdraw
  decompiles to exactly its source shape:
      benchWithdraw() {
        ldur x3, [x1, #7]        // load balance
        cmp x2, x3
        if (x2 > x3) { ... return; }         // if (amount > balance) return false;
        else { sub x4, x3, x2; stur x4, [x1, #7]; return; }   // balance -= amount; return true;
      }
  `--decompile` uses the structured renderer by default. If/else is solid; loop-body reconstruction
  and full expression lifting are best-effort (the honest Tier 2/3 frontier, irreducible regions
  fall back to `goto`, never wrong). 22 tests pass.
- Git: workspace initialized (local, uncommitted pending review).
- Next (Tier 2/3): faithful loop-body + expression reconstruction (register->value tracking to
  recover `balance -= amount` etc.); typed signatures into Tier 0; FluBench tier scoring; a UI.
