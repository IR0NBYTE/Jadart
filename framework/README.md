# jadart, tool reference

This is the reference for the tool itself: every command, what each module does, and how
to extend the parser to a new Dart release or a new target.

Start at the [top-level README](https://github.com/IR0NBYTE/jadart/blob/main/README.md) for what jadart is, a before/after showcase,
platform support and the honest limits. [DESIGN.md](https://github.com/IR0NBYTE/jadart/blob/main/DESIGN.md) is the annotated
snapshot format, cited to dart-lang/sdk. [EVAL.md](https://github.com/IR0NBYTE/jadart/blob/main/EVAL.md) has the measurements and
the comparison against other tools.

## Commands

Run these from `framework/`. `python3 -m jadart` and `python3 -m jadart.cli` are the same
entry point.

| command | does | options |
|---------|------|---------|
| `info` | header, version hash, format epoch, target, object and cluster counts, for both the vm and isolate snapshots | `--lenient` |
| `classes` | Tier 0 class and member skeleton with the resolved superclass hierarchy | `-f, --filter STR`, `-l, --library URL` |
| `disasm SYMBOL` | annotated arm64 for one function: direct calls named, ObjectPool constants resolved | `--sigs FILE` |
| `decompile CLASS` | class header plus reconstructed method bodies | `-t, --tier {1,2,3}`, `--sigs FILE` |
| `selectors` | every virtual-dispatch selector name recovered from the serialized dispatch table, with its offset | |
| `strings` | the recovered identifier and string pool, plus a cluster histogram | `-g, --grep PATTERN`, `-p, --plain` |
| `functions` | every code range in the image with call counts, name origin and owning library (r2 `afl`, IDA's Functions window) | `-f, --filter`, `-l, --library`, `-s, --sort`, `-n, --limit`, `--named`, `--anonymous`, `--called`, `--virtual`, `-v`, `--sigs FILE` |
| `xrefs STRING\|0xOFF\|FUNC` | what references this: functions that load a string or ObjectPool entry, or the direct and virtual call sites of a function (r2 `axt`) | `--sigs FILE` |
| `ffi` | the native boundary: shared-object names in the ObjectPool, the code that reads them, and the symbol literals that reach a call site there | `--full`, `--sigs FILE` |
| `verify` | the byte-exact acceptance gates | |
| `signatures REF...` | build a signature library from reference builds, so an `--obfuscate` binary can be named by shape | `-o, --out FILE`, `-q, --quiet` |
| `lift SYMBOL` | Tier 3 pseudo-Dart for one function, including top-level ones that belong to no class | `--sigs FILE` |
| `libraries` | libraries the snapshot was built from, by class count | `-a, --app`, `-g, --grep STR` |
| `export` | the whole app to a browsable tree: decompiled Dart plus the Flutter asset bundle, with the rest of the container inventoried and attributed | `-o, --out DIR`, `-t, --tier`, `-a, --app`, `-q, --quiet`, `--sigs FILE` |

Global: `-j` / `--json` emits one JSON document on stdout instead of a report, so every
command composes with `jq` and friends. Failures are JSON too, carrying the same exit code,
which means a caller never has to read stderr to find out what happened. `--version` prints
the tool version and the format epochs it can parse. `--color
{auto,always,never}` is accepted before or after the command word, and defaults to
colourising only on a tty.

`decompile --tier` picks how far the pipeline runs. Tier 3 (the default) gives pseudo-Dart
expressions, tier 2 gives the control-flow skeleton with arm64 inside each block, tier 1
gives annotated arm64 with the structure flat.

`disasm` takes a name from the snapshot, or an ELF `.symtab` name on a
`dwarf_stack_traces_mode` build, where the snapshot no longer holds the real ones.

Exit status:

| code | meaning |
|------|---------|
| 0 | success |
| 1 | nothing recovered under that name, or a Tier-A gate failed |
| 2 | argparse rejected the command line, or the snapshot won't parse |

The pre-subcommand flag form (`jadart libapp.so --decompile CLASS`) still works and is
translated internally. It's hidden from `--help`; new work should use the commands.

## What happens before a single snapshot byte is read

The parse profile is keyed on `(version hash, architecture, pointer model)`, not on the
hash alone. Part of the cluster grammar is chosen by a build flag rather than by the
version: `Deserializer::ReadCluster` gates on `#if !defined(DART_COMPRESSED_POINTERS)`
(app_snapshot.cc:9391) and routes String, PcDescriptors, CodeSourceMap and
CompressedStackMaps to `RODataDeserializationCluster`, whose `ReadFill` is empty and whose
payload lives in the data image instead of the stream.

That produces three distinct outcomes, and they are deliberately different errors.

| situation | result |
|-----------|--------|
| hash not in the registry | `UnknownEpoch`. `--lenient` overrides it, which means "this version is unknown, try anyway" |
| hash known, no validated grammar | `UnsupportedTarget` naming the release. `--lenient` does not override it |
| hash known, grammar exists, target not covered | `UnsupportedTarget` naming the offending token, listing what is covered |

`--lenient` deliberately does not bypass the last two. An unknown version is a gap in
coverage. A known version on an unimplemented pointer model is a grammar already known to
be wrong, and running it would be worse than refusing.

This is not hypothetical. Before the profile key was widened, the arm32 build of an app
sharing the arm64 hash resolved to the compressed profile and walked 437 clusters with the
alloc-pass self-check (`assigned == num_objects`) **passing**, because
`RODataDeserializationCluster::ReadAlloc` also reads exactly one varint per object. It
only failed later, in the fill pass.

## The pipeline

```
libapp.so / App
  |
  +- elf.py / macho.py      open_container() picks ELF64 or Mach-O, fail-loud.
  |                         Locates _kDartVmSnapshotData, _kDartIsolateSnapshotData and
  |                         _kDartIsolateSnapshotInstructions.
  +- snapshot.py            magic, length, kind, version hash, features, counts.
  +- versions.py            (hash, arch, pointer model) -> Profile, or refuse.
  +- clusters.py            ALLOC pass: per-cid read patterns, dense ref ids.
  |                         Self-check: assigned refs == num_objects.
  +- fillwalk.py            FILL pass: the object graph. Classes, Functions, Fields,
  |                         Types, the ObjectPool.
  +- fill.py                the canonical String cluster, i.e. the identifier pool.
  |                         On uncompressed targets it comes from the RO data image.
  +- program.py             resolve the graph into a Program. Tier 0 emit,
  |                         and the per-class decompile view.
  +- symbols.py             backfill names from ELF .symtab / DWARF where the snapshot
  |                         has none (dwarf_stack_traces_mode builds).
  +- disasm.py              instructions image + InstructionsTable, per-function arm64,
  |                         ObjectPool annotation.
  +- cfg.py                 Tier 2: dominators, post-dominators and follow nodes;
  |                         if/else and loops.
  +- expr.py                Tier 3: abstract interpretation over the register file.
  +- dispatch.py            Tier 3.4: the serialized global dispatch table -> selector names.
  +- verify.py              the acceptance gates, run against any stage's output.
```

## Modules

| file | responsibility |
|------|----------------|
| `elf.py` | minimal ELF64 reader: sections, symbols, VA to file offset, `.symtab` lookup |
| `macho.py` | the same for Mach-O 64, plus `open_container()`, the fail-loud picker |
| `stream.py` | datastream decoders, byte-exact to `runtime/vm/datastream.h`. Raises `TruncatedSnapshot` rather than `IndexError` |
| `versions.py` | `(hash, features)` to a format `Epoch` and `Arch`, or a precise refusal |
| `cids.py` | the class-id table, generated from the VM's `CLASS_ID_LIST`. Do not hand-edit |
| `snapshot.py` | header, version, features, counts, cluster-alloc tags |
| `clusters.py` | the alloc-pass walker, per-cid read patterns, byte-exact |
| `fillwalk.py` | the fill-pass walker: the whole object graph |
| `fill.py` | canonical String cluster recovery, the identifier pool |
| `program.py` | the resolved `Program` model, Tier 0 emit, the decompile view |
| `disasm.py` | instructions image and table, per-function arm64, ObjectPool annotation |
| `cfg.py` | Tier 2 control-flow reconstruction |
| `expr.py` | Tier 3 expression lift |
| `dispatch.py` | Tier 3.4 dispatch table decode and selector naming |
| `verify.py` | the byte-exact acceptance gates |
| `export.py` | whole-binary export: the source tree and the supporting dumps |
| `container.py` | extracts the Flutter asset bundle from the apk/ipa, decoding the two formats a plain copy leaves unreadable (gzipped NOTICES, binary AssetManifest), and inventories the rest |
| `symbols.py` | ELF and DWARF name backfill |
| `cli.py`, `console.py`, `__main__.py` | the command line and its output formatting |

Dev-time helpers live in `tools/` and nothing under `jadart/` imports them, so the tool
itself stays offline and dependency-free.

| file | does |
|------|------|
| `sdk_source.py` | fetch SDK source by tag over HTTP and compute the snapshot hash it would produce, about 2.5 MiB, no clone and no VM build |
| `gen_cids.py` | expand `CLASS_ID_LIST` through the real C preprocessor to get one release's cid table |
| `gen_epoch.py` | derive a whole `Epoch` entry from a release's own source, with `grammars` left empty |
| `build_corpus.py` | drive one app through several pinned SDKs, one build per distinct hash |
| `quality.py` | count the symptoms that make Tier 3 read like a disassembly, over a whole image: bare machine registers, byte-offset fields, `(...)` call sites, gotos, raw arm64. `--baseline FILE` prints before/after for all of them at once, so a change that trades one for another is visible rather than hidden |
| `cfgcheck.py` | read the structured statement tree back as a program and check, for every block, that the RENDERING claims exactly the successors the CFG has. Stronger than "no block placed twice and none dropped", which a broken structuring pass can satisfy while silently deleting a branch |
| `irfuzz.py` | differential execution against an emulated arm64, seven oracles over two lifters: `ir.py`'s value DAG, and `expr.py`, which is the one `export` prints from and whose PRINTED TEXT is evaluated against the CPU. `--cfg` generates whole control-flow graphs and RUNS the printed body as a program wherever the rendering is one (no goto, every block reachable) which is the only way to decide a value with two definitions: folding a name back into its use works for a name assigned once and gives up on every phi, so naming an if-join left the whole join unscored until this existed. `--mem` and `--cfgmem` add loads and stores and interpret the printed statements IN ORDER, which is how a value that goes stale when the memory it reads is written gets decided rather than assumed. `--fp` covers the scalar-double path, bit-exactly, because a Python float is an IEEE-754 binary64. Every oracle refuses a trial it cannot decide rather than guessing, so the deliberate reinterpretations (Smi tag, `>>` for both shifts, `<` for both signednesses) are excluded by construction instead of arriving as false defects |
| `appsweep.py` | widen the evidence past flubench: probe F-Droid for real Flutter apps by range-reading each APK's zip central directory, range-fetch just `libapp.so` out of the hits, and run the gates over all of them. One request per probe and two per fetch, so 26-180 MB of APK costs 6-24 MB of transfer. flubench is fifteen epochs of ONE app we wrote, which is why a real app hit a cluster it could not produce |
| `semdiff.py` | score the lift against the corpus app's own Dart source, across every epoch. `--hard` runs only the must-hold checks |

## Register roles for this epoch

Confirmed empirically against the FluBench 3.12.2 build and `constants_arm64.h`. `expr.py`
depends on these, so they're the first thing to recheck on a new epoch.

| register | role |
|----------|------|
| x15 | SP |
| x21 | dispatch table, pointing at `&array[kOriginElement]`, 4096 on ARM64 |
| x22 | NULL. `+0x20` is `true`, `+0x30` is `false` |
| x26 | THR |
| x27 | PP, the ObjectPool. Untagged on arm64 |
| x28 | HEAP_BASE. Reserved, which is what makes the write-barrier idiom unambiguous |
| x29, x30 | FP, LR |

ObjectPool entry `idx` sits at byte offset `0x10 + idx*8`
(`ObjectPool_elements_start_offset = 0x10`, `element_size = 8`, from
`runtime_offsets_extracted.h`). Keying entries at `idx*8` instead is a 2-slot shift that
mislabels every constant. unflutter has the same off-by-2, which is harmless there only
because its name recovery never reads pool offsets.

## Adding a Dart epoch

The work splits cleanly into a part that generates itself and a part that doesn't.

```bash
python3 tools/sdk_source.py --tag 3.11.5 --hash    # the hash that release would produce
python3 tools/gen_epoch.py  --tag 3.11.5           # a versions.py Epoch, grammars empty
python3 tools/build_corpus.py --plan               # which hashes are covered, which built
python3 tools/bench.py -n 5 --digest               # whole-image timings, memory, output digest
```

`measure.py --check` keeps the documented RESULTS honest. `bench.py` does the same for the
documented COSTS, which go stale the same way and for the same reason: a timing in a commit
message was typed by hand from one run on one machine. It uses a fresh subprocess per run so
nothing is warm that would not be warm for a user, reports the child's own peak RSS, and
prints a digest of the output so two checkouts can be compared for EQUIVALENCE rather than
only for speed. That digest is what makes a performance change reviewable: a rewrite that is
twice as fast and changes one line of output is a regression, not an optimisation.

`gen_epoch.py` derives everything that lives in the release's own headers: the hash, the
predefined cid count, the typed-data anchors, and the `ClassIdTag` position and width. It
had to survive real drift to work. 3.12 builds the `ClassId` enum from a single
`CLASS_ID_LIST` macro, while 3.11 and earlier write the body inline with per-family
`DEFINE_OBJECT_KIND` blocks and have no `CLASS_ID_LIST` at all. Expanding the enum itself
rather than one macro handles both. Run against 3.12.2 it reproduces the committed table
exactly: 175 cids, 0 disagreements.

It emits `grammars=frozenset()` on purpose, so a generated epoch is *identified* and still
refuses to parse until a binary of that release has passed the gates. An identical cid
table does not imply an identical grammar.

Dart 2.19 through 3.12 are supported now, and the diffs that got them there are worth
knowing before adding the next one, because **only one of them changes how many bytes a
cluster reads**. A diff of `app_snapshot.cc` alone would have reported "no drift" for all
but the first:

| Boundary | What moved | Where it is written |
|---|---|---|
| 3.9/3.10 | nothing; `UnlinkedCall` and `MonomorphicSmiableCall` swap cids | `class_id.h` |
| 3.3/3.4 | the cluster tag stops being `cid<<1\|canonical` in a uint64 and becomes an object header word | `app_snapshot.cc` `ReadCluster` |
| 3.2/3.3 | `ObjectPool` entry byte gains `SnapshotBehaviorBits`, `TypeBits` narrows 7 -> 4 | `object_pool_builder.h` |
| 3.1/3.2 | `ObjectPool::EntryType` renumbers: `kTaggedObject` was 0, becomes 1 | `object_pool_builder.h` |
| 3.1/3.2 | `PatchClass` drops a field from its serialized range | `raw_object.h` `to_snapshot` |
| 2.19/3.0 | `Record` swaps a field-names pointer for a packed `RecordShape` | `app_snapshot.cc` |

Three lessons are baked into those rows. Read `to_snapshot(kFullAOT)`, not `VISIT_TO`: the
GC range and the serialized range differ, and `Library` declares fifteen pointers while
serializing ten. Resolve the preprocessor for `DART_PRECOMPILED_RUNTIME` and `PRODUCT`
before diffing, or fifteen JIT-only bodies look like drift. And a renumbered enum or a
repacked bitfield leaves every length check agreeing while the values come out wrong, so
byte counts are necessary and not sufficient.

The workflow: `tools/gen_epoch.py --tag X` for the cid table, fill `grammars` from the
closest validated epoch, build a binary with `tools/build_corpus.py`, and keep the entry
only once every Tier-A gate passes on it.

## Adding a target

`arm64` and `x86_64` compressed, `arm64` uncompressed (iOS) and 32-bit `arm` are all
supported, each gated on real binaries. Four quantities follow the target word rather than
being constants, and `Arch` carries them: `compressed_word_size`, `object_alignment_log2`,
`instance_header_words` (the header is one machine word, so 32-bit has one slot and 64-bit
compressed has two) and `read32_per_word` (an unboxed field is written with
`ReadWordWith32BitReads`, whose loop count is `kBitsPerWord / kBitsPerInt32`). A fifth
lives in `disasm._string_header_size`: a heap String's data starts after a header rounded
up to a word, which is why the 64-bit compressed case is 16 bytes rather than the 12 its
fields occupy.

32-bit **does** get instruction decoding, in ARM mode (`_DECODERS` in `disasm.py`). Dart's
arm32 backend emits A32 throughout, which was probed rather than assumed: the same bytes
decode as coherent Dart in ARM mode and as unrelated branches in Thumb. 99.34% of
instructions decode across the thirteen arm32 corpus builds, against 99.83% on arm64, so
`disasm`, `functions`, `xrefs` and `decompile -t 1/-t 2` all work there.

What 32-bit does **not** get is Tier 3, and the reason is measured rather than pending.
`expr.Target` now carries the arm32 roles (`constants_arm.h`: THR=r10, PP=r5, FP=r11,
DISPATCH=r7, no null register, canonical objects at THR+0x34/0x38/0x3c), the arm32 frame
and return forms (`push {fp,lr}`, `bx lr`, `pop {..,pc}`, `mov pc,lr`) and its call form
(`blx`). With all of that, semdiff scores arm32 at **3/9 to 5/9** against the app's own
Dart source, where arm64 scores 9/9 on every epoch, and the failures include hard
checks. So `LIFTABLE_ARCHS` stays `{"arm64"}`: being in that set is a claim the output has
been checked against source, not a claim the table is written.

The register PAIR is now modelled, `State.pair` records which register holds the top
half of a 64-bit value whose low half is elsewhere, recognised at `asr rH,rL,#31`, at
`subs`+`sbcs`, at `umull`, and at two adjacent loads or stores off one base. So
`balance -= amount` comes out as `r1.field_0x4 -= r4`, one assignment rather than two
halves. The ObjectPool convention was derived the same way: of twelve plausible
combinations of (elements start, element size, tag bias), exactly one makes the offset
`benchCheckSecret` loads name the literal its source compares against, which says arm32
starts elements at 8, sizes them 4, and keeps **PP tagged**, unlike arm64.

That took semdiff from 3-5/9 to **5-7/9**. It is still not 9/9 and hard check 4 still
fails, so the gate stays shut. What remains is the boxing path: on a 32-bit build a Dart
`int` that does not fit in 31 bits is a heap Mint, so the loop in `benchComputeChecksum`
is a Smi overflow test (`lsl r0,r8,#1; cmp r8,r0,asr #1`), an allocation stub, and a
dynamic call, and `acc * 31` and `& 0xffffffff` live inside that rather than in plain
arithmetic. There is also one output on that function reading `return 0;` where the source
returns the accumulator, which is a wrong value rather than a missing one and has to be
understood before any of this is trusted.

Because the default keeps the old arm64 assumption, a `lift_function` call that forgets
`arch=` silently loses the gate. `test_every_lift_call_site_passes_the_target` checks all
of them; it exists because semdiff was exactly that call site and reported five failed
source checks per arm32 binary before it was threaded through.

Other containers follow `macho.py`'s shape, including its one trap: Mach-O
`nlist_64` symbols carry no size, so a symbol's extent has to be derived. Taking "up to
the next symbol" truncates the instructions image to its first function, because thousands
of function symbols live inside it. An extent runs to the end of its section instead,
tightened only by the next `_kDart*` boundary symbol in that same section.

## Tests

```bash
python3 -m pytest tests -q     # 191 passing
```

The arm64 FluBench Dart 3.12.2 fixtures are committed, so a fresh clone runs the suite
with no Flutter install. Tests whose fixture is absent skip and print the reason rather
than passing quietly. Optional fixtures widen coverage:

```bash
# the ELF/DWARF backfill, against any unstripped dwarf_stack_traces_mode build
JADART_REALAPP_LIB=/path/to/libapp.so python3 tests/test_core.py
```

The iOS and floating-point tests look for their `.dylib` and `.so` at fixed paths under a
local `jadart_e2e/` tree, and print how to build one when it isn't there. The iOS fixture
needs no Xcode: since Flutter 3.44.4, `gen_snapshot` writes the Mach-O dylib itself.

The interesting tests aren't the ones checking jadart is right on good input. They're the
ones checking it fails on bad input. `test_acceptance_gates_detect_a_wrong_grammar`
perturbs a correct parse in four ways that mimic real grammar errors (a cid renumbering,
an instance-geometry disagreement, a shifted Function fill spec, a miscounted header
varint) and asserts each is caught by its specific gate.
`test_simd_is_not_lifted_as_scalar` asserts that `fadd v0.2d, ...` is *not* rendered as a
double add, because that would silently turn vector code into wrong scalar source.

## Roadmap

Done: the snapshot core, the alloc and fill walk (Tier 0), disassembly and ObjectPool
annotation (Tier 1), control flow (Tier 2), expressions (Tier 3), call arguments (3.1),
semantic runtime stubs (3.2), virtual-dispatch attribution (3.3), selector names (3.4),
ELF symbol backfill, Mach-O containers, the uncompressed-pointer grammar, and the
acceptance gates.

Next:

- Support a second epoch. Three are identified and refused today; the corpus binaries
  already exist, so this is bounded work rather than an open question.
- 32-bit targets: ELF32 container plus a 32-bit word size.
- Split snapshots and deferred loading units, which aren't in the corpus yet.
- A navigable UI. jadart is a CLI today.

Not achievable, and measured rather than assumed: instance field *names*. See the limits
section of the [top-level README](https://github.com/IR0NBYTE/jadart/blob/main/README.md#limits).

## Licence

MIT. See [LICENSE](https://github.com/IR0NBYTE/jadart/blob/main/LICENSE).
