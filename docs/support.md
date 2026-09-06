# Platform and version support, in detail

Moved out of the README. The summary table lives there; this is the reasoning behind it,
including what "supported" is allowed to mean and where each target stops.

## Platform and version support

A target is a `(format epoch, architecture, pointer model)` triple, not just a version.
Pointer model is a build flag: `Deserializer::ReadCluster` gates on
`#if !defined(DART_COMPRESSED_POINTERS)` (app_snapshot.cc:9391) and routes String,
PcDescriptors, CodeSourceMap and CompressedStackMaps through a different cluster whose
payload lives in the data image rather than the stream. The arm64, x64 and arm32 builds of
one app all carry the same version hash, and one of them needs a different grammar.

| target | container | pointers | status |
|--------|-----------|----------|--------|
| Android arm64 | ELF64 | compressed | supported, every applicable Tier-A gate (9 to 11 of the 12, by target) |
| x86_64 (emulator, desktop) | ELF64 | compressed | supported, every applicable Tier-A gate (9 to 11 of the 12, by target). Structure only: see below |
| iOS / macOS arm64 | Mach-O 64 | uncompressed | supported, every applicable Tier-A gate (9 to 11 of the 12, by target) |
| Android arm32 (`armeabi-v7a`) | ELF32 | uncompressed | supported, every applicable Tier-A gate (9 to 11 of the 12, by target). Tiers 1 and 2 decode; Tier 3 refuses: see below |
| riscv32, riscv64, ia32 | n/a | n/a | recognised in the features string, refused by name |

x64 shares a grammar key with arm64, which is why the snapshot layer parsed x86_64 with no
changes. That makes architecture-independence a demonstration rather than a claim.

**arm32 decodes, and stops where it stops being right.** `disasm`, `functions`, `xrefs` and
`decompile -t 1/-t 2` all work on `armeabi-v7a`: 99.34% of instructions decode across the
thirteen arm32 corpus builds, against 99.83% on arm64. ARM mode, not Thumb, which was
probed rather than assumed: Dart's arm32 backend emits A32 throughout, and the same bytes
decode as coherent Dart one way and as unrelated branches the other.

`lift` and `decompile -t 3` refuse, and the boundary is exactly where the register ROLES
start mattering. `ldr r0, [sl, #0x3c]` reads a canonical object out of the thread; with no
role for r10 it renders as `sl.field_0x3d`, a field access on an untagged pointer with the
tag bias added anyway, and nothing in the output says so. Annotated arm32 needs none of
that model and is honest without it, so the two tiers are gated separately rather than
together. Everything from the snapshot works regardless: classes, libraries, strings,
selectors.

Version coverage, measured. `tools/sdk_source.py` computes the snapshot hash any SDK tag
*would* produce by fetching the 15 `runtime/vm` files that `tools/make_version.py` hashes,
about 2.5 MiB over HTTP, with no clone and no VM build. Predicted and observed hashes have
agreed on every corpus build, so a release can be identified before any binary of it exists.

**Dart 2.19.6 through 3.12.2 are supported**: eighteen registered format epochs across
fourteen grammar families, each gated on a real binary, and each also gated on a 32-bit
build of that release. Two of the eighteen are beta builds, because Flutter's beta channel
pins a Dart release of its own and an app published from it carries that hash for ever. `jadart --version` prints the
registry, oldest first, with the targets each epoch covers.

An epoch usually covers a whole minor line, so one profile serves every 3.11 release. That
is a measurement, not a rule, and it fails in both directions: 3.12.0 and 3.12.2 have
*different* hashes, while 3.1 through 3.3 differ from each other only in the cid table. On
the older lines it is finer still, since 3.0.0 and 3.0.7 diverge. A tool that assumed one
profile per minor version would be wrong about several of them.

"Identified, no grammar" is still a deliberate state for a release nothing has been gated
on, and jadart says so out loud rather than guessing:

```
jadart: epoch <name> (dart <version>) is identified but has no validated cluster
grammar, so there is nothing to parse it with. Deriving one means working out this
release's per-cluster ReadAlloc deltas and confirming them with `--verify` on a binary
built by that SDK.
```

Reaching back to 2.19 turned up six format changes, and **only one of them alters how many
bytes a cluster reads**. The cluster tag stops being `cid<<1|canonical` in a uint64 and
becomes an object header word at 3.4. `ObjectPool`'s entry byte gains `SnapshotBehaviorBits`
at 3.3, and one release earlier its `EntryType` enum renumbers so `kTaggedObject` moves
from 0 to 1: same layout, same lengths, different meaning. `PatchClass` drops a field from
its serialized range at 3.2, which is declared in `raw_object.h`'s `to_snapshot`, not in the
serializer. `Record` swaps a field-names pointer for a packed shape at 3.0. Diffing the
serializer alone would have reported "no drift" for five of the six.

