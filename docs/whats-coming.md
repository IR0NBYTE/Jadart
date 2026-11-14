# What is coming in the Dart SDK

Three lines of work in dart-lang/sdk change what a Dart binary can hold. This page says
what each is at one commit, what Jadart does with it today, and what a refusal by name
would test.

SDK paths are at commit `f3f72dd63911938effc75feacc86f52022216c67` of `main`
(2026-11-13, version 3.15.0, `tools/VERSION:26-29`). Flutter paths are at flutter/flutter
`5aa30617eadc7f45cf0a6810b3529ac59679ef03`. "Not established" means the source read did
not settle it. Quoted Jadart messages come from made-up input.

## Modular AOT and module snapshots

A second compiler, written in Dart, turns libraries into arm64 code and writes them as
module snapshots (`pkg/native_compiler/lib/snapshot/snapshot.dart:205`). An app is
module snapshots only, and the AOT runtime does not load them.

State: experimental, "not published or included in the SDK"
(`pkg/native_compiler/README.md`). It needs `--modular_aot`, is arm64 only
(`runtime/vm/module_snapshot.cc:39-62`), and targets macos and ios as Mach-O
(`pkg/native_compiler/lib/configuration.dart:36-57`). The AOT runtime answers "Cannot
load module snapshots on an AOT runtime" (`runtime/vm/dart_api_impl.cc:5618-5622`). The
3.13.7 tag has the reader too. Use by Flutter: not established.

A module is:

- A Mach-O dylib exporting `_kDartSnapshotData` and `_kDartSnapshotText`
  (`pkg/native_compiler/lib/runtime/vm_defs.dart:169-170`), the names an AOT app
  exports (`runtime/include/dart_api.h:4092-4094`). Loaded with
  `--load_module_snapshot` (`runtime/bin/main_impl.cc:431-448`).
- A header of magic, length and kind 3, `kModule` (`runtime/vm/snapshot.h:24-30`). No
  version hash follows: a format version, 1, then the CPU name alone as the features
  string (`module_snapshot.cc:2162-2190`).
- 40 cluster ids of its own, not class ids (`module_snapshot.cc:76-117`). Some name a
  library or class of another module (`389-398`, `490-506`).
- One object pool for each Code object, and code bodies laid end to end
  (`module_snapshot.cc:1716-1758`, `122-131`).
- Calls that load a Function or a stub from the pool, then its entry point, then `blr`;
  no `bl` to a fixed target
  (`pkg/native_compiler/lib/back_end/arm64/code_generator.dart:691-782`).

In Jadart, `snapshot._layout` takes the dylib for a 3.13 app, then `snapshot.parse_blob`
reads a hash at offset 20 and features at 52. A made-up module header is refused as an
"unknown format epoch" whose hash is stream bytes.

Refusal test: kind is 3, byte 20 is `81`, the varint for 1, and an architecture word
and a NUL follow. Kind 3 alone is `kFullAOT` through 3.12 (`snapshot.KIND`).

Reading it takes a second grammar, names resolved across modules, a pool per function,
and calls recovered from pool pairs.

## Dynamic modules and bytecode

A host app is built as a normal AOT snapshot with a declared interface. More libraries
are compiled later to bytecode, loaded at run time into the same heap, and run by an
interpreter inside the AOT runtime (`pkg/dynamic_modules/README.md:26-28`, `239-247`).

State: build option `dart_dynamic_modules`, default false (`runtime/runtime_args.gni:76`,
`runtime/BUILD.gn:235-236`), also in the 3.13.7 tag. That README says neither SDK ships
it (`102-105`). Flutter's engine has the switch, default off
(`engine/src/flutter/tools/gn:1237-1241`). A release that turns it on: not established.

What it adds:

- A bytecode file outside libapp: magic `0x44424333`, format version 4
  (`runtime/vm/constants_kbc.h:274-277`). The app fetches it (that README, `164-167`).
- Nothing in the host header. The features string has no token for it
  (`runtime/vm/dart.cc:904-1003`), `runtime/vm/raw_object.h` has no layout under the
  define, and `Bytecode` has a class id either way (`runtime/vm/class_id.h:41`).
- A loaded function holds a `Bytecode` object and its code is the `InterpretCall` stub
  (`runtime/vm/object.cc:8201-8213`). One process then runs both kinds of body.
- In host code, an interface call on a class a module may extend gains a class id range
  test (`runtime/vm/compiler/aot/aot_call_specializer.cc:1226-1248`).
- Bytecode objects inside a `kFullAOT` snapshot: not established. The reader exists
  under the define (`runtime/vm/app_snapshot.cc:3147-3176`).

Jadart parses the host as before. What fails is the assumption that libapp is the whole
program. Given the bytecode file, `macho.open_container` says "unrecognised container
(leading bytes 33434244)".

Refusal test: bytes `33 43 42 44` at offset 0, then a uint32 version. The host has no
header test; a live `InterpretCall` stub body is a candidate, not established.

Reading it takes a reader for the file's tables and code sections
(`pkg/dart2bytecode/docs/bytecode.md:39-83`), a disassembler for its instruction set
(`1006`), and a join of module names to host classes.

## arm64e pointer authentication

arm64e is Apple's arm64 ABI with signed pointers, added here as an architecture of its
own.

State: `dart_target_arch == "arm64e"` (`runtime/BUILD.gn:184-188`). The 3.13.7 tag does
not name it there. The changelog lists `Abi.iosArm64e` under 3.14.0, unreleased
(`CHANGELOG.md:182-193`). Use by Flutter: not established.

What changes:

- The features token is `arm64e` (`runtime/vm/dart.cc:968-969`).
- The Mach-O `cpusubtype` is `0x80000002` (`runtime/platform/mach_o.h:49`,
  `runtime/vm/mach_o.cc:2112-2113`).
- Calls to C functions use `blraaz` and `braaz`
  (`runtime/vm/compiler/assembler/assembler_arm64.h:1916-1941`). A search of
  `runtime/vm` found no other signed instruction.
- `runtime/vm/app_snapshot.cc` does not branch on it.

In Jadart, `versions._ARCH_WORDS` has no `arm64e`, so a known release is refused with
"the features string names no architecture". `macho.MachO64._parse` drops the subtype.

Refusal test: the token `arm64e`, or cputype arm64 with that subtype.

Reading it takes the word read as arm64, both opcodes decoded as `blr` and `br`, and a
gate on a real build.

## Smaller items

- iOS Simulator snapshots set their platform in `LC_BUILD_VERSION`
  (`runtime/vm/mach_o.cc:1359-1362`), which Jadart does not read.
- A stripped Mach-O snapshot keeps its exported symbols in `LC_SYMTAB`
  (`runtime/vm/mach_o.cc:3188-3190`, `3811-3819`), where Jadart looks.
- `app-aot-pecoff-obj` writes a COFF object, x86-64 only, that the linker turns into a
  DLL and a PDB (`runtime/vm/coff.h:27-33`). Flutter tools pass it for Windows x64 and
  link `app.so` as that DLL
  (`packages/flutter_tools/lib/src/base/build.dart:200-204`, `287-296`). Jadart opens
  ELF and Mach-O only. Refusal test: `MZ` at offset 0.

## Which to read first

Bytecode. It is the one case where code is absent from the file under review, arrives
after release, and runs unsandboxed (that README, `372-379`). Its format is written
down and four bytes name it. arm64e is smallest. Modular AOT is last: no AOT runtime
loads it here.

## Not read

- `runtime/vm/interpreter.cc`, and `runtime/vm/bytecode_reader.cc` past its header check.
- Module clusters other than Code and ObjectPool; the module compiler's stub bodies.
- Whether `Thread` offsets move under the define (`runtime/vm/thread.h:1660-1663`).
- Flutter beyond the two files cited, and any release branch.
- A design document for modular AOT: none found under `runtime/docs` or `docs`.
- No binary was built: every test above comes from writer source.
