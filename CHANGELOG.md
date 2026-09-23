# Changelog

Notable changes to jadart. Dates are the day the work landed on `main`.

The version number covers the **interface**, not the internals: the command set and their
options, the exit codes, the shape of `--json`, and the names re-exported from the `jadart`
package (`header`, `program`, `verify`, `export`, `decompile`, `strings`, `selectors`,
`constants`), and the exception classes those raise.
Everything under `jadart.*` submodules is implementation and may move in a minor release.
A new Dart format epoch is a minor release, because it only ever adds binaries that parse.

## Unreleased

### Fixed

- **`export` works on every input the other commands take.** Pointing it at a directory
  exited 3, the code that says the defect is in this program rather than in the file, with
  `KeyError: 'resources'`. The summary decided whether to describe the container by reading
  `c["assets"] or c["resources"] or c["native"]`, and no version of `unpack` has ever
  returned the last two. A container with assets never noticed, because `or` stops at the
  first truthy value; anything with none of them reached the second key and raised. That
  is a directory, and also an APK carrying no `flutter_assets`, which the report did not
  mention. A bare `.so` was never affected, because the CLI passes no container for one at
  all, and the report was wrong to say so. The test is now `c["members"]`, which is the same one
  `container.py` uses to decide whether to write `container.txt`, so the summary block and
  the file it points the reader at agree rather than being gated on different things. Two
  tests: one exports from all four inputs and checks that the block and the file appear
  together or not at all, the other compares the keys the summary reads against the keys
  the container walk writes, because `or` will hide the next wrong name exactly as it hid
  this one. While fixing it: the summary named `assets/` on a container that carried none,
  which is a path that is never created, and `jadart export` has always guarded the same
  line on the terminal. It reads `1 member` rather than `1 members` now too, which only
  became reachable once a single member container stopped crashing. Closes #25.
- **G13 checks something now.** It sat in the Tier B table on every run, hardcoded to pass
  with zero checks, waiting for a "both snapshots present" case that `verify_file` never
  produced. It now parses the vm header alongside the isolate one and compares the vm
  snapshot's object count against the isolate snapshot's base object count, which the VM
  itself asserts at load. The two numbers come out of two separately parsed headers, so a
  header misparse on either side is what would make it fail. A container with no vm
  snapshot, such as a stripped binary found by the magic scan, gets a skip that says so.
  Closes #3.
- **The call graph says what it dropped.** A code range that failed to decode was skipped
  with `except Exception: continue`, so the function was simply absent from the graph and
  every count printed beside it looked complete. Those ranges are recorded by pc on
  `CallIndex.undecodable` now, and `functions` prints how many and which. The library
  attribution had the same shape: one failure blanked the library column for every
  function, indistinguishable from a snapshot that records none. It now says why, and only
  swallows a `JadartError`; a defect in this program propagates. `function_table` returns a
  third value, `notes`, carrying both. Closes #5.
- **The operand caches survive between lifts.** `use_target` snapshotted, cleared and
  restored the three operand parser caches on every `lift_function` call, so every
  function started cold and the memoisation the module spends paragraphs justifying never
  paid: over 400 functions the cache was empty when lifting finished. It now returns early
  when the target being bound is the one already bound, which is every arm64 lift. A real
  switch to arm32 still clears and restores, and `export` is byte-identical with and without
  the change. Uncached `canon()` calls over those 400 functions go from 7,771 to 1,187.
  Closes #4.
- **`Function::Kind` is a named table with a measured provenance.** The constructor,
  getter and setter labels, and the instance/static receiver witnesses, were three sets of
  bare numbers commented "for this epoch" and applied to all eighteen. They are now derived
  by name from `FOR_EACH_RAW_FUNCTION_KIND`, and that list was fetched from `raw_object.h`
  for every registered release, 2.19.0 through 3.12.2: all eighteen declare the same
  seventeen kinds in the same order, so the numbers are right everywhere the tool parses.
  A test pins the derived values, and the comment carries the two-line check to repeat
  when a newer release is registered. Closes #6.

### Changed

- **A container is read in place, and nothing is written to disk.** Pointing any command
  at an APK or IPA used to copy the snapshot member into a `jadart-` temp directory, read
  the copy back, and remove the directory from an `atexit` hook. Since Android Gradle
  Plugin 3.6 a release APK stores native libraries uncompressed so the loader can map them,
  so `libapp.so` now comes straight out of the central directory: 1 ms for 4.2 MB, and a
  container that does deflate its libraries still works because zipfile inflates into
  memory just the same. Three things follow. A killed process leaves nothing behind, where
  before every SIGKILL leaked a full copy of someone's app into the temp directory, because
  `atexit` does not run; there was a fortnight old orphan in the temp directory here when
  this was written. No command asks for a temp file at all now, so nothing depends on
  finding a writable one. And `verify` reads the member once rather than twice, because the
  bytes are read once and handed to both readers instead of each opening the file for
  itself. The process wide cache that stopped one APK being unpacked three times is gone
  with the unpacking: a second call re-reads the member for about a millisecond, against
  the seventy the parse behind it takes, and holds no state between calls in exchange.
  `jadart.source` holds the new reader; `export.resolve_input` and `export.resolve_cached`
  are gone, both implementation under `jadart.*`. Closes #18.
- **A container member is inflated under a bound, not after one.** The size a zip declares
  for a member was checked before reading it, and then `ZipExtFile.read()` with no
  argument asked zlib for up to a gigabyte before truncating the result to that declared
  size, so the check was consulted only after the memory had been spent. A 199 KB archive
  declaring a four byte member and holding a 200 MB deflate stream reached 422 MB of
  resident memory. The member is now read a megabyte at a time and never past the size it
  declared, so the same archive reaches 22 MB and fails on its own bad CRC, which is the
  right answer for an archive that lies about a member. A test measures the peak against a
  control container of the same shape holding nothing, and fails on the unbounded read.
- **`--json` reports the file it actually read.** `jadart -j info app.apk` used to put the
  temp path in `"file"`, which named a directory that no longer existed by the time the
  caller read the document. It now names the container and the member it picked, as
  `app.apk!lib/arm64-v8a/libapp.so`. A binary named directly, or found inside a directory
  the user named, still reports its own path, so the field stays openable wherever a file
  exists to open. A path that does not exist now says "no such file or directory" from
  every entry point; the CLI and the library used to answer that with two different
  sentences.

## 1.1.0 - 2026-09-06

### Added

- **Const lists come back with their elements.** The fill pass was already reading every
  element of every Array to stay in step with the stream and then discarding them, so a
  decompiled table lookup showed the arithmetic over `pool_0xb970[i]` with nothing saying
  what was in it. For const DATA (a keystream, an S-box, a table of magic constants)
  that is the half that matters. `jadart constants` and `jadart.constants()` return them,
  `export` writes `constants.txt`, and a lifted body labels a long table `const[47] @0xb9b0`
  rather than spelling it at every use site. Short lists still print in full. Resolution is
  all-or-nothing per list: an element that is neither an int nor a string refuses the whole
  list, because a table printed with holes invites the reader to read the holes as zeroes.
- **`JadartError`**, the base every input failure now derives from. `except
  jadart.JadartError` skips a file this library cannot process without naming nine classes
  or matching on messages. `ContainerError`, `TruncatedSnapshot`, `AllocError`, `FillError`
  and `UnsupportedArch` are exported for the first time.

- **Field names, where the snapshot still carries them.** `jadart/fields.py` recovers the
  instance-field layout out of the surviving `Field` objects: each one records
  `Smi::New(Field::TargetOffsetOf(field))`, its byte offset in compressed words
  (`app_snapshot.cc:2238`), and the Smi's value is written in the Mint cluster's alloc
  pass (`:5365`), which `clusters.py` now keeps. `this.field_0x8` renders as
  `this.balance` where the receiver's class declares a field at 8, and stays an offset
  everywhere else. Tier 0 gains the layout: `distance;  // @0x58 unboxed`.
- Three Tier-A gates for it. G12 puts every recovered offset inside its owner's declared
  `instance_size`; G14 compares it against the displacement the field's implicit getter
  actually compiled to; G15 compares the unboxed-fields bitmap against the register width
  that getter used. All three are cross-checks between two things the toolchain wrote
  independently, and all three report 0 disagreements on 33 corpus binaries and 44 apps.

### Fixed

- **`jadart.decompile()` invented a receiver.** It passed `receiver={"x1": "this"}`
  unconditionally, where x1 holds the receiver in an instance method and something else
  entirely in a static one. `program.receiver_for()` exists to decide that and was wired
  into the CLI, `export` and `program`, every caller but the public one. Measured on the
  corpus binary: 403 functions and 1,534 lines where the library API printed a `this` the
  CLI correctly omits. A guess presented as a fact, in the most public surface there is.
- **Untyped exceptions escaped the library.** A truncated snapshot surfaced as
  `struct.error` and an unrecognised file as a bare `ValueError`, neither of which any
  documented `except` clause names, so a batch scan over a directory of APKs died on the
  first bad file however carefully it was written. Every container failure now leaves
  `open_container` as `ContainerError`. Note for anyone catching the old types: these are
  no longer `ValueError`.
- **The package did not import on the Python it claims to support.** `signatures.py` used
  PEP 604 `str | None` without `from __future__ import annotations`, so `export`,
  `decompile`, `functions`, `lift`, `xrefs` and `signatures` all failed on 3.9, the
  declared floor.
- **CI ran 180 of 188 tests and reported success.** The `if __name__ == "__main__"` block
  reads `globals()` when it runs, and it sat mid-file, so the eight tests defined below it
  were invisible to `python tests/test_core.py`, the entire field-layout suite. CI runs
  pytest now, and a test keeps the block at EOF.
- **A silent-wrongness guard that could not fail.**
  `test_bool_singletons_are_the_only_null_offsets_used` asserted against a hand-duplicated
  `_NULL_CONSTS` that nothing in `jadart/` read. Swapping `true` and `false` in the table
  the lifter does read inverted every recovered boolean and left the suite green; verified
  by mutation, before and after. It now pins the live table by value and direction.
- **Width changes rendered as the value they do not produce.** `sxtb x0, w1` printed
  `x1`: for 0xff the machine holds -1 and the output read 255. `sbfx` with a zero lsb
  zero-extended through `& mask`, which is precisely the sign it exists to carry. And
  `lsr` and `asr` both rendered `>>`, though Dart's `>>` is arithmetic and `>>>` is
  logical, so a logical shift printed as a sign-propagating one at 308 sites in the clean
  build. All four are exact now: the unsigned forms mask, the signed ones are a shift
  pair, and the two right shifts are told apart. This was drift away from the rule the
  same file applies to `ror`, `sbfiz` and `udiv`, all of which decline rather than
  approximate.
- Cross-target cache contamination. `use_target` saved, cleared and restored
  `_CANON_CACHE` but not `_MEM_CACHE` or `_DEFUSE_CACHE`, which store `canon()` results
  keyed on the operand string alone, so whichever target parsed a string first answered for
  both. Gated off today by `LIFTABLE_ARCHS`, armed the day arm32 lifting lands.
- `clusters.routing` keyed its cache on `id(table)` alone, which a runtime-built table
  could collide with after being freed. The entry holds the table now and the lookup
  checks it.
- `signatures.py` imported `_resolve` out of the package root, inverting the layering and
  pulling APK extraction and a process-lifetime cache into the analysis layer invisibly.
  It lives in `export.py` as `resolve_cached` now, and both callers import downward.
- `MissingDisassembler` no longer discards the capstone import error, which told users who
  had installed capstone to install capstone.
- `tools/measure.py` looked for extra binaries under one contributor's home directory.
  It reads `JADART_EXTRA_BINARIES` instead.
- Documentation reconciled against the code: the README claimed both "fifteen epochs" and
  "one supported epoch today"; five places claimed `8/8` Tier-A gates when there are 12
  defined and 9 to 11 applicable per target; the test count was stale in four files.

- `tools/appsweep.py --verify` matched the literal string `Tier A: 8/8`, so it reported 0
  of 48 apps passing from the moment a ninth gate existed. It now requires every applicable
  Tier-A gate to pass, whatever the count.

### Changed

- The documented limit "field names are gone from the format and are not coming back" was
  wrong and is corrected in README.md, HOW-IT-WORKS.md and EVAL.md. It came from observing
  that the offset-to-field table is tree-shaken, which is true, and generalising to every
  `Field` object, which is not: 245 of the corpus binary's 420 are instance fields with
  their offsets intact, and 36,555 of 59,160 across the 44 cached apps.

## 1.0.0 - 2026-08-17

First release under a version that describes what is here. `0.1.0` had stopped being true
some time ago: fifteen format epochs, 8 of 8 applicable Tier-A gates on all 33 binaries in
the checkout, 156 tests, and a command surface that had not changed shape in weeks.

The number covers the interface, not the reach. Tier 3 still models arm64 register roles
only, most field names are gone from the format (see Unreleased for the minority that
are not), and `jadart.*`
submodules remain implementation. What 1.0.0 says is that the commands, their exit codes,
the `--json` shape and the package re-exports are a contract.

### Added

- `jadart ffi`, the native boundary on one page: shared-object names in the ObjectPool,
  the functions that read them, and the symbol literals that reach a call site there.
  Built for apps whose interesting code is not in Dart at all. Classification is on the
  filename shape and the report says so; a binary with no such literal is refused with the
  reason rather than given an empty table.
- CI now runs `tools/cfgcheck.py` on both committed fixtures, and checks that an export is
  byte-identical under two different `PYTHONHASHSEED` values. A rendered edge the CFG does
  not have is the worst defect this tool can ship, and a hash-order dependency has shipped
  here once already; neither had anything watching it between releases.

- **Real apps, as evidence.** `tools/appsweep.py` probes F-Droid for Flutter apps by
  range-reading each APK's zip central directory, then range-fetches just `libapp.so` out
  of the hits: one request per probe, two per fetch, so 26-180 MB of APK costs 6-24 MB of
  transfer. 700 probes found 174 Flutter apps in about eight minutes. 48 of them are now
  swept: 44 pass all eight Tier-A gates, 13 of the 15 epochs are exercised by third-party
  code, and cfgcheck finds no edge violation in any of the 37 that lift.

### Fixed

Defects of one kind: a value printed with confidence that the machine does not hold.

- **A cluster no real app could do without.** `LibraryPrefixCid`, `import ... deferred
  as`, had no fill grammar, because flubench is one app we wrote and it never used a
  deferred import. FluffyChat 1.29 died on it at cluster #1080 of 1090. Four lines, once
  the kind was right.
- **Every snapshot was reported as the wrong kind.** `Snapshot::Kind` is kFull, kFullCore,
  kFullJIT, kFullAOT, then kModule in 3.12 with kNone below it; the table omitted
  kFullCore, so every value from 1 up shifted and kind 3, what every Flutter release
  snapshot is, printed as `kModule` on all fifteen epochs. It also hid the missing
  grammar: LibraryPrefix serialises `name` and `imports` under kFullAOT but is UNREACHABLE
  under kModule, so the label made the cluster look impossible to derive. A test had pinned
  the wrong answer, which is what made it durable.

- **A call no longer leaves behind the values it destroyed.** `_CALL_CLOBBERS` has said
  what a call takes with it since liveness needed the answer, and the value map ignored it,
  resetting the return register and nothing else. Anything known about x1-x14 or d0-d30
  walked through the call and was printed on the far side. Worst spelling: a register the
  map does not describe falls back to the receiver alias, so x1 after a call printed
  `this`. dart:collection's `_CompactLinkedHashBase.forEach` compares `_data` re-read after
  the callback against the copy taken before it, and both sides rendered as
  `this.field_0x10`, a concurrent-modification guard shown as a comparison that cannot
  fail.
- **A `goto` target no longer speaks for the path it did not come by.** `structure` emits a
  `goto` exactly where it could not express an edge, so a goto target is a join the walk
  does not know it is standing on. `ArgumentError.value` printed an optional argument on a
  path where the register holds null. Which registers are in dispute is decided by the
  dominator relation, not guessed.
- **An expression no longer outlives the register it reads.** `_pin` had written the
  invariant down and was wired to one writer. `Duration.toString` assigned x1 and then read
  `x1.field_0x8` off the value x1 had before, with both lines on the page.

Each has a test that fails without its fix. The cost is paid in bare machine registers,
which is the honest direction: on the corpus binary they go 27.9% to 28.2% while
byte-offset fields fall 28.9% to 27.8%.

## Before 1.0.0

Ninety-odd commits from 2026-07-15, in the git log with the measurement that motivated each
one. The shape of it: the snapshot format first and byte-exactly, then names, then the
three lifter tiers, then the acceptance gates that keep a wrong grammar from passing
quietly, then structuring the control flow and the oracles (`semdiff`, `cfgcheck`,
`irfuzz`) that score it against real source and real emulation.
