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
