# Changelog

Notable changes to jadart. Dates are the day the work landed on `main`.

The version number covers the **interface**, not the internals: the command set and their
options, the exit codes, the shape of `--json`, and the names re-exported from the `jadart`
package (`header`, `program`, `verify`, `export`, `decompile`, `strings`, `selectors`,
`constants`), and the exception classes those raise.
Everything under `jadart.*` submodules is implementation and may move in a minor release.
A new Dart format epoch is a minor release, because it only ever adds binaries that parse.

## Unreleased

### Added

- **A field of a value a cast let through is named, on the edges after the cast.** A
  name was printed off `this` and off an object the body allocated, the two bases whose
  class the snapshot states. A cast states a third. `x as C`, an implicit downcast and a
  covariant parameter check compile to `AssertAssignable`: inline class-id checks that
  jump past the stub, then a `bl` to C's type-testing stub with the value in x0 and the
  `Type` in x8, which returns only if the value is assignable. Where no class implements
  C, every subtype extends it and keeps C's fields at C's offsets, so past the cast C's
  map names the value's slots: `childAfter` printed `return t2.field_0x8.field_0x14;`
  and now prints `return t2.field_0x8.nextSibling;`, `parentData as FlexParentData` in
  RenderFlex's mixin application. A destination with type arguments is called through
  the entry point its Type holds, `ldr x9, [x8, #7]; blr x9`, and that call proves the
  same; a type parameter's, called through x4 with the TypeParameter in x8, proves
  nothing. `fields.cast_accesses` is a forward must-analysis over the body's CFG, with
  value numbers through copies and frame slots and intersection at every join, so a name
  is printed only where every path to the access proves the class; a join that code the
  entry does not reach flows into, a catch handler or an unchecked entry, knows nothing,
  and one where each path proves the class of a different value gives the join's value
  that class.

  Each piece of evidence is checked against a second encoding, and one disagreement
  refuses. `Class::is_implemented` against every class's `interfaces` array, 598 entries
  on each fixture and 776 to 2,358 on the seven app-sweep libraries, 0 contradicted; the
  abstract bit, which lets a check accept an id no instance has, against every class
  owning an allocation stub, 921 and 1,832 to 5,346, 0 carrying it; every specialised
  type-testing stub's own code, read path by path for the class ids it returns on,
  against its class's subclasses, 237 and 235 stubs and 399 to 1,362, all read and 0
  accepting an id outside the class, null and the ids the compiler's ranges treat as
  "don't care"; the two shared default stubs, which only their names identify, read as
  accepting null alone; and every inline check's accepted ids, 179 and 101 edges and 575
  to 1,287, 0 outside. A stub that let through a class outside its own would refuse that
  class everywhere, and an inline check that did declines its cast.

  Measured over every range against the commit before. Clean fixture: 96 accesses named
  of the 302 the analysis gives a class, every one from a `Field` object and none named
  by another channel (`nextSibling` and `previousSibling` off four `ParentData` classes,
  a `_Future`'s `_state`, `RenderMouseRegion.onEnter` and `onExit`,
  `_StreamControllerAddStreamState._varData`); 47 bodies and 98 lines change, each a
  one-for-one substitution of a byte offset by a name recorded for that range and offset,
  and `tools/quality.py`'s byte-offset row goes 52,626 to 52,556 with every other row and
  the line total the same. Obf fixture: 8 named, 8 lines, byte-offset row 54,162 to
  54,157. xeonjia (2.19.6), jsdict (3.3.4), labplus (3.5.4), anytime (3.6.2), kazumi and
  tsdm_client (3.11.5) and FluffyChat (3.13.0): 309, 305, 352, 414, 373, 496 and 397
  named, on 365, 316, 369, 442, 393, 556 and 414 lines, every one a substitution. `jadart
  export` changes 21 lines in 6 files on the clean fixture, all substitutions, and none
  on the obf one. A destination some class implements is still refused, where an
  abstract implementer with no concrete subclass would not need to be: 12 accesses over
  the nine binaries. `tools/pbfuzz.py --census` reads 2,086 wrong and 0 stale on both
  fixtures and `tools/cfgcheck.py` 0 violations, before and after. See DESIGN 13.1 (c).

  What it may cost is bounded. The walk sweeps the blocks in reverse postorder, carries
  the classes proven rather than every cast that proved them, and is charged per state
  entry it meets or scans: a body that spends 1,000 units per instruction is declined
  with nothing named. With no budget, the most any of the 3,890 bodies the analysis runs
  on in the two fixtures and the seven apps spends is 316 per instruction, and the 99th
  percentile 191 to 208. A crafted loop that casts and reads 200 times over, 1,003
  instructions, took 13.9 s against 0.028 s for the same body lifted without casts and
  now takes about as long as that.

- **An incoming argument is named by the register it arrived in.** The body printed an
  argument as the machine register it came in, `if (x2 < 0x28)`, while the pass every
  call site asks for a callee's arity had already read that x2 as the function's second
  register argument. Now `program.EntryNames` hands the lifter the same map the receiver
  already rode in on, `{"x1": "this", "x2": "a1"}`, built from three facts the binary
  states: the release passes fixed parameters in registers (Dart 3.4 on, which the
  snapshot hash pins), the code is a Dart function's of a kind the VM does not always call
  through the stack (its `Function`, the Smi the precompiler leaves for a dropped one, or
  a table entry below `first_entry_with_code`, which `DiscardCodeObjects` only does to a
  function's Code), and the body reads the register before it writes it (`entry_args`,
  the live set `entry_arity` was already computing). Compiled Dart reads no register it
  was not handed, so such a register holds what the caller left there, and in a register
  of `kCpuRegistersForArgs` that is an argument. `aN` says which register and nothing
  more: slot N of x1, x2, x3, x5, x6, x7, which is also the value's position in a direct
  call's printed list. Not a Dart name or type, neither of which the snapshot keeps for
  these, and not a position in the Dart parameter list, since a double rides in a V
  register beside them. jadx's fallback is the same shape, `rN` for a parameter with no
  debug name (NameGen.java); AOTopsy's `arg1` is the same slot.

  Whether a register STILL holds the argument at a use is decided the way it always was
  for `this`: `Lifter._leaf` prints the name only while the state map has never recorded
  the register on any path, and every write, call clobber, disagreeing join, loop forget
  and goto meet records it. Two places did not. A block no path from the entry reaches
  was handed an empty map, so a catch block's x1, the stack trace, printed `this`:
  `_run`'s `_list2(x0, this)` on the clean fixture, 1 line on each fixture, now
  `(x0, x1)`. A type-testing stub was taken to give every register back where it keeps
  four (`TypeTestABI::kPreservedAbiRegisters`), so x3, x5, x6 and x7 now go bare after
  one, and so does any of them holding a copy of a name, `mov x5, x2` or a reload of a
  spilled argument. And the Mint slow path the box-or-tag strip cuts calls a stub that
  uses x1 as its temporary (`AllocateMintABI::kTempReg`), so x1 is recorded where the
  strip cuts it. No line on either fixture reads such a register there; a crafted body
  can, and printed `a1`, `a3` or `this` for it. The leading run of
  argument registers is what a call list needs, but a name can skip a slot: `classify`
  never touches `this`, reads x2, and is `classify(a1)`; 253 counted ranges on the
  clean fixture read a register past a gap. Checked against the snapshot where it still
  says: 428 functions keep their `FunctionType` and resolve, the highest register read is
  never past `num_fixed_parameters` on any of them, and in the 11 that read past a gap it
  is exactly the last. Of the 1,075 ranges of the stack-calling kinds the pass counts a
  register for none. Where it declines, an arguments descriptor (372 ranges), stack
  arguments only (1,559) or a double in a V register (226), nothing is named.

  The signature lists what the body reads, `checksum(a1)`, without the receiver;
  `withdraw()` reads no argument, and `f(...)` is a list the lifter did not read, the
  spelling a call to it already prints. `jadart lift` prints the same list in its header
  and `-j` carries it as `params`, as does `jadart.decompile()`.

  Measured with `tools/quality.py`: lines carrying a bare machine register fall from
  19,446 to 12,289 on the clean fixture (10.5% to 6.7%) and from 18,269 to 11,929 on
  the obfuscated one (9.9% to 6.5%); 2,251 of the clean fixture's 8,194 ranges and
  2,004 of the obfuscated one's get a name past `this`, on 8,481 and 7,516 lines.
  `ellipsis`, `goto`, `rawasm` and `label` are identical. The line total falls 185,227
  to 184,060 and the byte-offset field count 53,463 to 52,626 (54,970 to 54,152 on obf)
  for one reason: a value spelled off an argument's name does not go stale when the
  register is reused, so it is not written out first. 6,138 ranges are byte-identical,
  1,594 change by the name alone on 5,117 lines, and 462 are restructured: declined
  frame reads fall 5,141 to 4,328, a spilled argument's reload,
  `var t7 = (FP - 24).field_0x1;`, now reading the argument, where the slot held the
  bare register before and the fallback read it back as itself; `var tN =`
  declarations fall 35,359 to 34,364; the rest is the same statement spelled with a
  different temporary boundary, `(t3 >> 1)` as `t3`. `jadart export` changes 260 of
  323 files on the clean fixture, 3,036 signature lines of which 1,112 become `(...)`
  and 1,924 list a name; on the obfuscated one only 163 signatures change, to `(...)`,
  since its surviving `Function`s are the closures and dispatchers. A register live
  into a loop that still holds what the function was entered with now reads by its
  entry name in the loop too, `var t0 = a1;` and `if (t1 < a3)` where it printed the
  register: 117 lines in 39 ranges on the clean fixture, 37 of them the `var` that
  starts a loop and the rest reads inside one, 48 of the 117 `this`.

  `tools/irfuzz.py --args` lifts the generated graphs with the six argument registers
  named and scores each name as its register's entry value: 0 mismatches over 2,000
  graphs in each of `--cfg`, `--cfg --nested`, `--cfg --flags`, `--cfgmem`, `--cfgmem
  --nested` and `--cfgmem --seed-outputs --nested`, 1,272 to 1,887 bodies printing a
  name per run. The three `--cfg` runs leave no printed expression undecidable, where
  without the flag the bare registers left up to 28,150; the three `--cfgmem` runs
  leave 90,826 to 125,324, against 75,952 to 184,389 without it. Put a
  loop's forget back and 200 graphs disagree 19 times; the join meet, 6 in 600; the
  merge record, 6 in 600 with memory; without the flag all three read 0. Every other
  oracle is unchanged on both fixtures: `irfuzz --corpus` 0 mismatches, `pbfuzz` 0
  disagreements and its census identical, `cfgcheck` 0 violations. Closes #255.

- **A method a `PatchClass` owns names the fields of `this`.** `Function.owner` is a
  Class or a PatchClass, and `Function::Owner` (object.cc:11358) resolves the second to
  the class it wraps. The lifter read only the first, so every member a mixin
  application takes from its mixin and every member a patch file adds to a core class,
  1,145 functions on the clean fixture, had no receiver class at all and nothing off
  `this` in them could carry a name: `describeSemanticsConfiguration` of
  `SemanticsAnnotationsMixin` printed `this.field_0x58` for the `late bool _container`
  its own source declares.
  `recover_fields` already took this hop for `Field.owner`, and dispatch.py for the class
  a table row belongs to; `fields._place_patched` is the third reader of the same fact.

  Three refusals, because the hop is a statement about `this` and not only about an
  owner. The function's StaticBit has to calibrate on the snapshot (`program.static_bit`
  returns None on two of the seven real apps measured, where every caller already treats
  every function as an instance method; the hop adds nothing there). Its kind has to be
  one whose first argument is the receiver, a method, an accessor, a generative
  constructor or an implicit accessor, so 748 static methods, factories, closures and
  forwarders on the clean fixture are declined. And where the function kept its
  signature, `FunctionType.parameter_types[0]`, the receiver's own type written by the
  FunctionType cluster and resolved through a `Type`'s class id, has to name the wrapped
  class: 337 of 337 do, over both fixtures and five real apps from 2.19.6 to 3.13.0,
  with the 42,716 Class-owned functions that also speak agreeing 42,716 times as the
  control, and one disagreement places none of them, the rule `recover_fields` applies
  to an offset outside its owner. `Epoch.ftype_params_index` says which of a
  FunctionType's six refs that array is, because `hash` moved from the end of
  UntaggedFunctionType to UntaggedAbstractType at 3.1 (raw_object.h, read on all
  nineteen registered releases; 3.13.0 keeps it at slot 4, raw_object.h:2984-2985 and
  :3051).

  397 functions placed on the clean fixture, 346 of them members of a mixin application,
  and 17 on the obf one. `tools/quality.py`'s byte-offset field row goes 53,511 to 53,463
  on the clean fixture (28.9% either way) and stays 54,970 on the obf one; 37 bodies and
  103 lines change on clean, every one a one-for-one substitution of a byte offset by the
  name the wrapped class's own `Field` object carries (`this._container@27266271`,
  `this._widget@20042623`, 17 distinct names), and 0 on obf, whose names are obfuscated
  too. The line total, `regline`, `ellipsis`, `goto`, `rawasm` and `label` are identical
  on both. `export` is unchanged byte for byte, because it and the `decompile` command
  list a class's methods by the owner ref and so have never written a PatchClass-owned
  method at all; `lift`, the `jadart.decompile` API and `tools/quality.py` see the
  change. On dev.labplus.app (3.5.4) 148 lines in 64 bodies change, on
  uk.me.amugofjava.anytime (3.6.2) 240 in 79 and on chat.fluffy.fluffychat (3.13.0,
  1,362 functions placed) 497 in 143, all substitutions; the two below 3.4 place 799 and
  761 functions and change no line, because their receiver arrives on the stack and is
  never `this` to the lifter. `tools/pbfuzz.py --census` reads the same as on main on
  both fixtures,
  2,086 wrong reads and 0 stale records, and `tools/cfgcheck.py` reports 0 violations of
  any kind on either. DESIGN 13.1 carries the per-channel measurement this came
  out of, zeros included: the type system was measured for seven sources of a base's
  class before this one was built, the cast channel is the one that remains and needs
  flow, and a callee's identity under `dedup_instructions` is refuted as a source with
  a counterexample. Part of #240.
- **A field whose `Field` object survives without a readable name is named by the
  implicit accessor the compiler made for it.** `KernelLoader::GenerateFieldAccessors`
  makes an instance field's getter and setter as `kImplicitGetter` and `kImplicitSetter`,
  named from the field, and sets each one's `data` to the Field itself
  (`set_accessor_field`); `BuildGraphOfFieldAccessor` builds the body out of that Field
  and parameter 0 alone. So the name and the slot are both the Field's, and the offset
  is the Field's own Smi, not a reading of the code. A Field usually names itself and is
  in the map already; `fields.recover_accessors` adds a name only where the Field's name
  is a string the VM snapshot holds, a base object the isolate snapshot refers to and
  never writes (`r`, `g`, `b`, `end`, `state`), while the accessor's `get:g` is written
  into the isolate snapshot.

  Two checks against second encodings, and one contradiction of either refuses the whole
  channel, the rule `recover_fields` applies to itself. Where the Field does name itself
  the two names must be equal: 145 of 145 on the clean fixture, 78 of 78 on the obf one.
  And the body, followed from the entry convention (x1, or the first pushed argument),
  through copies, spills and reloads, must reach the receiver at the Field's offset and
  nowhere else for a store: 84 on the clean fixture, 0 differing. A hand-written `get:`
  or `set:` is never read; see Fixed for what reading them cost.

  6 offsets over 3 classes on the clean fixture: `Color`'s `r`, `g` and `b`,
  `_AsyncStarStreamController`'s `controller` and `asyncStarBody`, and
  `_ConstantTickerModeDataListenable.value`. They take `tools/quality.py`'s byte-offset
  field row from 54,266 to 54,217 before the allocation channel, 49 lines. The obf
  fixture gains 0, because its accessor names are obfuscated too. Part of #240.
- **Dart 3.13, the current Flutter stable, is a registered epoch.** Hash
  `0451907c2eaa8467e848c0067bfe8ed4` is the 3.13.0 tag (`tools/sdk_source.py
  --identify`), which makes nineteen epochs over fifteen grammar families. It is the
  release that merged the vm and isolate snapshots into one (DESIGN 3), and nine
  things in the stream changed with that. Each is its own switch on the Epoch or a
  generated table, taken from the 3.13.0 source:

  - `Snapshot::Kind` lost kFullCore, so an AOT snapshot is kind 2. `info` names the
    kind from the epoch's own enum.
  - The base objects are seven fixed roots, not the vm snapshot's object table.
  - The roots' own objects are written first, so nine small clusters sit ahead of the
    canonical String cluster, and there are two ObjectPools: the empty one, then the
    one the code indexes.
  - Class alloc is a single count, a Closure carries a length in both passes, and the
    Code fill opens with two stub refs.
  - LocalVarDescriptors, ContextScope, ApiError, LanguageError, UnhandledException
    and UnwindError reach an AOT snapshot for the first time.
  - The roots open with 1,518 refs ahead of the ObjectStore: the Roots struct and
    the class table. The runtime stubs are 173 handles in that struct now, named by
    `VM_STUB_CODE_LIST`, so `tools/gen_objstore.py` reads roots.h and the lists it
    names, and `--check` re-derives the 3.13 layout with the other eighteen.
  - `LinkedHashBase` has a cid, 96, which moves every cid from there up by one
    (`ERA_3_13`, from `tools/gen_cids.py`).

  `verify` decided when it was right. On FluffyChat's F-Droid build (26.1 MB, the only
  3.13 binary there was) Tier A is 13 of 13 and Tier B 3 of 3 over 551,075 checks,
  the stream ending on the exact byte. The G3 gate lost what it compared, since the
  alloc pass no longer lists the predefined cids, and has a replacement: the 161
  class-table roots are read in cid order, each Class states its own id in the fill
  pass, and they sit behind 1,357 other roots, so a root run off by one ref fails all
  161. Two Tier-A gates are new and run only on 3.13. G16 binds the generated stub
  table to the binary: the Code fill names the LazyCompile and UnknownDartCode stubs by
  ref, and the roots must hold those refs where the stub list puts those names, so a
  table with a stub inserted or lost ahead of either fails, and then no stub is named.
  G17 compares the 456 lengths a Closure, ContextScope or LocalVarDescriptors states in
  each pass. G13 compares the header's base objects with the seven the release fixes.

  Against AOTopsy on the same file: 88,618 code ranges at the same 88,618 addresses,
  and the same owning class on every one of the 79,575 it gives an owner for. It lists
  10,679 classes to our 10,713; the 34 are the zero-size VM classes its listing skips,
  and all 10,679 are in ours under the same id and name. All 173 stubs are named, a
  stub named as a throw has no `ret` in its body, and a whole `export` is 2,572
  libraries, 83,330 methods and 1,102,633 lines in 125 s at a 403 MB peak, the same
  bytes on a second run. `functions` is the peak of any command, 558 MB.

  What it does not claim. 64-bit compressed pointers only, the target of that one
  binary: an iOS or arm32 3.13 build is refused by name, and an x86_64 one shares the
  grammar key with nothing behind it. A header the VM would not load as an app's AOT
  snapshot is refused before anything is read: any kind but kFullAOT, kModule included,
  and any base-object count but seven. Three shapes no binary has shown are refused
  rather than read on the source's word: a ContextScope or LocalVarDescriptors with
  anything in it, and a second ObjectPool with entries. Two stubs swapped between
  G16's anchors would pass every gate; their order is the source's, which
  `tools/gen_objstore.py --check` re-derives. On a build that keeps a symbol table, a
  stub's `stub X` symbol is spelled `_iso_stub_XStub` for the lifter and has to agree
  with the roots or the roots' names are dropped; no such 3.13 build has been seen. No
  3.13 fixture can be built with the 3.12.2 SDK this repository pins, so CI reads a
  hand-written 3.13 snapshot and the real-app test skips there.

  No output byte changes on an older release: 15 command outputs and the export tree
  of both fixtures, and 7 command outputs on each of six real apps from 2.19.6 to
  3.11.5, compare equal to main's. Closes #254.
- **A field of an object the body allocated is named, and the allocation says which
  class it is.** `Lifter._field` printed a recovered name only off `this`, because
  `Function.owner` was the only thing in the snapshot that stated a base's class, and
  59,131 of the 69,074 byte-offset field accesses on the clean fixture (85.6%) are off
  something else. There is a second such statement. `Code::owner()` is the Function,
  Class or AbstractType the code belongs to, and the VM makes a CLASS the owner of
  exactly one kind of code: that class's allocation stub, which
  `StubCode::GetAllocationStubForClass` builds and `Class::allocation_stub_` holds. 921
  of the 8,194 Code objects on each fixture are such stubs, called from 3,185 sites, so
  a `bl` to one allocates an instance of a class the snapshot names and the result is a
  base whose class is read rather than guessed.

  The stub's own body confirms it, which is what makes this a fact rather than a reading
  of one. Each loads the header word the new object will carry into
  `AllocateObjectABI::kTagsReg`, and bits 12..31 of that word are the class id, the same
  field `expr.detect_dispatch` extracts with `ubfx cid, tags, #0xc, #0x14`. That id is
  the owner Class's own id on 921 of 921 stubs on both fixtures, 0 disagreements, and
  one disagreement refuses the whole map on the argument `recover_fields` already makes
  about an offset outside its owner: all 921 owners were read the same way. Bits 8..11
  hold instance_size / kObjectAlignment and agree with the Class cluster's instance size
  on all 916 where four bits can hold it, which is a second agreement from a different
  half of the serialiser.

  Measured over all 8,194 and 8,188 ranges. Byte-offset field accesses 69,074 to 68,388
  on the clean fixture and 70,764 to 70,536 on the obf one; `tools/quality.py`'s
  per-line count 54,266 to 53,740 (29.3% to 29.0%) and 55,041 to 54,970, with `regline`,
  `ellipsis`, `goto`, `rawasm` and the line total identical on both. 2,573 allocations
  rendered as `new C()` becomes 5,193 and 5,138, so a call that printed
  `sub_0x16a418(...)` now prints `new Paint()`. Every one of the 2,410 changed export
  lines is a one-for-one substitution and none of them prints a byte offset it did not
  print before. `tools/pbfuzz.py --census` is unchanged at 2,086 wrong reads and 0 stale
  records on both, and `tools/irfuzz.py --corpus` on both fixtures, `--mem 15000` and
  `--cfgmem 6000` report 0 mismatches.

  The refusals are the half that had to hold. A name still comes only out of the owner's
  field map, so a slot whose `Field` object was tree-shaken keeps its offset: 6,812 of
  the 7,504 accesses this attributes on the clean fixture are not named. `instance_size`
  bounds the object, so an offset outside it cannot be a field of this class, and one
  that appears drops the whole attribution for that base rather than naming the one
  access it could still look up. The guard fires 0 times on either fixture, which is
  7,504 and 7,515 independent displacements out of the compiled code agreeing with the
  owner's instance geometry. A stub whose owner class has no surviving name is left out
  as well, 12 of 921 and 17 of 921: the class id is proven either way, but a field name
  off a value whose provenance the reader cannot see is a name with no way to check it.

  What this is NOT is the `_ALLOC_TYPE` half of the same idea, which was measured first
  and is worth exactly nothing. The object-store allocation stubs name `List`,
  `Context`, `Closure`, `double` and the typed-data arrays, and 2,536 field accesses on
  each fixture are off one of those results; 0 of them can be named, because every type
  in that table is a VM representation with no Dart `Field` object. The other source, a
  dominating cid comparison, was measured too: 1,631 single-cid comparisons feed an
  eq/ne branch on the clean fixture and 535 field accesses sit off the proven receiver
  on the proven edge, of which the field map names 17. See DESIGN section 13.

### Changed

- **`check.sh` runs the suite with capstone blocked, as CI does.** CI's
  install-without-capstone job requires every test that decodes an instruction to skip
  there rather than fail, and nothing local ran that: a cast-channel test that loaded the
  fixture without skipping passed `check.sh --full` and was first seen failing on CI
  (#277). `framework/tests/conftest.py` makes capstone unimportable in every worker when
  `JADART_TEST_NO_CAPSTONE` is set, and the fast set now runs the suite that way too:
  339 pass and 148 skip in about 7 seconds. With that test's skip taken back out, the
  step fails.

- **CONTRIBUTING.md and framework/README.md no longer state a test count.** They said
  378 and 397 while pytest collects 466; each copy went stale on the next change that
  added a test. Both point to the top-level README's Tests section instead, so there is
  one count to keep current.

- **A signature line says what the body reads.** `name() {` meant nothing; it now
  lists the argument registers the body reads by their names, `benchWithdraw(a1) {`,
  stays `()` where it reads none, and is `(...)` where the list was not read, at tier 3
  only. Tiers 1 and 2 print the machine's registers and keep their empty brackets.
  `jadart lift`'s header comment carries the same list, `// benchWithdraw(a1)  0x1eebac
  (36 bytes)`, and its `-j` output and `jadart.decompile()` gain a `params` string.
  That is an addition to the interface this file's version number covers, the shape
  of `--json` and a re-exported function, so it is a minor release; nothing is
  removed or renamed.
- `expr.entry_args` and `make_arity_resolver(...).args` give the registers a function
  reads its arguments from, from the same pass and cache as the count. `receiver_for`
  is unchanged and `EntryNames` builds on it; every lift call site now goes through
  `EntryNames` (#255).
- **`info --lenient` names a snapshot kind only where the number settles it.** The
  kind enum is numbered differently from Dart 3.13, so on a hash no epoch holds the
  number alone does not say which kind it is: 0 is `kFull` either way and 1 to 3 now
  print as `?1` to `?3`, where they printed the pre-3.13 name. That name was wrong on
  the first real 3.13 app, a release AOT snapshot reported as `kFullJIT`. A registered
  epoch is unaffected.
- **The quick path of `snapshot.walk_isolate` reads the canonical strings wherever
  their cluster is.** It returned an empty list whenever the first cluster was not
  String, which is every 3.13 snapshot. Through 3.12 a canonical String cluster is
  always first, so nothing changes there.
- **EVAL.md re-measures the field, because the tool it was scored against no longer
  exists.** `zboralski/unflutter`, the backend every row of the Phase 0 comparison used,
  has been removed by its author; the maintained successor is `BroNils/aotopsy`, a fork
  that adds x86_64, a decompiler and Frida export, and `caverav/flutterdec` is a second
  new entrant that emits pseudo-Dart. So taxonomy item 4, that every other tool stops at
  assembly or Ghidra C, is no longer true and says so. AOTopsy was built and run on the
  same two fixtures: it renders the same 8,194 ranges in 261,039 lines against our
  185,227, sees 71,068 field accesses against our 71,036 and names none of them against
  our 2,693, recovers a selector offset for 2,319 of 3,425 dispatch sites against our
  2,580 of 3,333 and names none against our 607, prints 31,500 goto lines against our
  5,493, and leaves 5,223 bodies partly unrendered where we leave none. It refuses an
  iOS dylib that we parse. On the real apps it is the other way around: FluffyChat's
  current F-Droid build is Dart 3.13.0, which AOTopsy reads and we refuse, and the
  section says so rather than leaving the axis unmeasured.

- **Every countable claim in the README was re-measured against this commit.** Each was
  true when it was written, none of them is gated, and the page itself describes that
  failure mode two sections further down. What had drifted: the goto fallback (19.2% of
  functions, now 1,414 of 8,194 at 17.3%), the share of conditionals whose arms each end
  in their own return (36%, now 38.5%), the Tier 0 member count (5,756, now 5,779), the
  dispatch sites that recover both a receiver and an offset (about 74%, now 2,580 of
  3,333 at 77.4%), the pipeline's exception-free range count (over 9,000, now the two
  fixtures' 16,382 with 0 exceptions), and the tests a fresh clone runs (around 177, now
  about 405 of 436). The showcase printed bare machine registers through `checksum`'s
  loop, which a run today names `t0` to `t5`. The 7.8% irreducible figure had no
  measurement behind it: 201 of the clean fixture's 8,194 functions (2.5%) hold a
  retreating edge whose target does not dominate it, and all 201 emit a goto, so none of
  them is a graph the structurer could have rendered without one.
- **The field-name sections say what names a field, which is three channels now and not
  one.** The README and EVAL's matching paragraph both still said a name is printed on
  `this` because `this` is the only value whose class the snapshot states, which the
  allocation-stub and accessor channels (#240) made false. Measured on the clean fixture,
  with the accessor channel as #258 left it: the three take byte-offset field lines from
  55,089 to 53,511, the field map 823 of them, the accessors 49 more and the allocation
  stubs 706 more, so 1,495 of the 10,758 lines that would carry a `this.field_0x` are
  cleared (13.9%).

### Fixed

- **A conditional's follow node is found without scanning on past a dead arm.** Where
  the two arms of a conditional meet only at the exit, `structure`'s `follow` pushes one
  tag per arm forward in reverse postorder to find the block both reach, and stopped
  only once no tagged block was left to visit. An arm that ends in a trap or a return
  passes its tag on to nothing, yet the other arm's carried the scan to the end of the
  function, so N such branches cost about N * N: N loops in a row whose bodies trap one
  way visited 3.0 million blocks at 1,000 loops, and `tier3_graph` took 9.37 s of CPU at
  4,000 where 1,000 took 0.60 (#302). It now counts the blocks still to visit that carry
  each tag and stops once either count is 0, since no block can then come to carry
  both; an arm that is a back edge carries none from the start. The answer is the same:
  on 1,500 random graphs each follow node is the one the scan to the end gives, crafted
  shapes print the same text, and the whole-binary tier 3 dump of both fixtures and of
  the seven app-sweep libraries is byte-identical to main's. CPU seconds of
  `tier3_graph` on those loops, main then this: 1,000, 2,000, 4,000 and 8,000 loops
  0.60, 2.31, 9.37 and 38.45 against 0.11, 0.39, 1.51 and 6.24, the rest of it the latch
  scan of #301; with that fixed too, 0.02, 0.05, 0.10 and 0.22. An arm that dies in a
  block laid out after the rest of the function, a trap the taken arm jumps to at the
  end, is still reached last, and N such checks still visit about N * N blocks.

- **A loop's latches are read off its header's predecessors.** `structure` builds a
  loop's body back from its latches, the blocks the header dominates that jump to it,
  and found them by asking every block of the function whether it jumps to the header,
  once per loop. So N loops in a row cost about N * N: 3.0 million lines of that scan at
  1,000 loops, and 2.50 s of CPU in `tier3_graph` at 8,000 where 2,000 took 0.16 (#301).
  The predecessor lists `structure` already builds hold them, in the same order. The
  answer is the same: in tier 3 lifts of 1,000 random ranges every loop body is the one
  the scan gives, and the whole-binary tier 3 dump of both fixtures and of the seven
  app-sweep libraries is byte-identical to main's. CPU seconds of `tier3_graph`, main
  then this: 2,000, 4,000, 8,000 and 16,000 loops in a row 0.16, 0.61, 2.50 and 9.93
  against 0.02, 0.04, 0.09 and 0.17. N loops nested in each other still cost about
  N * N here, since each loop's body holds every loop inside it: 88 and 358 lines of
  `loop_nodes` per instruction at 30 and 120 loops, where the scan made it 148 and 598.

- **The frame's push and pop are stripped only off SP.** `strip_boilerplate` made any
  `stp` or `ldp` of x29 and x30 a nop as the frame chain, whatever its base, so `ldp
  x29, x30, [x0, #0x10]` loaded FP and LR from an object with no line saying so: with
  `mov x0, x30; ret` after it, `return LR;`, which now prints `return
  x0.field_0x19;`, and `stp x29, x30, [x0, #0x10]` now prints its two stores (#294).
  The pair is stripped where its base is SP and nowhere else, FP included: every one
  on the two fixtures and FluffyChat is off x15, the push pre-indexed and the pop
  post-indexed, 15,136, 15,126 and 89,493 of them, all stripped as before, and the
  tier 3 dump of those three and the six other app-sweep libraries is byte-identical
  to main's.

- **An `ldp` into its own base reads both words off the base it had.** `ldp x8, x0,
  [x8, #8]` loads both words from the address x8 held before it ran, and tier 3 wrote
  x8 first and read the second word off the value just loaded: with `add x0, x0, x8;
  ret` after it, `return x8.field_0x9.field_0x11 + x8.field_0x9;`, which now prints
  `return x8.field_0x11 + x8.field_0x9;`, the second word the same rows print with x1
  as the first register (#293). The w and `ldpsw` forms had the same fault. The two
  load shapes the ARM ARM leaves CONSTRAINED UNPREDICTABLE now print as they are: a
  writeback into a loaded register at a zero immediate, `[x8, #0]!` or `[x8], #0`,
  which read as a plain load, and an `ldp` into one register twice, which kept the
  second word. capstone decodes neither, so only rows handed to `lift_function` reach
  them. Against unicorn, every `ldp` and `ldpsw` capstone decodes with the base as the
  first, the second or neither register, x and w, signed offset, pre and post-index at
  four immediates, 60 in all: 12 printed a wrong value on main and none do now; of 22
  unpredictable rows, 19 picked one outcome on main and none do now. No `ldp` or
  `ldpsw` on either fixture or FluffyChat names its base as a register or one register
  twice, and no load there writes back into its own base, 4,081,069 instructions in
  all; the tier 3 dump of those three and the six other app-sweep libraries is
  byte-identical to main's.

- **A Smi tag read back gives the value back, not half of it.** `sbfiz xD, xN, #1, #0x1f`
  is the Smi tag under compressed pointers, bits 0 to 30 of xN sign-extended and shifted
  up one. Tier 3 prints it as xN, the Dart value it tags, which is how a store, a call and
  a return read it, but the untag `sbfx #1, #0x1f` printed machine arithmetic on that
  value, so a tag read back was divided twice: `sbfiz x1, x2, #1, #0x1f; sbfx x0, x1, #1,
  #0x1f` printed `x2.toSigned(32) >> 1` where the CPU has bits 0 to 30 of x2
  sign-extended, `x2.toSigned(31)`, and the w form printed the same (#290). The tag now
  records on its value that the register holds it tagged, `V.smi`, and the untag reads it
  back: `x2.toSigned(31)`, or x2 where the value's bound proves it fits. Every tag on the
  fixtures and the seven app-sweep libraries is a box-or-tag check, `cmp xN, xD, asr #1;
  b.eq`, and the path tier 3 follows past it is the one where that comparison found xN
  fits, so there the register holds xN boxed and both halves of an unbox give xN back: the
  untag, and the Mint's value field, `ldur xR, [xD, #7]`, which printed as a field of the
  int, `a1.field_0x8`. The record goes where the value goes, through a 32-bit write, a
  name a stale register or a frame slot gives it, and a tag of a tagged register, which
  tags the word. Two paths that disagree on it agree on the value and drop the record, so
  a getter that boxes on one path and loads the field on the other still returns the
  field, and an untag past such a join reads the word as before.

  Measured against main over every range, lines counted by `difflib`. 16 ranges change on
  each fixture, 19 lines: 17 read a boxed value's Mint field as the value, `if (a1 ==
  THR.field_0x78.field_0x9b1.field_0x8)` for `a1.field_0x8 == ...`, and 2 untag a box, at
  0xfbfd4, which multiplied half the value, `(t0.field_0x8.toSigned(32) >> 1) * 0x2d51`,
  and multiplies `t0.field_0x8`. On FluffyChat, kazumi, labplus, jsdict, tsdm_client,
  anytime and xeonjia 45, 43, 41, 36, 52, 48 and 32 ranges change: 56, 47, 38, 31, 56, 46
  and 30 Mint-field lines, 4, 2, 4, 4, 4, 2 and 0 untag lines, and in 1, 0, 5, 6, 0, 7 and
  5 ranges an unbox, `t8 = t1.toSigned(32) >> 1; if (t1 & 1 != 0) { t8 = t1.field_0x8; }`,
  collapses to the value, with the temporaries after it renumbered. Most are the loop
  counter of `ChangeNotifier.notifyListeners`, reloaded boxed from its frame slot after
  each listener call, which reads `t1 += 1` where it read `t1 = t8 + 1`, one more than
  half of t1. Against unicorn 2.1.4, over random runs of up to seven instructions with a
  tag that end in an untag, three seeds of 5,000: of the runs where nothing but a tag or
  the untag reads a tag, 10,363 of 11,524 disagree on main and 0 of 11,551 here. Runs
  where another instruction reads a tag, an add, a shift or a compare, still read the
  value as the word, 675 of 3,303 disagree here and 3,089 of 3,294 on main; that is the
  reading of a tag by arithmetic, which this does not change.

- **A 32-bit `sdiv` divides the low halves of its registers, read as signed.** `sdiv w0,
  w1, w2` divides the low 32 bits of each register as signed values and keeps the low half
  of the quotient. Tier 3 printed `(x1 ~/ x2).toUnsigned(32)`, the whole registers
  divided: for x1 = 0x92b1d3f2ca02135e and x2 = 0xffffffff the CPU has 0x35fdeca2 and the
  text 0x92b1d3f3 (#291). It now prints `(x1.toSigned(32) ~/
  x2.toSigned(32)).toUnsigned(32)`, with a `.toSigned(32)` left off where the operand is
  already sign-extended from bit 31 or lower. `V.sext` records that: a signed bound, set
  where the text prints `.toSigned(k)` and carried through `>>` by a literal, so a Smi
  untag has 31. INT32_MIN ~/ -1 is 0x80000000 on the CPU and in the text. A zero divisor
  gives 0 on the CPU and throws in Dart; compiled code tests the divisor first. `sdiv x`
  was right and is unchanged, and `udiv`, which none of the nine binaries has in a w form,
  still prints as arm64.

  Measured against main. Every 32-bit sdiv on the fixtures and the seven app-sweep
  libraries, 2 on each fixture and 2, 4, 2, 2, 2, 2 and 2 on FluffyChat, kazumi, labplus,
  jsdict, tsdm_client, anytime and xeonjia, is the Smi `~/` or `%`: a `cbz` on the divisor
  and two untags, then the divide. An untag is a 31-bit value, so all 20 print as before
  and no line of either fixture or any of the seven libraries changes. Against unicorn
  2.1.4, over random runs of up to three instructions that end in an sdiv, three seeds of
  4,000: 7,547 of 8,928 w runs disagree on main and 0 of 8,848 here; 115 x runs disagree
  on main, each after an earlier w sdiv, and 0 here.

- **A loop's exit and a goto's join are worked out once, not per loop.** At each loop's
  exit `_exit_slots` asked `_loop_nodes` for the header and every block that reaches it,
  and what those write; at each goto's join `_join_kill` walked back over every block
  that reaches the target and on over every block its immediate dominator reaches. So N
  loops in a row cost about N * N to lift (#289): `add; cmp; b.lt` 8,000 times took
  18.97 s of CPU in `lift_function`, and 8,000 loops each leaving by a `cbz` into the
  next one's body 35.91. `_loop_nodes` is the same set for every block of a strongly
  connected piece of the graph, so what the exit asks is now folded once over the pieces
  in a topological order (`cfg.strong_components`, Tarjan's algorithm, iterative). The
  join walks back from the target only through the blocks between it and its
  dominator, read off the dominator tree: a block the dominator is above counts unless
  the target is above it too, and any other only where it is in the dominator's piece
  and the dominator reaches it there. A join in a tree of another entry, or in none, is
  walked as before. Output is unchanged: the whole-binary tier 3 dump of both fixtures
  and of the seven app-sweep libraries is byte-identical to main's, and in lifts of 300
  random ranges and of #282's graphs every exit and every join answers what the walks
  did. CPU seconds at 1,000, 2,000, 4,000 and 8,000 loops, main then this: in a row
  0.39, 1.32, 5.06 and 18.97 against 0.14, 0.36, 1.03 and 3.29; leaving by a `cbz`
  0.67, 2.45, 9.09 and 35.91 against 0.15, 0.31, 0.64 and 1.29; leaving by a `b` to the
  next head 1.44, 5.43, 21.25 and 90.48 against 0.40, 1.12, 3.56 and 12.61; with an
  if/else in each body 1.32, 4.69, 18.29 and 74.98 against 0.47, 1.26, 3.72 and 13.31;
  trapping one way round 1.33, 5.08, 19.68 and 78.90 against 0.77, 2.71, 10.32 and
  40.69. What still grows about four times per doubling is the structurer,
  `cfg.structure`, 58%, 72% and 66% of the first, third and fourth at 4,000, where
  `loop_nodes` scans every block for each loop's latches, and 92% of the last, in
  `follow`; the exit and the join take at most 6% each.

- **Which calls' results in d0 are read is worked out in one pass.** `_d0_result_reads`
  decides which calls' d0 a later read or a `ret` sees, on every lift of a function that
  calls something. It carried forward the set of calls whose d0 may still be there,
  rebuilt that set at every join and walked a block again each time it grew, so N if/else
  diamonds with a call in one arm cost about the cube of N: 1,000 took 8.05 s of CPU in
  `lift_function`, which `lift`, `decompile` and `export` call, 7.61 of them in that one
  call, and 2,000 took 58.07 (#296). It now asks backward whether d0 is live right after
  each call, one bit per block that is set at most once, the question liveness answers,
  over the blocks the entry or a root reaches. The answer is the same: on 400 random
  graphs with loops, edges out of the map, unreached blocks and extra roots it is what a
  walk of every path from every call gives, and the whole-binary tier 3 dump of both
  fixtures and of the seven app-sweep libraries is byte-identical to main's. CPU seconds,
  main then this: 250, 500, 1,000 and 2,000 diamonds 0.25, 1.23, 8.05 and 58.07 against
  0.11, 0.22, 0.44 and 0.88, and 8,000 take 3.90; the pass itself takes 0.01 s at 2,000.
  The same rows with every eighth join reading d0, so some results are read, print the
  same lines in 0.22 s at 500, 1.23 on main.

- **A loop that stores over a slot holding a register a join lost lifts.** Two rules
  forget a frame slot at a loop's head: one holding the value of a register a join lost
  goes when the loop writes or carries that register (#140), and one the loop stores a
  new value to that the next trip reads goes by `_loop_rewrites` (#109). The second was
  a `del` on the loop's state after the first had run, so a slot both named raised
  `KeyError: 'x29-8'` out of `lift_function` on a crafted 15-row range (#287). The
  rewrites now apply to the copy of the state before anything else drops a slot from
  it, where every slot they name is still there, and the slot is forgotten once: the
  reload in the loop reads it afresh, as a slot a loop rewrites does anywhere else.
  None of the nine binaries reached it, 0 errors in main's dumps of the two fixtures
  and the seven app-sweep libraries, and none of their lines change; 4,000 random
  graphs of up to 200 rows lift on this as on main.

- **A section too deep to structure prints its rows.** `structure` places a section no
  edge leads into after the body, and one nested too deeply for it ends the placing with
  a note counting what is left and saying `disasm` lists it. Tier 3's walk took that note
  for a section's over nothing and dropped it, so the rows left the output with no word:
  1,000 nested ifs behind a monomorphic entry printed `br x16   // x16 holds
  THR.field_0x258` and nothing else, without the monomorphic note either, and so did the
  same rows as a catch entry after a `ret`, at the CLI's recursion limit (#284). Each
  section left now keeps its note, the monomorphic one where the snapshot says so, and
  its rows follow as they are, at their addresses, as a whole function too deep to
  structure prints them, under `// nested too deeply to structure; its instructions
  follow as they are, in address order`; a section after it follows under its own note,
  and a block a goto names gets its label. Every row of the range is printed once. The
  body above prints as it did. In `lift`, `decompile`, `export`, `ffi` and
  `jadart.decompile`; tier 2 keeps its count, which was never dropped.

  Measured at the CLI's recursion limit: 1,000 ifs behind +8, 2,007 rows, went from 1
  line to 2,008, the two notes and 2,005 rows; 5,000 from 1 to 10,008; the catch entry
  from 1 line to 2,004. 50 deep is structured as before, 108 lines. Neither fixture has
  such a section, and neither changes a line. Printing the rest is linear: 200 catch
  entries each 600 deep, 240,202 rows, lift in 1.45 s of CPU against 1.05 s on main,
  which printed one line; 20,000 deep behind +8 takes 13.3 s here and 13.5 s on main,
  13.0 of them in `_idoms`, the same on both.

- **A section past a trap says what it does in the body.** `structure` places a section
  no edge leads into among the body's sections when all that comes before it is a trap
  or a call that cannot return, and tier 3 took it for body there: its goto into the body
  was printed bare. A catch entry past a `brk` that sets `x3 = 9` and jumps to the body's
  `add x0, x3, #1; ret` read as the body's `return this.field_0x8 + 1;`, where its own
  way in returns 10 (#283). It is now a section wherever `structure` puts it, as one after
  the body is: a block of the body that leads nowhere is printed again under it, from its
  own state, `return 9 + 1;`; a goto to one that leads on says `// the names past that
  label were worked out for the ways in above it, not checked for this one`; a goto to
  another such section is a way in the walk meets at the label, as one between the
  sections after the body is; and the body prints as it does without it, but for a label
  no goto names any more. A block past a trap that an edge reaches stays body, and so does
  a slow path laid out after a throw that an edge strip_boilerplate cut leads to, a stack
  check's or the one that boxes a Mint. The issue's example on the clean fixture, a
  section ending `goto L_0x175418;` in `resolve`, was a misread: that goto, and every one
  of the 6 bare gotos on each fixture from under a section's note to a label above it,
  is a stack check's slow path, `bl StackOverflowShared...; b back`, which the cut edge
  reaches, and each stays bare. In `lift`, `decompile`, `export`, `ffi` and
  `jadart.decompile`; tier 2 is unchanged.

  Measured over every range of the fixtures at the CLI's recursion limit: each has 762
  sections past a trap in 491 ranges, and no goto out of one reaches the body or another
  such section, so neither changes a line (0 of 8,194 and 0 of 8,188 ranges differ from
  main). On the seven app-sweep libraries one range changes, tsdm_client's at 0x8c0068,
  20 lines for 22: a catch entry's loop, placed past a trap, ran on into the body's
  `remove(t2, t1); goto sub_0x741930;` through a bare goto, and that block is now printed
  again under it, `remove(t25, t26);` with both read from the frame slots it loads
  itself. The body loses `L_0x8c04e8:`, which no goto names any more, and 17 lines are
  the later temporaries renumbered past the two new names. On crafted ranges of 1,000
  and 4,000 sections past a trap, each a catch entry
  with a branch back into the body, main printed 1,000 and 4,000 bare gotos and this
  prints none: to a loop head each takes the note, and to the `ret` each prints it again.
  4,000 of them lift in 0.26 s of CPU, 0.25 s on main; the clean fixture's largest range,
  `hash` at 0xed904 with 4,000 rows, in 0.125 s, best of five, and 0.124 s on main.

- **A Code object called through LR is read at its tagged offset.** Tier 3 kept x30, LR,
  among its untagged roles by name, so a read through it took no heap-object tag bias.
  From 3.3 on, AOT code calls a pool Code through LR: `Assembler::BranchLink` takes
  `code_reg = FLAG_precompiled_mode ? LR : CODE_REG` and calls `FieldAddress(code_reg,
  Code::entry_point_offset(entry_kind))` (assembler_arm64.cc:833-845 at 3.12.2, and so
  at every tag read from 3.3.0-174.2.beta to 3.13.0; 2.19.6 to 3.2.6 load CODE_REG).
  `ldr x30, [x27, #0x13e0]; ldur x30, [x30, #7]; blr x30` reads Code+8, the entry
  point, and `_get_ffi_native_resolver` at 0x25a0 on the clean fixture printed
  `pool_0x13e0.field_0x7(x1, NULL);` beside `pool_0x13e8.field_0x8(...);`, the same read
  through x8, where 0x7 is no word-aligned field (#280). LR is untagged now only where
  tier 3's graph proves it holds a return address: on entry with no write on any way in,
  or after a call. That is a must-analysis over the blocks, one bit each, so a join holds
  it only where every predecessor does and code no edge reaches holds it nowhere. Any
  other read or store through LR takes the bias, as one through any register of unknown
  value does, in `lift`, `decompile`, `export`, `ffi` and `jadart.decompile`. arm32's
  r14 takes the same rule, which no command reaches, as no command lifts arm32 rows.

  Measured with `lift` over every range against main, at the CLI's recursion limit.
  Every read through LR on both fixtures and the seven app-sweep libraries follows a
  load into LR earlier in its own block, from the pool, a far pool entry or the thread,
  and takes the bias now; none reads a return address and none stores through LR.
  Clean: 520 reads, 520 lines in 356 ranges change, each `pool_0x....field_0x7(` to
  `.field_0x8(`, and no other line; obf the same, 520 in 356. The apps: 23,598 lines in
  12,645 ranges, FluffyChat 14,565, kazumi 1,816, labplus 969, jsdict 897, tsdm_client
  4,119 and anytime 1,232, and none on xeonjia (2.19.6, which calls through CODE_REG).
  652 of tsdm_client's call the unchecked entry, `.field_0x17(` to `.field_0x18(`,
  Code+0x18 (raw_object.h:2026 at 3.11.5); every other one is `.field_0x7(` to
  `.field_0x8(`. The three reads through a Code LR loads from the thread, one on kazumi
  and two on tsdm_client, print no line. Lines calling `pool_0x....field_0x7(` go from
  520 and 520 to 0 on the fixtures and from 22,946 to 0 on the apps, and no read through
  LR takes an odd offset on any of the nine. `tools/quality.py`, `pbfuzz --census` and
  its 400 generated runs, `irfuzz --corpus`, `--cfg` and `--cfg --nested`, and `cfgcheck`
  print what they print on main. `export` changes 398 lines in 43 files of the clean
  fixture and 79 in 7 of the obf one, all that respelling, and tier 2 is byte-identical.
  CPU seconds of `lift_function`, main then this: the clean fixture's largest range,
  0xed904, 0.121 on both, best of 9; FluffyChat's, 0x750f3c, 0.232 and 0.228, best of 5;
  4,000 calls through LR in a row 0.20 on both, 20,000 reads through LR in one block
  0.15, 1,000 loops reading LR at their head 0.51, and 2,000 joins each reading LR, one
  arm loading it and the other calling, 59.0 and 58.6, which is main's cost for that
  shape and not this change's.

- **A Smi untag reads bit 31 as the sign.** `sbfx xD, xN, #1, #0x1f` is SmiUntag under
  compressed pointers, `sbfm` with immr 1 and imms kSmiBits + 1 = 31 at all eight tags
  read from 2.19.6 to 3.13.0: bits 1 to 31 of xN, sign-extended from bit 31, which is
  `xN.toSigned(32) >> 1` for every 64-bit xN. Tier 3 printed `xN >> 1`, which is that
  only where bits 31 to 63 of xN already agree, and the VM leaves them zero after a
  32-bit Smi add and after LoadCompressedSmi, and the heap base after LoadCompressed.
  `copyWith` at 0x5d10 on the clean fixture, `add w2, w5, #2; sbfx x5, x2, #1, #0x1f`,
  printed `t0 = ((x2 << 1) + 2).toUnsigned(32) >> 1;`, a large positive number where the
  machine has a negative one (#285). The value decides now, in `lift`, `decompile`,
  `export`, `ffi` and `jadart.decompile`. `>> 1` stays where the value proves bits 31 to
  63 agree, a bound under 2^31 or an int32 literal; a bound of 32 proves nothing, since
  `V.bits` is unsigned. A value a 32-bit write left is read through its low half, `t0 =
  ((x2 << 1) + 2).toSigned(32) >> 1;`, and anything else, a field load, a call result, a
  joined value or an entry register, takes the conversion too: a string's length reads
  `a0.field_0xc.field_0x8.toSigned(32) >> 1`. Two rules that read the printed text now
  know a width conversion is arithmetic: `_drop_dead_phis` took `.toSigned(` and
  `.toUnsigned(` for a call and kept a phi nothing reads, and `_READS_MEMORY` took
  `this.toSigned(` for a field of the receiver and assigned an untag of `this` in each
  arm of an `if`.

  Measured with `lift` over every range against main. Of the 3,731 untag sites on the
  clean fixture, 216 read a value a 32-bit write left, 3,507 one of unknown width and 8
  one proven to fit; 217, 3,507 and 8 of 3,732 on obf, and 5,071, 70,639 and 319 of
  76,029 on the seven app-sweep libraries. Lines with `.toUnsigned(32) >> 1` go from 216
  and 217 to 0 on the fixtures and from 1,043, 820, 550, 354, 1,286, 645 and 314 to 0 on
  FluffyChat, kazumi, labplus, jsdict, tsdm_client, anytime and xeonjia. Lines are
  counted per range over a `difflib.SequenceMatcher` alignment of this output with
  main's: in a replaced run of equal length the n-th lines pair up, a pair counts once as
  a respelling where this line respells to main's, and every other line counts on its
  own side. On clean 4,547 lines are respellings, and 4 ranges change more: a value that
  crosses the 200-character naming limit is named a step earlier and the names after it
  renumber, leaving 62 lines here and 59 of main's that are not respellings. Obf has
  4,518, and 62 and 59 in 4 ranges; the apps 92,678, and 1,234 and 1,206 in 51 ranges.
  With the naming limit lifted on both sides, every changed line in those ranges is a
  respelling. 22 more of main's lines go on the apps, in 11 ranges: dead phis main kept,
  named-argument indices bound to `((x << 1) + 2).toUnsigned(32) >> 1` that nothing
  reads, because `_drop_dead_phis` read `.toUnsigned(` as a call. On main the two rules
  misread nothing else in the nine binaries.
  `irfuzz`'s expression pass, widened locally to take `sbfx` and to read `>>` as Dart's
  arithmetic shift, over every straight-line run holding an untag: 1,967 of 2,109 runs
  disagree with the CPU on main and 0 here on clean, 1,967 of 2,111 and 0 on obf, and
  38,112 of 39,982 and 0 on the apps. `quality` counts 3 more lines on each fixture,
  the naming limit's, and as many bare-register and byte-offset lines as main does;
  `pbfuzz --census`, its 400 generated runs, `irfuzz --corpus` and `cfgcheck` print
  what they print on main. `export` of the clean fixture replaces 3,462 lines with 3,464
  in 101 of its 328 files, and its 213 `.toUnsigned(32) >> 1` lines go to 0; tier 2 is
  byte-identical. `ffi --full` changes 2 lines on tsdm_client and none on FluffyChat.

- **A run of loops no longer costs the cube of its length to lift.** Whether one block
  dominates another was a walk up `idom` from the lower one, and tier 3 asked it of every
  block each loop's header dominates, so 1,000 loops in a row (`add; cmp; b.lt` back to
  itself) took 13 s in `lift_function`, which `lift`, `decompile` and `export` all call,
  and 2,000 took 108 s: a crafted range stalled them (#282). Each dominator forest is now
  numbered once in preorder (`cfg.dom_numbers`, iterative), and a block is above another
  where its number and the end of its subtree's run bracket the other's, the check LLVM's
  `DominatorTreeBase::dominates` makes after `updateDFSNumbers`. Every question the lifter
  and the structurer answered by the walk is answered that way, including the forest
  `_trip_nodes` builds where a trap ends its path; the walk is kept for a map that is no
  forest, which `_idoms` never builds. What a loop's region writes, the header's subtree,
  is folded up the tree once rather than gathered per loop. Output is unchanged: the
  whole-binary tier 3 dump of both fixtures and of the seven app-sweep libraries, and
  `export` at tiers 3 and 2 of both fixtures, are byte-identical to main's. CPU seconds of
  `lift_function`, main then this: 125, 250, 500, 1,000 and 2,000 loops in a row 0.05,
  0.27, 1.89, 13.48 and 107.84 against 0.02, 0.04, 0.12, 0.38 and 1.29; 75, 150 and 300
  nested loops 0.10, 0.52 and 3.32 against 0.05, 0.15 and 0.51; 1,000 in a row behind a
  monomorphic entry 13.41 against 0.38; 1,000 loops each leaving by a goto into the next
  one's head, which `_join_kill` meets, 41.09 against 1.15. The clean fixture's largest
  range, `hash` at 0xed904, takes 0.119 s on both, best of 5. What is left grows about 3.4
  times per doubling, not 7 to 8: `_exit_slots` asks `_loop_nodes` for every block before
  each loop, 79% of 2,000 loops in a row under cProfile, and `_join_kill` walks back over
  the same blocks, 25% of the goto shape at 1,000.

- **A monomorphic section is lifted as the body it is, from its own entry.** #266
  placed the code a Code's monomorphic entry reaches as a section after the body, but
  lifted it inside the walk of the whole range, which starts on the miss handler and
  reaches none of it. Nothing in the section had a dominator, so the structurer found
  no loop in it and no join a dominator speaks for, and the lifter met each of its joins
  over everything that can reach it. The clean fixture's 868-byte `dyn:call` at
  0x2f5198 tested `x9 == NULL` where the same rows lifted from +8 name the value `t3`,
  and printed the loop after it as gotos whose counter no line assigned, so the printed
  loop never advanced; FluffyChat's `toLowerCase` printed three such loops. The check at
  +8 and the normal entry at +24 now each root a dominator tree of their own
  (`cfg.dominator_forest`): the body is placed first among the sections, the check is a
  guard over its miss handler with the body after it, and the analyses that ask for
  dominators, and the one that names a call's result in d0, ask from those roots. It
  starts from bare registers at +8, as before, and again at +24. A switchable call
  enters +8 with the receiver in x0 and the class id it expects in x5
  (flow_graph_compiler_arm64.cc:556-575 at 3.12.2), but +24 on is also the normal
  entry's code, which MegamorphicCallStub enters with the target Function in x0 and the
  entry address in x1 (stub_code_compiler_arm64.cc:3643-3660), so none of those, nor
  `this` or an `aN`, holds on every way in; and nothing from +24 on reads the check's
  flags, through a `cset` or a chain of lone branches, or the class id it left in x16.
  Only the shape MonomorphicCheckedEntryAOT emits is lifted so, a check that branches
  back to the miss handler and falls into a block of its own 16 bytes on: the same
  function and the same offsets, 8 and 24, in all 19 registered releases
  (assembler_arm64.cc:1941-1965 and object.h:5922-5923 at 3.12.2). A check that also
  branched into the body would dominate code the callers reach without it. The one
  flagged range of another shape, FluffyChat's `FixCallersTargetStub`, is lifted as
  before. The body is what its entries reach along the graph's edges: the code past a
  trap in it is a section like any other, so a catch entry there that jumps to a return
  prints the return again from its own state, and one that jumps on takes the REJOIN
  note, as a section after the body that jumps into it does; neither is a way in the
  body's joins meet. In a plain body the code past a trap is still part of it (#283).

  Measured with `lift` over every range against main. Clean fixture: all 78 sections
  change, 188,003 lines to 187,872; their bare-register lines go 215 to 183, of which 78
  are the miss handler's `br x16` under its guard and the other 105 are as many as the
  same rows have lifted from +8; loops 0 to 3, as from +8, and gotos 36 to 15. 67 sections
  say what the +8 lift says, the check and its miss branch aside, and the other 11 only
  lack the stack check's slow path past their throw, which the +8 lift places as a body
  does and main does not print either. Nothing else changes but 3 `var tN;` at the top of
  a body, for a name its section reads in a loop. The obf fixture is the same, 188,090 to
  187,959. Over the seven app-sweep libraries 4,004 of 4,005 sections change, 4,860,135
  lines to 4,855,275; bare-register lines 9,477 to 8,598, 4,004 of them the miss
  handler's; loops 0 to 173, as from +8, and gotos 1,718 to 801. 3,912 sections say what
  the +8 lift says and 92 only lack code past a trap, a stack check's slow path or, in 20,
  a Mint's, which main does not print either. 180 `var tN;` are added and 1 dropped at the
  top of 164 bodies, and no other line changes. No section prints `this` or an `aN`, on
  any of the nine. `export` changes 12 of the clean fixture's 328 files (850 lines out,
  728 in), 11 of obf's 312 (845, 724) and 837 of the apps' 10,232 (39,049, 35,168); tier 2
  is byte-identical on both fixtures. `tools/quality.py`, clean, main then this: 188,001
  and 187,870 lines, bare-register lines 12,768 and 12,736, byte-offset fields 53,835 and
  53,834, gotos 5,644 and 5,623 in 1,434 and 1,428 functions, labels 6,128 and 6,113,
  `(...)` and raw lines the same. `pbfuzz --census` keeps 2,082 wrong reads and 0 stale on
  both fixtures; out-of-scope names go 814 to 817, three loop latches that now see the
  slot they reload held a name, each printed as a declined read as from +8, and blocks
  holding only a declaration nothing reads 1,527 to 1,528, a phi under 0x1be718's null
  test, as from +8. `irfuzz --corpus`, the pbfuzz cases and `cfgcheck` (0 edge violations,
  0 dropped) read as on main. `export` takes as long as on main, 16 s and 17 s on the
  clean fixture and 124 s and 125 s on FluffyChat. A section costs what its rows cost
  lifted from +8, 0.007 s to 0.011 s for the one at 0x1be718: a body's loops are dominator
  work it now does, and 1,000 loops in a row behind a monomorphic entry take 13.4 s, as
  the same rows do as a plain body on main (#282). Behind a check of another shape they
  take 0.31 s, as on main.

- **A read or write through a copy of THR is at the offset as written.** x26 holds the
  Thread, an untagged address, so `ldr x9, [x26, #0x6c8]` prints `THR.field_0x6c8`.
  Through a copy it took the heap-object tag bias, because `_byte_off` asked the
  register's name: the FFI call sequence at 0x1390e8 on the clean fixture, `mov x25,
  x26; ldr x9, [x25, #0x7d0]`, printed `THR.field_0x6c8 = THR.field_0x7d1;`, one Thread
  spelled two ways in one line and the odd offset no slot. The walk already holds the
  copy as `THR` wherever it can show the register holds the thread: through a move, a
  spill and its reload, and a join every way in agrees on. A write, a call that
  clobbers the copy, a join that disagrees and a section no edge leads into each leave
  it something else, and `add x25, x26, #0x10` is `THR + 16`, not the thread. So the
  value decides now, in `lift`, `decompile`, `export`, `ffi` and `jadart.decompile`,
  and that line prints `THR.field_0x6c8 = THR.field_0x7d0;`. An element off a copy
  keeps its displacement as one off x26 does, and on arm32, which reads null, true and
  false out of r10, a copy of r10 reads them too. Only the thread follows its value:
  the null in x22 is a tagged object, a copy of FP or SP is already spelled with the
  bias the frame read itself carries, no copy of PP, the heap base or the dispatch
  table appears in the nine binaries below, and LR is copied once, by a FluffyChat
  stub keeping its return address.

  Measured with `lift` over every range against main. Lines with an odd THR offset go
  from 466 in 118 ranges to 0 on each fixture, and from 207, 278, 605, 669, 754, 729 and
  844 to 0 on xeonjia, jsdict, labplus, anytime, kazumi, tsdm_client and FluffyChat.
  Those are exactly the lines that change, each the same line with every odd THR offset
  one lower, and no other line changes. `export` changes 438 lines in 8 files of the
  clean fixture, the same substitution, and tier 2 is byte-identical. A must-analysis
  of the graph written apart from the lifter, following copies through registers and
  frame slots, with a block no edge leads into knowing only x26, proves the thread at
  every access the walk now reads as THR: 234 on each fixture, 207 to 425 on the apps.
  It proves it at 50 more, 1 on each fixture and 0 to 27 on the apps, where the walk
  declines the frame reload that brings the copy back (`var t38 = (FP - 80).field_0x1;`)
  and the access keeps the spelling of any unknown base. No access holds the thread on
  some paths only. `tools/quality.py`, `pbfuzz --census` and its 400 generated
  runs, `irfuzz --corpus` on both fixtures, `--cfg` and `--cfg --nested`, and
  `cfgcheck` print what they print on main. The largest range, 4,000 instructions,
  lifts in 0.119 s on main and here, and a crafted range that copies the thread from
  register to register through 4,000 joins in 0.59 to 0.61 s on both. Closes #273.

- **Tier 3 places the code only a second entry or a catch entry reaches.** It structured
  a range from its first instruction and placed nothing else, so a block no edge leads
  into left the output with nothing in its place: `lift` of the `dyn:-` forwarder at
  0x104 printed only the miss handler's `br x16`, and `_dispatch` at 0x7ac3c lost the
  catch entry that reports "while routing a pointer event". `lift`, `decompile`,
  `export`, `ffi` and `jadart.decompile` now place every such block after the body, as
  tier 2 has since #67, each section under the note that lists what it can be. The one
  at a Code's monomorphic entry says that instead, where the snapshot flags the code as
  having one, and that its normal entry is 24 bytes in: the same payload_info bit puts
  the entry a monomorphic call takes at the payload start plus 8 and `entry_point` at
  plus 24 (app_snapshot.cc:9625-9644 at 3.12.2, object.h:5922-5923). A catch entry is
  not named as one, since jadart does not read the ExceptionHandlers it walks past. A
  section starts from bare registers, as a block no path reaches does since #255. Where
  it runs on into a block of the body that leads nowhere, a return, a throw or a jump
  out, that block is printed again under it from its own state, so `invokeCallback`'s
  catch entry ends `return NULL;` and not in a goto to the body's `return t2;`, the
  callback's result. Where the block leads on, the goto says the names past its label
  were worked out for the body's ways in, not checked for this one. Dropping the body
  to bare registers at such a label instead changed 641 lines in 49 functions of the
  clean fixture, the static meet #237 measured and set aside. What strip_boilerplate
  cuts off on purpose stays out, a stack check's slow path and the one that boxes a
  Mint, and so does the note over a section that prints nothing, a `brk`. The code
  after a trap, which tier 3 placed with no note, now gets one.

  `tools/cfgcheck.py` counted only what the entry reaches and read 0 dropped blocks. It
  now checks tier 3's own graph too: on main 2,435 blocks with code in 858 functions no
  edge reaches and tier 3 leaves out, 2,436 on obf. 1,216 of them, in 610 functions, are
  the Mint slow path and stay out; the other 1,219 (1,220 on obf), in 258 functions, are
  placed, and it reads 0 dropped and 0 edge violations, a block printed again included.

  The changed answer, measured with `lift` over every range against main. On the clean
  fixture 184,062 lines become 188,003: 261 ranges gain 3,882 lines of sections under
  334 notes, 78 of them the monomorphic entry, one for each range the snapshot flags.
  The sections print 126 blocks of the body again and keep 49 gotos into it, each with
  its note. The bodies gain 49 labels, 6 notes and 1 declaration, and 3 lines that
  printed before change in 3 functions: an `if` no longer flipped round an arm that now
  holds a label. The obfuscated fixture is the same, to one line of sections. Over the
  seven app-sweep libraries 4,724,313 lines become 4,860,117: 6,951 ranges gain 134,857
  lines under 10,487 notes, 4,004 of them monomorphic entries, with 5,256 blocks printed
  again and 969 gotos noted; the bodies gain 641 labels, 199 notes, 100 declarations and
  3 `} else {` round an arm that now holds a label, and 4 lines that printed before
  change, 2 such flips and 2 calls folded into the next statement split from it by a
  label. `export` changes 35 of the clean fixture's 328 files, 163,083 lines to 165,915
  of which 3 are removed, and 13 of obf's 312, 16,434 to 17,724. Tier 2 is
  byte-identical on both. `tools/quality.py` on the clean fixture, main then this:
  184,060 and 188,001 lines, bare-register lines 12,353 and 12,768, offset fields
  52,626 and 53,905, `(...)` 5,139 and 5,288, gotos 5,493 and 5,644 in 1,414 and 1,434
  functions, raw lines 1,288 and 1,394, all 106 more in the sections and 78 of them the
  miss handler's `br x16` printed again; obf moves the same way. `pbfuzz` and `irfuzz
  --corpus`, `--cfg` and `--cfg --nested` do not reach the new sections: their counts
  are identical to main's. `pbfuzz --census` reads 2,072 wrong reads on main and 2,082
  here, the 10 more in the sections, 0 stale, and a note after a `throw` no longer
  counts as a statement under it, 37 on the clean fixture. Blocks holding only a
  declaration nothing reads go from 1,489 to 1,527, all in the sections. A crafted
  range of 4,000 `ret` lifts in 0.10 s, where scanning the printed lines at every
  section took 6.8 s. Closes #266.

- **`pbfuzz --census` judges a reload past `_reenter` by the way in the state came by.**
  The census keeps, per walk state, what each frame slot was filled with, and counts a
  reload the lifter declines as a wrong read when the slot held another register.
  `Lifter._reenter` hands a block a slot map of its own, its one predecessor's exit state
  or none at all, and the history stayed with the path printed above it, so past a trap
  an honest decline read as a wrong read of the register that path had stored. The
  history now follows the reset. On the clean fixture that takes 17 wrong reads away and
  judges 3 against the predecessor they came by, 2,086 to 2,072, and the same on obf.
  Reloads that name a value the slot did not hold, names out of scope included, go from
  2,853 to 2,886 under the new count, and the bound in
  `test_no_frame_slot_record_outlives_the_path_that_made_it` moves with them. The
  lifter's output does not change, only the oracle's reading of it.

- **A code symbol that ends before its instructions image is refused, not read as empty
  code.** The image states its own length in its first word, header and payload
  together (`Image::HeaderField::ImageSize`, image_snapshot.h:113 at 3.12.2), and the
  container sizes the symbol that holds it, so nothing made the one hold the other.
  Slicing the image clamps where a struct read would fail, so a short symbol was read
  as far as it went. The clean fixture with `_kDartIsolateSnapshotInstructions`'
  `st_size` set to 0 exited 0 from every command: `verify` said `Tier A 9/9, Tier B
  2/3 ... Grammar consistent.`, `functions` listed 8,193 ranges with sizes and no bytes
  behind them, `lift benchWithdraw` printed nothing and `decompile` said `no code
  (inlined / abstract / no range)`. A symbol shorter than the image says it is, or
  than its header, is now a `TruncatedSnapshot`, exit 2, that names it, and so is a
  table that places code at or past the image's end. That catches a cut inside the
  last function too, which the table alone cannot see, since it gives no sizes. The
  word equals the symbol's size on both fixtures and the seven app-sweep libraries,
  2.19.6 to 3.13.0, and `verify` prints the same line as before on all nine. A Mach-O
  symbol runs to its section's end and may hold more than the image, so only a shorter
  one is refused. `info` reads only the data symbol's header and still exits 0.
  Closes #267.

- **A header that declares any kind but kFullAOT is refused on every release, not only
  on 3.13.** Through Dart 3.12 the header's snapshot kind was held only to the range of
  the enum, so a kFull, kFullCore or kFullJIT header was read with the AOT grammar and
  passed: the clean fixture with the isolate header's kind set to 0 printed `kind kFull`
  in `info` and verified Tier A 11/11 over 66,323 checks, and so did kinds 1 and 2, the
  vm header set to any of the three, the obfuscated fixture at 9/9, and five real apps
  from 2.19.6 to 3.11.5 with the isolate header set to 0 or 2. These headers used to be
  read and are now refused with an `InputError`, exit 2, that names the kind declared
  and the one the release writes: the isolate header by all 17 commands, `info` with or
  without `--lenient`, and the vm header by `info` and `verify`, the two that read it.
  The others never read the vm header, so an edit to it alone changes nothing there,
  as before. kFullAOT is 3 at every registered tag from 2.19.0-444.2.beta to 3.12.2
  (snapshot.h:28) and 2 at 3.13.0 (snapshot.h:27), where #254 already refused the rest
  with the same message, so 3.13 reads as before. A hash no epoch holds is still held
  to the range alone under `--lenient`, since nothing says which enum numbers its kind.
  `info` and `verify`, plain and `-j`, are byte-identical to main's on both fixtures and
  on the seven real apps from 2.19.6 to 3.13.0. Closes #260.

- **A range no Function owns no longer prints its first argument as `this`.**
  `program.receiver_for` handed the lifter `{"x1": "this"}` for every range whose owner
  was not a static Function, and a range whose Code has no Function owner never is one.
  `benchCheckSecret`, a top-level function (flubench/app/lib/constructs.dart:16), is
  `benchCheckSecret(a0)` with `return a0.sel_0x0("FLUBENCH{str_literal_compare}");` on
  the clean fixture, which keeps its Function and the static bit, and on the obf one,
  which discards both, it was `sub_0x159098()` with `return this.sel_0x0(...)`: a
  receiver the function was never handed, and so a signature that listed no argument.
  x1 is now `this` only in a range whose Code a Function owns and the static bit leaves
  clear (`program.instance_function_refs`). Elsewhere it is what any other argument
  register is, `a0` where the code is a Dart function's and the body reads x1 before
  writing it (`EntryNames`, #255), and a bare register otherwise, so the obf
  `benchCheckSecret` now reads exactly as the clean one does. `receiver_for` takes the
  set as the keyword `instance_refs=`, because it replaced a positional set of the
  static functions and a caller still passing that would have inverted silently.
  `tools/semdiff.py`, which still handed `this` to every function, asks it too.

  The owners that are not a Function: on the obf fixture 6,421 ranges with no Code
  object and 185 whose owner is the Smi left for a dropped Function; on both fixtures 921
  allocation stubs (a Class), 339 and 338 type-testing stubs (a type) and 85 VM stubs
  (null). Nothing else in the snapshot says one of them takes a receiver. The dispatch
  table holds only instance methods, but AOT keeps one Code for functions whose code
  matches, and 2 of its 2,563 targets on the clean fixture are owned by a static
  closure (0x2b5900 is a `return NULL;` that static functions, constructors and closures
  share). The 78 Code objects with a monomorphic entry, which only instance code has,
  are all owned by a Function on both fixtures.

  Lines printing `this` over every range whose owner is not a Function, string literals
  not counted, against main with #255: 84 in 23 ranges on the clean fixture and 15,207
  in 3,800 on the obf one, and on the seven appsweep apps 269 in 58
  (chat.fluffy.fluffychat), 164 in 34 (com.predidit.kazumi), 108 in 27
  (dev.labplus.app), 125 in 29 (io.github.petlyh.jsdict), 188 in 37
  (kzs.th000.tsdm_client), 172 in 31 (uk.me.amugofjava.anytime) and 67 in 24
  (xyz.deepdaikon.xeonjia). All of them are 0 now. On the clean fixture and six of the
  apps every changed body is `this` turned into `x1` and nothing else, since none of
  those ranges is a Dart function's code. On the obf fixture 3,804 bodies change: 3,520
  turn `this` into `a0` and nothing else, on 13,618 lines; 234 turn it into `x1`, on
  1,224; and 50 also change shape, 5,435 lines to 5,592, because a register can go
  stale where a name cannot, so reads off x1 are written into temps first. One VM stub
  on chat.fluffy.fluffychat does the same, 31 lines to 32. `tools/quality.py` on the
  clean fixture: bare-register lines 12,289 to 12,353, every other row and the line
  total identical. On the obf one: lines 183,990 to 184,147, bare-register lines 11,929
  to 13,037, byte-offset fields 54,152 to 54,163, and `(...)`, goto, rawasm and labels
  identical.

  Nothing changes for a Function where the static bit does not calibrate, which is
  still read as every Function taking a receiver. That is the two 3.11.5 apps, where 1
  and 7 instance-kind witnesses carry bit 16, the bit both fixtures and the other five
  apps calibrate to, so no bit fits. There 13,780 of com.predidit.kazumi's 29,911 ranges
  a Function owns print `this`, 60,595 lines, and 16,108 of kzs.th000.tsdm_client's
  41,755, 67,745 lines. Bit 16 is set on the Function of 1,279 and 1,714 of those
  ranges, 5,353 and 7,720 lines, and on the seven binaries where it calibrates it means
  static. None of them is a closure, a static getter or a field initializer.
  Closes #259.

- **A data symbol that ends before its InstructionsTable is refused, not a crash.**
  `parse_instructions_table` read the table out of the data symbol's bytes at the offset
  the snapshot header gives, `roundUp(Snapshot::length(), 64)` plus
  `instructions_table_rodata_offset`, then `length` entries after it, and checked neither
  against the symbol. The clean fixture with `_kDartIsolateSnapshotData`'s `st_size` cut
  from 1,142,672 to 938,140, three bytes of the file, still parses its header, and
  `verify` and `functions` exited 3 with `unpack_from requires a buffer of at least
  938272 bytes`, the wording for a bug in jadart. The four-word preamble and the
  `length * 8` bytes of entries are now bounded against the symbol before either is
  read, and a short one is a `TruncatedSnapshot`, exit 2, that names it:
  `_kDartIsolateSnapshotData: the symbol is 938140 bytes, and its snapshot header puts
  the InstructionsTable at 938240..938272, past the symbol's end.` A Dart 3.13 library
  is named by its `_kDartSnapshotData`, and a crafted table offset or `length` that runs
  past the symbol is refused by the same two checks. `info` reads only the header and
  still exits 0.

  The bound is exact. A symbol that ends where the table does, 1,003,824 bytes on the
  clean fixture and 11,490,928 on FluffyChat (3.13.0), verifies with the same gates and
  check counts as the whole one, and the clean fixture's `functions` output is byte for
  byte the same; a byte less is refused. On the two fixtures and the seven app-sweep
  libraries, 2.19.6 to 3.13.0, the table ends 138,752 to 949,280 bytes before the
  symbol does, and all nine load as before. AOTopsy refuses the 938,140 cut with exit 1,
  `instrtable: data too short for table at offset 938240 (need 938272, have 938140)`,
  without naming the symbol. Closes #256.

- **A store pins a live read of the same slot whichever way either one spells it.**
  `Lifter._pin_mem` decides may-alias on the selector: two accesses at one offset are one
  slot whenever their bases may be one object, which the lifter cannot know. A slot has
  two spellings, though, the name a recovered map gives it and the byte offset any other
  base prints, and the rule compared the spellings, so a read through one stayed live
  across a store through the other. `InputMismatchException.` printed
  `this.field_0x1c = x2.field_0x20` after `this.offendingToken = ...`, a store to offset
  0x20 of a receiver x2 may be, and `divert` read `t7.field_0xc` after `t8.begin = ...`
  had written offset 0xc. `Lifter._covers` now spells every slot a write lands on both
  ways, by its offset and by each name the walk has printed at that offset, so the read
  is named before the store as it already was where both sides printed an offset. And a
  heap store no longer pins a read off THR or PP: those are the thread and the object
  pool, not Dart objects, and the obf fixture wrote `var t0 = THR.field_0x90;` in front
  of a constructor whose clean twin, storing through a name, did not.

  Measured against main over every range: 0 bodies change on the clean fixture and 1 on
  the obf one (that THR pin, one line fewer); 2, 1, 4, 4, 6, 5 and 6 on
  xeonjia (2.19.6), jsdict (3.3.4), labplus (3.5.4), anytime (3.6.2), kazumi and
  tsdm_client (3.11.5) and FluffyChat (3.13.0), 28 bodies in all and 18 lines more. 19
  of them name a value a same-offset store may overwrite, `pull` (the overscroll glow
  controller) and `divert` on most apps, or drop a frame slot that held one; 1,
  FluffyChat's `build`, prints one declaration nothing reads fewer; the other 8 only
  renumber, a pin whose name nothing then read. Where the store's base is an object the
  body just allocated the read could not in fact go stale, and the rule cannot see that
  for a name any more than it could for an offset. DESIGN 13.1 had measured this gap as
  one body on the clean fixture and none on the obf one; on this main it is 0 and 1, and
  the 1 is the THR pin.

- **A Dart 3.13 library is refused for its epoch by every command, not for a symbol it
  never had.** Dart 3.13 writes one snapshot where every release before it wrote a vm
  and an isolate one, and exports it as `_kDartSnapshotData` and `_kDartSnapshotText`
  (DESIGN 3). `info` reached the header through the magic scan and named the unknown
  epoch. Every other command asked the container for `_kDartIsolateSnapshotData` by
  name and answered `no symbol '_kDartIsolateSnapshotData' in this ELF. If this is a
  Flutter app, the snapshot is in libapp.so, not here`, about the libapp.so itself. On
  FluffyChat's current F-Droid build (26.1 MB, Dart 3.13.0) that was 15 of the 16
  commands; all 16 now exit 2 with the one `UnknownEpoch` text, and `export` writes
  nothing.

  `snapshot.images` says which of the two layouts a container carries, and
  `load_instructions`, `recover_program`, `walk_isolate` and `tools/build_corpus.py`
  start from it. The symbols only locate the images; the grammar still comes from the
  version hash, so a renamed symbol cannot select a parse. A library exporting both
  layouts is refused rather than read one way. `info` keys the single snapshot
  `isolate` and reports its instructions symbol as the anchor, and the Frida, IDA,
  Ghidra and radare2 scripts name the anchor the file exports instead of a constant:
  a script that resolved `_kDartIsolateSnapshotInstructions` in a 3.13 library would
  find nothing. No output byte changes on a library from 3.12 or earlier: the 15
  command outputs, a hook script and the whole `export` tree of each fixture (328 and
  312 files) compare equal to main's.

  The refusal for a file with neither layout now says what is true of it. A stripped
  libapp.so is told a snapshot starts at the offset the magic is at and that the
  symbols are what is missing; only a file with no snapshot in it is still pointed at
  libapp.so. The 3.13 epoch itself is #254. Closes #253.
- **A hand-written setter's name is no longer printed as its field's name.** The accessor
  channel added earlier in this release (#240) read every `get:` and `set:` Function
  whose body was one access off x1 or x2, and named that slot after the Function. That
  is right for an implicit accessor and wrong for a hand-written one: Dart forbids a
  field and a setter of one name in one class, so `set capacity` stores into
  `_capacity`. 56 of the 61 offsets it named on the clean fixture came from hand-written
  setters, and 263 printed lines carried one of those names: `this.capacity = x2;` inside
  `_Channel.set:capacity`, `this.ellipsis` and `this.locale` in `TextPainter` for
  `_ellipsis` and `_locale`, 269 names in all, 43 distinct (`alignment` 33,
  `textDirection` 27, `devicePixelRatio` 25). Its validation agreed 40 times out of 40,
  and all 40 were implicit accessors, so it never met a case that was wrong. The store
  rule did not ask what the base held either, so `RenderAnimatedSize.set:reverseDuration`,
  which stores into the controller it loads, named the receiver's offset 44, and the
  channel refused itself on all six real apps measured for #240 and named nothing there.
  It now reads only `kImplicitGetter` and `kImplicitSetter`, takes the offset from the
  Field the accessor's `data` points at, and checks the body against it from the entry
  convention; see Added.

  `tools/quality.py`'s byte-offset field row goes 53,296 to 53,511 on the clean fixture
  (28.8% to 28.9%), the honest number: 263 lines lose a name and one gains one
  (`_ConstantTickerModeDataListenable.value`, whose getter is more than the load), in 124
  bodies, every one a one-for-one substitution, and the allocation channel names 18 lines
  fewer because those names reached it through the field map. 262 export lines change on
  the clean fixture (261 lose a name, 1 gains one) and none on the obf one, whose
  `field` row stays 54,970; the line total, `regline`, `ellipsis`, `goto`, `rawasm` and
  `label` are identical on both, `tools/pbfuzz.py --census` reads as on main (2,086
  wrong reads, 0 stale records) and `tools/cfgcheck.py` reports 0 violations on either.
  On the six real apps the channel no longer refuses
  itself and names 6 to 12 offsets each: 13, 40, 126, 348, 495 and 668 printed lines
  gain a name (xeonjia, jsdict, labplus, anytime, kazumi, tsdm_client), mostly `Color`'s
  `r`, `g` and `b` and `Tween.end`, every one a substitution and none withdrawn. #258.

- **A displacement below the base is not a negative field offset.** A pre-indexed access
  kept the heap-object tag bias and came out as `t3.field_0x-3`, which is not a field and
  not an address a reader can use: `.field_0xN` says offset N of the object the base
  points at, and no object has one at -3. 236 lines of the clean export and 2 of the obf
  one, from 511 accesses over 60 of the 2,082 clean ranges that use one at all,
  nearly all of them `_quickCopy`'s backward copy loop at 0x1aace0 (`ldr x16, [x1, #-8]!`,
  at -2, -4, -8 and -16) plus a walk off one saved interior pointer from -64 to -176.
  `Lifter._frame_read` was written to avoid exactly this and its docstring says so, but
  nothing applied the rule to a base that is not a frame register. The other tools move
  the negative part into the base or refuse to spell it. Ghidra composes the same default
  name, `field_0x` plus hex, only past `if (ct->getSize() <= suboff || suboff < 0) throw
  LowlevelError("PTRSUB out of bounds into struct")` (`PrintC::opPtrsub`), and upstream of
  the printer `TypeStruct::isOffsetValid` answers false for a negative offset, so
  `RulePtrsubUndo` rewrites the PTRSUB back to an INT_ADD and the access prints as plain
  pointer arithmetic. Hex-Rays does this change's rewrite: a structure offset applied to a
  negative number "usually converts the whole (var-num) expression into the
  CONTAINING_RECORD macro". Binary Ninja cannot spell one, a structure member's offset
  being unsigned. So `_rebase` is `_frame_read`'s rule for every base: the displacement
  goes into the base expression and the offset stays a field offset, `(t4 - 8).field_0x1`,
  which is the same text the write-back prints on the next line. It folds the RAW
  displacement rather than the biased offset, so it is exact for a tagged and an untagged
  base alike and needs no representation bit; and the tag case does not overlap, so
  `ldur x0, [x1, #-1]` is still offset 0, the object header, `.tags`, which is 11,184 of
  the clean image's 11,695 negative displacements. Both exports lose every negative
  spelling, 236 lines to 0 and 2 to 0, and in the whole-image sweep 284 lines become 286
  on each fixture. The two added lines are #209's may-alias pin firing where it could not:
  `_pin_mem` takes the written selector with `_FIELD_LHS`, which `.field_0x-7` does not
  match, so a store below the base never froze a live read at the same offset through
  another base, and one of those reads is now named instead of re-read after the store.
  `tools/quality.py` reports the class 210 lines larger on each fixture for the same kind
  of reason, its `_FIELD_RE` cannot match a negative number either, so the byte-offset
  field symptom was understated rather than absent (clean 54,056 to 54,266, obf 54,831 to
  55,041); no other symptom moves. `pbfuzz --census` is unchanged on both fixtures, 2,086
  wrong reads and 0 stale records, and `irfuzz --corpus --runs 2001`, `--mem 15000` and
  `--cfgmem 6000` report 0 mismatches. None of those oracles can score this class:
  `corpus_cases` and `expr_cases` drop any operand containing `[`, and the memory
  generator draws only the displacements 7, 15, 23 and 31, so the gate for it is a test.
- **`tools/pbfuzz.py --cases` no longer scores a declined frame read as a disagreement.**
  The sweep reported 9 disagreements at 3,000 runs and every one of them was the harness's
  own. A spill to a frame slot is tracked in the slot map and printed as nothing, so the
  CPU runs `stur x1, [x29, #-8]` while the printed body's slot still holds the bytes the
  run started with, and the read #198 prints where a reload declines,
  `var t1 = (FP - 24).field_0x1;`, is the one line that reads one of each. Measured over
  the same corpus: 9 of the 2,429 scored runs printed a frame read and all 9 were called
  wrong, 2,411 printed none and none were. Keeping the three outcomes apart is the
  convention wherever this is done. Alive2 counts "incorrect transformations",
  "failed-to-prove transformations" and its own errors in three separate fields, and its
  `error()` adds "Couldn't prove the correctness of the transformation" without the
  unsound flag wherever an approximation reached the model, so a limit of the checker is
  never a defect of the subject. Csmith keeps its generated programs clear of the 191
  undefined and 52 unspecified behaviours of C99 rather than reading a diverging checksum
  on one as a miscompilation. `tools/irfuzz.py` draws the same line with two exception
  types and by leaving the registers a run writes unbound, so a bare one declines by
  itself. So both halves are modelled here: the spills of a register still holding the
  value the function came in with are replayed into the one memory image both sides start
  from, which leaves the declined reload SCORED rather than exempt, and everything else
  the machine wrote and the printed body printed no store for is taken from a unicorn
  write hook and read as a decline, which is where a spill of a computed value lands.
  `Declined` is a subclass of `Undecidable`, `Oracle.score` returns the four counts and
  `run` returns totals per class. Over the same 3,000 generated runs the sweep goes from
  2,429 scored, 2,420 clean and 9 disagreeing to 2,429 scored, 2,429 clean and 0
  disagreeing, the 571 unscored runs are reported as declines rather than as this
  harness's own limit, and 400 cases of the sweep are now gated so the next one of these
  cannot arrive as "10 instead of 9". At seed 9100 the same 3,000 runs go from 2,456
  scored, 2,449 clean and 7 disagreeing to 2,454 scored, 2,454 clean and 0 disagreeing:
  five of the seven are scored and agree, and the other two read a slot a later spill had
  overwritten with a value the machine computes, which no replay can anticipate, so they
  decline. No run that agreed before stopped being scored. The number moved because the
  scoring was wrong and not because the lifter changed: nothing under `jadart/` is
  touched, `tools/quality.py --json` and `jadart export` are byte-identical on both
  fixtures, and `pbfuzz --census` is unchanged at 2,086 wrong reads and 0 stale records
  on each.
- **A named field off an allocation still goes stale with the memory it reads.**
  `_READS_MEMORY` decides which tracked values an invalidation drops, and it matches the
  `field_0x` spelling plus `this.<name>`, the second alternative existing for exactly
  this reason: once a field has a name the read no longer spells `field_0x`. An
  allocation's result is a minted name, so there is no fixed spelling to match and
  `t7.<name>` is the same shape as `t7.someGetter`; which names are allocation bases is
  a fact about the body rather than about the text, so the ten invalidation sites ask
  the lifter (`Lifter._reads_mem`) and it consults that set. Without it `_pin_call`
  stopped seeing two values on the clean fixture and both were read after a call that
  could have written them. Free where nothing was allocated, which is most functions.

- **A flag-setting ALU op prints the value it wrote.** `subs x0, x1, x2` printed as arm64
  where `sub x0, x1, x2` prints `x1 - x2`, the only difference being the flag suffix, and
  the register it wrote then read as nothing: 262 raw lines on the clean fixture, 131
  `subs`, 103 `ands` and 28 `adds`. The flags and the value are two definitions of one
  instruction and only the flags were modelled. Every other tool splits them. Ghidra
  translates one instruction to a sequence of p-code operations each of which writes at
  most one varnode, so the register result is its own operation and the flag bits are
  theirs. Binary Ninja lifts the value as the ordinary definition and puts the flag IL
  beside it, only where a consumer reads it. LLVM's AArch64 `SUBSWrr` writes its GPR and
  carries `implicit-def $nzcv`, and the selector emits `$wzr = SUBSWrr` where the value
  is unused, which is what `cmp` is. So the value is taken from the plain twin
  (`_FLAG_VALUE`) and the flags stay with `_note_flags`; writing the zero register is that
  same `cmp` form written out, and `State.set` already drops it. On the clean fixture raw
  arm64 lines go 1,553 to 1,291 with `subs`, `ands` and `adds` gone from the histogram
  entirely, lines carrying a bare machine register 20,015 to 19,449, 254 lines off the
  output, and the #198 wrong-reload residual 2,089 to 2,086. The obf fixture moves by the
  same amounts.
- **A select reads the comparison the one block that reaches it left.** `_flag_cond`
  declined wherever the flags were set in another block, which was 102 of its 106 declines
  on the clean fixture, and 78 `csel` lines printed as arm64 while the same select beside
  its own `cmp` rendered exactly. The other tools keep this fact in state rather than per
  block: VEX holds the last flag-setting op and its operands in guest state (`CC_OP`,
  `CC_DEP1`, `CC_DEP2`) and computes the condition where it is READ, so it crosses an edge
  like any value; Hex-Rays makes the condition its own microinstruction over the two
  comparands; Binary Ninja resolves a flag use where the flags were set by one instruction
  that reaches it. `self._flags` already is such a thunk, so what was missing is the edge.
  It is taken only where the block has ONE predecessor, the one case with nothing to meet,
  and the values are re-read from the arriving state rather than carried as the text the
  predecessor captured, since that text can name a temp declared in a block `structure`
  printed elsewhere (#237). A comparison that overwrote an operand it compared is declined
  instead of re-read, because only the captured text has the old value there (#116). Three
  more selects render, raw arm64 1,291 to 1,288, and the census does not move. The ceiling
  is in the measurement rather than in an argument: of the 99 that still decline, 48 are
  joins, whose two ways in would have to agree before anything could be spelled, 13 had
  their comparison dropped before the edge and 4 are blocks nothing reaches.
- **The generated corpus can draw a flag-setting ALU op.** No gate in this repo could
  see the value above. One of those ops sits next to the branch that reads it, and a
  branch ends a straight-line run, so `tools/irfuzz.py`'s `expr_cases` draws 5 runs
  containing one out of 6,623 over the whole clean fixture and the default sweep reaches
  none of them, which is the shape #235 calls the real defect. The four register forms
  and two immediate forms are drawn now under `--flags`, in a pool of their own and as a
  pass of its own in the standard sweep, because every named case in the suite is a
  (seed, index) coordinate into a generator stream and widening the shared pool would
  move all of them (#230). On the generated graphs the oracle goes from 300 register
  results run against a CPU to 17,800, and from 127,350 printed expressions to 246,750,
  with no disagreement on any seed. `bic` and `bics` join the value-preserving set with
  them, since `xN & ~xM` is the operation exactly and leaving `bic` out would say the
  suffix mattered to the arithmetic.
- **A loop falls out to a block some run can enter.** A natural loop is the header plus
  the blocks it DOMINATES that reach a latch without passing the header, and `loop_nodes`
  asked the dominance half of its latches and only the reaching half of the body. A block
  no path from the entry reaches is dominated by nothing, so it answers the reaching half
  and no more: the backward walk took one in, `loop_exit` counted its edge out of the node
  set as a vote for where the loop goes, and with the votes tied the lowest address won,
  so the structurer printed a block no run enters as the one the loop falls out to, and
  the state the code after the loop is spelled from carried that block's writes. LLVM says
  the same from the other end, that for a block the entry cannot reach the concept of a
  loop is undefined, since dominance is. Hex-Rays
  (`mba_t::remove_empty_and_unreachable_blocks`) and Ghidra (its "Eliminate unreachable
  code" option, on by default) get there by deleting the block, which this does not do,
  because a catch entry is such a block and the CFG does not model the exception edge
  (#57, #234). 980 of the clean fixture's 1,154 loops held one, in 621 ranges, and not one
  of them picked a different exit, so no line of either fixture moves and the clean export
  is byte-identical. `tools/irfuzz.py --cfg --nested` finds the ones that do, 2 in about
  36,000 generated graphs, where the exit state claimed `x2 = x9 + 27` and `x2 = x14 *
  x12` for a register the CPU leaves at the value it was called with. Where the pick does
  change, Tier 3 prints less: 6 of 4,000 generated graphs place 20 instructions fewer, all
  of them in blocks nothing reaches, which Tier 3 does not place at all
  (`structure(..., orphans=False)`) and only printed here because the bogus exit put them
  after the loop with no label and no note. Tier 2 asks for the orphans and still places
  every one of them: 0 of the same 4,000 graphs place fewer with `orphans=True`. The
  lifter's `_back_loop` keeps such a predecessor deliberately, because there the question
  is what the loop MAY write and a handler with no edge in has to count; where the loop
  GOES is a claim, and the two now differ on purpose.
- **A section nothing reaches hands no state to a block that has another way in.**
  `structure` places a block no edge leads into, and the code after a trap or a call that
  cannot return, as its own labelled section, for the same reason: an exception edge may
  reach it. The section FALLS THROUGH into whatever the tree put below it, and `_reenter`
  stated the rule for a section that does not fall through only, so where the block below
  had other ways in it read what the section wrote on a path none of them takes. That is
  what a goto-join's own meet (`_join_kill`) exists to prevent, and it could not see this
  one: the narrowing it makes from the join's dominator cannot hold a block the entry does
  not reach. The guard is `_reenter` itself, asked on arrival.

  It asks TWO things, and the first attempt asked only one. A region nothing reaches is
  still a region, so a join inside one, every way into which is inside it too, has nothing
  to meet with: asking only where the state came from wiped such a join in `resolve`
  (`.text+0x1753f0`) on both fixtures, where both paths carry `x9 + 27` and the store
  printed it, and left `x8.field_0x1 = x2;`, a bare register no line of that body binds,
  for a value the output had. Every firing the naive version had on either fixture was
  that case. So the guard also asks for a predecessor the entry CAN reach, the one way in
  the arriving state cannot speak for, and then it fires nowhere on either fixture and
  nowhere in 8,000 generated graphs: no `tools/quality.py` symptom moves, the clean export
  is byte-identical, and `pbfuzz --census` is unchanged. The shape is neither fixture's
  and the generator does not draw it, so the gate for it is a test, which fails both
  without the guard and with the naive one.

  And `_reenter` hands the state to the block it is entering now. It replaced the register
  map and left `State.src` naming the block it had just disowned, which was enough while
  it only ran where nothing fell through and the block was lifted straight after it; read
  on a live arrival, the stale source fired the guard a second time inside `_render_loop`,
  after the loop had bound its carried registers to names, and that reset took the names
  with it. A counter's declaration and both of its write-backs left a loop, so the printed
  loop could not advance and the `sub x7, x7, #1` that drives it was nowhere in the body:
  a wrong answer rather than a vague one. The call site also makes the same `carried`
  exclusion the meet four lines below it makes, for the reason stated there, and hands
  `_join_write` the edge the walk arrived by, since a goto-join's phi record is about the
  EDGE and not the values: taking it from a state the guard has just replaced left
  `_join_wrote` short of a predecessor, so no join could bind its name on every way in and
  the register read bare there, which is #123 by another road.

  Widening the meet instead, so that a join forgets whatever an unreachable ancestor
  writes whichever way the walk came in, costs 1,488 bare-register lines on the clean
  fixture and 1,643 on obf and fixes nothing this does not. Closes #237.
- **A release build names its runtime stubs.** Every stub-aware rule in the lifter keys
  off an `_iso_stub_<Base>Stub` name: `_classify_stub` decides whether a `bl` is a
  throw, an allocation or machinery to drop, `_noreturn` whether a path ends there, and
  `_pin_call` whether the call gives every register back. A default `flutter build apk
  --release` gives it none, because a stub's `Code` is owned by no `Function` and the
  .so carries no symbol table, so both fixtures carried 0 stub names and the whole
  taxonomy was dead code on the build a user actually has. 16,438 of the clean image's
  34,979 direct call sites (47.0%) are calls to a stub, and six of those targets end in
  `blr x30; brk #0` and cannot return, yet printed as `sub_0x2d5d00(...)`, an ordinary
  Dart call that does. The name now comes from the snapshot's own object-store roots,
  where the isolate's `ObjectStore` fields are serialised in declaration order and the
  tail of that run is the stubs: 76 named on each fixture, from a table
  `tools/gen_objstore.py` expands out of each release's `object_store.h` (ten distinct
  root runs over the eighteen registered epochs). The table is checked against the
  binary on every parse, all 244 of 244 roots agreeing on the fixtures about which are
  `Code`, and nothing is named when they do not: naming a stub after its neighbour would
  be worse than leaving it `sub_0x...`. Tier 3 output changes on every build. On the
  clean image, `(...)` calls go from 9,196 to 5,139, lines from 188,930 to 184,380,
  byte-offset fields from 55,572 to 55,181, bare-register lines from 20,460 to 20,618,
  and `sub_0x2d5d00(...)` now prints as `throw NullCastError();`. The obf fixture moves
  by the same amounts. Tiers 1 and 2 gain the name in their listings, 1,126 lines of the
  clean disasm sample and 1,198 of the obf one, each a `bl` that gained a `; ->
  _iso_stub_...Stub` note and nothing else. `jadart functions` gains a fifth name
  origin, `roots`, kept apart from `snapshot`, `symtab` and `signature` because it is a
  position read out of this binary interpreted through a per-release table; under it the
  stack-overflow stub is the most-called range in the clean image, 5,093 callers. Half
  of #234; the entry below is the other half, and the two go together because a call
  that cannot return is only visible as one once the stub is named.
- **A stub that hands a value back is a call, not machinery to drop.** `_classify_stub`
  grouped the stubs that return a value in x0 (`InitLate*`, `Await`, `InitAsync`,
  `CloneContext`) with the stack-check, write-barrier and type-test stubs, which give
  every register back and are dropped. Dropping a call that returns something left the
  stale x0 standing in for the value: a lazy-init getter whose `if` arm called
  `InitLateFinalInstanceField` came out as `return x0;`, a whole body replaced by a bare
  register, thirteen times on the clean fixture once stub naming started working. They
  render as the calls they are now, `var t0 = InitLateFinalInstanceField(...);`, which
  is what `_rv_call` already assumed about them (#127). This was reachable before this
  change on a dwarf build with a symbol table, where the stubs were named.
- **A call that cannot return no longer falls through.** `build_cfg` ended a block at a
  terminator, at a trap mnemonic (#57) or at an address `exits` named, and a `bl` is
  none of those, so a call to a stub that throws kept its fall-through edge and the
  structurer rendered a path the machine never takes. `FocusTraversalPolicy.next` is the
  shape: three one-instruction blocks, each a `bl` to the null-cast-error stub, where
  the last printed `throw NullCastError(); goto L_0x12c928;`, a jump out of a throw, and
  the two `if`s above it lost their else arms to the edge. The same edge fed joins, so a
  phi met a value from a path that never arrives: 1,224 statements on the clean fixture
  printed under a `throw`. The lift now hands `build_cfg` the addresses nothing runs
  past (`expr._path_ends`) and those blocks end with no successor, as a trap's does; a
  block that ends a path also reports that it does not fall through, so an `if` arm that
  throws contributes nothing to the join. The code that was reached only through the old
  edge is still placed, as its own labelled section, the way the code after a trap is:
  angr drops such blocks after removing the edge, and Ghidra and Hex-Rays eliminate
  them, which is why both document a callee wrongly marked as non-returning hiding real
  source. Measured instead of argued: over the 16,382 ranges of the two fixtures not one
  instruction the structurer placed before stopped being placed, and `cfgcheck` reports
  0 edge violations and 0 dropped blocks on both. On the clean image this takes
  statements under a `throw` to 0, `goto`s from 6,830 to 5,493 and the functions
  emitting one from 1,649 to 1,414 (20.1% to 17.3%), lines with a bare machine register
  from 20,460 to 20,015, byte-offset fields from 55,572 to 54,069, and 3,451 lines off
  the output; the obf fixture moves by the same amounts. Tier 2 is untouched, and its
  export of the clean fixture is byte-identical. `tools/pbfuzz.py`'s census gains a
  `dead` counter for a statement under a `throw`, which has to be 0. Closes #234.
- **A spill name can be hoisted, so nothing reads a declaration that has closed.**
  `State.set` mints a name when a value is too long to inline, and it was the one
  minting site outside `Lifter._mint`, which #204 moved the other thirteen into so that
  a declaration could be lifted to the top of the body and the assignment left where the
  value is. A name the hoist does not know about cannot be moved, so a spill declared
  inside an `if` arm and read after the arm closed had no way to be fixed: five such
  reads shipped on the clean fixture, the residual #205 left. Those names are shared
  with the lifter now, and the count is 0. One read remains of a name no line binds at
  all, in one range of each fixture, where a walk the lifter discarded minted it and the
  walk that shipped did not; `_lift_function` declares it at the top, which everywhere
  else in that file means a value the lifter does not know.
- **A 32-bit destination says it cleared the top half.** arm64 writes the w view of a
  register by clearing its top 32 bits, and `canon()` folds the w view onto the x view,
  so the lifter printed the same text for a 32-bit result as for a 64-bit one and the
  top half it kept was a value the machine does not have. DESIGN section 13 listed the
  fold as one of three latent correctness issues, 59,073 sites; 3,727 of the clean
  fixture's 457,622 instructions compute into a w register. A 32-bit result now prints
  `.toUnsigned(32)`, which pairs with the `.toSigned(32)` an `asr` on a w register
  already printed, and that spelling says the register's width rather than a mask the
  program asked for. Two rules keep it off the rest of the output: reading the w view of
  a register takes the low 32 bits, so a consumer is handed the value as it was before
  the truncation and truncates its own result instead, which leaves one
  `.toUnsigned(32)` at the end of a chain of 32-bit operations rather than one on every
  step; and a conservative bound on each value (`V.bits`) leaves alone a result that
  provably has no bit above 31, a mask that small, a literal, a 32-bit shift right, or a
  sum of two bytes. 638 truncations reach the clean export, and not one
  `tools/quality.py` symptom moves on either fixture: the same 185,479 lines, 20,015
  bare-register lines and 54,069 byte-offset fields.
  `tools/irfuzz.py` no longer excludes w operands, which is what puts the class under a
  gate at all, and its evaluator understands both conversions: without them 3,500 of the
  clean fixture's printed expressions decline instead of being checked and nothing is
  reported, where it now checks 255,731 of them against 250,770 on main and finds no
  disagreement with the CPU in 2,002 runs on either fixture, where main has 32 and 30.
  Closes #235.

## 1.3.0 - 2026-10-29

Upgrading from 1.2.0. The command set, the options and `--json`'s `format_version` are
unchanged, and the JSON shape only gains fields, but some values a script may hold on to
are different now:

- Every name and every literal prints ESCAPED. A function, class, field or library name,
  an ELF symbol, a `--sigs` name and a string literal spell a C1 control, a format or bidi
  character, a zero width space and a character past the BMP as `\xNN`, `\uNNNN` or
  `\UNNNNNNNN`, and a `"` inside a quoted literal as `\"`. `strings -g`, `libraries -g`
  and `xrefs string` read a pattern as typed or as printed, so either spelling matches.
- A name longer than 200 characters as printed ends in `\... (N chars)`, N its real
  length, everywhere it prints, `jadart.program()` included. `symbols -j` cuts `name`,
  `owner` and `library` and says so in a `cut` dict, `qualified` stays whole, and
  `strings.txt` still prints each string once and whole. A name past 200 characters is not
  signable.
- `constants` quotes a list's string elements, where it printed them bare and
  comma-joined, and a slot reaching a list it has already printed says `same as 0x...`,
  `same_as` in `--json`.
- `export` writes nothing over anything. A library or asset whose path another took
  already, which obfuscation and a case-insensitive filesystem make ordinary, gets a `~N`
  before its extension: on a Mac the obfuscated fixture's export listed 307 libraries and
  held 208, and holds 307 now. A failure names the side it came from, the archive or the
  output directory.
- Three exits moved off 3, which means a bug in jadart. `signatures -o` into a missing
  directory, a directory it may not write or a path under a file raises `InputError`,
  exit 2, naming the path; an `export` path collision is resolved rather than fatal; and
  a function nested too deeply to structure prints its instructions under a comment where
  `export -t 2`, `decompile` and `lift` raised RecursionError.
- Three inputs are refused where they were parsed, each an exit 2. A features string past
  4096 bytes, a stripped binary whose snapshot magic is at three or more file offsets,
  since a library holds two, and an ELF or Mach-O whose name and table reads come to more
  than the file holds, a `ContainerError`.
- `xrefs` reports the matching entries no code loads directly again, as a count in the
  text output and under `"unloaded"` in `-j`, where 1.2.0 dropped them without a word. A
  pattern only such entries match lists them, says so and exits 0 as 1.1.0 did, and its
  `-j` is `"ok": true` with `"count": 0` where 1.2.0 gave `"ok": false`. `--class` is
  unchanged and reports no `"unloaded"`.
- A branch into the part of a function the 4,000-instruction cut left out prints a
  `goto` to that address with a comment saying it is past the cut, where it printed
  `goto sub_0x..`, which names another function.
- The decompiled body reads differently nearly everywhere, which is most of this release.
  New spellings a script may meet: `.field1_0x8` and `.field2_0x8` for a one or two byte
  access and `.field16_0x8` for a sixteen byte one, `(FP - 32).field_0x1` for a frame read
  the walk cannot answer, `tN` names for a loop-carried or join value, `// xN holds ...`
  on a raw line, `.toSigned(n)` for a bit field, and `(...)` where a call's arguments are
  not reconstructed. Tier 2 and tier 3 text is a reading of the code, not a stable format.

### Added

- **`tools/pbfuzz.py --census`, a gate for #196's class that needs no emulator.** A reload
  that spells a register the slot did not hold, and a record spelled on a path that
  superseded it, are both properties of the printed body and the instruction list, so this
  runs wherever capstone does, which is every pull request. That matters because nothing
  automated looked at this class before, in either direction: `irfuzz` generates no
  x29-relative frame slot, and `pbfuzz`'s fuzzing half scores any store resting on a
  written register as undecidable. #197 shipped 2,023 stale spellings past four green CI
  jobs, a clean suite and five CPU-verified shapes.

  It reads every range of a real image (`image.all_ranges`, 8,194 on the clean fixture and
  8,188 on the obf one, not the 6,849 and 238 that `fr.functions` gives), forks its
  bookkeeping where the lifter forks `State`, and scores only the last walk of each range
  because `lift_function` walks up to three times. Five earlier measurements of this class
  were wrong for want of one of those, so the census carries them rather than a scratch
  script. On `4623d71`: 8,606 records spelled, 0 stale, and 3,427 reads that name a
  different value than the slot held, of which 2,608 are ACTIONABLE (the slot held a
  register or an expression that was still available) and 819 are names out of their
  declaration's scope, which cannot be spelled at all.

  That split is the point rather than bookkeeping. Naming a spill earlier moves reads from
  the first number into the second without the reader gaining anything, so the test
  asserts
  both: the stale count is zero, which has no acceptable non-zero value; the actionable
  count has not risen above 2,608; and the total has not risen above 3,427. It then puts
  #197's bug back, both halves of it, and checks the census still reports it: a fill that
  no longer supersedes gives 20, records shared across arms give 561.

- **`tools/pbfuzz.py`, a differential oracle for the printed body where a register write
  is printed.** The existing oracles could not reach that case: `irfuzz._exec_one` raises
  on a line printed raw, so the case is dropped, and `irfuzz._mem_expr` maps
  `x20.field_0xN` to a fixed slot key, so a `_bump` that advances the base still reads the
  old slot. Those two are how the printed body assigns a register, and a printed register
  write is the precondition for the staleness #187 was opened for, so that class had never
  been measured. The new oracle generates straight-line runs mixing self-referential
  writes, write-back bases, raw lines and spill/reload round trips through an x29 frame
  slot, then interprets the printed body against a real CPU: a raw line is executed on the
  CPU against the body's own state with its `// x1 holds x1 + 8` note bound first, and
  memory is a real array, so a moved base reads where it now points. A store is scored
  only where every register in its text is an argument the run never writes or one the
  printed body has already assigned, because a bare register can be the lifter declining
  and FINDINGS.md records that the two are not distinguishable from the output. Clean:
  8,000 runs, 7,998 scored, 0 disagreements over seeds 1 to 16 and 12 environments each.
  Teeth over seeds 1 to 8 of the same set: `_pin` returning nothing makes 653 of 3,998
  scored runs disagree, where main has 0 of 4,000. Needs unicorn, as `irfuzz` does, and is
  not part of `check.sh`.


### Changed

- **The self-referential half of #187 is measured, and it is not a defect.** A register
  in the output means the value the function came in with until a printed statement
  assigns it, which is what `_verbatim`, `_phi_name`, the `_bump` invariant test and
  `tools/irfuzz.py` all take it to mean. A self-referential write prints no assignment, so
  `add x4, x4, #1` followed by a store prints `x4 + 1`, which is what the machine stored.
  The guard that keeps `x4 + 214 - x4` from being named apart is therefore a spelling
  choice, worth the declaration it does not mint, not a correctness guard. No output byte
  changes: this replaces a claim, not the renderer.
  `test_a_self_referential_write_keeps_the_spelling_that_cancels` said each named-first
  spelling was "correct in none" of 200 environments; that was scored by reading a bare
  register as the machine's current value rather than the printed body's, so it did not
  support the claim and is withdrawn. The assertions stand as spelling pins and
  `test_a_self_referential_write_is_right_under_printed_body_semantics` carries the
  measurement.

- **Declarations nothing reads, bound by a phi, are dropped.** `_phi` and `_render_loop`
  bind a name at a join or a loop header whenever the paths disagree about a register,
  before the body is printed and so before it is known whether the result is read. Where
  nothing reads it, the declaration and the writes to it on each arm say nothing, and a
  loop that carried six argument registers for a call that then declined to `(...)` left
  a dozen such lines. They are now dropped, together, declaration and every assignment;
  a phi stays whole where dropping it would leave an if-arm or a loop body holding
  nothing else (the one line that says the arm ran, as a dead slot name is kept), and
  where an assignment makes a call, the call being a side effect. Dropping a dead name
  can leave the value it was copied from read once, which then folds into its use, so a
  few lines read tighter too (`var t = this.field_0xc; ... t.field_0xc` becomes
  `this.field_0xc.field_0xc`). Tier 3 exports lose dead lines in 340 functions on the
  clean fixture, 223 on 2.19.6, 334 on 3.4.4 and 343 on 3.10.9, and none on obf; every
  change is a line removal or that fold, no live value moves, and no block is left
  empty. Closes #169.


### Fixed

- **A loop asked what every ANCESTOR of its header writes, and forgot the answer.**
  `_loop_nodes` closes backward over the header's predecessors without stopping at the
  header, so it returns every ancestor of it: on the clean fixture, 20,211 blocks across
  the 833 loops it is asked about where the natural body is 8,975, and 9,781 of the extra
  ones run BEFORE the loop. #129 called the inflation conservative. It is not: what the
  loop WRITES decides what is forgotten after it, a forgotten register prints as its own
  bare name, and a bare name reads as the value the function came in with, so a register
  the loop never touched came out holding the entry value where the machine has what the
  line before the loop computed. That is #206's class, reached by counting a pre-loop
  write as the loop's. The three questions asked of that set, what the loop writes, what
  it carries, and whether a break leaves it, now ask the natural body off the back edges,
  which is also what the field means by a loop: LLVM's is the maximal strongly connected
  set whose every entering edge reaches the header, and Ghidra's `LoopBody` marks the same
  one by Tarjan's method. 723 statements that ended in a bare register are gone, 8,872
  lines change on each fixture and the image is 394 shorter, `regline` falls 26,432 to
  26,365 and quality's bare-register lines 20,540 to 20,460, `sole` 1,398 to 1,397, and
  every census counter that must be zero is. The two things a trip can make stale are now
  written out above the loop, which the inflation was doing by accident through the
  carried name: a value whose text names a register the loop writes, and one that reads
  memory a trip stores to. That is `_pin` and `_pin_mem`'s argument at the region, asked
  over `_trip_body` so that a stack check's slow path, which gives back every register it
  is handed, pins nothing (#228).

- **The memory oracle drew its corpus from the lifter it was testing.** `--cfgmem` took
  the programs it generates and the per-trial register seeds from one `random.Random`, and
  how many trials a case runs is decided by the lifter, which breaks out of them on a
  mismatch and on an undecidable text. An ablation INSIDE the lifter therefore changed
  which programs came after it: 407 joins and 26 gotos clean against 414 and 30 with the
  heap meet switched off, over the same 400 graphs at the same seed. Two trees could not
  be compared on the result, and the two ablation gates that hang on a single case in
  hundreds read as blind the moment anything moved. The trials now draw from a generator
  of their own, as `run_cfg`'s have always done, and `run_mem` with them. With the corpus
  holding still, a gate can name the ONE case it is about rather than a count and a seed:
  the heap-meet gate asks case 135 of seed 1 and the loop write-back gate case 1048 of
  seed 7, both of them checked for being interpreted at all so that a case gone
  undecidable fails loudly instead of passing as a clean run (#230).

- **A store through a base the loop wrote names it unknown.** After the loop the machine
  holds what the last trip put in that register, while the register's own name says the
  value the function came in with, so the store wrote a field of the wrong object. It now
  goes through a name with no initialiser, which is #206's rule at the other map and
  #216's at the other end of the same argument. 39 stores on each fixture, 274 lines
  changed, and every census counter holds, `sole` at 1,398 and `wrong` at 2,579 among
  them. Two cases are deliberately not this and the test holds them: a register only a
  CALL inside the loop clobbered, which is #216's class and whose inclusion renames the
  base of every store after a loop that calls, and a register written BEFORE the loop,
  which holds what that line put there. The second needs the marking to ask the blocks the
  header dominates rather than `_loop_nodes`, which returns every ancestor of the header
  and so counts pre-loop writes as the loop's; that set is added for this one reader
  rather than changing what `written` and `carried` are computed over, which is #228
  (#208).

- **An access narrower than a word says how many bytes it moved.** A byte-offset spelling
  said nothing about the width, so `strb w0` printed the same text as `str x0` and a
  reader could not tell a byte store from a word store: the store side overstated and the
  load side understated. One and two bytes now say so, `.field1_0x8` and `.field2_0x8`, on
  both sides, and a sign-extending load carries the shift pair that says the sign, which
  the width alone does not; the ordinary load path printed neither before, so `ldrsb x0`
  read as the whole eight bytes unextended. FOUR keeps the plain spelling, because this
  target compresses pointers: 17,789 of the 20,941 four-byte loads on the clean build are
  followed by `add xN, xN, x28, lsl #32`, the decompression, so a four-byte read is what a
  reference field read looks like and the lifter prints the pointer it becomes. Marking
  those would decorate the most common read in the output with the width of a
  representation rather than of a value. In `_name_blind` the unsigned mask goes, since
  the spelling now says the width and `((FP - 8).field_0x1 & 0xffff)` said it twice.
  `_covers` gained the narrow spellings, so a write of one width still pins a live read of
  the same bytes under another: 96 four-byte stores on the clean build pin something, and
  without that they would stop. 491 lines change on the clean fixture, 10 more in all, and
  every census counter holds (#221).

- **A store through a base the join lost names it unknown.** The two arms left different
  values in the register, so `x2.field_0xc = x1;` claimed the object the function came in
  with while the machine has one of the two others, and the store wrote a field of the
  wrong object. It now goes through a name with no initialiser, `var tN;`, which says the
  lifter does not know what this points at: #206's rule at the other map, and #216's at
  the other end of the same argument, that a fallback must not borrow a name that already
  means something. 17 stores in 11 ranges of each fixture, `regline` 26,431 to 26,411, and
  every other census counter unchanged, `sole` at 1,398 among them. The issue's own
  measurement is 147 such stores over all 8,194 ranges; the other 130 come from a loop
  exit, where naming them costs 152 more blocks holding nothing but a declaration nothing
  reads and contradicts thirteen loop-reload expectations, so that half is measured and
  written up on the issue rather than shipped (#208).

- **A break out of two loops makes both of them carry the register.** `_render_loop`
  records an exit hazard for a register a break leaves holding something other than its
  own name, and `_lift_function` walks again with that register carried so the break names
  what it holds. Recorded against the innermost loop only, a break that leaves TWO loops
  named the register at the inner one and the outer one had still forgotten it, so the
  code after both read it bare, the name had no reader, and the walk dropped the carry and
  ran again without it: the second walk's fix came undone by the third. The hazard now
  goes to every loop the break leaves, which are the frames still on `_carrying` when the
  inner loop's own has been popped. On #176's own shape the store after both loops read a
  bare `x7` whose last write on one way in was an instruction the lifter models and does
  not print, so it read as the value the function came in with; it now reads a name bound
  to that write before the loops and assigned from x7 on each way out. No line of either
  fixture changes, the shape is not in them, and the test is the issue's listing (#176).

- **A goto backwards out of a loop leaves it.** `_loop_nodes` closes backward over every
  predecessor of the loop header, so it returns every ANCESTOR of the header: on the clean
  fixture that put blocks which run before the loop into all 6,131 of its loops, 70,789
  such blocks. Asked whether a goto leaves the loop, it answered no for a jump back to one
  of those, so the loop's carried names were not written back and the target read them
  holding what the previous trip left, which is the hazard #123 is about at the other kind
  of edge. 46 gotos on each fixture answered this wrongly, and the question now goes to
  `_back_loop`, the natural body, which was written for this issue and already had the
  dominance test. Six of 8,194 ranges change, 31 lines more on each fixture, 8 more
  carrying a bare register; the reads at those targets now name the value the goto left
  rather than one the loop had moved on from. `_loop_nodes` is unchanged where it is asked
  what the loop may WRITE, which wants an over-approximation, and where the blocks before
  the loop stand in for the ones between a store and the loop (#140); replacing it there
  was attempted again today and still fails `--cfgmem`, with the reason recorded on the
  issue. Every census counter holds, `undecl` 0 and `oos` 5, and 80 `--cfgmem` runs over
  40 seeds in both modes are clean, seed 9 among them, which is the seed that caught the
  previous attempt (#129).

- **Every name the body reads is bound somewhere in it.** `parsePartialNumber` read four
  names that no line declared or assigned anywhere in its 181 lines, six reads in all, so
  the output was not valid Dart and a reader had nothing to go on, which is worse than a
  name merely out of scope. A loop binds every carried register to a name and, once the
  body is walked, collapses the ones the body never assigned, substituting the entry value
  back through the body and the tail; a goto out of the loop is handed the state from
  INSIDE it, which still holds the name, and no substitution reaches that target's lines.
  `_carry_out` now counts such a register as escaped, the same way it counts one an exit
  writes back, so the loop keeps the name and the declaration stays. Only where the target
  has a single predecessor, since a join reads the register bare and a name kept for one
  of those would be a tautology. And loop-carried names are hoistable now, like every
  other name a join binds: #204 did that for `_mint` and left this site out, which is why
  its reads were counted and not fixed. Four undeclared names on each fixture to 0, and
  reads of a name whose declaration has closed from 28 in 11 ranges to 5 in 5.
  `pbfuzz.census` counts the first as `undecl` and the gate holds it at exactly zero: it
  is the one invariant here that is not a budget. 79 more lines on each fixture, 18 fewer
  carrying a bare register, and every other census counter unchanged (#205).

- **An access of sixteen bytes says so.** `.field_0x8` is eight bytes, and sixteen had no
  spelling at all, so `ldr q0` printed the eight-byte read of its low half and `str q0` an
  eight-byte write: a 16-byte copy came out character for character identical to an 8-byte
  one and named half the bytes it moved. 195 printed assignments on each fixture move
  sixteen bytes, 42 of them naming a bare q register, which the printed body never assigns
  and so reads as the value the function came in with. They now read and write
  `.field16_0x8`, a declined 16-byte reload names the read like any other, and all 198 of
  them carry a value. The width goes in the spelling because this output has no types to
  put it in: Ghidra gives a 128-bit register the type `undefined1 [16]` and slices it
  `._0_8_`, offset then size, and Hex-Rays gives it `_OWORD`, a type whose only known
  property is that it is sixteen bytes. Neither leaves the width unsaid. The bytes one
  write covers now have more than one spelling and no two of them contain each other, so
  `_pin_mem` matches every spelling of them (`_covers`); without that, three shapes in the
  new test read memory the write had already changed, and one of them, an eight-byte write
  to the top half of a live 16-byte read, is a staleness main could not represent at all.
  A narrower access through the floating-point file still declines rather than claim a
  width it cannot spell, and a narrower one in the general file is still the eight-byte
  read masked or extended. 0.65% more output, 1,223 lines on each fixture, almost all of
  it joins that now say which path a value came from instead of leaving a bare register to
  stand for both. Every census invariant unchanged: `wrong` 2,579, `name` 836, `oos` 28,
  `sole` 1,398, `empty`/`stale`/`unbalanced`/`twice`/`above` 0. A changed answer: every
  16-byte access, and the Smi note no longer offered for a write wider than a field
  (#209).

- **The low doubleword lane of a V register reads what dN holds.** `v0.d[0]` is the low 64
  bits of the register `d0` names, and the two were keyed apart, so the read found nothing
  under its own spelling and fell back to the bare operand. The printed body never assigns
  that, so it read as the value the function came in with: the isInfinite test Dart emits
  after a call that returns a double printed `if ((v0.d[0] & 0x7fffffffffffffff) !=
  0x7ff0000000000000)`, naming the entry v0 where the machine reads the double the call
  had just returned. 31 lines on each fixture, and every lane operand in both images is
  this one spelling, all 62 of them reads. Folded in `canon`, the one place, so a write to
  the lane lands on d0 too, which is what it overwrites (#134). `regline` 26,257 to 26,235
  on the clean build and 26,244 to 26,222 on the obfuscated one, one line shorter on each,
  and every other census counter unchanged. The same fold fixes the write side, which
  neither fixture holds: `mov v0.d[0], x3`, capstone's spelling for an insert into the low
  lane, wrote a key nothing reads and left d0 reading as the entry value with no printed
  assignment at all; `ins` and `fmov` of a lane print the instruction instead, and a raw
  line is itself a printed assignment (#187), so those were already consistent. A changed
  answer: those 31 lines per fixture.
  The 24 lines per fixture that still carry a bare q or v register are the other half of
  #209, a 16-byte value with no spelling, and are untouched (#209).

- **A frame read off SP says where it is in the frame the function was entered with.**
  `SP` in a read's text means SP AT that line, and the pushes and pops that move it print
  nothing, so `var t1 = SP.field_0x1; var t2 = SP.field_0x1;` stood for two addresses
  sixteen bytes apart and nothing in the output said SP had moved. The reads through FP
  were already rewritten into the coordinates of the frame FP started in (#165); this is
  the half that was left. `_frame_plan` now records SP's place in that frame at every
  access through it, and a declined reload spells its address against that place wherever
  it is known exactly, so one address has one spelling whatever SP does since. The place
  is recorded as the addressing mode sees it, BEFORE any write-back, because a
  post-indexed `ldp` reads sixteen bytes below where it leaves SP, which is the shape the
  issue opened with. Measured the same on both fixtures: 1,021 of 1,559 reads off SP
  anchor, and of 641 reads in 71 ranges whose text stood for more than one address, 574
  now say which. The 538 that decline are not a skipped analysis: the pass never places SP
  in its frame at all there, and running it in every function that READS through SP rather
  than only where something is stored through it anchors 0 more. A function with no
  prologue has nothing to anchor to, FP there being the caller's, and its reads are
  unchanged. A changed answer: every read off SP whose place is known now prints an offset
  from FP where it printed one from SP. `docs/usage.md` says what each spelling means
  (#207).

- **The rendered output's shape is gated, not only its per-symptom counts.** A count says
  how much and not what shape, and that is how #206 came within one review round of
  shipping 112 blocks rendered as `if (c) {` with `}` under it: two rounds verified its
  numbers and its composition, and neither looked at the text around the lines it changed.
  `cfgcheck` could not see it either, since it checks CFG edges and not rendered arms.
  `pbfuzz.census` now counts five invariants of the text itself and
  `test_no_frame_slot_record_outlives_the_path_that_made_it` holds four of them at exactly
  zero: blocks that hold nothing, functions whose braces do not balance under the scanner
  the drop passes use, a name the body declares twice, and a name read on a line above its
  declaration. The fifth, blocks whose only line is a declaration nothing reads, is a
  bound at 1,398, because `_drop_unread`'s guard trades an empty block for one of those on
  purpose. All five read the same on both fixtures. A sixth was measured and left out: a
  declaration whose text repeats one already used in the same function comes to 12,192 and
  cannot tell #207's defect from reading one field twice, and a number that cannot say
  which it is counting is not a gate (#210).

- **A call defines what it clobbers.** `State.forget` left a register holding its OWN bare
  name, and the printed body never assigns that, so it read as the value the function came
  in with. After a call that is whatever the callee left: `f(this); x1.field_0x8 = x2;`
  claimed the entry x2. The register's name was already taken, so reusing it as the
  definition was the bug. The call now DEFINES each volatile register it destroyed that
  liveness says is read again, with a fresh name and no initialiser, `var tN;`: a value the
  lifter does not know, which cannot be confused with an argument. Not the return
  registers, which `_result` names.

  **A changed answer, on every call site with a live volatile register.** Over all 8,194
  clean ranges and 8,188 obfuscated ones: lines 182,119 to 183,876 on the clean build and
  182,128 to 183,885 on the obfuscated one; lines carrying a bare machine register 26,633
  to 26,257 and 26,620 to 26,244; reads of a name whose declaration has closed unchanged
  at 28 in 11 on both, and blocks the rendering leaves empty still 0. The whole-image lift
  costs about 4% more, 16.68s to 17.47s, best of three in each of two runs alternating
  between the checkouts, and peak RSS does not move. All nine CPU oracle tests pass with
  the same scored population as main, to the expression: the generated bodies hold no
  calls, which is on `irfuzz`'s own list of what it cannot check, so this shape is one no
  oracle sees either way.

  This is what the field does rather than reuse the register's name. Ghidra emits an
  INDIRECT at a call, a placeholder for possible indirect effects used for SSA
  construction, whose output carries nothing through from before it; GCC's RTL SSA makes a
  clobber a definition in its own right, marking the register as holding an unknown value.
  It is also `_phi_name`'s own rule, always a fresh one and never the register.

  Printing the instruction raw instead was tried four ways first and each had a blocker,
  the decisive one being that `irfuzz._exec_one` scores a raw line as undecidable, so every
  converted line stopped being checked and the oracle lost the power to see a defect class.
  Defining the register keeps every line a statement, which is why this is the design.
  What it does not reach: a register clobbered inside a loop and read after it still prints
  the bare register, because the loop carries nothing for it. 74 of the new declarations
  per fixture, in 30 ranges, are read by nothing, which is `_drop_unread`'s pass order and
  not this change: its last call says why it stays restricted to `blind_named` (#176).

- **A raw line no longer crashes on a pinned name the hoist took.** `_verbatim` collects
  the names `_pin` wrote out into `raw_names` by matching each line as a declaration, and
  a name the hoist took is not one: it declares at the top of the body and assigns where
  the value is, `tN = ...;`, which the pattern does not match because it requires `var`.
  Matching unconditionally raised `AttributeError`, and an exception that escapes is exit
  3, a bug in Jadart rather than bad input. Nothing on either fixture hoists a name `_pin`
  writes out, so this shipped green with the hoist in; the first change that made
  `_verbatim` fire more often found it (#212, found working on #176).

- **A bare `q` or `v` register is counted.** `tools/quality.py`'s register pattern matched
  `w`, `x`, `d` and `s` only, so a line whose only register was `q0` or `v1` counted as
  carrying none, and `pbfuzz.census`'s `regline` inherited that because it uses that same
  pattern rather than a copy. The 1,169 declined 16-byte frame reads that still print
  their register were invisible to every number in the repo. 55 lines on the clean build
  and 55 on the obfuscated one are counted now; no output changes, the lifted lines are
  identical (#209).

- **A name is hoistable whichever site minted it.** Thirteen places allocated
  `t{tmpc}` themselves and then each decided for itself whether the name could be
  hoisted into scope. Only two could, `_phi` and `_name_blind`, so a name any other site
  minted and a later line read outside the block it was declared in was a read of
  something undeclared. `_mint` hands out every name now and owns the hoist split, the
  declaration going to the top of the body and the assignment staying where the value is,
  and `_lift_function` asks one set rather than two. Over all 8,194 clean ranges and
  8,188 obfuscated ones, **reads of a name whose declaration has closed go 164 in 115
  ranges to 28 in 11**, the same on both. 36 fewer lines carry a bare machine register as
  well, because a name in scope is a name the reader can be given. Output grows 167 lines
  for the declarations that moved, and one synthetic shape takes a third walk because the
  hoist decides on the lines as they will ship.

  What is left is in one pathological function and `_concatAll`: names minted by `_phi`
  and `_join_write`, which allocate outside `_mint` and declare elsewhere, plus the four
  that are declared nowhere at all (#205). Raising the hoist's iteration bound from 4 to
  12 changes none of them, so the residue is not a bound.

- **Liveness is asked about one register however the operand spells it.** `d0`, `s0`,
  `v0`, `q0`, `h0`, `b0` and `v0.16b` are one machine register, and `_regs` builds every
  liveness set calling them all `d0`. The STATE is keyed by `canon`, which keeps the view
  spellings apart on purpose so a value written under one is not read back under another
  (#114). The two are therefore different names for one register, and a caller holding a
  state key was asking about liveness with the wrong one. The bit table could not say so:
  an unknown name MINTED a bit, no liveness set held it, and the answer came back a
  confident "not live". That is how 1,169 frame reloads off the frame pointer, every one
  of them read again, came to be passed over (found reviewing #206). `_reg_mask` now maps
  through the identity the sets were built with, which makes all fifteen callers right
  rather than leaving each to remember which name to use.

  No output changes from that on its own: byte-identical over all 8,194 clean and 8,188
  obfuscated ranges. What it exposes is that `_pin_mem` can be right to name a value while
  the reader cannot use the name: `ldr q0` leaves `d0` holding the low half of a 16-byte
  read, which a field spelling cannot say, so the `ret` reading `d0` declines and the name
  goes unread. Its names are recorded in `raw_names` now, so the pass that drops what
  nothing reads takes them. **63 declarations nothing reads leave the output**, on each
  fixture.

- **A declined frame reload no longer reads as the value the function came in with.** A
  reload the walk cannot answer printed NOTHING and kept the load's own register. The
  printed body reads a register it never assigns as the incoming value, so

      ldur x3, [x29, #-8]        // a slot the walk lost
      stur x3, [x2, #7]

  printed `x2.field_0x8 = x3;`, which says the destination still holds the x3 the
  function was called with. It does not: the load happened. The reload now says the read
  it is, under a fresh name, which is `_phi_name`'s rule at the other end, always a fresh
  one and never the register:

      var t0 = (FP - 8).field_0x1;
      x2.field_0x8 = t0;

  The address is the base expression and `.field_0x1` is the read at it, which is the
  spelling the lifter already prints when that address is held in a register.
  `docs/usage.md` now says so, and says that FP and SP mean those registers at that line.

  **A changed answer, and a wide one.** `tools/quality.py` on the clean build: lines
  173,025 to 186,090, **lines carrying a bare machine register 33,797 to 20,678**, 19.5%
  of the output to 11.1%, byte-offset field lines 44,423 to 55,238, 25.7% to 29.7%, raw
  arm64 lines 1,553 either way and every other symptom unchanged to the line. Over the
  same ranges through `pbfuzz.census`, which lifts without a receiver, arity or field
  names: 171,119 lines to 182,015 and reads of a name out of its declaration's scope 171
  in 122 ranges to 164 in 115, on the obfuscated build too. Names nothing reads come out
  at 4,713 against 4,712, level: the pass that drops them runs once more for these names,
  after the passes that can delete a reader, and it now also keeps one that is all its
  block holds, which the two beside it already did. An `if` arm is the walk's to render,
  and taking its only line printed `if (c) {` with `}` under it, 112 times in 47 of those
  ranges, where main has none.
  `pbfuzz.census` counts those now and the gate holds them at zero.

  Where the slot held the load's own register the old output was right, 904 of that class
  on the clean build, and those are a named read now: still right at that line, and no
  longer spelled exactly like a reload that had given up.

  **What it does not do.** A read through the floating-point file declines unless it is
  exactly eight bytes, because that file has no convention for saying less where the
  general one has `_extended`: a 16-byte `q` or `v`, and a 4, 2 or 1-byte `s`, `h` or `b`.
  On the clean build that is 1,169 reads off the frame, all of them 16-byte, whose
  register is read again, so those still print it.

  And no record of what a slot held closes this class, which is what the attempts
  on #198 kept finding: once a path may have written the slot, neither the register nor a
  name for the register is what the load reads. Naming the value at the spill measured
  four fewer reads for 1.7% more output (#198).

- **A name is no longer read after its declaration has closed.** `_phi` declares its name
  at the level of the `if` it belongs to, which dominates the arms but not the reader:
  where that `if` is nested in an arm, the arm closes and the name is gone while a later
  line still reads it. The lifter printed

      while (true) {
        var t1 = x7;
        ...
      }
      L_0x24:
      x2.field_0x60 = t1;

  where `t1` is declared inside the loop and read at a goto target after it closes. A Dart
  parser rejects that and an agent reading the output resolves it to nothing. **1,488 such
  reads in 517 of 8,194 ranges** on the clean build and the same on obf, now 171 in 122.

  The declaration moves to the top of the body, joining the goto-join phis already
  declared there. The INITIALISER stays where it was, because it is the value from before
  that `if`, so `var t1 = x7;` inside the loop becomes `var t1;` at the top and `t1 = x7;`
  in place: the same assignment point and the same value. Definite assignment over a
  line-level CFG of the printed body finds no path reaching a hoisted read without passing
  its assignment, on either fixture.

  `_drop_dead_phis` also stops calling a block empty when it holds a nested one, which the
  hoist requires. That function keeps a dead phi whole rather than leave a block with
  nothing else, and the lines it counts are a block's DIRECT ones, so a parent whose body
  is one dead declaration plus an `if` looked bare. Invisible while a live declaration sat
  beside the dead one; the moment hoisting moved the live one away, 16 dead lines came back
  in 5 functions, 4 naming a bare machine register. The fix also drops **162 net lines in
  50 functions** that were already dead on main, every one a phi name nothing reads and
  none carrying a call, so lines naming a bare machine register go 33,836 to 33,797.

  What is left is two different things. Seventeen reads are of phi names, twelve of them
  minted by `_render_loop` and `_join_write`, which only `_phi` can act on today. The rest
  are call results and slot names whose declaration has closed in the same way, a class
  this does not reach because `_phi` is the only emission site consulting the decision.

  **A changed answer.** 88 files of the clean export differ. Two output changes beyond the
  declarations, both stated because an unstated one blocks: the 162 dead lines above, and
  **58 fewer `var tN = <call>;` lines**, because `_inline_single_use` folds a call into the
  next statement when that statement is its only reader and a hoisted `var tN;` was the
  line between. Both acceptance gates read as before (Tier A 11/11 and 9/9, Tier B 3/3),
  `cfgcheck` is clean on both fixtures, the export is byte-identical across two hash seeds,
  `pbfuzz --census` is unchanged at 2,608 actionable reads and 0 stale records, and the CPU
  oracles are unchanged at 0 mismatches. Lift 1.04x and export 1.02x against a baseline
  recorded from main on the same machine. One pinned assertion moves, and it was pinning
  the defect.

- **A reload of a dropped frame slot reads the value it held, not the load's own
  register.** `stale_on_write` drops a slot whose text names a register that is then
  reassigned (#173), and `_reload` fell back to spelling the LOAD'S OWN destination. That
  is right only where the slot held that very register, whose entry value the printed body
  still reads, so the reload round-trips; where it held anything else the fallback named a
  different value. `stur x6, [x29, #-8]; mov x6, x2; ldur x3, [x29, #-8]; stur x3, [x20, #7]`
  printed `x20.field_0x8 = x3;` for the x6 the machine stores, and now prints `= x6;`.

  Sound because the drop is about the MAP, not the output: the instruction that reassigned
  the register was FOLDED, so it printed no assignment and the printed body still reads
  that register as it did at the spill. The conditions that makes true are written at
  `State.dropped` and carried with it: nothing filled the slot, the key still names the
  same address, no write touched memory the text reads, and the printed body assigned none
  of the registers the text names. The record lives on the `State` so it forks with the
  arms and `_merge` intersects it, and it is killed by a FILL rather than by the slot
  leaving the map, because a store to a key already absent removes nothing.

  Across the 3.12.2 clean build the fallback misnamed **6,623 reads in 1,967 of 8,194
  functions**, now 2,129 in 545. The rest are slots lost to `_forget_frame` and `_merge`,
  which record nothing, and are #198. Nineteen shapes were scored against a real CPU over
  40 random register environments each: every one either agrees in 40 of 40 or declines,
  and none states a value. The four cases of
  `test_a_reload_of_a_dropped_slot_reads_the_value_it_held` carry the 0-of-60 against
  60-of-60 numbers, and it ends by putting the bug back.

  This is the second attempt. The first (#197) remembered the same thing on the Lifter and
  invalidated it nowhere, which printed 2,023 stale spellings on the clean build and was
  reverted in #200; #199 records the repros. What is different here is the kill condition,
  the scope, and that a region-level drop (`_stale_slots` at a loop exit) records only for
  keys whose text names no register a call in the region may have left holding something
  else.

  **A changed answer.** 180 files of the clean export differ. The size does not: 144,727
  lines to 144,728, with 3 fewer declarations. The obf export does not change, though that
  covers only 8,249 of its lifted lines and is not the evidence it looks like; measured
  over all 8,188 obf ranges the lifted output differs by about 8,000 lines with no
  staleness and no ordering residual. Both acceptance gates read as before (Tier A 11/11
  and 9/9, Tier B 3/3), `cfgcheck` is clean on both fixtures, and the export is
  byte-identical across two hash seeds.

- **A register expression is named before a move or a computed result reassigns a register
  it names.** The load pass below is the same hazard for the two other ways a register is
  reassigned: `add x3, x2, #0xad; add x2, x4, #1; stur x3, [..]` and the `mov x2, x4` form
  both printed `x20.field_0x8 = x2 + 173;`, reading the reassigned x2 where the machine
  stored the entry x2 plus 173. `_lift_block` now writes such a live expression out before
  any reassigning instruction, not only a load. What it leaves untouched is the still-open
  self-referential case, a store that reads a register set from its own earlier value and is
  right on main only by that stale read: a register live into a join (the phi machinery
  renames the arm write, keeping its pre-branch meaning, so a pin only adds a redundant phi
  temp); a write whose own result already names the register it sets, because a source holds
  a value that does (`sub x4, x7, x4`, right only by `x4 + 214 - x4` cancelling); a value a
  later self-referential store in the block reads; and a conditional select, which reads the
  flags to render. A differential against a real CPU (unicorn) that resolves each named
  value and reads the store in program order finds 0 regressions: over 69,116 straight-line
  runs, and a further 64,000 from a generator emphasising shifted operands, multiply-
  accumulate and self-referential writes, with about 2,031 fixes. The clean export changes
  about 9,000 lines, 265 of them named expressions and the rest the temp renumbering each
  ripples through its function; obf is unchanged and the raw-instruction line count does not
  move. Part of #187: a register reassigned self-referentially and the loop-invariant case
  #129 leaves are still read stale.

- **A register expression is named before a load reassigns a register it names.** The
  register map holds expressions, not results, and substitutes them into their uses later,
  which is sound only while the registers inside them still hold what they held. A load that
  reassigns one of those registers broke that: `add x3, x2, #0xad; ldur x2, [..]; stur x3,
  [..]` printed `x20.field_0x8 = x2 + 173;`, reading the reloaded x2, where the machine
  stored the entry x2 plus 173. This is the register-map twin of the frame-slot staleness
  #173 fixed, and the register half of #187; `_pin` already wrote such a value out before a
  base moves and before a raw line, and a load now does the same through `_name_stale_reg`.
  Only a load (an unrelated clobber), only a compound expression (a bare-register copy stays
  bare for the argument, phi and read-afresh rules), only the register map (a slot stays
  #173's), and only an expression every register of which still holds its bare self: one
  already stale from an untracked move or computed result is left alone, or naming it would
  freeze the wrong value and defeat the slot reload (#173) that still read it right. A
  differential against a real CPU (unicorn) that resolves each named value and reads the
  store in program order (the fp-slot oracle alone cannot, since a named store reads a temp
  it treats as undecidable) finds main reads the reloaded register and this reads the value
  the register held: 0 regressions over 66,000 generated runs where the same generator finds
  6 without the bare-self guard, and 90 fixes with 0 wrong on the functions the fixtures
  change. The clean export changes about 13,000 lines, but the change is some 320 named
  expressions in 224 functions; the rest is the temp renumbering each new name ripples
  through its function. 7 lines change on obf. Part of #187; the move and computed-result
  cases are the entry above, and the loop-invariant case #129 leaves is still read stale.

- **A return reached out of flow reads no undeclared temp.** The no-successor forget #179
  added for trap blocks now covers every block the walk reaches out of normal flow that
  has no successor, a return or an indirect jump out of the function as much as a trap. A
  loop that collapses a register's carried name (the receiver, which the loop never
  writes) drops the name's declaration but left a goto-target `return` reading it, so
  `_OneByteString.toUpperCase` and `toLowerCase` ended `return t1;` with t1 declared
  nowhere; they now read the bare register, `return x0`, the unchanged receiver. Two lines
  change on the clean fixture, none on obf. Part of #129 (the loop-latch and
  register-text-staleness halves remain, the latter tracked as #187).

- **A trap block reads no undeclared temp, and tier 3 prints no trap mnemonic raw.**
  Tier 3 renders a block the machine reaches out of normal flow (a goto, not fall-through)
  that ends in a trap as its one predecessor left it. A trap ends a block with no
  successor, so that state reaches no later line, and it could spell a value with a temp
  the live path never declared, so the block read a name nothing bound: `Random.nextInt`'s
  divide-by-zero throw printed `THR.field_0x210(..., t1, t0)` with t0 and t1 declared
  nowhere. A register keeps its temp name only while it is not reassigned, so the bare
  register is the same value; such a block now reads a name no `var` on the way to it
  declares as that register, and keeps the temps that are declared. The change is one line
  of the clean export, the nextInt throw, and none on obf. Separately,
  the tier-3 rule that prints no text for a trap listed only `brk` and `hlt`, so `udf`,
  `bkpt` and `trap` fell through and printed verbatim; all of `TRAPS` is dropped now, as
  `brk` was. No fixture holds a `udf` or `bkpt`, and an all-zero word read as code decodes
  to `udf`, so this changes no exported byte and covers crafted or other-toolchain input.
  Closes #179.

- **A frame slot reads its register afresh once a register its text names is reassigned.**
  A slot that spills a stable register keeps that register's name as its text, so a reload
  read the register's new value where the machine holds the one stored: `stur x6; mov x6,
  x1; ldur x3` printed `x20.field_0x8 = x6`, the reassigned x6, not the stored one. It is
  the stable-register twin of #140, which covered only a value a join lost; the hazard is
  any slot whose text names a register written between the store and the read. A slot now
  goes stale on the straight-line write that reassigns a register it names, the tight
  per-write form of the `_stale_slots` pass a goto join and a loop already run, keyed off
  the register by a reverse index so a write costs a lookup, not a scan. Not at a call,
  whose clobbers are named across it (#64) and whose outgoing arguments a drop would lose;
  a reload off the frame drops the other slots its register names but keeps the one it
  reads back, whose drop would collide two reloads. Exports change 184 files on the clean
  fixture, a stale register or expression becoming the register the reload reads, and none
  on obf. A targeted spill, reassign and reload differential against a real CPU (unicorn)
  corrects 1,654 lifted values and adds no new mismatch; 407 stale reads of shapes this
  does not reach remain, as on main. Closes #173.

- **Tier 3 honours traps in its CFG.** A `brk`, `hlt`, `udf` or `bkpt` ends its block
  with no edge past it, the rule tier 2 took in #57; `_lift_function` and `entry_arity`
  no longer build the graph with `traps=()`. Dart emits a trap after a call that cannot
  return, and the false edge past it let the walk run on. An arm that sets a value, calls
  a throw stub and traps now hands nothing to the code after the `if`: `cmp x1, #0; b.ne;
  mov x0, #7; b; mov x0, #5; bl; brk` lifts to `return 7;`, where it was `var t1; ...;
  t1 = t0; return t1;`. Removing the edge is sound, the machine never falls through a
  trap, so it only drops spurious joins: on the clean fixture 3,017 lines of code the
  walk ran on past a trap go, 932 bare-register declines become named values, and 445
  more reads spell `this`. Naming frame slots across a call (#64, landed earlier) is
  what keeps `_CompactLinkedHashBase.forEach`'s guard from reading `this.field_0xc !=
  this.field_0xc`: field self-comparisons on the clean fixture stay at 2, where the rule
  without the slot naming had 7. Exports change 87 files on the clean fixture and none
  on obf. Closes #64.

- **`returns_in_d0` honours traps too.** #64 flipped the lift and `entry_arity` to
  `traps=TRAPS` but left the third library call site, the selector-recovery helper
  `returns_in_d0`, at `traps=()`. It asks whether a function hands back a double at every
  `ret`, and the false edge past a trap kept a dead `ret` reachable, so a function whose
  only live `ret` returns d0 but which traps after a throw on another arm read as
  returning d0 and x0 both, and the helper said no where yes was right. It now ends a
  block at a trap, as the lift does. No exported byte changes on the clean fixture or obf:
  the helper runs 127 times on the clean build and once on obf, and its answer is the same
  with the trap honoured on every one, so this is a latent fix the two fixtures do not
  reach; a crafted test pins the corrected answer. Closes #178.

- **A return is not proven a double by a block the CPU cannot reach.** `_return_facts`
  decides a `ret` hands back d0 when a write to d0 reaches it, but it ran that proof over
  every block, forward-unreachable ones included, where the set of returns it classifies
  is reachable-only. A block a CPU never enters (its one in-edge was a trap's false
  fall-through, gone since #64) can `fmov d0; ret`, which proved d0 for a live `ret` that
  returns x0, so the function read as returning a double where it returns a tagged value.
  Honouring traps in `returns_in_d0` (#178) exposed one more such block. The proof now
  runs over the reachable blocks, the basis the return set already used. No exported byte
  changes on either fixture and no return verdict flips across every function (6,849 on
  the clean fixture, 238 on obf). The `read` flag this corrects differs on 10 of them and
  9 on obf, all with a forward-unreachable block; on the one whose `ret` is itself
  reachable (clean 0x16afcc) the classification gains the correct `x0` where the dead
  block had left it unresolved. A crafted test pins the case. Closes #182.

- **A function's own d0 is a d0 write the CPU can reach.** #182 made the return proof use
  the reachable blocks; the gate that decides a function writes d0 at all, and so goes
  through that proof rather than to `_argument_returns`, still ran over every block. A
  function whose only d0 write is in a block a CPU never enters was read as writing d0 of
  its own, so a reachable pass-through `ret` was labelled x0 with no caller to ask, where
  the honest answer is the argument's register once a caller or the peers of its selector
  speak. The gate now counts a d0 write only where the CPU can reach it, the basis #182
  gave the rest of the proof. No exported byte changes on either fixture, and no return
  verdict flips (6,849 functions on the clean fixture, 238 on obf); 22 and 21 now defer to
  `_argument_returns`, each either with no reachable `ret` or rendering the same register
  through `State.result`. Two crafted tests pin it. Closes #184.

- **A goto out of nested loops to a join names the value it carries, not the bare
  register.** A goto from an inner loop to a block the outer loop also leaves to reaches
  a join the structured walk never met, and `_join_kill` dropped the registers it
  disagrees about to their bare names, which read as the last printed line put them: a
  raw line's from inside the loop. With `umulh x7` printed in the loop and `add x7, x5,
  x1` before it, the store at the join read the `umulh`, where a path that leaves on the
  first inner trip has `x5 + x1` (#123). The loop now carries such a register past the
  join (`_note_goto` no longer stops where the target is a join), and the join reads a
  phi name written on every edge into it, the goto's and the loop's own exit, as the
  if/else join already does (`_join_write`). The single-loop case was #156; this is the
  nested half it left open, and the join half of #129. Tier 3 exports are unchanged on
  the clean fixture, 2.19.6, 3.4.4, 3.10.9 and obf: the shape needs the carried value
  read at the join, which the fixtures do not do, so the fix shows on the generated
  graphs of `tools/irfuzz.py --cfgmem --nested`, which it leaves clean. One crafted case
  in the tests that recorded the bare-register limit now asserts the named value. Part
  of #123.

- **A call's pushed arguments survive a second push, and saved registers no longer read
  as arguments.** `_stack_args` reads a call's arguments off the SP-relative slots, and
  two things went wrong (#147). A second push that moved SP dropped what the first push
  stored, so `stp x6, x7; str x5; bl` read one argument where three were pushed; the
  slots are now renamed by the move instead of dropped, and the whole list reads. That
  exposed the second: a slow path that spills volatile registers round a runtime call and
  reloads them after left the spill in the outgoing area, and the call printed it as its
  arguments, `pool_0x2650.field_0x7(t4, t3)` for a saved `stp x0, x1` on the clean
  fixture. A save is now told from an argument by what the code does after the call
  (`_save_wrapped_calls`): a run of pushes a run of pops reloads into the same registers
  is a save, and the call reads no stack arguments. Tier 3 exports change in 30 functions
  on the clean fixture, 1455 on 2.19.6, 36 on 3.4.4 and 31 on 3.10.9, and none on obf:
  dropped argument lists now read in full, and saved registers decline. Closes #147.

- **A value a join lost is no longer read back from a frame slot as the register.** A
  register the two arms of an `if` disagree about is dropped to its bare name, which
  reads like the entry value and like a raw line's result. A frame slot that spilled one
  kept the text `x6` while a later join left `x6` meaning something else, so a reload read
  the wrong value: two field stores printed `x6` for values the machine holds apart
  (#140). The slot is now tied to the lost register (`State.lost`, `State.lost_slot`) and
  dropped when that register is reassigned, when its name no longer describes the slot;
  until then the slot reads right, and the reload after reads the register afresh rather
  than a stale name. The outgoing argument area is untouched, its values read at the call
  before any reassignment. Tier 3 exports change in 498 functions on the clean fixture,
  374 on 2.19.6, 525 on 3.4.4 and 536 on 3.10.9, and none on obf: each a reload that read
  a stale register now reading the loaded value under its own name, which cannot be a
  wrong value, only a decline. Closes #140.

- **A write to a V register's upper lane no longer forgets the double in its low lane.**
  d0, v0.16b and q0 are one register, and #114 forgot the double tracked under dN on any
  write to a wider spelling. An insert into a lane entirely in the upper 64 bits (`ins
  v0.d[1], x5`, `mov v0.d[1], v3.d[0]`, `fmov v0.d[1], x5`, `.s[2]` and up) leaves the
  low 64 bits, which dN names, unchanged, so forgetting dN there declined a double the
  machine still holds. Now such an insert keeps dN, forgets only the wider spellings, and
  prints raw. An insert into the low lane (`.d[0]`, `.s[0]`, `.s[1]`, ...) still changes
  dN. No corpus export changes (none of the four builds inserts into an upper lane over
  a tracked double), so this restores a value the shape would lose rather than altering
  any current output. Part of #134.

- **A call to a function that takes a double left the double out of its argument list.**
  Dart passes a function's first six doubles in V0 to V5, apart from the x registers it
  passes integers and objects in. `entry_arity` counted only the x registers, so a
  register-only callee that also took a double had its double dropped: a call to
  `f(Object a, double b)`, which reads x1 and d0, printed `f(x1)`, and a call to
  `lerp(double, double, double)` printed the fields its caller happened to hold in x1
  and x2, a list that did not even start at the first argument. A register argument list
  cannot say where the doubles fall, so such a callee now declines to `...`, the same way
  a callee that takes both register and stack arguments and is handed a double already
  does (#148). `entry_arity` reads the V argument registers with `_fpu_args_live`,
  ignoring a `ret` that hands d0 back, which a function that only reads x registers and
  returns its object in x0 has too. Tier 3 exports change at 219 call sites on the clean
  fixture, 223 on 3.4.4 and 225 on 3.10.9, and at none on obf or 2.19.6, each a double
  taker's list, `lerp(x1.field_0x8, x2.field_0x10)` and `scale(this.field_0x8)` among
  them, now `(...)`. Closes #155.

- **A frame written out of sight, or read back wider, read as it was.** Three cases the
  review of #162 left, each on `main` too. A frame register moved where the walk did not
  see it moved: `strip_boilerplate` blanks every `mov x29, x15` and every `add` or `sub`
  of SP, not only the prologue's, so an FFI call's frame, which gives the C call a frame
  of its own and puts FP back after, and an SP adjust past the prologue, both kept the old
  slots, and a slot read through the moved register printed what was stored where it
  pointed before. A store through a register holding a frame address, built with `sub x16,
  x29, #8` or an FFI call's `add xD, SP, #imm`, left the slot it wrote reading as before.
  A load that extends what it reads printed the stored text whole: `stur w0; ldursw x3`
  read x3 as x0 where `sxtw x3, w0` reads it as `x0 << 32 >> 32`, and a narrow load took
  the low bits of a wider value as the whole of it. Now the walk is handed the frame moves
  `strip_boilerplate` blanked and drops the moved register's slots there, an FFI or leaf
  call's accesses through the moved FP are keyed into the frame it points into so a slot
  kept from before the call reads the same after, a store through a register that may hold
  a frame address (a forward analysis over the functions where one reaches a register)
  forgets the slots it may write, and a reload reads a slot only through the register file
  it was stored from and extends a narrow read as `sxtw` and `uxth` print it. Tier 3
  exports change in 110 functions on the clean fixture, 107 on 3.4.4, 110 on 3.10.9 and
  in none on obf or 2.19.6, almost all a saved FP printed as a native runtime call's
  argument, `THR.field_0x7d9(x29)`, now `(...)`, and a load past the FFI frame it is
  keyed into, `THR.field_0x6c8 = x0.field_0x7d9`. A store through a frame address in a
  register changes essentially no output, as the corpus reads through such addresses far
  more than it writes through them, but it was wrong where it did. Closes #165.

- **LR after a call, and a slot a store changed out of sight, read as changed.** A call
  writes LR with its own return address, and LR read the same after one as before it, two
  values under one name in one loop. A store replaced only the slots it filled, so one at
  -8 left the slot at -0xc with its top half changed, there and round a loop, and a load
  narrower or wider than the store before it read that store's whole value. A store
  `_step` prints raw (`stnp`, `stlr`, `st1`, an exclusive store, an atomic) changed no
  slot and named no field read it may have changed, and a store through SP was not checked
  against the slots kept through FP, nor one through FP against the arguments a call takes
  through SP, nor either round a loop. Now a call forgets LR, and a loop with one carries
  it; a store forgets each slot it writes a byte of, and a load reads a slot only at the
  width it was stored; a raw store off the frame forgets every slot and one elsewhere
  names each field read first; a loop header forgets the outgoing area where a trip may
  write it; and `_frame_meets` follows SP - FP through the function, an FFI call's frame
  and the slow paths `strip_boilerplate` cuts off included, so that only a store that may
  reach the other register's slots forgets them. FP moving takes SP's slots with it, and
  SP loaded, through itself too, is not known. A pair of q registers put the second 8
  bytes on, not 16, and a write-back store through FP, and a post-index one through SP,
  was filed where the register had been. The top half of a q register is no argument, so a
  q register saved round a call no longer reads as one: `pool_0x2650.field_0x7(q0)`, the
  inline box's slow path saving q0 round its allocation, prints `(...)`. Tier 3 exports
  change in 11 functions on the clean fixture, 10 on 2.19.6, 17 on 3.4.4 and 11 on 3.10.9,
  and in none on obf: 8, 10, 14 and 8 of those q saves; 2, 0, 3 and 2 that named the
  dispatch target a call then overwrites in LR; and `WidgetStateMapper.resolve` on clean
  and 3.10.9, whose temporaries are numbered one lower, where a store reached only past a
  throw is one of those `_frame_meets` finds, in 2 to 8 functions a build. The loop reload
  cost test compares two sizes rather than a time in seconds, and nested loops cost about
  half what they did, 0.58 s for 300 deep against 1.02 s, as each block's frame accesses,
  writes and reload steps are worked out once for all the loops around it. Closes #162.

- **A slot the loop does not store to survives it.** A loop's exit forgot every frame slot
  where a block of `_loop_nodes` stored to the frame, and those take in the blocks before
  the loop too (#129), which store to it as a rule. So a value saved before the loop read
  back after it as the register it was reloaded into: `_contentWidthFor` compares its
  first double argument with a call's result and printed `if (d1 > t2)`, which reads as
  its second (#157). The exit now drops only the slots a store in the loop's own blocks
  overlaps, 16 bytes of one a q register filled and 8 of any other: the natural loop of
  its back edges less a stack check's slow path, whose stub hands back every live register
  and stores to no slot; `strip_boilerplate` records the slow paths of the checks it takes
  out. The outgoing area goes at every exit, as a call in the loop takes what was pushed.
  A store it cannot place, a frame that moves or whose address reaches a register still
  drops them all. A slot whose text reads memory still goes where the loop stores to
  memory or calls, and one whose text names a register where the loop or the code before
  it writes that register, a block with a trap or a throw aside. `_contentWidthFor` now
  prints `if (d0 > t2)`, and `readValue` calls `readValueOfType(this, t2, x2)` where it
  printed `(x1, t2, x3)`. Tier 3 exports change in 183 functions on the clean fixture, 76
  on 2.19.6, 160 on 3.4.4 and 190 on 3.10.9, and in none on obf, where a bare register
  after a loop now reads as what its slot holds. Closes #157.

- **A goto out of a loop hands on what the last trip left.** A goto out of a loop handed
  its target the state the walk had at the jump, which is the first trip's: a register the
  loop writes further down still held its value from before the loop, so the target of a
  `b.eq` out of a counted loop stored `x5 + x1` where the CPU, leaving on the second trip,
  holds `x6 + x1`. A loop now forgets at its header each register it writes and does not
  carry, and the target reads the register. Where a printed line writes it, the bare
  register would read as that line's value, so each loop the goto leaves carries it where
  the goto is the target's only way in, as for a `break` (#123), now also for a `break`
  that leaves before the trip writes it. A register each trip reloads, through 64-bit
  loads and moves, from a frame slot that held its value before the loop and that the trip
  does not store to, keeps that value: a call in `compareTo`'s loop takes x6, and each
  trip reloads it. Only the loop a second trip runs counts, not a way back past a trap or
  a throw, nor a stack check's slow path that the boilerplate strip cut off. Tier 3
  exports change in `_removeDotSegments` and `_normalizeRelativePath` on the clean fixture
  and 3.10.9, and in `_removeDotSegments` on 3.4.4, where a flag the loop sets printed as
  the `false` it starts as; none on 2.19.6 or obf. Closes #154.

- **A call to a function with register and stack arguments prints both.** A Dart function
  that takes register arguments gets its first six integer and object arguments in x1, x2,
  x3, x5, x6 and x7, its first six unboxed doubles in V0 to V5, and the rest on the stack,
  the last one at SP+0. Some take none in registers, closures, generic functions and
  dispatchers among them. A callee that reads both registers and the stack had two answers
  from `entry_arity`, and the call printed one part as the whole list: framed, only what
  was pushed, `_addEntry(x2)` and `GlyphInfo._(x16, x30)`; frameless, as `hash6` to
  `hash20` are, only its registers (no export prints a call to one). `entry_arity` now
  gives such a callee a `StackArity`, its register count, how many stack slots it reads
  and whether it is handed a double in a V register. The call prints its six register
  arguments and then all that was pushed, `GlyphInfo._(t0, x2, x3, x5, x6, x7, x16, x30)`,
  and `...` where the list is not known: fewer than six registers read, a double handed
  over beside them, fewer values pushed than it reads or none, a stack read through an
  index computed from FP, or a callee the instruction cut stops short, neither of which
  says how far up it reads, or a register argument the caller holds no value for. A double
  counts as handed over where the callee reads d0 to d5 before writing them, or hands d0
  back at a `ret` no call and no write to x0 can come before. One that only hands a double
  on to a call, or hands it back after a write to x0, is not seen to take one. On the
  fixtures none is handed one: where a callee whose call prints a full list could hand d0
  to d5 on or back, every call to it finds them left there by a call that returns no
  double, and none returns in d0. A callee that reads only registers no longer takes what
  was pushed for its list where they are not known: 3.4.4's `contains` printed
  `contains(0)`, a value its callee never reads, and prints `contains(...)`. An address
  computed from FP and then overwritten is not taken for a read of arguments through it,
  or a `sync*` method that takes only `this`, as `_childrenInPaintOrder` does, would look
  like such a callee. Tier 3 exports change in 28 functions on the clean fixture, 27 on
  3.4.4 and 31 on 3.10.9, and in none on 2.19.6 or obf. 19 or 20 calls a build print both
  parts, each with as many pushed values as its callee reads, and 8 to 12 print `...`
  where they printed one part. Closes #148.

- **A function that hands back its double argument returns d0.** One that never writes d0
  had no rule of its own code to decide which register its `ret` hands back, so
  `Curve.transform`, which returns its argument where it is 0.0 or 1.0, printed
  `return x0;`, and so did `_Linear.transformInternal`, which only hands its argument
  back. A `ret` that neither a call nor a write to x0 can come before now returns d0 where
  the function's callers read d0. Where no direct caller reads either register, as for a
  function only the dispatch table calls, the other implementations of its selector speak
  for it: each returns in the register its own callers read, or in d0 where its own code
  hands back d0, and they have to agree. They are the functions the table places at one
  offset under one name whose classes share one below `Object`, where every concrete class
  under that one holds one of them in its row. Two selectors of one name that share an
  offset are told apart unless their classes are all the concrete ones under the class
  they share. A stub that gives every register back is not a call. Tier 3 exports change
  in those two functions on the clean fixture and 3.10.9, and in none on the other builds;
  obf's `Curve.transform`, which its export does not print, lifts to `return d0;` too.
  obf's table names one offset, not that one, so its `_Linear.transformInternal` still
  prints `return x0;` (#159). Closes #127.

- **A call's double read past the next instruction is named.** A call's d0 result got a
  name only where the very next of x0 and d0 an instruction touched was a read of d0.
  After a reload of x0, an inline box or a join it printed as `d0`, the d0 the function
  was handed: `BoxConstraints.constrain` stored `d0` as its width, and
  `_getYShiftPosition` multiplied `d0` for `transform`'s result. A `ret` one path reaches
  from a call and another from the function's own double was left to the x0 phi, so
  `getOffsetX` returned `x2.field_0x18` where it returns `_rightOffsetX`'s result. A pass
  over d0 now finds each call whose double reaches a read or a `ret` that hands d0 back,
  and names it, where it is a direct call to a function its callers read d0 from, or whose
  own code hands back d0, and such a `ret` now returns d0. A named stub is not one, and a
  slow path's save of q0 laid out after a throw no longer reads as the throw's caller
  reading its result. Tier 3 exports change in 29 functions on the clean fixture, 17 on
  2.19.6, 26 on 3.4.4 and 31 on 3.10.9. Closes #152, part of #127.

- **A loop names what it computed over a raw write it printed.** A register a loop writes
  is forgotten at its exits, and prints after the loop as itself, which reads as the last
  value a printed line put in it. Where that was a raw line in the loop, `umulh x7, ...`,
  and a line after it the loop did not print, `add x7, x5, x1`, the store after the loop
  read the `umulh`. A first walk now notes each register a `break` holds something else
  in, that the code after the loop reads and that the body prints a write to, and the walk
  runs again with the loop carrying it from its value before the loop, so each `break`
  names what it holds. A name nothing then reads, the register's only reader a call that
  prints `(...)`, is left out. A loop inside another is not covered: its node set holds
  the loop around it (#129). Tier 3 exports change in one function on each corpus build
  and the clean fixture: `_append` in serialization.dart on clean, 3.4.4 and 3.10.9, and
  `_synchronizeModifiers` on 2.19.6. Part of #123.

- **A call whose double result is read next names it.** A double comes back in d0, and a
  call's d0 result was never named: it read as d0, which is also how the d0 the function
  was handed reads, so `ratioOfTones` compared two calls' results as `d0 > d0`. Where the
  next of x0 and d0 an instruction after a call touches is d0, read, and x0 is not read,
  the result is the double, and gets the name; `eor v0.16b, v0.16b, v0.16b` writes d0 and
  reads nothing. A result that waits past a write to x0, a reload or a box, still prints
  as d0. A `ret` no longer reads the register it does not hand back, so d0 is not live up
  to a `return NULL;`, where every join on the way took a phi for it that nothing read.
  Tier 3 exports change in 149 functions on the clean fixture, 107 on 2.19.6, 135 on 3.4.4
  and 146 on 3.10.9. Part of #134 and #127.

- **A call to a function that reads its arguments off the stack prints what it pushed.**
  `entry_arity` counts the registers a function reads on entry and declines where it reads
  stack arguments off FP, but a frameless function reads them off SP, `ldr x0, [x15]`, and
  one that indexes them computes the address from FP, `add x1, x29, w0, sxtw #2; ldr x1,
  [x1, #0x28]`. Where such a function reads no register, it counted 0 and a call to it
  printed `f()`: `_absSub()` for the five values `_absSubSetSign` pushes. It declines now,
  and the call prints what was pushed, `_absSub(T5, T0, T6, T7, T8)`. One that reads
  registers as well keeps their count (#148). A call whose pushed arguments a second push
  cut short, as `stp ...!; str ...!` does, printed the part left as its argument list,
  `_doSort(x16)`; it prints `...` now (#147). The check in `_call_args` for an arguments
  descriptor in x4 never fired for a `bl`, as the call's own clobber of x4 set it and the
  call cleared it first; it is gone, since the callee's arity already declines where x4 is
  live on entry, and where it could have fired it would have been wrong, a descriptor
  coming with the fixed arguments still in x1..xN. Tier 3 exports change in 42 functions
  on the clean fixture, 35 on 3.4.4 and 37 on 3.10.9, and in 1,324 on 2.19.6, which pushes
  its arguments that way: 2,691 of the lines it gains are a call printing `...` where it
  printed part of its arguments. Closes #144.

- **A loop carries a register it reads only as a call argument.** A loop decides what it
  carries from the registers its body reads before writing, and a call read none, so a
  value passed to a call and set again later in the loop printed as its value from before
  the loop on every trip: `writeMap` wrote its first separator, `"`, before every key,
  where every later trip writes `,"`. The carried set now counts a call's printed
  arguments, as the function's liveness does since #122. A call whose argument register
  was never set before the loop printed `(...)`, and now names it, a bare register as
  often as not. Tier 3 exports change in 12 functions on the clean fixture, 7 on 3.4.4 and
  14 on 3.10.9; 2.19.6, which passes no arguments in registers, does not change. Closes
  #142.

- **A stub that returns a value is a call to the return rule.** The walk suppresses
  `InitLate*`, `Await`, `InitAsync` and `CloneContext` as it does the stubs that give
  every register back, and the rule that decides whether a `ret` hands back x0 or d0 took
  them that way too: a d0 written before one read as what the `ret` after it returns. They
  return their value in x0, so to that rule they are calls now. No tier 3 export changes
  on the fixtures. `tools/bench.py` (`lift`), `quality.py` and `semdiff.py` lift with the
  return rule now, as `export` does: the bench `lift` digest changes, and `quality.py`'s
  count of bare-register lines on the clean fixture goes from 37,248 to 37,233. Part of
  #127.

- **A dispatch offset other selectors share is not named.** The dispatch table is packed
  by row displacement, so selectors whose classes never meet can take the same offset, and
  a call site's immediate does not say which one it calls; the vote gave the offset to the
  name with the most defining classes. The clean build's 0x9c0e8 tests a bool and printed
  `.textScaleFactor`, a double getter, `controller.stream` printed `.maximumSize`, and 122
  calls of `.length` printed `.perform()`. Each function is now placed where the table
  puts it, in the rows of the concrete classes at or below its class that inherit it (an
  abstract class has no row; its abstract bit is read from the Class), and an offset is
  named only where every function placed there spells the one selector, a function with no
  name counting as another, and no function that fits more than one offset fits it. A
  sharer none of that can see, a getter whose `return false` some other function owns, is
  caught at the call site: a call whose result is read from x0 is not named for a selector
  that returns a double. 133 of the 168 names stay on the clean build, naming 607 of its
  2,580 recovered dispatch sites (974 before), and about 51% of the sites on the 2.19.6,
  3.4.4 and 3.10.9 builds (about 65% before). Closes #128.

- **A value read only as a call's argument is live up to the call.** `bl` reads no
  register to the machine, so tier 3 took a value read only as a call's argument, or as
  what a `throw` throws, as dead. A raw line overwriting a register it was spelled with
  did not name it first, and `foo(x1, x1 + 1)` passed the new x1 plus one; arms that
  disagreed on an argument left it a bare register after the join; and a call whose result
  is thrown printed `tooFew(); throw x0;`. A call whose callee's arity is known now reads
  the arguments it prints, and a throw reads x0: `throw tooFew();`. The extra phis exposed
  one more case, also fixed: an arm that loses a register at a join inside it, or
  recomputes from one it lost there, ends with the register spelled as it was before the
  `if`, and the phi took the value from before the `if`. Such an arm now assigns the
  register itself. Tier 3 exports change in 161 functions on the clean fixture, 117 on
  2.19.6, 243 on 3.4.4 and 257 on 3.10.9, most of them one of those three. Closes #122.

- **A register list load writes every register in it.** `ld1 {v0.16b, v1.16b}` writes
  d0 and d1, and tier 3 took only the first register of a list as written and the rest
  as read: a store of d1 after the load printed the field d1 held before, and the raw
  line said it read d1. Every register in the list is written now, and a load of one
  lane of each, `ld2 {v4.s, v5.s}[1]`, reads them too, since it keeps the other lanes.
  None of the five fixtures has a register list, so exports do not change. Part of
  #134.

- **A frame slot past the displacement is its own slot.** A slot further from FP than the
  9-bit displacement reaches is addressed through a register, `mov x17, #-0x158; str d0,
  [x29, x17]`, and tier 3 read every such access as `[x29]`, so all of them were one slot
  and a reload printed whatever was stored at another offset last. The offset is now read
  from the `mov` right before the access, which is where all 2,758 such accesses on the
  five fixtures set it. An offset it cannot read is printed as the instruction, and a
  store through one, off FP or SP, forgets every slot. A call now takes x16 and x17 with
  it too: they are scratch registers a stub or a veneer may use, and a value set in x17
  before a call printed as still there after it. Tier 3 exports change in 6 functions on
  the clean fixture (1,031 lines), 5 on 2.19.6, 8 on 3.4.4 and 6 on 3.10.9,
  `ColorScheme`'s `copyWith`, `fromSeed`, `hashCode` and `lerp` and `ThemeData`'s
  `copyWith`, `lerp` and constructor among them. obf does not change, as its export lifts
  none of the functions with such an access. Closes #137.

- **A negative number and a 32-bit shift read as Dart reads them.** Tier 3 gave a
  negative literal the precedence of a name, so `neg` of it printed `--128`, which is
  Dart's decrement, a field read off it `-128.field_0x8`, which Dart reads as
  `-(128.field_0x8)`, and `neg` of a `neg` printed `--x1`. They print `-(-128)`,
  `(-128).field_0x8` and `-(-x1)` now. A 32-bit shift right, `lsr w` or `asr w`, printed
  as a shift of the 64-bit register, which shifts its top half into the low 32 bits; it
  reads the low half now, `(x1 & 0xffffffff) >>> 3` and `x1.toSigned(32) >> 3`, except
  where the value is already masked to fit, as w values and hash mixing mostly are. A
  compressed Smi untagged with `asr w` comes out negative where it is. Tier 3 exports
  change by 42 lines on the clean fixture, 114 on 2.19.6, 52 on 3.4.4 and 40 on 3.10.9;
  obf does not change. Closes #130.

- **A goto into a loop's head reads no name and no value the goto skipped.** A loop
  head a goto also reaches was left out of the goto join's rules, because the loop binds
  its own names there, and the way in the walk did not take brought a state it never
  saw: the body read a name set only on the walked way in, and a value only that way
  left in a register (a 5 stored where the goto's way still has the register it came
  with). The goto join's meet, over the ways into the loop and not its latches, now
  applies there before the loop binds its names, with the rule for names of #121. And
  an instruction that keeps part of its destination, `movk`, `bfi`, `bfxil`, or a lane
  insert as capstone prints it (`mov v0.s[1], w3`), counts as reading it, so liveness
  sees the read and a raw one says what the register held. Tier 3 exports change in 11
  functions on the clean fixture (50 lines), 9 on 2.19.6, 11 on 3.4.4 and 13 on 3.10.9,
  each a value the ways in disagree on that now prints as its register. Closes #125.

- **A field saved in a frame slot across a call keeps the value it had when it was
  saved.** Tier 3 tracks what a slot `[x29, #d]` holds as the text stored there, so a
  field spilled before a call and reloaded after it printed as a fresh read of the field,
  which the callee may have rewritten, and often off a register the call had already
  clobbered. A concurrent modification guard, the length saved before a callback against
  the length after it, read as a field compared with itself: `_filterWhere` and
  `updateChildren` on the clean fixture, `lastWhere` and `markNeedsLayout` on 2.19.6. Such
  a value is now named where it is stored, `var t3 = this.field_0x10;`, when a reload of
  it after a call is printed: a backward dataflow over the frame slots finds those
  stores, a reload that only feeds a call's printed arguments counts as printed, and a
  spill written back unchanged around a call is not a new store, so the store before it
  is the one named (recognised within one block; see FINDINGS.md). Naming at the store
  puts the name above any `if` or loop the call is in, so the arms agree at the join and a
  loop does not read the field again on each trip. A name nothing ends up printing is
  left out, except where it is all an arm of an `if` holds, and one whose only use is the
  next statement folds back into it, in brackets unless it is one term. Field
  self-comparisons in the `export -t 3` go from 4 to 2 on the clean fixture (the two left
  are `fcmp` NaN checks), 15 to 14 on 2.19.6 and 3 to 2 on 3.10.9, and stay at 2 on 3.4.4;
  no build gains one. On the clean fixture 1,404 of 4,982 functions change, in 174 files,
  and the export grows from 143,760 to 147,637 lines; 4 of 166 change on the obfuscated
  fixture, and 1,354, 1,288 and 1,287 on the 2.19.6, 3.4.4 and 3.10.9 corpus builds. On
  8,000 generated functions that spill fields across calls and loops, run on the CPU,
  main's printed program disagreed with it on 1,378 and never ended on 2,357; it
  disagrees on none now and always ends. Lifting every range of the clean fixture takes
  8.1 s against 7.1 s before. A `ret` neither its callers nor its code decide, which
  falls back to d0 because d0 was written last, prints `return d0;` rather than what d0
  holds: with the spill named, `StadiumBorder.lerpFrom` returned the field where the
  machine returns the object it allocates. Part of #64; the trap rule is not in this
  change.

- **A loop that keeps a counter in a frame slot no longer reads the slot's first value on
  every trip.** The walk of a loop starts from the state before it, so a slot the body
  stores a new value to printed its pre-loop text at the top of the loop: a counter kept
  in a slot read `(1 + 1) >= 0xa`, a loop that never ends, where the CPU counts to 10 and
  returns. A slot the loop stores a new value to and reads at its top is forgotten there,
  and the reload prints its register. One it only writes back with the value it already
  held keeps it, and a store on a path that throws does not count, since tier 3's graph
  still runs on past a trap and past a throw stub with nothing after it. Closes #109.

- **A write to any spelling of a SIMD register reaches the double in it.** `d0`, `v0.16b`
  and `q0` are one register, and tier 3 tracked a double under the spelling it was
  written with, so a write under another left `d0` describing the value before it. `eor
  vN.16b, vN.16b, vN.16b`, which is how the VM loads 0.0, did exactly that, and so did
  `movi`, `ldr q0`, `ins v0.d[0]` and a call: the clean fixture's `lerp` printed its
  clamp to [0.0, 1.0] as `(d0 * x3.field_0x8) > (...)`, comparing a product the machine
  had just zeroed, and stores, returns and comparisons all over printed a bare `d0` or an
  older value where the machine has 0.0. The zeroing idioms are 0.0 now, any other write
  under another spelling makes the double unknown, and a call clobbers a V register under
  every spelling. An `if` whose arms leave different doubles in a register, one of them
  a literal, now names it at the join as it does for any other value, where it printed
  nothing and left a bare `d0` after, except where the other arm's double is the bare
  register, which a join inside that arm can leave where the value is lost. Tier 3
  exports change in 142 functions on the clean fixture (8,484 lines in 65 files, the
  export growing from 135,343 to 137,015 lines, most of it such an `if`), 175 on 2.19.6,
  183 on 3.4.4 and 154 on 3.10.9; obf does not change. Run on a CPU, those functions
  print 118, 590, 286 and 117 values right that main printed wrong, and 19 that main
  named right go bare, all in one function, the `pow` cases of `_findResultByJ`.
  `st1 {v0.16b}` now reads d0 too. Closes #114.

- **A `ret` hands back x0 unless something proves a double.** Tier 3 printed whichever of
  x0 and d0 a path wrote last, so a function that allocates an object and then fills its
  double fields printed its last field value as what it returns: `Rect.topRight` on the
  3.4.4 corpus build printed `return t1;`, the field, where it returns the Offset in `t0`.
  The snapshot cannot say which register comes back on any of the 18 registered releases:
  `Function::has_unboxed_double_return` reads `unboxed_parameters_info_`, which the AOT
  runtime compiles out and the Function cluster never writes. So the code says it. d0
  comes back when the function's callers read d0 after their `bl` to it, when a path to
  the `ret` never writes x0 but writes d0, or when a d0 the function wrote reaches the
  `ret` with nothing else reading it, a slow path's restore aside; x0 when its callers
  read x0, or when what d0 holds there was only ever stored. A `ret` none of that decides,
  such as a double summed in a loop that leaves x0 as scratch, keeps the old rule, and
  where that is d0 says only the register (see the frame-slot entry). Tier 3 exports
  change in 112 functions on clean, 103 on 2.19.6, 111 on 3.4.4 and 113 on 3.10.9 (265,
  255, 264 and 262 lines), and in none on obf. Of those 439, 296 are confirmed by their
  callers and the other 143 were read against the arm64, 118 of them returning a fresh
  allocation untouched; every one named a register its function does not return. Across 52
  arm64 builds, these five and 47 apps, 145,939 functions write V0: none the code proves
  returns d0 has callers that read x0, and the 424 whose callers read d0 where the code
  chose x0 print the same either way. The issue's loose count, functions that fill an
  object and return another temp, goes from 147 to 117 on 3.4.4, and every `ret` of those
  117 returns x0: the object they fill is not what they return. Tiers 1 and 2 are byte for
  byte as before. Closes #115.

- **A goto's target reads what the goto left.** A block only a goto reaches is lifted
  from the state its one predecessor left, and that state was taken before the printed
  program writes loop names back on the way there: in the goto's own write-back, and in
  a `break`'s when the goto follows a loop. So the target read a name with the meaning it
  had before the jump. 2.19.6's `parsePartialKeyword` returned `t4 + 1` right after
  `t4 += 1;`, one more than the machine does, and 3.4.4's `parsePartialString` passed `t0`
  to `chunkStringEscapeU` where the machine passes the `t0` from before `t0 = x0;`. The
  target now starts from the state as the jump leaves it: a value spelled as one of the
  registers the write-back copies reads as that name, any other value that mentions a
  name about to change is written out first (`var t27 = t0;`) where the target can read
  it, and what a `break` on the way wrote back is taken from the state past its loop. A
  function where some of those turn out unread is lifted again without them, 98 of the
  clean fixture's 8,194, so nothing else is renumbered. The tier 3 export changes in 4
  functions of the clean fixture, 8 of 2.19.6, 4 of 3.4.4 and 5 of 3.10.9, and in none
  of the obfuscated fixture; tiers 1 and 2 are unchanged. Run on a CPU with random
  inputs, those functions reached 12 of their 26 changed targets, where main printed 38
  register or slot values the machine contradicts: 10 now read right and 28 print the
  bare register. No value in them reads wrong now that main had right. A value written
  out before a goto is kept past a later join its target dominates, and a crafted
  function's write-outs stop at 2,048, past which a value is forgotten: one with 4,000
  slots and 250 gotos took 6 s and a gigabyte. In `tools/bench.py`, `export` and the
  whole-image `lift` take 4 to 5% and 3 to 4% longer. `tools/irfuzz.py --nested`
  generates a loop in a loop with a branch out of both, which no generated graph had:
  with `--cfgmem --seed-outputs` it finds 4, 8 and 3 mismatches in 500 graphs on main at
  seeds 1 to 3, and none now. `--cfg` scores the state the return is lifted in, as
  `--cfgmem` does: the mismatches it reported on main at seed 2, and at seed 7 with 1,500
  graphs (#125), came from the last block printed, not the return. Its trials draw from
  a generator of their own per graph, so what one graph scores no longer moves the
  graphs after it. Closes #106.

- **A bit field reads as wide as it is.** `sbfx` carries the top bit of its field up,
  and tier 3 printed it as `(x >> lsb) & mask`, which clears it, so a negative field read
  as a large positive one. `sbfiz` and `ubfiz` printed `x << lsb` and kept every bit
  above the field, and at `lsb` 1 printed the bare source as a Smi tag whatever the
  width: the clean fixture's `hashCode`s, `ubfiz x0, x0, #1, #0x1e`, returned their hash
  without the `& 0x3fffffff` the machine applies. And `ubfx` put its source in
  unbracketed, so `x1 & x2` read as `x1 & (x2 >> 4)`. They print `(x >>
  lsb).toSigned(width)`, `x.toSigned(width) << lsb`, `(x & mask) << lsb` and `((x1 & x2)
  >> 4) & mask` now, and a field that runs to the top bit as a plain shift. Only the Smi
  untag `sbfx #1, #31` and the Smi tag `sbfiz #1, #31` or `#63` keep the reading they
  had, `x >> 1` and the value itself (see `tools/irfuzz.py`); the hash is tagged in the
  open now, `<< 1`. Tier 3 exports change by 6 lines on the clean fixture and 4 on each
  of the 2.19.6, 3.4.4 and 3.10.9 corpus builds. Closes #124.

- **A raw line says what the registers it reads hold.** A raw line reads the machine
  registers it names, and tier 3 holds most registers as expressions it prints only where
  something reads them, so a register a raw line read could hold a value the printed
  body never gave it: `add x1, x1, #8; adcs x1, x1, x3` printed the `adcs` alone, which
  reads as working on the entry x1. The line now says what each such register holds,
  `adcs x1, x1, x3   // x1 holds x1 + 8`, in a comment rather than an assignment, so the
  printed body still assigns a register only where the machine's own instruction does.
  On the clean fixture's `export -t 3` that is 369 raw lines in 207 functions, 114 of
  them a `subs`, 75 a `br`, 49 an `ands`, 46 a `csel` and 31 an `ldar`; 348 in 191 on
  3.4.4. A name such a comment reads keeps its declaration, so a call's result it
  mentions is no longer folded into the next line (`var t3 = lerpDouble(...)`). A
  flag-setting instruction also no longer names the old value of a destination it does
  not read, as `subs x1, x0, x2` named x1 (#116). Closes #120.

- **A name is read only on paths that set it.** Tier 3 read a name on paths that never
  set it, in three ways. A goto join kept every register no block between wrote, and
  naming a value writes none, so a call's result or a phi named on one path into the
  join was read on the others. A phi bound above an `if` with the value from before it
  was skipped by a `goto` into the arm that left it alone: the clean fixture's
  `resolveAs` declared `var t1 = x0;` inside an arm two gotos jump into, then read `t1`.
  And an arm whose raw line or moved pointer left a register printing as itself counted
  as having left it alone. At a goto join, a value spelled with a name set in a block
  that does not dominate the join is now forgotten, and an arm a goto enters, or that
  prints a write to the register, assigns the phi itself. A definite-assignment check
  over every printed function finds a name read on a path that never set it in 108
  functions of the clean fixture's `export -t 3` before and 8 after, 114 and 3 on
  2.19.6, 93 and 3 on 3.4.4, 100 and 7 on 3.10.9, and in no function more often than
  before. With the changes above and below, tier 3 exports change in 323 functions on
  the clean fixture (2,499 lines in 65 files), 300 on 3.4.4, 298 on 3.10.9, 287 on
  2.19.6 and 82 on obf, and the clean export grows from 141,867 to 142,084 lines.
  Closes #121.

- **A raw line no longer changes what an earlier value reads as.** An instruction tier 3
  prints as it is assigns the registers it writes, so a value the lifter still held that
  was spelled with one of them read as the new value after it: `add x5, x1, #1; subs x1,
  x1, #8; str x5` printed `x1 + 1` for the old x1. Each such value still read later is
  named first (`var t0 = x1 + 1;`), as tier 3 already did before a pointer moves, a
  comparison captured from one is dropped, and every register a raw line writes is
  forgotten. What it writes is read as the architecture defines it: an `ldp` writes its
  second register too, a store-release or an atomic store none, an atomic load-op its
  second register and a compare-and-swap its first, and `st1 {v0.16b}, [x1], x2` moves
  its base; `br` reads its target. A name only another raw line would read is left out.
  A value read only as a call's argument is not counted as read yet (#122). Closes #118.

- **A branch reads the operands its flags were set from.** `subs x1, x1, #8` sets the
  flags from the x1 it is overwriting, and tier 3 rendered the branch after it with the
  x1 that was left: a copy loop in the clean fixture (0x2d32c8) printed `if (x1 == 8)`
  after the raw `subs`, where the machine leaves when the new x1 is 0. A branch's
  condition is rendered from the operands as the flag-setting instruction read them,
  which the lifter already kept for `csel`, and where something reads the flags an old
  value spelled with the register being overwritten is named first (`var t0 = x1;`),
  for a `csel` too. A `cbz` or `tbz` reads its register as it is. Of the conditions
  this changes, 118 of 213 on the clean fixture and 114 of 207 on 3.4.4 were wrong
  after a `subs` or `adds`; the rest follow an `ands`, which reads the same either way.
  Tier 3 exports change by 1,923 lines in 7 files on the clean fixture, 1,803 in 7 on
  3.4.4 and 1,870 in 7 on 3.10.9, much of it later temps renumbered, and by 8 and 12
  lines on obf and 2.19.6. Closes #116.

- **cfgcheck knows which arm of an `if` is taken.** It compared the set of places an
  `if`'s arms go with the set the block's CFG records, never which arm was which, so an
  `if` rendered the other way round, each arm running exactly when it should not, passed:
  #58's class of defect. Under the block's own condition the then-arm has to be the
  branch taken, under its negation the one not taken, for every shape the structurer
  emits (two successors, a branch out, a conditional return, a branch at the cut). Every
  corpus build and the fixtures still read 0, and so do 150,000 random functions. Closes
  #110.

- **cfgcheck holds an arm that leaves to the way its block leaves.** It read every branch
  out of the function or past the instruction cut as one and the same, so a rendering
  that called a branch into the part past the cut a branch out of the function, which is
  #70's mistake, passed; so did a conditional exit pointed at another address, a
  conditional return rendered as an indirect jump, and an exit arm emptied with the
  fallthrough nested in the other arm at the end of the function. Each block's ways out
  are read off its own record now (its branch elsewhere, its conditional return or
  indirect jump, where it runs on past the cut), and its arms have to reach exactly
  those, of that kind and to that address, besides its successors; running off the end of
  the body is the last block's only. Its reports name the ways out, as `exit 0x...`, `cut
  0x...`, `exit return` or `exit indirect`. Every corpus build, arm64 and arm32, and
  120,000 random functions still read 0. Closes #107.

- **`export` writes no asset over another, and blames a failure on the side it came
  from.** An APK's or IPA's assets went where their names said, as libraries did before
  #96: on the Brod & Co. apk with two members added, `Logo.txt` and `logo.txt` left one
  file on macOS, named `Logo.txt` and holding `logo.txt`'s bytes, while `assets.txt`
  listed both; a file another member needed as a directory refused the whole archive with
  exit 2 once the sources were written; a name the archive held twice kept only the last;
  and jadart's own `NOTICES`, `dependencies.txt` and `AssetManifest.decoded.json` were
  written over assets of those names, on macOS even when the archive's source was only
  `notices.z`. Assets take the library rule now, names held twice and names that clean up
  the same included, and jadart's files come from the members named exactly `NOTICES.Z`
  and `AssetManifest.bin` (the first, where the archive holds the name twice: main read
  the last), are taken before the assets, and are left out where an asset needs one of
  their names as a directory. `assets.txt` lists what each asset was written as and the
  moves, and `summary.txt` counts them. The library rule also renames: a Windows device
  name (`con.txt` becomes `_con.txt`), a control character or one of `<>:"|?*` (`_`), a
  trailing dot or space (dropped), a name past 119 bytes (cut) and a path past 16
  directories, on every platform, where the raw name went to disk before. Every member is
  checked against the size limits before any is written, where one past them refused the
  archive with part of it on disk. A failure writing the output, `<out>/assets` a file or
  a directory it may not write, was reported as `<apk>: cannot read this archive`, a
  `ContainerError` about an archive that is fine; it is an `InputError` naming the output
  directory now, and a failure reading the archive is still its `ContainerError`. The
  four Flutter apks on hand export byte for byte as before. Closes #104.

- **A snapshot's features string is read only as long as a real one can be.** It names
  the build's VM flags and target, in under 160 bytes in every AOT build measured, and it
  was read to its NUL however far away that was, kept whole, and printed whole by `info
  -j` and returned by `jadart.header()`: a 16.8 MB file of two headers whose features
  were the real flags and then 8 MB of `0xff` gave 100.7 MB of JSON and a 208 MB peak,
  every one of those bytes a six-character escape. A features string longer than 4096
  bytes is refused now with an `InputError` (exit 2) that says so; one with no NUL at all
  that runs past 4096 bytes raised `TruncatedSnapshot` before and is that `InputError`
  too, and one that ends inside the bound with no NUL is still reported truncated. The 92
  headers of 46 real libapp.so hold 118 to 156 bytes and read as before. Closes #101.

- **`export` no longer writes one library over another.** A library goes where its url
  says, and nothing checked that two did not land in one place. Obfuscation names
  libraries by short tokens, and `Ahd` and `ahd` are one file on macOS and Windows: the
  second overwrote the first, so on a Mac the obfuscated fixture's export listed 307
  libraries and held 208, HiveHex lost 128 and an obfuscated flagcheck build 129, without
  a word. A library whose file another needed as a directory (`package:zz/foo` and
  `package:zz/foo.dart/bar`) ended the export with exit 3, and so could a long url under
  a long output directory, past the 1024 bytes macOS takes in one path. Each library's
  path is now held unique under Unicode's canonical caseless match, which is how APFS
  compares names: the first in sorted order keeps its name, a path another library needs
  as a directory stays one, and the file that gives way takes `~2` (or the next free
  number) before `.dart`, on every platform alike. `summary.txt` lists each move, the
  terminal says how many, and `-j` gives them as `renamed`; the `files` list names the
  new paths. On a disk that ignores case this recovers the libraries main lost; on Linux,
  where main wrote both of each pair, those 356 files across the three builds keep their
  contents under the new names. A path component is held to 120 bytes of UTF-8 rather
  than 120 characters, which ext4 refused past 255 bytes, a Windows device name is caught
  after that cut as well as before and now takes in COM0, LPT0 and the superscript
  digits, a path goes at most 16 directories and 400 bytes down (real ones go 3 and 71),
  a lone surrogate is replaced like any character a filename cannot hold, and a file name
  that cuts to nothing is `unnamed.dart`. A library whose url is `_unattributed` lost its
  classes to the ones with no library; those go beside it now, and the summary names the
  file they went to, or says `-a` left them out, where it named a file `-a` never wrote.
  An output directory that is a file, or under one, is refused before the binary is read,
  and any failure to write the sources or the listings beside them (permission, a full
  disk) is an `InputError` (exit 2) naming it, where those were exit 3 too; assets are
  #104. On the fixtures, four corpus builds and the CTF apps, every file main wrote has
  the same contents. Closes #96.

- **A branch out of the function from inside a loop or an `if` reads as one.** cfgcheck
  read a branch out of the function, or past the instruction cut, as nothing at all, so
  an arm that leaves claimed whatever followed it and the check reported an edge the
  rendering never claimed: random small functions turned up about 30 to 50 per 90,000,
  every one of that shape. It reads them as leaving now, and holds an arm that leaves to
  the block's own way out, so a rendering that drops an exit is caught where it passed
  before, and a block that only branches out has to be followed by saying so, where a
  jump back into the function there passed; every corpus build still reads 0. Tier 3 left
  a loop through such a branch without writing the loop's names back, as a `break` does,
  so they said nothing of what the registers held where control left; the innermost
  loop's are written back now, as for a `break`. No corpus build or fixture has that
  shape, and their tier 3 exports are unchanged. Closes #86.

- **`signatures -o` into a path it cannot write exits 2.** A missing directory, a
  directory, a path under a file, a directory it may not write or a name too long raised
  the `OSError` from opening the file, and the CLI reported it as a bug in Jadart, with
  exit 3. Each is an `InputError` (exit 2) naming the path now, and the first three are
  refused before the references are read, so they no longer cost a build first; so is an
  empty `-o`, and so is a reference given as `-o`, or the libapp.so inside a reference
  given as a directory, which the library used to be written over. A write that fails
  part way, on a full disk say, or at Ctrl-C, leaves no library cut short behind, since
  one loads as a smaller library with nothing to say so: the file is emptied through its
  own descriptor, which reaches it behind a symlink or a hard link too, and removed while
  the path still names it. A broken pipe on `-o /dev/stdout` is that same exit 2, where
  it was 0. Closes #97.

- **A stripped binary is read for two snapshots at most.** With no `_kDart*SnapshotData`
  symbols, the snapshots are found by scanning for their magic, and each hit was parsed
  out of a copy of the rest of the file and listed: an ELF of 201 byte snapshot headers
  took 2.5s at 8 MB and 9.7s at 16 MB, four times that for each doubling, and `info`
  printed 459,074 lines for the 8 MB one, while a 32 MB file of nothing but the magic
  peaked at 429 MB listing its offsets before it was refused. A library holds two
  snapshots at most, the vm and the isolate one, so the scan stops at a third and refuses
  the file with an `InputError` (exit 2) that gives the offsets, before any is parsed;
  `jadart.header()` and `jadart.parse_libapp()` raise it where they returned a `blobN`
  for each. Each of those files is refused in 0.04s. A file with a third hit that did not
  parse was refused before too, with that hit's parse error; it is the count that is
  reported now. Each of 46 real libapp.so has the magic exactly twice, and with its
  section headers removed still reads to the two headers its symbols name. Closes #99.

- **A container's tables cannot cost more than the file.** An ELF or Mach-O gives the
  offset of each symbol's name, of each symbol table and of a segment's sections, and
  their counts, and nothing stopped them from overlapping, so a crafted file made every
  command pay a product before it ran: a symbol at each byte of one 20,000 byte name
  kept 200M characters and 260 MB from a 500 KB ELF, and as much from a 340 KB Mach-O;
  5,000 ELF section names into one long string kept 87M characters from 340 KB; 2,000
  section headers on one symbol table read it 2,000 times, 24s for 1.4 MB, and 2,000
  Mach-O symbol table commands on one table took 25s for 1 MB; 2,000 Mach-O segment
  commands each claiming 2,000 sections they do not hold made 4M sections and 554 MB
  from 304 KB. Symbols that all name one string read it whole once each, and a file that
  is half one name and half symbols on it took 29s to read as a 3.2 MB ELF and 76s as a
  3.2 MB Mach-O, four times that for each doubling. Finding a Mach-O snapshot blob's end
  also looked its section up again for each `_kDart` symbol, symbols times sections:
  0.61s at 383 KB, four times that for each doubling. A symbol on a name offset read
  already is skipped now, since the first symbol of a name is the one kept, and the
  names, the symbol tables and the Mach-O section headers each refuse the file with a
  `ContainerError` (exit 2) once reading them comes to more bytes than the file has,
  which only overlap can do: a table that runs past the end of the file says so first.
  The blob's end needs no lookup, since it is inside its section already; only where
  sections overlap, which they do in none of the 2,447 real Mach-O files, can it come
  out shorter than before. Each of those files is refused, or read, in under 0.03s and
  45 MB. Over 4,537 real ELF and Mach-O files, the corpus, the fixtures, the CTF apps
  and the NDK and Homebrew libraries among them, names came to at most 0.45 of the file
  and symbol tables to 0.68; 99 hold names sharing a tail, which a budget of the string
  table's size would have refused; and every one reads to the same symbols, sections and
  `_kDart` blobs as before. Remembering the offsets read costs a large symbol table a
  little: libwireshark's 524K symbols open in 0.54s and 438 MB, from 0.47s and 389 MB.
  Closes #95.

- **A long name is cut wherever it prints.** One string names every function that
  shares it, a class name comes back in each of its members and a library url in each
  of its classes, and nothing cut a name, so a long one cost the output its length at
  every one of them: on the clean fixture, making `build` 20,000 characters long added
  1.8M characters each to `functions` and `classes`, 2M to a tier 1 export and 3.6M to
  `symbols -j`. Names from the snapshot, ELF symbol names, `--sigs` names and library
  urls are cut where they print now, `jadart.program()` included: past 200 characters
  as printed, a name ends in `\... (N chars)`, N its length as written, which no name
  can spell, since a backslash in a name always prints as the start of an escape. That
  spelling is the one `decompile`, `disasm`, `xrefs`, `hook` and `symbols -f` take
  back, and a `--sigs` name keeps its `~` after the cut. `functions`, `classes`,
  `libraries`, `selectors`, `symbols` in every format, `decompile`, `disasm`, `xrefs`,
  `hook` and an export print as much for a 20,000 character name as for a 40,000 one,
  but for `strings.txt`, which prints each string once and whole; an export names a
  file after what is left of a cut url, without the mark. `symbols -j` keeps names as
  written: `name`, `owner` and `library` are cut at 200 characters, `qualified` is the
  cut owner and name joined, and a record with a field cut gives its whole length
  under `cut`. A cut name there is not one `hook` or `disasm` can find; its `va` is.
  `cut` is a new key, so the format version stays 1. `signatures` leaves a function
  whose name is longer than 200 characters out of the library, as it does one holding
  a line break; it writes the same library from both fixtures and the 3.12.2 build as
  before. `FillResult.names` escapes a string once, not once per ref on it. The longest
  name in the fixtures, the two CTF apps in ctfbench and the corpus is 165 characters,
  so exports at tiers 1 to 3 (1 and 2 for arm32), `functions`, `classes`, `libraries`,
  `selectors`, `decompile`, `hook` and the `-j` of `functions`, `classes`, `libraries`
  and `symbols` are byte for byte the same on both fixtures, those CTF apps and the
  2.19.6, 3.12.2 and two arm32 corpus builds. The `symbols` table and the IDA, Ghidra
  and radare2 scripts cut a qualified name at 200 already; the cut gains its backslash
  there, on 5 names of the clean fixture and 8 of the 2.19.6 build. Closes #94.

- **A crafted pool cannot make the const lists cost a product.** Nothing bounds how
  many pool slots name one object, or how many refs share one RO data string, and the
  const list paths paid for each again: an Array was resolved once per slot naming it,
  in `constants` and in the labels that every command naming pool entries builds,
  `quoted()` escaped all of a long string before cutting it to 200, and the fill decoded
  a RO data string once per ref on it, and once per string over bytes that strings
  overlapping it had decoded already. On stand-in pools, 3,000 slots reaching one 3,000
  element list took 0.34s to label and printed 62 MB from `constants` (123 MB with
  `-j`), and 3,000 lists of one 20,000 character string made 60 MB of labels and of
  `constants`; 3,000 refs on one such string in RO data made a 60 MB fill, and a 33 KB
  image of strings 16 bytes apart, each running to its end, filled 34M characters and
  127 MB of `constants`. Each Array and string is now resolved, decoded and quoted once,
  `quoted()` reads no further than its cut, the fill refuses RO data strings that come
  to more characters than the file has bytes, which only overlapping ones can (the 13
  arm32 corpus builds use 15% of that), and `constants` prints each thing once: a slot
  reaching a list already listed says `same as 0x...`, and a string whose escaped text
  runs past 200 characters is whole where it first appears and `same as 0x...[i]` where
  it comes back; `-j` says both with `same_as`. The same pools label in under 0.01s,
  list in under 1 MB, and fill in 0.3 MB. `constants`, its
  `-j` and exports at tiers 1 to 3 (1 and 2 for the corpus builds) are byte for byte the
  same on both fixtures, the two CTF apps in ctfbench and the 3.12.2 and two arm32
  corpus builds: none names an Array from two slots or holds a list string over 25
  characters. Closes #91.

- **A string in a const list label is cut at 200 like any literal.** `const[N]{...}`
  printed its string elements whole, where the same string in its own slot is cut, so
  one long string cost its length at every slot and use site naming the list. Closes
  #92.

- **`constants` quotes a list's string elements.** `constants` and `export`'s
  `constants.txt` printed them bare, joined by `, `, so a crafted list could not be read
  back: `["a, b"]` read as two elements, `"0x10"` as the int 0x10, and `""` as a gap.
  They print as the `const[N]{...}` label prints them now, in quotes with a quote inside
  escaped, and whole. Of the 39 lists in the fixtures, the two CTF apps in ctfbench and
  the 3.12.2 and two arm32 corpus builds, the 18 that hold a string change by their
  quotes alone and the rest not at all; none of them was ambiguous before. Closes #88.

- **A quote in a string literal does not end it.** A literal printed between double quotes
  kept a `"` in it raw, so on its line the literal ended early and what followed read as
  code: a string `a" ; isAdmin = true; x = "b` lifted to three statements, and the clean
  fixture's ASCII table read as `"... !"` and then code. The quote is `\"` now wherever a
  literal is quoted, a pool label at every tier and a const list element, and
  `xrefs string` and `strings -g` take it as typed or as printed. A literal whose
  escaped text runs past 200 characters is cut at the end of an escape; 6 cuts in the
  pools of both fixtures, the two CTF apps in ctfbench and arm32-2.19.6 left half of one.
  Over their exports at tiers 1 to 3 (1 and 2 for arm32), 669 lines change: 477 by the
  escape alone, and 192 are long literals whose cut moved. Nothing else does. The arm64
  disasm samples the tests pin move by 6 and 2 lines, all such notes, and are
  regenerated. Closes #83.

- **A function nested too deeply to structure prints its rows.** `structure` and the
  renderers recurse once for each level of nesting, so a range of 500 conditionals
  nested in each other, which only a crafted binary holds, ran out of Python's stack:
  `export -t 2`, `decompile` and `lift` raised RecursionError and exited 3, a bug in
  jadart. Such a function now prints its instructions at their addresses, under
  `// nested too deeply to structure`, and the rest of the output goes on; cfgcheck
  counts it apart. Nothing in the fixtures or the corpus nests that deep, and their
  output is unchanged. Closes #81.

- **A function cut short says where it goes on.** The instruction cut stops a long
  function after 4,000 instructions. A conditional there whose target is earlier had its
  not-taken arm recorded nowhere, so `mov; cmp; b.gt #0x0` printed as a loop with no way
  out, `while (true) { }` at tier 3 and an `if` with an empty arm inside one at tier 2,
  and a last instruction that falls through ended the body with nothing said. A branch into the part left out printed as `goto sub_0x...`,
  which names another function, though the address is inside this one: 2,679 lines in
  the 46 cut ranges of the corpus's 26 builds. Each now reads
  `goto 0x...;  // TRUNCATED: past the instruction cut`, the address as `disasm` prints
  it, and cfgcheck checks the fallthrough past the cut is printed. No range of the
  fixtures is cut, so their output is unchanged; on the corpus, `export -t 2` adds one
  such line, to `ColorScheme.fromSeed` in five arm32 builds, and changes no other. Closes
  #70.

- **A branch's condition reads the compare arm32 puts further back.** The condition was
  read from the instruction right before the branch, and on arm32 that is often not the
  compare: 8,606 of arm32-2.19.6's tier 2 conditions printed as `? op ?`. It now reads a
  double compared with `vcmp.f64` then `vmrs`, the 64-bit equality `cmp; cmpeq` as
  `a == b && c == d` (and `bne` as its negation), the Smi tag test `asrs rD, rS, #1; blo`
  as `(rS & 1) == 0`, and a second branch on the same compare, which starts a block of its
  own, from its one predecessor when that falls into it on a branch that sets no flags. A
  floating-point `vs` is the NaN test it is, `isNaN(d0) || isNaN(d1)`, where it printed
  `d0 vs d1`. A condition with `&&` or `||` negates as a whole, `a != b || c != d`, where
  flipping its first operator alone gave `a != b && c == d`, and a negated `!(c)` is `c`.
  On arm32-2.19.6's `export -t 2` 48 condition lines hold a `?` where 8,606 did, and on
  the clean fixture 31 at tier 2 and 57 at tier 3 where 105 and 131 did. Only condition
  lines change, 8,558 on arm32-2.19.6, 291 and 245 on the clean fixture at tiers 2 and 3;
  the obfuscated fixture's export is unchanged. Part of #70.

- **Tier 2 prints the code no edge reaches.** It placed only the blocks the entry reaches,
  so a block that only an exception edge, a jump through a register or a second entry
  leads to was in no statement, and nothing in the output said so: in 1.2.0, 8,580 of the
  clean fixture's 457,622 instructions, many of them catch entries that open with
  `sub x15, x29, #imm` right after a `ret` or a `b`. `decompile -t 2` and `export -t 2`
  now place every block, the unreached ones after everything else. A section that no block
  branches into, including the code after a trap that #57 places, follows a note,
  `// reached by no edge in this graph`, that lists what it can be: a catch entry, another
  entry point, a jump through a register, or dead code. An unreached tangle too deeply
  nested to structure is counted in a note instead, so that placing it cannot turn a
  crafted binary into a crash (#81 is the same limit on reachable code). Every decoded
  instruction of the clean fixture and arm32-2.19.6 is now in tier 2. The export only
  gains lines: 7,305 with 221 notes on the clean fixture, 2,964 with 70 on the obfuscated
  one, 2,001 with 56 on arm32-2.19.6. Tier 3 is unchanged, since `strip_boilerplate`
  leaves the stack check's slow path unreached on purpose. Closes #67.

- **Literals, two header fields and container listings print escaped too.** #74 escaped
  names; string literals went through `printable()`, which escaped C0 controls, DEL,
  surrogates and NEL/LS/PS and let C1 controls and format characters through, so a literal
  holding U+202E reversed the line it was printed on. On the clean fixture `strings.txt`
  carried 150 raw C1 characters, three bidi embedding characters, two soft hyphens and two
  no-break spaces. `printable()` now escapes what a name does (`fill._hides`): `\xNN`
  below 0x100, `\uNNNN`, and `\UNNNNNNNN` past the BMP, where `\u` would read ambiguously;
  a string that needs no escape is returned without a walk over it. `info` escapes the
  header's `features`, and its version hash, which `--lenient` prints unvetted. A
  container's member paths in `assets.txt` and in `summary.txt`'s "worth a look", its ABI
  directories in `container.txt` and the NOTICES package names in `dependencies.txt` are
  escaped like names. A pool label is the string as printed, so these strings print
  escaped in `disasm`, `decompile`, `xrefs` and the pool listings as well; on the clean,
  obfuscated and arm32-2.19.6 binaries, across `functions`, `classes`, `libraries`,
  `selectors`, `symbols`, `strings`, `info`, `constants` and `export -t 2`, that is 54
  lines, each the old line with only the new escapes. `xrefs string`, `strings -g` and
  `libraries -g` take a pattern as typed or as printed. An emoji built with U+200D or
  U+FE0F shows those as escapes. A signature library hashes pool labels, so one built
  before this may miss a function whose first instructions load such a string; on both
  fixtures the libraries come out identical. Closes #78.

- **Names from the binary print escaped, and read back that way.** Function, class,
  field and library names come out of the same strings as literals, so a crafted snapshot
  can put an escape sequence, a carriage return, a bidi override or a zero width space in
  one, and so can a hand-written `--sigs` library or the ELF symbol table. Literals were
  escaped with `printable()`; names reached every text surface raw, so a terminal ran the
  escape sequence and an agent read the bytes. Every name is now escaped the way `symbols`
  and `hook` already escaped theirs (`fill.visible`, moved from `interop`), as a `\u`
  escape, and the escaped spelling is what `decompile`, `xrefs`, `disasm`, `lift`, `hook`
  and `symbols -f` take back. `-j` carries the escaped names too, and so do the names the
  Python API returns (`program()`, `selectors()`, `decompile()`); `program().strings`
  stays the raw literals. `symbols -j` and the hook and symbol scripts keep a name as
  written, as they did, and escape it where they print it. A name the compiler wrote
  needs no escape and costs an `isprintable()` and a regex search, and the output of
  `functions`, `classes`, `libraries`, `selectors`, `strings`, `symbols` and `export -t 2`
  on both fixtures and arm32-2.19.6 is byte-identical to before. Closes #74.

- **The fence check reads `.MD` and `.markdown` files, and a heading after a quote in a
  list.** `--tracked` asked git for `*.md`, which it matches case sensitively, so
  `Guide.MD` and `notes.markdown`, which GitHub renders, were never checked; it asks for
  both extensions in any case now. And a quote marker after a list marker (`- > # x`)
  under HTML was not read as the heading line it is, which holds what the HTML above it
  left open; it is refused now, as `- # x` was. The docs in the repository still pass.
  Part of #48.

- **The fence check reads HTML anywhere in a line, and an element left open to the end.**
  It checked HTML only on a line opening with `<`, so `# <br> <table><tr><td>` put the
  rest of the page inside a heading and `* [<b>]` left a bold element open over it. No
  HTML may stand in a line of Markdown now, outside a code span, an autolink or an escape.
  Code spans are read a line at a time, which is how a renderer reads them when no earlier
  line of the paragraph leaves a run of backticks to pair with a later one and no link's
  destination, title or reference label takes one first, so `<` markup in a code span
  after either is refused, and a table row is read cell by cell too. YAML front matter is
  read as Markdown, since markdown-it and cmark render it. A top-level table, row, cell,
  div or p left open to the end of the file held the rest of the page and was not
  reported. Each now ends with its own end tag, in the order they opened, read with one
  stack of open elements, which a `<div></div>` in a list cannot pop for one left open at
  the top. An end tag closes one opened on an earlier line only where it is sure to be
  HTML, on the first line of a block at column 0 or in a block a block tag opens, since
  `    </div>` after a blank line or `-     </div>` after a paragraph is code.
  Three code spans in EVAL.md and FINDINGS.md that went on to a second line now fit on
  one, the issue template's title says `VERSION` where it said `<version>`, and the docs
  pass. Closes #48.

- **A signature library survives a crafted reference, and its lines are read to a bound.**
  `save()` wrote each name raw after a tab, so a name holding a line break split its entry
  and `load()` refused the library it had just written, and a name ending in `\r` came
  back without it. Names come from the reference binary, so only a crafted one has such a
  name: `build()` now leaves that function unsigned, and a `# from` source path, which is
  only shown, has its line breaks spelled out, as well as any byte that is not UTF-8,
  which raised an untyped error from `save()`. And after a valid header a line with no
  newline was read whole, so `--sigs <(printf '# jadart-signatures-1\n'; cat /dev/zero)`
  read until memory ran out; a line longer than 1 MiB is now refused with its path and
  number, an input error, in 0.15 s for that command. A library built from the clean
  fixture is byte-identical to before. Closes #49.

- **`xrefs` says which matching entries no code loads, instead of dropping them.** #22
  listed only the pool entries with a direct load, so `xrefs FILE string e` counted 1,113
  of the 1,444 entries 1.1.0 reported, with nothing said about the 331 left out, and
  `ifAbsent`, which matches 5 entries none of them loaded directly, answered "nothing
  matching 'ifAbsent' was referenced" and exited 1. No direct load is not no reference: a
  closure or a value built at runtime can reach the entry. The listing still keeps to the
  entries with loads; the text output then says how many matched with none, `-j` lists
  them under `"unloaded"`, and a pattern or pool offset that matches only such entries
  lists them, says so and exits 0, as 1.1.0 did; its `-j` is `"ok": true` with
  `"count": 0`, where 1.2.0 gave `"ok": false`. With `--class` nothing changes, and no
  `"unloaded"` is reported. A miss on an explicit `string` or `pool` kind no longer says
  it looked for a function, which only the 1.1.0 form does. Closes #62.

- **The call graph counts arm32's register calls.** An indirect call site was counted on
  `mn == "blr"`, arm64's name, so arm32's `blx rN` never counted: `functions -j` gave
  `"indirect": 0` for every function of all 13 arm32 corpus builds, and the graph's opaque
  site count was 0, which reads as every indirect call resolved. The call is read off the
  instruction word now (`branches.indirect_call`), as #44 did for direct calls, and the
  word test agrees with capstone on every `blr` of both fixtures and every `blx rN` of the
  13 arm32 builds. arm32-2.19.6's graph holds 6,332 indirect sites in 2,322 ranges, all
  opaque, since only arm64's dispatch is attributed to a selector; the 200 functions
  `functions -j` lists there by default carry 308 of them. Both arm64 fixtures are
  unchanged, at 5,370 indirect sites on the clean one. Closes #54.

- **A conditional branch at the 4,000-instruction cut keeps its taken edge.** When the
  last instruction decoded was a conditional branch whose target lay past the cut,
  `build_cfg` recorded the target neither as a successor nor as the block's exit, so tier
  2 printed an `if` with both arms empty, as if the branch went nowhere. It is the block's
  exit now, and prints as `if (cond) { goto sub_0x...; }`. One range is cut this way in
  the corpus: dart:core's top-level `_createTables` on arm32-3.6.2, 23,680 bytes, which
  `export` does not render, so no export changes. `tools/cfgcheck.py` reported it as the
  one edge violation of that build; it now also checks every branch target capstone reads
  against the graph, which flags that range and nothing else on main's graph across both
  fixtures and the 13 arm32 builds, and 0 now. Closes #58.

- **Tier 2 prints every label a goto names again.** Since 1.2.0 a branch out of the
  function printed `goto sub_0x...` by rebinding the name of `render`'s own label printer,
  so every `L_0x...:` after it in the same body printed nothing while the goto naming it
  stayed: 17 such gotos in the clean fixture's `export -t 2` and 4 on arm32-2.19.6, none
  now. On top of the trap fix below, which already removed one of the 17, the only lines
  that change are the 16 and the 4 labels put back. Closes #66.

- **Tier 2 stops at a trap.** `build_cfg` ended a block only at a branch or a return, so a
  `brk` (arm64) or `bkpt` (arm32) inside a range had an edge to the instruction after it,
  and tier 2 printed the code there as what runs next: 939 `brk` on the clean fixture and
  519 `bkpt` on arm32-2.19.6. Dart puts one after a call that does not return, so that
  code is reached, when at all, by a branch from somewhere else or by an exception. The
  clean fixture's `export -t 2` printed a `goto` straight after a trap 497 times, and
  arm32-2.19.6's 155. A trap now ends its block with no successor (`cfg.TRAPS`: `brk`,
  `hlt`, `udf`, `bkpt`, and capstone's arm32 `trap`). The code after one is still printed,
  as its own labelled section, because it can be a catch entry, which only an exception
  edge leads to: placing only what the entry reaches would have dropped 182 instructions
  in 12 sections of the clean fixture, 5 of them opening with the stack reset a catch
  entry starts with. On both fixtures and arm32-2.19.6, tier 2 prints every instruction it
  printed before and no other. `tools/cfgcheck.py` now reads traps off the instruction
  word, and finds the 939 and the 519 on the old graph and none now. This changes
  `decompile -t 2` and `export -t 2` on arm64 as well as arm32: 87 files of the clean
  fixture's export and 47 of arm32-2.19.6's. Tier 3 keeps the old graph and its output is
  unchanged: with the rule, the concurrent modification guard in `forEach` printed as a
  field compared with itself, a frame slot read back as the field it was loaded from.
  Tier 3 now names such a slot across a call (#64, above), and still keeps the old
  graph, because the edge past a trap also hides weaknesses in its walk that the rule
  would expose. Closes #57.

## 1.2.0 - 2026-10-03

Upgrading from 1.1.0. The `--json` shape is unchanged and only gains fields, but some
values a script may hold on to are different now:

- Every printed address is a virtual address, `_kDartIsolateSnapshotInstructions` plus the
  pc_offset, where 1.1.0 printed `.text+0x..`.
- A bare number given as an address is read as a virtual address when it lands inside the
  image. `.text+`, `isolate+` and `+` keep the pc_offset reading.
- A range with no name is labelled `sub_0x<va>`, where it was `sub_0x<pc_offset>`.
- A bug in jadart exits 3, where it exited 2 as though the input were bad.
- `verify` prints two lines when every gate passes; `-v` prints the table.
- A selector name that rested on a tied vote is no longer printed.
- `xrefs` on a string or a pool entry lists only the entries some code loads directly.
  1.1.0 also listed the matching ones with no direct load, under "no direct loads found":
  on the clean fixture `xrefs FILE e -j` counted 1,444 and counts 1,113, and a pattern
  only such entries match, such as `ifAbsent`, exits 1 where it exited 0. On arm32 the
  same query exits 1 with the reason. A pattern spelled `string`, `pool` or `function` is
  read as the kind now, and exits 2 without a pattern.
- From Python, a path that does not exist raises `InputError`, a `JadartError`, where
  1.1.0 let `FileNotFoundError` through, so code catching `OSError` there has to catch
  `jadart.JadartError`. A crafted file raises a `JadartError` too, not a builtin.
- `--json` names a container's member in `"file"` (`app.apk!lib/arm64-v8a/libapp.so`)
  where 1.1.0 gave a temp path that was already deleted.

### Added

- **`jadart symbols`: the names, at addresses other tools can use.** Every code range with
  its virtual address, file offset, size and the address calls actually enter at, as a
  table, as JSON, or as a script for radare2, Ghidra or IDA that names all of them inside
  the tool. It shares the address model the rest of the release moved to: every address is
  `_kDartIsolateSnapshotInstructions` plus the pc_offset, so a rebased load lines up on its
  own. Verified against the same binary loaded normally, at
  `-B 0x7000000000` in radare2, and imported into Ghidra with `-loader-imagebase`.
  - A script applies nothing to the wrong binary. It resolves the anchor, checks its size
    and then the first bytes of three known functions, and stops on any mismatch: the
    clean fixture's script against the obfuscated build stops at the size, and against a
    copy with one byte flipped inside a checked function it stops at the bytes.
  - Ranges get the bounds the snapshot records, which an analyser cannot work out, because
    a Dart range often ends in a call to a stub that does not return and analysis carries
    on into the next function. On the clean fixture's 8194 ranges, radare2 6.0.9 left to
    itself (`aaa`) finds 6707 of the starts, runs 652 functions past their end and never
    finds 1487; with the script it finds all 8194 and runs none past its end. 65 bodies
    come back shorter than the range, where radare2 ends at a return it can see: the range
    is still flagged from its start, so no code is attributed to the wrong function. That
    holds on a fresh session, after a full `aaa`, and when the script is applied twice.
    Ghidra gives 8194 of 8194 with the exact recorded body, with and without auto analysis,
    and 11051 of 11051 on an iOS dylib; IDA the same against a model of its API.
  - Functions whose Code has a monomorphic entry get a second label where calls land. Such
    a range opens on the switchable-call miss handler, so a label at the range start is on
    code normal calls never execute; the entry is `kPolymorphicEntryOffsetAOT` bytes in (24
    on arm64). 78 ranges on the clean fixture, 83 on iOS, and every one of them carries the
    miss handler's `br x16` at +4, which is what makes the claim checkable.
  - Names on a command line are reduced to `[A-Za-z0-9_]` plus the address, so they are
    unique and cannot be read as a pipe, a redirect or a backtick by the tool consuming
    them. The Dart name as written travels as base64, and invisible characters (bidi
    overrides, zero width, newlines) are escaped to `\uXXXX`.
- **`jadart hook`: a Frida script on the right address, reading the right registers.**
  Android arm64, observation only: `onEnter` and `onLeave` log and nothing is written to
  the process. It waits for `libapp.so` through `Process.attachModuleObserver`, resolves
  the anchor as an export, checks the bytes, and attaches at the entry calls enter at.
  - It reads arguments where the release and the function kind actually put them. From
    Dart 3.4 the fixed parameters of most functions arrive in `x1, x2, x3, x5, x6, x7`;
    before 3.4, and for closures, tear-offs, `dyn:` forwarders, dispatchers, method
    extractors, FFI trampolines, field initializers and irregexp functions in every
    release, they are on the Dart stack with the **last** argument at `[x15+0]`. The
    snapshot hash pins one Dart minor and the Function kind is in the snapshot, so the
    script picks the source rather than guessing, and prints the stack slots either way,
    because whether the global type flow analysis kept one function on the stack is not
    recorded in the snapshot.
  - Values print raw with both readings where the snapshot cannot settle it: an even word
    is shown as a Smi and as an unboxed int, `x22` is named as null, and an odd word is
    named as an object only when it lies in the compressed heap (upper half matching `x28`)
    and its header's class id is one the snapshot has a class for. Class ids come from the
    snapshot's own Class objects plus the epoch's table for the VM's predefined ones.
  - The entry and the bytes it checks have to lie inside the instructions image, and the
    entry inside its own range. Those offsets come from the snapshot, so a crafted one can
    put them anywhere: a Code flagged as having a monomorphic entry but only 8 bytes long
    sends the entry past the end of the image, where the byte slice is empty and the
    script's comparison of no bytes against no bytes passes, which would attach to a live
    process at an address nothing verified. Both bounds are refused with the reason.
  - A code range that starts outside the instructions image gets no address, and how many
    were dropped is said rather than left to read as a binary with fewer functions. When
    every range is outside, that is refused instead of reported as an empty answer.
  - Ambiguity is refused, not guessed: a bare name matching several ranges lists the
    candidates with their addresses and libraries (59% of named ranges share a name), and
    an address has to be a range start or its entry. Anything but Android arm64 is refused
    with the reason.
  - Tested against a running app: hooking a small CTF build on an emulator logged the
    receiver in `x1`, the submitted string in `x2` as `_OneByteString`, and the verdict
    function returning a `Bool`. For comparison, blutter's template reads every argument
    from `x15 + 8*i`, which on Dart 3 holds none of the register-passed ones and whose
    index 0 is the last stack argument rather than the first; its hook address is a
    `0xdeadbeef` placeholder and its first line throws until hand-edited.
- What was run against the real tool, and what was not. The radare2 script was applied in
  radare2 6.0.9 and the Ghidra script imported and run headless under Ghidra 12.1.4
  (PyGhidra). IDA was not available, so its script was checked against a model of
  `ida_funcs`/`ida_name`/`ida_bytes` that enforces IDA's own rules (no overlapping
  functions, `get_func` containment, `get_next_func` ordering) over the real file bytes.
  The script itself says so in its header. That verifies the logic, not IDA's behaviour.
- What is measured here and what is not. The address model is checked on 58 ELF builds and
  an iOS dylib, 546,037 ranges, with no disagreement. The monomorphic entry offset is
  measured on arm64 (2.19.6, 3.0.6, 3.2.6, 3.12.2) and arm32 (3.4.4); the x64 and riscv
  entries in `AOT_ENTRY_OFFSET` are read from the SDK and not measured, because no corpus
  binary targets them, so `entry_va` on those targets is the SDK's number rather than one
  this code has seen. That a range with no Code object has no monomorphic entry rests on
  the obfuscated arm64 fixture, the only obfuscated build here. The register convention
  was confirmed by a def-use scan over every range of 3.3.4, 3.4.4 and 3.12.2, and the
  class-id shift and width by disassembling the real prologues.
- **`xrefs` takes the kind to look for.** `jadart xrefs FILE KIND PATTERN`, with `KIND`
  one of `string`, `pool` or `function`, so a pattern that is both a string in the pool
  and a function name, such as `Future.` on the clean fixture, answers the question asked.
  `--exact` matches a pool string whole rather than as a substring, and for a string or a
  pool entry `--class NAME` keeps only the references from code owned by that class. The
  1.1.0 form, `xrefs FILE PATTERN`, still works and says which kind it took
  (`// resolved as string`). An unknown kind is an input error, exit 2. A pool entry no
  code loads directly is no longer listed; see the list above. (#22)
- **Exit code 3 means a bug in jadart, not in the file.** Sixteen handlers caught every
  exception and reported it as a problem with the input, so pointing a command at
  `libflutter.so` printed a symbol name and exited 2. They catch `JadartError` only now;
  anything else exits 3, names the exception type, and points at `JADART_DEBUG=1` for the
  traceback. Under `-j` it is still one JSON document, with `"internal": true`.
- **An agent skill that installs with one copy.** `skills/flutter-reverse-engineering/`
  holds `SKILL.md` in the layout agent runtimes look for, and the README says how to wire
  it into Claude Code or any other runtime. A test checks its frontmatter, because a skill
  whose name does not match its directory is never offered to the agent.

### Changed

- **Addresses are virtual addresses, not `.text+0x..`.** Every address Jadart printed was
  an offset into the isolate instructions image, labelled as though it were an offset into
  `.text`. The two start at different places, because `.text` also holds the VM
  instructions image in front of the isolate one, so the label named code somewhere else
  entirely: 0x16a80 out on the clean fixture, and a different amount per build (0x5980 on
  2.19.6, 0x6dc0 on arm32-3.11.5, 0x15f80 on x86_64, 0xc000 on iOS). Anyone pasting one
  into IDA, Ghidra, radare2 or Frida landed inside a different function, and nothing in the
  output offered an address that did work.
  - `functions`, `disasm`, `lift`, `decompile`, `xrefs`, `ffi` and `export` now print the
    virtual address, which is the value of `_kDartIsolateSnapshotInstructions` plus the
    pc_offset. Verified on 58 ELF builds and an iOS dylib against the container's own
    section headers, and against radare2 and Ghidra on the fixtures.
  - `disasm` also rebases the addresses inside a listing and the target of a branch or an
    `adr`, which capstone renders as a pc_offset (80 `adr` on the clean fixture). Every
    address inside the pipeline stays a pc_offset, which is what the object pool, the call
    graph and the lifter are keyed on. In `-j` the `operands` string is left exactly as
    capstone rendered it, so a consumer that parsed it before reads the same thing, and the
    rebased address is a new `target_va` beside it.
  - `functions` prints the rule above the table, and `info` gained an `[addresses]` block
    with the anchor symbol, its address and its file offset. `info -j` carries the same as
    an `anchor` object plus `address_rule`, so a caller holding a pc_offset can do the
    arithmetic without knowing where to look.
  - Every `-j` record that has a `pc_offset` now has the `va` for it as well.
  - A number typed as an address is read as a virtual address when it lands inside the
    image, which is the form now printed, so anything jadart prints can be pasted back and
    reach what it named. `disasm` prints `0x13ef44` inside `FormatException.`, and the
    pc_offset reading returned `sub_0x13ee74` for it; 2506 of the clean fixture's addresses
    sit in the window where the two readings overlap. `.text+`, `isolate+` and `+` still
    mean the pc_offset, for anything written against the older output, and `va+` forces the
    address reading.
- **`jadart functions` is twice as fast, and draws the same graph.** Building the call
  graph ran every code range through capstone and parsed the operand text back into
  numbers, about 0.73 s of the 0.89 s the command took on the clean fixture. A `bl` is
  one fixed opcode with its target in the low 26 bits, so direct edges now come off the
  raw instruction words, found with byte slicing and a regex in about 10 ms for the whole
  image. Capstone still reads the ranges that need operand text, and only those: a `blr`
  in a range that also loads from the dispatch table, since that is the only kind of
  `blr` the dispatch detector can name, and a pool load that could name a function,
  including the two instruction far form. A range decoded for dispatch alone stops at its
  last `blr`. That leaves 17 to 20% of the ranges and 28 to 34% of the instructions for
  capstone across the corpus, and the median `functions` run goes from 0.905 s to 0.458 s
  with peak memory unchanged; `xrefs` on a function name takes the same path. Pool loads
  are read with `_word_load` and `_word_add_pp`, the decoders `xrefs` gained in #27, so
  there is one reading of a pool access rather than two; both agree with capstone's own
  text on every one of the 7,755,621 instructions in the corpus, and a test holds that
  on the fixtures. The graph was compared field by field, list order included, against
  the full decode on sixteen arm64 binaries from Dart 2.19.6 to 3.12.2, with virtual
  sites on and off and with no snapshot names, and every one matches. It is exact because
  capstone decodes every word of every range on all of them, so the words read here are
  the words it would have printed. That premise is about real code. On crafted input it
  can fail: capstone stops at the first word it cannot decode and drops everything after
  it without saying so, while the word reader carries on, so a `bl` placed after a junk
  word now appears in the graph where it used to vanish. A range that still goes to
  capstone keeps the old stopping point. The silent stop itself predates this and is
  filed as #29. An arm32 image keeps the full sweep; the report said
  arm32 raises instead, but capstone's arm backend decodes it, and its graph is unchanged.
  The benchmark baseline was retaken with this, and it is also the first to record #27:
  `xrefs` on a string went from 0.666 s to 0.158 s there. Closes #17.
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
- **`xrefs` on a string or a pool entry reads the instruction words.** It found pool loads
  by disassembling every code range; it now reads the near `ldr` off `x27` and the far
  `add` off `x27` from the raw words, and drops the base when a later word writes that
  register. Output is identical on every pool entry of both fixtures, and the `xrefs`
  workload went from 1.32 s to 0.35 s on that change's own measurement. On arm32 it
  refuses with the reason: 1.1.0 looked for `x27` there too, which arm32 code never uses,
  and answered "no direct loads found" for strings the code does load. Closes #16.
- **`verify` says it once.** A pass printed 22 lines; it prints the tally and the verdict
  now, `-v` prints every gate, and a failure always prints in full and names the gate.
- **The repository.** CI is off, and `./check.sh` runs what CI ran: the suite, the
  acceptance gates on both fixtures, the measured claims and an install with no capstone,
  with `--full` adding the CFG checks, the determinism diff across two hash seeds and the
  benchmark. `tools/bench.py --check` holds every guarded workload to a committed baseline
  (#23). Pull requests need the maintainer's review (#21).

### Fixed

- **A function with no name is labelled by its address, and the label reads back.** An
  anonymous range printed as `sub_0x<pc_offset>` beside a column of virtual addresses, and
  no command accepted the label as input. Its number was the only handle a lifted body
  gave for the call, and pasted back it was read as an address: 799 of the clean fixture's
  2,254 such labels fell inside the image window and reached a different function, exit 0.
  The label is now `sub_0x<va>`, the address the rest of the output prints, or the
  pc_offset when the binary has no anchor symbol, and every command that takes a symbol
  reads it back: over all 2,254 anonymous ranges of the clean fixture and 7,987 of the obf
  one, the label and the number in it reach the range they name. This moves output bytes,
  and nothing else: the `name` column of `functions` and its `-j` `label` field, an
  unnamed call in a lifted body, a `goto` out of a function, the header of `disasm`,
  `lift` or `xrefs` and the `name` of `xrefs -j` for an anonymous range, and the functions
  `ffi` lists under a library. Named ranges, the `symbols` exports and every `pc_offset`
  and `va` field are unchanged. Closes #40.
- **Tier 2 ends an arm32 function where it returns.** The control-flow graph ended a block
  only at `b`, `ret`, `br`, `bx` and the conditional branches, so arm32's usual return,
  `pop {fp, pc}`, got an edge to whatever code followed it, and `decompile -t 2` and
  `export -t 2` rendered that code as if it ran after the return, in a quarter of the
  functions of every arm32 build. An indirect jump (`ldr pc, [r4, #3]`) and every
  conditional form (`popne`, `bxeq lr`, `ldrne pc, [sl, #imm]`) were missed the same way.
  Which instruction leaves the function is now read off its word (`branches.a32_exit`),
  which agrees with capstone on every one of the 131,382 such words in the 13 arm32 corpus
  builds: an unconditional one ends its block with no successor, a conditional one with an
  exit beside the fallthrough. A return prints `return;`, a conditional one `if (cond) {
  return; }`. `tools/cfgcheck.py` passed the wrong graph, because it compares the
  rendering against the graph it is handed; it now also judges the graph itself by
  capstone's reading of each word, which finds 3,434 violations on arm32-2.19.6 on the old
  graph and 0 now, and `check.sh --full` runs it on fixed arm32 words and on that build
  when present. arm64 output is unchanged. Closes #45.
- **`decompile`, `export` and `lift` print code addresses as virtual addresses.** Since
  #34 each method's header is a virtual address, and `disasm` rebases every branch, call
  and `adr` target, but the body under the header printed capstone's operand, a pc_offset:
  `bl #0x19ebf0` under `// 0x1ee6a8`. Inside the image window such a number is read back
  as a virtual address, so pasting it answered with a different function and exit 0, and
  another tool landed short by the anchor. Tier 1 did this for every call, every branch
  leaving the function and every `adr`, tier 2 for every call it does not name and every
  `adr`, and tier 3 for `adr`, in the text and `-j` forms. All three now print through the
  rebase `disasm` uses: `bl 0x2d5670`, `blne 0x355514`, `adr x10, 0x2d93f8`. Over `export`
  of both fixtures at every tier and of arm32-2.19.6 at tiers 1 and 2, the 83,897 such
  operands are rewritten, 0 remain, and every other line, block labels included, is
  unchanged. Closes #43.
- **The call graph draws arm32's conditional calls.** Its decoded walk, which every arm32
  range goes through, drew a direct edge only for a `bl`, so `blls`, `bleq` and `blne`,
  and any other spelling of a call such as `blgt` or `blx #imm`, were dropped without
  being counted: a quarter of arm32's direct edges. `functions` showed `in 0` for the
  stack-overflow stub that 5,310 functions call on arm32-2.19.6, and `xrefs function` said
  nothing called it. The walk now takes a call from the instruction word, as `disasm` has
  since #41. On all 13 arm32 corpus builds the graph holds every direct call
  `branches.row_kinds` finds, 25,527 edges on arm32-2.19.6 where it held 18,537; a call
  into the middle of a range, such as the write-barrier stub's per-register entries, still
  draws no edge, as a plain `bl` to such a target does on arm64. The graphs of both arm64
  fixtures are unchanged. Closes #44.
- **Tier 2 names arm32's conditional calls, as tier 1 does.** Since #41 a callee is found
  from the instruction word, which names `blls` to the stack-overflow stub and `bleq` to
  the null-error stubs, but only where `annotate` was handed the word's row kinds, and the
  tier 2 callers were not. They kept the mnemonic test (`bl` and `b` only), so `export -t
  2` of arm32-2.19.6 named 0 of the 8,375 conditional calls it prints, each a bare
  pc_offset inside the image window. It names 7,046 now, and arm32-3.11.5 7,234 of 8,724,
  each with the note `-t 1` gives the same call; the rest go into a stub past its first
  instruction, which no tier names. A conditional call keeps its condition (`blls ... ; ->
  stub ...`) rather than becoming a `call` that reads as unconditional. `annotate` now
  requires the row kinds, so no caller, tier 3 and the tools included, can fall back to
  the mnemonic test. arm64 output is unchanged: `export -t 2` and `-t 3` of both fixtures
  are byte-identical. Closes #42.
- **A branch into pc_offset 0 to 9 prints its target as an address.** capstone prints a
  target below 10 in decimal (`bl #8`) and the rest in hex (`bl #0xc`), and the check that
  a target read from the instruction word matches the operand looked only for a `#0x`
  number. So a branch, call or `adr` into the first ten bytes of the instructions image
  kept its pc_offset among virtual addresses in `disasm`, got `target_va: null` under
  `-j`, and since #41 lost its tier 1 callee name and block label. The check now reads the
  last number in either spelling, and the rebase keeps what comes before it (`tbz w0, #0,
  #4`). No compiled binary branches there, since pc_offset 0 is the image header, so on
  the fixtures and the arm32 corpus builds every row and every `export` file is unchanged;
  the case needs a crafted binary. Closes #46.
- **A bad `--sigs` file is a typed input error, exit 2.** A missing path, a directory, a
  file that is not a signature library, one that cannot be read, and a malformed line in
  one each escaped `signatures.load()` as a builtin exception (such as
  `FileNotFoundError`, `IsADirectoryError`, `PermissionError`, `ValueError`, `KeyError` or
  `UnicodeDecodeError`), which all nine commands that take `--sigs` reported as a bug in
  jadart: exit 3, a request to file an issue, and `"internal": true` under `-j`. Each is
  now an `InputError` naming the path, and for a bad line its number and what the line
  needs, so a script can tell a bad argument from a crash, as it already could for the
  binary next to it. The first line is read only as far as the header needs, so a file
  that does not start with it is refused at once: `--sigs /dev/zero` read without end
  before, and a large file with no newline was read whole. A library read through a pipe,
  from a process substitution or `/dev/stdin`, still loads. The file is read and written
  as UTF-8 rather than in the locale's encoding. Every line has to be what `jadart
  signatures` writes: the header exactly, a body line as a tag, 16 lowercase hex digits
  and a name, a count of at most 18 digits, and `\n` or `\r\n` line ends. Before, a header
  with spaces around it, `\r` line ends, uppercase or 17-digit hex, and a signed or padded
  count also loaded, and `int(h, 16)` took `+1` or `1_0`. A library `jadart signatures`
  wrote as UTF-8 loads to the same tables as before and saves back to the same bytes; one
  an earlier version wrote under another locale, such as the Windows default, with a
  non-ASCII character in it is refused as not UTF-8 and has to be rebuilt. Closes #38.
- **The skill file and the usage guide render as written again.** The `xrefs` examples
  that #22 added to `SKILL.md` and `docs/usage.md` opened a code block and never closed
  it. Under CommonMark the next fence closed it instead, and the fences after it were
  inverted: examples rendered as prose and prose as code. In `SKILL.md`, which coding
  agents read, that ran to the end of the file, the last 62 lines became one code block
  and 8 of its 13 headings stopped being headings; in `docs/usage.md` it ran until a fence
  with an info string realigned the pairing, and 3 of 11 headings were lost. One closing
  fence in each file puts every heading back, checked with markdown-it in CommonMark mode.
  Closes #39.
  - `check.sh` now runs `tools/fencecheck.py` over every `.md` file in the repository,
    including one not yet added. It walks the fences the way CommonMark pairs them rather
    than counting them, because a fence with an info string cannot close a block, so one
    standing where a closing fence was needed passes a count whenever the total stays
    even. It also reports that fence, which is what `docs/usage.md:291` was before this
    fix. Neither report knows which block lost its closing fence, so both list the blocks
    before it.
  - It checks a small dialect the docs already keep to, and refuses anything outside it
    rather than guess: three-backtick fences, opening at column 0 (a closing one may be
    indented, as CommonMark allows), not in a list, a quote or a footnote, not in HTML,
    and no byte order mark or NUL. A longer or a tilde fence could close a block that a
    missing fence left open and hide it. Any line opening with `<` starts HTML that runs
    to the next blank line, or for a comment block at column 0 to the line holding its
    `-->`, where no fence may stand. HTML other than a comment block starts after a blank
    line or a comment block, and it keeps to a short list of plain tags and attributes,
    closes every tag, quote and comment on its line, writes each closing tag as its name
    and spaces or tabs, leaves no inline or heading element open past it or holding a
    block tag, leaves no block open in a list, a quote or an indent, has no line
    CommonMark can read as a heading, holds none of Markdown's inline syntax (`*`, `_`,
    `~`, `[`, `]`, backslash, backtick) on any of its lines outside a comment block, holds
    no `<` inside a tag or a comment, and quotes any attribute value that is not a run of
    plain characters. A comment may run on only where it starts a new HTML block at column
    0, which every renderer reads to its first `-->`. Renderers disagree about which lines
    start an HTML block (GitHub's follows CommonMark 0.29, markdown-it the 0.31 tags) and
    where some end; a line that starts one is copied into the page as it is, where a
    comment, `<script>`, `<select>`, `<details>` or an open quote hides everything after
    it, and a line that opens with an inline tag and goes on past it is read as a
    paragraph, where CommonMark decides which `<` are tags and a character one reader
    takes as a space and another does not can move where a tag ends. HTML is checked on a
    line that opens with `<` and on the lines after it up to a blank line, or for a
    comment block up to the line holding its `-->`, not later in other lines.
  - Compared with markdown-it on 600,000 generated documents built from fence, list,
    quote, HTML, inline code and invisible-character lines: fencecheck passed 12,993 of
    them, and markdown-it leaves a block open in none. On the 2,031 generated documents in
    the dialect that it passes, deleting any one of their 2,769 closing fences made it
    fail every time. Of 180,000 more, built around HTML, attributes and comments and
    ending in a code block and a paragraph, it passed 15,857; of 600,000 single HTML lines
    built from tag fragments, quotes and invisible characters, 36,811; of 600,000 lines
    opening with an inline tag, 15,143; and of 300,000 tags whose attributes mix quotes,
    `>` and characters some readers take as spaces, 2,186. Parsed as a browser parses
    markdown-it's page, none lost the code block or the paragraph, and neither did any of
    150 of the documents rendered by GitHub. Of 400,000 lines opening with an inline,
    heading or block tag and followed by a heading, a paragraph and a code block, it
    passed 22,281, and of 200,000 paragraphs of two to five HTML and prose lines holding
    emphasis, link and code delimiters, 28,070; none of them left the heading, the
    paragraph or the code block inside an inline or heading element on markdown-it's page,
    nor did any of 100 of the lines rendered by GitHub. Of 120,000 documents mixing prose,
    comment blocks, lists, quotes, headings and HTML lines, it passed 24,313 that hold no
    HTML inside a Markdown heading line, and none of those wrapped, lost or moved a code
    block on markdown-it's page; of 240,000 more putting HTML lines in lists, quotes and
    indents among headings and prose, it passed 32,828, and none of the 31,590 of those
    that hold HTML only on lines the check reads left the rest inside a list, a quote, an
    inline or a heading element.
- **arm32 conditional branches print their target as an address.** Since addresses became
  virtual addresses, a branch target is rebased to match the column beside it, but which
  operands were branch targets was decided from the mnemonic: a list that knew arm64's
  `b.eq` and not arm32's `beq` or `blls`. On arm32 every conditional branch and every
  conditional call kept its pc_offset among virtual addresses with nothing marking it, and
  a pc_offset such as `#0x201e04` falls inside the image's address window, so pasting it
  back answered with the wrong function and exit 0. The print layer now reads the
  instruction word instead (`branches.py`, stdlib only): on both instruction sets the top
  byte fixes whether a word is a PC-relative branch or `adr`, and the immediate field gives
  its target. An operand is printed as an address only when that target is the number
  capstone printed and lies inside the image; otherwise it is left exactly as printed.
  Closes #37.
  - Relative branches left as pc_offsets, counted the way the issue counted them, with
    capstone's detail mode over every word of the image and `blr` excluded by operand kind:
    arm32-2.19.6 48,941 of 86,109 before and 0 after, arm32-3.11.5 45,461 of 84,351 before
    and 0 after, and 0 on both arm64 fixtures before and after.
  - The other two readers that decided from the mnemonic now read the word too, and the
    mnemonic path for block labels is gone rather than kept as a fallback. A conditional
    call names its callee, as `bl` always did: 9,554 more named calls over every range of
    arm32-2.19.6, such as `blls` to the stack-overflow stub. And tier 1 labels a
    conditional branch's target: over every range of arm32-2.19.6, 35,458 labels where
    there were 7,583, including both `blt` in `CertificateException`.
  - This changes arm32 output only. The text listing prints the address in place of the
    pc_offset, and tier 1 numbers its labels in address order, so a function that gains a
    label renumbers the ones after it: `CertificateException` prints `b L3` where it
    printed `b L1`. `disasm -j` only gains: over every range of arm32-2.19.6, 48,839 rows
    gain a `target_va` and 9,554 of those a callee note, and no other field of any row
    moves. On the arm64 fixtures `disasm` text and `-j` over every range, and all three
    `export` tiers, are byte-identical. Two new tests pin a hash of the `disasm` text and
    `-j` of every 32nd range of each fixture.
  - The top-byte tables were checked against capstone over all 2^32 words of each
    instruction set, each decoded at the bases 0x100000 and 0xa3c4000: every
    decodable word of a byte the tables name printed an address that moved with the base,
    and no word of any other byte did, 536,870,912 words on each set with no exception.
  - capstone is pinned below 6 in the `disasm` extra and in `requirements.txt`, because
    the tests pin listings recorded with the 5.0.9 wheel (whose `capstone.__version__`
    reads 5.0.7).
- **A word capstone cannot decode no longer hides the rest of a function.** capstone stops
  at such a word, and `disassemble_range` returned what it had decoded up to there, so
  everything after it was gone from `disasm`, `lift`, `decompile`, `export` and the call
  graph with nothing marking the cut. A range whose second word was junk read as a
  complete one-instruction function, which is the one kind of wrong answer this tool is
  built not to give. The word is now emitted as `.word 0x...` and decoding continues after
  it, which is what objdump does and what the lifter already did with an instruction it
  could not model. Both instruction sets here are fixed width, so stepping to the next
  word is exact rather than a resynchronisation guess.
  - This changes real output, on arm32. The issue expected no corpus binary to contain
    such a word, which holds for the arm64 fixtures: their output is byte-identical. It is
    not true of arm32. `0xe7100c13` appears once each in the 2.19.6, 3.0.6 and 3.1.5
    builds, in the middle of real code, and each was cutting its function short: 178
    instructions per binary come back, and the call graph finds the calls among them, so
    `_IntegerImplementation.~/` on arm32-2.19.6 gains a callee and a caller it always had.
    The other 24 corpus binaries are unchanged.
  - The cap every other path obeys still bounds the output, so a range of nothing but bad
    words cannot make the loop emit more rows than `MAX_INSNS`, and a tail shorter than one
    word is not reported as an instruction.

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
- **Four places the decompiler stated something it had not established.**
  - Gate G4 could not fail: it passed whenever the alloc pass recorded any length, and
    nothing compared those lengths with what the fill pass read. It compares them one by
    one now, and a single altered length fails it.
  - A selector name was accepted on a tied vote, which `Counter.most_common` breaks by
    insertion order, so 46 of 246 accepted names on the clean fixture were a coin flip
    printed as a method name. A tie is a rejection now: 168 names where there were 209,
    and 28.7% of dispatch sites named where it was 40.2%. The rest print as `sel_0x<off>`.
  - A compare with a shifted operand dropped the shift, so `cmp w5, w16, lsl #1` read as
    `w5 != w16`, on 134 sites. It prints the shift, and a shift outside 0 to 63 prints a
    `?`.
  - A branch out of the function had no successor, so the body stopped there or ran into
    an unrelated block, and a conditional one inverted its condition. Both render
    `goto sub_0x...` now, in 967 of the 970 functions that had one.
- **A crafted file raises a `JadartError`, never a builtin exception.** It could reach a
  caller as `struct.error`, `KeyError`, `ValueError`, `OverflowError`, `RecursionError`,
  `BadZipFile` or `FileExistsError`, none of which the documented except clause names. The
  varint reader stops at ten groups, the widest the format encodes, where a 1.28 MB run
  took 57 s and now fails in 0.1 ms. `NOTICES.Z` is inflated under a 64 MB ceiling, where
  a 400 KB member reached 1.68 GB. `AssetManifest.bin` nesting stops at 64 levels. A zip
  failure is a `ContainerError`, and a missing symbol is the new `MissingSymbol`, a
  `ContainerError`, so absence is told apart from corruption. `ContainerError` and
  `InputError` moved to `jadart.errors` and are still importable from where they were.
  In 1,500 runs over 500 corrupted binaries through `header`, `program` and `verify`, no
  untyped exception escapes.
- **A fully stripped `.so` parses.** An ELF with no section headers failed with
  `list index out of range` before the magic scan meant for it could run. It is read
  through its `PT_LOAD` program headers now, which is what the loader uses.
- **`export` keeps every path inside the output directory on Windows too.** Library urls
  were split on `/` only, so `package:foo\..\..\evil` kept its `..` inside one component
  and escaped once Windows read the backslash. They split on both now, lose trailing dots
  and spaces, replace the characters Windows forbids and rename its reserved device names.
- **Output is UTF-8 whatever the console.** Text files are written as UTF-8 with `\n` line
  ends, and stdout is reconfigured the same way, where a cp1252 console stopped an
  `export` partway through and a recovered string could crash a print.

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
