# How it works

Two questions, answered in order: what makes a Flutter app hard to read, and what jadart
does about each obstacle. Everything quoted here is real output from the command shown,
against binaries in this checkout.

Start at [README.md](README.md) for what the tool is and how to run it.
[DESIGN.md](DESIGN.md) is the annotated snapshot format cited to `dart-lang/sdk`, and
[EVAL.md](EVAL.md) has the measurements. This file sits between them: enough of the format
to understand the tool, and enough of the tool to trust it.

---

# Part 1. What makes a Flutter app hard to read

## 1.1 There is no bytecode

Flutter compiles Dart ahead of time. A release APK contains no bytecode, no reflection
metadata, and no class file you can open:

```
TheTimer.apk                          17.7 MB
  lib/arm64-v8a/libapp.so              2.9 MB   your Dart, compiled
  lib/arm64-v8a/libflutter.so          9.9 MB   the engine, not your code
  classes.dex                          0.7 MB   the Android shell
```

`classes.dex` is the Android embedding. Decompiling it with jadx gets you the shell that
starts the engine and nothing about the app. All of the application logic is in
`libapp.so`, which is where teams ship banking, health and identity code on the assumption
that AOT hides it.

## 1.2 `libapp.so` is a serialised VM heap

It is not a normal shared object with functions you can enumerate. Two things live inside
it, joined by offsets:

- **the data image**, a *clustered serialisation of the Dart heap*: classes, functions,
  strings, types, the ObjectPool
- **the instructions image**, a separate blob of machine code that the data image refers to
  only by offset

The data image begins with a twenty-byte header and then the thing everything else depends
on, a 32-character hash:

```
f5 f5 dc dc  |  55 20 07 00 00 00 00 00  |  03 00 00 00 00 00 00 00

magic     0xdcdcf5f5
length    467,029 bytes
kind      3                                  kFullAOT
hash      ee1eb666c76a5cb7746faf39d0b97547
features  product no-code_comments dwarf_stack_traces_mode ...
```

The hash is an MD5 over the raw bytes of fifteen `runtime/vm` source files
(`tools/make_version.py`). It is not a version number and there is no official table
mapping it to an SDK release. It is the only thing in the file that says how to read the
rest of it.

## 1.3 It is written in two passes, and it is sequential

The serialiser walks the heap twice.

- **alloc pass**: every object gets a dense incrementing id, and each cluster writes only
  its count. No field data yet.
- **fill pass**: each cluster writes its scalars and its references. Every id already
  exists, so a forward reference costs nothing.
- then the roots, then the serialized dispatch table.

On the corpus binary that is **54,145 objects across 356 clusters**.

The consequence is the one that hurts: **the stream cannot be seeked**. Object 40,000 is
only reachable by replaying both passes from the start, in order, with the correct grammar
for every cluster in between. There is no index and no table of contents. Getting one class
out means getting all of them out.

## 1.4 The machine code is arm64, but not the arm64 you know

Here is a whole method. Nine instructions, and an ordinary disassembler decodes every one
of them correctly:

```
$ jadart disasm libapp.so benchWithdraw

  0x0b812c  ldur  x3, [x1, #7]
  0x0b8130  cmp   x2, x3
  0x0b8134  b.le  #0xb8140
  0x0b8138  add   x0, x22, #0x30
  0x0b813c  ret
  0x0b8140  sub   x4, x3, x2
  0x0b8144  stur  x4, [x1, #7]
  0x0b8148  add   x0, x22, #0x20
  0x0b814c  ret
```

Correct, and useless, because Dart AOT does not follow the platform conventions the tool
assumes (`constants_arm64.h`):

| register | role |
|---|---|
| `x15` | **the stack pointer**. The hardware `SP` is used only in the prologue |
| `x27` | the ObjectPool. Every constant is reached through it, not by address |
| `x26` | the current thread |
| `x22` | `null`, with the canonical `true` at `+0x20` and `false` at `+0x30` |
| `x21` | the dispatch table |

So in the listing above, `add x0, x22, #0x30` is `return false`, and `[x1, #7]` is field 8
of the receiver less the heap-object tag. Three specific failures follow for a generic
tool:

1. **No stack frame.** `x15` is not `SP`, so the frame analysis that finds locals and
   parameters finds nothing.
2. **No arguments.** Dart pushes arguments rather than passing them in `x0`-`x7`, so the
   signature does not appear.
3. **No cross-references.** Every constant load goes through the ObjectPool, so the link
   between a string and the code that uses it is an index, not an address.

## 1.5 And the format moves

The cluster grammar changes with the SDK. This is the reason earlier tools stopped working
rather than degrading: Darter and Doldrums both broke on format drift.

```
cidcanonical-2.19   dart 2.19.6   adb4292f
cidcanonical-3.0    dart 3.0.6    90b56a56
   ...
objectheader-3.12   dart 3.12.0   41be3daa
objectheader-3.12   dart 3.12.2   ace65428
```

Two epoch families are visible in those names: the object header layout changed at 3.4, and
the class-id table is renumbered as the VM gains classes. A parser built for one epoch does
not fail loudly on another. It produces a coherent-looking object graph made of garbage,
which is worse.

---

# Part 2. What jadart does about it

## 2.1 Identify the build, or refuse

The hash plus the features string resolve to a *format epoch* and a target. There is no
fallback:

```
$ jadart info unknown-app.so

jadart: unknown format epoch: version_hash='aa64af18e7d086041ac127cc4bc50c5e'
  Refusing to guess, because the wrong grammar mis-parses rather than failing.
  Supported: Dart 2.19.6 through 3.12.2, 15 epochs.
  To place this build:  tools/sdk_source.py --identify aa64af18... --tags <candidates>
```

The profile key is `(hash, architecture, pointer model)` and not the hash alone, because a
build flag changes the grammar: with compressed pointers, String and several other clusters
move their payload into the data image and their `ReadFill` is empty. The arm32 and arm64
builds of one app share a version hash and need different grammars.

`tools/sdk_source.py` computes the hash an SDK tag *would* produce by fetching those
fifteen files over HTTP, about 2.5 MiB, with no clone and no VM build. That turns "which
SDK is this?" into a search rather than a guess.

## 2.2 Walk both passes

`clusters.py` runs the alloc pass, `fillwalk.py` the fill pass. The fill grammar is a table
of per-class read patterns, each entry cited to the VM source. For example, `LibraryPrefix`
(`import ... deferred as`):

```python
# WriteFromTo runs `name` through to_snapshot(kind), which for kFullAOT stops at
# `imports_` (raw_object.h:2891), so the importer is NOT serialised: two refs, not the
# three the field list suggests. Then num_imports_ as Write<uint16_t> and
# is_deferred_load_ as Write<bool> (app_snapshot.cc:4711).
"LibraryPrefixCid":      (2,  [T, B],        0, -1),
```

Forty-four cluster kinds are handled this way, twenty-two of them through that table.
Between them they cover every cluster in the corpus and in 44 real third-party apps.

## 2.3 Prove the walk before believing it

A parser that mis-reads produces plausible output, so the walk is checked byte-exactly
before anything downstream runs:

```
$ jadart verify libapp.so

  [PASS] G4  string alloc/fill lengths      9013 checks
  [PASS] G5  ref ids in range              20484 checks
  [PASS] G6  instance size vs class          319 checks
  [PASS] G11 dispatch anchor + exact end   29190 checks
        table at 0xe086f, 29190 entries, ends exactly at 0xe509c

Tier A: 11/11 passed
```

These are cross-checks between two things the format states independently, not heuristics.
G6 compares each instance cluster's object size against the size its Class object declares.
G11 locates the dispatch table by anchor and requires it to decode to end *exactly* at the
stream boundary, 29,190 entries later. A wrong grammar cannot satisfy them by accident.

## 2.4 The tier ladder

Recovery happens in stages, and each one is useful on its own.

**Tier 0, from the object graph alone.** No instruction is decoded yet:

```
$ jadart classes libapp.so -f BenchAccount

class BenchAccount {
  benchWithdraw() { ... }
}
```

1,843 named classes with their members, purely from the snapshot. This is where the other
static tools stop.

**Tier 1** annotates the disassembly: direct calls named, ObjectPool constants resolved.
That is the listing in section 1.4.

**Tier 2** recovers control flow with forward and post-dominators, so the branch becomes a
structure rather than a label:

```
  ldur x3, [x1, #7]
  cmp x2, x3
  if (x2 > x3) {
    add x0, x22, #0x30
    return;
  } else {
    sub x4, x3, x2
    stur x4, [x1, #7]
```

**Tier 3** recovers the expressions, by abstract interpretation over the register file:

```
$ jadart lift libapp.so benchWithdraw

  if (x2 > this.field_0x8) {
    return false;
  } else {
    this.field_0x8 -= x2;
    return true;
  }
```

Against the Dart that was compiled:

```dart
bool benchWithdraw(int amount) {
  if (amount > balance) return false;
  balance -= amount;
  return true;
}
```

`x22+0x30` became `false`. `[x1, #7]` became a field on the receiver. The `sub` and the
`stur` became one compound assignment. What did not come back is the argument name and the
field name. The argument name is gone for good; the field name is gone for THIS field,
whose `Field` object the optimiser dropped. Where one survives, and 245 do on this binary,
the slot is printed by name instead, see 2.9.

## 2.5 Names, and where each one comes from

Three sources, and the output says which:

- **from the snapshot.** On an ordinary build this covers 72.5% of functions.
- **from the ELF `.symtab`.** On a `dwarf_stack_traces_mode` build the snapshot no longer
  holds the real names and the symbol table does.
- **by shape.** Under `--obfuscate` the snapshot yields 2.2%, because Dart's obfuscator
  renames `dart:core` and the framework as well as the app. `toRadixString` is not hidden
  in the binary, it is absent. So the code is matched against a reference build where the
  name survived, which is what IDA does with FLIRT and Ghidra with Function ID:

```
$ jadart functions TheTimer.apk --sigs dart33.sig
// 9213 code ranges   snapshot 203   signature 4336   anonymous 4674

  String.fromCharCode~
  _toPow2String~
```

The trailing `~` marks a matched name. It is right about 99.3% of the time over 4,440
matches, where a name read from this binary is a fact. Where the two disagree the binary
wins.

## 2.6 Virtual calls

A dispatch-table call carries only an offset, so the callee looks unknowable. The offset is
recoverable: the serialized dispatch table is walked and each selector offset mapped back
to a source name.

```
$ jadart selectors libapp.so
// 209 virtual-dispatch selectors recovered

  _childrenInPaintOrder@153319124   selector_offset=9      call-site imm=-4087
  _createNode@182492240             selector_offset=63     call-site imm=-4033
```

So `x2.sel_0x3e2e()` becomes `x2.renderObject()` where the table knows the name, and stays
`sel_0x3e2e` where it does not.

## 2.7 Where it refuses

Three refusals, all deliberate:

| situation | output |
|---|---|
| an instruction the lifter does not model | the raw arm64 line |
| a call whose argument list cannot be proven | `name(...)` |
| a field whose `Field` object was tree-shaken | `field_0x8` |
| a field on a receiver whose class is not known | `field_0x8`, even where a name exists |

Each of these could be replaced with a plausible guess that would improve a readability
metric. A fabricated argument is indistinguishable from a real one, which is exactly why it
is worse than a gap.

## 2.8 What keeps it honest

The snapshot layer self-validates byte-exactly. The machine-code layer was long held to
have no equivalent, and that is false. Four instruments:

| instrument | what it catches | result |
|---|---|---|
| `verify` | a wrong cluster grammar | every applicable Tier-A gate on 33 corpus binaries and 44 real apps |
| `cfgcheck` | a rendered edge the CFG does not have | 0 violations |
| `irfuzz` | a printed expression the CPU disagrees with | 0 mismatches, 7 oracles |
| `semdiff` | output that drifts from the app's real Dart source | 9/9 across 14 epochs |

`irfuzz` is the one worth explaining. It builds a block twice, once as instructions on an
emulated arm64 and once as the text the lifter printed, puts random values in the input
registers, and compares bit-exactly. If the printed expression computes something the CPU
does not, that is a defect and not a matter of taste. A fourth oracle generates whole
control-flow graphs, which is how several join and loop defects were found.

Three of the seven exist because the first four had a stated exclusion each, and an
exclusion is where a defect lives undetected:

- **memory** was excluded on the grounds that real code with several blocks also calls
  out, which is true of the corpus and not of GENERATED code. `--mem` maps a page, points
  a register at it, and *interprets the printed statements in order*, a `var t0 = ...;`
  means the value at the line it stands on, which is the whole question. `--cfgmem` does
  the same across whole control-flow graphs, interpreting `goto` as a jump in a flat op
  list rather than skipping the graphs that need one. They found four defects: a value
  loaded before a store to the same field kept printing as a read of that field (1,146
  printed expressions, 377 of 8,194 functions); a join's phi assignment redefined a
  register that earlier expressions still named (963 of 3,685 phis, 230 functions); a
  group of assignments (a phi group, a loop's carried write-back) read the values the
  group itself had just written (109 of 1,728 groups, 34 functions); and a join left a
  register bare after the body had already assigned that name, so a silent reload in one
  arm was never printed (833 joins, 266 functions).
- **floating point** was outside the sample entirely, and the scalar-FP path had already
  diverged from the integer one once, in a precedence fix that reached only one of the two
  call sites. `--fp` fuzzes the scalar-double runs the compiler really emits against a
  Python float, which *is* an IEEE-754 binary64, so the comparison needs no approximation.
  Clean over 773,000 comparisons on the corpus and nine shipped apps.

Each oracle is also tested for teeth: a known defect is reintroduced and the oracle must
fire. An oracle that passes vacuously is worse than none.

## 2.9 Fields, and the ones that still have a name

A field access compiles to a byte offset and the table that maps offsets back to names is
tree-shaken, which is why `field_0x8` is the third refusal in the table above. That much is
right. What this page said next, that every `Field` object left in a release snapshot is
a static, so no field name survives at all, was a generalisation from a sample and it is
false.

Each surviving `Field` object still records where it lives. `FieldSerializationCluster::
WriteFill` (app_snapshot.cc:2234-2239) writes, after the kind bits, either the static
field's table id or `Smi::New(Field::TargetOffsetOf(field))`, and that second number is
the instance offset in compressed words. On the corpus binary 245 of the 420 `Field`
objects take the second branch; across the 44 cached third-party apps, 36,555 of 59,160.

So `jadart classes` prints the layout, not just the name list:

```
$ jadart classes libapp.so -f PointerEvent

class PointerEvent extends ... {
  viewId;        // @0x8 unboxed
  distance;      // @0x58 unboxed
  distanceMax;   // @0x60 unboxed
  synthesized;   // @0xa0
  transform;     // @0xa4
```

The `unboxed` marks come from the class's unboxed-fields bitmap and say the slot holds a
raw double rather than a tagged pointer, which is why those offsets are eight apart where
the tagged tail is four.

In a method body the name is substituted only on `this`, because that is the one value in
the register file whose class the snapshot states. `x3.field_0x8` keeps its offset even
where some class has a field there, since attributing it would be a claim about what x3
holds that nothing in the binary makes.

Three cross-checks decide whether this is safe to print, and all three are byte-exact:

| check | what it compares | corpus |
|---|---|---|
| G12 | the offset against the owner's own `instance_size` | 226 fields, 0 outside |
| G14 | the offset against the displacement an implicit getter compiled to | 58 getters, 0 disagree |
| G15 | the unboxed bit against the register width that getter used | 58 getters, 0 disagree |

G14 is the one that matters most. An implicit getter's whole body is one load of the field
its `Function.data` points at, so the code generator and the serialiser wrote the same
number twice without consulting each other. Nothing inside the snapshot alone could catch
an off-by-one in the units of `target_offset_`; this does.

---

# Part 3. Limits

Stated plainly, because a tool that only lists wins cannot be judged.

- **Most field names are gone; the claim that all of them are was wrong.** The
  offset-to-field table IS tree-shaken, and the earlier version of this line went on to
  say that every surviving `Field` object is a static. It is not: 245 of the corpus
  binary's 420 are instance fields carrying their own byte offset, and 36,555 of 59,160
  across the 44 cached apps. Those are printed by name. What remains true is that the
  fields the optimiser fully inlined leave nothing behind, `BenchAccount.balance` among
  them, and that a name can only be attached where the receiver's class is stated, so
  12.6% of the `this.field_0x` lines on the corpus get a name and the rest keep the
  offset. Inferring the others from trivial getters was measured and stays refused: 7.1%
  of getters on a clean build, 0 of 14 on an obfuscated one.
- **The app's own identifiers, under obfuscation.** A reference build cannot supply them,
  because nobody else compiled this app. Signature matching lifts the library half of that
  loss and leaves the rest.
- **Tier 3 is arm64 only.** arm32 decodes and structures (tiers 1 and 2) but is not lifted:
  a Dart `int` is 64-bit and arrives in a register pair there, and the model for that is
  built but does not yet meet the bar `semdiff` sets.
- **The epoch registry can never be complete.** About 8% of shipped Flutter apps are built
  from something other than a stable SDK tag. Those are refused by name rather than parsed
  with the nearest grammar.

---

# Where the code lives

```
elf.py / macho.py   open the container, fail loud
snapshot.py         header, hash, features, counts
versions.py         (hash, arch, pointer model) -> epoch, or refuse
clusters.py         alloc pass
fillwalk.py         fill pass, the object graph
program.py          resolve the graph, Tier 0
disasm.py           instructions image, per-function arm64, pool annotation
cfg.py              Tier 2: dominators, if/else and loops
expr.py             Tier 3: abstract interpretation over the register file
dispatch.py         the dispatch table -> selector names
verify.py           the acceptance gates
```

Dev-time harnesses live in `framework/tools/` and nothing under `framework/jadart/` imports
them, so the tool itself stays offline and dependency-free.
