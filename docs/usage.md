# Using Jadart

The command walkthroughs, moved out of the README so the landing page stays a landing
page. `jadart <command> --help` documents any one command; this is the narrative version.

## Unpacking the whole app

jadx separates what it decompiles from what it merely extracts. That idea is worth
borrowing; copying the output is not. A Flutter APK holds **two** programs: `libapp.so` is
the Dart, `classes.dex` is the Android embedding and its plugins, so Jadart writes out only
the part it makes more readable, and tells you what reads the rest.

```
jadart export app.apk -o out/
```

```
out/
  sources/        decompiled Dart, one file per library
  assets/         the Flutter asset bundle, unwrapped and decoded
  assets.txt      what each asset is, and which are worth opening first
  container.txt   what else is in the container, and what reads it
  strings.txt     the recovered identifier and literal pool
  pool.txt        ObjectPool entries that resolve to a name
  selectors.txt   virtual-dispatch selector offsets -> names
  summary.txt     what was recovered, and what was not
```

There is no `resources/` or `native/`. Unpacking `res/`, `META-INF/` and three copies of a
10 MB Flutter engine would add nothing to bytes you already have, and `unzip` and apktool do
that better. On the app above it was the difference between 41 MB of output and 3.2 MB.
What you get instead is orientation:

```
Also in here, and what reads it
  flutter engine         3 files   29.6 MB  the Flutter runtime itself, not this app's code
  java/kotlin            1 file     0.7 MB  the Flutter embedding and any plugins: `jadx -d out-java <app>`
  manifest               1 file     0.0 MB  binary AXML (permissions, exported components): `apktool d <app>`
  android resources     40 files    0.1 MB  `apktool d <app>`
  signing               23 files    0.0 MB  `apksigner verify -v <app>`
```

Two Flutter formats are **decoded**, not copied, because copying either leaves it unreadable:

- **`NOTICES.Z` is gzip.** Inside is every licence of every package the build links, a
  complete third-party dependency inventory, and usually the fastest way to learn that an
  app bundles a particular crypto or analytics library. It lands as `assets/NOTICES` with
  the package names pulled out into `assets/dependencies.txt` (82 and 98 packages on the
  two apps in the corpus).
- **`AssetManifest.bin` is Flutter's `StandardMessageCodec`.** This one is not optional:
  Flutter stopped shipping the readable `AssetManifest.json` after 3.10, so on any current
  app the binary blob is the *only* index of what the app declares as an asset.

`assets.txt` sniffs each asset by magic bytes and marks the ones worth opening first: a
certificate, a key, a database, a model, or a name suggesting configuration:

```
9 files in the Flutter asset bundle. `*` marks ones worth opening first:

* assets/cert.cer                     1,814  PEM key/certificate
  assets/hivehex.png                206,670  png
  fonts/MaterialIcons-Regular.otf     1,324  otf font
```

Asset routing is on path segments rather than container type, so an APK's
`assets/flutter_assets/...` and an IPA's `Frameworks/App.framework/flutter_assets/...` are
handled by one rule with neither special-cased.

## What it recovers, tier by tier

| tier | what you get | honest fallback |
|------|--------------|-----------------|
| 0 | class / method / field skeleton with the resolved superclass hierarchy (`FluBenchApp extends StatelessWidget`). 1843 named classes, 5756 members, 9013 strings on the clean corpus | classes whose names were stripped keep their structure |
| 1 | per-function arm64 with direct call targets named and ObjectPool constants resolved to their string or function, including far pool loads (`add xD, x27, #hi; ldr [xD, #lo]`) | unresolved pool slots print their raw offset |
| 2 | `if`/`else` and loops reconstructed as pseudo-Dart from the CFG, using forward and post-dominators, plus a Cifuentes follow node for the 36% of conditionals whose arms each end in their own `return` and so post-dominate at the virtual exit | 19.2% of functions still emit at least one `goto`, against 7.8% that are genuinely irreducible. `tools/cfgcheck.py` reads the structured tree back as a program and checks, for every block in the image, that the rendering claims exactly the successors the CFG has |
| 3 | expressions, by abstract interpretation over the register file: field load/store, arithmetic, `bool`/`null`/int constants, element access, compound `-=`, `return <expr>`, and scalar floating point (including int-to-double and double-to-int conversions, and `math.max`) | any instruction the lifter doesn't model prints as its arm64 line |
| 3.1 | call arguments from the callee's register arity, read at the target address and so not dependent on the callee having a recovered name (`benchWithdraw(t8, (x1.field_0x8 >> 1) ~/ 2)`). A call whose result is read gets that result named, so the value can be followed to its use | the stack convention, an arguments descriptor, and a target outside the image print `(...)` rather than a guess |
| 3.2 | VM runtime stubs rendered as source operations: `throw`, `throw NullCastError()`, `new List()`. Pure machinery is stripped so it never reaches output: frame setup, the stack-overflow check, the write barrier, type tests, and the Smi box-or-tag idiom, which surfaces as a bogus `if (x != x)` if you leave it in | anything else stays a named `bl` |
| 3.3 | virtual and interface calls attributed to a receiver plus a stable selector offset, `x1.sel_0xb34(...)`. About 74% of dispatch sites recover both | the rest print `(dynamic call)` |
| 3.4 | that offset resolved to a **source selector name**: `this.renderObject`, `x1.build(...)`. 168 selectors on the clean corpus, naming 28.7% of the dispatch sites that have a recovered offset | names need two agreeing classes AND an untied vote, so the rest keep `sel_0x<off>` |

Two things sit outside the tier ladder and matter a lot in practice.

**Full-image disassembly coverage.** Fixing the instruction-table walk to size a
function by the next table entry, across all entries rather than only recovered owners,
took obfuscated builds from 4% to 100% of the instruction image. Functions discarded by
`--obfuscate` keep their instructions and lose only their Code object.

**ELF and DWARF name backfill.** A default `flutter build --release` turns on
`dwarf_stack_traces_mode`, which strips Dart names out of the snapshot and emits them into
the ELF `.symtab` instead. Snapshot-only recovery on such a build yields short hash tokens
like `AB` and `Aba`. Jadart maps each recovered code range back to the covering symbol. On
a real third-party app that recovered **9666 real function names** the snapshot no longer
held, alongside 7225 string literals and 100% disassembly coverage over 11052 ranges. This
needs a `.so` that still has a symbol table: an unstripped build intermediate, a debug
`.so`, or a matching `--split-debug-info` file. A fully stripped shipped `.so` loses those
names for every tool.

Selector naming is not a heuristic. A method defined in class `C` occupies `C`'s own
dispatch row, so `selector_offset = k - cid(C)`, and every class defining that same
selector must independently produce the same number. On the corpus `get:hashCode` is
corroborated by 127 distinct defining classes, `toString` by 67, `build` by 48,
`createState` by 46, `createRenderObject` by 42, `dispose` by 40. That is the whole
Flutter widget lifecycle, each at its own offset. A name needs at least two agreeing
classes, and an offset claimed by two different names is dropped.

## The function table, and what calls what

`jadart functions` is the listing every disassembler opens on: radare2's `afl`, IDA's
Functions window, Ghidra's Symbol Tree. It covers **every** code range, not the subset
that kept a name, because `--obfuscate` discards a function's `Code` object while leaving
its instructions in place, and those ranges are real and reachable.

```
$ jadart functions TheTimer.apk --sigs dart33.sig -s callers
// 9213 code ranges  snapshot 203  signature 4334  anonymous 4676
address           size  calls    in  name
.text+0x2112e0     128      0  6095  stub _iso_stub_StackOverflowSharedWithoutFPURegsStub~
.text+0x211460     180      0   810  stub _iso_stub_AllocateMintSharedWithoutFPURegsStub~
.text+0x2111e4     252      0   645  stub _iso_stub_AllocateArrayStub~
.text+0x2810       584      4   452  _interpolate~
```

Two columns exist here that a native disassembler has no way to fill:

**Where the name came from.** `snapshot` was serialised into the binary, `symtab` was
backfilled from the ELF symbol table on a dwarf build, `signature` was matched against a
reference and is an inference. IDA and Ghidra show one name column; conflating three
strengths of evidence is exactly the thing this tool refuses to do elsewhere.

**The owning library.** A Dart function belongs to a library url, so `-l` groups by
`package:myapp/main.dart` and app code separates from framework code with no reference
binary and no list of known packages.

`--anonymous` is the one to reach for after a signature pass: what no reference could name
is, by construction, the code somebody wrote for this app.

### xrefs now answers for functions too

`jadart xrefs` used to resolve ObjectPool entries only. On the corpus binary that is 349
pool references against **34,979 direct calls**, so it answered about one call site in a
hundred. It now also takes a function name or address and reports its call sites, the way
r2 spells `axt`:

```
$ jadart xrefs libapp.so benchWithdraw
// benchWithdraw  .text+0xb812c  1 call sites
    .text+0xb7db0    428 bytes
```

### ffi: where the Dart stops being the answer

Some apps put nothing interesting in Dart at all. BrunnerCTF 2025's "Brod and Co." is one:
the flag is not in the snapshot, it is inside an 18KB `libnative.so` the app reaches over
FFI, and the Dart half is a map to it rather than the answer. Jadart already recovered
every piece of that map, the library name from `strings`, the reading code from `xrefs`,
the looked-up symbols from `lift`, and made the analyst assemble it. `jadart ffi` puts
the three on one page:

```
$ jadart ffi libapp.so
// jadart FFI boundary  (epoch objectheader-3.8, dart 3.8.1)
// shared-object names in the ObjectPool, and the code that reads them

libnative.so   pool_0xd650
  initialize  .text+0x166370  476 bytes
      var t2 = lookup(pool_0xd658, t0, "process_data_complete");
      var t5 = lookup(pool_0xd670, THR.field_0x68.field_0x13b9, "get_client_version");
      printToConsole("Native library loaded successfully");
      printToConsole("Main function: process_data_complete");
      printToConsole("VULNERABILITIES ACTIVE: Buffer overflow, weak crypto, format string");
  _open@9050071  .text+0x1666d0  136 bytes
      pool_0xd6d8.field_0x7("libnative.so", NULL);
```

`nm -D` on that `libnative.so` exports both names, and `process_data_complete` is the one
the challenge turns on. `--full` prints the whole lifted body of each function instead of
only the lines carrying a literal.

What the command does NOT claim is that anything was loaded. It classifies a pool literal
by its **filename shape** (`.so`, `.dylib`, `.dll`, a path into a `.framework`) and
reports which code reads it. That a `DynamicLibrary.open` was the reader is a separate
fact, and where Jadart can see it, it is visible in the lifted line rather than asserted in
the header. A binary with no such literal is refused outright, with the reason:

```
$ jadart ffi libapp.so
jadart: no shared-object name in the ObjectPool, so nothing here says this snapshot
reaches native code. That is evidence, not proof: a name built at runtime, or passed in
from the Java side, leaves no literal to find
```

### Virtual calls are resolved, not just labelled

Call edges come in three kinds and only the first is a plain `bl`: direct (34,979 sites),
indirect through a register (5,370), and pool-mediated (349, a function torn out of the
pool and called later). The indirect ones are where a Dart image differs most from native
code, and they are not left as "indirect": a virtual call goes through the dispatch-table
register, and the serialized dispatch table says which classes implement that selector. So
**48% of indirect sites resolve to a concrete set of possible targets**, and the rest are
counted as opaque, which is what a closure call through a captured context genuinely is.

```
$ jadart xrefs libapp.so createElement
// createElement  .text+0xff398
  11 virtual call sites  (one of 18 implementations of this selector)
    .text+0x59fe4    636 bytes
    ...
```

`overloads` is the honest part. One implementation means the site can only land here and
the edge is as good as a direct call; eighteen means this is one candidate and the
receiver's runtime class decides. Direct and virtual edges never merge, because one
`toString` site would otherwise add eighty-odd edges indistinguishable from real calls.

**A subtlety worth recording.** `row = cid + selector_offset` is a packing, not a matrix:
two different (class, selector) pairs legitimately share a row. Walking every class id at
one offset therefore returns real implementations mixed with unrelated collisions, and
taken raw the median selector came back with **370** targets, which is nonsense for a
method a few dozen classes override. The filter is the one Tier 3.4 already trusts for
naming: every real implementation carries the same method name, so the modal name is the
selector. That takes the median to 4 and `toString` from 649 candidates to 82.

Which means the pass needs names, so on an `--obfuscate` build it collapses on its own.
Feeding it `--sigs` composes the two features: on the 24hCTF binary, functions reachable
through a resolved virtual call go from **19 to 729**.

## Naming library code that was obfuscated away

On an ordinary build Jadart reads **72.5%** of function names straight out of the snapshot
(73.9% on a second app). A `--obfuscate` build collapses that to **2.2%**, because Dart's
obfuscator renames dart:core and the Flutter framework too: `toRadixString` and `padLeft`
are not hidden in the file, they are absent from it. No parser recovers them.

The code, however, is the same code every app of that Dart release ships. So the names can
come from a reference build where they survived. That is what `jadart signatures` builds
and `--sigs` applies. The idea is Ghidra's Function ID, adapted rather than copied: hash
each function with its operands masked, then disambiguate what is left using the call
graph and mark undiscriminating entries so they never match.

```bash
# build a library from normal builds of the same Dart release
jadart signatures corpus/3.3.4/libapp.so corpus/3.2.6/libapp.so corpus/3.4.4/libapp.so \
       -o dart33.sig

# apply it to an obfuscated app
jadart lift TheTimer.apk 0x739c8 --sigs dart33.sig
```

```
  while (true) {                          |    while (true) {
    if (x5 < x3) {                        |      if (x5 < x3) {
      x2.sel_m0x1(x5);                    |        x2.sel_m0x1(x5);
      x1.sel_m0x1(x5);                    |        x1.sel_m0x1(x5);
      sub_0x24860(...);                   |        _toPow2String~(...);
      sub_0x1cad5c(...);                  |        padLeft~(...);
```

**Where we do better than a direct port.** Ghidra masks constant operands because it
cannot say what they mean. We can: an arm64 Dart function reaches its constants through
the object pool, and Jadart already resolves that offset to the string or function it
names. So a masked immediate becomes a *resolved referent*, `[PP:"time of request: "]`.
String literals survive obfuscation untouched, which makes them the strongest signal
available on exactly the builds that need it most.

**Measured**, on an application in no reference, with ground truth for every function:

| | matched | precision |
|---|---|---|
| three references, unseen app | 4440 | **99.3%** |
| ...of those, `context` level | 4297 | 99.4% |
| ...`pool` level | 81 | 93.8% |
| ...`shape` level | 62 | 96.8% |
| one reference only | 4087 | 99.1% |
| reference 3.12.2, target 3.10.9 | 3457 | 98.8% |

Cross-version holding at ~99% means one library covers a range of releases, not one per
release. On the obfuscated 24hCTF binary the effect is 204 named ranges becoming **4354**,
2.2% to 47.3%.

**Two rules keep it honest.**

A matched name ends in `~`, always. It was inferred from a different binary and is right
about 99% of the time rather than always; a name without the mark was read out of this
binary and is a fact. A recovered name always wins over a matched one.

A shape that two functions share names nothing and is dropped, which is the reason to pass
several references: one build cannot disagree with itself. Three references drop 1251
shapes on that ground. Two classes are excluded outright, the way Ghidra's Auto Fail
excludes known-undiscriminating entries: dart:core's native-call thunks, which are
generated from one template and differ only in a pool slot the runtime patches to null,
and the `dyn:` invocation forwarders, where `dyn:+` and `dyn:-` collide even inside a
single reference build.

**What it will never do** is name the app's own code, which appears in no reference. That
is the useful half of the split: after a match pass, what is still anonymous is the part
somebody wrote. On the CTF binary the flag builder and its XOR routine both correctly come
back unnamed.

