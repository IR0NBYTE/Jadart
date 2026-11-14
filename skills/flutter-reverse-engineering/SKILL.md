---
name: flutter-reverse-engineering
description: Reverse engineer a Flutter (Dart AOT) Android or iOS app from a stripped binary. Recover the class tree, method bodies, strings, embedded data tables and virtual call names, without inventing what the binary does not say. Use when asked to analyse, audit, decompile or crack a Flutter app, an APK/IPA containing libapp.so or App.framework, or a Dart AOT snapshot.
---

# Reverse engineering Flutter apps

This skill is for any coding agent. It assumes only that you can run shell commands and
read their output. Nothing here depends on a particular agent, editor or vendor.

The instrument is `jadart`. Everything below is about how to *think* while using it; the
command reference lives in `jadart <command> --help` and does not need repeating.

```
git clone https://github.com/IR0NBYTE/Jadart.git
pip install './Jadart/framework[disasm]'
```

If `jadart` is not on PATH, say so and stop rather than guessing at an install: a wrong
package is worse than no tool.

---

## The one rule

**Never fill in a gap the tool deliberately left.**

A Flutter release build has been through AOT compilation and tree shaking. Real
information is gone: local variable names, most field names, generic type arguments,
comments. `jadart` is built so that a thing it could not recover comes out looking like a
gap rather than an answer. That property is the whole point, and you are the weakest link
in it: the natural move when reading `pool_0xb968.field_0x8(...)` is to say what it
"probably" does, and that turns a careful analysis into a confident fabrication carrying
the authority of a byte-exact tool.

So: **report gaps as gaps.** If the user needs the answer, say what would close it
(a dynamic trace, a reference binary, the app's own network calls), not what it might be.

### The vocabulary of a refusal

Every one of these means *the tool declined*, not *the tool failed*:

| You see | It means | Do not say |
|---|---|---|
| `x2`, `x19`, `r4` | a machine register whose value was not reconstructed | "the counter", "the index" |
| `a1`, `a3` | what the function was entered with in that argument register (x2, x5): the slot, not the parameter's name, type or position in the Dart signature | "the amount", "the second parameter" |
| `f(...)` in a signature | a function whose argument list was not read: a descriptor, the stack, or a double | "takes no arguments" |
| `f()`, `f(a1, a3)` in a signature | the argument registers the body reads; a parameter it never reads is not listed | "takes no arguments", "takes two parameters" |
| `field_0x8` | an instance field at byte offset 8; its name was not recovered | "the `balance` field" |
| `x1 u< x2`, `u>=` | an unsigned comparison; Dart has no operator for one | "`x1 < x2`" |
| `(...)` | a call whose arguments were not reconstructed | "called with the user id" |
| `pool_0x1234` | an object pool slot that resolved to no name | "the HTTP client" |
| `sub_0x1234` | a call to an unnamed function at that address | "the validator" |
| `dispatch(...)` | a virtual call whose target depends on runtime type | "calls `List.add`" |
| a raw `ldur x0, [x1, #7]` line | an instruction the lifter does not model | anything about its meaning |
| `const[47] @0xb9b0{...}` | a const list, shown truncated | guess the rest; run `constants <path> @0xb9b0` |
| `goto L_0x1234` | an edge the structurer could not nest | "a loop" without checking |
| `// reached by no edge ...` | code no branch shown leads to | "it runs after that" |
| `// TRUNCATED: past the instruction cut` | the function goes on past the 4,000 instructions decoded | "it ends here" |

A section under `// reached by no edge ...` lists what it can be, and which one it is was
not worked out; it says `the monomorphic entry` only where the snapshot flags the code as
having one. It starts from bare registers. Where the check falls into the normal entry,
as MonomorphicCheckedEntryAOT emits, the monomorphic one is the function's body and is
lifted as one from that entry: its loops and joins read as they would from the entry. It
starts bare again at the normal entry 24 bytes in, where the callers come in too, so read
no register there as the receiver. If it is a catch entry, the VM enters it with
the exception in x0 and the stack trace in x1 (kExceptionObjectReg and
kStackTraceObjectReg, constants_arm64.h), but nothing in the output says it is one. Where
it runs on into a return or a throw of the body, that code is printed again under it, from
its own state. A goto out of it into the body says `// the names past that label were
worked out for the ways in above it, not checked for this one`: what is past that label
is the body's, so do not say "the catch returns t2".

A name holding `\u202e`, `\u001b`, `\u200b` or another `\u` escape is a name the binary
really carries, with a character in it that would reorder, hide or colour the text around
it if printed: a bidi override, a control, a zero width space. Jadart writes it as the
escape, and takes it back that way; a backslash in a name prints as `\\`. Quote it as
written; it says the binary was crafted or tampered with, not that it was decoded wrong.
On a name ending in `~`, which a `--sigs` library supplied, it says that library was.
A name ending in `\... (N chars)` ran past 200 characters as printed and was cut there;
N is its whole length, and the cut spelling is the one commands take back. `symbols -j`
keeps names as written, `name`, `owner` and `library` cut at 200 characters, and gives
each whole length under `cut`; a name cut there is not one to look a function up by, so
use its `va`.

A string literal in quotes is escaped the same way, and a quote inside it prints as `\"`:
`"a\" ; isAdmin = true"` is one string, never code after a string. A literal whose escaped
text runs past 200 characters ends in `..."`, cut short, in a `const[N]{...}` label too;
`strings` prints it whole. `constants` quotes a list's string elements as well: `"a, b"`
is one element, and `"0x10"` is a string, not the int `0x10`. It prints each thing once.
A string whose escaped text runs past 200 characters is whole where it first appears and
`same as 0x...[i]` where it comes back: the list, and the element, that hold it whole.
A slot whose list was listed already is `same as 0x...`, that list's offset. `-j` says
both with `same_as`: `{"same_as": offset}` in place of `elements`, and
`{"same_as": offset, "index": i}` in place of the string.

Two examples, so the distinction is concrete.

> Body: `var t0 = pool_0xb968.field_0x8(...);`
>
> **Wrong:** "It calls the list's `add` method with the decoded byte."
> **Right:** "It calls an unresolved pool target, with arguments the tool did not
> reconstruct. Resolving it needs `jadart xrefs` or a dynamic trace."

> Body: `if (a1 > this.field_0x8) { return false; }`
>
> **Wrong:** "If the amount exceeds the balance it fails."
> **Right:** "It compares its second register argument against the field at offset 8 and
> returns false when greater. Neither name is in the snapshot; `jadart classes` will say
> whether the owning class declares a name for offset 8, and the argument's name would
> need the source or a caller that says what it passes."

The second one matters most, because it is the tempting case. The structure is fully
recovered and only the names are missing, so a plausible story is easy to tell. Tell the
structure; leave the names alone.

---

## What survives AOT, and what does not

Knowing this stops you from hunting for things that cannot exist.

**Usually survives.** Class names and the library each came from. Method names. String
and identifier literals. The call graph. Virtual dispatch selector names. Const data
tables (keystreams, lookup tables, magic constants). Which native libraries are loaded
and which symbols are read out of them.

**Usually gone.** Local variable names. Most instance field names, though a real minority
survive and `jadart` prints those. Generic type arguments after erasure. Anything only a
debug build carries.

**What `--obfuscate` changes.** It renames identifiers. It does **not** encrypt strings,
and it does not touch const data. So on an obfuscated build you lose names and keep
structure, string cross-references, and every embedded table. That is usually enough.

**Where the secret actually lives.** If an app stores a secret as a plain literal, `strings`
finds it and no decompiler is needed. When `strings` comes up empty the interesting cases
are: a value XORed or otherwise derived at runtime, a hash compared against an embedded
digest, or a key assembled from parts. All three leave their constants in the binary, which
is what `jadart constants` is for.

---

## Route by question

Do not start with `export`. On a real app it is well over a hundred thousand lines and it
will bury the answer along with your context budget.

| The question | Run |
|---|---|
| Is this even a Flutter app, and is it supported? | `jadart info <path>` |
| What is in it? | `jadart classes <path> -f <filter>` |
| What does one class do? | `jadart decompile <path> <Class>` |
| What does one function do? | `jadart lift <path> <symbol>` |
| Show me the machine code | `jadart disasm <path> <symbol>` |
| What text does it contain? | `jadart strings <path> -g <pattern>` |
| What data tables are embedded? | `jadart constants <path>` |
| What is in the table a body names as `@0xb9b0`? | `jadart constants <path> @0xb9b0` |
| Who touches this string or function? | `jadart xrefs <path> <kind> <what>` |
| What are the virtual calls really calling? | `jadart selectors <path>` |
| What native code does it reach into? | `jadart ffi <path>` |
| Did the parse actually work? | `jadart verify <path>` |
| I want the whole tree on disk | `jadart export <path> <outdir>` |
| Where is this function in IDA, Ghidra or radare2? | `jadart symbols <path> -f <name>` |
| Name every function inside one of those | `jadart symbols <path> --format r2\|ghidra\|ida` |
| Watch a function at run time | `jadart hook <path> <Class.method>` |
| Many calls on one binary | `jadart serve <path> --socket <s> &`, then `--server <s>` |

`symbols` gives the real virtual address, file offset and size of every code range, and
`--format` writes a script that names them inside the tool. Addresses are relative to
the instructions symbol the binary exports, which `jadart info` prints as the anchor
(`_kDartIsolateSnapshotInstructions`, or `_kDartSnapshotText` from Dart 3.13), so a
rebased load still lines up, and a script refuses
a binary whose bytes do not match rather than applying the wrong names. Any address jadart
prints can go straight into another tool: `functions`, `disasm`, `lift`, `decompile` and
`xrefs` all print the virtual address. (Older releases printed `.text+0x..`, which was
relative to the VM instructions image and landed inside a different function.)

`hook` writes a Frida script (Android arm64) that attaches where calls actually enter and
logs arguments from the registers or the Dart stack, whichever this Dart release and
function kind use. It only logs; it changes nothing in the process.

`xrefs` accepts an explicit kind:

```text
jadart xrefs <path> string <pattern>
jadart xrefs <path> string <pattern> --exact
jadart xrefs <path> pool <offset>
jadart xrefs <path> function <name-or-address>
jadart xrefs <path> string <pattern> --class <Class>
```

A matching string that no code loads directly is reported under `"unloaded"` in `-j`, not
listed with the loads. No direct load is not proof nothing uses it: a closure or a value
built at runtime can still reach it.

For the shape of the code around a function, ask for a graph instead of chaining xrefs:

```text
jadart xrefs <path> function <name> --graph -j --depth 2   # nodes, edges, kinds
jadart xrefs <path> function <name> --dot                  # Graphviz, ids are addresses
jadart disasm <path> <name> --graph -j                     # the lifter's blocks and edges
```

An edge of kind `virtual` is a call that may land there, not one that does.

`jadart` takes an APK, an IPA, a directory or a bare `libapp.so` / `App.framework/App`.
You do not need to unzip anything first.

Add `-j` to any command for JSON. Exit code is `0` on success, `1` when nothing in the
binary matched what you asked for or an acceptance gate failed, `2` when the input will
not parse or the command line is wrong, `3` when jadart itself has a bug, which is never
your file's fault, and `130` when interrupted. A miss is `1`, not `2`: the file was fine
and the name is not in it. With `-j` the error is JSON too, so you never have to parse
stderr. Read through a pipe, as
you do, `-j` is one compact line with no indentation; only a terminal gets it indented.

`lift -j` gives each function `calls` and `strings` beside `body`, so do not grep the body
for them. `calls` is one entry per callee in order of first use: `name` as printed, `kind`
(`direct`, `alloc`, `stub`, `tail`, `virtual`, `indirect`), `va` where the callee is a
range in this binary, and `count` where it is called more than once. `strings` is one
entry per pool slot: `text` as printed and `pool`, which `xrefs <path> pool` takes. Part
of what `benchFetchToken` gives:

```
"calls":[{"name":"Future.delayed","kind":"direct","va":1840620},
{"name":"List","kind":"alloc","va":2970980}],
"strings":[{"text":"\"FLUBENCH{async_marker}:\"","pool":"0x96f8"}]
```

---

## Workflows

### First contact

```
jadart info app.apk        # epoch, architecture, object counts
jadart verify app.apk      # byte-exact gates: did the parse really work?
```

If `verify` reports gates passing, everything downstream rests on a parse that was checked
against the format, not guessed at. If it refuses, believe it.

### Find the logic behind a screen or a button

```
jadart strings app.apk -g "<label the user sees>"
jadart xrefs app.apk string "<that string>"        # who references it
jadart decompile app.apk <the class it named>
```

Working backwards from a visible string is almost always faster than reading the class
tree top down.

### A hardened target: no literal to find

This is the case that matters, and it works even on a fully obfuscated build.

```
jadart constants app.apk
```

Read the table lengths. They are the tell:

- **32 or 64 words** starting `0x428a2f98, 0x71374491` is SHA-256's round constant table
- **8 words** sitting near it is very often an embedded digest to compare against
- **an odd length** matching no known algorithm is usually the app's own data: a
  keystream, an S-box, an encoded payload
- **256 bytes** is a substitution table

Then find the code that reads the interesting one and lift it:

```
jadart xrefs app.apk pool 0x<pool offset from constants>
jadart lift app.apk <the function that came back>
```

The arithmetic comes out readable even when every name is gone. A recovered loop will show
you the multiplier, the addend, the mask and the shift of a keystream generator directly.
Combine those constants with the table and reproduce the computation offline. That is the
whole crack, and none of it required the app to run.

### Obfuscated builds

Names are gone, so stop looking for them. Structure, strings, xrefs and const data all
survive. Search by *shape* instead of by name: table lengths, recognisable constants,
string cross-references, call-graph position. `jadart selectors` may recover far fewer
names than on a clean build; that is expected, not a malfunction.

---

## Outcomes that look like errors and are not

Report these as findings, not as failures. Do not retry them and do not work around them.

**`UnknownEpoch`.** The binary was built by a Dart release whose snapshot format is not
registered. This is the tool refusing to parse with a grammar that might be wrong, which is
correct: a wrong grammar produces a plausible and entirely fictional object graph. The
error text carries the version hash and the command that would identify it. Report the hash.

**`UnsupportedTarget`.** Known Dart release, architecture or pointer model with no grammar.

**`UnsupportedArch`.** The snapshot parsed and the instructions are for an architecture the
expression lifter does not model. Everything that does not come from machine code still
works: classes, libraries, strings, verify.

**`MissingDisassembler`.** `capstone` is not installed. It is optional on purpose, because
the snapshot layer does not need it. Install `jadart[disasm]`.

Everything the library raises for input it cannot handle derives from `JadartError`, so in
a script you can catch that one class and move to the next file.

---

## Cost discipline

You are working with a large binary and a limited context.

- Never paste a whole export into your context. Query for what you need.
- Prefer `lift <symbol>` over `decompile <Class>` over `export`.
- Use `-g` / `-f` filters on `strings` and `classes`. Unfiltered output on a real app is
  tens of thousands of lines.
- `constants` on a large app is long. Read the lengths and offsets first, then pull the
  one table you want.
- When you need the whole tree, `export` it to disk and read individual files, rather than
  bringing all of it into context at once.

### Many calls on one binary

Every call reads the binary again before it answers. On a 26 MB app that is 0.8 to
1.6 s per `lift`, `disasm`, `decompile` or `xrefs ... string`, 2.5 s per
`xrefs ... function` or `functions -f NAME` and 5.5 s per `functions`, whatever you
asked for. When you expect more than a handful of calls on one binary, start a server
once, in the background, and name its socket on every call after that:

```
mkdir -m 700 -p ~/.jadart
jadart serve app.apk --socket ~/.jadart/app.sock >/dev/null 2>&1 &
jadart --server ~/.jadart/app.sock lift app.apk Vault.unlock
jadart --server ~/.jadart/app.sock xrefs app.apk function Vault.unlock
```

The output is identical to the same command without `--server`, so everything else in
this file applies unchanged. The first call that needs a table builds it; later calls
take about 0.1 s. The socket must be in a directory only you can write, so not in
`/tmp`, where another user could put their own at that path: jadart refuses a shared
directory. Keep the path short (about 100 bytes at most).

- A line `jadart: server at ... not used, <reason>; answering without it` on stderr means
  the answer below it is still correct and was computed the slow way. Start the server
  again if you have more calls to make.
- One server holds one binary, and holds its tables in memory: 813 MB for that 26 MB
  app once every kind of command has been asked. For a second binary start a second
  server on another socket path, and expect that much again.
- A call waits 10 s for the server, then answers the slow way with that same line. The
  first `functions` or `xrefs ... function` builds the whole call graph, 5.5 s on that
  app even when it names one function, and can take longer on a larger one: give that
  call `--server-wait 60`.
- `export` and anything with `--sigs` never use the server.
- The server stops by itself after 30 minutes without a request. Stop it sooner with
  `kill` when you are done, which also gives the memory back.

---

## Reporting

State what was recovered, then state what was not, then say what would close the gap.

A finding is worth more when its limits are on the page. "The check compares the input's
SHA-256 against an embedded digest at pool offset 0xb9d8; the digest is recoverable but the
accepted input is not, since a hash cannot be inverted" is a real answer. "The password is
probably admin123" is not an answer at all, and the difference is the entire value of doing
this with a tool that refuses to guess.
