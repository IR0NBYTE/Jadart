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
in it: the natural move when reading `pool_0xb968.field_0x7(...)` is to say what it
"probably" does, and that turns a careful analysis into a confident fabrication carrying
the authority of a byte-exact tool.

So: **report gaps as gaps.** If the user needs the answer, say what would close it
(a dynamic trace, a reference binary, the app's own network calls), not what it might be.

### The vocabulary of a refusal

Every one of these means *the tool declined*, not *the tool failed*:

| You see | It means | Do not say |
|---|---|---|
| `x2`, `x19`, `r4` | a machine register whose value was not reconstructed | "the counter", "the index" |
| `field_0x8` | an instance field at byte offset 8; its name is not in the snapshot | "the `balance` field" |
| `(...)` | a call whose arguments were not reconstructed | "called with the user id" |
| `pool_0x1234` | an object pool slot that resolved to no name | "the HTTP client" |
| `sub_0x1234` | a call to an unnamed function at that offset | "the validation routine" |
| `dispatch(...)` | a virtual call whose target depends on runtime type | "calls `List.add`" |
| a raw `ldur x0, [x1, #7]` line | an instruction the lifter does not model | anything about its meaning |
| `const[47] @0xb9b0{...}` | a const list, shown truncated | guess the rest; run `constants` |
| `goto L_0x1234` | an edge the structurer could not nest | "a loop" without checking |

Two examples, so the distinction is concrete.

> Body: `var t0 = pool_0xb968.field_0x7(...);`
>
> **Wrong:** "It calls the list's `add` method with the decoded byte."
> **Right:** "It calls an unresolved pool target, with arguments the tool did not
> reconstruct. Resolving it needs `jadart xrefs` or a dynamic trace."

> Body: `if (x2 > this.field_0x8) { return false; }`
>
> **Wrong:** "If the amount exceeds the balance it fails."
> **Right:** "It compares an unreconstructed register against the field at offset 8 and
> returns false when greater. The field name is not in the snapshot; `jadart classes` will
> say whether the owning class declares a name for offset 8."

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
| Who touches this string or function? | `jadart xrefs <path> <what>` |
| What are the virtual calls really calling? | `jadart selectors <path>` |
| What native code does it reach into? | `jadart ffi <path>` |
| Did the parse actually work? | `jadart verify <path>` |
| I want the whole tree on disk | `jadart export <path> <outdir>` |

`jadart` takes an APK, an IPA, a directory or a bare `libapp.so` / `App.framework/App`.
You do not need to unzip anything first.

Add `-j` to any command for JSON. Exit code is `0` on success and `2` on failure, and with
`-j` the error is JSON too, so you never have to parse stderr.

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
jadart xrefs app.apk "<that string>"        # who references it
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
jadart xrefs app.apk 0x<pool offset from constants>
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

---

## Reporting

State what was recovered, then state what was not, then say what would close the gap.

A finding is worth more when its limits are on the page. "The check compares the input's
SHA-256 against an embedded digest at pool offset 0xb9d8; the digest is recoverable but the
accepted input is not, since a hash cannot be inverted" is a real answer. "The password is
probably admin123" is not an answer at all, and the difference is the entire value of doing
this with a tool that refuses to guess.
