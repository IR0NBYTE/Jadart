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
  written: `name`,
  `owner` and `library` are cut at 200 characters, `qualified` is the cut owner and
  name joined, and a record with a field cut gives its whole length under `cut`. A cut
  name there is not one `hook` or `disasm` can find; its `va` is. `cut` is a new key,
  so the format version stays 1. `signatures` leaves a function whose name is longer
  than 200 characters out of the library, as it does one holding a line break; it
  writes the same library from both fixtures and the 3.12.2 build as before.
  `FillResult.names` escapes a string once, not once per ref on it. The longest name
  in the fixtures, the two CTF apps in ctfbench and the corpus is 165 characters, so
  exports at tiers 1 to 3 (1 and 2 for arm32), `functions`, `classes`, `libraries`,
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
  field compared with itself, which is a frame slot it cannot yet name across a call
  (#64). Closes #57.

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
