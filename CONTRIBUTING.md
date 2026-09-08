# Contributing to Jadart

Thanks for looking. Jadart decompiles Flutter / Dart AOT snapshots, so most work here is
either format work (a new Dart version, a new target) or decompiler work (better output
from the same bytes).

## Ways to contribute

- Bug reports. Include the snapshot version hash and the exact command you ran.
- A new Dart epoch: derive a release's cluster grammar and prove it with the gates.
- A new target: 32-bit / ELF32, or another container.
- Decompiler quality: expressions, control flow, naming.
- Corpus and evaluation: more binaries, more comparison rows in EVAL.md.

## Getting started

You need python3 and nothing else for the core. Disassembly needs capstone.

```bash
cd jadart/framework
pip install -e '.[disasm]' pytest
python3 -m pytest tests -q      # 193 tests, all must pass
```

Use pytest, not `python3 tests/test_core.py`. The file still carries a script runner for
convenience, but pytest is the only collector that cannot miss a test.

`./check.sh` from the repository root runs the suite, the acceptance gates on both
fixtures, the measured claims and the no-capstone install. `./check.sh --full` adds the
CFG edge check and the determinism diff. Run it before you open a pull request: there is
no CI doing it for you.

The suite runs against the committed FluBench fixtures, so a fresh clone works with no
Flutter install. To also exercise the ELF symbol backfill, point it at any unstripped
`dwarf_stack_traces_mode` build:

```bash
JADART_REALAPP_LIB=/path/to/libapp.so python3 -m pytest tests -q
```

`JADART_EXTRA_BINARIES` does the same for the optional iOS and x64 fixtures: a
colon-separated list of paths, each one skipped with a message when absent.

Use the tool on something before you change it. Run these from `framework/`:

```bash
python3 -m jadart verify path/to/libapp.so
python3 -m jadart decompile path/to/libapp.so BenchAccount
```

## Correctness comes first

Read this part before writing code. Jadart exists because the other tools in this space
guess. Meet unflutter with a snapshot it doesn't know and it falls back to its newest
hand-coded profile, then prints confident nonsense. Three rules follow from not doing
that.

**Never guess a grammar.** If the version, the architecture or the pointer model isn't
one we have validated, raise and stop. `UnsupportedTarget` fires before a single snapshot
byte is read. A fallback path added "so it at least does something" is the one change
that will always be rejected.

**"It parsed" is not evidence.** The alloc-pass self-check (`assigned == num_objects`)
passes on a build whose pointer model we have no grammar for, because the wrong grammar
happens to read the same number of varints. That was a real silent-wrongness window in
this project, found in an audit (EVAL.md, "Target resolution"). A clean parse proves
nothing by itself.

**Support is a measured claim.** A version or target counts as supported only when every
Tier-A gate passes on at least three independently built binaries, one of which is an
`--obfuscate` build:

```bash
python3 -m jadart verify path/to/libapp.so
```

The gates (`framework/jadart/verify.py`) cross-check values the snapshot encodes twice in
independently derived places, so agreement can't survive a misparse: the CLASS alloc cid
list against the fill pass's own `class_id`s (G3), String alloc lengths against the
lengths the fill pass re-reads (G4), instance geometry against that cid's Class fields
(G6), `Function.code_index - 1` against the instructions-table slot (G7), the dispatch
table anchor (G11). One binary is a hypothesis, not support.

When something can't be recovered, render the honest form and say why. Instance fields
print as `this.field_0x8` because AOT tree-shakes the field names. A selector no two
classes corroborate stays `sel_0x<off>`. An instruction the lifter doesn't model falls
back to its arm64 line. Nothing is invented.

## Adding support for a new Dart version

Each step has a tool. Run them from `framework/`.

**1. Identify it.** The snapshot version hash is an MD5 over 15 files in `runtime/vm`
(`tools/make_version.py` in dart-lang/sdk), so you can compute the hash any SDK tag would
produce by fetching about 2.5 MiB over HTTP. No clone, no VM build.

```bash
python3 tools/sdk_source.py --tag 3.11.5 --hash
python3 tools/sdk_source.py --identify <hash> --tags 3.11.5 3.11.0
```

Target the hash, not the version number. One hash usually covers a whole minor line, but
measure it rather than assuming it: 3.12.0 and 3.12.2 have different hashes.

**2. Generate the epoch.** `tools/gen_epoch.py` derives the cid table, the typed-data
anchors and the ClassIdTag layout from that release's own `class_id.h` and `raw_object.h`.

```bash
python3 tools/gen_epoch.py --tag 3.11.5
```

It emits `grammars` empty on purpose. A generated epoch identifies the version and still
refuses to parse it, which gives the useful failure ("dart 3.11.5, identified, no
validated cluster grammar") instead of a confident wrong answer.

**3. Get a binary.** `tools/build_corpus.py` drives the FluBench app through pinned SDKs
and collects one `libapp.so` per format hash.

```bash
python3 tools/build_corpus.py --plan          # what would be built, and why
python3 tools/build_corpus.py --build 3.41.9
```

**4. Fill in the grammar, then prove it.** Start from the closest validated epoch, work
out that release's per-cluster ReadAlloc deltas, and run `jadart verify`. Only when the gates
pass on three binaries does `versions.py` get to claim support.

Expect drift, and expect it in small places. Between 3.11.5 and 3.12.2 the object header's
immutable bit moved from 6 to 7, so a canonical String cluster tag reads `0x5d042` on one
and `0x5d082` on the other while the cid field still decodes fine. That is the class of
bug the gates are there to catch.

## What to work on

Check the open issues first. These come straight from the roadmap and are real:

- **A new Dart release.** Every Flutter stable and beta since 2.19.6 is registered, so
  the next one is the task, and the steps above are the whole recipe. An
  "unknown format epoch" issue with a version hash is the usual starting point.
- **arm32 at Tier 3.** Tiers 1 and 2 already decode `armeabi-v7a`; the lifter refuses
  because it has no register-role model for the arm32 calling convention.
  [docs/support.md](docs/support.md) says exactly where it stops and why.
- **A navigable UI.** Output is a flat dump right now. Cross-references, click-through
  from a call to its target, a class tree.
- **Blutter and Ghidra rows in EVAL.md.** Both are pending in the comparison table.
  Running them over the FluBench corpus and scoring with `flubench/score.py` closes a hole
  in the evaluation and needs no Jadart internals.

Anything bigger than a weekend, open an issue first so we can agree on the approach before
you do the work.

## Code style

- `jadart/` is stdlib-only. capstone is the single exception, and only for disassembly.
  Nothing under `jadart/` touches the network or shells out. Dev-time code in `tools/` may
  fetch over HTTP; it stays stdlib too.
- Comments explain *why*, not what. If the code is clear, leave it alone.
- Cite the source. Anything derived from the VM carries a dart-lang/sdk reference with
  file and line, like `app_snapshot.cc:9391`. Those citations are the most valuable thing
  in the codebase. Keep them accurate and don't drop them in a refactor.
- No dash-spliced prose in comments or docs. Use two sentences, a comma, or parentheses.
  Hyphens that are code stay: `a - b`, `--json`, `no-compressed-pointers`.
- Keep lines within 90 columns.
- Fail loud. Raise a named exception rather than letting a bare `IndexError` escape, and
  never add a silent fallback.

## Pull requests

1. Fork and branch off `main`.
2. One bug fix or one feature per PR.
3. `python3 -m pytest tests -q` passes, and the count doesn't go down. New behaviour
   comes with a test.
4. Format or grammar work: paste the `jadart verify` output in the PR description. Say which
   binaries, which gates, and confirm one was an `--obfuscate` build.
5. Describe what changed and why. Numbers beat adjectives.

## License

MIT, same as the rest of the project. By contributing you agree your work ships under it.
