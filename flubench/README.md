# FluBench (Phase 0)

A benchmark for Flutter/Dart reverse-engineering tools. The corpus is our own
labeled construct app, so the declared class/method/function names, the string
literals, and the call graph are exact ground truth. A tool is scored on how much
of that it recovers from the compiled `libapp.so`.

This is the harness the whole research program measures against (RESEARCH.md).
Phase 0 is a single-Dart-version, single-tool (unflutter) slice; the structure is
built to expand along every axis.

## Layout

```
flubench/
  app/                 Flutter corpus app
    lib/constructs.dart  the labeled constructs (ground truth lives here)
    lib/main.dart        driver that references every construct (no tree-shaking)
  build.sh             build clean + obfuscated, extract arm64 libapp.so + symbols
  groundtruth.py       source -> ground_truth.json (classes/functions/strings)
  score.py             one tool's output -> recall scorecard
  run.sh               build -> ground truth -> run unflutter -> score
  artifacts/           build outputs, ground truth, scorecards (git-ignored)
```

## Constructs (the axes of recovery being probed)

| id | symbol | what it stresses |
|----|--------|------------------|
| C1 | benchCheckSecret | string-literal recovery + equality |
| C2 | benchComputeChecksum | tagged-Smi arithmetic, loop, branch |
| C3 | benchMakeAdder | closure capture |
| C4 | benchFirstOrDefault | generics |
| C5 | benchFetchToken | async (SuspendState lowering) |
| C6 | BenchAccount / benchWithdraw | class with fields + method |
| C7 | benchDecodeFlag | computed secret (base64 + xor), NOT a literal |
| C8 | benchMakePair | record type (Dart 3) |

## Run

```bash
bash flubench/run.sh
```

Requires `flutter` on PATH and unflutter built at `../unflutter/unflutter`.
Prints a scorecard: clean vs obfuscated recall for classes / functions / strings.

## Metrics (Phase 0)

- Recall: fraction of ground-truth symbols found anywhere in the tool's output.
  Generous substring match, so a tool is never under-credited for a naming-format
  difference. False-positive analysis is a separate axis to add.

## Expansion plan (later phases)

- Dart versions: build the same app across 3.8 / 3.10 / 3.11 / 3.12 via FVM; adds
  the version-robustness axis (does the tool identify and correctly parse each).
- Tools: add Blutter and Ghidra+scripts backends to score.py (one loader each).
- Constructs: expand the set; tag each with the tier it exercises.
- Tiers (decompiler): Tier 0 skeleton recall is what score.py measures today; add
  Tier 1+ body fidelity via compile-and-diff against the known source.
- Robustness signal: flag when a tool parses without positively identifying the
  version (unflutter's silent-fallback failure mode) vs failing loud.
- Negative/FP axis: measure invented names and mis-attributed xrefs, not just recall.

## Notes

- The obfuscated build keeps its de-obfuscation map under `artifacts/symbols/`
  (`--split-debug-info`), which is a second ground-truth source for scoring
  obfuscated-name recovery.
- Corpus apps use `ndkVersion = "29.0.14206865"` to avoid the corrupt-NDK auto
  download (see FINDINGS.md).
