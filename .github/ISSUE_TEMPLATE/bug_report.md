---
name: Bug report
about: jadart crashed, refused a binary it should handle, or printed something wrong
title: ''
labels: bug
assignees: ''
---

## What happened

## What you expected instead

## Command

```
jadart <command> path/to/libapp.so ...
```

## The binary

Run `jadart info <libapp.so>` and paste the header block, or fill this in:

- Snapshot version hash:
- Dart / Flutter version, if known:
- Architecture: arm64 / x64 / arm32
- Pointer model: compressed / no-compressed-pointers
- Container: ELF64 / Mach-O
- Built with `--obfuscate`: yes / no
- Built with `dwarf_stack_traces_mode` (default for `flutter build --release`): yes / no

## Gate output

```
jadart verify path/to/libapp.so
```

Paste the result. If a Tier-A gate fails, that failure is usually the bug.

## Error output

The full `jadart: ...` line, or the JSON from `-j`, exactly as printed.

## Environment

- python3 version:
- OS:
- capstone version (only matters for `disasm`, `decompile`, `lift` and friends):

## Notes

Please don't attach a `libapp.so` you don't have the right to share. A version hash, the
gate output, and the traceback are usually enough. If a fixture is needed to reproduce it,
a small FluBench-style app that triggers the same path is ideal.
