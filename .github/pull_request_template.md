## What this changes

## Why

Link the issue if there is one.

## Tests

```
cd framework && python3 -m pytest tests -q
```

- [ ] The suite passes and the count didn't go down
- [ ] New behaviour has a test, or this is docs only

Paste the last line (`N passed`).

## Format or grammar work

Skip this section if the PR doesn't touch `versions.py`, `clusters.py`, `fillwalk.py`,
`snapshot.py`, or a container reader.

```
jadart verify path/to/libapp.so
```

- [ ] Every Tier-A gate passes on at least three independently built binaries
- [ ] One of them is an `--obfuscate` build
- [ ] Gate output pasted below, with each binary named

## Checklist

- [ ] `jadart/` stays stdlib-only (capstone is the one exception, disassembly only)
- [ ] Anything derived from the VM cites dart-lang/sdk with file and line
- [ ] Unknown input fails loud. No new silent fallback, no guessed grammar
- [ ] Unrecoverable things render honestly (`field_0x8`, `sel_0x<off>`, raw arm64) rather
      than being invented
- [ ] Lines within 90 columns
