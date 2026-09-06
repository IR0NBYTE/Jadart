# Security policy

## The threat model is the point

Jadart exists to open binaries you did not build and do not trust. A malware sample, a
competitor's APK, a CTF challenge written specifically to be hostile. Every input is
attacker-controlled by definition, and "don't open untrusted files" is not advice this tool
can take.

So the security bar is: **a crafted snapshot must never do anything worse than produce a
clean error.** Concretely, no input should be able to make Jadart

- execute code, or load anything the user did not point it at,
- write outside the output directory passed to `export -o`,
- consume unbounded memory or disk,
- or, worst of all for a tool like this, **silently return a wrong answer** (see below).

## What is already hardened

These are deliberate, tested properties rather than assumptions:

- **Every stream read is bounds-checked.** Truncated, empty, all-zero and randomly
  perturbed snapshots exit `2` with a message rather than a traceback. Reference ids are
  bounded to 4 bytes.
- **Zip members are size-checked before extraction**, so a decompression bomb in an APK or
  IPA is refused rather than written to disk.
- **`export` strips `.` and `..` from every library URL** before it becomes a path, and
  extracted members are taken by basename, so a crafted library name cannot escape the
  output directory.
- **Unknown format versions are refused, not guessed at.** This is a security property, not
  only a correctness one: a mis-parsed snapshot produces a plausible-looking object graph,
  and someone auditing an app would act on it.

## Reporting

Please report privately first: open a **GitHub security advisory** on the repository
rather than a public issue. Include the input that triggers it if you can share it, or a
description of how to generate one.

There is no bounty. Credit in the release notes if you want it.

### In scope

- Anything from the list at the top of this file.
- Path traversal, resource exhaustion, or writes outside the output directory.
- A parse that succeeds on a crafted input while producing structurally wrong output. This
  is the interesting class for this project: the acceptance gates (`jadart verify`) exist to
  make it detectable, so a way to pass all gates with a wrong parse is a real finding.

### Not in scope

- **Jadart refusing to parse something.** A refusal is the designed behaviour for an
  unknown format version, an unsupported target, or a non-Flutter file. If the message is
  wrong or unhelpful, that is a normal bug. Please file it as one.
- **Crashes with a clean error message and a documented exit code.** Exit `1` means the
  thing you asked for is not in that binary; exit `2` means it will not parse.
- **That the tool works.** Recovering a class tree and method bodies from a shipped app is
  the intended function, not a vulnerability.
- Findings in `capstone`, which is an optional dependency. Report those upstream.

## An unhandled traceback is a bug worth filing

If any input makes Jadart print a Python traceback instead of a message, that is a defect
even when it is not exploitable: it means an error path was never considered, and those are
where the exploitable ones live. A plain issue is fine for these.

## On what this tool is for

Jadart is for reverse engineers, security reviewers, and anyone auditing software they have
a right to audit. Whether analysing a particular binary is lawful depends on where you are
and what you agreed to when you obtained it. That is your call to make, not something a
README can settle for you.
