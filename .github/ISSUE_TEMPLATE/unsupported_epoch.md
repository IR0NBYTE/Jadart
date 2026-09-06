---
name: Unsupported Dart release
about: Jadart refused a binary with "unknown format epoch"
title: 'epoch: Dart <version> (<version hash>)'
labels: 'epoch'
---

That error is the tool working. It will not parse a release whose grammar it does not
have, because a wrong grammar yields a confident and entirely fictional object graph.

**Paste the full error.** It carries the version hash and the target.

```
$ jadart info <file>
```

**Do you know which Dart release built it?** If not, that is fine, say so. If you do, or
you can run `flutter --version` on the machine that built it, say which.

**Can you share a binary?** Not required. If you cannot, the version hash alone is often
enough to identify the release, and identifying it is the first half of the work.

<!-- Adding an epoch is a bounded task, not an open question: the acceptance gates decide
     when the grammar is right. CONTRIBUTING.md walks through it. -->
