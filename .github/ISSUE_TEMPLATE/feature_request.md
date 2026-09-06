---
name: Feature request
about: A capability jadart doesn't have yet
title: ''
labels: enhancement
assignees: ''
---

## What's missing

## What you're trying to do

The concrete task, not just the feature. It usually changes the design.

## What the output should look like

A sample of the pseudo-Dart, the CLI flag, or the report you'd want.

## How would we know it's right

This is the important one. jadart doesn't ship a capability because it produced plausible
output; it ships one when something independent confirms it. So: which ground truth, which
invariant, which acceptance gate? For format work that means the Tier-A gates in
`framework/jadart/verify.py` on three binaries including an `--obfuscate` build. For
recovery work it usually means FluBench ground truth or a cross-check that a wrong answer
couldn't survive.

## Prior art

Does another tool do this (unflutter, Blutter, Ghidra)? What does it emit, and where does
it stop?

## Scope

Rough guess at the size, and whether you want to implement it yourself.
