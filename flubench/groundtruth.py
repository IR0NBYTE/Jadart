#!/usr/bin/env python3
"""Extract ground-truth symbols from FluBench construct sources.

The corpus is our own code, so the declared class/method/function names and the
string literals ARE the ground truth. A tool is scored on how many it recovers
from the compiled snapshot.

Usage: groundtruth.py app/lib/constructs.dart [more.dart ...] > ground_truth.json
"""
import json
import re
import sys

# Top-level or method declarations: `<ret/generics> benchName(` and `bool benchWithdraw(`.
# We deliberately anchor on the bench*/Bench* naming convention of the corpus.
FUNC_RE = re.compile(r'\b([A-Za-z_][\w]*)\s*(?:<[^>]*>)?\s*\(', re.M)
CLASS_RE = re.compile(r'\bclass\s+([A-Za-z_][\w]*)', re.M)
# String literals (single or double quoted, no interpolation-only fragments).
STR_RE = re.compile(r"""'([^'\\\n]*(?:\\.[^'\\\n]*)*)'|"([^"\\\n]*(?:\\.[^"\\\n]*)*)\"""")


def extract(paths):
    classes, funcs, strings = set(), set(), set()
    for p in paths:
        src = open(p, encoding="utf-8").read()
        # strip line comments so we do not mine names out of prose
        code = re.sub(r'//[^\n]*', '', src)
        # drop non-data string literals that are not app content:
        #  - import/export/part directives (dart:/package: URIs)
        #  - @pragma(...) annotation arguments (vm:never-inline etc.)
        code = re.sub(r'^\s*(?:import|export|part)\s+[^\n]*', '', code, flags=re.M)
        code = re.sub(r'@pragma\([^)]*\)', '', code)
        for m in CLASS_RE.finditer(code):
            classes.add(m.group(1))
        for m in FUNC_RE.finditer(code):
            name = m.group(1)
            # keep only our corpus-named symbols; skip keywords/framework calls
            if name.startswith("bench") or name.startswith("Bench"):
                funcs.add(name)
        for m in STR_RE.finditer(code):
            s = m.group(1) if m.group(1) is not None else m.group(2)
            if s and len(s) >= 4 and "$" not in s:
                strings.add(s)
    return {
        "classes": sorted(classes),
        "functions": sorted(funcs),
        "strings": sorted(strings),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: groundtruth.py <dart file> [...]")
    print(json.dumps(extract(sys.argv[1:]), indent=2))
