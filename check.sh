#!/usr/bin/env bash
# Everything that has to hold before a release, run locally.
#
# This is what .github/workflows/tests.yml used to run on every push. That workflow is
# disabled, so these checks live here instead: same checks, run when you decide to.
#
#   ./check.sh            the fast set, about a minute
#   ./check.sh --full     adds the CFG edge check and the determinism diff, a few minutes
set -uo pipefail
cd "$(dirname "$0")"

PY=${PY:-$PWD/.venv/bin/python}
JADART=${JADART:-$PWD/.venv/bin/jadart}
FULL=0
[ "${1:-}" = "--full" ] && FULL=1

CLEAN=flubench/artifacts/clean/lib/arm64-v8a/libapp.so
OBF=flubench/artifacts/obf/lib/arm64-v8a/libapp.so
fail=0

step() {
  printf '\n== %s\n' "$1"; shift
  if "$@"; then return 0; fi
  echo "   FAILED"; fail=1
}

if [ ! -x "$PY" ]; then
  echo "No interpreter at $PY."
  echo "Set one up with:  python3 -m venv .venv && .venv/bin/pip install -e './framework[disasm]' pytest"
  exit 2
fi

step "test suite" env -C framework "$PY" -m pytest tests -q -rs

# Byte-exact, and the reason a wrong grammar is caught rather than guessed at. The exit
# code is the contract: 0 when every applicable Tier-A gate passed.
for f in "$CLEAN" "$OBF"; do
  step "acceptance gates: $(basename "$(dirname "$(dirname "$(dirname "$f")")")")" \
    "$JADART" verify "$f"
done

# The measured claims in EVAL.md, against what the tool actually reports.
step "measured claims still hold" "$PY" framework/tools/measure.py --check

# The package has to work without the disasm extra, or that claim is only true untested.
step "parses with no capstone" "$PY" - <<'PYEOF'
import sys
sys.modules["capstone"] = None
sys.path.insert(0, "framework")
import jadart
n = len(jadart.strings("flubench/artifacts/clean/lib/arm64-v8a/libapp.so"))
print(f"   {n} strings recovered with capstone blocked")
PYEOF

if [ "$FULL" = 1 ]; then
  # A rendered edge the CFG does not have is the worst defect this tool can ship: the
  # output stays plausible and says control goes somewhere it cannot.
  for f in "$CLEAN" "$OBF"; do
    step "no function claims an edge its CFG lacks" "$PY" framework/tools/cfgcheck.py "$f"
  done

  # Python randomises string hashing per process, and a set iterated in hash order has
  # reached the output here before: two runs, two different names, about one run in five.
  step "same binary exports to the same bytes" bash -c '
    t=$(mktemp -d)
    for s in 1 424242; do
      PYTHONHASHSEED=$s '"$JADART"' export '"$CLEAN"' -o "$t/$s" -q >/dev/null || exit 1
    done
    diff -r "$t/1" "$t/424242" >/dev/null && echo "   identical across two hash seeds"'
fi

echo
if [ "$fail" = 0 ]; then
  echo "all checks passed"
else
  echo "SOMETHING FAILED, see above"
fi
exit "$fail"
