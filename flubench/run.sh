#!/usr/bin/env bash
# FluBench Phase 0 harness: build the corpus, extract ground truth, run a tool
# (unflutter) on clean and obfuscated libapp.so, and score name/string recall.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ART="$HERE/artifacts"
UNFLUTTER="$HERE/../unflutter/unflutter"

echo "== 1. build corpus =="
bash "$HERE/build.sh"

echo "== 2. ground truth =="
python3 "$HERE/groundtruth.py" "$HERE/app/lib/constructs.dart" > "$ART/ground_truth.json"
python3 -c "import json;d=json.load(open('$ART/ground_truth.json'));print('  classes',len(d['classes']),'functions',len(d['functions']),'strings',len(d['strings']))"

echo "== 3. run unflutter (clean) =="
"$UNFLUTTER" "$ART/clean/lib/arm64-v8a/libapp.so" >/dev/null 2>&1 || true
echo "== 4. run unflutter (obfuscated) =="
"$UNFLUTTER" "$ART/obf/lib/arm64-v8a/libapp.so" >/dev/null 2>&1 || true

echo "== 5. score =="
python3 "$HERE/score.py" --truth "$ART/ground_truth.json" \
  --unflutter-out "$ART/clean/lib/arm64-v8a/libapp.unflutter" --label clean \
  > "$ART/score_clean.json"
python3 "$HERE/score.py" --truth "$ART/ground_truth.json" \
  --unflutter-out "$ART/obf/lib/arm64-v8a/libapp.unflutter" --label obf \
  > "$ART/score_obf.json"

echo ""
echo "== scorecard (Dart $(cat "$ART/dart_version.txt"), backend unflutter) =="
python3 - "$ART/score_clean.json" "$ART/score_obf.json" <<'PY'
import json, sys
rows = [json.load(open(p)) for p in sys.argv[1:]]
print(f"{'build':8} {'classes':>12} {'functions':>12} {'strings':>12}")
for r in rows:
    def c(k): return f"{r[k]['recovered']}/{r[k]['total']} ({r[k]['recall_pct']}%)"
    print(f"{r['label']:8} {c('classes'):>12} {c('functions'):>12} {c('strings'):>12}")
PY
