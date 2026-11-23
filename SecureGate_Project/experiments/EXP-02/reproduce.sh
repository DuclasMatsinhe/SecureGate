#!/usr/bin/env bash
# Reproduce the EXP-02 findings and say, check by check, whether they match the published final run.
#
# Usage (from the repository root, with the project's virtual environment active):
#   bash SecureGate_Project/experiments/EXP-02/reproduce.sh            # checks 1-4, about 5 minutes, no scanners needed
#   bash SecureGate_Project/experiments/EXP-02/reproduce.sh --scanners # also re-runs one real-scanner shard of L2 and of R
#
# The published results are read from the branch semester8-exp02-results (fetched into ../exp02-results if missing).
set -u
EXP=SecureGate_Project/experiments/EXP-02
RUN=final-run-44892918564
FROZEN=$(cut -d' ' -f1 "$EXP/FROZEN.sha256")
WITH_SCANNERS=0; [ "${1:-}" = "--scanners" ] && WITH_SCANNERS=1
OUT=$(mktemp -d /tmp/securegate-reproduce.XXXXXX)
pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1"; fail=$((fail+1)); }

[ -f "$EXP/harness.py" ] || { echo "Run this from the repository root."; exit 2; }
python -c "import security_engine" 2>/dev/null || { echo "Activate the virtual environment first (. .venv/bin/activate)."; exit 2; }

if [ ! -d ../exp02-results/EXP-02/$RUN ]; then
  echo "Fetching the published results into ../exp02-results ..."
  git fetch -q origin semester8-exp02-results && git worktree add -q ../exp02-results FETCH_HEAD 2>/dev/null \
    || (cd ../exp02-results && git fetch -q origin semester8-exp02-results && git checkout -q FETCH_HEAD)
fi
R=../exp02-results/EXP-02/$RUN
[ -d "$R" ] || { echo "Published results not found at $R"; exit 2; }
echo "Published run: $R"
echo "Working folder: $OUT"
echo

echo "1. The protocol in this checkout is the frozen protocol"
h=$(python "$EXP/harness.py" protocol --out "$OUT/protocol.json")
[ "$h" = "$FROZEN" ] && [ "$h" = "$(cat "$R/protocol.sha256")" ] && ok "SHA-256 $h" || bad "protocol hash $h differs from frozen $FROZEN"

echo "2. Every published shard ran the frozen protocol in final mode"
n=$(grep -l "\"protocol_sha256\": \"$FROZEN\"" "$R"/shards/*/environment.json | xargs grep -l '"final": true' | wc -l)
[ "$n" = "11" ] && ok "11 of 11 shards" || bad "$n of 11 shards"

echo "3. The published numbers follow from the published raw runs"
python "$EXP/analysis.py" --title "EXP-02 (final), workflow run 44892918564" --out "$OUT/analysis" "$R"/shards/* > /dev/null
diff -q "$OUT/analysis/summary.md" "$R/analysis/summary.md" > /dev/null && ok "analysis/summary.md reproduced exactly" || bad "re-analysis differs (diff $OUT/analysis/summary.md $R/analysis/summary.md)"

echo "4. Re-running the simulated level (L1, 2,360 runs) gives the same verdicts"
python "$EXP/harness.py" run --level L1 --reps 10 --out "$OUT/L1" > "$OUT/L1.log" 2>&1
r=$(python "$EXP/compare_runs.py" "$R/analysis/runs_all.csv" "$OUT/L1/runs.csv" | head -1)
echo "$r" | grep -q " 0 differ" && ok "$r" || bad "$r"

if [ $WITH_SCANNERS = 1 ]; then
  echo "5. Real scanners are the pinned versions"
  v="$(semgrep --version 2>/dev/null | head -1) / $(pip-audit --version 2>/dev/null) / $(gitleaks version 2>/dev/null)"
  echo "$v" | grep -q "1.180.0" && echo "$v" | grep -q "2.10.1" && echo "$v" | grep -q "8.30.1" && ok "$v" || bad "found: $v (need Semgrep 1.180.0, pip-audit 2.10.1, Gitleaks 8.30.1; see VERIFY.md section 4)"
  echo "6. Re-running one real-scanner shard of L2 (synthetic projects) gives the same verdicts"
  python "$EXP/harness.py" run --level L2 --shard 1/5 --reps 1 --out "$OUT/L2-1" > "$OUT/L2-1.log" 2>&1
  r=$(python "$EXP/compare_runs.py" "$R/analysis/runs_all.csv" "$OUT/L2-1/runs.csv" | head -1)
  echo "$r" | grep -q " 0 differ" && ok "$r" || bad "$r (see $OUT/L2-1)"
  echo "7. Re-running one real-scanner shard of R (public projects) gives the same verdicts"
  python "$EXP/harness.py" run --level R --shard 3/5 --reps 1 --out "$OUT/R-3" > "$OUT/R-3.log" 2>&1
  r=$(python "$EXP/compare_runs.py" "$R/analysis/runs_all.csv" "$OUT/R-3/runs.csv" | head -1)
  echo "$r" | grep -q " 0 differ" && ok "$r" || bad "$r (pip-audit data are live: check whether only finding counts changed; see $OUT/R-3)"
fi

echo
echo "Result: $pass passed, $fail failed. Outputs kept in $OUT"
[ $fail = 0 ]
