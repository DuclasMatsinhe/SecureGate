# Verifying EXP-02 on your own machine

Four levels of checking, quickest first. Commands assume Linux, macOS or WSL (Windows: use WSL Ubuntu), Python 3.13 and git. Run them from a fresh clone:

```bash
git clone --branch semester8-final https://github.com/DuclasMatsinhe/securegate.git
cd securegate
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q                      # 164 tests, includes the pilot-reproduction test
git fetch origin semester8-exp02-results
git worktree add ../exp02-results FETCH_HEAD
R=../exp02-results/EXP-02/candidate-run-44875857860
```

## 1. Same protocol, same numbers from the raw data (2 minutes, no scanners)

```bash
python SecureGate_Project/experiments/EXP-02/harness.py protocol --out /tmp/protocol.json   # prints the SHA-256
cat $R/protocol.sha256                                                                        # must be identical
python SecureGate_Project/experiments/EXP-02/analysis.py --title "EXP-02 (candidate), workflow run 44875857860" --out /tmp/my-analysis $R/shards/*
diff /tmp/my-analysis/summary.md $R/analysis/summary.md && echo "analysis reproduced"
```

## 2. Inspect any single run

Each shard keeps every run in `runs.tar.gz`: manifest, policy, raw scanner output, CLI output.

```bash
mkdir -p /tmp/l2-3 && tar -xzf $R/shards/L2-3/runs.tar.gz -C /tmp/l2-3
grep -l L2-F9-semgrep $R/shards/*/runs.csv                     # which shard holds a cell
less /tmp/l2-3/runs/<cell>/<arm>-r1/run_manifest.json           # verdict, reasons, evidence per scanner
```

## 3. Re-run the simulated level (2 minutes, no scanners)

L1 is deterministic: every verdict and category must match.

```bash
python SecureGate_Project/experiments/EXP-02/harness.py run --level L1 --reps 10 --out /tmp/my-L1
python SecureGate_Project/experiments/EXP-02/compare_runs.py $R/analysis/runs_all.csv /tmp/my-L1/runs.csv
# expected: "2360 of your runs compared; 0 differ"
```

## 4. Re-run with the real scanners (L2 and R)

Install the pinned tools in a separate virtual environment and put only their commands on PATH:

```bash
python3 -m venv ~/sg-scanners
~/sg-scanners/bin/pip install semgrep==1.180.0 pip-audit==2.10.1
curl -sSfL -o /tmp/gitleaks.tgz https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
echo "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb  /tmp/gitleaks.tgz" | sha256sum -c -
mkdir -p ~/sg-bin && tar -xzf /tmp/gitleaks.tgz -C ~/sg-bin gitleaks
ln -sf ~/sg-scanners/bin/semgrep ~/sg-scanners/bin/pysemgrep ~/sg-scanners/bin/pip-audit ~/sg-bin/
export PATH=~/sg-bin:$PATH
```
(macOS: use the `darwin_arm64` or `darwin_x64` Gitleaks archive; its checksum differs, take it from the release's `checksums.txt`.)

One shard with one repetition takes about 3–5 minutes; the full level takes 1–3 hours on one machine:

```bash
python SecureGate_Project/experiments/EXP-02/harness.py run --level L2 --shard 1/5 --reps 1 --out /tmp/my-L2-1
python SecureGate_Project/experiments/EXP-02/harness.py run --level R  --shard 3/5 --reps 1 --out /tmp/my-R-3
python SecureGate_Project/experiments/EXP-02/compare_runs.py $R/analysis/runs_all.csv /tmp/my-L2-1/runs.csv /tmp/my-R-3/runs.csv
```

What should match and what may not:
- **L2:** verdicts and categories should match exactly; timings will differ.
- **R:** pip-audit queries PyPI's vulnerability data live, so the *number* of findings on the real projects can grow over time. Verdicts and categories should still match, including flasky's silent pass under S0/S1 (pip-audit audits 0 dependencies) and the discover-flask INCOMPLETE under S3P.
- Any difference: the run's `run_manifest.json` and raw output in your `--out` folder show why.

## 5. Re-run everything on GitHub Actions

Push the same commit to `semester8-exp02-run` (or use *Run workflow* on `experiments-exp02` in the Actions tab). The workflow runs 11 shards in parallel (about 45 minutes) and adds a new folder to `semester8-exp02-results`; compare its `analysis/summary.md` with the candidate run's.
