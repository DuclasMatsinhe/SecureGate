# EXP-03 (smoke), workflow run 45116210350

Rates: % (numerator/denominator) [Wilson 95% interval]. Levels are never pooled.

## Level H

| Metric | S0 | S1 | S2 | S3 | S3P |
|---|---|---|---|---|---|
| SPR_cells | 11.1% (1/9) [2.0, 43.5] | 0.0% (0/9) [0.0, 29.9] | 0.0% (0/9) [0.0, 29.9] | 0.0% (0/9) [0.0, 29.9] | 0.0% (0/9) [0.0, 29.9] |
| SPR_runs | 11.1% (2/18) [3.1, 32.8] | 0.0% (0/18) [0.0, 17.6] | 0.0% (0/18) [0.0, 17.6] | 0.0% (0/18) [0.0, 17.6] | 0.0% (0/18) [0.0, 17.6] |
| CC_cells | 0.0% (0/9) [0.0, 29.9] | 0.0% (0/9) [0.0, 29.9] | 0.0% (0/9) [0.0, 29.9] | 100.0% (9/9) [70.1, 100.0] | 100.0% (9/9) [70.1, 100.0] |
| CC_runs | 0.0% (0/18) [0.0, 17.6] | 0.0% (0/18) [0.0, 17.6] | 0.0% (0/18) [0.0, 17.6] | 100.0% (18/18) [82.4, 100.0] | 100.0% (18/18) [82.4, 100.0] |
| MAB_runs | n/a | n/a | n/a | n/a | n/a |
| FBR_runs | n/a | n/a | n/a | n/a | n/a |
| TBR_runs | n/a | n/a | n/a | n/a | n/a |
| FPP_runs | n/a | n/a | n/a | n/a | n/a |

Run-to-run consistency: 100.0% (50/50) [92.9, 100.0]

Silent-pass cells per fault class (modal verdict PASS / cells):

| Fault | S0 | S1 | S2 | S3 | S3P |
|---|---|---|---|---|---|
| F2 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| F4 | 1/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| F7 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |

Paired comparisons (exact McNemar on cell-level silent passes):

- S0 vs S1: 9 cells; silent only under S0: 1; only under S1: 0; p = 1.0
- S1 vs S2: 9 cells; silent only under S1: 0; only under S2: 0; p = 1.0
- S2 vs S3: 9 cells; silent only under S2: 0; only under S3: 0; p = 1.0
- S3 vs S3P: 9 cells; silent only under S3: 0; only under S3P: 0; p = 1.0

Overhead (clean, known-finding and baseline runs; medians):

| Arm | evidence validation s | share of engine run | wall s |
|---|---|---|---|
| S0 | 0.000845 | 0.000215 | 4.08775 |
| S1 | 0.00088 | 0.000263 | 3.40015 |
| S2 | 0.000869 | 0.00026 | 3.39695 |
| S3 | 0.000907 | 0.000269 | 3.42635 |
| S3P | 0.013926 | 0.004185 | 3.38425 |

Silent-pass cells: S0: H-microblog-F4-pip-audit; S1: none; S2: none; S3: none; S3P: none

Real-project baselines (observed, no ground truth):

| Cell | S0 | S1 | S2 | S3 | S3P |
|---|---|---|---|---|---|
| H-microblog-base | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` |

## Metric definitions

- **SPR_cells**: Silent-pass rate (primary). Faulted cells (kind F or FK) whose modal verdict over repetitions is PASS / all faulted cells of the level.
- **SPR_runs**: Faulted runs with verdict PASS / all faulted runs (kind F or FK).
- **CC_runs**: Correct cause. Faulted runs with verdict INCOMPLETE and every faulted scanner labelled with an expected category / all faulted runs. Meaningful for S3 and S3P only.
- **CC_cells**: Faulted cells whose modal run is INCOMPLETE with the expected category / all faulted cells.
- **MAB_runs**: Misattributed BLOCK. Runs of kind F (fault, no finding anywhere) with verdict BLOCK / all kind-F runs: the gate blames the code although only a tool failed. Not computed for level R, where the real projects may hold genuine findings in the other scanners.
- **FBR_runs**: False-block rate. Clean-control runs (kind C) with any verdict other than PASS / all kind-C runs.
- **TBR_runs**: True-block rate. Known-finding runs (kind K) with verdict BLOCK / all kind-K runs.
- **FPP_runs**: Finding preservation. Partial-failure runs (kind FK) whose verdict lists the known finding as a BLOCKING_FINDING reason / all kind-FK runs.
- **consistency**: (cell, arm) pairs whose repetitions all gave the same verdict / all (cell, arm) pairs.
- **overhead**: Medians over clean, known-finding and baseline runs: evidence-validation time, its share of the engine's run time, and wall time per run.
- **paired_tests**: Exact two-sided McNemar test on cell-level silent passes between two arms (discordant cells only).
