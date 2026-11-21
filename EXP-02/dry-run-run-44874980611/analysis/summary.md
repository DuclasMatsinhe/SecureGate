# EXP-02 (dry-run), workflow run 44874980611

Rates: % (numerator/denominator) [Wilson 95% interval]. Levels are never pooled.

## Level L1

| Metric | S0 | S1 | S2 | S3 |
|---|---|---|---|---|
| SPR_cells | 30.9% (17/55) [20.3, 44.0] | 12.7% (7/55) [6.3, 24.0] | 0.0% (0/55) [0.0, 6.5] | 0.0% (0/55) [0.0, 6.5] |
| SPR_runs | 30.9% (34/110) [23.0, 40.1] | 12.7% (14/110) [7.7, 20.2] | 0.0% (0/110) [0.0, 3.4] | 0.0% (0/110) [0.0, 3.4] |
| CC_cells | 0.0% (0/55) [0.0, 6.5] | 0.0% (0/55) [0.0, 6.5] | 0.0% (0/55) [0.0, 6.5] | 100.0% (55/55) [93.5, 100.0] |
| CC_runs | 0.0% (0/110) [0.0, 3.4] | 0.0% (0/110) [0.0, 3.4] | 0.0% (0/110) [0.0, 3.4] | 100.0% (110/110) [96.6, 100.0] |
| MAB_runs | 45.2% (28/62) [33.4, 57.5] | 77.4% (48/62) [65.6, 86.0] | 100.0% (62/62) [94.2, 100.0] | 0.0% (0/62) [0.0, 5.8] |
| FBR_runs | 0.0% (0/2) [0.0, 65.8] | 0.0% (0/2) [0.0, 65.8] | 0.0% (0/2) [0.0, 65.8] | 0.0% (0/2) [0.0, 65.8] |
| TBR_runs | 100.0% (6/6) [61.0, 100.0] | 100.0% (6/6) [61.0, 100.0] | 100.0% (6/6) [61.0, 100.0] | 100.0% (6/6) [61.0, 100.0] |
| FPP_runs | 100.0% (48/48) [92.6, 100.0] | 100.0% (48/48) [92.6, 100.0] | 100.0% (48/48) [92.6, 100.0] | 100.0% (48/48) [92.6, 100.0] |

Run-to-run consistency: 100.0% (236/236) [98.4, 100.0]

Silent-pass cells per fault class (modal verdict PASS / cells):

| Fault | S0 | S1 | S2 | S3 |
|---|---|---|---|---|
| F1 | 0/11 | 0/11 | 0/11 | 0/11 |
| F2 | 0/9 | 0/9 | 0/9 | 0/9 |
| F3 | 0/3 | 0/3 | 0/3 | 0/3 |
| F4 | 3/3 | 0/3 | 0/3 | 0/3 |
| F5 | 3/3 | 0/3 | 0/3 | 0/3 |
| F6 | 3/9 | 0/9 | 0/9 | 0/9 |
| F7 | 3/3 | 0/3 | 0/3 | 0/3 |
| F8 | 3/9 | 3/9 | 0/9 | 0/9 |
| F9 | 2/2 | 2/2 | 0/2 | 0/2 |
| F10 | 0/3 | 2/3 | 0/3 | 0/3 |

Paired comparisons (exact McNemar on cell-level silent passes):

- S0 vs S1: 55 cells; silent only under S0: 12; only under S1: 2; p = 0.012939
- S1 vs S2: 55 cells; silent only under S1: 7; only under S2: 0; p = 0.015625
- S2 vs S3: 55 cells; silent only under S2: 0; only under S3: 0; p = 1.0

Overhead (clean, known-finding and baseline runs; medians):

| Arm | evidence validation s | share of engine run | wall s |
|---|---|---|---|
| S0 | 9.6e-05 | 0.1195 | 0.0019 |
| S1 | 9.2e-05 | 0.139 | 0.0018 |
| S2 | 9.3e-05 | 0.0945 | 0.0018 |
| S3 | 9.3e-05 | 0.095 | 0.00185 |

Silent-pass cells: S0: L1-F4-gitleaks, L1-F4-pip-audit, L1-F4-semgrep, L1-F5-gitleaks, L1-F5-pip-audit, L1-F5-semgrep, L1-F6-gitleaks, L1-F6-pip-audit, L1-F6-semgrep, L1-F7-gitleaks, L1-F7-pip-audit, L1-F7-semgrep, L1-F8-gitleaks, L1-F8-pip-audit, L1-F8-semgrep, L1-F9-pip-audit, L1-F9-semgrep; S1: L1-F10-gitleaks, L1-F10-pip-audit, L1-F8-gitleaks, L1-F8-pip-audit, L1-F8-semgrep, L1-F9-pip-audit, L1-F9-semgrep; S2: none; S3: none

## Level L2

| Metric | S0 | S1 | S2 | S3 | S3P |
|---|---|---|---|---|---|
| SPR_cells | 46.0% (17/37) [31.0, 61.6] | 18.9% (7/37) [9.5, 34.2] | 2.7% (1/37) [0.5, 13.8] | 2.7% (1/37) [0.5, 13.8] | 0.0% (0/37) [0.0, 9.4] |
| SPR_runs | 46.0% (17/37) [31.0, 61.6] | 18.9% (7/37) [9.5, 34.2] | 2.7% (1/37) [0.5, 13.8] | 2.7% (1/37) [0.5, 13.8] | 0.0% (0/37) [0.0, 9.4] |
| CC_cells | 0.0% (0/37) [0.0, 9.4] | 0.0% (0/37) [0.0, 9.4] | 0.0% (0/37) [0.0, 9.4] | 97.3% (36/37) [86.2, 99.5] | 100.0% (37/37) [90.6, 100.0] |
| CC_runs | 0.0% (0/37) [0.0, 9.4] | 0.0% (0/37) [0.0, 9.4] | 0.0% (0/37) [0.0, 9.4] | 97.3% (36/37) [86.2, 99.5] | 100.0% (37/37) [90.6, 100.0] |
| MAB_runs | 45.2% (14/31) [29.2, 62.2] | 77.4% (24/31) [60.2, 88.6] | 96.8% (30/31) [83.8, 99.4] | 0.0% (0/31) [0.0, 11.0] | 0.0% (0/31) [0.0, 11.0] |
| FBR_runs | 0.0% (0/3) [0.0, 56.1] | 0.0% (0/3) [0.0, 56.1] | 0.0% (0/3) [0.0, 56.1] | 0.0% (0/3) [0.0, 56.1] | 0.0% (0/3) [0.0, 56.1] |
| TBR_runs | 100.0% (6/6) [61.0, 100.0] | 100.0% (6/6) [61.0, 100.0] | 100.0% (6/6) [61.0, 100.0] | 100.0% (6/6) [61.0, 100.0] | 100.0% (6/6) [61.0, 100.0] |
| FPP_runs | 100.0% (6/6) [61.0, 100.0] | 100.0% (6/6) [61.0, 100.0] | 100.0% (6/6) [61.0, 100.0] | 100.0% (6/6) [61.0, 100.0] | 100.0% (6/6) [61.0, 100.0] |

Run-to-run consistency: 100.0% (230/230) [98.4, 100.0]

Silent-pass cells per fault class (modal verdict PASS / cells):

| Fault | S0 | S1 | S2 | S3 | S3P |
|---|---|---|---|---|---|
| F1 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| F2 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| F3 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| F4 | 3/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| F5 | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| F6 | 3/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| F7 | 3/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| F8 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| F9 | 2/2 | 2/2 | 1/2 | 1/2 | 0/2 |
| F10 | 0/4 | 2/4 | 0/4 | 0/4 | 0/4 |

Paired comparisons (exact McNemar on cell-level silent passes):

- S0 vs S1: 37 cells; silent only under S0: 12; only under S1: 2; p = 0.012939
- S1 vs S2: 37 cells; silent only under S1: 6; only under S2: 0; p = 0.03125
- S2 vs S3: 37 cells; silent only under S2: 0; only under S3: 0; p = 1.0
- S3 vs S3P: 37 cells; silent only under S3: 1; only under S3P: 0; p = 1.0

Overhead (clean, known-finding and baseline runs; medians):

| Arm | evidence validation s | share of engine run | wall s |
|---|---|---|---|
| S0 | 0.000398 | 0.000115 | 3.4808 |
| S1 | 0.000388 | 0.000115 | 3.439 |
| S2 | 0.000405 | 0.000115 | 3.449 |
| S3 | 0.000396 | 0.000117 | 3.4433 |
| S3P | 0.000739 | 0.00022 | 3.4444 |

Silent-pass cells: S0: L2-F4-gitleaks, L2-F4-pip-audit, L2-F4-semgrep, L2-F5-gitleaks, L2-F5-pip-audit, L2-F5-semgrep, L2-F6-gitleaks, L2-F6-pip-audit, L2-F6-semgrep, L2-F7-gitleaks, L2-F7-pip-audit, L2-F7-semgrep, L2-F8-gitleaks, L2-F8-pip-audit, L2-F8-semgrep, L2-F9-pip-audit, L2-F9-semgrep; S1: L2-F10-gitleaks, L2-F10-pip-audit, L2-F8-gitleaks, L2-F8-pip-audit, L2-F8-semgrep, L2-F9-pip-audit, L2-F9-semgrep; S2: L2-F9-semgrep; S3: L2-F9-semgrep; S3P: none

## Level R

| Metric | S0 | S1 | S2 | S3 | S3P |
|---|---|---|---|---|---|
| SPR_cells | 22.2% (10/45) [12.5, 36.3] | 0.0% (0/45) [0.0, 7.9] | 0.0% (0/45) [0.0, 7.9] | 0.0% (0/45) [0.0, 7.9] | 0.0% (0/45) [0.0, 7.9] |
| SPR_runs | 22.2% (10/45) [12.5, 36.3] | 0.0% (0/45) [0.0, 7.9] | 0.0% (0/45) [0.0, 7.9] | 0.0% (0/45) [0.0, 7.9] | 0.0% (0/45) [0.0, 7.9] |
| CC_cells | 0.0% (0/45) [0.0, 7.9] | 0.0% (0/45) [0.0, 7.9] | 0.0% (0/45) [0.0, 7.9] | 100.0% (45/45) [92.1, 100.0] | 100.0% (45/45) [92.1, 100.0] |
| CC_runs | 0.0% (0/45) [0.0, 7.9] | 0.0% (0/45) [0.0, 7.9] | 0.0% (0/45) [0.0, 7.9] | 100.0% (45/45) [92.1, 100.0] | 100.0% (45/45) [92.1, 100.0] |
| MAB_runs | 77.8% (35/45) [63.7, 87.5] | 100.0% (45/45) [92.1, 100.0] | 100.0% (45/45) [92.1, 100.0] | 0.0% (0/45) [0.0, 7.9] | 0.0% (0/45) [0.0, 7.9] |
| FBR_runs | n/a | n/a | n/a | n/a | n/a |
| TBR_runs | n/a | n/a | n/a | n/a | n/a |
| FPP_runs | n/a | n/a | n/a | n/a | n/a |

Run-to-run consistency: 100.0% (250/250) [98.5, 100.0]

Silent-pass cells per fault class (modal verdict PASS / cells):

| Fault | S0 | S1 | S2 | S3 | S3P |
|---|---|---|---|---|---|
| F2 | 0/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| F4 | 7/15 | 0/15 | 0/15 | 0/15 | 0/15 |
| F7 | 3/15 | 0/15 | 0/15 | 0/15 | 0/15 |

Paired comparisons (exact McNemar on cell-level silent passes):

- S0 vs S1: 45 cells; silent only under S0: 10; only under S1: 0; p = 0.001953
- S1 vs S2: 45 cells; silent only under S1: 0; only under S2: 0; p = 1.0
- S2 vs S3: 45 cells; silent only under S2: 0; only under S3: 0; p = 1.0
- S3 vs S3P: 45 cells; silent only under S3: 0; only under S3P: 0; p = 1.0

Overhead (clean, known-finding and baseline runs; medians):

| Arm | evidence validation s | share of engine run | wall s |
|---|---|---|---|
| S0 | 0.000775 | 0.000173 | 3.7519 |
| S1 | 0.000797 | 0.000238 | 3.4088 |
| S2 | 0.000735 | 0.000221 | 3.3895 |
| S3 | 0.000833 | 0.000249 | 3.3757 |
| S3P | 0.010973 | 0.003311 | 3.3689 |

Silent-pass cells: S0: R-discover-flask-F4-pip-audit, R-flask-by-example-F4-pip-audit, R-flasky-F4-gitleaks, R-flasky-F4-pip-audit, R-flasky-F4-semgrep, R-flasky-F7-gitleaks, R-flasky-F7-pip-audit, R-flasky-F7-semgrep, R-microblog-F4-pip-audit, R-microblog-api-F4-pip-audit; S1: none; S2: none; S3: none; S3P: none

Real-project baselines (observed, no ground truth):

| Cell | S0 | S1 | S2 | S3 | S3P |
|---|---|---|---|---|---|
| R-discover-flask-base | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | INCOMPLETE `semgrep:PARTIAL_COVERAGE;pip-audit:VALID;gitleaks:VALID` |
| R-flask-by-example-base | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` |
| R-flasky-base | PASS `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | PASS `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:NO_COVERAGE;gitleaks:VALID` | INCOMPLETE `semgrep:VALID;pip-audit:NO_COVERAGE;gitleaks:VALID` | INCOMPLETE `semgrep:VALID;pip-audit:NO_COVERAGE;gitleaks:VALID` |
| R-microblog-api-base | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` |
| R-microblog-base | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` |

## Metric definitions

- **SPR_cells**: Silent-pass rate (primary). Faulted cells (kind F or FK) whose modal verdict over repetitions is PASS / all faulted cells of the level.
- **SPR_runs**: Faulted runs with verdict PASS / all faulted runs (kind F or FK).
- **CC_runs**: Correct cause. Faulted runs with verdict INCOMPLETE and every faulted scanner labelled with an expected category / all faulted runs. Meaningful for S3 and S3P only.
- **CC_cells**: Faulted cells whose modal run is INCOMPLETE with the expected category / all faulted cells.
- **MAB_runs**: Misattributed BLOCK. Runs of kind F (fault, no finding anywhere) with verdict BLOCK / all kind-F runs: the gate blames the code although only a tool failed.
- **FBR_runs**: False-block rate. Clean-control runs (kind C) with any verdict other than PASS / all kind-C runs.
- **TBR_runs**: True-block rate. Known-finding runs (kind K) with verdict BLOCK / all kind-K runs.
- **FPP_runs**: Finding preservation. Partial-failure runs (kind FK) whose verdict lists the known finding as a BLOCKING_FINDING reason / all kind-FK runs.
- **consistency**: (cell, arm) pairs whose repetitions all gave the same verdict / all (cell, arm) pairs.
- **overhead**: Medians over clean, known-finding and baseline runs: evidence-validation time, its share of the engine's run time, and wall time per run.
- **paired_tests**: Exact two-sided McNemar test on cell-level silent passes between two arms (discordant cells only).
