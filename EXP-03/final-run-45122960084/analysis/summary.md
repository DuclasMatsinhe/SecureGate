# EXP-03 (final), workflow run 45122960084

Rates: % (numerator/denominator) [Wilson 95% interval]. Levels are never pooled.

## Level H

| Metric | S0 | S1 | S2 | S3 | S3P |
|---|---|---|---|---|---|
| SPR_cells | 12.5% (9/72) [6.7, 22.1] | 0.0% (0/72) [0.0, 5.1] | 0.0% (0/72) [0.0, 5.1] | 0.0% (0/72) [0.0, 5.1] | 0.0% (0/72) [0.0, 5.1] |
| SPR_runs | 12.5% (90/720) [10.3, 15.1] | 0.0% (0/720) [0.0, 0.5] | 0.0% (0/720) [0.0, 0.5] | 0.0% (0/720) [0.0, 0.5] | 0.0% (0/720) [0.0, 0.5] |
| CC_cells | 0.0% (0/72) [0.0, 5.1] | 0.0% (0/72) [0.0, 5.1] | 0.0% (0/72) [0.0, 5.1] | 100.0% (72/72) [94.9, 100.0] | 100.0% (72/72) [94.9, 100.0] |
| CC_runs | 0.0% (0/720) [0.0, 0.5] | 0.0% (0/720) [0.0, 0.5] | 0.0% (0/720) [0.0, 0.5] | 100.0% (720/720) [99.5, 100.0] | 100.0% (720/720) [99.5, 100.0] |
| MAB_runs | n/a | n/a | n/a | n/a | n/a |
| FBR_runs | n/a | n/a | n/a | n/a | n/a |
| TBR_runs | n/a | n/a | n/a | n/a | n/a |
| FPP_runs | n/a | n/a | n/a | n/a | n/a |

Run-to-run consistency: 100.0% (400/400) [99.1, 100.0]

Silent-pass cells per fault class (modal verdict PASS / cells):

| Fault | S0 | S1 | S2 | S3 | S3P |
|---|---|---|---|---|---|
| F2 | 0/24 | 0/24 | 0/24 | 0/24 | 0/24 |
| F4 | 6/24 | 0/24 | 0/24 | 0/24 | 0/24 |
| F7 | 3/24 | 0/24 | 0/24 | 0/24 | 0/24 |

Paired comparisons (exact McNemar on cell-level silent passes):

- S0 vs S1: 72 cells; silent only under S0: 9; only under S1: 0; p = 0.003906
- S1 vs S2: 72 cells; silent only under S1: 0; only under S2: 0; p = 1.0
- S2 vs S3: 72 cells; silent only under S2: 0; only under S3: 0; p = 1.0
- S3 vs S3P: 72 cells; silent only under S3: 0; only under S3P: 0; p = 1.0

Overhead (clean, known-finding and baseline runs; medians):

| Arm | evidence validation s | share of engine run | wall s |
|---|---|---|---|
| S0 | 0.000578 | 0.000151 | 3.54115 |
| S1 | 0.000581 | 0.00016 | 3.53015 |
| S2 | 0.000594 | 0.000156 | 3.53825 |
| S3 | 0.000591 | 0.00016 | 3.52715 |
| S3P | 0.014512 | 0.004241 | 3.55235 |

Silent-pass cells: S0: H-cookiecutter-flask-F4-gitleaks, H-cookiecutter-flask-F4-pip-audit, H-cookiecutter-flask-F4-semgrep, H-cookiecutter-flask-F7-gitleaks, H-cookiecutter-flask-F7-pip-audit, H-cookiecutter-flask-F7-semgrep, H-flask-ask-F4-pip-audit, H-rq-dashboard-F4-pip-audit, H-traefik-manager-F4-gitleaks; S1: none; S2: none; S3: none; S3P: none

Real-project baselines (observed, no ground truth):

| Cell | S0 | S1 | S2 | S3 | S3P |
|---|---|---|---|---|---|
| H-cookiecutter-flask-base | PASS `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | PASS `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | PASS `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | PASS `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | INCOMPLETE `semgrep:PARTIAL_COVERAGE;pip-audit:VALID;gitleaks:VALID` |
| H-flask-ask-base | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` |
| H-flask-jwt-extended-base | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` |
| H-flask-oauthlib-base | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` |
| H-git-webhook-base | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | INCOMPLETE `semgrep:PARTIAL_COVERAGE;pip-audit:VALID;gitleaks:VALID` |
| H-nyaa-base | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` |
| H-rq-dashboard-base | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | INCOMPLETE `semgrep:PARTIAL_COVERAGE;pip-audit:VALID;gitleaks:VALID` |
| H-traefik-manager-base | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` | BLOCK `semgrep:VALID;pip-audit:VALID;gitleaks:VALID` |

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
