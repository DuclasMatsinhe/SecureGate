# EXP-03: pre-registered held-out confirmation

EXP-03 repeats the EXP-02 real-project level (R) on eight public projects that were never run
before, with the predictions written down first. See `PREREGISTRATION.md` for the question, the
selection rule, the design and the predictions P1–P6.

| File | What it is |
|---|---|
| `PREREGISTRATION.md` | Question, selection rule, design, predictions, reporting rules |
| `selection/candidates.txt` | The GitHub search snapshot the projects were selected from |
| `selection/selection_log.txt` | The decision for every candidate examined |
| `heldout.py` | Runs the EXP-02 harness on the held-out projects (level `H`); writes the protocol |
| `protocol.json`, `FROZEN.sha256` | The frozen protocol and its SHA-256 |
| `check_predictions.py` | Decides P1–P6 from the run results (CONFIRMED / REFUTED) |
| `run_config.json` | `smoke` or `final`, read by `.github/workflows/experiments-exp03.yml` |

## Sequence

1. **Freeze.** `protocol.json` and `FROZEN.sha256` are committed. The protocol embeds the SHA-256
   of `PREREGISTRATION.md`, of the selection files and of the EXP-02 harness, so changing any of
   them invalidates the freeze and the final run is refused.
2. **Archive.** The pre-registration, protocol, freeze file and selection folder are archived on
   Zenodo before the final run: [10.5281/zenodo.24456056](https://doi.org/10.5281/zenodo.24456056)
   (published 23 Nov 2026 by the student).
3. **Smoke run.** `run_config.json` = `smoke`; push to `semester8-exp03-run`. Shard 1 runs one
   EXP-02 project (microblog) with 2 repetitions. No held-out project is touched.
4. **Final run.** `run_config.json` = `final`; push to `semester8-exp03-run`. Eight shards, one
   held-out project each, 10 repetitions: 4,000 gate runs. Done once.
5. **Results.** Added to `semester8-exp02-results` under `EXP-03/<mode>-run-<id>/`, with
   `analysis/predictions.md` (P1–P6) and the EXP-02 `analysis.py` summary.

## Testing the checker

`check_predictions.py` was tested before the run on the EXP-02 final level-R data:

    python check_predictions.py <EXP-02/final-run-44892918564> --out /tmp/chk --level R

All six predictions hold there (45 fault cells, 250 cell-arm pairs). P3's rule was derived from
those data, so this is a test of the checker, not evidence for P3.

## Result of the final run (23 Nov 2026)

Workflow run [45122960084](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/45122960084), commit `c574d01`, protocol `b6eca924…` (the frozen one), 8 of 8 shards, 4,000 gate runs, no errors. Results: `semester8-exp02-results`, folder `EXP-03/final-run-45122960084/` (`analysis/predictions.md`, `analysis/summary.md`, raw shards).

| Prediction | Observed | Result |
|---|---|---|
| P1 no silent pass under S3 or S3P | S3 0/72, S3P 0/72 fault cells | CONFIRMED |
| P2 no silent pass under S1 or S2 | S1 0/72, S2 0/72 | CONFIRMED |
| P3 S0 outcome follows from the unmodified exit codes | 72/72 cells as predicted (9 predicted silent passes) | CONFIRMED |
| P4 S3 names an expected cause in ≥ 95% of fault cells | 72/72 (100%) | CONFIRMED |
| P5 ≥ 99% of cell-arm pairs consistent over 10 repetitions | 400/400 | CONFIRMED |
| P6 median validation < 50 ms (S3), < 1,000 ms (S3P) | 0.47 ms, 12.18 ms | CONFIRMED |

Exploratory (not predictions):

- S0 silently passed 9 of 72 fault cells (12.5%, Wilson 95% 6.7–22.1%): every F4 and F7 cell of cookiecutter-flask (the only unmodified project that passes), and F4 on pip-audit (flask-ask, rq-dashboard) and on Gitleaks (traefik-manager). McNemar S0 vs S1: p = 0.0039.
- Unmodified projects: cookiecutter-flask passes under S0–S3; the other seven are blocked under every arm by real findings (pip-audit in six, Gitleaks in five; reported in aggregate only).
- S3P returned INCOMPLETE on three unmodified projects: cookiecutter-flask (5 template files with `{{cookiecutter…}}` names and contents, not valid Python by design), git-webhook (`manage.py`) and rq-dashboard (`fabfile.py`), both Python 2 `print` statements. Semgrep reported these files as scanned with no error. This is the parse check's known cost (limitations, item 1).
- Overhead: median gate run 3.5 s; evidence validation 0.6 ms (S0–S3) and 14.5 ms (S3P) on clean and baseline runs.
