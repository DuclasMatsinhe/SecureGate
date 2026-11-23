# EXP-03 pre-registration: held-out confirmation on new public projects

Author: Duclas Argentina Francisco Matsinhe (Marwadi University, B.Tech ICT, project 01CT3801)
Written: 23 November 2026, before any scanner was run on the projects listed below.
Status: written by the student; the guide has not yet reviewed it.

## 1. Purpose

EXP-02 was run on five public projects that were also used while the method was being
developed (level R). Its results could therefore fit those projects by accident. EXP-03 asks a
narrower question: **do the EXP-02 level-R results hold on eight public projects that were never
run before, with the predictions written down first?**

Nothing about SecureGate or the experiment is changed for EXP-03. The harness, engine, arms
(S0, S1, S2, S3, S3P), pinned scanner versions (Semgrep 1.180.0, pip-audit 2.10.1 with
`--no-deps --disable-pip`, Gitleaks 8.30.1), Semgrep rules, policies and fault realisations
(F2 crash, F4 silent exit 0 with no report, F7 truncated report) are the EXP-02 ones.
`heldout.py` imports the EXP-02 harness file and records its SHA-256 in the EXP-03 protocol.

## 2. Project selection (fixed rule, applied once)

1. Source: one GitHub repository search, run on 23 November 2026, query
   `flask language:Python stars:200..5000 archived:false`, sorted by stars (descending),
   first 100 results. The returned list is saved in `selection/candidates.txt`.
2. Candidates are taken in the returned order. A candidate is excluded if
   - it was used in EXP-01 or EXP-02, or considered for them (microblog, microblog-api, flasky,
     flack, flask-by-example, discover-flask);
   - it cannot be cloned;
   - it has no `requirements.txt` in the repository root;
   - any non-blank, non-comment line of that file is not of the form `name==version`
     (so pip-audit can audit it without resolving or building packages, as in EXP-02);
   - it has fewer than 10 or more than 300 `.py` files.
3. The first eight remaining candidates are selected and pinned to the commit at the head of
   their default branch at selection time.

The rule was coded and applied in a single step; this section records it as applied. The
decision for every candidate examined is in `selection/selection_log.txt`. The only things
inspected were the requirements file and the number of `.py` files, plus the checkout size of
one project (traefik-manager, 74 MB) to set the CI time limit. No scanner output from any
candidate was seen before this document was written, so selection cannot have been tuned to
the outcome.

| # | Project | Commit |
|---|---|---|
| 1 | cookiecutter-flask/cookiecutter-flask | e5666c23a633b5b6fcb0dc2cfda2441d7f885727 |
| 2 | nyaadevs/nyaa | 4fe0ff5b1aa7ec7c9bb2667d97e10ce2a318c676 |
| 3 | johnwheeler/flask-ask | a93488b700479a3b2d80eb54d0f6585caae15ef3 |
| 4 | chr0nzz/traefik-manager | 29eb9456a92614175856470737da2a3daf96ae09 |
| 5 | vimalloc/flask-jwt-extended | ba708e89ac50ce69577c537ca7132e8d4dd3fc18 |
| 6 | NetEaseGame/git-webhook | 4c57f1bfdb4b87183ef4adea30e90dce86fde2fa |
| 7 | Parallels/rq-dashboard | 384def1a3c06263f2b2de901d0a26960fffb3f38 |
| 8 | lepture/flask-oauthlib | 260a1d5e608ea6149e4f9e89c592eb1519943098 |

## 3. Design

- Cells: per project, one unmodified cell (B) and nine fault cells (F2, F4, F7 x Semgrep,
  pip-audit, Gitleaks): 8 baseline cells and 72 fault cells.
- Arms: S0, S1, S2, S3, S3P. Repetitions: 10. Total: 80 x 5 x 10 = 4,000 gate runs.
- Unit of analysis: the cell (modal verdict over the 10 repetitions), as in EXP-02.
- Environment: GitHub-hosted `ubuntu-24.04` runners, workflow `experiments-exp03.yml`.
- pip-audit queries the live PyPI vulnerability service; the audit date is the run date.
- Before the final run, a smoke run on one EXP-02 project (microblog) checks the set-up.
  Smoke results are kept but are not EXP-03 results.
- The protocol (`protocol.json`) is frozen in `FROZEN.sha256`; it includes the SHA-256 of this
  file, the selection files and the shared harness. The final run refuses any other protocol.
- The final run is done once. If it fails for an infrastructure reason (runner lost, network),
  it is repeated unchanged and the failed attempt is reported.

## 4. Predictions

Each prediction is decided mechanically by `check_predictions.py`, which was written and
tested on EXP-02 level-R data before this run (there all six hold; P3's rule was derived from
those data, so EXP-02 is not evidence for it).

| ID | Prediction | Refuted if |
|---|---|---|
| P1 (primary) | No fault cell passes under S3 or S3P. | any of the 72 fault cells has modal verdict PASS under S3 or S3P |
| P2 | No fault cell passes under S1 or S2. | any fault cell passes under S1 or S2 |
| P3 | S0 passes a fault cell exactly when the faulted scanner exits 0 under the fault (always for F4; for F7 when that scanner exits 0 on the unmodified project; never for F2) and the other two scanners exit 0 on the unmodified project. | the S0 outcome of any fault cell differs from this rule |
| P4 | Under S3 the faulted scanner's category is one of the expected ones in at least 95% of fault cells. | fewer than 69 of 72 |
| P5 | Verdict and categories are identical across all 10 repetitions for at least 99% of cell-arm pairs. | fewer than 396 of 400 |
| P6 | Median evidence-validation time per gate run is below 50 ms under S3 and below 1,000 ms under S3P. | either median is at or above its limit |

P1 is the primary claim of SecureGate. P3 states why S0 fails: an exit-code-only gate cannot
tell "nothing found" from "nothing ran". It implies S0 silent passes on every F4 cell of a
project whose other two scanners exit 0, but it does not fix how many such projects there are.

## 5. Exploratory (no prediction)

- Verdicts of the unmodified projects under each arm, and the causes of any INCOMPLETE verdict
  (for example pip-audit auditing no dependencies, or Python files that do not parse under S3P).
- Run-level rates, Wilson intervals and McNemar tests from the EXP-02 `analysis.py`.

These are reported as observations. They are not used to judge the predictions.

## 6. Reporting

All six predictions are reported in the paper whatever their outcome. A refuted prediction is
reported as refuted, with the cells that refute it; it is not re-run, re-defined or dropped.
Any deviation from this document is recorded in `SecureGate_Project/docs/decision-log.md` and
stated next to the result.

## 7. Archive

This file, `protocol.json`, `FROZEN.sha256` and the `selection/` folder are archived on Zenodo
before the final run, so the date of the predictions can be checked independently.
