# EXP-02: final fault-injection study — protocol v1 (draft for guide approval)

**Status:** protocol drafted 21 Nov 2026; **not frozen**. A dry run checks every realisation before the freeze. After the guide approves, the SHA-256 of `protocol.json` is written to `FROZEN.sha256` and committed *before* the final runs; `harness.py run --final` refuses to start if the protocol differs. Decisions: DEC-014, DEC-015, DEC-016.

| Field | Content |
|---|---|
| **1. Experiment ID** | EXP-02 (final study) |
| **2. Research questions** | RQ1 failure modes (which faults make an exit-code-only gate pass?); RQ2 effectiveness (how far do evidence checks reduce silent passes and name the cause?); RQ3 cost (false blocks, lost true blocks, time); RQ4 partial failure (are real findings kept when another scanner fails?) |
| **3. Objective** | Measure, under controlled scanner faults with ground truth fixed in advance, how the four gate strategies S0–S3 (and the optional parse check, arm S3P) decide, at three levels kept apart: simulated (L1), real binaries on synthetic projects (L2), real binaries on pinned public projects (R) |
| **4. Hypotheses** | H1: S0 silently passes some fault classes. H2: evidence checks remove them; schema checks alone (S1) miss coverage faults. H3: no rise in false blocks on clean projects; every known finding still blocks. H4: evidence validation adds < 5% to the engine's run time. H5 (new): the parse check (S3P) removes the Semgrep syntax-error silent pass without new INCOMPLETE verdicts on the real projects' baselines |
| **5. Environment** | GitHub-hosted `ubuntu-24.04`, Python 3.13; Semgrep 1.180.0, pip-audit 2.10.1, Gitleaks 8.30.1 (SHA-256 checked); all actions pinned by SHA; workflow `experiments-exp02.yml` (11 parallel shards + one analysis job). Engine commit recorded in every shard's `environment.json` |
| **6. Inputs** | **L1:** real outputs recorded in EXP-00 (`inputs/recorded/`). **L2:** 14 synthetic projects created at run time (3 clean; 6 with a known finding: `eval()`, `pickle.loads()`, `urllib3==1.26.5`, `jinja2==2.10`, a GitHub-token-shaped and an AWS-key-shaped string generated at run time). **R:** five public Python projects pinned to a commit, fetched read-only: miguelgrinberg/microblog `a975ef6`, miguelgrinberg/microblog-api `e250d71`, miguelgrinberg/flasky `3beedd6`, realpython/flask-by-example `532c0ea`, realpython/discover-flask `00762e9`. Semgrep uses two local probe rules kept outside the targets; pip-audit audits the pinned requirements as written (`--no-deps --disable-pip`, DEC-016). No real credentials |
| **7. Procedure** | `harness.py protocol` writes every cell with its kind, fault, faulted scanner(s), realisation, expected categories, ground truth and any prediction. `harness.py run` executes each cell under every arm of its level, 10 repetitions each: **L1** 59 cells × 4 arms (S0–S3); **L2** 46 cells × 5 arms (S0–S3, S3P); **R** 50 cells × 5 arms. Faults: F1 missing executable path; F2–F7 and F10 by wrapper executables around the real tool (crash; hang past a 3 s timeout; no report; whitespace-only report; `{}`; report cut at 50%; exit code contradicting the report); F8–F10 also by real inputs (no Python files; not a git repository; empty requirements; a syntax error; a pinned requirement not on PyPI; an invalid Gitleaks config). Six partial-failure cells pair a faulted scanner with a known finding in another. On R, F2, F4 and F7 are applied to each scanner of each project, and each project's unmodified baseline is observed |
| **8. Expected result** | In `protocol.json`. Ground truth: clean → PASS; known finding → BLOCK; any fault → not PASS, and under S3/S3P INCOMPLETE with an expected category; partial failure → the known finding is listed. Prediction for L2-F9-semgrep: PASS under S2 and S3 (Semgrep reports nothing), INCOMPLETE under S3P |
| **9. Actual result** | Candidate run below (full protocol, before approval); final run after the freeze |
| **10. Raw measurements** | Branch `semester8-exp02-results`, folder `EXP-02/<mode>-run-<id>/`: per shard `runs.csv`, `environment.json`, `harness.log`, schema check and `runs.tar.gz` (every manifest, policy, report and raw scanner output); `protocol.json` and its SHA-256; `analysis/` (metrics, summary, merged runs) |
| **11. Analysis** | `analysis.py`, one command over all shards. Unit of analysis: the cell (designed, deterministic). Primary metric SPR_cells (faulted cells whose modal verdict is PASS); run-level rates reported alongside. Correct cause, misattributed BLOCK, false-block, true-block and finding-preservation rates; run-to-run consistency; per-fault-class tables; exact McNemar tests on cell-level silent passes between consecutive arms; Wilson 95% intervals throughout; overhead as medians. Definitions and denominators: `analysis.METRIC_DEFINITIONS`. The script reproduces the EXP-01 pilot numbers (unit test `tests/test_exp02.py`) |
| **12. Conclusion** | After the runs |

## Changes from the EXP-01 pilot (why, and where recorded)

| Change | Reason | Record |
|---|---|---|
| 10 repetitions per cell and arm (pilot: 2 at L1, 3 at L2) | Planned final-study size; repetitions test stability, the cell remains the unit of analysis | Protocol |
| Controls: 3 clean and 6 known-finding projects (pilot: 1 and 3) | Narrower false-block and true-block intervals | Protocol |
| F5 and F10 run with real binaries for all three scanners (pilot: F5 simulated only; F10 real for Gitleaks only) | Complete real-binary coverage of the fault catalogue | Protocol |
| pip-audit F9: pinned requirement not on PyPI, audited with `--no-deps --disable-pip` | In the pilot, pip's resolver failed instead of skipping (NO_OUTPUT, not PARTIAL_COVERAGE) | DEC-016 |
| New arm S3P (S3 + parse check) | Measures the FR-14a extension separately, so S0–S3 keep their pilot meaning | DEC-015 |
| New level R (five pinned public projects) | External validity: realistic code and dependency sets; baseline behaviour observed | DEC-016 |
| Gitleaks F10 (L1) uses the leak exit code with an empty report | Exercises INCONSISTENT_EXIT; the pilot's exit-1 case remains as L2-F10b | Protocol |
| `on_incomplete` stays `block`; FR-20a added | Confirmed findings can never be relaxed by `warn` | DEC-014 |

## Ethics

All secrets are synthetic and generated at run time; no token is stored (each shard is checked for unredacted GitHub- and AWS-shaped strings before upload). The five public projects are only fetched and scanned read-only on GitHub-hosted runners; nothing is pushed to them; Gitleaks runs with `--redact`. Any real secret or vulnerability found in a public project is reported only in aggregate (category and count), never in detail, and the maintainers are informed if a live credential appears.

## Dry runs (21 Nov 2026)

Two dry runs at 1–2 repetitions (workflow runs 44874980611 and 44875418735, branch `semester8-exp02-results`, folders `EXP-02/dry-run-run-*`) ran all 11 shards and the analysis. Every realisation behaved as specified: the new pip-audit F9 realisation now gives PARTIAL_COVERAGE; F5 and F10 work with real binaries; clean controls passed (3/3) and known findings blocked (6/6, including `jinja2==2.10` and the AWS-key-shaped string); L2-F9-semgrep passed under S3 and was caught under S3P, as predicted. No protocol change was needed.

Two observations on the real projects, checked by probes (`shards/L1-1/probes/` in the second dry run):

- **pip-audit does not follow nested requirement files with `--no-deps`.** flasky's `requirements.txt` holds only `-r requirements/heroku.txt`. pip-audit 2.10.1 with `--no-deps --disable-pip` audited 0 dependencies, printed "No known vulnerabilities found" and exited 0; run on the nested file directly it found 4 vulnerabilities in its 3 pins (and still did not follow that file's own `-r prod.txt`). In default mode pip-audit failed instead (it could not build `dominate` on Python 3.13). S0 and S1 therefore PASS the flasky baseline; S2 and S3 report NO_COVERAGE. This is a naturally occurring silent pass, observed rather than injected; it will be reported to the pip-audit maintainers.
- **Python 2 code and the parse check.** discover-flask's `manage.py` uses a Python 2 `print` statement. Semgrep lists the file as scanned and reports no error; the FR-14a parse check flags it, so the baseline becomes INCOMPLETE under S3P only. Whether that is a useful warning or a false INCOMPLETE is reported as an observed cost of S3P (H5).

## Candidate run (21 Nov 2026) — full protocol, before approval

Workflow run 44875857860, commit `3a3c088`, protocol SHA-256 `4716bbba…30fed`; 7,160 runs (L1 2,360; L2 2,300; R 2,500), 11/11 shards; every one of 716 cell–arm pairs gave the same verdict in all 10 repetitions. Results: branch `semester8-exp02-results`, folder `EXP-02/candidate-run-44875857860/` (`analysis/summary.md`, `analysis/metrics.json`). Labelled *candidate* because the protocol is not yet approved; the final run repeats it under `--final`.

| Level | Silent-pass cells S0 / S1 / S2 / S3 / S3P | Correct cause under S3 | False blocks | True blocks | Findings kept (partial failure) |
|---|---|---|---|---|---|
| L1 simulated | 17/55, 7/55, 0/55, 0/55, – | 55/55 | 0/10 runs | 30/30 | 240/240 |
| L2 real, synthetic | 17/37, 7/37, 1/37, 1/37, 0/37 | 36/37 (miss: L2-F9-semgrep, as predicted) | 0/30 | 60/60 | 60/60 |
| R real, public projects | 10/45, 0/45, 0/45, 0/45, 0/45 | 45/45 | – | – | – |

Exact McNemar on cell-level silent passes at L2: S0 vs S1 p = 0.013; S1 vs S2 p = 0.031; S2 vs S3 and S3 vs S3P p = 1.0. Misattributed BLOCK at L2 (fault-only runs): S0 140/310, S1 240/310, S2 300/310, S3 0/310. Evidence validation: median 0.41 ms per run at L2, 1.0 ms at R; S3P adds 0.3 ms and 16 ms. Real projects: under S0 a missing pip-audit report (F4) passed all five projects, four of which otherwise block on 61–189 vulnerability findings; flasky passes under S0/S1 with no fault injected (pip-audit audits 0 dependencies, see Dry runs); S3P turns the discover-flask baseline INCOMPLETE (Python 2 file).
