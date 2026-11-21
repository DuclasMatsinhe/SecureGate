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
| **9. Actual result** | Added after the runs, from `analysis.py` only |
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
