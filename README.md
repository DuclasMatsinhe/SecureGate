# SecureGate: Evidence-Aware Security Gating for CI/CD Pipelines

SecureGate is a security gate for GitHub Actions. It runs three security scanners — **Semgrep** (SAST), **pip-audit** (SCA) and **Gitleaks** (secret scanning) — and **checks each scanner's evidence before trusting it**. A scanner that crashed, timed out, wrote no report, wrote a broken report or scanned nothing is never mistaken for a clean scan.

B.Tech ICT final-year project (01CT3801), Marwadi University · Duclas Argentina Francisco Matsinhe · Guide: Dharmendrasinh Zala

## Why

Most CI/CD security gates decide from the scanners' exit codes. When a scanner fails in a way that still exits 0, the gate reports PASS although nothing was checked: a **silent pass**. In our study, a gate that read only exit codes silently passed **46%** of faulty scans with the real scanners; SecureGate's evidence checks reduced this to **2.7%**, and to **0%** with its optional parse check, without blocking any clean project.

## Verdicts

| Verdict | Exit code | Meaning |
|---|---|---|
| PASS | 0 | Every required scanner produced valid evidence and no finding reached the blocking threshold |
| BLOCK | 1 | Valid evidence shows a finding at or above the threshold |
| INCOMPLETE | 2 | A required scanner's evidence is missing or invalid, so security was **not** established; confirmed findings are still listed |
| Invalid policy or usage | 3 | The policy file or the command line is invalid |

The evidence checks cover **execution** (missing tool, launch failure, timeout, unexpected exit code), the **report** (missing, empty, invalid JSON, wrong structure), **consistency** (an exit code that contradicts the report) and **coverage** (nothing scanned, or part of the input skipped or failed).

## Gate strategies

Four strategies are compared in the experiments; S3 is the default.

| Strategy | What it checks | Invalid evidence becomes |
|---|---|---|
| S0 | Exit codes only (today's common practice) | BLOCK, or a silent PASS |
| S1 | S0 + report present, valid JSON, expected structure | BLOCK |
| S2 | S1 + exit code consistent with the report, and coverage | BLOCK |
| S3 | Same checks as S2 | INCOMPLETE, with the cause named |

An optional parse check (`scanners.semgrep.parse_check = true`) also catches Python files that Semgrep lists as scanned but cannot have parsed; in the experiments it is the arm "S3P".

## Quick start

```bash
pip install -r requirements.txt
# install the pinned scanners: see SecureGate_Project/docs/install-and-usage.md
python -m security_engine.cli                     # uses securegate.toml if present
python -m security_engine.cli --strategy S0       # exit-code-only baseline (experiments)
python -m security_engine.cli --legacy            # the unchanged Semester 7 engine
```

Each run writes `securegate-out/run_manifest.json` (schema 1.2: tool versions, commands, rule sources, policy hash, timings, evidence per scanner, verdict and reasons), `report.md`, and the raw scanner outputs in `raw/<run_id>/`.

**CI:** `.github/workflows/ci-security.yml` runs Tests → SecureGate → Docker build. The gate's exit code decides the job, so BLOCK, INCOMPLETE and policy errors stop the pipeline before the image is built.

**Tests:** `python -m pytest -q` (164 tests; the Semester 7 tests are unchanged).

## Experiments

| ID | What | Status |
|---|---|---|
| [EXP-00](SecureGate_Project/experiments/EXP-00-live-scanner-check/README.md) | Live check of how the real scanners fail | Done, 17 Nov 2026 |
| [EXP-01](SecureGate_Project/experiments/EXP-01-pilot/README.md) | Pilot: S0–S3 × fault classes F1–F10, 844 runs, run twice | Done, 17 Nov 2026 |
| [EXP-02](SecureGate_Project/experiments/EXP-02/README.md) | Final study: 7,160 runs at three levels (simulated; real scanners on synthetic projects; real scanners on five public projects) | Final run 21 Nov 2026 (frozen protocol), replicated by the candidate run |

To check the results yourself, run `bash SecureGate_Project/experiments/EXP-02/reproduce.sh` or follow [EXP-02/VERIFY.md](SecureGate_Project/experiments/EXP-02/VERIFY.md). Raw results are on the branch `semester8-exp02-results`.

## Documentation

All in `SecureGate_Project/docs/`:

| Document | Content |
|---|---|
| [architecture.md](SecureGate_Project/docs/architecture.md) | Modules, evidence pipeline, outputs |
| [install-and-usage.md](SecureGate_Project/docs/install-and-usage.md) | Pinned tool installation, CLI, library use |
| [policy-guide.md](SecureGate_Project/docs/policy-guide.md) | Every policy key, strategies S0–S3, the parse check, suppressions |
| [ci-integration.md](SecureGate_Project/docs/ci-integration.md) | Workflow design and the validation runs |
| [requirements/engine-requirements-v1.md](SecureGate_Project/docs/requirements/engine-requirements-v1.md) | 44 requirements (FR-01–FR-35, FR-14a, FR-20a, NFR-01–NFR-07), change log for v1.1 and v1.2 |
| [traceability-matrix.md](SecureGate_Project/docs/traceability-matrix.md) | Requirement → tests, generated from a test run |
| [test-report.md](SecureGate_Project/docs/test-report.md) | Generated test results |
| [decision-log.md](SecureGate_Project/docs/decision-log.md) | Design decisions DEC-001–DEC-018 |
| [completion-report.md](SecureGate_Project/docs/completion-report.md) | What was done, verified and left open in the Semester 8 completion work |
| [reproducibility.md](SecureGate_Project/docs/reproducibility.md) | How to reproduce runs and experiments |
| [limitations.md](SecureGate_Project/docs/limitations.md) | Known limits of the engine and the evidence |

## Repository layout

| Path | Content |
|---|---|
| `security_engine/` | The gate: scanner adapters, evidence checks, verdicts, reports, CLI; `engine.py` is the Semester 7 engine, kept unchanged |
| `tests/` | Unit and integration tests, recorded scanner outputs in `fixtures/` |
| `tools/` | Traceability-matrix and test-report generator |
| `app/`, `run.py`, `Dockerfile` | The small Flask application the pipeline builds and deploys |
| `securegate.toml` | The gate's policy for this repository |
| `semgrep_test.py`, `pip_audit_test_requirements.txt` | Intentionally vulnerable Semester 7 samples (an SQL injection pattern and `urllib3==1.26.5`), excluded from the normal scan |
| `SecureGate_Project/` | Documentation, experiments, research log and paper notes |
| `.github/workflows/` | CI (`ci-security.yml`) and the experiment workflows |

## Semester 7 baseline

SecureGate builds on the Semester 7 project, a DevSecOps continuous security validation pipeline for cloud-native applications. Its engine normalised findings from the same three scanners, evaluated their severity against a policy and made a pass/fail decision before the Docker build. That engine is kept unchanged (`--legacy`) as the baseline.

```text
Developer → GitHub repository → GitHub Actions → application tests
          → SAST + SCA + secret scanning → Security Validation Engine
          → policy evaluation → security gate → Docker build → test deployment
```

```text
Semgrep   ─────┐
               │
pip-audit ─────┼──→ SecurityFinding
               │          │
Gitleaks  ─────┘          ↓
                SecurityValidationEngine
                          │
                          ↓
                 Severity evaluation
                          │
                          ↓
                   Security policy
                          │
                  ┌───────┴───────┐
                  ↓               ↓
               PASSED           FAILED
                  │               │
                  ↓               ↓
            Docker build    Pipeline stops
```

The Semester 8 audit of this baseline found its main gap: a missing scanner report was read as an empty list of findings, and the gate recorded no scanner health, so a failed scanner could look like a clean scan. SecureGate's evidence checks and the INCOMPLETE verdict address exactly that.

## Licence and citation

Code: [MIT](LICENSE). Experiment results, documentation and figures: [CC BY 4.0](LICENSE-DATA.md). To cite this work, use [CITATION.cff](CITATION.cff) (GitHub shows a "Cite this repository" button).
