# Semester 7 â€” Continuous Security Validation Pipeline

## Project

Implementation of an integrated **DevSecOps Continuous Security Validation Pipeline for Cloud-Native Applications**.

The project integrates automated security validation into the CI/CD lifecycle using multiple security scanners and a custom **Security Validation Engine**. The engine normalizes findings from different security tools, evaluates their severity according to a defined security policy, and produces an explicit **security-gate decision** before the Docker build stage.

The goal is to support continuous, automated security validation and prevent builds from progressing when blocking security findings are detected.

---

## Architecture

Developer
â†“
GitHub Repository
â†“
GitHub Actions CI/CD
â†“
Application Tests
â†“
SAST + SCA + Secret Scanning
â†“
Security Validation Engine
â†“
Security Policy Evaluation
â†“
Security Gate
â†“
Docker Build
â†“
Test Deployment

### Security Validation Flow

```text
Semgrep â”€â”€â”€â”€â”€â”€â”€â”€â”
                â”‚
pip-audit â”€â”€â”€â”€â”€â”€â”¼â”€â”€â†’ SecurityFinding
                â”‚          â”‚
Gitleaks â”€â”€â”€â”€â”€â”€â”€â”˜          â†“
                   SecurityValidationEngine
                            â”‚
                            â†“
                    Severity Evaluation
                            â”‚
                            â†“
                     Security Policy
                            â”‚
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”
                    â†“               â†“
                 PASSED           FAILED
                    â”‚               â”‚
                    â†“               â†“
              Docker Build      Pipeline Stops

## Semester 8: evidence-aware security gate (engine v2)

SecureGate runs Semgrep, pip-audit and Gitleaks, **checks each scanner's evidence before trusting it**, and gives one of three verdicts:

| Verdict | Exit code | Meaning |
|---|---|---|
| PASS | 0 | Every required scanner produced valid evidence and nothing reached the blocking threshold |
| BLOCK | 1 | Valid evidence shows a finding at or above the threshold |
| INCOMPLETE | 2 | A required scanner's evidence is missing or invalid, so security was **not** established. Real findings are still listed |
| (config error) | 3 | The policy file or the command line is invalid |

The evidence checks cover execution (missing tool, launch failure, timeout, unexpected exit code), the report (missing, empty, invalid JSON, wrong structure), consistency (exit code contradicts the report) and coverage (nothing scanned, or part of the input failed).

```bash
python -m security_engine.cli                     # uses securegate.toml if present
python -m security_engine.cli --strategy S0       # experiments: exit-code-only baseline
python -m security_engine.cli --legacy            # the unchanged Semester 7 engine
```

Each run writes `securegate-out/run_manifest.json` (schema 1.1: versions, commands, rule sources, policy hash, timings, evidence status, verdict and reasons), `report.md` and the raw outputs of that run in `raw/<run_id>/`.

**CI:** `.github/workflows/ci-security.yml` runs Tests → SecureGate → Docker build. The gate's exit code decides the job, so BLOCK, INCOMPLETE and policy errors stop the pipeline before the image is built.

**Documentation** (`SecureGate_Project/docs/`):

| Document | Content |
|---|---|
| [architecture.md](SecureGate_Project/docs/architecture.md) | Modules, evidence pipeline, outputs |
| [install-and-usage.md](SecureGate_Project/docs/install-and-usage.md) | Pinned tool installation, CLI, library use |
| [policy-guide.md](SecureGate_Project/docs/policy-guide.md) | Every policy key, strategies S0–S3, suppressions |
| [ci-integration.md](SecureGate_Project/docs/ci-integration.md) | Workflow design and the validation runs |
| [requirements/engine-requirements-v1.md](SecureGate_Project/docs/requirements/engine-requirements-v1.md) | FR-01–FR-35, NFR-01–NFR-07 (v1.1 change log in §7) |
| [traceability-matrix.md](SecureGate_Project/docs/traceability-matrix.md) | Requirement → tests, generated from a test run |
| [test-report.md](SecureGate_Project/docs/test-report.md) | Generated test results |
| [decision-log.md](SecureGate_Project/docs/decision-log.md) | DEC-001–DEC-013 |
| [reproducibility.md](SecureGate_Project/docs/reproducibility.md) | How to reproduce runs and experiments |
| [limitations.md](SecureGate_Project/docs/limitations.md) | Known limits of the engine and the evidence |
| [experiments/](SecureGate_Project/experiments/README.md) | EXP-00 live scanner check, EXP-01 pilot protocol and results |

Tests: `python -m pytest -q` (155 tests). The Semester 7 tests are unchanged.
