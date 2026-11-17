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

## Semester 8: evidence-aware security gate (engine v2, in development)

The new gate (`security_engine/gate.py`) runs Semgrep, pip-audit and Gitleaks, **checks each scanner's evidence before trusting it**, and gives one of three verdicts:

| Verdict | Exit code | Meaning |
|---|---|---|
| PASS | 0 | Every required scanner produced valid evidence and nothing reached the blocking threshold |
| BLOCK | 1 | Valid evidence shows a finding at or above the threshold |
| INCOMPLETE | 2 | A required scanner's evidence is missing or invalid, so security was **not** established. Real findings are still listed |
| (config error) | 3 | The policy file or the command line is invalid |

The evidence checks cover:
- **Execution:** the tool is missing, fails to start, times out, or exits with an unexpected code.
- **Report:** the report is missing, empty, invalid JSON or the wrong structure.
- **Consistency:** the exit code contradicts the report.
- **Coverage:** the scanner scanned nothing, or skipped part of the input.

Run it:

```bash
python -m security_engine.cli                     # uses securegate.toml if present
python -m security_engine.cli --strategy S0       # experiment: exit-code-only baseline
python -m security_engine.cli --legacy            # the unchanged Semester 7 engine
```

Each run writes `securegate-out/run_manifest.json` (versions, commands, policy hash, evidence status, verdict and reasons) and `securegate-out/report.md`. The report is also appended to the GitHub Actions job summary when it runs in Actions.

The policy lives in `securegate.toml`: strategy, thresholds, timeouts, required scanners, what INCOMPLETE does, and time-limited suppressions.

Tests: `python -m pytest`. The Semester 7 tests are unchanged, and `tests/test_gate.py` reproduces every fault probe from the audit.
