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
