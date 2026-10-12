# SecureGate

## Final-Year Project

**Working title:** SecureGate: A Policy-Driven Continuous Security Validation Platform for CI/CD Pipelines

### Project goal

Develop, deploy, and experimentally evaluate a publicly accessible DevSecOps security-validation platform that integrates automated security scanning, finding normalization, configurable security policies, and CI/CD security gates.

### Dual outcomes

1. **Functional Product:** A publicly accessible SecureGate web platform and GitHub integration.
2. **Research Paper:** An experimentally evaluated research contribution based on the SecureGate framework.

### Existing baseline

SecureGate builds upon the Semester 7 DevSecOps implementation, which included GitHub Actions, Semgrep, pip-audit, Gitleaks, a custom Security Validation Engine, policy evaluation, a security gate, Docker, and test deployment.

### Development principle

Research → Design → Implement → Test → Experiment → Analyze → Document → Paper

Every major product feature should have a documented rationale, implementation evidence, tests, and—where appropriate—an associated experiment and research-paper contribution.

## Repository structure

- `frontend/` — SecureGate web interface
- `backend/` — backend API and application services
- `security-engine/` — core validation and decision engine
- `github-action/` — GitHub Actions integration
- `scanners/` — scanner adapters/integration
- `tests/` — automated tests
- `experiments/` — controlled experiments
- `results/` — raw and processed research results
- `research/` — literature, research gap, methodology and references
- `paper/` — research-paper drafts and figures
- `docs/` — requirements, architecture, decisions and meeting records
- `deployment/` — deployment and infrastructure configuration
- `presentations/` — project presentations

## Current status

**Phase 0 — Project Foundation**

The repository structure has been established. The next priorities are:

1. Audit the Semester 7 implementation.
2. Conduct the academic literature and market/competitor study.
3. Establish the research gap.
4. Finalize research questions and product requirements.
5. Design the SecureGate architecture.
