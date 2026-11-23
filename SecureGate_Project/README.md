# SecureGate project folder

**Title:** SecureGate: Evidence-Aware Security Gating for CI/CD Pipelines Using SAST, SCA and Secret Scanning
(earlier working title: *SecureGate: A Policy-Driven Continuous Security Validation Platform for CI/CD Pipelines*)

B.Tech ICT final-year project (01CT3801), Marwadi University · Duclas Argentina Francisco Matsinhe · Guide: Dharmendrasinh Zala

## Goal

Build an evidence-aware security gate for CI/CD pipelines, and measure by controlled fault injection how scanner failures affect its decisions.

The project has two outcomes:

1. **Product:** SecureGate, a reusable GitHub Action that any repository can add: it checks the evidence of Semgrep, pip-audit and Gitleaks before deciding PASS, BLOCK or INCOMPLETE.
2. **Research paper:** a controlled comparison of four evidence-handling strategies (S0–S3) under ten injected scanner fault classes.

The original charter asked for a publicly deployed web platform (GitHub sign-in, connect a repository, view findings, configure policies, scan history). On 23 Nov 2026 the student chose to deliver these through GitHub itself, as a reusable Action, instead of a hosted web application (DEC-020); this still has to be confirmed with the guide.

## Development principle

Research → Design → Implement → Test → Experiment → Analyse → Document → Paper

Every major feature has a documented rationale, implementation evidence, tests and, where appropriate, an experiment and a contribution to the paper.

## Folder contents

| Folder | Content |
|---|---|
| `docs/` | Requirements, architecture, policy guide, CI integration, decisions, traceability, test report, limitations, meeting records |
| `experiments/` | EXP-00 (live scanner check), EXP-01 (pilot), EXP-02 (final study) with protocols, harnesses and results |
| `research/` | Literature notes and the research log |
| `paper/` | Notes on the research paper (the draft itself is kept outside the repository) |
| `PROJECT_ROADMAP.md` | The original roadmap (kept as written; status is tracked in `docs/completion-report.md`) |

The gate's code is at the repository root (`security_engine/`, `tests/`, `tools/`); see the main README.

## Current status (23 Nov 2026)

- Engine, CI integration and documentation: done and verified (171 tests; 44 requirements traced).
- Reusable GitHub Action: done; self-test covers every decision path, including use by reference from GitHub (run 45119833564).
- Literature review: preliminary review and formal database search completed (18 Nov 2026).
- EXP-01 pilot: done and replicated (17 Nov 2026).
- EXP-02 final study: protocol frozen and run as final (21 Nov 2026, 7,160 runs), identical to the earlier candidate run; frozen without the guide's approval (DEC-018).
- EXP-03 held-out confirmation: pre-registered and frozen, smoke run passed; final run after the pre-registration is archived on Zenodo.
- Research paper: complete draft with the final EXP-02 results; venue to be decided with the guide.
