# SecureGate Project Charter

## Working title

**SecureGate: A Policy-Driven Continuous Security Validation Platform for CI/CD Pipelines**

## Project type

Final-Year B.Tech Project

## Primary outcomes

1. Functional product: publicly deployed SecureGate platform.
2. Research paper: experimentally evaluated research manuscript.

## Background

The project builds upon the Semester 7 DevSecOps implementation and extends it into a deployable product and research study.

## Initial product concept

SecureGate integrates automated security validation into CI/CD pipelines. It is intended to normalize findings from multiple security scanners, apply configurable security policies, and make an automated security-gate decision before a build/deployment proceeds.

## Initial scanner scope

- Semgrep — SAST
- pip-audit — SCA
- Gitleaks — secret detection

This scope is provisional and may change after literature, market and technical analysis.

## Product users

Primary:
- software developers
- student developers
- small development teams
- DevOps/DevSecOps practitioners

## Research direction

The research will investigate the effectiveness, enforcement behavior and performance of policy-driven continuous security validation in CI/CD.

The final research questions and contribution must be established through literature and prior-art analysis.

## Success criteria

### Product
- Publicly deployed.
- External user can authenticate with GitHub.
- External user can connect a test repository.
- Security validation can execute.
- Findings can be viewed.
- Policies can be configured.
- Security gate can return PASS/BLOCK.
- Scan history is available.

### Research
- Defensible research gap.
- Clear research questions.
- Reproducible methodology.
- Controlled experiments.
- Quantitative results.
- Limitations and threats to validity documented.
- Manuscript suitable for submission to an appropriate venue.

### Evidence
- Reproducible GitHub repository.
- Development history.
- Experiment records.
- Raw and processed results.
- Architecture and design records.
- Paper drafts.

## Important constraint

No claim of novelty or patentability should be made until relevant academic literature and patent/prior-art searches have been performed.
