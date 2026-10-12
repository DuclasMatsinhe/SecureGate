# Semester 7 Baseline Audit

**Status:** Initial source review completed; runtime tests not yet verified.
**Source reviewed:** `devsecops-semester7-main.zip` supplied by the project owner.

## Existing assets to preserve

- `security_engine/models.py`: shared `SecurityFinding` model.
- `security_engine/scanners/semgrep.py`: Semgrep adapter.
- `security_engine/scanners/pip_audit.py`: pip-audit adapter.
- `security_engine/scanners/gitleaks.py`: Gitleaks adapter.
- `security_engine/engine.py`: scanner orchestration, severity counts, highest-severity calculation, and threshold-based blocking.
- `security_engine/cli.py`: command-line entry point.
- `.github/workflows/ci-security.yml`: GitHub Actions jobs for tests, SAST, SCA, secret scanning, and Docker build.
- `tests/` and `tests/fixtures/`: app, scanner parsing, and engine test assets.
- `Dockerfile`, `app/`, and `requirements.txt`: basic container/application foundation.

## Confirmed observations

1. The workflow runs the `test`, `sast`, `sca`, and `secrets` jobs, and the Docker job depends on all four. The shown workflow does not invoke `security_engine/cli.py` or otherwise pass scanner outputs into the custom engine.
2. `SecurityValidationEngine.run_all_scanners()` catches scanner exceptions, prints a warning, and continues. It returns collected findings without a structured scanner-health status. An absent or failed scanner can therefore be difficult for downstream code to distinguish from a clean result.
3. `has_blocking_findings()` uses a single severity threshold, defaulting to `HIGH`; it is not yet a per-repository policy with separate outcomes such as block, warn, and ignore.
4. `summary()` exposes finding counts, highest severity, and a boolean blocking result, but does not include scan completeness, scanner errors, or a policy decision explanation.
5. Runtime test collection was attempted with `python -m pytest -q` but stopped at import because Flask is not installed in the inspection environment. Installing dependencies was also attempted but package-index access was unavailable. **No test pass/fail conclusion can be drawn yet.**

## Keep / Modify / Add

### Keep
- Existing finding model and scanner adapters as the starting point.
- Parser fixtures and existing tests.
- Dockerfile and basic application health endpoint, subject to review.

### Modify
- Define explicit scanner execution statuses: success, findings detected, tool missing, execution error, and invalid output.
- Make incomplete validation fail closed when policy requires all configured scanners to complete.
- Replace the single hard-coded severity threshold with validated, versioned policy configuration.
- Add structured policy decisions and reasons to the engine output.
- Integrate the engine into CI so its decision—not merely independent scanner exit codes—controls progression to Docker build.
- Improve SCA severity mapping only where reliable metadata is available; represent unknown severity explicitly rather than silently guessing.

### Add
- Integration tests covering clean scans, blocking findings, warnings, ignored findings, scanner failure, malformed output, and missing tools.
- A reproducible baseline experiment and raw-results format.
- SecureGate API, persistence, GitHub App integration, and dashboard in later milestones.
- Documentation linking each research question to a requirement, issue, test, experiment, and paper section once research questions are finalized.

## Baseline limitations

- This audit is based on the supplied source archive, not a successful run of the GitHub-hosted workflow.
- No claim is made that the current implementation is novel.
- Research questions and claims of novelty must wait until literature and prior-art analysis is complete.
- Preserve the original Semester 7 repository and record changes in SecureGate separately so the baseline remains reproducible.

## Next acceptance criteria

- [ ] Dependencies can be installed in a normal development environment.
- [ ] Existing tests run and their baseline results are recorded.
- [ ] Engine behavior is documented for scanner errors and unknown severities.
- [ ] A GitHub Actions integration test demonstrates that the custom engine's decision controls the Docker build.
