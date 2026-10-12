# Semester 7 Baseline Audit

**Status:** Initial source review completed; Flask health test passed; complete test suite and end-to-end pipeline not yet verified.  
**Source reviewed:** `devsecops-semester7-main.zip` supplied by the project owner.  
**Last updated:** 12 October 2026.

## 1. Existing Assets to Preserve

- `security_engine/models.py`: Shared `SecurityFinding` model.
- `security_engine/scanners/semgrep.py`: Semgrep adapter.
- `security_engine/scanners/pip_audit.py`: pip-audit adapter.
- `security_engine/scanners/gitleaks.py`: Gitleaks adapter.
- `security_engine/engine.py`: Scanner orchestration, severity counts, highest-severity calculation, and threshold-based blocking.
- `security_engine/cli.py`: Command-line entry point.
- `.github/workflows/ci-security.yml`: GitHub Actions jobs for tests, SAST, SCA, secret scanning, and Docker build.
- `tests/` and `tests/fixtures/`: Application, scanner-parsing, and engine test assets.
- `Dockerfile`, `app/`, and `requirements.txt`: Basic container and application foundation.

## 2. Confirmed Observations

1. The workflow runs the `test`, `sast`, `sca`, and `secrets` jobs, and the Docker job depends on all four. The reviewed workflow does not invoke `security_engine/cli.py` or otherwise pass scanner outputs into the custom engine.
2. `SecurityValidationEngine.run_all_scanners()` catches scanner exceptions, prints a warning, and continues. It returns collected findings without a structured scanner-health status. An absent or failed scanner may therefore be difficult for downstream code to distinguish from a clean result.
3. `has_blocking_findings()` uses a single severity threshold, defaulting to `HIGH`. It is not yet a per-repository policy with separate outcomes such as `BLOCK`, `WARN`, and `IGNORE`.
4. `summary()` exposes finding counts, highest severity, and a boolean blocking result, but does not include scan completeness, scanner errors, or an explanation of the policy decision.
5. The Flask health test has now passed in the local Windows environment. The complete test suite has not yet been run successfully.
6. The Flask test result does not establish that the scanners execute successfully against real code, that the custom engine controls the CI/CD workflow, or that the Docker build works end to end.

## 3. Initial Baseline Test Results

### 3.1 Flask Application Test

**Date:** 12 October 2026

**Environment**
- Operating system: Windows.
- Python: 3.13.14.
- Flask: 3.1.3.
- pytest: 9.1.1.
- Environment: Project virtual environment.

**Command executed**

`python -m pytest tests/test_app.py -v`

The command was executed using the virtual-environment Python executable because PowerShell script activation was blocked by the current execution policy.

**Result**
- Test: `tests/test_app.py::test_health`
- Outcome: **1 passed in 0.25 seconds.**

**Interpretation**

The existing Flask health test passes in the local Windows environment. This verifies the behavior covered by that test only. It does not independently verify every application route, live server behavior, scanner execution, security-gate enforcement, or deployment.

### 3.2 Scanner and Security-Engine Tests

An earlier inspection run reported eight scanner-parsing and security-engine tests passing in a separate Linux execution environment.

**Environment reported by that run**
- Python: 3.13.5.
- pytest: 9.0.2.
- Operating environment: Linux x86-64.
- Flask: Not installed.

**Result**
- Scanner-parsing and security-engine tests: 8 passed.
- Complete test suite: Test collection was blocked because Flask was unavailable in that environment.

These eight tests have not yet been reproduced in the local Windows environment. They should be treated as preliminary results from a separate environment, not as the final local baseline.

### 3.3 Remaining Verification

| Check | Status |
|---|---|
| Flask health test | Passed |
| Complete local test suite | Pending |
| Reproduction of the eight earlier passing tests | Pending |
| Live Semgrep execution | Not verified |
| Live pip-audit execution | Not verified |
| Live Gitleaks execution | Not verified |
| Custom engine integration into GitHub Actions | Not verified |
| Docker build | Not verified |
| End-to-end security-gate enforcement | Not verified |

## 4. Keep / Modify / Add

### 4.1 Keep

- Existing finding model and scanner adapters as the starting point.
- Parser fixtures and existing tests.
- Dockerfile and basic application health endpoint, subject to further review.
- Original Semester 7 repository as the baseline implementation.

### 4.2 Modify

- Define explicit scanner execution statuses: success, findings detected, tool missing, execution error, and invalid output.
- Make incomplete validation fail closed when policy requires all configured scanners to complete.
- Replace the single hard-coded severity threshold with validated, versioned policy configuration.
- Add structured policy decisions and explanations to the engine output.
- Integrate the custom engine into CI so its decision—not merely independent scanner exit codes—controls progression to the Docker build.
- Improve SCA severity mapping only where reliable metadata is available; represent unknown severity explicitly rather than silently guessing.

### 4.3 Add

- Integration tests covering clean scans, blocking findings, warnings, ignored findings, scanner failure, malformed output, and missing tools.
- A reproducible baseline experiment and raw-results format.
- SecureGate API, persistence, GitHub App integration, and dashboard in later milestones.
- Traceability between finalized research questions, requirements, GitHub issues, implementation, tests, experiments, results, and paper sections.

## 5. Baseline Limitations

- The audit is based on the supplied source archive and the tests explicitly documented above.
- The complete local test suite has not yet been verified.
- Earlier test results came from a separate environment and have not all been reproduced locally.
- The GitHub-hosted workflow has not yet been demonstrated to enforce the custom engine's policy decision.
- No claim is made that the existing implementation is novel.
- Research questions and claims of novelty must wait until literature and prior-art analysis is complete.
- The original Semester 7 repository must remain unchanged as the reference baseline. SecureGate improvements should be developed and documented separately.
- Tests and experiments must not be reported as successful unless they have actually been executed and their results recorded.

## 6. Next Acceptance Criteria

- [x] Flask dependencies installed in the local project virtual environment.
- [x] Existing Flask health test executed successfully.
- [ ] Complete existing test suite runs and results are recorded.
- [ ] Earlier scanner-parsing and security-engine test results are reproduced locally.
- [ ] Engine behavior is tested for scanner errors and unknown severities.
- [ ] Each configured scanner's execution status can be distinguished from a clean scan.
- [ ] A GitHub Actions integration test demonstrates that the custom engine's decision controls the Docker build.
- [ ] Baseline experiment procedures and initial results are documented.

## 7. Change History

- **12 October 2026:** Initial source review documented.
- **12 October 2026:** Recorded eight preliminary passing scanner-parsing and engine tests from a separate environment; complete test collection in that environment was blocked by missing Flask.
- **12 October 2026:** Installed the project dependencies in the local Windows virtual environment and verified that `tests/test_app.py::test_health` passed in 0.25 seconds.
- **12 October 2026:** Updated verification status and acceptance criteria to distinguish completed checks from pending work.
