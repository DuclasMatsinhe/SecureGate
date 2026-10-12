# Semester 7 Baseline Audit

**Status:** Source review completed; complete existing test suite passed locally; live scanner execution and end-to-end CI/CD behavior remain unverified.  
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

1. The reviewed workflow runs the `test`, `sast`, `sca`, and `secrets` jobs, and the Docker job depends on all four. The reviewed workflow does not invoke `security_engine/cli.py` or otherwise pass scanner outputs into the custom engine.
2. `SecurityValidationEngine.run_all_scanners()` catches scanner exceptions, prints a warning, and continues. It returns collected findings without a structured scanner-health status. An absent or failed scanner may therefore be difficult for downstream code to distinguish from a clean result.
3. `has_blocking_findings()` uses a single severity threshold, defaulting to `HIGH`. It is not yet a per-repository policy with separate outcomes such as `BLOCK`, `WARN`, and `IGNORE`.
4. `summary()` exposes finding counts, highest severity, and a boolean blocking result, but does not include scan completeness, scanner errors, or an explanation of the policy decision.
5. The complete existing test suite has now passed in the local Windows environment. This verifies the behavior covered by the nine existing tests, not the entire end-to-end security pipeline.
6. The current tests do not establish that the three scanners execute successfully against real code, that the custom engine controls the GitHub Actions workflow, or that the Docker build is correctly gated by the engine's decision.

## 3. Baseline Test Results

### 3.1 Local Environment

- Date: 12 October 2026.
- Operating system: Windows.
- Python: 3.13.14.
- Flask: 3.1.3.
- pytest: 9.1.1.
- Environment: Project virtual environment.

### 3.2 Complete Test Suite

**Command executed:**

`python -m pytest -v`

The command was executed using the project's virtual-environment Python executable.

**Result: 9 passed in 0.19 seconds.**

| Test | Result |
|---|---|
| `tests/test_app.py::test_health` | PASSED |
| `tests/test_scanners.py::test_parse_semgrep_results` | PASSED |
| `tests/test_scanners.py::test_parse_pip_audit_results` | PASSED |
| `tests/test_scanners.py::test_parse_gitleaks_results` | PASSED |
| `tests/test_security_engine.py::test_engine_collects_findings` | PASSED |
| `tests/test_security_engine.py::test_engine_counts_severities` | PASSED |
| `tests/test_security_engine.py::test_engine_detects_blocking_finding` | PASSED |
| `tests/test_security_engine.py::test_engine_allows_low_findings` | PASSED |
| `tests/test_security_engine.py::test_engine_summary` | PASSED |

**Interpretation**

All nine discovered tests passed. The result establishes a reproducible initial test-suite baseline for the tested application health endpoint, scanner-result parsing, and security-engine behaviors.

The suite does not yet verify live scanner execution, scanner failure handling, malformed output beyond the existing fixtures, configurable policy enforcement, or end-to-end GitHub Actions and Docker integration.

### 3.3 Earlier Inspection Results

An earlier inspection run reported eight scanner-parsing and security-engine tests passing in a separate Linux environment. That environment lacked Flask, so complete test collection was blocked.

The earlier result is retained as historical context. The nine-test Windows run above is the current verified local baseline.

### 3.4 Remaining Verification

| Check | Status |
|---|---|
| Flask health test | PASSED |
| Complete existing test suite | PASSED: 9 tests |
| Semgrep result-parser tests | PASSED |
| pip-audit result-parser tests | PASSED |
| Gitleaks result-parser tests | PASSED |
| Existing security-engine unit tests | PASSED |
| Live Semgrep execution | Not verified |
| Live pip-audit execution | Not verified |
| Live Gitleaks execution | Not verified |
| Scanner failure and incomplete-scan behavior | Requires further testing |
| Custom engine integration into GitHub Actions | Not verified |
| Docker build | Not verified |
| End-to-end security-gate enforcement | Not verified |

## 4. Keep / Modify / Add

### 4.1 Keep

- Existing finding model and scanner adapters as the starting point.
- Existing parser fixtures and passing tests.
- Dockerfile and basic application health endpoint, subject to further review.
- Original Semester 7 repository as the baseline implementation.
- The nine-test result as the initial local test baseline.

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

- The audit is based on the supplied source archive and the test runs explicitly documented above.
- Passing unit tests do not establish end-to-end system correctness.
- Live scanner execution and the complete CI/CD security-gate behavior remain unverified.
- No claim is made that the existing implementation is novel.
- Research questions and claims of novelty must wait until literature and prior-art analysis is complete.
- Preserve the original Semester 7 repository as the reference baseline. Develop and document SecureGate improvements separately.
- Do not report unexecuted tests, experiments, or deployment checks as successful.

## 6. Next Acceptance Criteria

- [x] Install project dependencies in the local virtual environment.
- [x] Run the existing Flask health test successfully.
- [x] Run the complete existing test suite: 9 tests passed.
- [x] Record the local test environment and results.
- [ ] Verify live execution of Semgrep, pip-audit, and Gitleaks.
- [ ] Test scanner errors, missing tools, invalid output, and unknown severities.
- [ ] Define and test explicit scanner-health and policy-decision behavior.
- [ ] Integrate the custom engine into GitHub Actions.
- [ ] Demonstrate that the engine's decision controls the Docker build.
- [ ] Establish reproducible baseline experiments and record raw results.

## 7. Change History

- **12 October 2026:** Initial source review documented.
- **12 October 2026:** Recorded preliminary results from the separate inspection environment.
- **12 October 2026:** Installed the dependencies in the local Windows virtual environment and verified the Flask health test.
- **12 October 2026:** Executed the complete existing test suite locally; all nine tests passed in 0.19 seconds.
- **12 October 2026:** Updated acceptance criteria to reflect the verified baseline and remaining integration checks.
