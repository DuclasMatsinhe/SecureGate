# Semester 7 Baseline Audit

**Status:** Source review completed; all nine existing tests passed locally; all three scanner executables have completed controlled live tests. Default-rule secret detection and end-to-end CI/CD enforcement remain to be verified.  
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

## 2. Confirmed Source Observations

1. The reviewed workflow runs the `test`, `sast`, `sca`, and `secrets` jobs, and the Docker job depends on all four. The reviewed workflow does not invoke `security_engine/cli.py` or otherwise pass scanner outputs into the custom engine.
2. `SecurityValidationEngine.run_all_scanners()` catches scanner exceptions, prints a warning, and continues. It returns collected findings without a structured scanner-health status. An absent or failed scanner may therefore be difficult for downstream code to distinguish from a clean result.
3. `has_blocking_findings()` uses a single severity threshold, defaulting to `HIGH`. It is not yet a per-repository policy with separate outcomes such as `BLOCK`, `WARN`, and `IGNORE`.
4. `summary()` exposes finding counts, highest severity, and a boolean blocking result, but does not include scan completeness, scanner errors, or an explanation of the policy decision.
5. The existing tests cover application health, scanner-result parsing, and basic security-engine behavior. They do not establish end-to-end CI/CD correctness.

## 3. Local Test Environment

- Date: 12 October 2026.
- Operating system: Windows.
- Python: 3.13.14.
- Flask: 3.1.3.
- pytest: 9.1.1.
- Environment: Project virtual environment.

## 4. Existing Test Suite Results

**Command executed:** `python -m pytest -v`, using the project's virtual-environment Python executable.

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

**Interpretation:** All nine discovered tests passed. This establishes an initial local baseline for the tested application health endpoint, scanner-result parsing, and security-engine behaviors.

## 5. Controlled Live Scanner Experiments

### 5.1 Semgrep

**Version:** 1.180.0  
**Command:** `semgrep scan --config p/python semgrep_test.py`, executed through the virtual-environment executable.

**Test input:** A temporary Python file containing user-controlled SQL string construction and a directly returned string.

**Observed result:**
- Scan completed successfully.
- One file scanned.
- 151 rules ran.
- Two code findings were reported:
  - `python.flask.security.injection.tainted-sql-string`
  - `python.flask.security.audit.directly-returned-format-string`

**Interpretation:** Semgrep successfully executed and detected the intended SQL-injection pattern, as well as a second rule match. The second finding is not, by itself, proof of an exploitable vulnerability in the isolated test function.

**Limitations:** The scan used the `p/python` ruleset while not logged in. Semgrep reported that additional Pro rules were unavailable. The test file was temporary and is not part of the production application.

### 5.2 pip-audit

**Version:** 2.10.1  
**Test input:** A temporary requirements file specifying `urllib3==1.26.5`.

**Observed result:**
- pip-audit executed and reported 18 vulnerability records associated with the package.
- The output included vulnerability identifiers and suggested fixed versions.
- A warning indicated that the temporary virtual-environment path may have moved due to Windows redirects, links, or junctions.

**Interpretation:** pip-audit successfully identified known vulnerability records for the deliberately outdated test dependency.

**Limitations:** The 18 records should not be interpreted as 18 unique underlying vulnerabilities. The test validates the scanner's ability to retrieve and report vulnerability information for this controlled dependency, not the vulnerability status of the full SecureGate application. The environment warning should be investigated if it recurs during project scans.

### 5.3 Gitleaks

**Version:** 8.30.1  
**Test input:** A temporary text file containing a synthetic secret-like value. The initial default-rule scans reported no leaks. A subsequent test used a temporary custom Gitleaks rule matching `SECUREGATE_TEST_SECRET_[A-Z0-9]{16}`.

**Command used for the custom-rule test:**

`gitleaks dir --config .\gitleaks-test\test-rules.toml .\gitleaks-test`

**Observed result:**
- Gitleaks executed successfully.
- One leak was reported with the custom rule.
- The test used synthetic data and did not require a real credential.

**Interpretation:** Gitleaks can scan the test directory and report a finding when a matching rule is configured.

**Limitations:** Positive detection under the default rule set has not been established by these tests. The earlier examples were not detected. The custom rule proves the scanner's reporting path works for that rule, but does not prove that the default secret-detection rules are correctly configured for the intended use cases.

## 6. Combined Verification Summary

| Component | Verified behavior | Remaining limitation |
|---|---|---|
| Flask application | Health test passed | Other routes and live server behavior not comprehensively tested |
| Semgrep | Two findings detected in a controlled Python file | Additional rules and production-repository scanning not evaluated |
| pip-audit | 18 vulnerability records reported for the test dependency | Full project dependency audit not evaluated |
| Gitleaks | One finding detected using a temporary custom rule | Default-rule positive detection not yet verified |
| Security engine | Existing unit tests passed | Live scanner integration and failure handling not verified |
| GitHub Actions | Workflow structure reviewed | Engine's decision has not been proven to control the Docker build |
| Docker | Dockerfile exists | Build and security-gate integration not verified |

## 7. Keep / Modify / Add

### 7.1 Keep

- Existing finding model and scanner adapters as the starting point.
- Existing parser fixtures and passing tests.
- Dockerfile and basic application health endpoint, subject to further review.
- Original Semester 7 repository as the reference baseline.
- The nine-test local result and controlled scanner-test evidence.

### 7.2 Modify

- Define explicit scanner execution statuses: success, findings detected, tool missing, execution error, and invalid output.
- Make incomplete validation fail closed when policy requires all configured scanners to complete.
- Replace the single hard-coded severity threshold with validated, versioned policy configuration.
- Add structured policy decisions and explanations to the engine output.
- Integrate the custom engine into CI so its decision—not merely independent scanner exit codes—controls progression to the Docker build.
- Improve SCA severity mapping only where reliable metadata is available; represent unknown severity explicitly rather than silently guessing.
- Investigate why the initial Gitleaks default-rule tests did not detect the synthetic values before claiming default configuration is validated.

### 7.3 Add

- Integration tests covering clean scans, blocking findings, warnings, ignored findings, scanner failure, malformed output, and missing tools.
- A reproducible baseline experiment procedure with saved scanner versions, commands, test inputs, outputs, and raw measurements.
- SecureGate API, persistence, GitHub App integration, and dashboard in later milestones.
- Traceability between finalized research questions, requirements, GitHub issues, implementation, tests, experiments, results, and paper sections.

## 8. Baseline Limitations

- The audit is based on the supplied source archive and the tests documented above.
- The controlled scanner experiments are preliminary functional checks, not a comprehensive security evaluation.
- No claim is made that the existing implementation is novel.
- Research questions and claims of novelty must wait until literature and prior-art analysis is complete.
- Preserve the original Semester 7 repository as the reference baseline. Develop and document SecureGate improvements separately.
- Do not report unexecuted tests, experiments, or deployment checks as successful.

## 9. Next Acceptance Criteria

- [x] Install project dependencies in the local virtual environment.
- [x] Run the existing Flask health test.
- [x] Run the complete existing test suite: 9 tests passed.
- [x] Execute Semgrep against a controlled Python sample and record its findings.
- [x] Execute pip-audit against a controlled outdated dependency and record its vulnerability records.
- [x] Execute Gitleaks and confirm a finding using a temporary custom rule.
- [ ] Verify Gitleaks default-rule detection with a suitable controlled test case.
- [ ] Verify scanner adapters against actual scanner output, not only parser fixtures.
- [ ] Test scanner errors, missing tools, invalid output, and unknown severities.
- [ ] Define and test explicit scanner-health and policy-decision behavior.
- [ ] Integrate the custom engine into GitHub Actions.
- [ ] Demonstrate that the engine's decision controls the Docker build.
- [ ] Establish reproducible baseline experiments and record raw results.

## 10. Change History

- **12 October 2026:** Initial source review documented.
- **12 October 2026:** Recorded preliminary test results from the separate inspection environment.
- **12 October 2026:** Verified the Flask health test in the local Windows virtual environment.
- **12 October 2026:** Executed the complete existing test suite locally; all nine tests passed in 0.19 seconds.
- **12 October 2026:** Verified Semgrep detection of two findings in a controlled Python sample.
- **12 October 2026:** Verified pip-audit reporting of 18 vulnerability records for `urllib3==1.26.5`.
- **12 October 2026:** Verified Gitleaks detection of one synthetic finding using a temporary custom rule; default-rule detection remains unverified.
