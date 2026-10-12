# Semester 7 Baseline Audit

**Status:** Baseline source review and initial local validation completed. All nine existing tests passed. Semgrep, pip-audit, and Gitleaks completed controlled scanner tests. Default-rule secret detection and end-to-end CI/CD enforcement remain unverified.

**Source reviewed:** `devsecops-semester7-main.zip` supplied by the project owner.

**Last updated:** 12 October 2026.

## 1. Existing Assets to Preserve

- `security_engine/models.py`: Shared `SecurityFinding` model.
- `security_engine/scanners/semgrep.py`: Semgrep adapter.
- `security_engine/scanners/pip_audit.py`: pip-audit adapter.
- `security_engine/scanners/gitleaks.py`: Gitleaks adapter.
- `security_engine/engine.py`: Scanner orchestration, severity counts, highest-severity calculation, and threshold-based blocking.
- `security_engine/cli.py`: Command-line entry point and security-gate result.
- `.github/workflows/ci-security.yml`: GitHub Actions workflow for tests, SAST, SCA, secret scanning, and Docker build.
- `tests/` and `tests/fixtures/`: Application, scanner-parsing, and engine test assets.
- `Dockerfile`, `app/`, and `requirements.txt`: Basic application and container foundation.

These assets form the reference baseline. Improvements should be developed separately and compared against this baseline rather than silently replacing the original implementation.

## 2. Confirmed Source Observations

1. The reviewed GitHub Actions workflow runs the `test`, `sast`, `sca`, and `secrets` jobs. The Docker job depends on these jobs, but the reviewed workflow does not invoke `security_engine/cli.py` or otherwise demonstrate that scanner outputs are evaluated by the custom engine.

2. `SecurityValidationEngine.run_all_scanners()` invokes Semgrep, pip-audit, and Gitleaks sequentially and aggregates the findings returned by the adapters.

3. The engine catches `FileNotFoundError` and other exceptions, prints warnings, and continues. Scanner execution status is not represented separately from the collected findings. Consequently, a failed or unavailable scanner may be difficult for downstream code to distinguish from a successful scan with no findings.

4. The Gitleaks adapter executes the scanner with JSON reporting and reads `gitleaks-report.json`. It returns an empty list if the report is missing or invalid JSON. This behavior can make a scanner or report-processing failure appear equivalent to a clean scan.

5. The current engine uses a single severity threshold, defaulting to `HIGH`, rather than a configurable policy with separate `BLOCK`, `WARN`, and `IGNORE` outcomes.

6. `summary()` exposes finding counts, highest severity, and a boolean blocking result. It does not include scanner health, scan completeness, scanner errors, or a policy-decision explanation.

7. The CLI returns exit code `1` when HIGH or CRITICAL findings meet the blocking threshold and `0` otherwise. However, the reviewed GitHub Actions workflow has not been shown to use this decision to control Docker build progression.

8. The existing tests cover application health, scanner-result parsing, and basic engine behavior. They do not establish end-to-end CI/CD correctness.

## 3. Local Test Environment

- **Date:** 12 October 2026.
- **Operating system:** Windows.
- **Python:** 3.13.14.
- **Flask:** 3.1.3.
- **pytest:** 9.1.1.
- **Environment:** Project virtual environment.

The scanner versions recorded during the controlled tests were:

- **Semgrep:** 1.180.0.
- **pip-audit:** 2.10.1.
- **Gitleaks:** 8.30.1.

These are observed versions from the local test environment, not pinned versions for the eventual production deployment.

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

**Interpretation:** All nine discovered tests passed. This establishes an initial local baseline for the tested application health endpoint, scanner-result parsing, and security-engine behaviors. It does not establish that all three scanners execute correctly through the Python adapters or that the CI security gate works end to end.

## 5. Controlled Live Scanner Experiments

### 5.1 Semgrep

**Version:** 1.180.0.

**Command:**

`semgrep scan --config p/python semgrep_test.py`

The command was executed using the virtual-environment executable.

**Test input:** A temporary Python file containing user-controlled SQL string construction and a directly returned string.

**Observed result:**

- Scan completed successfully.
- One file was scanned.
- 151 rules ran.
- Two code findings were reported:
  - `python.flask.security.injection.tainted-sql-string`
  - `python.flask.security.audit.directly-returned-format-string`

**Interpretation:** Semgrep successfully executed and detected the intended SQL-injection pattern, along with a second rule match. The second finding is not, by itself, proof of an exploitable vulnerability in the isolated test function.

**Limitations:**

- The scan used the `p/python` ruleset while not logged in.
- Semgrep reported that additional Pro rules were unavailable.
- The input file was temporary and was not part of the production application.
- The experiment does not yet measure detection effectiveness across a representative vulnerability dataset.

### 5.2 pip-audit

**Version:** 2.10.1.

**Test input:** A temporary requirements file specifying `urllib3==1.26.5`.

**Observed result:**

- pip-audit executed successfully.
- It reported 18 vulnerability records associated with the package.
- The output included vulnerability identifiers and suggested fixed versions.
- A warning indicated that the temporary virtual-environment path may have moved because of Windows redirects, links, or junctions.

**Interpretation:** pip-audit successfully identified known vulnerability records for the deliberately outdated test dependency.

**Limitations:**

- The 18 records must not be interpreted as 18 unique underlying vulnerabilities.
- The test does not establish the vulnerability status of the full SecureGate application.
- The environment warning should be investigated if it recurs during project scans.
- The mapping of dependency vulnerabilities to SecureGate's common severity model still requires validation.

### 5.3 Gitleaks

**Version:** 8.30.1.

**Test input:** A temporary text file containing a synthetic secret-like value.

**Initial result:** The default-rule scans did not report a leak.

A subsequent experiment created a temporary custom rule matching:

`SECUREGATE_TEST_SECRET_[A-Z0-9]{16}`

The test used synthetic data, not a real credential.

**Command used:**

`gitleaks dir --config .\gitleaks-test\test-rules.toml .\gitleaks-test`

**Observed result:**

- Gitleaks executed successfully.
- One finding was reported with the custom rule.
- The scanner's output showed that the configured rule matched the synthetic test value.

**Interpretation:** Gitleaks can scan the test directory and report a finding when a matching rule is configured.

**Limitations:**

- Positive detection under the default rule set has not been established by these tests.
- The earlier synthetic examples were not detected.
- The custom-rule test validates that specific rule's detection path, not the effectiveness of all default rules.
- The Python adapter's behavior with missing reports, invalid JSON, and non-zero scanner exit codes still needs dedicated tests.

## 6. Combined Verification Summary

| Component | Verified behavior | Remaining limitation |
|---|---|---|
| Flask application | Health test passed | Other routes and live server behavior not comprehensively tested |
| Existing test suite | Nine tests passed | No end-to-end CI/CD test |
| Semgrep | Two findings detected in a controlled Python file | Additional rules and production-repository scanning not evaluated |
| pip-audit | 18 vulnerability records reported for the test dependency | Full project dependency audit not evaluated |
| Gitleaks | One finding detected using a temporary custom rule | Default-rule positive detection not verified |
| Security engine | Existing unit tests passed | Live adapter integration and failure handling not verified |
| GitHub Actions | Workflow structure reviewed | The custom engine's decision has not been proven to control Docker progression |
| Docker | Dockerfile exists | Build and security-gate integration not verified |

## 7. Keep, Modify, and Add

### 7.1 Keep

- The existing `SecurityFinding` model as the starting point.
- Existing scanner adapters and parsing fixtures, subject to further testing.
- The existing nine passing tests as the regression baseline.
- The Dockerfile and basic application health endpoint, subject to further review.
- The original Semester 7 repository as the reference baseline.
- The recorded controlled scanner experiments and their limitations.

### 7.2 Modify

1. **Scanner execution status:** Introduce explicit states such as `SUCCESS`, `FINDINGS_DETECTED`, `TOOL_MISSING`, `EXECUTION_ERROR`, and `INVALID_OUTPUT`. A scan that completes successfully with no findings must remain distinguishable from a scan that fails.

2. **Fail-closed behavior:** When policy requires all configured scanners, an incomplete validation must not silently pass the security gate.

3. **Gitleaks report handling:** Validate the scanner's exit code, report existence, and JSON contents. Treat missing or malformed output as a validation error, not automatically as zero findings.

4. **Semgrep and pip-audit adapters:** Review subprocess invocation, exit-code interpretation, JSON parsing, and error handling. Confirm that normal findings are not mistaken for execution failures and that execution failures are not mistaken for clean scans.

5. **Policy configuration:** Replace the single hard-coded severity threshold with validated, versioned policy configuration. Support explicit outcomes such as `BLOCK`, `WARN`, and `IGNORE`, with defined behavior for each severity and finding category.

6. **Policy explanations:** Include the selected policy, scanner status, decision, and reason in structured engine output.

7. **CI integration:** Make the custom engine's evaluated decision authoritative for progression to the Docker build. Preserve individual scanner reports for diagnostics and reproducibility.

8. **SCA severity mapping:** Use reliable vulnerability metadata where available. Represent unknown severity explicitly instead of silently guessing.

9. **Secret detection:** Investigate the initial default-rule test results and design a controlled positive test case appropriate for the default Gitleaks rules.

### 7.3 Add

- Unit and integration tests for clean scans, blocking findings, warnings, ignored findings, scanner failures, missing tools, malformed output, and unknown severity.
- Tests demonstrating that scanner failure cannot be treated as a successful clean scan when the configured policy requires that scanner.
- CI tests demonstrating that a blocking decision prevents the Docker build and a passing decision allows it to proceed.
- A reproducible experiment procedure recording tool versions, commands, test inputs, outputs, raw measurements, and analysis.
- SecureGate API, persistence, GitHub App integration, and dashboard in later development milestones.
- Traceability between finalized research questions, requirements, GitHub issues, implementation, tests, experiments, results, and paper sections.

## 8. Baseline Limitations and Research Integrity

- This audit is based on the supplied source archive and the tests documented above.
- The controlled scanner experiments are preliminary functional checks, not a comprehensive security evaluation.
- The scanner results do not establish the accuracy, completeness, or effectiveness of the overall security-validation framework.
- No claim is made that the existing implementation is novel.
- Research questions and novelty claims must be established only after literature review and prior-art analysis.
- The original Semester 7 repository must be preserved as the reference baseline.
- Improvements must be documented separately so that baseline and improved behavior can be compared.
- Tests, experiments, and deployment checks that have not been executed must remain marked as incomplete.
- Raw experimental data must be preserved without alteration to improve reported outcomes.

## 9. Next Acceptance Criteria

### Completed

- [x] Install project dependencies in the local virtual environment.
- [x] Run the Flask health test.
- [x] Run the complete existing test suite: nine tests passed.
- [x] Execute Semgrep against a controlled Python sample and record its findings.
- [x] Execute pip-audit against a controlled outdated dependency and record its vulnerability records.
- [x] Execute Gitleaks and confirm a finding using a temporary custom rule.

### Outstanding

- [ ] Verify Gitleaks default-rule detection with a suitable controlled test case.
- [ ] Test the actual Python scanner adapters against live scanner output.
- [ ] Test scanner errors, missing tools, invalid output, and unknown severities.
- [ ] Define and test explicit scanner-health behavior.
- [ ] Define and test versioned policy configuration and decision explanations.
- [ ] Integrate the custom engine into GitHub Actions.
- [ ] Demonstrate that the engine's decision controls Docker build progression.
- [ ] Verify that scanner failures cannot silently produce a passing decision.
- [ ] Establish reproducible baseline experiments and record raw results.
- [ ] Run and document the improved implementation's regression and integration tests.

## 10. Change History

- **12 October 2026:** Initial source review documented.
- **12 October 2026:** Recorded preliminary test results from the separate inspection environment.
- **12 October 2026:** Verified the Flask health test in the local Windows virtual environment.
- **12 October 2026:** Executed the complete existing test suite locally; all nine tests passed in 0.19 seconds.
- **12 October 2026:** Verified Semgrep detection of two findings in a controlled Python sample.
- **12 October 2026:** Verified pip-audit reporting of 18 vulnerability records for `urllib3==1.26.5`.
- **12 October 2026:** Verified Gitleaks detection of one synthetic finding using a temporary custom rule; default-rule detection remains unverified.
- **12 October 2026:** Documented scanner-health, policy enforcement, adapter integration, and CI/CD gate validation as outstanding engineering work.
