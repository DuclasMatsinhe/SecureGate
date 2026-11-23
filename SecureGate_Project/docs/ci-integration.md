# CI integration

**Workflow:** `.github/workflows/ci-security.yml` (DEC-012) · **Triggers:** push to `main`, `securegate-development`, `semester8-*`; pull requests to `main` and `securegate-development`; manual dispatch.

## 1. Pipeline

```mermaid
flowchart LR
  T[Tests<br/>pytest, 164 tests] --> G[SecureGate<br/>pinned scanners,<br/>CLI exit code decides] --> D[Docker build]
  G -. always .-> A[(Artifact: manifest,<br/>report, raw outputs)]
```

| Job | Does | Fails when |
|---|---|---|
| Tests | `pip install -r requirements-dev.txt`; `pytest -q` (also validates the repository policy) | any test fails |
| SecureGate | installs Semgrep 1.180.0 and pip-audit 2.10.1 in their own venv and Gitleaks 8.30.1 (SHA-256 checked); runs `python -m security_engine.cli`; writes the verdict as a job annotation; validates the manifest against its JSON Schema; uploads the evidence; then enforces the exit code | exit 1 (BLOCK), 2 (INCOMPLETE) or 3 (policy/usage error) |
| Docker build | `docker build` | only runs after the gate job succeeds, i.e. PASS |

BLOCK and INCOMPLETE can never pass silently: the "Enforce gate verdict" step exits with the gate's code, and the Docker job `needs` the gate job. With `on_incomplete = "warn"` in the policy the gate itself returns 0 for INCOMPLETE; that is a visible, versioned policy choice (its hash is in the manifest), not a workflow setting.

## 2. Security of the workflow

- `permissions: contents: read` for the whole workflow; no secrets are used.
- `persist-credentials: false` on every checkout.
- Every action pinned to a full commit SHA (checkout v7.0.1, setup-python v7.1.0, upload-artifact v7.0.2); `tests/test_action.py` fails if one is not.
- No `${{ }}` expression is expanded inside a `run:` script; values are passed through `env:` (also enforced by `tests/test_action.py`). This closed D2: the policy now uses `p/python` and `p/github-actions`, validated on `semester8-ci-validate-d2` (run [45119728760](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/45119728760): PASS, Semgrep evidence VALID).
- Scanner versions pinned; the Gitleaks binary verified with `sha256sum -c` before use.
- Scanners run from a separate virtual environment, so they cannot change the application's dependencies.
- Full history checkout (`fetch-depth: 0`) so Gitleaks scans history, not only the last commit.
- Evidence artifact kept 30 days; secrets in it are redacted by the engine (FR-29) and by Gitleaks (`--redact`).

## 3. Validation with real runs

Each validation branch is the completion branch plus one commit that changes `securegate.toml`. They are never merged.

| Branch | Change | Expected | Final workflow (commit `5709211`) | Earlier runs |
|---|---|---|---|---|
| `semester8-completion` | none | PASS → Docker build runs | PASS, exit 0, Docker built ([44090612694](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44090612694)) | PASS [44082447919](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44082447919), [44083975063](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44083975063); BLOCK on own code [44089985683](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44089985683) (§4) |
| `semester8-ci-validate-block` | pip-audit pointed at `pip_audit_test_requirements.txt` (urllib3 1.26.5) | BLOCK, job fails, Docker skipped | BLOCK, exit 1, `pip-audit: BLOCKING_FINDING x18`, Docker skipped ([44090927129](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44090927129)) | BLOCK [44082714889](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44082714889), [44089995015](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44089995015) |
| `semester8-ci-validate-incomplete` | `executable = "semgrep-not-installed"` | INCOMPLETE, job fails, Docker skipped | INCOMPLETE, exit 2, `semgrep: TOOL_MISSING`, Docker skipped ([44090934106](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44090934106)) | INCOMPLETE [44082720043](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44082720043), [44090003173](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44090003173) |
| `semester8-ci-validate-config` | `strategy = "S9"` | pipeline stops before the gate | Tests job failed (repository-policy test); gate and Docker skipped ([44090938218](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44090938218)) | same [44083925171](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44083925171), [44090012385](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44090012385) |

The gate's own exit 3 is covered by unit tests (`test_cli_invalid_policy_exits_3`, `test_only_pass_lets_ci_continue`) and a local run ("strategy must be one of S0, S1, S2, S3", exit 3).

The verdicts above were read from the public GitHub API (job conclusions and the "SecureGate verdict" annotation).

## 4. A real block on SecureGate's own code

Run [44089985683](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44089985683) (commit `059cbb9`) was **blocked by the gate itself**: `semgrep: BLOCKING_FINDING x2`, Docker build skipped. The only Python file changed since the previous PASS was `tools/traceability_report.py`, which parsed pytest's JUnit XML with `xml.etree.ElementTree` (two `ET.parse` calls; Semgrep's `p/python` flags this because of XML entity attacks). The input was trusted, but instead of suppressing the finding the tool was rewritten to collect test outcomes in-process with a pytest plugin, so no XML is parsed. The exact rule IDs are in that run's evidence artifact (artifact download needs a signed-in GitHub account; the public API shows the verdict annotation only).

## 5. Making it a required check

To stop merges, mark the **SecureGate** job as a required status check in the branch protection of `main`. That is a repository-settings change and was not made; it needs the owner's approval.

## 6. The reusable Action

`action.yml` packages the same gate for other repositories (see the main README for the usage snippet). It is a composite action: it installs the pinned scanners in their own virtual environment, verifies the Gitleaks binary, runs `security_engine.cli` from the Action's own folder against the caller's checkout, writes the report to the job summary, uploads the manifest, and ends the step with the gate's exit code (or only sets the outputs when `fail-job: false`).

The self-test workflow `action-selftest.yml` builds synthetic projects with `tools/make_fixture.py` and checks the decision of each case:

| Case | Expected | Run [45119833564](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/45119833564) |
|---|---|---|
| clean project | PASS, exit 0 | PASS, exit 0 |
| SAST finding (`eval`) | BLOCK, exit 1 | BLOCK, exit 1 |
| SCA finding (old urllib3) | BLOCK, exit 1 | BLOCK, exit 1 |
| secret finding (synthetic token) | BLOCK, exit 1; no token in the evidence | BLOCK, exit 1; none found |
| Semgrep missing | INCOMPLETE, exit 2 | INCOMPLETE, exit 2, `TOOL_MISSING` |
| pip-audit missing + SAST finding | INCOMPLETE, exit 2, finding listed | INCOMPLETE, exit 2 |
| invalid policy (`strategy = "S9"`) | exit 3, no verdict | exit 3 |
| Action used by reference (`DuclasMatsinhe/SecureGate@semester8-final`) on a SAST finding | step fails with BLOCK | failed, BLOCK, exit 1 |

The first self-test run (45119706809) failed in every non-PASS case: composite-action shells start with `bash -e`, so the gate's non-zero exit ended the step before the decision was recorded. Fixed in the next commit; this is why the self-test exists.
