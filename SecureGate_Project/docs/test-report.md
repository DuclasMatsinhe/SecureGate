# Test report

Generated 2026-11-17 12:32 UTC from `test-results.xml` at commit `4dbe5ee` (branch `semester8-completion`).

- Test cases run: 155; failures: 0; errors: 0; skipped: 0; time: 2.02 s
- Command: `python -m pytest -q --junitxml=test-results.xml`

| Test file | What it covers | Passed | Failed | Skipped |
|---|---|---|---|---|
| `test_app.py` | Flask app health check (Semester 7) | 1 | 0 | 0 |
| `test_completion.py` | Gap closures: records, rule sources, isolation, coverage, schema, redaction, timings, CLI/library equivalence | 43 | 0 | 0 |
| `test_gate.py` | Engine v2: probes C0-C13c under S0/S3, policy, CLI, manifest, real subprocesses | 71 | 0 | 0 |
| `test_live_outputs.py` | Real scanner outputs recorded in EXP-00 (simulated replay of real data) | 14 | 0 | 0 |
| `test_scanners.py` | Semester 7 scanner wrappers (unchanged) | 8 | 0 | 0 |
| `test_security_engine.py` | Semester 7 engine (unchanged, NFR-06) | 12 | 0 | 0 |
| `test_traceability.py` | Traceability completeness and static guarantees (no shell, non-root Docker) | 6 | 0 | 0 |

Real-binary tests: `test_gate.py::test_real_*` start real subprocesses (Python stand-ins for timeouts, crashes and missing executables). The real Semgrep, pip-audit and Gitleaks binaries are exercised in CI (`ci-security.yml`) and in EXP-00/EXP-01 L2, not in this unit-test run.

