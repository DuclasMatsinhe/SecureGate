# Test report

Generated 2026-11-23 05:50 UTC by `tools/traceability_report.py` at commit `f49f817` (branch `semester8-final`).

- Test cases run: 171; passed: 171; failed: 0; skipped: 0; pytest exit code 0; time: 2.67 s
- Command: `python tools/traceability_report.py SecureGate_Project/docs` (runs pytest on `tests/`)

| Test file | What it covers | Passed | Failed | Skipped |
|---|---|---|---|---|
| `test_action.py` | Reusable GitHub Action metadata; actions pinned to SHAs; no expressions in run scripts | 3 | 0 | 0 |
| `test_app.py` | Flask app health check (Semester 7) | 1 | 0 | 0 |
| `test_completion.py` | Gap closures: records, rule sources, isolation, coverage, schema, redaction, timings, CLI/library equivalence | 43 | 0 | 0 |
| `test_exp02.py` | EXP-02 protocol determinism, L1 shard run, analysis reproduces the pilot | 4 | 0 | 0 |
| `test_exp03.py` | EXP-03 held-out protocol: complete, frozen, reuses the EXP-02 harness unchanged | 4 | 0 | 0 |
| `test_gate.py` | Engine v2: probes C0-C13c under S0/S3, policy, CLI, manifest, real subprocesses | 76 | 0 | 0 |
| `test_live_outputs.py` | Real scanner outputs recorded in EXP-00 (simulated replay of real data) | 14 | 0 | 0 |
| `test_scanners.py` | Semester 7 scanner wrappers (unchanged) | 8 | 0 | 0 |
| `test_security_engine.py` | Semester 7 engine (unchanged, NFR-06) | 12 | 0 | 0 |
| `test_traceability.py` | Traceability completeness and static guarantees (no shell, non-root Docker) | 6 | 0 | 0 |

Real-binary tests: `test_gate.py::test_real_*` start real subprocesses (Python stand-ins for timeouts, crashes and missing executables). The real Semgrep, pip-audit and Gitleaks binaries are exercised in CI (`ci-security.yml`) and in EXP-00/EXP-01 L2, not in this unit-test run.

