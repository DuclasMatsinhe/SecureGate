# EXP-00: Live scanner check (pilot)

| Field | Content |
|---|---|
| **1. Experiment ID** | EXP-00 (pilot for OBJ2; not part of the frozen main experiment) |
| **2. Research question** | SRQ1: which scanner failures produce misleading gate verdicts? Pilot scope: how do the real tools behave on failure? |
| **3. Objective** | Record the real exit codes, report contents and coverage signals of Semgrep, pip-audit and Gitleaks for normal and failure cases, to ground the fault catalogue (F1–F10) |
| **4. Hypothesis** | Descriptive pilot; no hypothesis tested. Open question U21: does Gitleaks use the same exit code for errors and leaks? |
| **5. Environment** | GitHub-hosted `ubuntu-24.04`, Python 3.13.18; Semgrep 1.180.0, pip-audit 2.10.1, Gitleaks 8.30.1 (`results/environment.json`) |
| **6. Inputs** | 26 synthetic cases (10 controls, 16 failure cases) created at run time by `live_scanner_check.py`; fake tokens only, scrubbed from outputs |
| **7. Procedure** | Workflow run 44043396994 on branch `live-scanner-check` ran `live_scanner_check.py`, then engine v2 (S3, S0) and the Semester 7 engine on this repository |
| **8. Expected result** | Documented behaviour for the controls; unknown for the failure cases (that is what was measured) |
| **9. Actual result** | See `analysis.md` §1–2. Key points: Gitleaks on a non-git folder exits 0 with an empty report (silent pass); Gitleaks (default) and pip-audit use exit 1 for both findings and crashes; Semgrep does not report Python parse errors |
| **10. Raw measurements** | `results/summary.json` (per case: command, exit code, duration, parsed summary). Full raw outputs: branch `live-scanner-results`, commit `d1b0b90` |
| **11. Analysis** | `analysis.md` §3: changes to the fault catalogue (F8 revised, F9 output-level only, F10 confirmed) |
| **12. Conclusion** | The engine was updated (commit `5880cd8`): Gitleaks no-coverage detection from its log, tool error lines in reasons, pinned Semgrep rule packs. Recorded real outputs are replayed in `tests/test_live_outputs.py` |

**Reproduce:** `python live_scanner_check.py` on Linux with Gitleaks on PATH; it installs the pinned Semgrep and pip-audit in a private venv.

**Limitations:**
- Single run; no repetitions.
- The simulated network outage (PA09) did not work, probably because pip-audit served a cached result.
- The "clean" pip-audit control (`flask==3.0.3`) has known vulnerabilities.
