# EXP-01: pilot of the fault-injection experiment (protocol not frozen)

**Status:** pilot run done, 17 Nov 2026. These are **pilot results**, used to test the harness and the protocol. They are not the study's final results; the protocol freeze needs guide approval (target 6 Dec 2026). Decision: DEC-013.

| Field | Content |
|---|---|
| **1. Experiment ID** | EXP-01 (pilot) |
| **2. Research questions** | SRQ1 (do silent passes occur under exit-code-only gating?), SRQ2 (do evidence checks detect and classify them?), SRQ3 (cost: false blocks, lost true blocks, time), SRQ4 (are real findings kept under partial failure?) |
| **3. Objective** | Run the full strategy × fault matrix once at L1 (simulated) and L2 (real binaries), check the harness, metrics and archiving, and find protocol problems before the freeze |
| **4. Hypotheses** | H1: S0 has silent passes. H2: S3 removes them and classifies them correctly. H3: S3 adds no false blocks on clean code and keeps every true block. H4: evidence validation costs < 5% of run time (hypothesis, not an acceptance threshold, NFR-07) |
| **5. Environment** | GitHub-hosted `ubuntu-24.04` (image 20261111.127.1), Python 3.13.18; Semgrep 1.180.0, pip-audit 2.10.1, Gitleaks 8.30.1 (SHA-256 checked); engine 2.0.0.dev1 at commit `46fcaf5`; workflow `experiments.yml`, run [44083865707](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44083865707) |
| **6. Inputs** | L1: real outputs recorded in EXP-00 (`inputs/recorded/`); one clean pip-audit report is *derived* (vulnerabilities removed from the real flask 3.0.3 recording). L2: synthetic projects created at run time (clean code; `eval()` matched by a committed local Semgrep rule; `urllib3==1.26.5`; a GitHub-token-shaped string generated at run time and committed to a throwaway repository). No real credentials |
| **7. Procedure** | `harness.py` builds the cells, writes the expected category per fault **before** running (`protocol.json`), then runs every cell under S0, S1, S2 and S3. L1: 59 cells × 4 strategies × 2 repetitions = 472 runs, through the library with a replay runner. L2: 31 cells × 4 × 3 = 372 runs through the CLI as a subprocess; F1 by a missing executable path, F2–F7 by wrapper executables (crash, hang past a 3 s timeout, silent, `{}`, report cut at 50%), F8–F10 by real inputs (no Python files; not a git repository; empty requirements; a syntax error; a package not on PyPI; an invalid Gitleaks config). Probes for decision D2 and for Semgrep parse-error reporting ran in the same job |
| **8. Expected result** | Per `protocol.json`: S3 gives INCOMPLETE with the expected category for every fault; S0 lets through the faults it cannot see (F4–F9); no false blocks; all true blocks kept |
| **9. Actual result** | Below |
| **10. Raw measurements** | `results/run-44083865707/` (protocol, `runs.csv`, metrics, environment, summary, probes, schema check). Every manifest, report, policy and raw scanner output: `runs.tar.gz` per level on branch `semester8-completion-results`, folder `EXP-01/run-44083865707/` (commit `d38fd8b`). 844 manifests validated against schema 1.1 |
| **11. Analysis** | Below |
| **12. Conclusion** | Below |

## 9. Results

Rates over runs with Wilson 95% intervals. The cells are designed, not sampled, so the intervals describe this cell set only.

### L2: real binaries (headline for the pilot)

| Metric | S0 | S1 | S2 | S3 |
|---|---|---|---|---|
| SPR (silent passes on faulted runs, lower is better) | 0.481 (39/81) [0.376, 0.589] | 0.148 (12/81) [0.087, 0.241] | 0.037 (3/81) [0.013, 0.103] | 0.037 (3/81) [0.013, 0.103] |
| ICA (INCOMPLETE with the expected category) | 0 | 0 | 0 | 0.926 (75/81) [0.848, 0.966] |
| FBR (false blocks on clean code) | 0/3 | 0/3 | 0/3 | 0/3 |
| CBR (true findings blocked) | 9/9 | 9/9 | 9/9 | 9/9 |
| FPP (finding kept when another scanner fails) | 6/6 | 6/6 | 6/6 | 6/6 |
| Verdict consistency across 3 repetitions | 124/124 cell-strategy groups | | | |

### L1: simulated (replayed real outputs)

| Metric | S0 | S1 | S2 | S3 |
|---|---|---|---|---|
| SPR | 0.309 (34/110) | 0.109 (12/110) | 0 (0/110) | 0 (0/110) |
| ICA | 0 | 0 | 0 | 1.000 (110/110) |
| FBR / CBR / FPP | 0/2, 6/6, 48/48 for every strategy | | | |

The L1 results from CI are identical, run for run, to a local run of the same commit (deterministic replay).

### Timing (L2, clean and known-finding cells, 12 runs per strategy)

| Strategy | Wall time median [IQR] s | Scanner execution median s | Evidence validation median s | Validation share of the engine run |
|---|---|---|---|---|
| S0 | 6.71 [6.64, 6.76] | 5.20 | 0.00041 | 0.006% |
| S3 | 6.64 [6.60, 6.69] | 5.17 | 0.00038 | 0.006% |

Evidence validation is measured inside the engine, separately from scanner execution. Wall time includes Python start-up and the three `--version` calls.

### Probes

| Probe | Result |
|---|---|
| D2: `p/python` on this repository | exit 0; 28 files; 0 findings; 0 errors |
| D2: `p/github-actions` on this repository | exit 0; a real pack (11 YAML rules); 2 workflow files; **0 findings** (the 12 mutable-tag warnings from EXP-00 are gone because the actions are now pinned to SHAs); **2 `PartialParsing` errors** at `ci-security.yml` line 154, `${{ github.sha }}` inside `run:` |
| Semgrep syntax error, default / `--strict` / `--verbose` | all exit 0, 2 files scanned, no error, no skipped entry: the broken file is not reported by any flag |

## 11. Analysis

1. **H1 supported (pilot):** with real binaries, exit-code-only gating (S0) passed 39 of 81 faulted runs: missing, empty, schema-invalid and truncated reports, and every no-coverage case.
2. **H2 mostly supported:** S2 and S3 detected every fault except one. The 3 remaining silent passes are all the same cell, `L2-F9-semgrep`: Semgrep 1.180.0 does not report a file with a syntax error at all (also under `--strict` and `--verbose`), so no evidence check can see it. This is a scanner limit, not an engine defect, and it matches EXP-00 SG04.
3. **ICA 0.926 under S3:** the 6 misclassified runs are the F9 cells. Semgrep F9 passed (point 2). For pip-audit, a package missing from PyPI made the real tool fail (exit 1, empty stdout), so S3 said INCOMPLETE `NO_OUTPUT` rather than the expected `PARTIAL_COVERAGE`. The run was still stopped; only the label differs from the protocol's expectation. The F9 realisation for pip-audit must change before the freeze (e.g. a skip that pip-audit really reports).
4. **S1 versus S0:** S1 removed most report-level silent passes but not coverage faults. In L1, for "exit 1 but no vulnerabilities in the report" (pip-audit F10) S1 passed while S0 blocked (DEC-006). L2 had no realisation of that case.
5. **H3 supported for this small set:** no false blocks (0/3) and all true blocks kept (9/9) under every strategy; findings from a valid scanner were kept in all 6 partial-failure runs. The control set is small (wide intervals).
6. **H4:** evidence validation took about 0.4 ms per run, about 0.006% of engine run time, and S3's wall time was not higher than S0's. This is far below 5%. It measures the validation code only; the gating step itself (installing and running scanners) is the main cost.
7. **D2:** adding `p/github-actions` would make SecureGate report PARTIAL_COVERAGE on its own workflow (Semgrep cannot fully parse `${{ }}` inside `run:`), and so INCOMPLETE. The CI policy therefore stays `p/python` for now (DEC-009).

## 12. Conclusion

The harness, metrics, archiving and schema checks work end to end on real binaries. Before the protocol freeze: (a) change the pip-audit F9 realisation; (b) decide whether to keep Semgrep F9 as a documented scanner limit; (c) add real L2 realisations for F5 and F10 (Semgrep, pip-audit); (d) enlarge the clean and known-finding sets; (e) fix repetitions and the clean dependency (`six==1.17.0` had no known vulnerabilities on 17 Nov 2026).

**Workflow note:** in this run the scanners' virtual environment was first on `PATH`, so `python` in the workflow resolved to that environment. The engine needs only the standard library, so the harness ran normally (same Python 3.13.18), but the unit-test step found no pytest there and recorded nothing (`unit-tests.txt` is empty). Fixed afterwards: only the scanner commands are linked onto `PATH`, and the step uses `pipefail`.
