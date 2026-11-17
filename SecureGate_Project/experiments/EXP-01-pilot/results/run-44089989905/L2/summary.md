# EXP-01 pilot results: L2

**Level:** REAL BINARIES (pinned Semgrep, pip-audit, Gitleaks via the CLI)  
**Status:** pilot, protocol not frozen. Not final study results.  
**Engine:** 2.0.0.dev1 at commit `059cbb9`; Python 3.13.18; Linux-7.0.0-1017-azure-x86_64-with-glibc2.39

Scanners: 1.180.0 / pip-audit 2.10.1 / Gitleaks 8.30.1; GitHub run 44089989905

Cells: 31; runs: 372. Rates with Wilson 95% intervals over runs (cells are not a random sample, so the intervals describe this cell set only).

| Metric | S0 | S1 | S2 | S3 |
|---|---|---|---|---|
| SPR | 0.481 (39/81) [0.376, 0.589] | 0.148 (12/81) [0.087, 0.241] | 0.037 (3/81) [0.013, 0.103] | 0.037 (3/81) [0.013, 0.103] |
| FDR | 0.518 (42/81) [0.411, 0.624] | 0.852 (69/81) [0.759, 0.913] | 0.963 (78/81) [0.897, 0.987] | 0.963 (78/81) [0.897, 0.987] |
| ICA | 0.000 (0/81) [0.000, 0.045] | 0.000 (0/81) [0.000, 0.045] | 0.000 (0/81) [0.000, 0.045] | 0.926 (75/81) [0.848, 0.966] |
| FBR | 0.000 (0/3) [0.000, 0.561] | 0.000 (0/3) [0.000, 0.561] | 0.000 (0/3) [0.000, 0.561] | 0.000 (0/3) [0.000, 0.561] |
| CBR | 1.000 (9/9) [0.701, 1.000] | 1.000 (9/9) [0.701, 1.000] | 1.000 (9/9) [0.701, 1.000] | 1.000 (9/9) [0.701, 1.000] |
| FPP | 1.000 (6/6) [0.610, 1.000] | 1.000 (6/6) [0.610, 1.000] | 1.000 (6/6) [0.610, 1.000] | 1.000 (6/6) [0.610, 1.000] |

Run-to-run verdict consistency: 1.000 (124/124) [0.970, 1.000]

## Verdict per cell

| Cell | Realisation | Expected (faulted scanner) | S0 | S1 | S2 | S3 |
|---|---|---|---|---|---|---|
| L2-C-clean | real tools, clean synthetic project | PASS | PASS | PASS | PASS | PASS |
| L2-K-semgrep | eval() matched by the local probe rule | BLOCK | BLOCK | BLOCK | BLOCK | BLOCK |
| L2-K-pip-audit | urllib3==1.26.5 (known vulnerabilities) | BLOCK | BLOCK | BLOCK | BLOCK | BLOCK |
| L2-K-gitleaks | synthetic GitHub token generated at run time, committed | BLOCK | BLOCK | BLOCK | BLOCK | BLOCK |
| L2-F2-semgrep | L2 wrapper executable (crash) | NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L2-F2-pip-audit | L2 wrapper executable (crash) | NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L2-F2-gitleaks | L2 wrapper executable (crash) | NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L2-F3-semgrep | L2 wrapper executable (hang) | TIMEOUT | BLOCK `TIMEOUT` | BLOCK `TIMEOUT` | BLOCK `TIMEOUT` | INCOMPLETE `TIMEOUT` |
| L2-F3-pip-audit | L2 wrapper executable (hang) | TIMEOUT | BLOCK `TIMEOUT` | BLOCK `TIMEOUT` | BLOCK `TIMEOUT` | INCOMPLETE `TIMEOUT` |
| L2-F3-gitleaks | L2 wrapper executable (hang) | TIMEOUT | BLOCK `TIMEOUT` | BLOCK `TIMEOUT` | BLOCK `TIMEOUT` | INCOMPLETE `TIMEOUT` |
| L2-F4-semgrep | L2 wrapper executable (silent) | NO_OUTPUT | PASS `VALID` | BLOCK `NO_OUTPUT` | BLOCK `NO_OUTPUT` | INCOMPLETE `NO_OUTPUT` |
| L2-F4-pip-audit | L2 wrapper executable (silent) | NO_OUTPUT | PASS `VALID` | BLOCK `NO_OUTPUT` | BLOCK `NO_OUTPUT` | INCOMPLETE `NO_OUTPUT` |
| L2-F4-gitleaks | L2 wrapper executable (silent) | NO_OUTPUT | PASS `VALID` | BLOCK `NO_OUTPUT` | BLOCK `NO_OUTPUT` | INCOMPLETE `NO_OUTPUT` |
| L2-F6-semgrep | L2 wrapper executable (schema) | SCHEMA_INVALID | PASS `VALID` | BLOCK `SCHEMA_INVALID` | BLOCK `SCHEMA_INVALID` | INCOMPLETE `SCHEMA_INVALID` |
| L2-F6-pip-audit | L2 wrapper executable (schema) | SCHEMA_INVALID | PASS `VALID` | BLOCK `SCHEMA_INVALID` | BLOCK `SCHEMA_INVALID` | INCOMPLETE `SCHEMA_INVALID` |
| L2-F6-gitleaks | L2 wrapper executable (schema) | SCHEMA_INVALID | PASS `VALID` | BLOCK `SCHEMA_INVALID` | BLOCK `SCHEMA_INVALID` | INCOMPLETE `SCHEMA_INVALID` |
| L2-F7-semgrep | L2 wrapper executable (truncate) | INVALID_JSON | PASS `VALID` | BLOCK `INVALID_JSON` | BLOCK `INVALID_JSON` | INCOMPLETE `INVALID_JSON` |
| L2-F7-pip-audit | L2 wrapper executable (truncate) | INVALID_JSON | PASS `VALID` | BLOCK `INVALID_JSON` | BLOCK `INVALID_JSON` | INCOMPLETE `INVALID_JSON` |
| L2-F7-gitleaks | L2 wrapper executable (truncate) | INVALID_JSON | PASS `VALID` | BLOCK `INVALID_JSON` | BLOCK `INVALID_JSON` | INCOMPLETE `INVALID_JSON` |
| L2-F1-semgrep | L2 executable path does not exist | TOOL_MISSING | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | INCOMPLETE `TOOL_MISSING` |
| L2-F1-pip-audit | L2 executable path does not exist | TOOL_MISSING | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | INCOMPLETE `TOOL_MISSING` |
| L2-F1-gitleaks | L2 executable path does not exist | TOOL_MISSING | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | INCOMPLETE `TOOL_MISSING` |
| L2-F8-semgrep | L3 project with no Python files | NO_COVERAGE | PASS `VALID` | PASS `VALID` | BLOCK `NO_COVERAGE` | INCOMPLETE `NO_COVERAGE` |
| L2-F8-gitleaks | L3 folder is not a git repository (holds a synthetic token) | NO_COVERAGE | PASS `VALID` | PASS `VALID` | BLOCK `NO_COVERAGE` | INCOMPLETE `NO_COVERAGE` |
| L2-F8-pip-audit | L3 empty requirements file | NO_COVERAGE | PASS `VALID` | PASS `VALID` | BLOCK `NO_COVERAGE` | INCOMPLETE `NO_COVERAGE` |
| L2-F9-semgrep | L3 one file with a syntax error | PARTIAL_COVERAGE | PASS `VALID` | PASS `VALID` | PASS `VALID` | PASS `VALID` |
| L2-F9-pip-audit | L3 requirement that does not exist on PyPI | PARTIAL_COVERAGE | BLOCK `VALID` | BLOCK `NO_OUTPUT` | BLOCK `NO_OUTPUT` | INCOMPLETE `NO_OUTPUT` |
| L2-F10-gitleaks | L3 invalid Gitleaks config (exit 1 = error code, leak code is 3) | INCONSISTENT_EXIT/NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L2-F1-semgrep+K-pip-audit | Semgrep missing while pip-audit finds urllib3 vulnerabilities | TOOL_MISSING | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | INCOMPLETE `TOOL_MISSING` |
| L2-F2-pip-audit+K-semgrep | pip-audit crashes while Semgrep finds eval() | NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L2-F1x3 | all scanners missing | TOOL_MISSING | BLOCK `TOOL_MISSING+TOOL_MISSING+TOOL_MISSING` | BLOCK `TOOL_MISSING+TOOL_MISSING+TOOL_MISSING` | BLOCK `TOOL_MISSING+TOOL_MISSING+TOOL_MISSING` | INCOMPLETE `TOOL_MISSING+TOOL_MISSING+TOOL_MISSING` |

## Timing (clean and known-finding cells)

| Strategy | wall median s | scanner execution median s | evidence validation median s | validation share of run (median) |
|---|---|---|---|---|
| S0 | 10.09685 | 7.919 | 0.000472 | 4.7e-05 |
| S1 | 9.98105 | 7.8055 | 0.000434 | 4.4e-05 |
| S2 | 10.1148 | 7.883 | 0.000447 | 4.4e-05 |
| S3 | 10.1101 | 7.8925 | 0.000441 | 4.3e-05 |

Clean and known-finding cells only (fault cells end early or wait for timeouts). L1 replays outputs, so its execution time is not a real scanner time.
