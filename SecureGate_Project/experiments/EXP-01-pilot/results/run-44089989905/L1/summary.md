# EXP-01 pilot results: L1

**Level:** SIMULATED (recorded outputs replayed; no scanner binary runs)  
**Status:** pilot, protocol not frozen. Not final study results.  
**Engine:** 2.0.0.dev1 at commit `059cbb9`; Python 3.13.18; Linux-7.0.0-1017-azure-x86_64-with-glibc2.39

Cells: 59; runs: 472. Rates with Wilson 95% intervals over runs (cells are not a random sample, so the intervals describe this cell set only).

| Metric | S0 | S1 | S2 | S3 |
|---|---|---|---|---|
| SPR | 0.309 (34/110) [0.230, 0.401] | 0.109 (12/110) [0.064, 0.181] | 0.000 (0/110) [0.000, 0.034] | 0.000 (0/110) [0.000, 0.034] |
| FDR | 0.691 (76/110) [0.599, 0.770] | 0.891 (98/110) [0.819, 0.936] | 1.000 (110/110) [0.966, 1.000] | 1.000 (110/110) [0.966, 1.000] |
| ICA | 0.000 (0/110) [0.000, 0.034] | 0.000 (0/110) [0.000, 0.034] | 0.000 (0/110) [0.000, 0.034] | 1.000 (110/110) [0.966, 1.000] |
| FBR | 0.000 (0/2) [0.000, 0.658] | 0.000 (0/2) [0.000, 0.658] | 0.000 (0/2) [0.000, 0.658] | 0.000 (0/2) [0.000, 0.658] |
| CBR | 1.000 (6/6) [0.610, 1.000] | 1.000 (6/6) [0.610, 1.000] | 1.000 (6/6) [0.610, 1.000] | 1.000 (6/6) [0.610, 1.000] |
| FPP | 1.000 (48/48) [0.926, 1.000] | 1.000 (48/48) [0.926, 1.000] | 1.000 (48/48) [0.926, 1.000] | 1.000 (48/48) [0.926, 1.000] |

Run-to-run verdict consistency: 1.000 (236/236) [0.984, 1.000]

## Verdict per cell

| Cell | Realisation | Expected (faulted scanner) | S0 | S1 | S2 | S3 |
|---|---|---|---|---|---|---|
| L1-C-clean | all three scanners: recorded clean outputs | PASS | PASS | PASS | PASS | PASS |
| L1-K-semgrep | recorded real finding (semgrep) | BLOCK | BLOCK | BLOCK | BLOCK | BLOCK |
| L1-K-pip-audit | recorded real finding (pip-audit) | BLOCK | BLOCK | BLOCK | BLOCK | BLOCK |
| L1-K-gitleaks | recorded real finding (gitleaks) | BLOCK | BLOCK | BLOCK | BLOCK | BLOCK |
| L1-F1-semgrep | launch error: executable not found | TOOL_MISSING | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | INCOMPLETE `TOOL_MISSING` |
| L1-F1-pip-audit | launch error: executable not found | TOOL_MISSING | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | INCOMPLETE `TOOL_MISSING` |
| L1-F1-gitleaks | launch error: executable not found | TOOL_MISSING | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | INCOMPLETE `TOOL_MISSING` |
| L1-F2-semgrep | exit 2, no report | NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L1-F2-pip-audit | exit 2, no report | NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L1-F2-gitleaks | exit 1, no report | NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L1-F3-semgrep | killed after the policy timeout | TIMEOUT | BLOCK `TIMEOUT` | BLOCK `TIMEOUT` | BLOCK `TIMEOUT` | INCOMPLETE `TIMEOUT` |
| L1-F3-pip-audit | killed after the policy timeout | TIMEOUT | BLOCK `TIMEOUT` | BLOCK `TIMEOUT` | BLOCK `TIMEOUT` | INCOMPLETE `TIMEOUT` |
| L1-F3-gitleaks | killed after the policy timeout | TIMEOUT | BLOCK `TIMEOUT` | BLOCK `TIMEOUT` | BLOCK `TIMEOUT` | INCOMPLETE `TIMEOUT` |
| L1-F4-semgrep | exit 0, report not written | NO_OUTPUT | PASS `VALID` | BLOCK `NO_OUTPUT` | BLOCK `NO_OUTPUT` | INCOMPLETE `NO_OUTPUT` |
| L1-F4-pip-audit | exit 0, report not written | NO_OUTPUT | PASS `VALID` | BLOCK `NO_OUTPUT` | BLOCK `NO_OUTPUT` | INCOMPLETE `NO_OUTPUT` |
| L1-F4-gitleaks | exit 0, report not written | NO_OUTPUT | PASS `VALID` | BLOCK `NO_OUTPUT` | BLOCK `NO_OUTPUT` | INCOMPLETE `NO_OUTPUT` |
| L1-F5-semgrep | exit 0, whitespace-only report | NO_OUTPUT | PASS `VALID` | BLOCK `NO_OUTPUT` | BLOCK `NO_OUTPUT` | INCOMPLETE `NO_OUTPUT` |
| L1-F5-pip-audit | exit 0, whitespace-only report | NO_OUTPUT | PASS `VALID` | BLOCK `NO_OUTPUT` | BLOCK `NO_OUTPUT` | INCOMPLETE `NO_OUTPUT` |
| L1-F5-gitleaks | exit 0, whitespace-only report | NO_OUTPUT | PASS `VALID` | BLOCK `NO_OUTPUT` | BLOCK `NO_OUTPUT` | INCOMPLETE `NO_OUTPUT` |
| L1-F6-semgrep | exit 0, report is {} | SCHEMA_INVALID | PASS `VALID` | BLOCK `SCHEMA_INVALID` | BLOCK `SCHEMA_INVALID` | INCOMPLETE `SCHEMA_INVALID` |
| L1-F6-pip-audit | exit 0, report is {} | SCHEMA_INVALID | PASS `VALID` | BLOCK `SCHEMA_INVALID` | BLOCK `SCHEMA_INVALID` | INCOMPLETE `SCHEMA_INVALID` |
| L1-F6-gitleaks | exit 0, report is {} | SCHEMA_INVALID | PASS `VALID` | BLOCK `SCHEMA_INVALID` | BLOCK `SCHEMA_INVALID` | INCOMPLETE `SCHEMA_INVALID` |
| L1-F7-semgrep | exit 0, report cut at 50% of bytes | INVALID_JSON | PASS `VALID` | BLOCK `INVALID_JSON` | BLOCK `INVALID_JSON` | INCOMPLETE `INVALID_JSON` |
| L1-F7-pip-audit | exit 0, report cut at 50% of bytes | INVALID_JSON | PASS `VALID` | BLOCK `INVALID_JSON` | BLOCK `INVALID_JSON` | INCOMPLETE `INVALID_JSON` |
| L1-F7-gitleaks | exit 0, report cut at 50% of bytes | INVALID_JSON | PASS `VALID` | BLOCK `INVALID_JSON` | BLOCK `INVALID_JSON` | INCOMPLETE `INVALID_JSON` |
| L1-F8-semgrep | recorded real SG06: paths.scanned empty | NO_COVERAGE | PASS `VALID` | PASS `VALID` | BLOCK `NO_COVERAGE` | INCOMPLETE `NO_COVERAGE` |
| L1-F8-pip-audit | dependencies list empty | NO_COVERAGE | PASS `VALID` | PASS `VALID` | BLOCK `NO_COVERAGE` | INCOMPLETE `NO_COVERAGE` |
| L1-F8-gitleaks | recorded real GL05: not a git repository, 0 commits scanned | NO_COVERAGE | PASS `VALID` | PASS `VALID` | BLOCK `NO_COVERAGE` | INCOMPLETE `NO_COVERAGE` |
| L1-F9-semgrep | paths.skipped holds an analysis failure | PARTIAL_COVERAGE | PASS `VALID` | PASS `VALID` | BLOCK `PARTIAL_COVERAGE` | INCOMPLETE `PARTIAL_COVERAGE` |
| L1-F9-pip-audit | one dependency has skip_reason | PARTIAL_COVERAGE | PASS `VALID` | PASS `VALID` | BLOCK `PARTIAL_COVERAGE` | INCOMPLETE `PARTIAL_COVERAGE` |
| L1-F10-semgrep | exit 1 (findings) but results empty | INCONSISTENT_EXIT/NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L1-F10-pip-audit | exit 1 (vulnerabilities) but none reported | INCONSISTENT_EXIT/NONZERO_EXIT | BLOCK `VALID` | PASS `VALID` | BLOCK `INCONSISTENT_EXIT` | INCOMPLETE `INCONSISTENT_EXIT` |
| L1-F10-gitleaks | exit 1 (Gitleaks error code; leak code is 3) with empty report | INCONSISTENT_EXIT/NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L1-F1-semgrep+K-pip-audit | launch error: executable not found | TOOL_MISSING | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | INCOMPLETE `TOOL_MISSING` |
| L1-F1-semgrep+K-gitleaks | launch error: executable not found | TOOL_MISSING | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | INCOMPLETE `TOOL_MISSING` |
| L1-F1-pip-audit+K-semgrep | launch error: executable not found | TOOL_MISSING | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | INCOMPLETE `TOOL_MISSING` |
| L1-F1-pip-audit+K-gitleaks | launch error: executable not found | TOOL_MISSING | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | INCOMPLETE `TOOL_MISSING` |
| L1-F1-gitleaks+K-semgrep | launch error: executable not found | TOOL_MISSING | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | INCOMPLETE `TOOL_MISSING` |
| L1-F1-gitleaks+K-pip-audit | launch error: executable not found | TOOL_MISSING | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | BLOCK `TOOL_MISSING` | INCOMPLETE `TOOL_MISSING` |
| L1-F2-semgrep+K-pip-audit | exit 2, no report | NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L1-F2-semgrep+K-gitleaks | exit 2, no report | NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L1-F2-pip-audit+K-semgrep | exit 2, no report | NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L1-F2-pip-audit+K-gitleaks | exit 2, no report | NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L1-F2-gitleaks+K-semgrep | exit 1, no report | NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L1-F2-gitleaks+K-pip-audit | exit 1, no report | NONZERO_EXIT | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | BLOCK `NONZERO_EXIT` | INCOMPLETE `NONZERO_EXIT` |
| L1-F6-semgrep+K-pip-audit | exit 0, report is {} | SCHEMA_INVALID | BLOCK `VALID` | BLOCK `SCHEMA_INVALID` | BLOCK `SCHEMA_INVALID` | INCOMPLETE `SCHEMA_INVALID` |
| L1-F6-semgrep+K-gitleaks | exit 0, report is {} | SCHEMA_INVALID | BLOCK `VALID` | BLOCK `SCHEMA_INVALID` | BLOCK `SCHEMA_INVALID` | INCOMPLETE `SCHEMA_INVALID` |
| L1-F6-pip-audit+K-semgrep | exit 0, report is {} | SCHEMA_INVALID | BLOCK `VALID` | BLOCK `SCHEMA_INVALID` | BLOCK `SCHEMA_INVALID` | INCOMPLETE `SCHEMA_INVALID` |
| L1-F6-pip-audit+K-gitleaks | exit 0, report is {} | SCHEMA_INVALID | BLOCK `VALID` | BLOCK `SCHEMA_INVALID` | BLOCK `SCHEMA_INVALID` | INCOMPLETE `SCHEMA_INVALID` |
| L1-F6-gitleaks+K-semgrep | exit 0, report is {} | SCHEMA_INVALID | BLOCK `VALID` | BLOCK `SCHEMA_INVALID` | BLOCK `SCHEMA_INVALID` | INCOMPLETE `SCHEMA_INVALID` |
| L1-F6-gitleaks+K-pip-audit | exit 0, report is {} | SCHEMA_INVALID | BLOCK `VALID` | BLOCK `SCHEMA_INVALID` | BLOCK `SCHEMA_INVALID` | INCOMPLETE `SCHEMA_INVALID` |
| L1-F8-semgrep+K-pip-audit | recorded real SG06: paths.scanned empty | NO_COVERAGE | BLOCK `VALID` | BLOCK `VALID` | BLOCK `NO_COVERAGE` | INCOMPLETE `NO_COVERAGE` |
| L1-F8-semgrep+K-gitleaks | recorded real SG06: paths.scanned empty | NO_COVERAGE | BLOCK `VALID` | BLOCK `VALID` | BLOCK `NO_COVERAGE` | INCOMPLETE `NO_COVERAGE` |
| L1-F8-pip-audit+K-semgrep | dependencies list empty | NO_COVERAGE | BLOCK `VALID` | BLOCK `VALID` | BLOCK `NO_COVERAGE` | INCOMPLETE `NO_COVERAGE` |
| L1-F8-pip-audit+K-gitleaks | dependencies list empty | NO_COVERAGE | BLOCK `VALID` | BLOCK `VALID` | BLOCK `NO_COVERAGE` | INCOMPLETE `NO_COVERAGE` |
| L1-F8-gitleaks+K-semgrep | recorded real GL05: not a git repository, 0 commits scanned | NO_COVERAGE | BLOCK `VALID` | BLOCK `VALID` | BLOCK `NO_COVERAGE` | INCOMPLETE `NO_COVERAGE` |
| L1-F8-gitleaks+K-pip-audit | recorded real GL05: not a git repository, 0 commits scanned | NO_COVERAGE | BLOCK `VALID` | BLOCK `VALID` | BLOCK `NO_COVERAGE` | INCOMPLETE `NO_COVERAGE` |
| L1-F1x2 | all listed scanners missing | TOOL_MISSING | BLOCK `TOOL_MISSING+TOOL_MISSING` | BLOCK `TOOL_MISSING+TOOL_MISSING` | BLOCK `TOOL_MISSING+TOOL_MISSING` | INCOMPLETE `TOOL_MISSING+TOOL_MISSING` |
| L1-F1x3 | all listed scanners missing | TOOL_MISSING | BLOCK `TOOL_MISSING+TOOL_MISSING+TOOL_MISSING` | BLOCK `TOOL_MISSING+TOOL_MISSING+TOOL_MISSING` | BLOCK `TOOL_MISSING+TOOL_MISSING+TOOL_MISSING` | INCOMPLETE `TOOL_MISSING+TOOL_MISSING+TOOL_MISSING` |

## Timing (clean and known-finding cells)

| Strategy | wall median s | scanner execution median s | evidence validation median s | validation share of run (median) |
|---|---|---|---|---|
| S0 | 0.0034 | 0.0 | 0.000143 | 0.143 |
| S1 | 0.00335 | 0.0 | 0.00012 | 0.12 |
| S2 | 0.0036 | 0.0 | 0.000121 | 0.1215 |
| S3 | 0.00365 | 0.0 | 0.000154 | 0.1125 |

Clean and known-finding cells only (fault cells end early or wait for timeouts). L1 replays outputs, so its execution time is not a real scanner time.
