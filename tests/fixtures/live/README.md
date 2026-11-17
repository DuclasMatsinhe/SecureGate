# Real scanner outputs (live check, 17 Nov 2026)

These files were recorded from real tool runs on a GitHub-hosted runner (`ubuntu-24.04`, Python 3.13.18):

| Tool | Version |
|---|---|
| Semgrep | 1.180.0 |
| pip-audit | 2.10.1 |
| Gitleaks | 8.30.1 |

- **Source:** workflow run 44043396994, branch `live-scanner-results`.
- **Inputs:** synthetic only. Fake tokens were scrubbed to `<REDACTED_SYNTHETIC_TOKEN>`.

| File | Case | What the real tool did |
|---|---|---|
| semgrep_finding.json | SG02 | exit 0, 1 result |
| semgrep_no_files.json | SG06 | exit 0, `paths.scanned` empty |
| semgrep_bad_config_exit7.json | SG07 | exit 7, valid JSON with `errors[]` |
| pip_audit_vulnerable.json | PA02 | exit 1, urllib3 1.26.5 with 18 vulnerabilities |
| pip_audit_unknown_package.stderr | PA03 | exit 1, **empty stdout** (same exit code as "vulnerabilities found") |
| gitleaks_leak_report.json | GL02 | exit 1 by default (3 with `--exit-code 3`), 1 finding |
| gitleaks_not_a_repo.stderr | GL05 | **exit 0, empty report, 0 commits scanned**: silent pass |
| gitleaks_bad_config.stderr | GL04 | exit 1, no report (same as a leak with default settings) |
