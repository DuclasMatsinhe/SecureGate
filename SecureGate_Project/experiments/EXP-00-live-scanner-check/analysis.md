# Live scanner check: results and consequences (17 Nov 2026)

## Run details

| Item | Value |
|---|---|
| Where | GitHub-hosted runner `ubuntu-24.04`, Python 3.13.18 |
| Workflow | Run 44043396994; branch `live-scanner-check` (commit `b4bc961`); results on branch `live-scanner-results` (commit `d1b0b90`) |
| Tools | Semgrep 1.180.0 · pip-audit 2.10.1 · Gitleaks 8.30.1 (all pinned versions installed as requested) |
| Inputs | 26 synthetic cases (10 controls, 16 failure cases), plus engine v2 (strategies S3 and S0) and the Semester 7 engine run on the SecureGate repository |
| Safety | Synthetic inputs only; fake tokens scrubbed; no secrets in the published results (verified) |

This closes Stage 5.1 open items 3 to 5 (live Semgrep, pip-audit and Gitleaks behaviour) and U21 (Gitleaks error exit code).

## 1. What the real tools did

### Semgrep 1.180.0

| Case | Exit | Report | Meaning |
|---|---|---|---|
| SG01 clean | 0 | valid, 0 results | Control as expected |
| SG02 finding | 0 | 1 result | **Findings do not change the exit code** (documented behaviour confirmed) |
| SG03 finding + `--error` | 1 | 1 result | As documented |
| **SG04 syntax error in one file** | **0** | 0 results, **0 errors**, the broken file listed as *scanned* | **The parse failure is invisible in the report.** This is a silent coverage gap that no report-based check can detect |
| SG05 syntax error + real finding | 0 | the finding in the other file is still reported | The finding is preserved, but the gap stays invisible |
| SG06 nothing to scan | 0 | `paths.scanned` = [] | Detectable (`NO_COVERAGE`) |
| SG07 invalid rules file | **7** | valid JSON with `errors[]` | Detectable (`NONZERO_EXIT`) |
| SG08 missing target | **2** | valid JSON with `errors[]` | Detectable |
| SG09 SecureGate's old command (`--config auto`) | 0 | 1 result | Works; it pulls registry rules that change over time |

### pip-audit 2.10.1

| Case | Exit | Report | Meaning |
|---|---|---|---|
| PA01 "clean" `flask==3.0.3` | 1 | 2 vulnerabilities | **Our clean control is not clean.** T-clean must use current versions, fixed at protocol freeze |
| PA02 `urllib3==1.26.5` | 1 | 18 vulnerabilities | Known-finding control works |
| PA03–PA06 unknown package (with or without `--no-deps`, `--strict`) | **1** | **empty stdout** | **Fatal error with the same exit code as "vulnerabilities found".** No `skip_reason` |
| PA07 malformed line, PA08 missing file | 1 | empty stdout | Same ambiguity |
| PA09 simulated network outage | 1 | 18 vulnerabilities | **Simulation invalid**: the result was served anyway (probably from cache). An outage needs another method |

### Gitleaks 8.30.1

| Case | Exit | Report | Meaning |
|---|---|---|---|
| GL01 clean repository | 0 | `[]` | Control as expected |
| GL02 synthetic token | **1** | 1 finding (`github-pat`) | Default leak exit code is 1 |
| GL03 `--exit-code 3` | 3 | 1 finding | An explicit exit code separates leaks from errors |
| GL04 invalid config | **1** | none | **Error exit = default leak exit (1). U21 confirmed** |
| **GL05 `detect` on a folder without git history** | **0** | **`[]`**, log says "not a git repository … 0 commits scanned" | **Silent pass**: a secret in the folder is never examined. Only the log shows it |
| GL06 missing source, GL07 unwritable report path | 1 | none | Same exit code as a leak |
| GL08 `--no-git` on the same folder | 1 | 1 finding | Directory mode does scan it |

## 2. Real engine runs on the SecureGate repository

| Engine | Rules | Verdict | Why |
|---|---|---|---|
| v2, S3 (`p/python`) | Python only | PASS (exit 0) | 23 files scanned; 11 dependencies audited; no leaks |
| v2, S0 | same | PASS | — |
| Semester 7 engine | `--config auto` | **FAIL** (exit 1) | 15 Semgrep findings: 12 MEDIUM "mutable action tag" in the workflows (**real hardening issues**); 1 HIGH curl-pipe in the temporary live-check workflow; **2 HIGH Python 3.6 compatibility warnings** on modern code, which are noise. The noise alone was enough to fail the gate |

Neither rule set flags `semgrep_test.py`: the SQL string is built but never executed, so there is no sink.

## 3. Consequences for the fault catalogue (Stage 8 §6.6)

| Fault | Before | After the live check |
|---|---|---|
| F8 no coverage | Semgrep internal/parse error → `errors[]` | **Revised.** Semgrep 1.180.0 does not report Python parse errors at all, so this exact trigger is **undetectable** from the report. Real, detectable no-coverage triggers: Semgrep with nothing to scan (SG06), and **Gitleaks on a non-git folder (GL05, detectable only from the log)**. The invisible Semgrep parse gap becomes a **reported limitation**, and itself a finding |
| F9 partial coverage | pip-audit `skip_reason` | **Not reproducible** with `-r` requirements files: unknown packages crash instead of being skipped. F9 stays an **output-level (L1)** fault, justified by the documentation (E82), with this limitation stated |
| F10 ambiguous exit | Conditional | **Confirmed real for two tools:** Gitleaks (default leak code 1 = error code 1) and pip-audit (vulnerabilities and fatal errors both exit 1). **F10 is now included** |
| Network outage (excluded) | Optional | Remains excluded: the proxy simulation did not work |

**New observation for the paper (RQ1).** An exit-code-only gate (S0) handles these real ambiguities by accident: pip-audit's crash and Gitleaks' config error both *look like findings*, so S0 blocks them. That is "fail closed for the wrong reason": the developer is told to fix code that is not at fault. And S0 *passes* the Gitleaks non-repository case outright. This is exactly the silent-pass versus misattributed-block distinction the study measures.

## 4. Engine changes made from this evidence (commit `5880cd8`, branch `semester8-engine`)

- **Gitleaks coverage from its log:** "not a git repository" or "0 commits scanned" gives `NO_COVERAGE`. Commits scanned are recorded.
- **Failure reasons quote the tool's own error line,** e.g. "No matching distribution found", rather than a dump of its internal command.
- **Semgrep accepts several pinned rule packs; `auto` is rejected.**
- **Tests:** 14 new tests replay the recorded real outputs. Total: **106 passing**.

## 5. Decisions now open

| # | Decision | Recommendation |
|---|---|---|
| D2 | Semgrep rule packs | `["p/python", "p/github-actions"]`, to keep the workflow checks that `auto` provided without its noise. Verify the pack name in one run before adopting it |
| D5 | Gitleaks mode | Keep `detect` (git history) in CI with `fetch-depth: 0`. The engine now flags the no-repository case. Consider `--no-git` for the experiment fixtures that are not git repositories |
| New | Fix the 12 mutable action tags | Pin actions by commit SHA when the CI gate is wired (milestone MS4), as planned for supply-chain safety (P27) |
| New | Temporary branches | Delete `live-scanner-check` and `live-scanner-results` after review. They are not for merging, and the results branch also holds an 8 MB Gitleaks download committed by mistake |

## 6. Slide and protocol updates

- **Review 1 slide 5 ("Defaults" card)** can now cite **observed** behaviour: "Live check: Gitleaks scans a non-git folder, finds nothing and exits 0; pip-audit and Gitleaks use exit 1 for both findings and crashes."
- **Backup fault table:** F10 becomes "Confirmed (live)", and F8 is revised as above.
- **Protocol (due 6 Dec):** choose T-clean dependency versions with no known vulnerabilities on the freeze date.
