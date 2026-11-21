# SecureGate engine: requirements specification (v1.1)

**Date:** 17 November 2026 · **Status:** v1.1, implemented on branch `semester8-completion`; still a draft for guide review (feeds SRS v1, milestone MS2, 6 Dec). Changes from v1 are listed in §7; requirement text is unchanged except where §7 says so.
**Scope:** the security engine, modules M2–M5 (orchestration, evidence validation, verdict and policy, reporting). Not in scope: GitHub Actions wiring (M1), job-summary styling (M6), dashboard (OBJ8), fault-injection harness (M7, except the hooks it needs).
**Sources:**
- the Stage 5 audit (code at `e7ca85b`, probes C0–C13c);
- Stage 8 (objectives, strategies S0–S3, faults F1–F10, metrics);
- Stage 9 (modules, exit codes);
- tool documentation (E81, E82).

**Priorities:**
- **Must:** needed for the experiments or to remove a silent pass.
- **Should:** needed for a usable gate.
- **Could:** useful if time allows.

---

## 1. Starting point (verified, `e7ca85b`)

| Area | Today | Problem it causes |
|---|---|---|
| Result model | `ScannerResult.status ∈ {SUCCESS, ERROR}` | No way to express "ran but evidence is unusable" |
| Verdict | `security_gate_passed = not blocking and scanner_errors == 0` | Binary; an error looks like a security block (C7, C8, C10–C12) |
| Semgrep adapter | `--config auto`, no timeout; `data.get("results", [])` | `{}` and parse errors pass silently (C1, C2) |
| pip-audit adapter | No `--strict`; `data.get("dependencies", [])` | `{}` and skipped dependencies pass silently (C5, C6) |
| Gitleaks adapter | Exit 0 and 1 both accepted; missing report → ERROR | Exit 1 with an empty report passes (C9, if exit 1 means error) |
| Severity | INFO/WARNING/ERROR mapped; unknown values ignored | EXPERIMENT and INVENTORY findings are counted but never block (C13a/b) |
| Findings on error | Dropped (`engine.py` L79–80) | A real finding is lost when the scanner also errors |
| Records | None | No tool versions, rules, timings or policy for reproducibility |

---

## 2. Functional requirements

### 2.1 Scanner execution (M2)

| ID | Requirement | Priority | Why | Acceptance test |
|---|---|---|---|---|
| FR-01 | All scanners run through one adapter interface. Each adapter takes the target and policy settings and returns a raw execution record | Must | Uniform handling; adding scanners later | Unit test: each adapter returns the same record type |
| FR-02 | Each scanner has a timeout, set in the policy (default per scanner). A timed-out scanner is killed and recorded as such | Must | No timeouts today; fault F3 | Fake scanner that sleeps past the timeout → record shows `TIMEOUT` within timeout + 5 s |
| FR-03 | For every run, record the exit code, stdout, stderr (size-capped), start and end time, and duration | Must | Evidence for validation and overhead metric | Unit test on a fake scanner |
| FR-04 | Record each tool's version (from `--version`) and the rule source: Semgrep config ID or file hash; pip-audit vulnerability service; Gitleaks config hash or "default" | Must | Reproducibility; manifest | Manifest contains all version and rule fields |
| FR-05 | Use pinned, explicit configuration instead of registry defaults: Semgrep with a pinned rule pack or local rules (not `--config auto`); Gitleaks with an explicit `--exit-code`, so leaks and errors get different codes | Must | Rule drift (E42, E15); C9 ambiguity | Commands in the manifest show the pinned config and explicit exit code |
| FR-06 | Detect a missing executable and a launch failure separately from a scanner error | Must | Faults F1; C11 | PATH without the tool → `TOOL_MISSING` |
| FR-07 | Delete any stale report file before each run, and write reports to a fresh per-run folder | Must | A stale report must never count as evidence | Pre-existing report + scanner that writes nothing → `NO_OUTPUT` |
| FR-08 | Scanners run independently: one scanner's failure never stops or changes the others | Must | Partial failure (SRQ4) | One scanner crashes → the other two still produce valid records |
| FR-09 | Never use `shell=True`; pass arguments as a list | Must | Security | Code check (lint rule) |

### 2.2 Evidence validation and normalisation (M3: research core)

| ID | Requirement | Priority | Why | Acceptance test |
|---|---|---|---|---|
| FR-10 | Check presence: the report or stdout exists and is not empty or whitespace | Must | F4, F5; C10 | Empty output → `NO_OUTPUT` |
| FR-11 | Check the JSON parses completely | Must | F7; C7 | Truncated JSON → `INVALID_JSON` |
| FR-12 | Check each tool's report against a minimal schema: required keys and types (Semgrep `results`, `errors`, `paths`; pip-audit `dependencies` list; Gitleaks top-level list) | Must | F6; C1, C5 | `{}` → `SCHEMA_INVALID` for Semgrep and pip-audit |
| FR-13 | Check that the exit code is consistent with the tool's documented meaning and the report content (e.g. exit 1 from Gitleaks with an empty findings list) | Must | F10; C9 | Gitleaks exit 1 + `[]` → `INCONSISTENT_EXIT` (exact rule confirmed by the live check) |
| FR-14 | Check coverage: Semgrep `errors[]` and `paths.scanned`/`skipped`; pip-audit `skip_reason`. No files scanned → `NO_COVERAGE`; some skipped → `PARTIAL_COVERAGE` | Must | F8, F9; C2, C6; E81, E82 | Semgrep parse error → `NO_COVERAGE` or `PARTIAL_COVERAGE`; pip-audit skip → `PARTIAL_COVERAGE` |
| FR-14a | **(v1.2)** Optional Semgrep parse check (`scanners.semgrep.parse_check`, default off; strategies S2/S3 only): every `.py` file that Semgrep lists in `paths.scanned` is parsed with CPython; a file that cannot be parsed gives PARTIAL_COVERAGE | Could | Semgrep recovers from syntax errors without reporting them (EXP-00 SG04, EXP-01 L2-F9-semgrep), so a broken file can count as scanned | Broken file listed as scanned + `parse_check = true` → PARTIAL_COVERAGE; off by default → no change |
| FR-15 | Assign each scanner exactly one evidence status (`VALID` or `INVALID`) and, if invalid, one primary failure category from the taxonomy (§4), plus details | Must | Diagnosability; INCOMPLETE accuracy metric | Every fault in the catalogue maps to its expected category |
| FR-16 | Normalise findings to one model: tool, rule ID, severity, file, line, title | Must | Aggregation | Existing adapter tests, updated |
| FR-17 | Unknown or unmapped severity values must not be ignored silently. Map them by a policy default (initially HIGH) and record that this happened | Must | C13a/b | EXPERIMENT and INVENTORY findings → mapped and reported, not dropped |
| FR-18 | Keep findings from a scanner with partial evidence (e.g. partial coverage) and mark them as coming from incomplete evidence | Must | SRQ4; today findings are dropped on error | Partial coverage + a real finding → finding still listed |

### 2.3 Verdict and policy (M4)

| ID | Requirement | Priority | Why | Acceptance test |
|---|---|---|---|---|
| FR-19 | Produce one of three verdicts: **PASS** (all required scanners valid, no blocking finding); **BLOCK** (all required scanners valid, at least one blocking finding); **INCOMPLETE** (any required scanner invalid) | Must | Core design | One unit test per verdict |
| FR-20 | INCOMPLETE takes precedence over BLOCK, and the verdict still lists every blocking finding from valid scanners | Must | Partial failure must not hide findings | Timeout + real finding → INCOMPLETE with the finding listed |
| FR-20a | **(v1.2)** `on_incomplete` never relaxes a run that has a confirmed blocking finding from a valid scanner: with `warn`, such a run still exits 2 and carries a `FINDING_NOT_DOWNGRADED` note | Must | A real finding must always stop the job, whatever the policy says about incomplete evidence | Timeout + real finding + `on_incomplete = "warn"` → INCOMPLETE, exit 2, finding listed |
| FR-21 | Every verdict carries reasons: a machine-readable code and a plain-language sentence (e.g. `SCHEMA_INVALID: Semgrep report has no 'results' key`) | Must | Transparency; job summary | Reasons present for every non-PASS verdict |
| FR-22 | Read a versioned policy file (YAML; **v1.1: TOML**, DEC-002), validated against a schema. It holds: policy version; required scanners; minimum blocking severity per scanner; timeouts; `on_incomplete` (`block` default; `warn`, `review` optional); strategy (S0–S3); suppressions with justification and expiry date | Must | "Policy-driven"; experiments vary the strategy | Valid policy loads; each invalid field is rejected with a clear message |
| FR-23 | Support the four handling strategies by policy only, with no other code path changes: S0 exit codes only; S1 + schema; S2 + presence, consistency and coverage (**v1.1: presence moves to S1**, DEC-006); S3 = S2 + INCOMPLETE routing. Under S0–S2, a detected fault yields BLOCK (fail-closed) | Must | Independent variable of the study | Same fault under S0–S3 gives the verdicts in the frozen protocol table |
| FR-24 | Expired suppressions stop applying, and the run reports that they expired | Should | Accountability | Suppression with a past expiry → finding counts again |
| FR-25 | Same evidence + same policy → same verdict (deterministic) | Must | Reproducibility | Re-running the decision on stored evidence gives an identical verdict |
| FR-26 | Any unexpected internal exception in the engine gives INCOMPLETE (`ENGINE_ERROR`), never PASS | Must | Fail-safe | Injected exception in a validator → INCOMPLETE |

### 2.4 Reporting and audit (M5)

| ID | Requirement | Priority | Why | Acceptance test |
|---|---|---|---|---|
| FR-27 | Write a run manifest (`run_manifest.json`) with: run ID; timestamps; target commit SHA; engine version; tool versions; rule and policy hashes; strategy; per-scanner execution record, evidence status, category and coverage counts; findings summary; verdict; reasons; durations | Must | Experiments (OBJ6); reproducibility | Manifest validates against its JSON Schema on every run |
| FR-28 | Write a human-readable report (Markdown) suitable for the GitHub Actions job summary: verdict, reason, per-scanner health, top findings | Should | M6; usability | Report renders for PASS, BLOCK and INCOMPLETE fixtures |
| FR-29 | Redact secret values in all outputs (keep rule ID, file and line only) | Must | Ethics; Gitleaks reports contain secrets | Synthetic secret never appears in the manifest, report or stdout |
| FR-30 | Store no personal data (no author names or e-mails) in the manifest | Must | Data minimisation | Manifest field check |

### 2.5 Command-line interface

| ID | Requirement | Priority | Why | Acceptance test |
|---|---|---|---|---|
| FR-31 | CLI options: `--target`, `--policy`, `--out` (output folder), `--strategy` (overrides the policy, for experiments) | Must | CI and experiment use | CLI tests |
| FR-32 | Exit codes: **0** PASS, **1** BLOCK, **2** INCOMPLETE. **Proposed addition: 3** for an invalid policy or invalid CLI usage, so a configuration mistake is not confused with INCOMPLETE (AWS ASH uses a similar separation) | Must | CI enforcement | One test per exit code |
| FR-33 | Print the verdict summary as JSON to stdout, for backward compatibility. Keep the key `security_gate_passed`, meaning true only on PASS | Should | Existing tests and tooling | Old consumers still parse the output |

### 2.6 Hooks for the experiments (M7 support)

| ID | Requirement | Priority | Why | Acceptance test |
|---|---|---|---|---|
| FR-34 | The process runner is injectable, so tests and the harness can replace a scanner's execution or output at the adapter boundary without changing engine logic | Must | Output-level fault injection (L1) | Harness injects `{}` without patching engine code |
| FR-35 | Engine behaviour is identical whether called from the CLI or from a test harness | Must | Validity of results | The same fixture gives the same manifest verdict both ways |

---

## 3. Non-functional requirements

| ID | Requirement | Measure |
|---|---|---|
| NFR-01 Compatibility | Python 3.13 on Linux (GitHub-hosted Ubuntu runners); scanners at pinned versions | CI runs on the pinned image |
| NFR-02 Reliability | Fail-safe: no path from an engine error or invalid evidence to PASS | Fault catalogue tests (every F1–F10 case non-PASS) |
| NFR-03 Security | No `shell=True`; runs as a non-root user in Docker; no secrets in logs; dependencies pinned | Lint check; Dockerfile check; redaction test |
| NFR-04 Maintainability | Type hints; one module per concern (adapters, validators, policy, verdict, reporting); each requirement covered by ≥ 1 test | Traceability table (§5) complete |
| NFR-05 Reproducibility | Versions, rules, policy and commit recorded per run; deterministic decision | FR-25 and FR-27 tests |
| NFR-06 Backward compatibility | The existing 21 tests pass. A test that asserts old *defective* behaviour (e.g. treating an error the same as a block) is updated with a written justification, not deleted silently | Test log with justifications |
| NFR-07 Performance | Evidence validation time is measured and reported per run. H4 (< 5% overhead) is a hypothesis to test, **not** an acceptance threshold | Durations in the manifest |

---

## 4. Failure taxonomy (evidence categories)

| Category | Meaning | Typical fault | Today |
|---|---|---|---|
| `TOOL_MISSING` | Executable not found | F1 | ERROR (C11) |
| `LAUNCH_ERROR` | Could not start (permissions, OS error) | F1 variant | ERROR |
| `TIMEOUT` | Exceeded the policy timeout | F3 | Hangs |
| `NONZERO_EXIT` | Exit code outside the tool's documented success codes | F2 | ERROR (C8) |
| `NO_OUTPUT` | Report or stdout missing or empty | F4, F5 | ERROR (C10) |
| `INVALID_JSON` | Output does not parse | F7 | ERROR (C7) |
| `SCHEMA_INVALID` | Parses but lacks required structure | F6 | **Silent PASS (C1, C5)** |
| `INCONSISTENT_EXIT` | Exit code contradicts report content | F10 | **Silent PASS (C9, conditional)** |
| `NO_COVERAGE` | Ran but scanned nothing | F8 | **Silent PASS (C2)** |
| `PARTIAL_COVERAGE` | Ran but skipped part of the input | F9 | **Silent PASS (C6)** |
| `ENGINE_ERROR` | Unexpected internal exception | (FR-26) | — |

**Change from Stage 8:** `INCONSISTENT_EXIT` and `ENGINE_ERROR` are added. Stage 8 mapped F10 to "`NONZERO_EXIT` / inconsistent"; a separate category makes the INCOMPLETE classification accuracy metric clearer. Logged here for the SRS.

---

## 5. Traceability

| Requirement group | Module | Objective | Closes probe / fault | RQ |
|---|---|---|---|---|
| FR-01–FR-09 | M2 | OBJ2, OBJ4 | F1, F2, F3; C8, C11 | SRQ1, SRQ3 |
| FR-10–FR-18 | M3 | OBJ2–OBJ4 | F4–F10; C1, C2, C5, C6, C7, C9, C10, C13a/b | SRQ1, SRQ2, SRQ4 |
| FR-19–FR-26 | M4 | OBJ3, OBJ4 | All (verdict level); C12 | SRQ2, SRQ4 |
| FR-27–FR-30 | M5 | OBJ4–OBJ6 | — | All (data) |
| FR-31–FR-33 | CLI | OBJ5 | — | — |
| FR-34–FR-35 | M7 hooks | OBJ6 | L1 injection | All |

**Engine acceptance (OBJ4):**
1. All 7 silent-pass probes now give INCOMPLETE under S3 with the correct category.
2. The 5 fail-closed probes give INCOMPLETE (not BLOCK) under S3.
3. The 4 correct probes are unchanged.
4. The existing tests pass, or are updated with justification.

---

## 6. Decisions needed before coding

| # | Decision | Recommendation |
|---|---|---|
| D1 | Add exit code 3 for configuration and usage errors (FR-32)? | Yes. It is a small change from Stage 9 (0/1/2), and it keeps INCOMPLETE meaning "evidence failed" only |
| D2 | Semgrep rules: a pinned registry pack (e.g. `p/python` at a fixed version) or committed local rules? | Pinned pack for realism, cached for reproducibility; confirm after the live check |
| D3 | Default for unknown severities (FR-17) | HIGH (fail-safe), reported as a mapping |
| D4 | Does MEDIUM (Semgrep WARNING) block? | Keep HIGH as the default threshold (current behaviour), now written in the policy |
| D5 | Gitleaks command: `detect` (current, older syntax) or `git` / `dir` (newer)? | Decide from the live check output |
| D6 | pip-audit `--strict`? | No: detect `skip_reason` in validation instead, so S0–S3 can be compared on the same raw output |

Inputs still pending: the **live scanner check** (confirms FR-13 and FR-14 details, D2 and D5).

---

## 7. Change log

### v1.1 (17 Nov 2026, branch `semester8-completion`)

| Item | Change | Why | Record |
|---|---|---|---|
| FR-22 | Policy format TOML instead of YAML | Standard library parser (`tomllib`), comments allowed | DEC-002 |
| FR-23 | Presence check moves from S2 to S1 | A schema check needs a report to exist | DEC-006 |
| FR-32 | Exit code 3 for policy and usage errors | Keeps INCOMPLETE meaning "evidence failed" | DEC-003 (D1) |
| FR-05 | Semgrep accepts a list of pinned packs; `auto` rejected | Reproducibility | DEC-004, DEC-009 |
| FR-04 | Rule sources also include `.gitleaksignore` (hash and entry count) | It changes Gitleaks' results | DEC-011 |
| FR-14 | Semgrep skipped files classified: analysis failures are PARTIAL_COVERAGE, deliberate skips are recorded only | Avoid false INCOMPLETE on intended exclusions | DEC-008 |
| FR-27 | Manifest schema 1.1 with a JSON Schema file | Machine-checkable manifests | DEC-010 |
| NFR-07 | Execution, evidence-validation and decision time recorded separately | Overhead analysis (H4) | DEC-010 |
| §6 D2 | Still open for the frozen protocol; development default `p/python`, experiments use local rules | Needs the EXP-01 probe and guide approval | DEC-009 |
| §6 D5 | Gitleaks keeps `detect --source` (works on 8.30.1; recorded in every manifest) | Live check showed it works; `git`/`dir` subcommands can replace it later without changing evidence handling | EXP-00 |

### v1.2 (21 Nov 2026, branch `semester8-final`)

| Item | Change | Why | Record |
|---|---|---|---|
| FR-20a | New: `on_incomplete` cannot relax a run with a confirmed finding from a valid scanner | Closes the case where `warn` turned "real secret + timeout" into a passing job; FR-20 (INCOMPLETE first) is kept | DEC-014 |
| FR-14a | New, optional: Semgrep parse check | Targets the only residual silent pass in EXP-01; off by default so S0–S3 keep their EXP-01 meaning | DEC-015 |
| FR-27 | Manifest schema 1.2: `checks_applied` may include `parse_check` | Records when the optional check ran | DEC-015 |

No requirement was removed. Every requirement maps to tests in `tests/traceability.py`; the generated matrix is `docs/traceability-matrix.md`.

