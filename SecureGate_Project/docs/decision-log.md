# Decision Log

Record important technical, research and project decisions here.

## Entry template

### Decision ID
DEC-001

### Date
YYYY-MM-DD

### Decision
Describe the decision.

### Context
Why was the decision needed?

### Alternatives considered
- Alternative A
- Alternative B

### Decision rationale
Explain why the selected approach was chosen.

### Evidence
Link to relevant literature, experiment, issue or documentation.

### Consequences
What changes because of this decision?

### Revisit condition
When should this decision be reconsidered?

---

## DEC-001: Keep the Semester 7 engine unchanged beside engine v2
- **Date:** 2026-11-17
- **Decision:** Build the evidence-aware gate in new modules. Keep `SecurityValidationEngine` unchanged and runnable with `--legacy`.
- **Context:** The engine needed three-state verdicts and evidence checks. The study also needs a reference for the original behaviour.
- **Alternatives considered:** rewrite the old engine in place; delete it.
- **Decision rationale:** The 21 original tests stay valid unchanged, and the old behaviour remains available for comparison.
- **Evidence:** `docs/requirements/engine-requirements-v1.md` (NFR-06).
- **Consequences:** Two engines in the package until the end of the study.
- **Revisit condition:** After the paper's experiments are archived.

## DEC-002: Policy file in TOML
- **Date:** 2026-11-17
- **Decision:** `securegate.toml`, read with Python's built-in `tomllib`.
- **Context:** The requirements (FR-22) said YAML.
- **Alternatives considered:** YAML (needs PyYAML); JSON (no comments).
- **Decision rationale:** No extra dependency, and comments are allowed.
- **Evidence:** Python 3.11+ standard library.
- **Consequences:** FR-22 is implemented with TOML; requirements v2 should say so.
- **Revisit condition:** If users need YAML for consistency with their CI files.

## DEC-003: Exit code 3 for policy and usage errors
- **Date:** 2026-11-17
- **Decision:** 0 PASS, 1 BLOCK, 2 INCOMPLETE, **3** invalid policy or command line.
- **Context:** A configuration mistake must not look like INCOMPLETE (evidence failure).
- **Alternatives considered:** 0/1/2 only (Stage 9 design).
- **Decision rationale:** It keeps INCOMPLETE meaning "evidence failed". AWS Automated Security Helper uses a similar separation.
- **Evidence:** Requirements D1.
- **Consequences:** CI must treat exit 3 as a failure.
- **Revisit condition:** None expected.

## DEC-004: Pinned Semgrep rules; `--config auto` rejected
- **Date:** 2026-11-17
- **Decision:** The policy names one or more pinned rule packs; `auto` is refused.
- **Context:** In the live check (EXP-00), `auto` produced different rules from the pinned pack, including Python 3.6 compatibility noise that failed the old gate.
- **Alternatives considered:** keep `auto`; local rules only.
- **Decision rationale:** Reproducibility (NFR-05) and a stable rule set across experiment runs.
- **Evidence:** `experiments/EXP-00-live-scanner-check/analysis.md` §2.
- **Consequences:** Default `p/python`. Adding `p/github-actions` is pending (D2) to keep the workflow checks.
- **Revisit condition:** When the rule pack is chosen for the frozen protocol (6 Dec).

## DEC-005: Gitleaks with an explicit leak exit code, and coverage read from its log
- **Date:** 2026-11-17
- **Decision:** Run Gitleaks with `--exit-code 3` and `--redact`. Treat "not a git repository" or "0 commits scanned" in its log as NO_COVERAGE.
- **Context:** In EXP-00, Gitleaks used exit 1 for both leaks and errors, and passed silently on a non-git folder (exit 0, empty report).
- **Alternatives considered:** default exit code; `--no-git` mode everywhere.
- **Decision rationale:** Leaks and crashes become distinguishable, and the silent pass is caught.
- **Evidence:** EXP-00 cases GL02–GL07; `tests/test_live_outputs.py`.
- **Consequences:** CI must check out full history (`fetch-depth: 0`) for meaningful history scans.
- **Revisit condition:** If Gitleaks changes its exit codes or log messages (tests will catch it).

---

## Decisions from the completion work (branch `semester8-completion`, 17 Nov 2026)

DEC-002 to DEC-005 above were confirmed, not changed. Status: **accepted for development**. Items marked *pending guide approval* are decided for the pilot only and must be confirmed before the protocol freeze (target 6 Dec).

## DEC-006: Strategy semantics S0–S3 (FR-23 deviation)
- **Decision:** The checks per strategy are defined once, in `security_engine/adapters.py` (`STRATEGY_CHECKS`), and recorded in every manifest (`checks_applied`):

  | Strategy | Checks | Invalid evidence gives |
  |---|---|---|
  | S0 | execution, exit code | BLOCK |
  | S1 | + presence, JSON, schema | BLOCK |
  | S2 | + exit/report consistency, coverage | BLOCK |
  | S3 | same checks as S2 | **INCOMPLETE** |

- **Deviation from FR-23 v1:** FR-23 listed "presence" under S2. Presence moved to S1, because a schema check cannot run on a report that does not exist; S1 without presence would have to call a missing report "schema-invalid".
- **Consequence observed (EXP-01 L1):** for pip-audit exit 1 with a report listing no vulnerabilities (F10), S0 gives BLOCK (it trusts the exit code) but S1 gives PASS (it trusts the parsed report, and consistency is not checked until S2). S1 is therefore not uniformly safer than S0. This is a result to report, not a defect to hide.
- **Revisit:** at the protocol freeze, if the guide prefers presence in S2.

## DEC-007: Incomplete, partial and failed evidence in verdicts
- **Decision:** (1) Any required scanner with invalid evidence (any category in the taxonomy, including PARTIAL_COVERAGE) makes the run INCOMPLETE under S3 and BLOCK under S0–S2. (2) Findings from valid scanners are always kept and listed (BLOCKING_FINDING reasons) even when the verdict is INCOMPLETE. (3) Findings parsed from invalid evidence are kept but marked `from_incomplete_evidence`. (4) An optional scanner's failure is a note, not a reason. (5) `on_incomplete` = `block` (default, exit 2), `warn` (exit 0) or `review` (exit 2 + MANUAL_REVIEW note).
- **Rationale:** Partial coverage means part of the input was never checked, so security is not established (NFR-02: no path from invalid evidence to PASS).
- **Evidence:** `test_gate.py::test_partial_failure_keeps_real_findings`, `test_completion.py::test_two_failures_one_real_finding`; EXP-01 FPP.

## DEC-008: Semgrep rules: deliberate skips are not failures
- **Decision:** Semgrep `paths.skipped` is read. Skips caused by `analysis_failed_parser_or_internal_error`, `insufficient_permissions` or `nonexistent_file` count as PARTIAL_COVERAGE. Deliberate skips (ignore files, excluded paths, wrong language, size limits) are recorded in `coverage.files_skipped` only.
- **Known limit:** Semgrep 1.180.0 did not report a Python syntax error at all in EXP-00 (SG04). The engine cannot see what the tool does not report; EXP-01 probes `--strict` and `--verbose` for this.

## DEC-009: Semgrep rule packs, version pinning and rule updates (D2) — *pending guide approval*
- **Decision for development:** Semgrep, pip-audit and Gitleaks versions are pinned in CI and in the experiment workflow (1.180.0 / 2.10.1 / 8.30.1); the Gitleaks binary is checked against a recorded SHA-256; GitHub Actions are pinned to full commit SHAs. The CI policy keeps `p/python`; `p/github-actions` is evaluated by the EXP-01 probe before it is added.
- **Rule-update control:** registry packs are not content-hashed (Semgrep does not expose a pack version), so each manifest records the pack name, the Semgrep version and the run date. The **experiments use a committed local rule file** whose SHA-256 is recorded, so experiment runs do not depend on registry changes. Updating a version or pack = one reviewed commit that changes the pin, plus a CI run.
- **Alternatives:** `--config auto` (rejected, DEC-004); committed copies of registry packs (licence and maintenance cost).
- **Probe result (EXP-01, run 44083865707):** `p/github-actions` is a real pack (11 rules). On this repository it found nothing (actions are SHA-pinned) but raised 2 `PartialParsing` errors on `${{ github.sha }}` inside a `run:` line, which the engine correctly treats as PARTIAL_COVERAGE, so the gate would say INCOMPLETE on its own workflow. **CI keeps `p/python`.** Revisit if the workflow is rewritten to avoid expressions inside `run:` (pass them through `env:`), which is also the hardening the pack recommends.

## DEC-010: Run manifest schema 1.1 and output isolation
- **Decision:** The manifest has a JSON Schema (draft 2020-12, `security_engine/schemas/run_manifest.schema.json`), validated in unit tests, in CI and for every experiment manifest. Schema 1.1 adds `timings`, per-scanner `rule_sources`, `checks_applied` and `validation_s`. Raw scanner outputs go to `raw/<run_id>/` (new folder per run); stale reports are deleted before each run.
- **Rationale:** FR-07, FR-27, NFR-05; the experiments compare manifests across hundreds of runs.

## DEC-011: Synthetic secrets in tests, and `.gitleaksignore`
- **Decision:** Synthetic credential-like test values are built by string concatenation so no literal appears in scannable source. One literal from commit `41c10e7` remains in history (history is never rewritten), so its single fingerprint is in `.gitleaksignore`. The Gitleaks adapter records the ignore file's SHA-256 and entry count as a rule source, because it changes Gitleaks' results.
- **Rationale:** The gate scans its own repository history in CI; a synthetic value must not block it, and the exception must be visible and auditable.
- **Revisit:** Any new `.gitleaksignore` entry needs its own justification in that file.

## DEC-012: CI design
- **Decision:** `ci-security.yml` replaces the Semester 7 workflow on this branch: Tests → SecureGate → Docker build. The gate runs the CLI and its exit code decides the job (0 PASS; 1 BLOCK, 2 INCOMPLETE, 3 policy error all fail it), so the Docker build runs only after PASS. Permissions `contents: read`; `persist-credentials: false`; scanners in their own virtual environment; evidence uploaded with `if: always()`; the verdict is also written as a job annotation.
- **Deviation:** the Semester 7 jobs (semgrep-action, gitleaks-action) are removed; the gate now runs the scanners itself. `semgrep-action` is deprecated and needed a token.
- **Validation:** real runs on the `semester8-ci-validate-*` branches (see `docs/ci-integration.md`).

## DEC-013: EXP-01 pilot design — *pending guide approval*
- **Decision:** A pilot before the protocol freeze, at two levels kept in separate tables: L1 simulated (real EXP-00 outputs replayed with deterministic fault edits) and L2 real binaries (wrapper executables for F2–F7, real-induced faults for F8–F10). Expected categories are written in the harness before any run. Results are labelled "pilot" and added as new folders on `semester8-completion-results`.
- **Revisit:** at the freeze: cell set, repetitions, T-clean dependency, and whether F9/F10 stay.

## DEC-014: Verdict precedence under partial failure (21 Nov 2026)
- **Question:** when one required scanner fails and another confirms a blocking finding, should S3 return BLOCK (finding first) or INCOMPLETE (evidence first)?
- **Decision:** keep FR-20: INCOMPLETE (exit 2) takes precedence and lists every confirmed finding. Add FR-20a: `on_incomplete = "warn"` or `"review"` never relaxes such a run; it still exits 2, with a `FINDING_NOT_DOWNGRADED` note.
- **Why:** the scan really is incomplete (the failed scanner may hide more findings), and the closest industry tool, AWS Automated Security Helper, also checks for incomplete scans before findings by default. Both labels stop the job under the default policy; the only unsafe combination was `warn` + a confirmed finding, which FR-20a removes.
- **Effect on results:** none on EXP-01 (only `on_incomplete = "block"` was evaluated). The Review 1 deck showed "BLOCK precedence" as planned; that plan is replaced by this decision.

## DEC-015: Optional Semgrep parse check (21 Nov 2026)
- **Problem:** the only silent pass left under S3 in EXP-01 (L2-F9-semgrep): Semgrep 1.180.0 lists a file with a syntax error in `paths.scanned`, reports "Parsed lines ~100%" and no error, so no check that reads Semgrep's report can see it.
- **Decision:** add `scanners.semgrep.parse_check` (FR-14a), default `false`. When on, and the strategy includes coverage checks (S2/S3), each `.py` file in Semgrep's own `paths.scanned` is parsed with CPython (`ast.parse`); unparsable files give PARTIAL_COVERAGE. Only files Semgrep lists are checked, so Semgrep's ignore rules are respected, and paths outside the target are ignored.
- **Why optional:** it is an independent check, not scanner evidence, and CPython's grammar may differ from the target project's Python version (e.g. Python 2 files). Keeping it off by default leaves S0–S3 exactly as in EXP-01; EXP-02 measures it as an extra arm ("S3+P") so its benefit and its false-INCOMPLETE cost on real repositories are both reported.
- **Manifest:** schema 1.2 (`checks_applied` may include `parse_check`; coverage numbers `python_files_parse_checked`, `python_files_unparsable`).


## DEC-016: EXP-02 final-study design (21 Nov 2026) — *protocol pending guide approval*
- **Decision:** EXP-02 runs three levels kept in separate tables: L1 simulated (as EXP-01), L2 real binaries on 14 synthetic projects, and a new level R with five public Python projects pinned to a commit (read-only). 10 repetitions per cell and arm. Arms S0–S3 everywhere and S3P (S3 + FR-14a parse check) at L2 and R. Expected outcomes and ground truth are written in `protocol.json`; its SHA-256 goes into `FROZEN.sha256` after guide approval, and final runs refuse a different protocol.
- **pip-audit invocation:** `--no-deps --disable-pip` for every L2 and R run: pip-audit audits the pinned requirements exactly as written, without pip resolution or package builds. Reasons: (1) the EXP-01 F9 realisation failed because pip's resolver errors on a package that is not on PyPI instead of skipping it; (2) old pinned projects cannot be installed on Python 3.13 (source builds), which would turn every baseline into a resolver failure; (3) runs become faster and deterministic. Cost: transitive dependencies are not audited, which is stated as a limitation. The audit date is each run's start time (pip-audit queries PyPI live).
- **Why real projects:** the synthetic projects are minimal; R tests whether the fault detection and the parse check behave the same on realistic code, dependency sets and histories, and records how the unmodified projects are judged (observed, no ground truth).
- **Ethics:** public projects are fetched read-only on GitHub-hosted runners; Gitleaks runs with `--redact`; real findings are reported in aggregate only. This extends the Review 1 statement "own repositories only".
- **Revisit:** if the dry run shows a realisation does not behave as specified (e.g. pip-audit does not skip, a clean control has a new vulnerability), the cell is changed and the change recorded here **before** the freeze.
