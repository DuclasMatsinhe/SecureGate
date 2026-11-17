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
