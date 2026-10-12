# SecureGate Initial GitHub Issue Backlog

Create these as separate GitHub Issues. Suggested labels: `security`, `product`, `testing`, `experiment`, `documentation`, `research`.

## SG-001 — Establish reproducible Semester 7 baseline
**Labels:** testing, documentation

- Set up the project in a clean Python environment.
- Install requirements and run the existing tests.
- Record Python version, dependency versions, commands, test output, and any failures.
- Do not alter results to make the baseline look better.

**Acceptance criteria:** baseline test log and environment details are committed under `results/raw/` or `docs/audits/`.

## SG-002 — Model scanner health and incomplete validation
**Labels:** security, product, testing

- Represent each scanner's execution status and error information.
- Distinguish “no findings” from “scanner did not run” and “scanner failed.”
- Define when incomplete scans must block progression.

**Acceptance criteria:** tests cover success, missing executable, execution error, and invalid output.

## SG-003 — Design versioned policy configuration
**Labels:** security, product, research

- Specify schema for severity and finding-type actions such as `BLOCK`, `WARN`, and `IGNORE`.
- Validate unsupported severities/actions and define unknown-severity behavior.
- Include a policy version or stable identifier in every decision.

**Acceptance criteria:** documented schema and unit tests for valid/invalid policies; no unsupported novelty claim.

## SG-004 — Integrate the security engine into GitHub Actions
**Labels:** security, product, testing

- Make scanner outputs available to the custom engine in a consistent format.
- Run the policy evaluation after scans and before Docker build.
- Ensure the Docker job depends on the engine's decision.

**Acceptance criteria:** a blocking fixture prevents Docker build; a clean fixture permits it; scanner failure follows the documented fail-closed policy.

## SG-005 — Improve finding normalization and traceability
**Labels:** product, testing

- Review field mapping across Semgrep, pip-audit, and Gitleaks.
- Preserve scanner/source identity and source-specific identifiers where available.
- Handle missing/unknown severity without inventing values.

**Acceptance criteria:** fixtures and tests cover expected fields, missing fields, unknown severities, and duplicate-like findings.

## SG-006 — Define the experimental protocol
**Labels:** experiment, research, documentation

- Create controlled clean and vulnerable application cases.
- Define ground truth and test cases before running experiments.
- Record detection, policy-decision correctness, scan duration, total pipeline duration, and failures.
- Store raw data separately from processed summaries.

**Acceptance criteria:** a versioned protocol and machine-readable raw-results template are committed before the main experiment.

## SG-007 — Conduct literature and competitor analysis
**Labels:** research, documentation

- Review recent peer-reviewed work and official documentation for comparable products.
- Record source, date, method, capabilities, limitations, and relevance.
- Use findings to refine the research gap and research questions.

**Acceptance criteria:** evidence-backed comparison matrix and references; no claim that combining scanners alone is novel.

## Dependency order

Start with SG-001. SG-002 and SG-003 can be designed in parallel. Complete SG-004 after their contracts are agreed. SG-005 supports SG-002/SG-004. SG-006 and SG-007 should progress alongside implementation, not after it.
