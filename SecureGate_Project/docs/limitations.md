# Limitations

What SecureGate and its current evidence do **not** show. Each item says where it comes from.
Updated 23 Nov 2026 (EXP-02 final run 44892918564; EXP-03 pre-registered, not yet run).

## Engine

1. **The engine sees mostly what the scanner reports.** Semgrep 1.180.0 lists a Python file with a syntax error as scanned and reports no error, even with `--strict` and `--verbose` (EXP-00 SG04, EXP-01 F9). Under S2/S3 this was the only fault left that passed (EXP-02 L2: 1 of 37 fault cells). The optional parse check (FR-14a, DEC-015, arm S3P) closes it (0 of 37), but it is an independent check, not scanner evidence: CPython's grammar may differ from the project's, so a Python 2 file in a real project gives INCOMPLETE (EXP-02 R: discover-flask). It is off by default.
2. **pip-audit uses one exit code (1) for "vulnerabilities found" and for crashes.** The engine separates them by reading the report (exit 1 with empty stdout = NO_OUTPUT; exit 1 with no vulnerabilities = INCONSISTENT_EXIT under S2/S3). Under S0 these cases look the same (EXP-00 PA03).
3. **pip-audit is run with `--no-deps --disable-pip` in the experiments (DEC-016).** It audits the pinned requirements as written: transitive dependencies are not audited, and it does not follow `-r` includes in nested files. On flasky it audited 0 dependencies: S0 and S1 passed the project, S2 blocked it and S3 returned INCOMPLETE with NO_COVERAGE (EXP-02 R). The CI policy of this repository uses pip-audit's default resolution.
4. **Coverage for Gitleaks is read from its log text** ("N commits scanned", "not a git repository"). A Gitleaks version that changes these messages would break this check; `tests/test_live_outputs.py` replays the real messages and would fail first.
5. **Registry rule packs are not content-hashed.** Semgrep does not expose a pack version, so a `p/python` result is identified by pack name, Semgrep version and date only (DEC-009). Experiments use a committed local rule file instead.
6. **The pip-audit vulnerability database is online and changes.** The same requirements file can give different findings on different days; the audit date is each run's start time.
7. **S1 is not uniformly safer than S0** (DEC-006): for an exit code that claims findings while the report lists none, S0 blocks and S1 passes, because consistency is checked only from S2.
8. **Redaction is pattern-based** (FR-29). It covers common token formats and `key=value` secrets; an unusual secret format in a tool's error message could pass through. Gitleaks itself runs with `--redact`.
9. **Only Python projects, three tools, GitHub Actions.** Other ecosystems, scanners and CI systems need new adapters or workflows.

## Product (GitHub Action)

10. **SecureGate is delivered as a reusable GitHub Action (`action.yml`), not as a hosted web platform** (decision of 23 Nov 2026, DEC-020). Sign-in, repository access and run history come from GitHub itself; there is no separate dashboard, user database or GitHub App.
11. **The pinned scanner installation supports Linux x64 runners only** (the Gitleaks binary is checked against one SHA-256). Other runners must put the scanners on `PATH` themselves (`install-scanners: false`).
12. **Evidence is kept as a workflow artifact for 30 days** (GitHub's retention), so the scan history is as long as the repository's Actions history and artifact retention.
13. **Making SecureGate a required status check** is a repository-settings change; it has not been configured on this repository (needs the owner's approval).

## CI integration

14. **An invalid policy is stopped by the Tests job** (the repository-policy test) before the gate step in this repository's CI, so the gate's exit-3 path is verified by unit tests, the Action self-test and local runs.
15. **Validation used a public repository and GitHub-hosted runners.** Self-hosted runners and private repositories were not tested.
16. **The vulnerable-dependency and missing-tool validations are deliberate misconfigurations or synthetic projects**, not real incidents.

## Experiments (EXP-02 final study)

17. **The protocol was frozen by the student without external approval** (DEC-018). It was frozen before the final run and is byte-identical to the candidate run's protocol, which gave the same 7,160 verdicts.
18. **Injected, not field-frequency, faults.** Rates such as SPR describe this designed cell set; they are not estimates of how often scanners fail in practice. Wilson intervals are over a designed, not random, set of cells.
19. **L1 is simulated.** It replays real recorded outputs with deterministic edits; it shows how the decision logic behaves, not how real tools fail. L1, L2 and R are never pooled.
20. **Small control sets at L2:** 3 clean and 6 known-finding synthetic projects (the pilot plan aimed at 5 clean). False-block and true-block rates therefore have wide intervals.
21. **Real projects (R) have no ground truth for their unmodified state**, so missed-alarm rates are not computed there, and the five R projects were also used during development. EXP-03 repeats R on eight projects never run before, with predictions written first (pre-registered); until it runs, R results are not confirmed on held-out projects.
22. **Timing on shared hosted runners is noisy**; overhead is reported as medians, and the evidence-validation time is measured inside the engine, separately from scanner execution. The cost of the scanners themselves, compared with a pipeline without any security step, is not part of the evaluation.
23. **Same author builds and evaluates.** Mitigations: expected outcomes written before the run (`protocol.json`, `FROZEN.sha256`), raw data kept and archived (Zenodo 10.5281/zenodo.24454737), results generated by scripts, EXP-03 pre-registered.
