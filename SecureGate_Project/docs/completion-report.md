# SecureGate completion report (Semester 8 development plan)

> **Update, 23 Nov 2026:** the product is now a reusable GitHub Action (`action.yml`, DEC-020) with a self-test of every decision path; D2 is closed (workflow expressions passed through `env:`, `p/github-actions` added to the CI policy); EXP-03 (pre-registered held-out confirmation) is frozen and smoke-tested; 171 tests pass. `limitations.md` was rewritten for the EXP-02 final results.
>
> **Update, 21 Nov 2026 (branch `semester8-final`):** requirements v1.2 add FR-14a (optional parse check) and FR-20a (confirmed findings are never relaxed), giving 44 requirements and 164 tests; decisions DEC-014–DEC-018; the EXP-02 final study has a candidate run (see `experiments/EXP-02/README.md`). The figures below describe the state on 17 Nov 2026.

**Date:** 17 Nov 2026 · **Branch:** `semester8-completion` (from `semester8-engine` at `52c2c3b`) · **Author of all commits:** Duclas Matsinhe

Everything below was executed and checked. Where something was not done or not verified, it says so.

## 1. Requirements satisfied

All 42 requirements of the engine specification v1.1 (FR-01–FR-35, NFR-01–NFR-07) are implemented. 41 are verified by named passing tests ([traceability-matrix.md](traceability-matrix.md), generated from a real test run); NFR-01 (compatibility) is verified by CI runs on `ubuntu-24.04` with Python 3.13 and the pinned scanners.

Gaps from the plan that were closed on this branch:

| Gap | Implementation | Verified by |
|---|---|---|
| Execution records | exit code, timings, stdout size, capped stderr, launch errors per scanner | `test_execution_record_fields`, `test_real_crash_records_exit_code_and_stderr` |
| Reproducibility | tool versions, commands, policy SHA-256, rule sources (local rule/requirements file hashes, registry pack names, `.gitleaksignore` hash) | `test_rule_sources_*`, `test_gitleaks_ignore_file_is_recorded` |
| Output isolation, stale reports | `raw/<run_id>/` per run; stale report deleted first | `test_each_run_gets_its_own_raw_folder`, `test_previous_runs_report_is_never_reused` |
| Coverage incl. skipped files | Semgrep `paths.skipped` classified (failures vs deliberate skips) | `test_semgrep_failed_file_analysis_is_partial_coverage`, `test_semgrep_deliberate_skips_*` |
| S0–S3 semantics | `STRATEGY_CHECKS`; `checks_applied` in the manifest | `test_checks_applied_*`, `test_only_s3_produces_incomplete` |
| Policy validation and versioning | strict TOML validation, exit 3, canonical hash | `test_invalid_policies_are_rejected`, `test_policy_hash_changes_with_policy` |
| Manifest schema and redaction | JSON Schema 1.1; wider redaction patterns; no secret in any output file | `test_manifest_conforms_to_json_schema` (5 scenarios), `test_redaction_*`, `test_no_secret_reaches_any_output_file`; 844 experiment manifests validated |
| CLI/harness equivalence | same verdict, exit code and reasons | `test_cli_and_library_give_identical_decisions` |
| Requirement-to-test traceability | `tests/traceability.py`, enforced by a test; matrix generated | `test_every_requirement_is_traced`, `test_traced_tests_exist` |
| Execution vs validation overhead | `timings` block; per-scanner `validation_s` | `test_timings_separate_execution_validation_and_decision`; EXP-01 timing |

## 2. Outstanding

| Item | Why open | Needs |
|---|---|---|
| Protocol freeze (cells, repetitions, controls, F9/F10 realisations) | Pilot only; guide approval required | Guide review (target 6 Dec) |
| D2 Semgrep rule packs for the frozen protocol | `p/github-actions` gives PartialParsing on this workflow (EXP-01 probe) | Decide; optionally move `${{ }}` out of `run:` |
| SecureGate as a required status check on `main` | Repository-settings change | Owner approval |
| Merge `semester8-completion` into `main` | Not authorised | Owner decision after review |
| Semgrep does not report syntax errors | Scanner limit (EXP-00 SG04, EXP-01 F9) | Report as limitation, or add a separate parse check later |
| Gate exit 3 inside a CI gate step | An invalid policy is stopped earlier by the Tests job | Nothing (covered by unit tests); documented |

## 3. Changes made

Commits on `semester8-completion` (oldest first): `41c10e7` engine gaps + 47 tests + traceability; `8d4a01b` synthetic secrets and `.gitleaksignore`; `f8b7c4e` scanner id in every reason (bug found by the harness); `46fcaf5` EXP-01 harness and workflow; `4dbe5ee` CI exit-3 handling; `ff1edbd` docs, requirements v1.1, DEC-006–013; `d36ef81` workflow PATH fix; `059cbb9` pilot results; `98df54b` traceability tool without XML (blocked by the gate itself); `5709211` regenerated matrix; `5304106` CI docs; plus this report.

Requirement deviations, each recorded: FR-22 TOML (DEC-002), FR-23 presence in S1 (DEC-006), FR-32 exit 3 (DEC-003), FR-05 pack lists (DEC-009), FR-04 ignore file as a rule source (DEC-011). See requirements §7.

## 4. Tests run and results

| Run | Result |
|---|---|
| Unit and integration tests (local and CI) | **155 passed, 0 failed** ([test-report.md](test-report.md)) |
| Lint (ruff E, F, W, B; line length 120) on all new and changed engine, test, tool and harness files | clean |
| Gitleaks 8.30.1 on full repository history | no leaks (after DEC-011) |
| EXP-01 L1 simulated (472 runs) | CI result identical run for run to a local run |
| EXP-01 L2 real binaries (372 runs, twice) | see §7; identical verdicts in both runs |

## 5. GitHub Actions runs

| Purpose | Run | Result |
|---|---|---|
| CI PASS on final workflow | [44090612694](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44090612694) | Tests ✓, SecureGate PASS, Docker built |
| CI BLOCK | [44090927129](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44090927129) | BLOCK, exit 1, Docker skipped |
| CI INCOMPLETE | [44090934106](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44090934106) | INCOMPLETE, exit 2, Docker skipped |
| CI invalid policy | [44090938218](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44090938218) | Tests job fails, gate and Docker skipped |
| CI real block on own code | [44089985683](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44089985683) | BLOCK (Semgrep, XML parsing) → fixed |
| EXP-01 pilot | [44083865707](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44083865707) | success; results on `semester8-completion-results` |
| EXP-01 replication | [44089989905](https://github.com/DuclasMatsinhe/SecureGate/actions/runs/44089989905) | success; identical verdicts; 155 unit tests recorded |

All results were read from the public GitHub API. Earlier runs are listed in [ci-integration.md](ci-integration.md).

## 6. Branches and commits

| Branch | Head | Note |
|---|---|---|
| `main` | `a6c44c3` | unchanged |
| `semester8-integration` | `e7ca85b` | unchanged |
| `semester8-engine` | `52c2c3b` | unchanged (baseline of this work) |
| `live-scanner-check` / `live-scanner-results` | `043c992` / `d054ce2` | unchanged (EXP-00 evidence) |
| `semester8-completion` | see `git log` | **the completion work** |
| `semester8-experiments` | `059cbb9` | trigger branch for `experiments.yml` |
| `semester8-completion-results` | `21306df` | experiment results, one new folder per run |
| `semester8-ci-validate-block` / `-incomplete` / `-config` | `c6c2fc6` / `ccb628d` / `42cf2d3` | CI validation only; never merged |

No branch was deleted, no force push was made, no historical result was changed, no repository setting or secret was touched.

## 7. Evidence produced

- **EXP-01 pilot, real binaries (L2):** silent-pass rate S0 0.481 (39/81) → S2/S3 0.037 (3/81); S3 classification accuracy 0.926; no false blocks (0/3); all true blocks kept (9/9); findings kept under partial failure (6/6); verdicts identical across 3 repetitions; evidence validation about 0.4 ms per run (≈0.006% of engine time). The 3 remaining silent passes are one cell: Semgrep not reporting a syntax error.
- **EXP-01 L1 (simulated):** S0 0.309 → S2/S3 0; S3 ICA 1.0. Shows that S1 is not uniformly safer than S0 (DEC-006).
- **Replication (run 44089989905):** all 372 L2 and 472 L1 verdicts and categories identical to the first pilot; validation cost again ≈0.45 ms per run; wall times differ between runners (6.7 s vs 10.1 s median).
- **D2 probe:** `p/github-actions` is a real pack; on this repository it finds nothing but raises PartialParsing errors.
- **CI:** PASS, BLOCK, INCOMPLETE and config paths observed in real runs; one real block on the project's own code.
- Pilot results: `experiments/EXP-01-pilot/` (README with the 12 fields, results, protocol); raw archives on `semester8-completion-results`.

## 8. Limitations

See [limitations.md](limitations.md). The main ones: the gate sees only what scanners report; injected (not field-frequency) faults; pilot cell set and small controls; L1 is simulated; three tools, Python and GitHub Actions only; the same person builds and evaluates.

## 9. Next steps for the paper

1. Review the pilot with the guide; freeze the protocol (`protocol.json` becomes the frozen version) by 6 Dec.
2. Fix the F9 realisation for pip-audit and add real L2 realisations for F5 and F10 (Semgrep, pip-audit).
3. Enlarge the clean and known-finding sets (at least 5 each) so FBR and CBR have useful intervals.
4. Run the frozen protocol with the final repetitions; report L1 and L2 separately; keep S0 as baseline.
5. Measure the whole-pipeline overhead against a no-security workflow (the pilot measured only the engine's validation cost).
6. Write the results section around SPR, ICA, FBR, CBR and FPP, with the Semgrep parse-error limit and the S1-versus-S0 observation as findings.
