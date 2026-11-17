"""Requirement -> test traceability (engine requirements v1.1).

Every requirement in SecureGate_Project/docs/requirements/engine-requirements-v1.md
must map to at least one test here, or to a written justification in
VERIFIED_OUTSIDE_UNIT_TESTS. tests/test_traceability.py enforces this, and
tools/traceability_report.py turns it plus a test run into the matrix.
"""

REQUIREMENT_TESTS = {
    # 2.1 Scanner execution (M2)
    "FR-01": ["test_traceability.py::test_adapters_share_one_interface",
              "test_gate.py::test_probe_under_s3"],
    "FR-02": ["test_gate.py::test_real_timeout_stops_scanner", "test_gate.py::test_timeouts_come_from_policy",
              "test_gate.py::test_c12_all_scanners_fail"],
    "FR-03": ["test_completion.py::test_execution_record_fields", "test_completion.py::test_stderr_tail_is_capped",
              "test_completion.py::test_real_crash_records_exit_code_and_stderr",
              "test_gate.py::test_real_command_captures_exit_code_and_output"],
    "FR-04": ["test_completion.py::test_rule_sources_hash_local_files_and_name_registry_packs",
              "test_completion.py::test_manifest_records_versions_policy_hash_and_commands",
              "test_gate.py::test_scanner_versions_recorded",
              "test_completion.py::test_gitleaks_ignore_file_is_recorded"],
    "FR-05": ["test_gate.py::test_commands_are_pinned_and_explicit",
              "test_live_outputs.py::test_semgrep_unpinned_or_empty_config_rejected",
              "test_live_outputs.py::test_semgrep_accepts_several_rule_packs"],
    "FR-06": ["test_gate.py::test_real_missing_executable", "test_gate.py::test_probe_under_s3"],
    "FR-07": ["test_gate.py::test_stale_gitleaks_report_is_not_reused",
              "test_completion.py::test_each_run_gets_its_own_raw_folder",
              "test_completion.py::test_previous_runs_report_is_never_reused"],
    "FR-08": ["test_gate.py::test_partial_failure_keeps_real_findings",
              "test_completion.py::test_mixed_failures_report_every_scanner"],
    "FR-09": ["test_traceability.py::test_no_shell_execution_in_engine"],
    # 2.2 Evidence validation (M3)
    "FR-10": ["test_gate.py::test_probe_under_s3",
              "test_live_outputs.py::test_real_pip_audit_crash_is_not_mistaken_for_vulnerabilities"],
    "FR-11": ["test_gate.py::test_probe_under_s3"],
    "FR-12": ["test_gate.py::test_probe_under_s3",
              "test_live_outputs.py::test_real_semgrep_output_passes_schema_and_blocks_on_finding"],
    "FR-13": ["test_gate.py::test_probe_under_s3", "test_gate.py::test_pip_audit_exit_code_contradicting_report",
              "test_live_outputs.py::test_real_gitleaks_config_error_with_default_exit_code_is_ambiguous"],
    "FR-14": ["test_gate.py::test_probe_under_s3",
              "test_completion.py::test_semgrep_failed_file_analysis_is_partial_coverage",
              "test_completion.py::test_semgrep_deliberate_skips_are_recorded_not_failed",
              "test_live_outputs.py::test_real_semgrep_scanning_no_files_is_no_coverage",
              "test_live_outputs.py::test_real_gitleaks_non_repository_silent_pass_is_caught"],
    "FR-15": ["test_gate.py::test_probe_under_s3", "test_completion.py::test_mixed_failures_report_every_scanner"],
    "FR-16": ["test_scanners.py::test_parse_semgrep_results", "test_scanners.py::test_parse_pip_audit_results",
              "test_scanners.py::test_parse_gitleaks_results"],
    "FR-17": ["test_gate.py::test_unknown_severity_is_mapped_and_reported", "test_gate.py::test_probe_under_s3"],
    "FR-18": ["test_gate.py::test_findings_from_invalid_evidence_are_kept_and_marked"],
    # 2.3 Verdict and policy (M4)
    "FR-19": ["test_gate.py::test_probe_under_s3", "test_gate.py::test_genuine_findings_block",
              "test_gate.py::test_report_renders_each_verdict"],
    "FR-20": ["test_gate.py::test_partial_failure_keeps_real_findings",
              "test_completion.py::test_two_failures_one_real_finding"],
    "FR-21": ["test_gate.py::test_partial_failure_keeps_real_findings",
              "test_completion.py::test_mixed_failures_report_every_scanner"],
    "FR-22": ["test_gate.py::test_invalid_policies_are_rejected", "test_gate.py::test_default_policy_loads",
              "test_gate.py::test_repository_policy_file_is_valid",
              "test_gate.py::test_policy_hash_changes_with_policy",
              "test_gate.py::test_threshold_per_scanner", "test_gate.py::test_optional_scanner_failure_is_a_note",
              "test_gate.py::test_on_incomplete_warn_does_not_fail_the_job"],
    "FR-23": ["test_gate.py::test_probe_under_s0_baseline",
              "test_gate.py::test_strategies_detect_progressively_more_faults",
              "test_completion.py::test_checks_applied_are_recorded_per_strategy",
              "test_completion.py::test_only_s3_produces_incomplete"],
    "FR-24": ["test_gate.py::test_active_and_expired_suppressions"],
    "FR-25": ["test_gate.py::test_same_evidence_same_verdict"],
    "FR-26": ["test_gate.py::test_engine_error_never_passes"],
    # 2.4 Reporting and audit (M5)
    "FR-27": ["test_gate.py::test_manifest_is_complete_and_valid",
              "test_completion.py::test_manifest_conforms_to_json_schema",
              "test_completion.py::test_schema_rejects_an_incomplete_manifest"],
    "FR-28": ["test_gate.py::test_report_renders_each_verdict", "test_gate.py::test_cli_appends_github_job_summary"],
    "FR-29": ["test_gate.py::test_manifest_redacts_secrets_and_home_paths",
              "test_completion.py::test_redaction_patterns",
              "test_completion.py::test_redaction_keeps_key_names",
              "test_completion.py::test_redaction_leaves_ordinary_messages_alone",
              "test_completion.py::test_no_secret_reaches_any_output_file"],
    "FR-30": ["test_gate.py::test_manifest_redacts_secrets_and_home_paths",
              "test_traceability.py::test_manifest_has_no_personal_fields"],
    # 2.5 CLI
    "FR-31": ["test_gate.py::test_cli_strategy_override", "test_gate.py::test_cli_exit_codes"],
    "FR-32": ["test_gate.py::test_cli_exit_codes", "test_gate.py::test_cli_invalid_policy_exits_3",
              "test_gate.py::test_cli_usage_error_exits_3", "test_completion.py::test_only_pass_lets_ci_continue"],
    "FR-33": ["test_gate.py::test_cli_exit_codes"],
    # 2.6 Experiment hooks
    "FR-34": ["test_gate.py::test_probe_under_s3", "test_live_outputs.py::test_real_gitleaks_leak_report_blocks"],
    "FR-35": ["test_completion.py::test_cli_and_library_give_identical_decisions"],
    # 3. Non-functional
    "NFR-02": ["test_gate.py::test_probe_under_s3", "test_gate.py::test_engine_error_never_passes",
               "test_completion.py::test_only_s3_produces_incomplete"],
    "NFR-03": ["test_traceability.py::test_no_shell_execution_in_engine",
               "test_traceability.py::test_dockerfile_runs_as_non_root",
               "test_completion.py::test_no_secret_reaches_any_output_file"],
    "NFR-04": ["test_traceability.py::test_every_requirement_is_traced"],
    "NFR-05": ["test_gate.py::test_same_evidence_same_verdict",
               "test_completion.py::test_rule_sources_hash_local_files_and_name_registry_packs"],
    "NFR-06": ["test_security_engine.py::test_security_gate_blocks_high_findings",
               "test_security_engine.py::test_scanner_error_prevents_gate_from_passing",
               "test_scanners.py::test_run_semgrep_success_with_findings"],
    "NFR-07": ["test_completion.py::test_timings_separate_execution_validation_and_decision"],
}

VERIFIED_OUTSIDE_UNIT_TESTS = {
    "NFR-01": "Compatibility (Python 3.13 on GitHub-hosted Ubuntu with the pinned scanners) is verified by the "
              "CI workflow run and the live scanner check on ubuntu-24.04, not by a unit test.",
}
