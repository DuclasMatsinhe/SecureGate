from pathlib import Path
"""Tests for the evidence-aware gate (requirements v1, FR-01 to FR-35)."""

import json
import sys
from datetime import date

import pytest

from security_engine import cli
from security_engine.execution import CommandRunner
from security_engine.gate import SecureGate
from security_engine.policy import PolicyError, load_policy, policy_from_dict
from security_engine.report import validate_manifest

from gate_helpers import (FakeRunner, LEAK_CODE, gitleaks_report, pip_report, policy,
                          semgrep_report, semgrep_result, vulnerable_dep)


def run(tmp_path, strategy="S3", pol=None, **behaviours):
    gate = SecureGate(pol or policy(strategy), runner=FakeRunner(**behaviours), today=date(2026, 11, 17))
    return gate.run(target=str(tmp_path), out_dir=str(tmp_path / "out"))


def categories(result):
    return {e.scanner: e.category for e in result.evidences}


# ---------------------------------------------------------------- audit probes C0-C13c
# (probe id, behaviours, expected S3 verdict, expected category or None, expected S0 verdict)
PROBES = [
    ("C0 all clean", {}, "PASS", None, "PASS"),
    ("C1 semgrep {}", {"semgrep": {"exit": 0, "stdout": "{}"}}, "INCOMPLETE", "SCHEMA_INVALID", "PASS"),
    ("C2 semgrep parse errors, nothing scanned",
     {"semgrep": {"exit": 0, "stdout": semgrep_report(errors=[{"type": "Syntax error", "level": "warn"}],
                                                      scanned=[])}},
     "INCOMPLETE", "NO_COVERAGE", "PASS"),
    ("C3 semgrep CRITICAL", {"semgrep": {"exit": 0, "stdout": semgrep_report([semgrep_result("CRITICAL")])}},
     "BLOCK", None, "BLOCK"),
    ("C4 semgrep ERROR", {"semgrep": {"exit": 0, "stdout": semgrep_report([semgrep_result("ERROR")])}},
     "BLOCK", None, "BLOCK"),
    ("C5 pip-audit {}", {"pip_audit": {"exit": 0, "stdout": "{}"}}, "INCOMPLETE", "SCHEMA_INVALID", "PASS"),
    ("C6 pip-audit skipped dependency",
     {"pip_audit": {"exit": 0, "stdout": pip_report([{"name": "flask", "version": "3.0.3", "vulns": []},
                                                     {"name": "private-pkg", "skip_reason": "not found on PyPI"}])}},
     "INCOMPLETE", "PARTIAL_COVERAGE", "PASS"),
    ("C7 pip-audit truncated JSON", {"pip_audit": {"exit": 0, "stdout": pip_report()[:20]}},
     "INCOMPLETE", "INVALID_JSON", "PASS"),
    ("C8 pip-audit exit 1, no output", {"pip_audit": {"exit": 1, "stdout": ""}},
     "INCOMPLETE", "NO_OUTPUT", "BLOCK"),
    ("C9 gitleaks leak code with empty report", {"gitleaks": {"exit": LEAK_CODE, "report": "[]"}},
     "INCOMPLETE", "INCONSISTENT_EXIT", "BLOCK"),
    ("C9b gitleaks exit 1 (error) with empty report", {"gitleaks": {"exit": 1, "report": "[]"}},
     "INCOMPLETE", "NONZERO_EXIT", "BLOCK"),
    ("C10 gitleaks exit 0, no report", {"gitleaks": {"exit": 0, "report": None}},
     "INCOMPLETE", "NO_OUTPUT", "PASS"),
    ("C11 semgrep missing", {"semgrep": {"launch_error": "TOOL_MISSING"}}, "INCOMPLETE", "TOOL_MISSING", "BLOCK"),
    ("C13a semgrep EXPERIMENT", {"semgrep": {"exit": 0, "stdout": semgrep_report([semgrep_result("EXPERIMENT")])}},
     "BLOCK", None, "BLOCK"),
    ("C13b semgrep INVENTORY", {"semgrep": {"exit": 0, "stdout": semgrep_report([semgrep_result("INVENTORY")])}},
     "BLOCK", None, "BLOCK"),
    ("C13c semgrep WARNING below threshold",
     {"semgrep": {"exit": 0, "stdout": semgrep_report([semgrep_result("WARNING")])}}, "PASS", None, "PASS"),
]


@pytest.mark.parametrize("name,behaviours,expected,category,_s0", PROBES, ids=[p[0] for p in PROBES])
def test_probe_under_s3(tmp_path, name, behaviours, expected, category, _s0):
    result = run(tmp_path, "S3", **behaviours)
    assert result.verdict.verdict == expected
    if category:
        assert category in categories(result).values()
        assert result.verdict.exit_code == 2


@pytest.mark.parametrize("name,behaviours,_s3,_cat,expected_s0", PROBES, ids=[p[0] for p in PROBES])
def test_probe_under_s0_baseline(tmp_path, name, behaviours, _s3, _cat, expected_s0):
    assert run(tmp_path, "S0", **behaviours).verdict.verdict == expected_s0


def test_c12_all_scanners_fail(tmp_path):
    fail = {"launch_error": "TIMEOUT"}
    result = run(tmp_path, "S3", semgrep=fail, pip_audit=fail, gitleaks=fail)
    assert result.verdict.verdict == "INCOMPLETE"
    assert set(categories(result).values()) == {"TIMEOUT"}


def test_strategies_detect_progressively_more_faults(tmp_path):
    """H2 shape: S1 catches schema faults but not coverage faults; S2 catches both; S3 labels them."""
    schema_fault = {"semgrep": {"exit": 0, "stdout": "{}"}}
    coverage_fault = {"pip_audit": {"exit": 0, "stdout": pip_report([{"name": "x", "skip_reason": "skipped"}])}}
    assert run(tmp_path, "S1", **schema_fault).verdict.verdict == "BLOCK"
    assert run(tmp_path, "S1", **coverage_fault).verdict.verdict == "PASS"
    assert run(tmp_path, "S2", **coverage_fault).verdict.verdict == "BLOCK"
    assert run(tmp_path, "S3", **coverage_fault).verdict.verdict == "INCOMPLETE"


# ---------------------------------------------------------------- partial failure, findings kept
def test_partial_failure_keeps_real_findings(tmp_path):
    result = run(tmp_path, "S3", semgrep={"launch_error": "TIMEOUT"},
                 pip_audit={"exit": 1, "stdout": pip_report([vulnerable_dep()])})
    assert result.verdict.verdict == "INCOMPLETE"
    codes = [r.code for r in result.verdict.reasons]
    assert "TIMEOUT" in codes and "BLOCKING_FINDING" in codes
    assert any("PYSEC-TEST-1" in r.message for r in result.verdict.reasons)


def test_findings_from_invalid_evidence_are_kept_and_marked(tmp_path):
    report = semgrep_report([semgrep_result("ERROR")], errors=[{"type": "Timeout", "level": "warn"}])
    result = run(tmp_path, "S3", semgrep={"exit": 0, "stdout": report})
    semgrep = next(e for e in result.evidences if e.scanner == "semgrep")
    assert semgrep.category == "PARTIAL_COVERAGE"
    assert semgrep.findings and semgrep.findings[0].from_incomplete_evidence


def test_genuine_findings_block(tmp_path):
    result = run(tmp_path, "S3", pip_audit={"exit": 1, "stdout": pip_report([vulnerable_dep()])},
                 gitleaks={"exit": LEAK_CODE, "report": gitleaks_report(1)})
    assert result.verdict.verdict == "BLOCK"
    assert result.verdict.exit_code == 1
    assert len(result.verdict.blocking_findings) == 2


def test_pip_audit_exit_code_contradicting_report(tmp_path):
    result = run(tmp_path, "S3", pip_audit={"exit": 0, "stdout": pip_report([vulnerable_dep()])})
    assert "INCONSISTENT_EXIT" in categories(result).values()


# ---------------------------------------------------------------- execution (real processes)
def test_real_timeout_stops_scanner():
    record = CommandRunner().run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
    assert record.launch_error == "TIMEOUT"
    assert record.duration_s < 10


def test_real_missing_executable():
    record = CommandRunner().run(["securegate-no-such-tool-xyz"], timeout=5)
    assert record.launch_error == "TOOL_MISSING"


def test_real_command_captures_exit_code_and_output():
    record = CommandRunner().run([sys.executable, "-c", "print('hi'); raise SystemExit(4)"], timeout=10)
    assert record.exit_code == 4 and record.stdout.strip() == "hi"


def test_timeouts_come_from_policy(tmp_path):
    runner = FakeRunner()
    pol = policy_from_dict({"scanners": {"semgrep": {"timeout": 42}, "gitleaks": {"leak_exit_code": 3}}})
    SecureGate(pol, runner=runner).run(target=str(tmp_path), out_dir=str(tmp_path / "out"))
    assert ("semgrep", 42) in {(tool, t) for tool, _, t in runner.calls}


def test_commands_are_pinned_and_explicit(tmp_path):
    runner = FakeRunner()
    SecureGate(policy(), runner=runner).run(target=str(tmp_path), out_dir=str(tmp_path / "out"))
    commands = {tool: cmd for tool, cmd, _ in runner.calls}
    assert "auto" not in commands["semgrep"]
    assert commands["semgrep"][commands["semgrep"].index("--config") + 1] == "p/python"
    assert commands["gitleaks"][commands["gitleaks"].index("--exit-code") + 1] == str(LEAK_CODE)
    assert "--redact" in commands["gitleaks"]


def test_stale_gitleaks_report_is_not_reused(tmp_path):
    out = tmp_path / "out" / "raw"
    out.mkdir(parents=True)
    (out / "gitleaks-report.json").write_text("[]")
    result = run(tmp_path, "S3", gitleaks={"exit": 0, "report": None})
    assert "NO_OUTPUT" in categories(result).values()


def test_engine_error_never_passes(tmp_path):
    result = run(tmp_path, "S3", semgrep={"raise_error": True})
    assert result.verdict.verdict == "INCOMPLETE"
    assert "ENGINE_ERROR" in categories(result).values()
    assert run(tmp_path, "S0", semgrep={"raise_error": True}).verdict.verdict == "BLOCK"


def test_scanner_versions_recorded(tmp_path):
    result = run(tmp_path)
    assert all(e.version.endswith("9.9.9-fake") for e in result.evidences)


# ---------------------------------------------------------------- policy
def test_default_policy_loads():
    pol = load_policy()
    assert pol.strategy == "S3" and pol.on_incomplete == "block"
    assert pol.required_scanners == ["semgrep", "pip-audit", "gitleaks"]


def test_repository_policy_file_is_valid():
    pol = load_policy("securegate.toml")
    assert pol.strategy == "S3"


@pytest.mark.parametrize("raw,fragment", [
    ({"strategy": "S9"}, "strategy"),
    ({"on_incomplete": "ignore"}, "on_incomplete"),
    ({"thresholds": {"default": "SEVERE"}}, "thresholds"),
    ({"unknown_key": 1}, "unknown policy key"),
    ({"scanners": {"semgrep": {"timeout": 0}}}, "timeout"),
    ({"scanners": {"semgrep": {"enabled": False}}}, "disabled"),
    ({"scanners": {"gitleaks": {"leak_exit_code": 1}}}, "leak_exit_code"),
    ({"suppressions": [{"rule_id": "x", "reason": "r"}]}, "expires"),
])
def test_invalid_policies_are_rejected(raw, fragment):
    with pytest.raises(PolicyError, match=fragment):
        policy_from_dict(raw)


def test_policy_hash_changes_with_policy():
    assert policy_from_dict({}).sha256() != policy_from_dict({"strategy": "S0"}).sha256()


def test_on_incomplete_warn_does_not_fail_the_job(tmp_path):
    pol = policy(on_incomplete="warn")
    result = run(tmp_path, pol=pol, semgrep={"exit": 0, "stdout": "{}"})
    assert result.verdict.verdict == "INCOMPLETE" and result.verdict.exit_code == 0


def test_on_incomplete_warn_never_relaxes_a_confirmed_finding(tmp_path):
    # FR-20a: incomplete evidence may be relaxed to a warning, a confirmed finding may not.
    pol = policy(on_incomplete="warn")
    result = run(tmp_path, pol=pol,
                 semgrep={"exit": 0, "stdout": semgrep_report([semgrep_result("ERROR")])},
                 gitleaks={"launch_error": "TOOL_MISSING"})
    assert result.verdict.verdict == "INCOMPLETE" and result.verdict.exit_code == 2
    assert any(r.code == "BLOCKING_FINDING" for r in result.verdict.reasons)
    assert any(n.code == "FINDING_NOT_DOWNGRADED" for n in result.verdict.notes)
    # Without a finding, warn still relaxes incomplete evidence.
    clean = run(tmp_path, pol=pol, gitleaks={"launch_error": "TOOL_MISSING"})
    assert clean.verdict.verdict == "INCOMPLETE" and clean.verdict.exit_code == 0
    assert not any(n.code == "FINDING_NOT_DOWNGRADED" for n in clean.verdict.notes)


def test_optional_scanner_failure_is_a_note(tmp_path):
    pol = policy(required_scanners=["semgrep", "pip-audit"])
    result = run(tmp_path, pol=pol, gitleaks={"launch_error": "TOOL_MISSING"})
    assert result.verdict.verdict == "PASS"
    assert any(n.code == "TOOL_MISSING" for n in result.verdict.notes)


def test_threshold_per_scanner(tmp_path):
    pol = policy(thresholds={"default": "HIGH", "semgrep": "MEDIUM"})
    result = run(tmp_path, pol=pol, semgrep={"exit": 0, "stdout": semgrep_report([semgrep_result("WARNING")])})
    assert result.verdict.verdict == "BLOCK"


def test_active_and_expired_suppressions(tmp_path):
    finding = {"semgrep": {"exit": 0, "stdout": semgrep_report([semgrep_result("ERROR", rule="r1")])}}
    active = policy(suppressions=[{"rule_id": "r1", "reason": "accepted risk", "expires": "2026-12-31"}])
    expired = policy(suppressions=[{"rule_id": "r1", "reason": "accepted risk", "expires": "2026-01-01"}])
    assert run(tmp_path, pol=active, **finding).verdict.verdict == "PASS"
    result = run(tmp_path, pol=expired, **finding)
    assert result.verdict.verdict == "BLOCK"
    assert any(n.code == "SUPPRESSION_EXPIRED" for n in result.verdict.notes)


def test_unknown_severity_is_mapped_and_reported(tmp_path):
    result = run(tmp_path, semgrep={"exit": 0, "stdout": semgrep_report([semgrep_result("EXPERIMENT")])})
    assert any(n.code == "SEVERITY_MAPPED" for n in result.verdict.notes)


# ---------------------------------------------------------------- determinism and records
def test_same_evidence_same_verdict(tmp_path):
    fault = {"pip_audit": {"exit": 0, "stdout": "{}"}}
    a, b = run(tmp_path, **fault), run(tmp_path, **fault)
    assert a.verdict.to_dict() == b.verdict.to_dict()


def test_manifest_is_complete_and_valid(tmp_path):
    result = run(tmp_path, semgrep={"exit": 0, "stdout": "{}"})
    manifest = json.loads(result.manifest_path.read_text())
    assert validate_manifest(manifest) == []
    assert manifest["policy"]["strategy"] == "S3" and len(manifest["policy"]["sha256"]) == 64
    assert manifest["verdict"]["verdict"] == "INCOMPLETE"
    assert {s["scanner"] for s in manifest["scanners"]} == {"semgrep", "pip-audit", "gitleaks"}


def test_manifest_redacts_secrets_and_home_paths(tmp_path):
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    result = run(tmp_path, gitleaks={"exit": 1, "report": "[]", "stderr": f"failed near {token}"})
    text = result.manifest_path.read_text() + result.report_path.read_text()
    assert token not in text
    assert "[REDACTED]" in result.manifest_path.read_text()


def test_report_renders_each_verdict(tmp_path):
    assert "verdict: PASS" in run(tmp_path).report_markdown
    blocked = run(tmp_path, pip_audit={"exit": 1, "stdout": pip_report([vulnerable_dep()])})
    assert "verdict: BLOCK" in blocked.report_markdown
    assert "not a security clearance" in run(tmp_path, semgrep={"exit": 0, "stdout": "{}"}).report_markdown


# ---------------------------------------------------------------- CLI exit codes
def test_cli_exit_codes(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    base = ["--out", str(tmp_path / "o"), "--no-summary"]
    (tmp_path / "securegate.toml").write_text('strategy = "S3"\n[scanners.gitleaks]\nleak_exit_code = 3\n')
    assert cli.main(base, runner=FakeRunner()) == 0
    assert cli.main(base, runner=FakeRunner(pip_audit={"exit": 1, "stdout": pip_report([vulnerable_dep()])})) == 1
    assert cli.main(base, runner=FakeRunner(semgrep={"exit": 0, "stdout": "{}"})) == 2
    assert '"verdict": "INCOMPLETE"' in capsys.readouterr().out


def test_cli_invalid_policy_exits_3(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "bad.toml").write_text('strategy = "S9"\n')
    assert cli.main(["--policy", "bad.toml", "--no-summary"], runner=FakeRunner()) == 3


def test_cli_usage_error_exits_3():
    with pytest.raises(SystemExit) as exc:
        cli.main(["--strategy", "S7"])
    assert exc.value.code == 3


def test_cli_strategy_override(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    args = ["--out", str(tmp_path / "o"), "--no-summary", "--strategy", "S0"]
    assert cli.main(args, runner=FakeRunner(semgrep={"exit": 0, "stdout": "{}"})) == 0


def test_cli_appends_github_job_summary(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    cli.main(["--out", str(tmp_path / "o")], runner=FakeRunner())
    assert "SecureGate verdict: PASS" in summary.read_text()


# ---------------------------------------------------------------- FR-14a parse check (v1.2)
def _broken_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("def add(a, b):\n    return a + b\n")
    (target / "broken.py").write_text("def broken(:\n    return 1\n")
    return target


def _run_target(target, out, strategy="S3", parse_check=True):
    pol = policy(strategy, scanners={"gitleaks": {"leak_exit_code": LEAK_CODE},
                                     "semgrep": {"parse_check": parse_check}})
    runner = FakeRunner(semgrep={"exit": 0, "stdout": semgrep_report(scanned=("app.py", "broken.py"))})
    return SecureGate(pol, runner=runner, today=date(2026, 11, 17)).run(target=str(target), out_dir=str(out))


def test_parse_check_flags_unparsable_file_semgrep_lists_as_scanned(tmp_path):
    target = _broken_target(tmp_path)
    result = _run_target(target, tmp_path / "out")
    semgrep = next(e for e in result.evidences if e.scanner == "semgrep")
    assert semgrep.category == "PARTIAL_COVERAGE" and "broken.py" in semgrep.problems[0].message
    assert semgrep.coverage["python_files_unparsable"] == 1 and "parse_check" in semgrep.checks_applied
    assert result.verdict.verdict == "INCOMPLETE"
    import jsonschema
    schema = json.loads((Path(__file__).resolve().parents[1] / "security_engine" / "schemas"
                         / "run_manifest.schema.json").read_text())
    jsonschema.validate(json.loads(result.manifest_path.read_text()), schema)


def test_parse_check_is_off_by_default_and_needs_coverage_checks(tmp_path):
    target = _broken_target(tmp_path)
    assert _run_target(target, tmp_path / "a", parse_check=False).verdict.verdict == "PASS"
    assert _run_target(target, tmp_path / "b", strategy="S1").verdict.verdict == "PASS"


def test_parse_check_passes_valid_files_and_ignores_paths_outside_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n")
    (tmp_path / "outside.py").write_text("def broken(:\n")
    pol = policy(scanners={"gitleaks": {"leak_exit_code": LEAK_CODE}, "semgrep": {"parse_check": True}})
    runner = FakeRunner(semgrep={"exit": 0, "stdout": semgrep_report(scanned=("app.py", "../outside.py"))})
    result = SecureGate(pol, runner=runner, today=date(2026, 11, 17)).run(target=str(target),
                                                                           out_dir=str(tmp_path / "out"))
    semgrep = next(e for e in result.evidences if e.scanner == "semgrep")
    assert result.verdict.verdict == "PASS" and semgrep.coverage["python_files_parse_checked"] == 1


def test_parse_check_policy_value_must_be_boolean():
    with pytest.raises(PolicyError, match="parse_check"):
        policy_from_dict({"scanners": {"semgrep": {"parse_check": "yes"}}})
