"""Engine behaviour on real scanner outputs recorded in the live check (17 Nov 2026).

Semgrep 1.180.0, pip-audit 2.10.1, Gitleaks 8.30.1. See tests/fixtures/live/README.md.
"""

from datetime import date
from pathlib import Path

import pytest

from security_engine.gate import SecureGate
from security_engine.policy import PolicyError, policy_from_dict

from gate_helpers import LEAK_CODE, FakeRunner, policy

LIVE = Path(__file__).parent / "fixtures" / "live"


def live(name):
    return (LIVE / name).read_text(encoding="utf-8")


def run(tmp_path, strategy="S3", pol=None, **behaviours):
    gate = SecureGate(pol or policy(strategy), runner=FakeRunner(**behaviours), today=date(2026, 11, 17))
    return gate.run(target=str(tmp_path), out_dir=str(tmp_path / "out"))


def evidence(result, scanner):
    return next(e for e in result.evidences if e.scanner == scanner)


def test_real_semgrep_output_passes_schema_and_blocks_on_finding(tmp_path):
    result = run(tmp_path, semgrep={"exit": 0, "stdout": live("semgrep_finding.json")})
    semgrep = evidence(result, "semgrep")
    assert semgrep.status == "VALID"
    assert semgrep.coverage["files_scanned"] == 1
    assert result.verdict.verdict == "BLOCK"


def test_real_semgrep_scanning_no_files_is_no_coverage(tmp_path):
    result = run(tmp_path, semgrep={"exit": 0, "stdout": live("semgrep_no_files.json")})
    assert evidence(result, "semgrep").category == "NO_COVERAGE"
    assert result.verdict.verdict == "INCOMPLETE"
    assert run(tmp_path, "S0", semgrep={"exit": 0, "stdout": live("semgrep_no_files.json")}).verdict.verdict == "PASS"


def test_real_semgrep_bad_config_exit_7(tmp_path):
    result = run(tmp_path, semgrep={"exit": 7, "stdout": live("semgrep_bad_config_exit7.json")})
    assert evidence(result, "semgrep").category == "NONZERO_EXIT"


def test_real_pip_audit_vulnerabilities_block(tmp_path):
    result = run(tmp_path, pip_audit={"exit": 1, "stdout": live("pip_audit_vulnerable.json")})
    assert evidence(result, "pip-audit").status == "VALID"
    assert result.verdict.verdict == "BLOCK"
    assert len(result.verdict.blocking_findings) == 18


def test_real_pip_audit_crash_is_not_mistaken_for_vulnerabilities(tmp_path):
    """pip-audit exits 1 both for 'vulnerabilities found' and for a fatal error (empty stdout)."""
    crash = {"exit": 1, "stdout": "", "stderr": live("pip_audit_unknown_package.stderr")}
    result = run(tmp_path, pip_audit=crash)
    pip = evidence(result, "pip-audit")
    assert pip.category == "NO_OUTPUT"
    assert "No matching distribution found" in pip.problems[0].message
    assert result.verdict.verdict == "INCOMPLETE"
    # The exit-code-only baseline reads the same exit 1 as "vulnerabilities found".
    s0 = run(tmp_path, "S0", pip_audit=crash).verdict
    assert s0.verdict == "BLOCK" and any(r.code == "EXIT_CODE_FINDINGS" for r in s0.reasons)


def test_real_gitleaks_leak_report_blocks(tmp_path):
    result = run(tmp_path, gitleaks={"exit": LEAK_CODE, "report": live("gitleaks_leak_report.json")})
    assert evidence(result, "gitleaks").status == "VALID"
    assert result.verdict.verdict == "BLOCK"


def test_real_gitleaks_non_repository_silent_pass_is_caught(tmp_path):
    """Live case GL05: exit 0 and an empty report, but Gitleaks scanned 0 commits."""
    silent = {"exit": 0, "report": "[]", "stderr": live("gitleaks_not_a_repo.stderr")}
    result = run(tmp_path, gitleaks=silent)
    gitleaks = evidence(result, "gitleaks")
    assert gitleaks.category == "NO_COVERAGE"
    assert gitleaks.coverage["commits_scanned"] == 0
    assert result.verdict.verdict == "INCOMPLETE"
    for strategy in ("S0", "S1"):
        assert run(tmp_path, strategy, gitleaks=silent).verdict.verdict == "PASS"


def test_real_gitleaks_config_error_with_default_exit_code_is_ambiguous(tmp_path):
    """With the default --exit-code 1, a config error looks exactly like a leak to an exit-code-only gate."""
    error = {"exit": 1, "stderr": live("gitleaks_bad_config.stderr")}
    pol = policy_from_dict({"strategy": "S0", "scanners": {"gitleaks": {"leak_exit_code": 3}}})
    s0 = run(tmp_path, pol=pol, gitleaks=error)
    assert s0.verdict.verdict == "BLOCK"
    s3 = run(tmp_path, gitleaks=error)
    gitleaks = evidence(s3, "gitleaks")
    assert gitleaks.category == "NONZERO_EXIT"
    assert "unable to load gitleaks config" in gitleaks.problems[0].message


def test_gitleaks_normal_log_is_not_flagged(tmp_path):
    log = "INF 12 commits scanned.\nINF scanned ~2048 bytes (2.05 KB) in 80ms\nINF no leaks found\n"
    result = run(tmp_path, gitleaks={"exit": 0, "report": "[]", "stderr": log})
    gitleaks = evidence(result, "gitleaks")
    assert gitleaks.status == "VALID" and gitleaks.coverage["commits_scanned"] == 12


def test_semgrep_accepts_several_rule_packs(tmp_path):
    runner = FakeRunner()
    pol = policy_from_dict({"scanners": {"semgrep": {"config": ["p/python", "p/github-actions"]},
                                         "gitleaks": {"leak_exit_code": 3}}})
    SecureGate(pol, runner=runner).run(target=str(tmp_path), out_dir=str(tmp_path / "out"))
    cmd = next(c for tool, c, _ in runner.calls if tool == "semgrep")
    assert cmd.count("--config") == 2 and "p/github-actions" in cmd


@pytest.mark.parametrize("config", ["auto", ["p/python", "auto"], [], ""])
def test_semgrep_unpinned_or_empty_config_rejected(config):
    with pytest.raises(PolicyError):
        policy_from_dict({"scanners": {"semgrep": {"config": config}}})
