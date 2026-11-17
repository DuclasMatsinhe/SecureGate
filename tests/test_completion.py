"""Tests for the requirement gaps closed on the semester8-completion branch.

Each test names the requirement(s) it verifies in tests/traceability.py.
"""

import json
import sys
from datetime import date
from pathlib import Path

import jsonschema
import pytest

from security_engine import cli
from security_engine.adapters import STRATEGY_CHECKS
from security_engine.gate import SecureGate
from security_engine.policy import policy_from_dict
from security_engine.report import REDACTED, redact

from gate_helpers import LEAK_CODE, FakeRunner, gitleaks_report, pip_report, policy, semgrep_report, \
    semgrep_result, vulnerable_dep

SCHEMA = json.loads((Path(__file__).parents[1] / "security_engine" / "schemas" /
                     "run_manifest.schema.json").read_text(encoding="utf-8"))


def run(tmp_path, strategy="S3", pol=None, runner=None, **behaviours):
    gate = SecureGate(pol or policy(strategy), runner=runner or FakeRunner(**behaviours), today=date(2026, 11, 17))
    return gate.run(target=str(tmp_path), out_dir=str(tmp_path / "out"))


def evidence(result, scanner):
    return next(e for e in result.evidences if e.scanner == scanner)


# ---------------------------------------------------------------- execution records (FR-03)
def test_execution_record_fields(tmp_path):
    record = evidence(run(tmp_path), "semgrep").execution.to_dict()
    assert set(record) == {"command", "started_at", "duration_s", "exit_code", "launch_error",
                           "launch_detail", "stdout_bytes", "stderr_tail"}
    assert record["exit_code"] == 0 and record["stdout_bytes"] > 0


def test_stderr_tail_is_capped(tmp_path):
    result = run(tmp_path, semgrep={"exit": 0, "stdout": semgrep_report(), "stderr": "x" * 10000})
    assert len(evidence(result, "semgrep").execution.to_dict()["stderr_tail"]) == 2000


def test_real_crash_records_exit_code_and_stderr():
    from security_engine.execution import CommandRunner
    record = CommandRunner().run([sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(2)"],
                                 timeout=10)
    assert record.exit_code == 2 and "boom" in record.stderr and record.launch_error is None


# ---------------------------------------------------------------- reproducibility (FR-04, NFR-05)
def test_rule_sources_hash_local_files_and_name_registry_packs(tmp_path):
    (tmp_path / "rules.yml").write_text("rules: []\n")
    (tmp_path / "requirements.txt").write_text("flask==3.1.2\n")
    pol = policy_from_dict({"scanners": {"semgrep": {"config": ["rules.yml", "p/python"]},
                                         "gitleaks": {"leak_exit_code": LEAK_CODE}}})
    result = run(tmp_path, pol=pol)
    semgrep_sources = evidence(result, "semgrep").rule_sources
    assert semgrep_sources[0]["kind"] == "rules_file" and len(semgrep_sources[0]["sha256"]) == 64
    assert semgrep_sources[1] == {"kind": "registry", "id": "p/python",
                                  "note": semgrep_sources[1]["note"]}
    pip_sources = evidence(result, "pip-audit").rule_sources
    assert pip_sources[0]["kind"] == "requirements_file" and len(pip_sources[0]["sha256"]) == 64
    assert pip_sources[1] == {"kind": "vulnerability_service", "id": "pypi (default)"}
    assert evidence(result, "gitleaks").rule_sources[0]["kind"] == "builtin"


def test_gitleaks_ignore_file_is_recorded(tmp_path):
    (tmp_path / ".gitleaksignore").write_text("# synthetic fixture\nabc:tests/x.py:generic-api-key:1\n")
    sources = evidence(run(tmp_path), "gitleaks").rule_sources
    assert sources[-1]["kind"] == "ignore_file" and sources[-1]["entries"] == 1 and len(sources[-1]["sha256"]) == 64


def test_manifest_records_versions_policy_hash_and_commands(tmp_path):
    m = run(tmp_path).manifest
    assert m["policy"]["sha256"] and all(s["version"].endswith("9.9.9-fake") for s in m["scanners"])
    assert all(s["execution"]["command"] for s in m["scanners"])


# ---------------------------------------------------------------- isolation and stale reports (FR-07)
def test_each_run_gets_its_own_raw_folder(tmp_path):
    a, b = run(tmp_path), run(tmp_path)
    raw = sorted(p.name for p in (tmp_path / "out" / "raw").iterdir())
    assert len(raw) == 2 and a.manifest["run_id"] in raw and b.manifest["run_id"] in raw


def test_previous_runs_report_is_never_reused(tmp_path):
    run(tmp_path, gitleaks={"exit": LEAK_CODE, "report": gitleaks_report(1)})
    second = run(tmp_path, gitleaks={"exit": 0, "report": None})
    assert evidence(second, "gitleaks").category == "NO_OUTPUT"


# ---------------------------------------------------------------- coverage incl. skipped files (FR-14)
def _semgrep_with_skips(reasons):
    data = json.loads(semgrep_report())
    data["paths"]["skipped"] = [{"path": f"f{i}.py", "reason": r} for i, r in enumerate(reasons)]
    return json.dumps(data)


def test_semgrep_failed_file_analysis_is_partial_coverage(tmp_path):
    result = run(tmp_path, semgrep={"exit": 0,
                                    "stdout": _semgrep_with_skips(["analysis_failed_parser_or_internal_error"])})
    semgrep = evidence(result, "semgrep")
    assert semgrep.category == "PARTIAL_COVERAGE" and semgrep.coverage["files_failed"] == 1
    assert result.verdict.verdict == "INCOMPLETE"


def test_semgrep_deliberate_skips_are_recorded_not_failed(tmp_path):
    result = run(tmp_path, semgrep={"exit": 0, "stdout": _semgrep_with_skips(
        ["semgrepignore_patterns_match", "cli_exclude_flags_match", "wrong_language"])})
    semgrep = evidence(result, "semgrep")
    assert semgrep.status == "VALID" and semgrep.coverage["files_skipped"] == 3


# ---------------------------------------------------------------- strategy semantics (FR-23)
@pytest.mark.parametrize("strategy", ["S0", "S1", "S2", "S3"])
def test_checks_applied_are_recorded_per_strategy(tmp_path, strategy):
    m = run(tmp_path, strategy).manifest
    assert all(s["checks_applied"] == list(STRATEGY_CHECKS[strategy]) for s in m["scanners"])
    assert m["policy"]["strategy"] == strategy


def test_only_s3_produces_incomplete(tmp_path):
    fault = {"semgrep": {"launch_error": "TOOL_MISSING"}}
    verdicts = {s: run(tmp_path, s, **fault).verdict.verdict for s in ("S0", "S1", "S2", "S3")}
    assert verdicts == {"S0": "BLOCK", "S1": "BLOCK", "S2": "BLOCK", "S3": "INCOMPLETE"}


# ---------------------------------------------------------------- multiple simultaneous failures
def test_mixed_failures_report_every_scanner(tmp_path):
    result = run(tmp_path, semgrep={"launch_error": "TIMEOUT"}, pip_audit={"exit": 0, "stdout": "{}"},
                 gitleaks={"exit": 0, "report": None})
    cats = {e.scanner: e.category for e in result.evidences}
    assert cats == {"semgrep": "TIMEOUT", "pip-audit": "SCHEMA_INVALID", "gitleaks": "NO_OUTPUT"}
    assert {r.scanner for r in result.verdict.reasons} == {"semgrep", "pip-audit", "gitleaks"}


def test_two_failures_one_real_finding(tmp_path):
    result = run(tmp_path, semgrep={"launch_error": "TOOL_MISSING"}, pip_audit={"exit": 0, "stdout": "{}"},
                 gitleaks={"exit": LEAK_CODE, "report": gitleaks_report(1)})
    assert result.verdict.verdict == "INCOMPLETE"
    assert sum(r.code == "BLOCKING_FINDING" for r in result.verdict.reasons) == 1


def test_reasons_always_name_the_scanner_id(tmp_path):
    result = run(tmp_path, semgrep={"exit": 0, "stdout": semgrep_report([semgrep_result("ERROR")])},
                 gitleaks={"exit": LEAK_CODE, "report": gitleaks_report(1)}, pip_audit={"launch_error": "TIMEOUT"})
    assert {r.scanner for r in result.verdict.reasons} == {"semgrep", "gitleaks", "pip-audit"}


# ---------------------------------------------------------------- manifest schema (FR-27)
@pytest.mark.parametrize("behaviours", [
    {},
    {"semgrep": {"exit": 0, "stdout": "{}"}},
    {"pip_audit": {"exit": 1, "stdout": pip_report([vulnerable_dep()])}},
    {"semgrep": {"raise_error": True}},
    {"semgrep": {"launch_error": "TIMEOUT"}, "gitleaks": {"exit": 1}},
], ids=["pass", "incomplete", "block", "engine-error", "multi-failure"])
def test_manifest_conforms_to_json_schema(tmp_path, behaviours):
    manifest = json.loads(run(tmp_path, **behaviours).manifest_path.read_text())
    jsonschema.validate(manifest, SCHEMA)


def test_schema_rejects_an_incomplete_manifest(tmp_path):
    manifest = json.loads(run(tmp_path).manifest_path.read_text())
    del manifest["policy"]["sha256"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(manifest, SCHEMA)


# ---------------------------------------------------------------- redaction (FR-29)
SYNTHETIC_SECRETS = [
    "ghp_" + "A" * 36,
    "github_pat_" + "B" * 30,
    "glpat-" + "C" * 20,
    "AKIA" + "D" * 16,
    "xoxb-" + "1" * 12,
    "sk_live_" + "E" * 24,
    "AIza" + "F" * 35,
    "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12,
    "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIsynthetic\n-----END RSA " + "PRIVATE KEY-----",
]


@pytest.mark.parametrize("secret", SYNTHETIC_SECRETS, ids=lambda s: s[:6])
def test_redaction_patterns(secret):
    assert secret not in redact(f"context {secret} context")


@pytest.mark.parametrize("text,kept", [
    # Built by concatenation so secret scanners reading this file see no literal credential.
    ("pass" + "word=" + "hunter2" * 2, "password="),
    ("api_" + "key: '" + "abcdef" + "123456'", "api_key: '"),
    ("https://user:" + "s3cr3t" + "pass@example.com/repo", "https://"),
])
def test_redaction_keeps_key_names(text, kept):
    out = redact(text)
    assert REDACTED in out and out.startswith(kept)


def test_redaction_leaves_ordinary_messages_alone():
    msg = "Gitleaks exited 3 (leaks found) but its report is empty"
    assert redact(msg) == msg


def test_no_secret_reaches_any_output_file(tmp_path):
    secret = "ghp_" + "Z9" * 18
    result = run(tmp_path, gitleaks={"exit": 1, "report": "[]", "stderr": f"error near {secret}"},
                 semgrep={"exit": 2, "stdout": "", "stderr": f"FATAL password={secret}"})
    for path in (tmp_path / "out").rglob("*"):
        if path.is_file():
            assert secret not in path.read_text(errors="replace"), path
    assert result.verdict.verdict == "INCOMPLETE"


# ---------------------------------------------------------------- overhead measurement (NFR-07)
def test_timings_separate_execution_validation_and_decision(tmp_path):
    m = run(tmp_path).manifest
    t = m["timings"]
    assert set(t) == {"scanning_s", "scanner_execution_s", "evidence_validation_s", "decision_s"}
    assert all(v >= 0 for v in t.values())
    assert t["scanner_execution_s"] == pytest.approx(sum(s["execution"]["duration_s"] for s in m["scanners"]),
                                                     abs=0.01)
    assert t["evidence_validation_s"] == pytest.approx(sum(s["validation_s"] for s in m["scanners"]), abs=1e-4)


# ---------------------------------------------------------------- CLI and harness equivalence (FR-35)
@pytest.mark.parametrize("behaviours,expected", [
    ({}, "PASS"),
    ({"pip_audit": {"exit": 1, "stdout": pip_report([vulnerable_dep()])}}, "BLOCK"),
    ({"semgrep": {"exit": 0, "stdout": "{}"}}, "INCOMPLETE"),
])
def test_cli_and_library_give_identical_decisions(tmp_path, monkeypatch, behaviours, expected):
    monkeypatch.chdir(tmp_path)
    direct = SecureGate(policy(), runner=FakeRunner(**behaviours)).run(target=".", out_dir="direct")
    (tmp_path / "p.toml").write_text('strategy = "S3"\n[scanners.gitleaks]\nleak_exit_code = 3\n')
    code = cli.main(["--policy", "p.toml", "--out", "via-cli", "--no-summary"], runner=FakeRunner(**behaviours))
    via_cli = json.loads((tmp_path / "via-cli" / "run_manifest.json").read_text())
    assert direct.verdict.verdict == via_cli["verdict"]["verdict"] == expected
    assert code == direct.verdict.exit_code
    strip = lambda v: {k: v[k] for k in ("verdict", "exit_code", "reasons", "blocking_findings")}  # noqa: E731
    assert strip(direct.manifest["verdict"]) == strip(via_cli["verdict"])


# ---------------------------------------------------------------- downstream enforcement (FR-32, OBJ5)
def test_only_pass_lets_ci_continue(tmp_path, monkeypatch):
    """CI continues only on exit 0: BLOCK (1), INCOMPLETE (2) and config errors (3) all stop the job."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "p.toml").write_text('strategy = "S3"\n[scanners.gitleaks]\nleak_exit_code = 3\n')
    base = ["--policy", "p.toml", "--out", "o", "--no-summary"]
    codes = {
        "PASS": cli.main(base, runner=FakeRunner()),
        "BLOCK": cli.main(base, runner=FakeRunner(
            semgrep={"exit": 0, "stdout": semgrep_report([semgrep_result("ERROR")])})),
        "INCOMPLETE": cli.main(base, runner=FakeRunner(gitleaks={"launch_error": "TOOL_MISSING"})),
        "CONFIG": cli.main(["--policy", "missing.toml", "--no-summary"], runner=FakeRunner()),
    }
    assert codes == {"PASS": 0, "BLOCK": 1, "INCOMPLETE": 2, "CONFIG": 3}
