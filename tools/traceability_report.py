"""Run the test suite and build the requirement traceability matrix and the test report from it.

    python tools/traceability_report.py SecureGate_Project/docs

Writes traceability-matrix.md and test-report.md. Every status shown comes from the test run made
by this script (pytest in-process, outcomes collected by a small plugin); nothing is typed by hand.
No XML is parsed (SecureGate's own Semgrep gate flagged the earlier JUnit-XML version).
"""

import re
import subprocess
import sys
import time

import pytest
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from traceability import REQUIREMENT_TESTS, VERIFIED_OUTSIDE_UNIT_TESTS  # noqa: E402

REQ_DOC = ROOT / "SecureGate_Project" / "docs" / "requirements" / "engine-requirements-v1.md"


def requirements():
    reqs = {}
    for line in REQ_DOC.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\| ((?:N?FR)-\d\d[a-z]?)(?: [A-Za-z ]+)? \| ([^|]+)\|", line)
        if m and m.group(1) not in reqs:
            text = m.group(2).strip()
            reqs[m.group(1)] = text if len(text) < 110 else text[:107].rsplit(" ", 1)[0].rstrip(",;:(") + " …"
    return reqs


class _Collector:
    def __init__(self):
        self.outcomes = {}   # "file.py::test_name" -> list of outcomes (one per parametrised case)

    def pytest_runtest_logreport(self, report):
        if report.when == "call" or (report.when == "setup" and report.outcome != "passed"):
            file, _, name = report.nodeid.partition("::")
            key = f"{Path(file).name}::{name.split('[')[0]}"
            self.outcomes.setdefault(key, []).append(report.outcome)


def run_tests():
    collector = _Collector()
    started = time.perf_counter()
    code = pytest.main(["-q", "-p", "no:cacheprovider", str(ROOT / "tests")], plugins=[collector])
    return collector.outcomes, int(code), time.perf_counter() - started


def status(outcomes):
    return "failed" if "failed" in outcomes else "skipped" if "skipped" in outcomes else "passed"


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True).stdout.strip()


def main(out_dir):
    out_dir = Path(out_dir)
    reqs = requirements()
    outcomes, exit_code, elapsed = run_tests()
    res = {k: status(v) for k, v in outcomes.items()}
    stamp = (f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC by `tools/traceability_report.py` "
             f"at commit `{git('rev-parse', '--short', 'HEAD')}` "
             f"(branch `{git('rev-parse', '--abbrev-ref', 'HEAD')}`).")

    lines = ["# Requirement traceability matrix", "", stamp,
             "Source of the mapping: `tests/traceability.py` (enforced by `tests/test_traceability.py`).", "",
             "| Requirement | Summary | Verified by | Result |", "|---|---|---|---|"]
    status_count = Counter()
    for rid, text in reqs.items():
        tests = REQUIREMENT_TESTS.get(rid, [])
        if tests:
            states = [res.get(t, "not run") for t in tests]
            overall = "PASS" if all(s == "passed" for s in states) else "FAIL"
            shown = "<br>".join(f"`{t}`" + ("" if s == "passed" else f" ({s})")
                                for t, s in zip(tests, states, strict=True))
        else:
            overall, shown = "Verified outside unit tests", VERIFIED_OUTSIDE_UNIT_TESTS.get(rid, "**MISSING**")
        status_count[overall] += 1
        lines.append(f"| {rid} | {text} | {shown} | {overall} |")
    lines += ["", "**Summary:** " + ", ".join(f"{k}: {v}" for k, v in sorted(status_count.items())), ""]
    (out_dir / "traceability-matrix.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    per_file = Counter()
    for key, outs in outcomes.items():
        for o in outs:
            per_file[(key.split("::")[0], o)] += 1
    total = sum(per_file.values())
    files = sorted({f for f, _ in per_file})
    report = ["# Test report", "", stamp, "",
              f"- Test cases run: {total}; passed: {sum(v for (f, o), v in per_file.items() if o == 'passed')}; "
              f"failed: {sum(v for (f, o), v in per_file.items() if o == 'failed')}; "
              f"skipped: {sum(v for (f, o), v in per_file.items() if o == 'skipped')}; pytest exit code {exit_code}; "
              f"time: {elapsed:.2f} s",
              "- Command: `python tools/traceability_report.py SecureGate_Project/docs` (runs pytest on `tests/`)", "",
              "| Test file | What it covers | Passed | Failed | Skipped |", "|---|---|---|---|---|"]
    about = {
        "test_app.py": "Flask app health check (Semester 7)",
        "test_scanners.py": "Semester 7 scanner wrappers (unchanged)",
        "test_security_engine.py": "Semester 7 engine (unchanged, NFR-06)",
        "test_gate.py": "Engine v2: probes C0-C13c under S0/S3, policy, CLI, manifest, real subprocesses",
        "test_live_outputs.py": "Real scanner outputs recorded in EXP-00 (simulated replay of real data)",
        "test_completion.py": "Gap closures: records, rule sources, isolation, coverage, schema, redaction, timings, "
                              "CLI/library equivalence",
        "test_traceability.py": "Traceability completeness and static guarantees (no shell, non-root Docker)",
    }
    for f in files:
        report.append(f"| `{f}` | {about.get(f, '')} | {per_file[(f, 'passed')]} | {per_file[(f, 'failed')]} | "
                      f"{per_file[(f, 'skipped')]} |")
    report += ["", "Real-binary tests: `test_gate.py::test_real_*` start real subprocesses (Python stand-ins for "
               "timeouts, crashes and missing executables). The real Semgrep, pip-audit and Gitleaks binaries are "
               "exercised in CI (`ci-security.yml`) and in EXP-00/EXP-01 L2, not in this unit-test run.", ""]
    (out_dir / "test-report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(f"wrote {out_dir / 'traceability-matrix.md'} and {out_dir / 'test-report.md'}; {dict(status_count)}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]) if len(sys.argv) > 1 else "usage: traceability_report.py OUT_DIR")
