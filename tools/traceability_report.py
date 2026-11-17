"""Build the requirement traceability matrix and the test report from a real test run.

    python -m pytest -q --junitxml=test-results.xml
    python tools/traceability_report.py test-results.xml SecureGate_Project/docs

Writes traceability-matrix.md and test-report.md. Every status shown comes from the JUnit file
of that run; nothing is typed by hand.
"""

import re
import subprocess
import sys
import xml.etree.ElementTree as ET  # parsing our own pytest output, not untrusted input
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
        m = re.match(r"^\| ((?:N?FR)-\d\d)(?: [A-Za-z ]+)? \| ([^|]+)\|", line)
        if m and m.group(1) not in reqs:
            text = m.group(2).strip()
            reqs[m.group(1)] = text if len(text) < 110 else text[:107] + "..."
    return reqs


def results(junit):
    out = {}
    for case in ET.parse(junit).getroot().iter("testcase"):
        file = Path(case.get("classname").replace(".", "/")).name + ".py"
        name = case.get("name").split("[")[0]
        status = "failed" if case.find("failure") is not None or case.find("error") is not None else \
            "skipped" if case.find("skipped") is not None else "passed"
        key = f"{file}::{name}"
        prev = out.get(key, "passed")
        out[key] = status if status != "passed" else prev   # a parametrised test passes only if all cases pass
        out.setdefault(key + "#n", 0)
        out[key + "#n"] += 1
    return out


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True).stdout.strip()


def main(junit, out_dir):
    out_dir = Path(out_dir)
    reqs, res = requirements(), results(junit)
    root = ET.parse(junit).getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    stamp = (f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC from `{Path(junit).name}` "
             f"at commit `{git('rev-parse', '--short', 'HEAD')}` (branch `{git('rev-parse', '--abbrev-ref', 'HEAD')}`).")

    lines = ["# Requirement traceability matrix", "", stamp,
             "Source of the mapping: `tests/traceability.py` (enforced by `tests/test_traceability.py`).", "",
             "| Requirement | Summary | Verified by | Result |", "|---|---|---|---|"]
    status_count = Counter()
    for rid, text in reqs.items():
        tests = REQUIREMENT_TESTS.get(rid, [])
        if tests:
            states = [res.get(t, "not run") for t in tests]
            overall = "PASS" if all(s == "passed" for s in states) else "FAIL"
            shown = "<br>".join(f"`{t}`" + ("" if s == "passed" else f" ({s})") for t, s in zip(tests, states))
        else:
            overall, shown = "Verified outside unit tests", VERIFIED_OUTSIDE_UNIT_TESTS.get(rid, "**MISSING**")
        status_count[overall] += 1
        lines.append(f"| {rid} | {text} | {shown} | {overall} |")
    lines += ["", "**Summary:** " + ", ".join(f"{k}: {v}" for k, v in sorted(status_count.items())), ""]
    (out_dir / "traceability-matrix.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    per_file = Counter()
    for key, state in res.items():
        if not key.endswith("#n"):
            per_file[(key.split("::")[0], state)] += res[key + "#n"]
    files = sorted({f for f, _ in per_file})
    report = ["# Test report", "", stamp, "",
              f"- Test cases run: {suite.get('tests')}; failures: {suite.get('failures')}; errors: {suite.get('errors')}; "
              f"skipped: {suite.get('skipped')}; time: {float(suite.get('time')):.2f} s",
              "- Command: `python -m pytest -q --junitxml=test-results.xml`", "",
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


if __name__ == "__main__":
    main(*sys.argv[1:3])
