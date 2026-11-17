"""Test helpers: a fake process runner and realistic scanner outputs.

The fake runner replaces real scanner execution at the adapter boundary
(FR-34), so every fault can be injected without changing engine code.
"""

import json
from pathlib import Path

from security_engine.execution import ExecutionRecord, utc_now
from security_engine.policy import policy_from_dict

LEAK_CODE = 3


def semgrep_report(results=None, errors=None, scanned=("app.py",)):
    report = {"results": results or [], "errors": errors or []}
    if scanned is not None:
        report["paths"] = {"scanned": list(scanned)}
    return json.dumps(report)


def semgrep_result(severity="ERROR", rule="python.test.rule", path="app.py", line=3):
    return {"check_id": rule, "path": path, "start": {"line": line},
            "extra": {"severity": severity, "message": "Synthetic finding"}}


def pip_report(dependencies=None):
    return json.dumps({"dependencies": dependencies if dependencies is not None
                       else [{"name": "flask", "version": "3.0.3", "vulns": []}], "fixes": []})


def vulnerable_dep():
    return {"name": "urllib3", "version": "1.26.5",
            "vulns": [{"id": "PYSEC-TEST-1", "description": "Synthetic vulnerability"}]}


def gitleaks_report(leaks=0):
    return json.dumps([{"RuleID": "generic-api-key", "Description": "Synthetic leak",
                        "File": "config.py", "StartLine": 2 + i} for i in range(leaks)])


CLEAN = {
    "semgrep": {"exit": 0, "stdout": semgrep_report()},
    "pip-audit": {"exit": 0, "stdout": pip_report()},
    "gitleaks": {"exit": 0, "report": gitleaks_report(0)},
}


class FakeRunner:
    """Pretends to run scanners. Each behaviour is a dict with optional keys:
    exit, stdout, stderr, report (Gitleaks file content), launch_error, raise_error."""

    def __init__(self, **behaviours):
        self.behaviours = {**CLEAN}
        for key, value in behaviours.items():
            self.behaviours[key.replace("_", "-")] = value
        self.calls = []

    @staticmethod
    def _tool(command):
        name = Path(command[0]).name
        for tool in ("pip-audit", "semgrep", "gitleaks"):
            if tool in name:
                return tool
        raise AssertionError(f"unexpected command {command}")

    def run(self, command, timeout, cwd=None):
        command = [str(c) for c in command]
        tool = self._tool(command)
        if "--version" in command or command[1:2] == ["version"]:
            return ExecutionRecord(command, utc_now(), 0.01, 0, stdout=f"{tool} 9.9.9-fake")
        self.calls.append((tool, command, timeout))
        b = self.behaviours[tool]
        if b.get("raise_error"):
            raise RuntimeError("synthetic engine fault")
        if b.get("launch_error"):
            return ExecutionRecord(command, utc_now(), 0.01, None, launch_error=b["launch_error"],
                                   launch_detail=f"synthetic {b['launch_error']}")
        if tool == "gitleaks" and b.get("report") is not None:
            path = Path(command[command.index("--report-path") + 1])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(b["report"], encoding="utf-8")
        return ExecutionRecord(command, utc_now(), 0.05, b.get("exit", 0),
                               stdout=b.get("stdout", ""), stderr=b.get("stderr", ""))


def policy(strategy="S3", **overrides):
    raw = {"strategy": strategy,
           "scanners": {"gitleaks": {"leak_exit_code": LEAK_CODE}}}
    raw.update(overrides)
    return policy_from_dict(raw)
