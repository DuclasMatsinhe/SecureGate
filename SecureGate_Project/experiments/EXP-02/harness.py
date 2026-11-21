"""SecureGate experiment harness, EXP-02 (final study).

Three levels, never pooled in one results table:

  L1  SIMULATED.  Real scanner outputs recorded in EXP-00 are replayed at the adapter
      boundary, with deterministic fault edits. No scanner binary runs. Arms S0-S3.
  L2  REAL BINARIES, SYNTHETIC TARGETS.  The pinned Semgrep, pip-audit and Gitleaks run
      through the securegate CLI on synthetic projects. Faults are applied to the real
      execution by wrapper executables (execution level) or by real inputs that make the
      real tool fail (real-induced). Arms S0-S3 and S3P (S3 + optional parse check, FR-14a).
  R   REAL BINARIES, REAL PROJECTS.  Five public Python repositories pinned to a commit,
      scanned read-only. Baseline runs are observed (no ground truth); faulted runs use the
      same wrappers as L2, so their ground truth is "the faulted scanner's evidence is invalid".

Every cell's expected outcome is written in protocol.json before any run. The protocol is
frozen by recording its SHA-256 in FROZEN.sha256; final runs refuse to start if it differs.
All secrets are synthetic and generated at run time; nothing secret is stored.

Usage:
  python harness.py protocol --out protocol.json
  python harness.py run --level L2 --shard 1/5 --reps 10 --out results/L2-1 [--final]
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

from security_engine import __version__ as ENGINE_VERSION  # noqa: E402
from security_engine.execution import ExecutionRecord, utc_now  # noqa: E402
from security_engine.gate import SecureGate  # noqa: E402
from security_engine.policy import policy_from_dict  # noqa: E402

PROTOCOL_VERSION = "EXP-02 v1"
SCANNERS = ("semgrep", "pip-audit", "gitleaks")
LEAK_CODE = 3
REC = HERE / "inputs" / "recorded"

# Arm -> (strategy, parse_check). S0-S3 are the strategies of FR-23; S3P adds the optional
# FR-14a parse check to S3 and is reported separately.
ARMS = {"S0": ("S0", False), "S1": ("S1", False), "S2": ("S2", False), "S3": ("S3", False), "S3P": ("S3", True)}
LEVEL_ARMS = {"L1": ("S0", "S1", "S2", "S3"), "L2": tuple(ARMS), "R": tuple(ARMS)}

FAULTS = {
    "F1": ("executable missing", ["TOOL_MISSING"]),
    "F2": ("crash: unexpected non-zero exit, no report", ["NONZERO_EXIT"]),
    "F3": ("timeout / hang", ["TIMEOUT"]),
    "F4": ("missing report (exit 0, nothing written)", ["NO_OUTPUT"]),
    "F5": ("empty report (zero bytes / whitespace)", ["NO_OUTPUT"]),
    "F6": ("schema-invalid report ({})", ["SCHEMA_INVALID"]),
    "F7": ("truncated JSON (cut at 50%)", ["INVALID_JSON"]),
    "F8": ("no coverage (scanned nothing)", ["NO_COVERAGE"]),
    "F9": ("partial coverage (some inputs skipped or failed)", ["PARTIAL_COVERAGE"]),
    "F10": ("exit status inconsistent with report", ["INCONSISTENT_EXIT", "NONZERO_EXIT"]),
}

# Pinned public repositories for level R (read-only; fully pinned requirements.txt at the root).
# Commit first, then URL: a 40-hex commit placed right after a name ending in "api" reads as a
# generic API key to Gitleaks (false positive in commit 5383c6b, listed in .gitleaksignore).
REAL_REPOS = {
    "microblog": ("a975ef64864354867c88e0ed3a17ba7d17dca752", "https://github.com/miguelgrinberg/microblog"),
    "microblog-api": ("e250d7115b47010ff0e7051d5868485fff4e32fb", "https://github.com/miguelgrinberg/microblog-api"),
    "flasky": ("3beedd640b9146b0bd65c8c2ecf402b01798bc33", "https://github.com/miguelgrinberg/flasky"),
    "flask-by-example": ("532c0ea8ed6fc8add43dd5ad74daa98065f723aa", "https://github.com/realpython/flask-by-example"),
    "discover-flask": ("00762e9ee9e5713cb61ca8734236d05d6e424da9", "https://github.com/realpython/discover-flask"),
}
R_FAULTS = ("F2", "F4", "F7")  # one execution fault and two report faults per scanner and repository

# pip-audit audits the pinned requirements as written (no resolution, no package builds); see DEC-016.
PIP_AUDIT_ARGS = ["--no-deps", "--disable-pip"]


@dataclass
class Cell:
    cell_id: str
    level: str
    kind: str  # C clean control, K known finding, F fault, FK fault + finding elsewhere, B real-repo baseline
    fault: str = "F0"
    faulted: tuple = ()
    finding_in: tuple = ()
    realisation: str = ""
    expected_category: tuple = ()
    ground_truth: str = ""  # PASS, BLOCK, NOT_PASS (fault) or OBSERVED (baseline)
    prediction: dict = field(default_factory=dict)  # arm -> predicted verdict, where a known limit applies
    notes: str = ""
    target: dict = field(default_factory=dict)
    policy: dict = field(default_factory=dict)
    behaviour: dict = field(default_factory=dict)


def _gt(kind):
    return {"C": "PASS", "K": "BLOCK", "F": "NOT_PASS", "FK": "NOT_PASS", "B": "OBSERVED"}[kind]


def _cell(cell_id, level, kind, fault="F0", faulted=(), finding_in=(), **kw):
    exp = tuple(FAULTS[fault][1]) if fault != "F0" else ()
    return Cell(cell_id, level, kind, fault, tuple(faulted), tuple(finding_in),
                expected_category=exp, ground_truth=_gt(kind), **kw)


# ====================================================================== L1 (simulated)
def _read(name):
    return (REC / name).read_text(encoding="utf-8")


def _clean_pip_audit():
    """Derived from the real flask 3.0.3 recording with its vulnerabilities removed (labelled derived)."""
    data = json.loads(_read("pip_audit_flask303.json"))
    for dep in data["dependencies"]:
        dep["vulns"] = []
    data["fixes"] = []
    return json.dumps(data)


def _base(scanner, finding):
    if scanner == "semgrep":
        return {"exit": 0, "stdout": _read("semgrep_finding.json" if finding else "semgrep_clean.json")}
    if scanner == "pip-audit":
        return ({"exit": 1, "stdout": _read("pip_audit_vulnerable.json")} if finding
                else {"exit": 0, "stdout": _clean_pip_audit()})
    if finding:
        return {"exit": LEAK_CODE, "report": _read("gitleaks_leak_report.json"), "stderr": _read("gitleaks_leak.stderr")}
    return {"exit": 0, "report": _read("gitleaks_clean_report.json"), "stderr": _read("gitleaks_clean.stderr")}


def _l1_fault(scanner, fault):
    """Return (behaviour, realisation) or None when the fault does not apply to this scanner."""
    clean = _base(scanner, finding=False)
    key = "report" if scanner == "gitleaks" else "stdout"
    payload = clean[key]
    if fault == "F1":
        return {"launch_error": "TOOL_MISSING"}, "launch error: executable not found"
    if fault == "F2":
        code = 1 if scanner == "gitleaks" else 2
        return {"exit": code, "stdout": "", "report": None, "stderr": "synthetic crash"}, f"exit {code}, no report"
    if fault == "F3":
        return {"launch_error": "TIMEOUT"}, "killed after the policy timeout"
    if fault == "F4":
        return {**clean, key: None if scanner == "gitleaks" else ""}, "exit 0, report not written"
    if fault == "F5":
        return {**clean, key: "  \n"}, "exit 0, whitespace-only report"
    if fault == "F6":
        return {**clean, key: "{}"}, "exit 0, report is {}"
    if fault == "F7":
        return {**clean, key: payload[: len(payload) // 2]}, "exit 0, report cut at 50% of bytes"
    if fault == "F8":
        if scanner == "semgrep":
            return {"exit": 0, "stdout": _read("semgrep_no_files.json")}, "recorded real SG06: paths.scanned empty"
        if scanner == "gitleaks":
            return ({"exit": 0, "report": "[]", "stderr": _read("gitleaks_not_a_repo.stderr")},
                    "recorded real GL05: not a git repository, 0 commits scanned")
        return {"exit": 0, "stdout": json.dumps({"dependencies": [], "fixes": []})}, "dependencies list empty"
    if fault == "F9":
        if scanner == "semgrep":
            data = json.loads(payload)
            data.setdefault("paths", {})["skipped"] = [{"path": "broken.py",
                                                       "reason": "analysis_failed_parser_or_internal_error"}]
            return {"exit": 0, "stdout": json.dumps(data)}, "paths.skipped holds an analysis failure"
        if scanner == "pip-audit":
            data = json.loads(payload)
            data["dependencies"].append({"name": "securegate-nonexistent-probe-package",
                                         "skip_reason": "Dependency not found on PyPI and could not be audited"})
            return {"exit": 0, "stdout": json.dumps(data)}, "one dependency has skip_reason"
        return None
    if fault == "F10":
        if scanner == "semgrep":
            return {"exit": 1, "stdout": payload}, "exit 1 (findings) but results empty"
        if scanner == "pip-audit":
            return {"exit": 1, "stdout": payload}, "exit 1 (vulnerabilities) but none reported"
        return {"exit": LEAK_CODE, "report": "[]", "stderr": ""}, "leak exit code but empty report"
    raise ValueError(fault)


def l1_cells():
    cells = [_cell("L1-C-clean", "L1", "C", realisation="all three scanners: recorded clean outputs")]
    for s in SCANNERS:
        cells.append(_cell(f"L1-K-{s}", "L1", "K", finding_in=(s,), realisation=f"recorded real finding ({s})"))
    for fault in FAULTS:
        for s in SCANNERS:
            made = _l1_fault(s, fault)
            if made:
                cells.append(_cell(f"L1-{fault}-{s}", "L1", "F", fault, (s,), realisation=made[1],
                                   behaviour={s: made[0]}))
    for fault in ("F1", "F2", "F6", "F8"):
        for bad in SCANNERS:
            for good in SCANNERS:
                if bad != good:
                    made = _l1_fault(bad, fault)
                    cells.append(_cell(f"L1-{fault}-{bad}+K-{good}", "L1", "FK", fault, (bad,), (good,),
                                       realisation=made[1], behaviour={bad: made[0]}))
    for combo in (("semgrep", "pip-audit"), SCANNERS):
        cells.append(_cell(f"L1-F1x{len(combo)}", "L1", "F", "F1", combo, realisation="all listed scanners missing",
                           behaviour={s: {"launch_error": "TOOL_MISSING"} for s in combo}))
    return cells


class ReplayRunner:
    """Replays scanner behaviours at the adapter boundary. Same contract as the real CommandRunner."""

    def __init__(self, behaviours):
        self.behaviours = behaviours

    def run(self, command, timeout, cwd=None):
        command = [str(c) for c in command]
        tool = next(t for t in ("pip-audit", "semgrep", "gitleaks") if t in Path(command[0]).name)
        if "--version" in command or command[1:2] == ["version"]:
            return ExecutionRecord(command, utc_now(), 0.0, 0, stdout=f"{tool} replayed (EXP-00 recordings)")
        b = self.behaviours[tool]
        if b.get("launch_error"):
            return ExecutionRecord(command, utc_now(), 0.0, None, launch_error=b["launch_error"],
                                   launch_detail="injected (L1)")
        if tool == "gitleaks" and b.get("report") is not None:
            path = Path(command[command.index("--report-path") + 1])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(b["report"], encoding="utf-8")
        return ExecutionRecord(command, utc_now(), 0.0, b.get("exit", 0), stdout=b.get("stdout") or "",
                               stderr=b.get("stderr", ""))


# ====================================================================== L2 and R (real binaries)
RULES = (
    "rules:\n"
    "  - id: probe-eval\n    pattern: eval(...)\n    message: Use of eval (synthetic probe rule)\n"
    "    languages: [python]\n    severity: ERROR\n"
    "  - id: probe-pickle-loads\n    pattern: pickle.loads(...)\n    message: Unpickling data (synthetic probe rule)\n"
    "    languages: [python]\n    severity: ERROR\n"
)
CLEAN_PY = "def add(a, b):\n    return a + b\n"
FINDING_EVAL = "def run(user_input):\n    return eval(user_input)\n"
FINDING_PICKLE = "import pickle\n\n\ndef load(blob):\n    return pickle.loads(blob)\n"
BROKEN_PY = "def broken(:\n    return 1\n"
CLEAN_REQ = "six==1.17.0\n"
CLEAN_REQ_2 = "six==1.17.0\nattrs==25.3.0\n"
VULN_REQ = "urllib3==1.26.5\n"
VULN_REQ_2 = "jinja2==2.10\n"
MISSING_REQ = "securegate-nonexistent-probe-package==0.0.1\n"

TARGETS = {
    # name: spec (materialised at run time; secrets generated then, never stored)
    "t-clean": {"files": {"app.py": CLEAN_PY}, "req": CLEAN_REQ},
    "t-clean-pkg": {"files": {"pkg/__init__.py": "", "pkg/core.py": CLEAN_PY,
                              "pkg/util.py": "def double(x):\n    return 2 * x\n",
                              "main.py": "from pkg.core import add\n\nprint(add(1, 2))\n"}, "req": CLEAN_REQ_2},
    "t-clean-history": {"files": {"app.py": CLEAN_PY}, "req": CLEAN_REQ, "history": 3},
    "t-sast-eval": {"files": {"app.py": FINDING_EVAL}, "req": CLEAN_REQ},
    "t-sast-pickle": {"files": {"app.py": FINDING_PICKLE}, "req": CLEAN_REQ},
    "t-sca-urllib3": {"files": {"app.py": CLEAN_PY}, "req": VULN_REQ},
    "t-sca-jinja2": {"files": {"app.py": CLEAN_PY}, "req": VULN_REQ_2},
    "t-secret-github": {"files": {"app.py": CLEAN_PY}, "req": CLEAN_REQ, "secret": "github"},
    "t-secret-aws": {"files": {"app.py": CLEAN_PY}, "req": CLEAN_REQ, "secret": "aws"},
    "t-nopy": {"files": {}, "req": CLEAN_REQ},
    "t-nogit": {"files": {"app.py": CLEAN_PY}, "req": CLEAN_REQ, "secret": "github", "git": False},
    "t-noreq": {"files": {"app.py": CLEAN_PY}, "req": ""},
    "t-broken": {"files": {"app.py": CLEAN_PY, "broken.py": BROKEN_PY}, "req": CLEAN_REQ},
    "t-missingpkg": {"files": {"app.py": CLEAN_PY}, "req": CLEAN_REQ + MISSING_REQ},
}

WRAPPER = r'''#!{python}
"""SecureGate EXP-02 fault wrapper (synthetic). Mode: {mode}. Real tool: {real}."""
import subprocess, sys, time
from pathlib import Path
mode, real, args = "{mode}", "{real}", sys.argv[1:]
if "--version" in args or args[:1] == ["version"]:
    sys.exit(subprocess.call([real] + args))
report = Path(args[args.index("--report-path") + 1]) if "--report-path" in args else None
if mode == "crash":
    sys.stderr.write("synthetic crash (wrapper)\n"); sys.exit(2)
if mode == "hang":
    time.sleep(120); sys.exit(0)
if mode == "silent":
    sys.exit(0)
p = subprocess.run([real] + args, capture_output=True, text=True)
sys.stderr.write(p.stderr)
text = report.read_text() if report and report.exists() else p.stdout
if mode == "empty":
    text, code = "  \n", p.returncode
elif mode == "schema":
    text, code = "{{}}", 0
elif mode == "truncate":
    text, code = text[: len(text) // 2], p.returncode
elif mode.startswith("exitlie:"):
    code = int(mode.split(":")[1])
else:
    sys.exit(97)
if report:
    report.write_text(text)
else:
    sys.stdout.write(text)
sys.exit(code)
'''
WRAPPER_FAULTS = {"F2": "crash", "F3": "hang", "F4": "silent", "F5": "empty", "F6": "schema", "F7": "truncate",
                  "F10": "exitlie"}
EXITLIE_CODE = {"semgrep": 1, "pip-audit": 1, "gitleaks": LEAK_CODE}


def wrapper_mode(fault, scanner):
    mode = WRAPPER_FAULTS[fault]
    return f"exitlie:{EXITLIE_CODE[scanner]}" if mode == "exitlie" else mode


def _wrapped(fault, scanner):
    mode = wrapper_mode(fault, scanner)
    pol = {scanner: {"executable": f"@wrapper:{scanner}:{mode}"}}
    if fault == "F3":
        pol[scanner]["timeout"] = 3
    return pol, f"wrapper executable ({mode})"


def l2_cells():
    cells = []
    add = cells.append
    for t in ("t-clean", "t-clean-pkg", "t-clean-history"):
        add(_cell(f"L2-C-{t[2:]}", "L2", "C", realisation=f"real tools, synthetic project {t}", target={"name": t}))
    known = {"semgrep": ("t-sast-eval", "t-sast-pickle"), "pip-audit": ("t-sca-urllib3", "t-sca-jinja2"),
             "gitleaks": ("t-secret-github", "t-secret-aws")}
    for s, targets in known.items():
        for t in targets:
            add(_cell(f"L2-K-{t[2:]}", "L2", "K", finding_in=(s,), realisation=f"known finding in {t}",
                      target={"name": t}))
    for fault in WRAPPER_FAULTS:
        for s in SCANNERS:
            pol, how = _wrapped(fault, s)
            add(_cell(f"L2-{fault}-{s}", "L2", "F", fault, (s,), realisation=f"execution level: {how}",
                      target={"name": "t-clean"}, policy=pol))
    for s in SCANNERS:
        add(_cell(f"L2-F1-{s}", "L2", "F", "F1", (s,), realisation="executable path does not exist",
                  target={"name": "t-clean"}, policy={s: {"executable": "@missing"}}))
    add(_cell("L2-F8-semgrep", "L2", "F", "F8", ("semgrep",), realisation="real-induced: no Python files",
              target={"name": "t-nopy"}))
    add(_cell("L2-F8-gitleaks", "L2", "F", "F8", ("gitleaks",),
              realisation="real-induced: folder is not a git repository (holds a synthetic token)",
              target={"name": "t-nogit"}))
    add(_cell("L2-F8-pip-audit", "L2", "F", "F8", ("pip-audit",), realisation="real-induced: empty requirements file",
              target={"name": "t-noreq"}))
    add(_cell("L2-F9-semgrep", "L2", "F", "F9", ("semgrep",), realisation="real-induced: one file with a syntax error",
              target={"name": "t-broken"},
              prediction={"S2": "PASS", "S3": "PASS", "S3P": "INCOMPLETE"},
              notes="EXP-01: Semgrep 1.180.0 lists the file as scanned and reports no error; only the FR-14a "
                    "parse check (S3P) is predicted to detect it"))
    add(_cell("L2-F9-pip-audit", "L2", "F", "F9", ("pip-audit",),
              realisation="real-induced: pinned requirement not on PyPI (audited with --no-deps --disable-pip)",
              target={"name": "t-missingpkg"},
              notes="Replaces the EXP-01 realisation, where pip's resolver failed instead of skipping (DEC-016)"))
    add(_cell("L2-F10b-gitleaks", "L2", "F", "F10", ("gitleaks",),
              realisation="real-induced: invalid Gitleaks config (exit 1 = error code, leak code is 3)",
              target={"name": "t-clean"}, policy={"gitleaks": {"config": "@badconfig"}}))
    partial = [("F1", "semgrep", "pip-audit", "t-sca-urllib3"), ("F2", "pip-audit", "semgrep", "t-sast-eval"),
               ("F3", "gitleaks", "semgrep", "t-sast-eval"), ("F7", "semgrep", "gitleaks", "t-secret-github"),
               ("F4", "pip-audit", "gitleaks", "t-secret-github"), ("F6", "gitleaks", "pip-audit", "t-sca-urllib3")]
    for fault, bad, good, t in partial:
        if fault == "F1":
            pol, how = {bad: {"executable": "@missing"}}, "executable path does not exist"
        else:
            pol, how = _wrapped(fault, bad)
        add(_cell(f"L2-{fault}-{bad}+K-{good}", "L2", "FK", fault, (bad,), (good,),
                  realisation=f"{bad}: {how}; {good} holds a known finding", target={"name": t}, policy=pol))
    add(_cell("L2-F1x3", "L2", "F", "F1", SCANNERS, realisation="all scanners missing", target={"name": "t-clean"},
              policy={s: {"executable": "@missing"} for s in SCANNERS}))
    return cells


def r_cells():
    cells = []
    for name, (commit, url) in REAL_REPOS.items():
        target = {"repo": name, "url": url, "commit": commit}
        cells.append(_cell(f"R-{name}-base", "R", "B", realisation=f"{url} @ {commit[:7]}, no fault", target=target,
                           notes="observed: no ground truth for the unmodified project"))
        for fault in R_FAULTS:
            for s in SCANNERS:
                pol, how = _wrapped(fault, s)
                cells.append(_cell(f"R-{name}-{fault}-{s}", "R", "F", fault, (s,), realisation=f"{how} on {name}",
                                   target=target, policy=pol))
    return cells


def all_cells(level):
    return {"L1": l1_cells, "L2": l2_cells, "R": r_cells}[level]()


# ---------------------------------------------------------------------- materialisation
def _git(repo, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


def _secret(kind):
    if kind == "github":
        token = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
        return f'GITHUB_TOKEN = "{token}"\n'
    key = "AKIA" + "".join(secrets.choice(string.ascii_uppercase + "234567") for _ in range(16))
    return f'AWS_ACCESS_KEY_ID = "{key}"\n'


def make_synthetic(root, name):
    spec = TARGETS[name]
    t = root / name
    t.mkdir(parents=True)
    for rel, text in spec["files"].items():
        (t / rel).parent.mkdir(parents=True, exist_ok=True)
        (t / rel).write_text(text)
    (t / "requirements.txt").write_text(spec["req"])
    if spec.get("secret"):
        (t / "settings.py").write_text(_secret(spec["secret"]))
    if spec.get("git", True):
        _git(t, "init", "-q")
        _git(t, "add", ".")
        _git(t, "commit", "-q", "-m", "fixture")
        for i in range(1, spec.get("history", 1)):
            (t / "CHANGES.txt").write_text(f"revision {i}\n")
            _git(t, "add", ".")
            _git(t, "commit", "-q", "-m", f"fixture revision {i}")
    return t


def fetch_repo(root, name, url, commit):
    t = root / name
    t.mkdir(parents=True)
    _git(t, "init", "-q")
    _git(t, "fetch", "-q", "--depth", "1", url, commit)
    _git(t, "checkout", "-q", "FETCH_HEAD")
    head = subprocess.run(["git", "-C", str(t), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if head != commit:
        raise RuntimeError(f"{name}: checked out {head}, expected {commit}")
    return t


class Workspace:
    def __init__(self, tools):
        self.root = Path(tempfile.mkdtemp(prefix="sg_exp02_"))
        self.tools = tools
        self.targets = {}
        (self.root / "wrappers").mkdir()
        self.rules = self.root / "rules.yml"
        self.rules.write_text(RULES)
        self.bad_config = self.root / "gitleaks-bad.toml"
        self.bad_config.write_text("[[rules]]\nid = \nregex = '''unclosed\n")

    def target(self, spec):
        key = spec.get("name") or spec["repo"]
        if key not in self.targets:
            if "name" in spec:
                self.targets[key] = make_synthetic(self.root / "targets", key)
            else:
                self.targets[key] = fetch_repo(self.root / "repos", key, spec["url"], spec["commit"])
        return self.targets[key]

    def resolve(self, value):
        if value == "@missing":
            return str(self.root / "not-installed" / "tool")
        if value == "@badconfig":
            return str(self.bad_config)
        if isinstance(value, str) and value.startswith("@wrapper:"):
            _, scanner, mode = value.split(":", 2)
            w = self.root / "wrappers" / f"{scanner}-{mode.replace(':', '-')}"
            if not w.exists():
                w.write_text(WRAPPER.format(python=sys.executable, mode=mode, real=self.tools[scanner]))
                w.chmod(0o755)
            return str(w)
        return value

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def toml_value(v):
    return json.dumps(v) if not isinstance(v, bool) else ("true" if v else "false")


def write_policy(path, arm, overrides, ws):
    strategy, parse_check = ARMS[arm]
    scanners = {
        "semgrep": {"config": str(ws.rules), "timeout": 300, "parse_check": parse_check},
        "pip-audit": {"timeout": 300, "extra_args": PIP_AUDIT_ARGS},
        "gitleaks": {"leak_exit_code": LEAK_CODE, "timeout": 300},
    }
    for s, extra in overrides.items():
        scanners[s].update({k: ws.resolve(v) for k, v in extra.items()})
    lines = [f'version = "{PROTOCOL_VERSION}"', f'strategy = "{strategy}"', 'on_incomplete = "block"', ""]
    for s, cfg in scanners.items():
        lines.append(f"[scanners.{s}]")
        lines += [f"{k} = {toml_value(v)}" for k, v in cfg.items()]
        lines.append("")
    path.write_text("\n".join(lines))


# ====================================================================== runs
def row(cell, arm, rep, manifest, exit_code, wall):
    by = {s["scanner"]: s for s in manifest["scanners"]}
    verdict = manifest["verdict"]
    faulted_cats = [by[s]["category"] for s in cell.faulted if s in by]
    preserved = [s for s in cell.finding_in
                 if any(r["code"] == "BLOCKING_FINDING" and r["scanner"] == s for r in verdict["reasons"])]
    return {
        "level": cell.level, "cell_id": cell.cell_id, "kind": cell.kind, "fault": cell.fault,
        "faulted": "+".join(cell.faulted), "finding_in": "+".join(cell.finding_in),
        "arm": arm, "strategy": ARMS[arm][0], "parse_check": ARMS[arm][1], "rep": rep,
        "ground_truth": cell.ground_truth, "verdict": verdict["verdict"], "exit_code": exit_code,
        "faulted_categories": "+".join(c or "VALID" for c in faulted_cats),
        "all_categories": ";".join(f"{s}:{by[s]['category'] or 'VALID'}" for s in SCANNERS if s in by),
        "category_correct": bool(cell.faulted) and all(c in cell.expected_category for c in faulted_cats),
        "findings_preserved": (len(preserved) == len(cell.finding_in)) if cell.finding_in else "",
        "blocking_findings": verdict.get("blocking_findings", ""),
        "reason_codes": ";".join(sorted({f"{r['scanner']}:{r['code']}" for r in verdict["reasons"]})),
        "wall_s": round(wall, 4), "duration_s": manifest["duration_s"],
        **{k: manifest["timings"][k] for k in ("scanner_execution_s", "evidence_validation_s", "decision_s")},
        "run_id": manifest["run_id"], "started_at": manifest.get("started_at", ""),
        "policy_sha256": manifest["policy"]["sha256"],
        "scanner_versions": ";".join(f"{s['scanner']}={s['version']}" for s in manifest["scanners"]),
    }


def run_l1(cells, arms, reps, out):
    rows = []
    for cell in cells:
        behaviours = {s: _base(s, s in cell.finding_in) for s in SCANNERS}
        behaviours.update(cell.behaviour)
        for arm in arms:
            strategy, _ = ARMS[arm]
            pol = policy_from_dict({"strategy": strategy, "scanners": {"gitleaks": {"leak_exit_code": LEAK_CODE}}})
            for rep in range(1, reps + 1):
                run_dir = out / "runs" / cell.cell_id / f"{arm}-r{rep}"
                target = Path(tempfile.mkdtemp(prefix="sg_l1_"))
                started = time.perf_counter()
                result = SecureGate(pol, runner=ReplayRunner(behaviours)).run(target=str(target), out_dir=str(run_dir))
                wall = time.perf_counter() - started
                shutil.rmtree(target, ignore_errors=True)
                rows.append(row(cell, arm, rep, result.manifest, result.verdict.exit_code, wall))
    return rows


def run_real(cells, arms, reps, out, tools):
    ws, rows = Workspace(tools), []
    try:
        for cell in cells:
            try:
                target = ws.target(cell.target)
            except Exception as exc:  # noqa: BLE001 - recorded, never hidden
                (out / "errors.txt").open("a").write(f"{cell.cell_id}: target not prepared: {exc}\n")
                continue
            for arm in arms:
                for rep in range(1, reps + 1):
                    run_dir = (out / "runs" / cell.cell_id / f"{arm}-r{rep}").resolve()
                    run_dir.mkdir(parents=True, exist_ok=True)
                    pol = run_dir / "policy.toml"
                    write_policy(pol, arm, cell.policy, ws)
                    started = time.perf_counter()
                    proc = subprocess.run([sys.executable, "-m", "security_engine.cli", "--target", str(target),
                                           "--policy", str(pol), "--out", str(run_dir), "--no-summary"],
                                          cwd=REPO, capture_output=True, text=True, timeout=1200)
                    wall = time.perf_counter() - started
                    (run_dir / "cli_stdout.json").write_text(proc.stdout)
                    manifest = json.loads((run_dir / "run_manifest.json").read_text())
                    rows.append(row(cell, arm, rep, manifest, proc.returncode, wall))
                    print(f"{cell.cell_id:34} {arm:3} r{rep} -> {rows[-1]['verdict']:10} {wall:6.2f}s", flush=True)
    finally:
        ws.cleanup()
    return rows


# ====================================================================== protocol
def protocol_dict():
    cells = {lvl: [{k: v for k, v in asdict(c).items() if k != "behaviour"} for c in all_cells(lvl)]
             for lvl in LEVEL_ARMS}
    return {
        "protocol": PROTOCOL_VERSION,
        "engine_version": ENGINE_VERSION,
        "levels": {"L1": "simulated: recorded real outputs replayed with deterministic fault edits",
                   "L2": "real pinned binaries on synthetic projects; execution-level and real-induced faults",
                   "R": "real pinned binaries on five pinned public repositories; execution-level faults"},
        "arms": {a: {"strategy": s, "parse_check": p} for a, (s, p) in ARMS.items()},
        "level_arms": LEVEL_ARMS,
        "repetitions": {"L1": 10, "L2": 10, "R": 10},
        "scanner_versions": {"semgrep": "1.180.0", "pip-audit": "2.10.1", "gitleaks": "8.30.1"},
        "pip_audit_args": PIP_AUDIT_ARGS,
        "semgrep_rules": RULES,
        "faults": {k: {"description": v[0], "expected_categories": v[1]} for k, v in FAULTS.items()},
        "ground_truth": {"C": "PASS", "K": "BLOCK (finding in the scanner named in finding_in)",
                         "F": "not PASS; under S3/S3P INCOMPLETE with an expected category",
                         "FK": "not PASS; the known finding is listed (FR-20)", "B": "observed, no ground truth"},
        "real_repos": {k: {"url": u, "commit": c} for k, (c, u) in REAL_REPOS.items()},
        "metrics": "see analysis.py METRIC_DEFINITIONS (denominators stated there)",
        "cells": cells,
    }


def protocol_bytes():
    return (json.dumps(protocol_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8")


# ====================================================================== environment and outputs
def environment(level, tools):
    env = {"level": level, "protocol": PROTOCOL_VERSION, "protocol_sha256": hashlib.sha256(protocol_bytes()).hexdigest(),
           "engine_version": ENGINE_VERSION, "python": sys.version.split()[0], "platform": platform.platform(),
           "runner": os.environ.get("RUNNER_NAME"), "image": os.environ.get("ImageOS"),
           "image_version": os.environ.get("ImageVersion"), "github_run_id": os.environ.get("GITHUB_RUN_ID"),
           "github_sha": os.environ.get("GITHUB_SHA"), "started_utc": utc_now(),
           "pip_audit_service": "pypi (live; audit date = started_utc)"}
    env["git_commit"] = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"],
                                       capture_output=True, text=True).stdout.strip() or None
    for s, path in tools.items():
        cmd = [path, "version"] if s == "gitleaks" else [path, "--version"]
        env[f"{s}_version"] = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
    return env


def shard(cells, spec):
    i, n = (int(x) for x in spec.split("/"))
    if not 1 <= i <= n:
        raise SystemExit(f"bad shard {spec}")
    return [c for k, c in enumerate(cells) if k % n == i - 1]


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("protocol")
    p.add_argument("--out", required=True)
    r = sub.add_parser("run")
    r.add_argument("--level", choices=list(LEVEL_ARMS), required=True)
    r.add_argument("--shard", default="1/1")
    r.add_argument("--reps", type=int, required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--final", action="store_true", help="refuse to run unless the protocol matches FROZEN.sha256")
    args = ap.parse_args()

    if args.cmd == "protocol":
        Path(args.out).write_bytes(protocol_bytes())
        print(hashlib.sha256(protocol_bytes()).hexdigest())
        return

    digest = hashlib.sha256(protocol_bytes()).hexdigest()
    if args.final:
        frozen = HERE / "FROZEN.sha256"
        if not frozen.exists() or frozen.read_text().split()[0] != digest:
            sys.exit(f"protocol {digest} is not the frozen protocol; final runs refused")
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        sys.exit(f"refusing to write into non-empty {out}: results are never overwritten")
    out.mkdir(parents=True, exist_ok=True)
    tools = {}
    if args.level != "L1":
        for s in SCANNERS:
            path = shutil.which(s)
            if not path:
                sys.exit(f"{s} not on PATH; {args.level} needs the pinned real scanners")
            tools[s] = path
    cells = shard(all_cells(args.level), args.shard)
    arms = LEVEL_ARMS[args.level]
    env = {**environment(args.level, tools), "shard": args.shard, "reps": args.reps, "final": args.final,
           "cells": [c.cell_id for c in cells]}
    rows = run_l1(cells, arms, args.reps, out) if args.level == "L1" else run_real(cells, arms, args.reps, out, tools)
    env["finished_utc"] = utc_now()
    (out / "environment.json").write_text(json.dumps(env, indent=2))
    if rows:
        with open(out / "runs.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    print(f"{len(rows)} runs written to {out}")


if __name__ == "__main__":
    main()
