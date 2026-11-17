"""SecureGate experiment harness (EXP-01 pilot, protocol not yet frozen).

Two levels, never mixed in one results table:

  L1  SIMULATED.  Scanner outputs are replayed at the adapter boundary (FR-34).
      Base outputs are real recordings from EXP-00 (inputs/recorded/); faults are
      deterministic edits of them. No scanner binary runs.
  L2  REAL BINARIES.  Real Semgrep, pip-audit and Gitleaks run through the
      securegate CLI as a subprocess. Faults are induced with wrapper executables
      (L2 proper) or with real inputs that make the real tool fail (L3).

Every cell has an expected outcome written before the run (protocol.json).
All inputs are synthetic; secret fixtures are generated at run time.

Usage:
  python harness.py L1 --out results/L1
  python harness.py L2 --out results/L2 --reps 2        (needs the pinned scanners on PATH)
"""

import argparse
import csv
import json
import math
import os
import platform
import secrets
import shutil
import statistics
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

STRATEGIES = ("S0", "S1", "S2", "S3")
SCANNERS = ("semgrep", "pip-audit", "gitleaks")
LEAK_CODE = 3
REC = HERE / "inputs" / "recorded"

# Expected evidence category for each injected fault (Stage 8 fault catalogue, written before any run).
FAULTS = {
    "F1": ("executable missing", {"TOOL_MISSING"}),
    "F2": ("crash: unexpected non-zero exit, no report", {"NONZERO_EXIT"}),
    "F3": ("timeout / hang", {"TIMEOUT"}),
    "F4": ("missing report (exit 0, nothing written)", {"NO_OUTPUT"}),
    "F5": ("empty report (zero bytes / whitespace)", {"NO_OUTPUT"}),
    "F6": ("schema-invalid report ({})", {"SCHEMA_INVALID"}),
    "F7": ("truncated JSON (cut at 50%)", {"INVALID_JSON"}),
    "F8": ("no coverage (scanned nothing)", {"NO_COVERAGE"}),
    "F9": ("partial coverage (some inputs skipped or failed)", {"PARTIAL_COVERAGE"}),
    "F10": ("exit status inconsistent with report", {"INCONSISTENT_EXIT", "NONZERO_EXIT"}),
}


@dataclass
class Cell:
    cell_id: str
    level: str
    kind: str  # C clean control, K known finding, F fault, FK fault + finding elsewhere
    fault: str = "F0"
    faulted: tuple = ()  # scanners with an injected fault
    finding_in: tuple = ()  # scanners whose input holds a genuine finding
    realisation: str = ""  # how the fault is produced
    expected_category: tuple = ()  # accepted categories for the faulted scanner(s)
    notes: str = ""
    spec: dict = field(default_factory=dict, repr=False)


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
        return (
            {"exit": 1, "stdout": _read("pip_audit_vulnerable.json")}
            if finding
            else {"exit": 0, "stdout": _clean_pip_audit()}
        )
    if finding:
        return {
            "exit": LEAK_CODE,
            "report": _read("gitleaks_leak_report.json"),
            "stderr": _read("gitleaks_leak.stderr"),
        }
    return {"exit": 0, "report": _read("gitleaks_clean_report.json"), "stderr": _read("gitleaks_clean.stderr")}


def _l1_fault(scanner, fault):
    """Return (behaviour, realisation) or None when the fault does not apply to this scanner."""
    clean = _base(scanner, finding=False)
    payload_key = "report" if scanner == "gitleaks" else "stdout"
    payload = clean[payload_key]
    if fault == "F1":
        return {"launch_error": "TOOL_MISSING"}, "launch error: executable not found"
    if fault == "F2":
        crash_exit = 1 if scanner == "gitleaks" else 2  # Gitleaks' own error code; its leak code is 3
        return {
            "exit": crash_exit,
            "stdout": "",
            "report": None,
            "stderr": "synthetic crash",
        }, f"exit {crash_exit}, no report"
    if fault == "F3":
        return {"launch_error": "TIMEOUT"}, "killed after the policy timeout"
    if fault == "F4":
        return {**clean, payload_key: None if scanner == "gitleaks" else ""}, "exit 0, report not written"
    if fault == "F5":
        return {**clean, payload_key: "  \n"}, "exit 0, whitespace-only report"
    if fault == "F6":
        return {**clean, payload_key: "{}"}, "exit 0, report is {}"
    if fault == "F7":
        return {**clean, payload_key: payload[: len(payload) // 2]}, "exit 0, report cut at 50% of bytes"
    if fault == "F8":
        if scanner == "semgrep":
            return {"exit": 0, "stdout": _read("semgrep_no_files.json")}, "recorded real SG06: paths.scanned empty"
        if scanner == "gitleaks":
            return {
                "exit": 0,
                "report": "[]",
                "stderr": _read("gitleaks_not_a_repo.stderr"),
            }, "recorded real GL05: not a git repository, 0 commits scanned"
        return {"exit": 0, "stdout": json.dumps({"dependencies": [], "fixes": []})}, "dependencies list empty"
    if fault == "F9":
        if scanner == "semgrep":
            data = json.loads(payload)
            data.setdefault("paths", {})["skipped"] = [
                {"path": "broken.py", "reason": "analysis_failed_parser_or_internal_error"}
            ]
            return {"exit": 0, "stdout": json.dumps(data)}, "paths.skipped holds an analysis failure"
        if scanner == "pip-audit":
            data = json.loads(payload)
            data["dependencies"].append(
                {"name": "securegate-nonexistent-probe-package", "skip_reason": "Dependency not found on PyPI"}
            )
            return {"exit": 0, "stdout": json.dumps(data)}, "one dependency has skip_reason"
        return None
    if fault == "F10":
        if scanner == "semgrep":
            return {"exit": 1, "stdout": payload}, "exit 1 (findings) but results empty"
        if scanner == "pip-audit":
            return {"exit": 1, "stdout": payload}, "exit 1 (vulnerabilities) but none reported"
        return {
            "exit": 1,
            "report": "[]",
            "stderr": "synthetic error",
        }, "exit 1 (Gitleaks error code; leak code is 3) with empty report"
    raise ValueError(fault)


class ReplayRunner:
    """Replays scanner behaviours at the adapter boundary. Same contract as the real CommandRunner."""

    def __init__(self, behaviours):
        self.behaviours = behaviours

    def run(self, command, timeout, cwd=None):
        command = [str(c) for c in command]
        name = Path(command[0]).name
        tool = next(t for t in ("pip-audit", "semgrep", "gitleaks") if t in name)
        if "--version" in command or command[1:2] == ["version"]:
            return ExecutionRecord(command, utc_now(), 0.0, 0, stdout=f"{tool} replayed (EXP-00 recordings)")
        b = self.behaviours[tool]
        if b.get("launch_error"):
            return ExecutionRecord(
                command, utc_now(), 0.0, None, launch_error=b["launch_error"], launch_detail="injected (L1)"
            )
        if tool == "gitleaks" and b.get("report") is not None:
            path = Path(command[command.index("--report-path") + 1])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(b["report"], encoding="utf-8")
        return ExecutionRecord(
            command, utc_now(), 0.0, b.get("exit", 0), stdout=b.get("stdout") or "", stderr=b.get("stderr", "")
        )


def l1_cells():
    cells = [Cell("L1-C-clean", "L1", "C", realisation="all three scanners: recorded clean outputs")]
    for s in SCANNERS:
        cells.append(Cell(f"L1-K-{s}", "L1", "K", finding_in=(s,), realisation=f"recorded real finding ({s})"))
    for fault in FAULTS:
        for s in SCANNERS:
            made = _l1_fault(s, fault)
            if made is None:
                continue
            cells.append(
                Cell(
                    f"L1-{fault}-{s}",
                    "L1",
                    "F",
                    fault,
                    (s,),
                    (),
                    made[1],
                    tuple(sorted(FAULTS[fault][1])),
                    spec={"behaviour": {s: made[0]}},
                )
            )
    # Partial failure: a fault in one scanner while another holds a genuine finding (FPP).
    for fault in ("F1", "F2", "F6", "F8"):
        for bad in SCANNERS:
            for good in SCANNERS:
                if bad == good:
                    continue
                made = _l1_fault(bad, fault)
                cells.append(
                    Cell(
                        f"L1-{fault}-{bad}+K-{good}",
                        "L1",
                        "FK",
                        fault,
                        (bad,),
                        (good,),
                        made[1],
                        tuple(sorted(FAULTS[fault][1])),
                        spec={"behaviour": {bad: made[0]}},
                    )
                )
    # Several scanners failing at once.
    for combo in (("semgrep", "pip-audit"), SCANNERS):
        cells.append(
            Cell(
                f"L1-F1x{len(combo)}",
                "L1",
                "F",
                "F1",
                combo,
                (),
                "all listed scanners missing",
                ("TOOL_MISSING",),
                spec={"behaviour": {s: {"launch_error": "TOOL_MISSING"} for s in combo}},
            )
        )
    return cells


def l1_policy(strategy):
    return policy_from_dict({"strategy": strategy, "scanners": {"gitleaks": {"leak_exit_code": LEAK_CODE}}})


def run_l1(out, reps):
    cells, rows = l1_cells(), []
    for cell in cells:
        behaviours = {s: _base(s, s in cell.finding_in) for s in SCANNERS}
        behaviours.update(cell.spec.get("behaviour", {}))
        for strategy in STRATEGIES:
            for rep in range(1, reps + 1):
                run_dir = out / "runs" / cell.cell_id / f"{strategy}-r{rep}"
                target = Path(tempfile.mkdtemp(prefix="sg_l1_"))
                started = time.perf_counter()
                result = SecureGate(l1_policy(strategy), runner=ReplayRunner(behaviours)).run(
                    target=str(target), out_dir=str(run_dir)
                )
                wall = time.perf_counter() - started
                shutil.rmtree(target, ignore_errors=True)
                rows.append(row_from_manifest(cell, strategy, rep, result.manifest, result.verdict.exit_code, wall))
    return cells, rows


# ====================================================================== L2 (real binaries)
WRAPPER = r'''#!{python}
"""SecureGate L2 fault wrapper (synthetic). Mode: {mode}. Real tool: {real}."""
import subprocess, sys, time
from pathlib import Path
mode, real, args = "{mode}", "{real}", sys.argv[1:]
if "--version" in args or args[:1] == ["version"]:
    sys.exit(subprocess.call([real] + args))
if mode == "crash":
    sys.stderr.write("synthetic crash (L2 wrapper)\n"); sys.exit(2)
if mode == "hang":
    time.sleep(120); sys.exit(0)
if mode == "silent":
    sys.exit(0)
if mode == "schema":
    report = args[args.index("--report-path") + 1] if "--report-path" in args else None
    (Path(report).write_text("{{}}") if report else sys.stdout.write("{{}}")); sys.exit(0)
if mode == "truncate":
    p = subprocess.run([real] + args, capture_output=True, text=True)
    sys.stderr.write(p.stderr)
    if "--report-path" in args:
        rp = Path(args[args.index("--report-path") + 1])
        if rp.exists():
            text = rp.read_text(); rp.write_text(text[: len(text) // 2])
        sys.stdout.write(p.stdout)
    else:
        sys.stdout.write(p.stdout[: len(p.stdout) // 2])
    sys.exit(p.returncode)
sys.exit(97)
'''

WRAPPER_FAULTS = {"F2": "crash", "F3": "hang", "F4": "silent", "F6": "schema", "F7": "truncate"}


def _git(repo, *args):
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    }
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


RULES = (
    "rules:\n  - id: probe-eval\n    pattern: eval(...)\n    message: Use of eval (synthetic probe rule)\n"
    "    languages: [python]\n    severity: ERROR\n"
)
CLEAN_PY = "def add(a, b):\n    return a + b\n"
FINDING_PY = "def run(user_input):\n    return eval(user_input)\n"
BROKEN_PY = "def broken(:\n    return 1\n"
CLEAN_REQ = "six==1.17.0\n"
VULN_REQ = "urllib3==1.26.5\n"
MISSING_REQ = "securegate-nonexistent-probe-package==0.0.1\n"


def make_target(root, name, *, py=CLEAN_PY, req=CLEAN_REQ, secret=False, git=True, extra=None):
    t = root / name
    t.mkdir(parents=True)
    if py is not None:
        (t / "app.py").write_text(py)
    (t / "requirements.txt").write_text(req)
    (t / "rules.yml").write_text(RULES)
    for rel, text in (extra or {}).items():
        (t / rel).write_text(text)
    if secret:  # generated now, never stored in the repository
        token = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
        (t / "settings.py").write_text(f'GITHUB_TOKEN = "{token}"\n')
    if git:
        _git(t, "init", "-q")
        _git(t, "add", ".")
        _git(t, "commit", "-q", "-m", "fixture")
    return t


def l2_cells(work, tools):
    root = work / "targets"
    wrappers = work / "wrappers"
    wrappers.mkdir(parents=True)
    cells = []

    def add(cell_id, kind, target, *, fault="F0", faulted=(), finding_in=(), realisation="", policy=None, notes=""):
        exp = tuple(sorted(FAULTS[fault][1])) if fault != "F0" else ()
        cells.append(
            Cell(
                cell_id,
                "L2",
                kind,
                fault,
                faulted,
                finding_in,
                realisation,
                exp,
                notes,
                spec={"target": str(target), "policy": policy or {}},
            )
        )

    clean = make_target(root, "t-clean")
    add("L2-C-clean", "C", clean, realisation="real tools, clean synthetic project")
    add(
        "L2-K-semgrep",
        "K",
        make_target(root, "t-sast", py=FINDING_PY),
        finding_in=("semgrep",),
        realisation="eval() matched by the local probe rule",
    )
    add(
        "L2-K-pip-audit",
        "K",
        make_target(root, "t-sca", req=VULN_REQ),
        finding_in=("pip-audit",),
        realisation="urllib3==1.26.5 (known vulnerabilities)",
    )
    add(
        "L2-K-gitleaks",
        "K",
        make_target(root, "t-secret", secret=True),
        finding_in=("gitleaks",),
        realisation="synthetic GitHub token generated at run time, committed",
    )

    for fault, mode in WRAPPER_FAULTS.items():
        for s in SCANNERS:
            w = wrappers / f"{s}-{mode}"
            w.write_text(WRAPPER.format(python=sys.executable, mode=mode, real=tools[s]))
            w.chmod(0o755)
            pol = {s: {"executable": str(w)}}
            if fault == "F3":
                pol[s]["timeout"] = 3
            add(
                f"L2-{fault}-{s}",
                "F",
                clean,
                fault=fault,
                faulted=(s,),
                policy=pol,
                realisation=f"L2 wrapper executable ({mode})",
            )
    for s in SCANNERS:
        add(
            f"L2-F1-{s}",
            "F",
            clean,
            fault="F1",
            faulted=(s,),
            policy={s: {"executable": str(work / "not-installed" / s)}},
            realisation="L2 executable path does not exist",
        )

    # L3: real inputs that make the real tool fail or scan nothing.
    add(
        "L2-F8-semgrep",
        "F",
        make_target(root, "t-nopy", py=None),
        fault="F8",
        faulted=("semgrep",),
        realisation="L3 project with no Python files",
    )
    add(
        "L2-F8-gitleaks",
        "F",
        make_target(root, "t-nogit", git=False, secret=True),
        fault="F8",
        faulted=("gitleaks",),
        realisation="L3 folder is not a git repository (holds a synthetic token)",
    )
    add(
        "L2-F8-pip-audit",
        "F",
        make_target(root, "t-noreq", req=""),
        fault="F8",
        faulted=("pip-audit",),
        realisation="L3 empty requirements file",
    )
    add(
        "L2-F9-semgrep",
        "F",
        make_target(root, "t-broken", extra={"broken.py": BROKEN_PY}),
        fault="F9",
        faulted=("semgrep",),
        realisation="L3 one file with a syntax error",
        notes="EXP-00 SG04: Semgrep 1.180.0 reported no parse error; a silent pass is the expected real outcome",
    )
    add(
        "L2-F9-pip-audit",
        "F",
        make_target(root, "t-missingpkg", req=CLEAN_REQ + MISSING_REQ),
        fault="F9",
        faulted=("pip-audit",),
        realisation="L3 requirement that does not exist on PyPI",
        notes="EXP-00 PA03: pip-audit exits 1 with empty stdout instead of skipping",
    )
    bad_cfg = work / "gitleaks-bad.toml"
    bad_cfg.write_text("[[rules]]\nid = \nregex = '''unclosed\n")
    add(
        "L2-F10-gitleaks",
        "F",
        clean,
        fault="F10",
        faulted=("gitleaks",),
        policy={"gitleaks": {"config": str(bad_cfg)}},
        realisation="L3 invalid Gitleaks config (exit 1 = error code, leak code is 3)",
    )

    # Partial failure with a genuine finding elsewhere (FPP).
    add(
        "L2-F1-semgrep+K-pip-audit",
        "FK",
        make_target(root, "t-sca-2", req=VULN_REQ),
        fault="F1",
        faulted=("semgrep",),
        finding_in=("pip-audit",),
        policy={"semgrep": {"executable": str(work / "not-installed" / "semgrep")}},
        realisation="Semgrep missing while pip-audit finds urllib3 vulnerabilities",
    )
    add(
        "L2-F2-pip-audit+K-semgrep",
        "FK",
        make_target(root, "t-sast-2", py=FINDING_PY),
        fault="F2",
        faulted=("pip-audit",),
        finding_in=("semgrep",),
        policy={"pip-audit": {"executable": str(wrappers / "pip-audit-crash")}},
        realisation="pip-audit crashes while Semgrep finds eval()",
    )
    add(
        "L2-F1x3",
        "F",
        clean,
        fault="F1",
        faulted=SCANNERS,
        policy={s: {"executable": str(work / "not-installed" / s)} for s in SCANNERS},
        realisation="all scanners missing",
    )
    return cells


def toml_value(v):
    return json.dumps(v) if not isinstance(v, bool) else ("true" if v else "false")


def write_policy(path, strategy, overrides):
    scanners = {
        "semgrep": {"config": "rules.yml", "timeout": 300},
        "pip-audit": {"timeout": 300},
        "gitleaks": {"leak_exit_code": LEAK_CODE, "timeout": 300},
    }
    for s, extra in overrides.items():
        scanners[s].update(extra)
    lines = ['version = "exp01-pilot"', f'strategy = "{strategy}"', 'on_incomplete = "block"', ""]
    for s, cfg in scanners.items():
        lines.append(f"[scanners.{s}]")
        lines += [f"{k} = {toml_value(v)}" for k, v in cfg.items()]
        lines.append("")
    path.write_text("\n".join(lines))


def run_l2(out, reps, tools):
    work = Path(tempfile.mkdtemp(prefix="sg_l2_"))
    cells, rows = l2_cells(work, tools), []
    for cell in cells:
        for strategy in STRATEGIES:
            for rep in range(1, reps + 1):
                run_dir = (out / "runs" / cell.cell_id / f"{strategy}-r{rep}").resolve()
                run_dir.mkdir(parents=True, exist_ok=True)
                pol = run_dir / "policy.toml"
                write_policy(pol, strategy, cell.spec["policy"])
                started = time.perf_counter()
                proc = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "security_engine.cli",
                        "--target",
                        cell.spec["target"],
                        "--policy",
                        str(pol),
                        "--out",
                        str(run_dir),
                        "--no-summary",
                    ],
                    cwd=REPO,
                    capture_output=True,
                    text=True,
                    timeout=900,
                )
                wall = time.perf_counter() - started
                (run_dir / "cli_stdout.json").write_text(proc.stdout)
                manifest = json.loads((run_dir / "run_manifest.json").read_text())
                rows.append(row_from_manifest(cell, strategy, rep, manifest, proc.returncode, wall))
                print(f"{cell.cell_id:32} {strategy} r{rep} -> {rows[-1]['verdict']:10} {wall:6.2f}s", flush=True)
    shutil.rmtree(work, ignore_errors=True)
    return cells, rows


# ====================================================================== analysis
def row_from_manifest(cell, strategy, rep, manifest, exit_code, wall):
    by = {s["scanner"]: s for s in manifest["scanners"]}
    verdict = manifest["verdict"]
    faulted_cats = [by[s]["category"] for s in cell.faulted if s in by]
    preserved = [
        s
        for s in cell.finding_in
        if any(r["code"] == "BLOCKING_FINDING" and r["scanner"] == s for r in verdict["reasons"])
    ]
    return {
        "level": cell.level,
        "cell_id": cell.cell_id,
        "kind": cell.kind,
        "fault": cell.fault,
        "faulted": "+".join(cell.faulted),
        "finding_in": "+".join(cell.finding_in),
        "strategy": strategy,
        "rep": rep,
        "verdict": verdict["verdict"],
        "exit_code": exit_code,
        "faulted_categories": "+".join(c or "VALID" for c in faulted_cats),
        "category_correct": bool(cell.faulted) and all(c in cell.expected_category for c in faulted_cats),
        "findings_preserved": len(preserved) == len(cell.finding_in) if cell.finding_in else "",
        "reason_codes": ";".join(sorted({f"{r['scanner']}:{r['code']}" for r in verdict["reasons"]})),
        "wall_s": round(wall, 4),
        "duration_s": manifest["duration_s"],
        **{k: manifest["timings"][k] for k in ("scanner_execution_s", "evidence_validation_s", "decision_s")},
        "run_id": manifest["run_id"],
        "policy_sha256": manifest["policy"]["sha256"],
        "scanner_versions": ";".join(f"{s['scanner']}={s['version']}" for s in manifest["scanners"]),
    }


def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return {"k": k, "n": n, "rate": round(p, 4), "ci95": [round(max(0, c - h), 4), round(min(1, c + h), 4)]}


def metrics(rows):
    out = {}
    for level in sorted({r["level"] for r in rows}):
        out[level] = {}
        for s in STRATEGIES:
            rs = [r for r in rows if r["level"] == level and r["strategy"] == s]
            F = [r for r in rs if r["kind"] in ("F", "FK")]
            C = [r for r in rs if r["kind"] == "C"]
            K = [r for r in rs if r["kind"] == "K"]
            FK = [r for r in rs if r["kind"] == "FK"]
            out[level][s] = {
                "SPR": wilson(sum(r["verdict"] == "PASS" for r in F), len(F)),
                "FDR": wilson(sum(r["verdict"] != "PASS" for r in F), len(F)),
                "ICA": wilson(sum(r["verdict"] == "INCOMPLETE" and r["category_correct"] for r in F), len(F)),
                "FBR": wilson(sum(r["verdict"] != "PASS" for r in C), len(C)),
                "CBR": wilson(sum(r["verdict"] == "BLOCK" for r in K), len(K)),
                "FPP": wilson(sum(r["findings_preserved"] is True for r in FK), len(FK)),
                "verdicts_on_faults": {v: sum(r["verdict"] == v for r in F) for v in ("PASS", "BLOCK", "INCOMPLETE")},
            }
        # Consistency: all repetitions of a cell and strategy give the same verdict.
        groups = {}
        for r in rows:
            if r["level"] == level:
                groups.setdefault((r["cell_id"], r["strategy"]), set()).add(r["verdict"])
        out[level]["consistency"] = wilson(sum(len(v) == 1 for v in groups.values()), len(groups))
        out[level]["timing"] = timing(rows, level)
    return out


def _q(values):
    if not values:
        return None
    values = sorted(values)
    qs = statistics.quantiles(values, n=4) if len(values) > 1 else [values[0]] * 3
    return {"n": len(values), "median": round(statistics.median(values), 6), "iqr": [round(qs[0], 6), round(qs[2], 6)]}


def timing(rows, level):
    rs = [r for r in rows if r["level"] == level and r["kind"] in ("C", "K")]
    res = {}
    for s in STRATEGIES:
        sub = [r for r in rs if r["strategy"] == s]
        share = [r["evidence_validation_s"] / r["duration_s"] for r in sub if r["duration_s"]]
        res[s] = {
            "wall_s": _q([r["wall_s"] for r in sub]),
            "duration_s": _q([r["duration_s"] for r in sub]),
            "scanner_execution_s": _q([r["scanner_execution_s"] for r in sub]),
            "evidence_validation_s": _q([r["evidence_validation_s"] for r in sub]),
            "validation_share_of_run": _q(share),
        }
    res["note"] = (
        "Clean and known-finding cells only (fault cells end early or wait for timeouts). "
        "L1 replays outputs, so its execution time is not a real scanner time."
    )
    return res


def environment(level, tools):
    env = {
        "level": level,
        "engine_version": ENGINE_VERSION,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "runner": os.environ.get("RUNNER_NAME"),
        "image": os.environ.get("ImageOS"),
        "image_version": os.environ.get("ImageVersion"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_sha": os.environ.get("GITHUB_SHA"),
        "started_utc": utc_now(),
    }
    try:
        env["git_commit"] = subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip()
    except OSError:
        env["git_commit"] = None
    if tools:
        for s, path in tools.items():
            cmd = [path, "version"] if s == "gitleaks" else [path, "--version"]
            env[f"{s}_version"] = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
    return env


def write_outputs(out, level, cells, rows, env):
    out.mkdir(parents=True, exist_ok=True)
    (out / "protocol.json").write_text(
        json.dumps(
            {
                "status": "PILOT - protocol not frozen; results are not final study results",
                "level": level,
                "strategies": STRATEGIES,
                "faults": {k: {"description": v[0], "expected": sorted(v[1])} for k, v in FAULTS.items()},
                "cells": [{k: v for k, v in asdict(c).items() if k != "spec"} for c in cells],
            },
            indent=2,
        )
    )
    with open(out / "runs.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    m = metrics(rows)
    (out / "metrics.json").write_text(json.dumps(m, indent=2))
    (out / "environment.json").write_text(json.dumps(env, indent=2))
    (out / "summary.md").write_text(summary_md(level, cells, rows, m, env))
    return m


def _fmt(x):
    return "n/a" if x is None else f"{x['rate']:.3f} ({x['k']}/{x['n']}) [{x['ci95'][0]:.3f}, {x['ci95'][1]:.3f}]"


def summary_md(level, cells, rows, m, env):
    kind = (
        "SIMULATED (recorded outputs replayed; no scanner binary runs)"
        if level == "L1"
        else "REAL BINARIES (pinned Semgrep, pip-audit, Gitleaks via the CLI)"
    )
    lines = [
        f"# EXP-01 pilot results: {level}",
        "",
        f"**Level:** {kind}  ",
        "**Status:** pilot, protocol not frozen. Not final study results.  ",
        f"**Engine:** {env['engine_version']} at commit `{(env.get('git_commit') or '?')[:7]}`; "
        f"Python {env['python']}; {env['platform']}",
        "",
    ]
    if level == "L2":
        lines += [
            f"Scanners: {env.get('semgrep_version')} / {env.get('pip-audit_version')} / "
            f"Gitleaks {env.get('gitleaks_version')}; GitHub run {env.get('github_run_id')}",
            "",
        ]
    lines += [
        f"Cells: {len(cells)}; runs: {len(rows)}. Rates with Wilson 95% intervals over runs "
        "(cells are not a random sample, so the intervals describe this cell set only).",
        "",
        "| Metric | " + " | ".join(STRATEGIES) + " |",
        "|---|" + "---|" * len(STRATEGIES),
    ]
    for key in ("SPR", "FDR", "ICA", "FBR", "CBR", "FPP"):
        lines.append(f"| {key} | " + " | ".join(_fmt(m[level][s][key]) for s in STRATEGIES) + " |")
    lines += [
        "",
        f"Run-to-run verdict consistency: {_fmt(m[level]['consistency'])}",
        "",
        "## Verdict per cell",
        "",
        "| Cell | Realisation | Expected (faulted scanner) | " + " | ".join(STRATEGIES) + " |",
        "|---|---|---|" + "---|" * len(STRATEGIES),
    ]
    for c in cells:
        cell_rows = {s: [r for r in rows if r["cell_id"] == c.cell_id and r["strategy"] == s] for s in STRATEGIES}

        def show(rs):
            verdicts = sorted({r["verdict"] for r in rs})
            cats = sorted({r["faulted_categories"] for r in rs if r["faulted_categories"]})
            return "/".join(verdicts) + (f" `{'/'.join(cats)}`" if cats else "")

        exp = "/".join(c.expected_category) or ("PASS" if c.kind == "C" else "BLOCK")
        lines.append(
            f"| {c.cell_id} | {c.realisation} | {exp} | " + " | ".join(show(cell_rows[s]) for s in STRATEGIES) + " |"
        )
    t = m[level]["timing"]
    lines += [
        "",
        "## Timing (clean and known-finding cells)",
        "",
        "| Strategy | wall median s | scanner execution median s | evidence validation median s | "
        "validation share of run (median) |",
        "|---|---|---|---|---|",
    ]
    for s in STRATEGIES:
        x = t[s]
        if x["wall_s"]:
            lines.append(
                f"| {s} | {x['wall_s']['median']} | {x['scanner_execution_s']['median']} | "
                f"{x['evidence_validation_s']['median']} | "
                f"{x['validation_share_of_run']['median'] if x['validation_share_of_run'] else 'n/a'} |"
            )
    lines += ["", t["note"], ""]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("level", choices=["L1", "L2"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--reps", type=int, default=1)
    args = ap.parse_args()
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        sys.exit(f"refusing to write into non-empty {out}: results are never overwritten")
    tools = {}
    if args.level == "L2":
        for s in SCANNERS:
            path = shutil.which(s)
            if not path:
                sys.exit(f"{s} not on PATH; L2 needs the pinned real scanners")
            tools[s] = path
    env = environment(args.level, tools)
    cells, rows = (run_l1 if args.level == "L1" else lambda o, r: run_l2(o, r, tools))(out, args.reps)
    m = write_outputs(out, args.level, cells, rows, env)
    print(
        json.dumps(
            {s: {k: (m[args.level][s][k] or {}).get("rate") for k in ("SPR", "FBR", "CBR", "ICA")} for s in STRATEGIES},
            indent=1,
        )
    )


if __name__ == "__main__":
    main()
