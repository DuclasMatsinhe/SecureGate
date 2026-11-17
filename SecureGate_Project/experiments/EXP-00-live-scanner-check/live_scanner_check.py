#!/usr/bin/env python3
"""SecureGate live scanner check (Stage 5.1 evidence closure / OBJ2 pilot).

Runs Semgrep, pip-audit and Gitleaks against small synthetic fixtures and
records exit codes, outputs and coverage signals for normal and failure cases.
The results decide which fault classes (F8, F9, F10 and others) are real.

SAFETY
  * Works only inside a new temporary directory. It never reads or changes
    your SecureGate repositories, and it pushes nothing anywhere.
  * Uses only synthetic code and randomly generated fake tokens that are not
    valid credentials.
  * Stored outputs are scrubbed of the fake tokens and of your home-directory
    path. No username, hostname or e-mail is recorded.
  * Needs internet access: pip installs, pip-audit advisory lookups, and one
    Semgrep case that uses the Semgrep registry (`--config auto`, which sends
    Semgrep usage metrics; the scanned code is synthetic).

USAGE (Linux, macOS, WSL2 or GitHub Codespaces; native Windows is not supported
by Semgrep)
  python3 live_scanner_check.py                 # pinned Semgrep + pip-audit in a private venv
  python3 live_scanner_check.py --skip-install  # use semgrep / pip-audit already on PATH
  python3 live_scanner_check.py --gitleaks /path/to/gitleaks

Gitleaks must be on PATH or given with --gitleaks (it is a Go binary, not a pip package).
Run it from any scratch folder, not inside a repository.
At the end the script prints the path of a .zip file: send that file back.
"""
import argparse
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
import venv
from datetime import datetime, timezone
from pathlib import Path

HOME = str(Path.home())
CASE_TIMEOUT = 900  # seconds; pip-audit dependency resolution can be slow
REDACTED = "<REDACTED_SYNTHETIC_TOKEN>"


# ---------------------------------------------------------------- helpers
def scrub(text, tokens):
    for t in tokens:
        text = text.replace(t, REDACTED)
    if len(HOME) > 1:
        text = text.replace(HOME, "~")
    return text


def bin_dir(venv_dir):
    return Path(venv_dir) / ("Scripts" if os.name == "nt" else "bin")


def find_tool(name, preferred_dir=None):
    if preferred_dir:
        for cand in (preferred_dir / name, preferred_dir / f"{name}.exe"):
            if cand.exists():
                return str(cand)
    return shutil.which(name)


def run_quiet(cmd, **kw):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kw)
        return (r.stdout + r.stderr).strip()
    except Exception as exc:  # noqa: BLE001 - we record whatever happened
        return f"<could not run: {exc!r}>"


def install_tools(work, semgrep_version, pip_audit_version):
    vdir = work / "venv"
    venv.create(vdir, with_pip=True)
    py = bin_dir(vdir) / ("python.exe" if os.name == "nt" else "python")
    notes = []
    for pinned, name in ((f"semgrep=={semgrep_version}", "semgrep"),
                         (f"pip-audit=={pip_audit_version}", "pip-audit")):
        print(f"  installing {pinned} ...", flush=True)
        r = subprocess.run([str(py), "-m", "pip", "install", "-q", pinned],
                           capture_output=True, text=True)
        if r.returncode != 0:
            notes.append(f"Pinned install failed for {pinned}; installed the latest {name} instead.\n"
                         f"{r.stderr[-1500:]}")
            print(f"  pinned {pinned} unavailable, installing latest {name} ...", flush=True)
            r2 = subprocess.run([str(py), "-m", "pip", "install", "-q", name],
                                capture_output=True, text=True)
            if r2.returncode != 0:
                notes.append(f"Install of {name} failed:\n{r2.stderr[-1500:]}")
    return bin_dir(vdir), notes


def git_env():
    env = dict(os.environ)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull  # ignore personal git config, hooks, signing
    return env


def git(repo, *args):
    subprocess.run(["git", "-c", "user.name=probe", "-c", "user.email=probe@example.invalid",
                    "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
                   cwd=repo, check=True, capture_output=True, env=git_env())


# ---------------------------------------------------------------- fixtures
def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_fixtures(work):
    fx = work / "fixtures"
    alnum = string.ascii_letters + string.digits
    upper = string.ascii_uppercase + string.digits
    gh_token = "ghp_" + "".join(secrets.choice(alnum) for _ in range(36))
    aws_key = "AKIA" + "".join(secrets.choice(upper) for _ in range(16))
    tokens = [gh_token, aws_key]

    # Semgrep: local deterministic rule (offline) plus code variants
    write(fx / "rules.yml",
          "rules:\n"
          "  - id: probe-eval\n"
          "    pattern: eval(...)\n"
          "    message: Use of eval (synthetic probe rule)\n"
          "    languages: [python]\n"
          "    severity: ERROR\n")
    write(fx / "bad_rules.yml", "rules:\n  - id: broken\n    pattern: [unclosed\n")
    clean = "def add(a, b):\n    return a + b\n"
    finding = "def run(user_input):\n    return eval(user_input)\n"
    broken = "def broken(:\n    return 1\n"
    write(fx / "sg_clean" / "app.py", clean)
    write(fx / "sg_finding" / "app.py", finding)
    write(fx / "sg_broken" / "good.py", clean)
    write(fx / "sg_broken" / "broken.py", broken)
    write(fx / "sg_mixed" / "finding.py", finding)
    write(fx / "sg_mixed" / "broken.py", broken)
    (fx / "sg_empty").mkdir(parents=True, exist_ok=True)

    # pip-audit requirement variants
    missing_pkg = "securegate-nonexistent-probe-package"
    reqs = {
        "pa_clean": "flask==3.0.3\n",
        "pa_vuln": "urllib3==1.26.5\n",
        "pa_missing": f"{missing_pkg}==0.0.1\n",
        "pa_mixed": f"urllib3==1.26.5\n{missing_pkg}==0.0.1\n",
        "pa_malformed": "flask=>>3\n",
    }
    for d, txt in reqs.items():
        write(fx / d / "requirements.txt", txt)
    (fx / "pa_nofile").mkdir(parents=True, exist_ok=True)

    # Gitleaks git repositories
    for name, content in (("gl_clean", f"# config\nDEBUG = False\n"),
                          ("gl_secret", f'GITHUB_TOKEN = "{gh_token}"\nAWS_ACCESS_KEY_ID = "{aws_key}"\n')):
        repo = fx / name
        write(repo / "config.py", content)
        git(repo, "init", "-q")
        git(repo, "add", ".")
        git(repo, "commit", "-q", "-m", "fixture")
    write(fx / "gl_plaindir" / "config.py", f'GITHUB_TOKEN = "{gh_token}"\n')
    write(fx / "gl_bad.toml", "[[rules]]\nid = \nregex = '''unclosed\n")
    return fx, tokens


# ---------------------------------------------------------------- summaries
def summarise_semgrep(stdout, _report):
    try:
        d = json.loads(stdout)
    except Exception:  # noqa: BLE001
        return {"json_parsed": False}
    paths = d.get("paths") or {}
    errs = d.get("errors") or []
    return {
        "json_parsed": True,
        "top_level_keys": sorted(d.keys()) if isinstance(d, dict) else type(d).__name__,
        "results": len(d.get("results") or []),
        "errors": len(errs),
        "error_types": sorted({f"{e.get('type')}/{e.get('level')}" for e in errs if isinstance(e, dict)}),
        "paths_scanned": len(paths.get("scanned") or []) if "scanned" in paths else None,
        "paths_skipped": len(paths.get("skipped") or []) if "skipped" in paths else None,
        "version_field": d.get("version"),
    }


def summarise_pip_audit(stdout, _report):
    try:
        d = json.loads(stdout)
    except Exception:  # noqa: BLE001
        return {"json_parsed": False}
    deps = d.get("dependencies") or [] if isinstance(d, dict) else []
    skipped = [x for x in deps if isinstance(x, dict) and x.get("skip_reason")]
    return {
        "json_parsed": True,
        "top_level_keys": sorted(d.keys()) if isinstance(d, dict) else type(d).__name__,
        "dependencies": len(deps),
        "vulnerabilities": sum(len(x.get("vulns") or []) for x in deps if isinstance(x, dict)),
        "skipped": len(skipped),
        "skip_reasons": sorted({x["skip_reason"] for x in skipped}),
    }


def summarise_gitleaks(_stdout, report):
    if report is None or not report.exists():
        return {"report_exists": False}
    raw = report.read_text(encoding="utf-8", errors="replace")
    out = {"report_exists": True, "report_bytes": len(raw.encode())}
    try:
        d = json.loads(raw)
        out.update(json_parsed=True, findings=len(d) if isinstance(d, list) else None,
                   rule_ids=sorted({f.get("RuleID") for f in d if isinstance(f, dict)}) if isinstance(d, list) else None)
    except Exception:  # noqa: BLE001
        out["json_parsed"] = False
    return out


SUMMARISERS = {"semgrep": summarise_semgrep, "pip-audit": summarise_pip_audit, "gitleaks": summarise_gitleaks}


# ---------------------------------------------------------------- cases
def build_cases(fx, work, sg, pa, gl):
    sg_local = lambda target_cfg: [sg, "--config", str(target_cfg), "--json", "--metrics=off",
                                   "--disable-version-check"]
    rules = fx / "rules.yml"
    pa_base = [pa, "-r", "requirements.txt", "--format", "json"] if pa else None

    def gl_cmd(report, *extra, source="."):
        return [gl, "detect", "--source", source, "--report-format", "json",
                "--report-path", str(report), "--no-banner", *extra] if gl else None

    rp = work / "gl_reports"
    rp.mkdir(exist_ok=True)
    C = []
    add = lambda **k: C.append(k)
    # Semgrep (SecureGate runs: semgrep --config auto --json .)
    add(id="SG01", tool="semgrep", fault="control", cwd=fx / "sg_clean", cmd=sg and sg_local(rules) + ["."],
        expected="exit 0; 0 results; 0 errors", question="Clean baseline")
    add(id="SG02", tool="semgrep", fault="control", cwd=fx / "sg_finding", cmd=sg and sg_local(rules) + ["."],
        expected="exit 0 with 1 result (documented: findings do not change the exit code without --error)",
        question="Do findings change the exit code?")
    add(id="SG03", tool="semgrep", fault="control", cwd=fx / "sg_finding",
        cmd=sg and sg_local(rules) + ["--error", "."], expected="exit 1 (documented with --error)",
        question="Does --error turn findings into exit 1?")
    add(id="SG04", tool="semgrep", fault="F8", cwd=fx / "sg_broken", cmd=sg and sg_local(rules) + ["."],
        expected="UNKNOWN (measured)", question="Parse error in one file: exit code? errors[]? scanned count?")
    add(id="SG05", tool="semgrep", fault="F8+finding (SRQ4)", cwd=fx / "sg_mixed", cmd=sg and sg_local(rules) + ["."],
        expected="UNKNOWN (measured)", question="Parse error next to a real finding: is the finding still reported?")
    add(id="SG06", tool="semgrep", fault="F8 (no files)", cwd=fx / "sg_empty", cmd=sg and sg_local(rules) + ["."],
        expected="UNKNOWN (measured)", question="Nothing to scan: exit code and scanned count?")
    add(id="SG07", tool="semgrep", fault="F2 (bad config)", cwd=fx / "sg_finding",
        cmd=sg and sg_local(fx / "bad_rules.yml") + ["."], expected="UNKNOWN (measured)",
        question="Invalid rules file: exit code? JSON on stdout?")
    add(id="SG08", tool="semgrep", fault="F2 (bad target)", cwd=fx / "sg_finding",
        cmd=sg and sg_local(rules) + ["does_not_exist"], expected="UNKNOWN (measured)",
        question="Non-existent target path: exit code?")
    add(id="SG09", tool="semgrep", fault="control (SecureGate command)", cwd=fx / "sg_finding",
        cmd=sg and [sg, "--config", "auto", "--json", "."], expected="UNKNOWN (registry rules; needs network)",
        question="SecureGate's exact command: does it run, and what does it report?")
    # pip-audit (SecureGate runs: pip-audit -r requirements.txt --format json)
    add(id="PA01", tool="pip-audit", fault="control", cwd=fx / "pa_clean", cmd=pa_base,
        expected="exit 0; no vulnerabilities", question="Clean baseline")
    add(id="PA02", tool="pip-audit", fault="control", cwd=fx / "pa_vuln", cmd=pa_base,
        expected="exit 1; vulnerabilities in urllib3 1.26.5", question="Known vulnerable dependency")
    add(id="PA03", tool="pip-audit", fault="F9/F2", cwd=fx / "pa_missing", cmd=pa_base,
        expected="UNKNOWN (measured)", question="Non-existent package with dependency resolution: error or skip?")
    add(id="PA04", tool="pip-audit", fault="F9", cwd=fx / "pa_missing", cmd=pa_base and pa_base + ["--no-deps"],
        expected="UNKNOWN (measured)", question="Non-existent package without resolution: exit 0 with skip_reason?")
    add(id="PA05", tool="pip-audit", fault="F9 (--strict)", cwd=fx / "pa_missing",
        cmd=pa_base and pa_base + ["--no-deps", "--strict"], expected="UNKNOWN (measured; expected non-zero)",
        question="Does --strict turn the skip into a failure?")
    add(id="PA06", tool="pip-audit", fault="F9+finding (SRQ4)", cwd=fx / "pa_mixed",
        cmd=pa_base and pa_base + ["--no-deps"], expected="UNKNOWN (measured)",
        question="Vulnerable package plus skipped package: exit code? both visible?")
    add(id="PA07", tool="pip-audit", fault="F2 (malformed file)", cwd=fx / "pa_malformed", cmd=pa_base,
        expected="UNKNOWN (measured)", question="Malformed requirement line: exit code? JSON?")
    add(id="PA08", tool="pip-audit", fault="F2/F4 (missing file)", cwd=fx / "pa_nofile", cmd=pa_base,
        expected="UNKNOWN (measured)", question="requirements.txt missing: exit code? JSON?")
    add(id="PA09", tool="pip-audit", fault="F2 (network outage)", cwd=fx / "pa_vuln",
        cmd=pa_base and pa_base + ["--no-deps"],
        env={"HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9",
             "https_proxy": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9", "NO_PROXY": ""},
        expected="UNKNOWN (measured)", question="Advisory service unreachable: exit code? silent empty result?")
    # Gitleaks (SecureGate runs: gitleaks detect --source . --report-format json --report-path R --no-banner)
    add(id="GL01", tool="gitleaks", fault="control", cwd=fx / "gl_clean", report=rp / "GL01.json",
        cmd=gl_cmd(rp / "GL01.json"), expected="exit 0; report []", question="Clean baseline")
    add(id="GL02", tool="gitleaks", fault="control", cwd=fx / "gl_secret", report=rp / "GL02.json",
        cmd=gl_cmd(rp / "GL02.json"), expected="exit 1 (default --exit-code); >= 1 finding",
        question="Synthetic secrets detected by default rules?")
    add(id="GL03", tool="gitleaks", fault="control", cwd=fx / "gl_secret", report=rp / "GL03.json",
        cmd=gl_cmd(rp / "GL03.json", "--exit-code", "3"), expected="exit 3",
        question="Does an explicit --exit-code separate leaks from errors?")
    add(id="GL04", tool="gitleaks", fault="F10 (bad config)", cwd=fx / "gl_clean", report=rp / "GL04.json",
        cmd=gl_cmd(rp / "GL04.json", "--config", str(fx / "gl_bad.toml")), expected="UNKNOWN (U21)",
        question="Invalid config: which exit code? Same as a leak (1)? Report written?")
    add(id="GL05", tool="gitleaks", fault="F10 (not a repo)", cwd=fx / "gl_plaindir", report=rp / "GL05.json",
        cmd=gl_cmd(rp / "GL05.json"), expected="UNKNOWN (U21)",
        question="`detect` on a folder that is not a git repo: exit code? report?")
    add(id="GL06", tool="gitleaks", fault="F2 (bad source)", cwd=fx / "gl_clean", report=rp / "GL06.json",
        cmd=gl_cmd(rp / "GL06.json", source="does_not_exist"), expected="UNKNOWN (U21)",
        question="Non-existent source: exit code? report?")
    add(id="GL07", tool="gitleaks", fault="F4 (report not writable)", cwd=fx / "gl_secret",
        report=work / "no_such_dir" / "GL07.json",
        cmd=gl_cmd(work / "no_such_dir" / "GL07.json"), expected="UNKNOWN (measured)",
        question="Report path not writable: exit code? report missing?")
    add(id="GL08", tool="gitleaks", fault="control (--no-git)", cwd=fx / "gl_plaindir", report=rp / "GL08.json",
        cmd=gl_cmd(rp / "GL08.json", "--no-git"), expected="exit 1; >= 1 finding",
        question="Directory mode finds the secret?")
    return C


def run_case(case, out_cases, tokens):
    d = out_cases / case["id"]
    d.mkdir(parents=True, exist_ok=True)
    rec = {k: case[k] for k in ("id", "tool", "fault", "expected", "question")}
    if not case["cmd"]:
        rec.update(status="SKIPPED", reason=f"{case['tool']} not found")
        (d / "result.json").write_text(json.dumps(rec, indent=2))
        return rec
    cmd = [str(c) for c in case["cmd"]]
    rec["command"] = scrub(" ".join(cmd), tokens)
    rep = case.get("report")
    if rep and Path(rep).exists():
        Path(rep).unlink()
    env = dict(os.environ)
    env.update(case.get("env", {}))
    t0 = time.monotonic()
    try:
        p = subprocess.run(cmd, cwd=case["cwd"], capture_output=True, text=True,
                           timeout=CASE_TIMEOUT, env=env)
        rc, so, se, status = p.returncode, p.stdout, p.stderr, "RAN"
    except subprocess.TimeoutExpired as e:
        rc, status = None, "TIMEOUT"
        so = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        se = (e.stderr or b"").decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
    except OSError as e:
        rc, so, se, status = None, "", repr(e), "LAUNCH_ERROR"
    rec["duration_s"] = round(time.monotonic() - t0, 2)
    rec.update(status=status, exit_code=rc)
    (d / "stdout.txt").write_text(scrub(so, tokens), encoding="utf-8")
    (d / "stderr.txt").write_text(scrub(se, tokens), encoding="utf-8")
    rep_path = Path(rep) if rep else None
    rec["summary"] = SUMMARISERS[case["tool"]](so, rep_path)
    if rep_path and rep_path.exists():
        (d / "report.json").write_text(scrub(rep_path.read_text(encoding="utf-8", errors="replace"), tokens),
                                       encoding="utf-8")
    rec["stdout_bytes"], rec["stderr_bytes"] = len(so.encode()), len(se.encode())
    (d / "result.json").write_text(json.dumps(rec, indent=2), encoding="utf-8")
    return rec


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=None, help="output folder (default: ./securegate_live_check_<timestamp>)")
    ap.add_argument("--semgrep-version", default="1.180.0")
    ap.add_argument("--pip-audit-version", default="2.10.1")
    ap.add_argument("--gitleaks", default=None, help="path to the gitleaks binary")
    ap.add_argument("--skip-install", action="store_true", help="use tools already on PATH")
    ap.add_argument("--keep", action="store_true", help="keep the temporary work folder")
    a = ap.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(a.out or f"securegate_live_check_{stamp}").resolve()
    (out / "cases").mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="sg_live_"))
    print(f"Work folder (temporary): {work}\nOutput folder: {out}", flush=True)

    notes, tooldir = [], None
    if not a.skip_install:
        tooldir, notes = install_tools(work, a.semgrep_version, a.pip_audit_version)
    sg = find_tool("semgrep", tooldir)
    pa = find_tool("pip-audit", tooldir)
    gl = a.gitleaks or find_tool("gitleaks")

    fx, tokens = make_fixtures(work)
    env_info = {
        "run_utc": stamp,
        "os": f"{platform.system()} {platform.release()} {platform.machine()}",
        "python": sys.version.split()[0],
        "requested_versions": {"semgrep": a.semgrep_version, "pip-audit": a.pip_audit_version},
        "installed_versions": {
            "semgrep": run_quiet([sg, "--version"]) if sg else "NOT FOUND",
            "pip-audit": run_quiet([pa, "--version"]) if pa else "NOT FOUND",
            "gitleaks": run_quiet([gl, "version"]) if gl else "NOT FOUND",
            "git": run_quiet(["git", "--version"]),
        },
        "install_notes": [scrub(n, tokens) for n in notes],
    }
    (out / "environment.json").write_text(json.dumps(env_info, indent=2), encoding="utf-8")
    print(json.dumps(env_info["installed_versions"], indent=2), flush=True)

    results = []
    for case in build_cases(fx, work, sg, pa, gl):
        print(f"  {case['id']} {case['tool']:<9} {case['fault']:<28}", end=" ", flush=True)
        r = run_case(case, out / "cases", tokens)
        results.append(r)
        print(r.get("status"), "exit", r.get("exit_code"), flush=True)

    (out / "summary.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    cols = ["id", "tool", "fault", "status", "exit_code", "duration_s", "expected", "question", "summary"]
    with open(out / "summary.tsv", "w", encoding="utf-8") as f:
        f.write("\t".join(cols) + "\n")
        for r in results:
            f.write("\t".join(json.dumps(r.get(c)) if c == "summary" else str(r.get(c, "")) for c in cols) + "\n")

    zip_path = shutil.make_archive(str(out), "zip", out.parent, out.name)
    if not a.keep:
        shutil.rmtree(work, ignore_errors=True)
    print(f"\nDone. Send this file back:\n  {zip_path}")


if __name__ == "__main__":
    main()
