"""EXP-03: pre-registered held-out confirmation of the EXP-02 real-project results.

EXP-03 reuses the EXP-02 harness unchanged (same engine, arms, scanners, pinned scanner versions,
wrapper faults F2/F4/F7, policies and row format) on eight public projects that were never run
before. Only the list of projects and the level name ("H") differ. The projects were chosen by a
fixed rule from a recorded search snapshot (selection/), before any scanner ran on them, and the
predictions in PREREGISTRATION.md were written before the final run.

The EXP-03 protocol is frozen in FROZEN.sha256. It embeds the SHA-256 of the EXP-02 harness file,
so a change to the shared harness also changes the EXP-03 protocol and the final run is refused.

  python heldout.py protocol --out protocol.json
  python heldout.py run --shard 1/8 --reps 10 --out results/H-1 --final   # one project per shard
  python heldout.py run --smoke --reps 2 --out results/smoke     # EXP-02 project only; checks set-up

--smoke replaces the held-out projects with one EXP-02 project (microblog), so the CI set-up can
be checked without looking at any held-out project. Smoke results are never analysed as EXP-03.
"""
import argparse
import csv
import hashlib
import importlib.util
import json
import shutil
import sys
from dataclasses import asdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXP02 = HERE.parent / "EXP-02"
HARNESS_FILE = EXP02 / "harness.py"

_spec = importlib.util.spec_from_file_location("exp02_harness", HARNESS_FILE)
h = importlib.util.module_from_spec(_spec)
sys.modules["exp02_harness"] = h
_spec.loader.exec_module(h)

PROTOCOL_VERSION = "EXP-03 v1"
LEVEL = "H"
REPS = 10

# Selected by the rule in PREREGISTRATION.md section 2, in the order the search returned them.
# Commit first, then URL (see the Gitleaks note in the EXP-02 harness).
HELDOUT_REPOS = {
    "cookiecutter-flask": ("e5666c23a633b5b6fcb0dc2cfda2441d7f885727", "https://github.com/cookiecutter-flask/cookiecutter-flask"),
    "nyaa": ("4fe0ff5b1aa7ec7c9bb2667d97e10ce2a318c676", "https://github.com/nyaadevs/nyaa"),
    "flask-ask": ("a93488b700479a3b2d80eb54d0f6585caae15ef3", "https://github.com/johnwheeler/flask-ask"),
    "traefik-manager": ("29eb9456a92614175856470737da2a3daf96ae09", "https://github.com/chr0nzz/traefik-manager"),
    "flask-jwt-extended": ("ba708e89ac50ce69577c537ca7132e8d4dd3fc18", "https://github.com/vimalloc/flask-jwt-extended"),
    "git-webhook": ("4c57f1bfdb4b87183ef4adea30e90dce86fde2fa", "https://github.com/NetEaseGame/git-webhook"),
    "rq-dashboard": ("384def1a3c06263f2b2de901d0a26960fffb3f38", "https://github.com/Parallels/rq-dashboard"),
    "flask-oauthlib": ("260a1d5e608ea6149e4f9e89c592eb1519943098", "https://github.com/lepture/flask-oauthlib"),
}
SMOKE_REPOS = {"microblog": h.REAL_REPOS["microblog"]}
FAULTS = h.R_FAULTS  # F2 crash, F4 silent exit 0, F7 truncated report: identical to EXP-02 level R
ARMS = h.LEVEL_ARMS["R"]


def cells(repos=HELDOUT_REPOS):
    out = []
    for name, (commit, url) in repos.items():
        target = {"repo": name, "url": url, "commit": commit}
        out.append(h._cell(f"H-{name}-base", LEVEL, "B", realisation=f"{url} @ {commit[:7]}, no fault",
                           target=target, notes="observed: no ground truth for the unmodified project"))
        for fault in FAULTS:
            for s in h.SCANNERS:
                pol, how = h._wrapped(fault, s)
                out.append(h._cell(f"H-{name}-{fault}-{s}", LEVEL, "F", fault, (s,), realisation=f"{how} on {name}",
                                   target=target, policy=pol))
    return out


def shard_repos(repos, spec):
    """Shard i/n holds the projects whose position modulo n is i-1, so each project is cloned once."""
    i, n = (int(x) for x in spec.split("/"))
    if not 1 <= i <= n:
        raise SystemExit(f"bad shard {spec}")
    return {k: v for j, (k, v) in enumerate(repos.items()) if j % n == i - 1}


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def protocol_dict():
    return {
        "protocol": PROTOCOL_VERSION,
        "purpose": "held-out confirmation of EXP-02 level R; predictions in PREREGISTRATION.md",
        "engine_version": h.ENGINE_VERSION,
        "reuses": {"harness": "SecureGate_Project/experiments/EXP-02/harness.py",
                   "harness_sha256": sha256_file(HARNESS_FILE),
                   "exp02_protocol_sha256": hashlib.sha256(h.protocol_bytes()).hexdigest()},
        "level": {LEVEL: "real pinned binaries on eight held-out public repositories; execution-level faults"},
        "arms": {a: {"strategy": s, "parse_check": p} for a, (s, p) in h.ARMS.items() if a in ARMS},
        "repetitions": REPS,
        "scanner_versions": {"semgrep": "1.180.0", "pip-audit": "2.10.1", "gitleaks": "8.30.1"},
        "pip_audit_args": h.PIP_AUDIT_ARGS,
        "semgrep_rules_sha256": hashlib.sha256(h.RULES.encode()).hexdigest(),
        "faults": {k: {"description": h.FAULTS[k][0], "expected_categories": h.FAULTS[k][1]} for k in FAULTS},
        "heldout_repos": {k: {"url": u, "commit": c} for k, (c, u) in HELDOUT_REPOS.items()},
        "selection": {"rule": "PREREGISTRATION.md section 2", "log_sha256": sha256_file(HERE / "selection" / "selection_log.txt"),
                      "candidates_sha256": sha256_file(HERE / "selection" / "candidates.txt")},
        "preregistration_sha256": sha256_file(HERE / "PREREGISTRATION.md"),
        "metrics": "EXP-02 analysis.py METRIC_DEFINITIONS; predictions P1-P6 in PREREGISTRATION.md",
        "cells": [{k: v for k, v in asdict(c).items() if k != "behaviour"} for c in cells()],
    }


def protocol_bytes():
    return (json.dumps(protocol_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("protocol")
    p.add_argument("--out", required=True)
    r = sub.add_parser("run")
    r.add_argument("--shard", default="1/1")
    r.add_argument("--reps", type=int, required=True)
    r.add_argument("--out", required=True)
    g = r.add_mutually_exclusive_group()
    g.add_argument("--final", action="store_true", help="refuse to run unless the protocol matches FROZEN.sha256")
    g.add_argument("--smoke", action="store_true", help="run on one EXP-02 project instead of the held-out set")
    args = ap.parse_args()

    digest = hashlib.sha256(protocol_bytes()).hexdigest()
    if args.cmd == "protocol":
        Path(args.out).write_bytes(protocol_bytes())
        print(digest)
        return
    if args.final:
        frozen = HERE / "FROZEN.sha256"
        if not frozen.exists() or frozen.read_text().split()[0] != digest:
            sys.exit(f"protocol {digest} is not the frozen EXP-03 protocol; final run refused")
        if args.reps != REPS:
            sys.exit(f"the frozen protocol fixes {REPS} repetitions")
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        sys.exit(f"refusing to write into non-empty {out}: results are never overwritten")
    out.mkdir(parents=True, exist_ok=True)
    tools = {}
    for s in h.SCANNERS:
        path = shutil.which(s)
        if not path:
            sys.exit(f"{s} not on PATH; EXP-03 needs the pinned real scanners")
        tools[s] = path
    selected = cells(shard_repos(SMOKE_REPOS if args.smoke else HELDOUT_REPOS, args.shard))
    env = {**h.environment(LEVEL, tools), "protocol": PROTOCOL_VERSION, "protocol_sha256": digest,
           "mode": "smoke" if args.smoke else ("final" if args.final else "unfrozen"),
           "shard": args.shard, "reps": args.reps, "final": args.final, "cells": [c.cell_id for c in selected]}
    rows = h.run_real(selected, ARMS, args.reps, out, tools)
    env["finished_utc"] = h.utc_now()
    (out / "environment.json").write_text(json.dumps(env, indent=2))
    if rows:
        with open(out / "runs.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    print(f"{len(rows)} runs written to {out}")


if __name__ == "__main__":
    main()
