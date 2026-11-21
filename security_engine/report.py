"""Run manifest and human-readable report (M5, FR-27 to FR-30)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional

from . import evidence as ev
from .verdict import Verdict

MANIFEST_SCHEMA_VERSION = "1.2"
MAX_FINDINGS_IN_REPORT = 20

# Common credential shapes, redacted from any free text we store (FR-29).
_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?i)(\b(?:https?|ftp)://[^\s:/@]+:)[^\s@/]+(?=@)"),
    re.compile(r"(?i)((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
               r"aws_secret_access_key)[\"']?\s*[:=]\s*[\"']?)[^\s\"',;]{6,}"),
]
REDACTED = "[REDACTED]"

REQUIRED_MANIFEST_KEYS = {
    "schema_version", "run_id", "engine", "started_at", "finished_at", "duration_s", "timings",
    "target", "policy", "scanners", "findings", "verdict",
}


def redact(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        if pattern.groups:  # keep the key name, hide the value
            text = pattern.sub(lambda m: m.group(1) + REDACTED, text)
        else:
            text = pattern.sub(REDACTED, text)
    return text


def _scrub(value, home: str):
    """Redact secrets and replace the home folder (it can contain a username) in every string."""
    if isinstance(value, str):
        value = redact(value)
        return value.replace(home, "~") if home and len(home) > 1 else value
    if isinstance(value, list):
        return [_scrub(v, home) for v in value]
    if isinstance(value, dict):
        return {k: _scrub(v, home) for k, v in value.items()}
    return value


def build_manifest(*, run_id, engine_version, started_at, finished_at, duration_s, target_name,
                   commit, policy, evidences: List[ev.Evidence], verdict: Verdict,
                   timings: Optional[dict] = None) -> dict:
    findings = [f for e in evidences for f in e.findings]
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run_id": run_id,
        "engine": {"name": "securegate", "version": engine_version},
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_s": round(duration_s, 3),
        "timings": timings or {},
        "target": {"name": target_name, "commit": commit},
        "policy": {
            "source": policy.source,
            "sha256": policy.sha256(),
            "version": policy.version,
            "strategy": policy.strategy,
            "on_incomplete": policy.on_incomplete,
            "required_scanners": policy.required_scanners,
            "thresholds": policy.thresholds,
        },
        "scanners": [e.to_dict() for e in evidences],
        "findings": [f.to_dict() for f in findings],
        "verdict": verdict.to_dict(),
    }
    return _scrub(manifest, str(Path.home()))


def validate_manifest(manifest: dict) -> List[str]:
    """Return a list of problems (empty if the manifest is well formed)."""
    problems = [f"missing key: {k}" for k in sorted(REQUIRED_MANIFEST_KEYS - set(manifest))]
    verdict = manifest.get("verdict", {})
    if verdict.get("verdict") not in ("PASS", "BLOCK", "INCOMPLETE"):
        problems.append("verdict.verdict must be PASS, BLOCK or INCOMPLETE")
    for i, s in enumerate(manifest.get("scanners", [])):
        for key in ("scanner", "evidence_status", "category", "version", "execution"):
            if key not in s:
                problems.append(f"scanners[{i}] missing {key}")
        if s.get("evidence_status") == "INVALID" and not s.get("category"):
            problems.append(f"scanners[{i}] is INVALID without a category")
    return problems


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


_VERDICT_LINE = {
    "PASS": "**PASS**: all required scanners produced valid evidence and no blocking findings were found.",
    "BLOCK": "**BLOCK**: valid evidence shows a security problem at or above the policy threshold, "
             "or (strategies S0 to S2) a scanner failed.",
    "INCOMPLETE": "**INCOMPLETE**: security was not established, because at least one scanner's evidence "
                  "is missing or invalid. This is not a security clearance. Fix the pipeline and rerun.",
}


def render_markdown(manifest: dict) -> str:
    v = manifest["verdict"]
    lines = [f"## SecureGate verdict: {v['verdict']}", "", _VERDICT_LINE[v["verdict"]], ""]
    if v["reasons"]:
        lines += ["### Reasons", ""]
        lines += [f"- `{r['code']}`: {r['message']}" for r in v["reasons"]]
        lines.append("")
    lines += ["### Scanner health", "", "| Scanner | Evidence | Category | Exit code | Time (s) | Findings |",
              "|---|---|---|---|---|---|"]
    for s in manifest["scanners"]:
        ex = s.get("execution") or {}
        lines.append(f"| {s['scanner']} | {s['evidence_status']} | {s['category'] or '-'} | "
                     f"{ex.get('exit_code')} | {ex.get('duration_s')} | {s['findings_count']} |")
    lines.append("")
    findings = manifest["findings"]
    if findings:
        lines += ["### Findings", "", "| Tool | Severity | Rule | Location | Note |", "|---|---|---|---|---|"]
        ranked = sorted(findings, key=lambda f: -ev.SEVERITY_RANK.get(f["severity"], 0))
        for f in ranked[:MAX_FINDINGS_IN_REPORT]:
            where = f"{f['file']}:{f['line']}" if f.get("file") else "dependency"
            note = []
            if f["suppressed"]:
                note.append("suppressed")
            if f["severity_mapped"]:
                note.append(f"severity {f['raw_severity']!s} mapped")
            if f["from_incomplete_evidence"]:
                note.append("from incomplete evidence")
            lines.append(f"| {f['tool']} | {f['severity']} | {f['rule_id'] or f['title']} | {where} | "
                         f"{', '.join(note) or '-'} |")
        if len(findings) > MAX_FINDINGS_IN_REPORT:
            lines.append(f"\n_{len(findings) - MAX_FINDINGS_IN_REPORT} more in run_manifest.json._")
        lines.append("")
    if v["notes"]:
        lines += ["### Notes", ""] + [f"- `{n['code']}`: {n['message']}" for n in v["notes"]] + [""]
    p = manifest["policy"]
    lines.append(f"_Policy {p['source']} v{p['version']} (sha256 {p['sha256'][:12]}), strategy {p['strategy']}, "
                 f"run {manifest['run_id']}, engine {manifest['engine']['version']}._")
    return "\n".join(lines) + "\n"
