"""Scanner adapters and evidence validation (M2 + M3).

Each adapter knows three things about its tool:
  1. how to run it (command, documented success exit codes),
  2. what its report must look like (schema check),
  3. how to tell whether it really examined the input (coverage) and
     whether its exit code agrees with its report (consistency).

`evaluate()` applies these checks according to the handling strategy:
  S0  exit codes only (baseline)
  S1  + presence, JSON and schema checks
  S2  + exit-code consistency and coverage checks
  S3  same checks as S2; the verdict routes invalid evidence to INCOMPLETE
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional, Tuple

from . import evidence as ev
from .execution import ExecutionRecord
from .models import SecurityFinding
from .scanners.gitleaks import parse_gitleaks_results
from .scanners.pip_audit import parse_pip_audit_results
from .scanners.semgrep import parse_semgrep_results

SCHEMA_STRATEGIES = {"S1", "S2", "S3"}
DEEP_STRATEGIES = {"S2", "S3"}


class Adapter:
    key = ""
    display_name = ""
    executable_name = ""

    def command(self, executable: str, cfg: dict, out_dir: Path) -> List[str]:
        raise NotImplementedError

    def version_command(self, executable: str) -> List[str]:
        return [executable, "--version"]

    def config_id(self, cfg: dict) -> Optional[str]:
        return None

    def prepare(self, out_dir: Path) -> None:
        """Remove stale outputs before a run (FR-07)."""

    def collect(self, record: ExecutionRecord, out_dir: Path) -> Optional[str]:
        """Return the raw report text, or None if there is none."""
        return record.stdout

    def success_codes(self, cfg: dict) -> set:
        return {0}

    def exit_indicates_findings(self, exit_code: Optional[int], cfg: dict) -> bool:
        return False

    def schema_problem(self, data) -> Optional[str]:
        return None

    def parse(self, data) -> List[SecurityFinding]:
        raise NotImplementedError

    def consistency_problem(self, record: ExecutionRecord, data, findings: list, cfg: dict) -> Optional[str]:
        return None

    def coverage(self, data) -> Tuple[Optional[str], dict, Optional[str]]:
        """Return (category or None, coverage numbers, message)."""
        return None, {}, None


class SemgrepAdapter(Adapter):
    key = "semgrep"
    display_name = "Semgrep"
    executable_name = "semgrep"

    def command(self, executable, cfg, out_dir):
        return [executable, "--config", cfg["config"], "--json", "--metrics=off",
                "--disable-version-check", *cfg["extra_args"], "."]

    def config_id(self, cfg):
        return cfg["config"]

    def schema_problem(self, data):
        if not isinstance(data, dict):
            return "Semgrep report is not a JSON object"
        missing = [k for k in ("results", "errors") if k not in data]
        if missing:
            return f"Semgrep report has no {' or '.join(repr(k) for k in missing)} key"
        if not isinstance(data["results"], list):
            return "Semgrep 'results' is not a list"
        if not isinstance(data["errors"], list):
            return "Semgrep 'errors' is not a list"
        if not all(isinstance(r, dict) for r in data["results"]):
            return "Semgrep 'results' contains a non-object entry"
        paths = data.get("paths")
        if paths is not None and not isinstance(paths, dict):
            return "Semgrep 'paths' is not an object"
        return None

    def parse(self, data):
        return parse_semgrep_results(data)

    def coverage(self, data):
        errors = data.get("errors") or []
        paths = data.get("paths") or {}
        scanned = paths.get("scanned") if isinstance(paths, dict) else None
        numbers = {"files_scanned": len(scanned) if isinstance(scanned, list) else None,
                   "errors": len(errors)}
        if isinstance(scanned, list) and len(scanned) == 0:
            return ev.NO_COVERAGE, numbers, "Semgrep reports that it scanned 0 files"
        if errors:
            kinds = sorted({str(e.get("type", "error")) if isinstance(e, dict) else "error" for e in errors})
            return (ev.PARTIAL_COVERAGE, numbers,
                    f"Semgrep reported {len(errors)} error(s) during the scan ({', '.join(kinds)[:200]})")
        return None, numbers, None


class PipAuditAdapter(Adapter):
    key = "pip-audit"
    display_name = "pip-audit"
    executable_name = "pip-audit"

    def command(self, executable, cfg, out_dir):
        return [executable, "-r", cfg["requirements"], "--format", "json", *cfg["extra_args"]]

    def config_id(self, cfg):
        return f"requirements={cfg['requirements']}"

    def success_codes(self, cfg):
        # pip-audit: 0 = no known vulnerabilities, 1 = vulnerabilities found.
        return {0, 1}

    def exit_indicates_findings(self, exit_code, cfg):
        return exit_code == 1

    def schema_problem(self, data):
        if not isinstance(data, dict):
            return "pip-audit report is not a JSON object"
        if "dependencies" not in data:
            return "pip-audit report has no 'dependencies' key"
        deps = data["dependencies"]
        if not isinstance(deps, list):
            return "pip-audit 'dependencies' is not a list"
        for dep in deps:
            if not isinstance(dep, dict) or "name" not in dep:
                return "pip-audit 'dependencies' contains an entry without a name"
            if "vulns" in dep and not isinstance(dep["vulns"], list):
                return f"pip-audit 'vulns' for {dep.get('name')} is not a list"
        return None

    def parse(self, data):
        return parse_pip_audit_results(data)

    def consistency_problem(self, record, data, findings, cfg):
        if record.exit_code == 0 and findings:
            return "pip-audit exited 0 (no vulnerabilities) but its report lists vulnerabilities"
        if record.exit_code == 1 and not findings:
            return "pip-audit exited 1 (vulnerabilities found) but its report lists none"
        return None

    def coverage(self, data):
        deps = data.get("dependencies") or []
        skipped = [d for d in deps if isinstance(d, dict) and d.get("skip_reason")]
        audited = len(deps) - len(skipped)
        numbers = {"dependencies": len(deps), "audited": audited, "skipped": len(skipped)}
        if not deps:
            return ev.NO_COVERAGE, numbers, "pip-audit audited no dependencies"
        if audited == 0:
            return ev.NO_COVERAGE, numbers, "pip-audit skipped every dependency"
        if skipped:
            names = ", ".join(str(d.get("name")) for d in skipped[:5])
            return (ev.PARTIAL_COVERAGE, numbers,
                    f"pip-audit skipped {len(skipped)} of {len(deps)} dependencies ({names})")
        return None, numbers, None


class GitleaksAdapter(Adapter):
    key = "gitleaks"
    display_name = "Gitleaks"
    executable_name = "gitleaks"
    report_name = "gitleaks-report.json"

    def report_path(self, out_dir: Path) -> Path:
        return Path(out_dir).resolve() / "raw" / self.report_name

    def command(self, executable, cfg, out_dir):
        cmd = [executable, "detect", "--source", ".", "--report-format", "json",
               "--report-path", str(self.report_path(out_dir)), "--no-banner", "--redact",
               "--exit-code", str(cfg["leak_exit_code"])]
        if cfg.get("config"):
            cmd += ["--config", cfg["config"]]
        return cmd + list(cfg["extra_args"])

    def version_command(self, executable):
        return [executable, "version"]

    def config_id(self, cfg):
        return cfg.get("config") or "default rules"

    def prepare(self, out_dir):
        path = self.report_path(out_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.unlink(missing_ok=True)

    def collect(self, record, out_dir):
        path = self.report_path(out_dir)
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8", errors="replace")

    def success_codes(self, cfg):
        return {0, cfg["leak_exit_code"]}

    def exit_indicates_findings(self, exit_code, cfg):
        return exit_code == cfg["leak_exit_code"]

    def schema_problem(self, data):
        if not isinstance(data, list):
            return "Gitleaks report is not a JSON list"
        if not all(isinstance(item, dict) for item in data):
            return "Gitleaks report contains a non-object entry"
        return None

    def parse(self, data):
        return parse_gitleaks_results(data)

    def consistency_problem(self, record, data, findings, cfg):
        leak_code = cfg["leak_exit_code"]
        if record.exit_code == 0 and findings:
            return "Gitleaks exited 0 (no leaks) but its report lists leaks"
        if record.exit_code == leak_code and not findings:
            return f"Gitleaks exited {leak_code} (leaks found) but its report is empty"
        return None

    def coverage(self, data):
        return None, {"findings": len(data)}, None


ADAPTERS = {a.key: a for a in (SemgrepAdapter(), PipAuditAdapter(), GitleaksAdapter())}


def _lenient_findings(adapter: Adapter, data) -> List[SecurityFinding]:
    """Best-effort parse that never raises (used for every strategy)."""
    if data is None:
        return []
    try:
        return adapter.parse(data)
    except (ValueError, TypeError, AttributeError):
        return []


def normalise(found: List[SecurityFinding], display_name: str, unknown_severity: str) -> List[ev.Finding]:
    """Convert parser output to the common model; unknown severities are mapped, never ignored (FR-17)."""
    result = []
    for f in found:
        raw = str(f.severity or "").upper()
        mapped = raw not in ev.SEVERITY_RANK
        result.append(ev.Finding(
            tool=display_name,
            severity=unknown_severity if mapped else raw,
            raw_severity=f.severity,
            severity_mapped=mapped,
            title=str(f.title),
            description=str(f.description),
            file=f.file,
            line=f.line,
            rule_id=f.rule_id,
        ))
    return result


def evaluate(adapter: Adapter, record: ExecutionRecord, raw: Optional[str], strategy: str,
             cfg: dict, required: bool, unknown_severity: str) -> ev.Evidence:
    """Turn one execution into validated evidence according to the strategy."""
    evidence = ev.Evidence(scanner=adapter.key, display_name=adapter.display_name,
                           required=required, execution=record, config_id=adapter.config_id(cfg))

    if record.launch_error:
        evidence.add_problem(record.launch_error,
                             f"{adapter.display_name}: {record.launch_detail or record.launch_error}")
        return evidence.finalise()

    data = None
    parse_category = parse_message = None
    if raw is None or not raw.strip():
        parse_category, parse_message = ev.NO_OUTPUT, f"{adapter.display_name} produced no report"
    else:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            parse_category = ev.INVALID_JSON
            parse_message = f"{adapter.display_name} report is not valid JSON ({exc.msg} at char {exc.pos})"

    schema_message = adapter.schema_problem(data) if data is not None else None
    raw_findings = _lenient_findings(adapter, data)
    evidence.findings = normalise(raw_findings, adapter.display_name, unknown_severity)
    evidence.exit_indicates_findings = adapter.exit_indicates_findings(record.exit_code, cfg)

    if record.exit_code not in adapter.success_codes(cfg):
        evidence.add_problem(
            ev.NONZERO_EXIT,
            f"{adapter.display_name} exited with code {record.exit_code}; "
            f"expected {sorted(adapter.success_codes(cfg))}",
        )

    if strategy in SCHEMA_STRATEGIES:
        if parse_category:
            evidence.add_problem(parse_category, parse_message)
        elif schema_message:
            evidence.add_problem(ev.SCHEMA_INVALID, f"{adapter.display_name}: {schema_message}")

    if strategy in DEEP_STRATEGIES and data is not None and schema_message is None:
        inconsistency = adapter.consistency_problem(record, data, raw_findings, cfg)
        if inconsistency:
            evidence.add_problem(ev.INCONSISTENT_EXIT, inconsistency)
        category, numbers, message = adapter.coverage(data)
        evidence.coverage = numbers
        if category:
            evidence.add_problem(category, message)
    elif data is not None and schema_message is None:
        evidence.coverage = adapter.coverage(data)[1]

    return evidence.finalise()


def scanner_cwd(target: str) -> str:
    return os.path.abspath(target)
