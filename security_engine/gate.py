"""SecureGate orchestrator: run scanners, validate evidence, decide, record.

Fail-safe by construction: an unexpected error anywhere in the engine
becomes an ENGINE_ERROR (INCOMPLETE under S3, BLOCK otherwise), never PASS
(FR-26).
"""

from __future__ import annotations

import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional

from . import __version__
from . import evidence as ev
from .adapters import ADAPTERS, Adapter, evaluate, scanner_cwd
from .execution import CommandRunner, VersionCache, resolve_executable, utc_now
from .policy import Policy
from .report import build_manifest, render_markdown, write_json
from .verdict import EXIT_CODES, INCOMPLETE, BLOCK, Reason, Verdict, decide


@dataclass
class GateResult:
    verdict: Verdict
    evidences: List[ev.Evidence]
    manifest: dict
    manifest_path: Path
    report_path: Path
    report_markdown: str


class SecureGate:
    def __init__(self, policy: Policy, runner: Optional[CommandRunner] = None,
                 adapters: Optional[Dict[str, Adapter]] = None, today: Optional[date] = None):
        self.policy = policy
        self.runner = runner or CommandRunner()
        self.adapters = adapters or ADAPTERS
        self.today = today

    def _scan(self, name: str, target: str, raw_dir: Path, versions: VersionCache) -> ev.Evidence:
        adapter = self.adapters[name]
        cfg = self.policy.scanners[name]
        required = name in self.policy.required_scanners
        try:
            executable = resolve_executable(adapter.executable_name, cfg.get("executable") or None)
            adapter.prepare(raw_dir)
            command = adapter.command(executable, cfg, raw_dir)
            record = self.runner.run(command, timeout=cfg["timeout"], cwd=scanner_cwd(target))
            raw = adapter.collect(record, raw_dir)
            validation_start = time.perf_counter()
            evidence = evaluate(adapter, record, raw, self.policy.strategy, cfg, required,
                                self.policy.unknown_severity)
            evidence.validation_s = time.perf_counter() - validation_start
            evidence.rule_sources = adapter.rule_sources(cfg, target)
            if not record.launch_error:
                evidence.version = versions.get(self.runner, name, adapter.version_command(executable))
            return evidence
        except Exception as exc:  # noqa: BLE001 - fail-safe by design
            evidence = ev.Evidence(scanner=name, display_name=adapter.display_name, required=required)
            evidence.add_problem(ev.ENGINE_ERROR, f"Engine error while handling {adapter.display_name}: "
                                                  f"{type(exc).__name__}: {exc}")
            return evidence.finalise()

    def run(self, target: str = ".", out_dir: str = "securegate-out") -> GateResult:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        run_id = str(uuid.uuid4())
        started_at, start = utc_now(), time.monotonic()
        versions = VersionCache()
        raw_dir = out / "raw" / run_id  # fresh per run, so no earlier output can be reused (FR-07)

        evidences = [self._scan(name, target, raw_dir, versions) for name in self.policy.enabled_scanners()]
        scanning_s = time.monotonic() - start

        decision_start = time.perf_counter()
        try:
            verdict = decide(evidences, self.policy, self.today)
        except Exception as exc:  # noqa: BLE001 - fail-safe by design
            outcome = INCOMPLETE if self.policy.strategy == "S3" else BLOCK
            verdict = Verdict(verdict=outcome, exit_code=EXIT_CODES[outcome], strategy=self.policy.strategy,
                              reasons=[Reason(ev.ENGINE_ERROR, f"Engine error while deciding: "
                                                               f"{type(exc).__name__}: {exc}")])

        decision_s = time.perf_counter() - decision_start

        timings = {
            "scanning_s": round(scanning_s, 3),
            "scanner_execution_s": round(sum(e.execution.duration_s for e in evidences if e.execution), 3),
            "evidence_validation_s": round(sum(e.validation_s for e in evidences), 6),
            "decision_s": round(decision_s, 6),
        }
        manifest = build_manifest(
            run_id=run_id, engine_version=__version__, started_at=started_at, finished_at=utc_now(),
            duration_s=time.monotonic() - start, target_name=Path(scanner_cwd(target)).name,
            commit=_git_commit(target), policy=self.policy, evidences=evidences, verdict=verdict,
            timings=timings,
        )
        manifest_path = out / "run_manifest.json"
        write_json(manifest_path, manifest)
        markdown = render_markdown(manifest)
        report_path = out / "report.md"
        report_path.write_text(markdown, encoding="utf-8")
        return GateResult(verdict, evidences, manifest, manifest_path, report_path, markdown)


def _git_commit(target: str) -> Optional[str]:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=scanner_cwd(target),
                                capture_output=True, text=True, timeout=10, check=False)
        sha = result.stdout.strip()
        return sha if result.returncode == 0 and len(sha) == 40 else None
    except (OSError, subprocess.SubprocessError):
        return None
