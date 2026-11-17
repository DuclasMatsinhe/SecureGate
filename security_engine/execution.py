"""Scanner process execution (M2).

Runs one external command with a hard timeout and records what happened:
exit code, output, duration, and launch failures (missing tool, OS error,
timeout). The runner is injectable so tests and the fault-injection
harness can replace real execution (requirement FR-34).
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Sequence

TOOL_MISSING = "TOOL_MISSING"
LAUNCH_ERROR = "LAUNCH_ERROR"
TIMEOUT = "TIMEOUT"

STDERR_TAIL_CHARS = 2000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ExecutionRecord:
    """Raw outcome of running one scanner command."""

    command: List[str]
    started_at: str
    duration_s: float
    exit_code: Optional[int]
    stdout: str = ""
    stderr: str = ""
    launch_error: Optional[str] = None
    launch_detail: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "command": list(self.command),
            "started_at": self.started_at,
            "duration_s": round(self.duration_s, 3),
            "exit_code": self.exit_code,
            "launch_error": self.launch_error,
            "launch_detail": self.launch_detail,
            "stdout_bytes": len(self.stdout.encode("utf-8", "replace")),
            "stderr_tail": self.stderr[-STDERR_TAIL_CHARS:],
        }


class CommandRunner:
    """Runs commands for real, without a shell, with a hard timeout."""

    def run(
        self,
        command: Sequence[str],
        timeout: float,
        cwd: Optional[str] = None,
    ) -> ExecutionRecord:
        command = [str(part) for part in command]
        started_at = utc_now()
        start = time.monotonic()

        def record(**kwargs) -> ExecutionRecord:
            return ExecutionRecord(
                command=command,
                started_at=started_at,
                duration_s=time.monotonic() - start,
                **kwargs,
            )

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=cwd,
                start_new_session=(os.name != "nt"),
            )
        except FileNotFoundError as exc:
            return record(exit_code=None, launch_error=TOOL_MISSING, launch_detail=str(exc))
        except OSError as exc:
            return record(exit_code=None, launch_error=LAUNCH_ERROR, launch_detail=str(exc))

        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_process_tree(process)
            stdout, stderr = process.communicate()
            return record(
                exit_code=None,
                stdout=stdout or "",
                stderr=stderr or "",
                launch_error=TIMEOUT,
                launch_detail=f"Exceeded the {timeout:g} s timeout and was stopped.",
            )

        return record(exit_code=process.returncode, stdout=stdout or "", stderr=stderr or "")


def _kill_process_tree(process: subprocess.Popen) -> None:
    """Stop the scanner and any child processes it started."""
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except OSError:
            pass


def resolve_executable(name: str, override: Optional[str] = None) -> str:
    """Find a scanner executable.

    Order: explicit policy override, PATH, the current Python environment's
    scripts folder. Falls back to the bare name so a missing tool is
    reported as TOOL_MISSING at run time instead of raising here.
    """
    if override:
        return override
    found = shutil.which(name)
    if found:
        return found
    scripts_dir = os.path.dirname(sys.executable)
    for candidate in (name, f"{name}.exe"):
        path = os.path.join(scripts_dir, candidate)
        if os.path.isfile(path):
            return path
    return name


@dataclass
class VersionCache:
    """Remembers tool versions within one run."""

    versions: dict = field(default_factory=dict)

    def get(self, runner: CommandRunner, key: str, command: Sequence[str]) -> str:
        if key not in self.versions:
            try:
                result = runner.run(command, timeout=60)
                text = (result.stdout or result.stderr or "").strip()
                if result.launch_error or result.exit_code != 0 or not text:
                    self.versions[key] = "unknown"
                else:
                    self.versions[key] = text.splitlines()[0][:120]
            except Exception:  # noqa: BLE001 - version lookup must never break a run
                self.versions[key] = "unknown"
        return self.versions[key]
