"""Evidence model and failure taxonomy (M3).

Every scanner run is turned into one `Evidence` object: VALID or INVALID,
with exactly one primary failure category when invalid (FR-15).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .execution import ExecutionRecord

VALID = "VALID"
INVALID = "INVALID"

# Failure categories, in precedence order: when several apply, the first
# one listed becomes the primary category.
TOOL_MISSING = "TOOL_MISSING"
LAUNCH_ERROR = "LAUNCH_ERROR"
TIMEOUT = "TIMEOUT"
NONZERO_EXIT = "NONZERO_EXIT"
NO_OUTPUT = "NO_OUTPUT"
INVALID_JSON = "INVALID_JSON"
SCHEMA_INVALID = "SCHEMA_INVALID"
INCONSISTENT_EXIT = "INCONSISTENT_EXIT"
NO_COVERAGE = "NO_COVERAGE"
PARTIAL_COVERAGE = "PARTIAL_COVERAGE"
ENGINE_ERROR = "ENGINE_ERROR"

CATEGORY_ORDER = [
    TOOL_MISSING,
    LAUNCH_ERROR,
    TIMEOUT,
    NONZERO_EXIT,
    NO_OUTPUT,
    INVALID_JSON,
    SCHEMA_INVALID,
    INCONSISTENT_EXIT,
    NO_COVERAGE,
    PARTIAL_COVERAGE,
    ENGINE_ERROR,
]

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    """A normalised finding (FR-16)."""

    tool: str
    severity: str
    title: str
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    rule_id: Optional[str] = None
    raw_severity: Optional[str] = None
    severity_mapped: bool = False
    from_incomplete_evidence: bool = False
    suppressed: bool = False
    suppression_reason: Optional[str] = None

    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "severity": self.severity,
            "raw_severity": self.raw_severity,
            "severity_mapped": self.severity_mapped,
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "from_incomplete_evidence": self.from_incomplete_evidence,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
        }


@dataclass
class Problem:
    category: str
    message: str


@dataclass
class Evidence:
    """Validated outcome of one scanner run."""

    scanner: str
    display_name: str
    required: bool
    status: str = VALID
    category: Optional[str] = None
    problems: List[Problem] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    exit_indicates_findings: bool = False
    version: str = "unknown"
    config_id: Optional[str] = None
    rule_sources: List[dict] = field(default_factory=list)
    checks_applied: List[str] = field(default_factory=list)
    validation_s: float = 0.0
    execution: Optional[ExecutionRecord] = None

    def add_problem(self, category: str, message: str) -> None:
        self.problems.append(Problem(category, message))

    def finalise(self) -> "Evidence":
        """Set status and primary category from the recorded problems."""
        if self.problems:
            self.status = INVALID
            present = {p.category for p in self.problems}
            self.category = next(c for c in CATEGORY_ORDER if c in present)
            for finding in self.findings:
                finding.from_incomplete_evidence = True
        else:
            self.status = VALID
            self.category = None
        return self

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "required": self.required,
            "version": self.version,
            "config": self.config_id,
            "rule_sources": self.rule_sources,
            "checks_applied": list(self.checks_applied),
            "evidence_status": self.status,
            "category": self.category,
            "problems": [{"category": p.category, "message": p.message} for p in self.problems],
            "coverage": self.coverage,
            "exit_indicates_findings": self.exit_indicates_findings,
            "findings_count": len(self.findings),
            "validation_s": round(self.validation_s, 6),
            "execution": self.execution.to_dict() if self.execution else None,
        }
