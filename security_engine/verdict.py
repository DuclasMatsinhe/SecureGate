"""Verdict and policy decision (M4, FR-19 to FR-26).

PASS        all required scanners produced valid evidence, no blocking finding
BLOCK       valid evidence shows a finding at or above the policy threshold
INCOMPLETE  a required scanner's evidence is invalid (strategy S3 only);
            blocking findings from valid scanners are still listed

Under strategies S0-S2 there is no INCOMPLETE state: invalid evidence
fails closed as BLOCK, as typical gates do.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import date
from typing import List, Optional

from . import evidence as ev
from .policy import Policy

PASS = "PASS"
BLOCK = "BLOCK"
INCOMPLETE = "INCOMPLETE"

EXIT_CODES = {PASS: 0, BLOCK: 1, INCOMPLETE: 2}
EXIT_CONFIG_ERROR = 3


@dataclass
class Reason:
    code: str
    message: str
    scanner: Optional[str] = None

    def to_dict(self) -> dict:
        return {"code": self.code, "scanner": self.scanner, "message": self.message}


@dataclass
class Verdict:
    verdict: str
    exit_code: int
    strategy: str
    reasons: List[Reason] = field(default_factory=list)
    notes: List[Reason] = field(default_factory=list)
    blocking_findings: List[ev.Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "strategy": self.strategy,
            "reasons": [r.to_dict() for r in self.reasons],
            "notes": [n.to_dict() for n in self.notes],
            "blocking_findings": len(self.blocking_findings),
        }


def apply_suppressions(evidences: List[ev.Evidence], policy: Policy, today: date) -> List[Reason]:
    """Mark findings covered by an active suppression; report expired ones (FR-24)."""
    notes: List[Reason] = []
    for supp in policy.suppressions:
        active = today <= supp.expires
        matched = 0
        for e in evidences:
            if supp.tool and supp.tool != e.scanner:
                continue
            for f in e.findings:
                if f.rule_id != supp.rule_id:
                    continue
                if supp.path and not (f.file and fnmatch.fnmatch(f.file, supp.path)):
                    continue
                matched += 1
                if active:
                    f.suppressed = True
                    f.suppression_reason = supp.reason
        if matched and not active:
            notes.append(Reason("SUPPRESSION_EXPIRED",
                                f"Suppression for {supp.rule_id} expired on {supp.expires.isoformat()}; "
                                f"{matched} finding(s) count again"))
    return notes


def decide(evidences: List[ev.Evidence], policy: Policy, today: Optional[date] = None) -> Verdict:
    strategy = policy.strategy
    notes = apply_suppressions(evidences, policy, today or date.today())

    blocking: List[ev.Finding] = []
    for e in evidences:
        threshold = ev.SEVERITY_RANK[policy.threshold_for(e.scanner)]
        for f in e.findings:
            if f.severity_mapped:
                notes.append(Reason("SEVERITY_MAPPED",
                                    f"{e.display_name} severity {f.raw_severity!r} is unknown; "
                                    f"treated as {f.severity} ({f.rule_id or f.title})", e.scanner))
            if not f.suppressed and f.rank() >= threshold:
                blocking.append(f)

    invalid_required = [e for e in evidences if e.required and e.status == ev.INVALID]
    for e in evidences:
        if not e.required and e.status == ev.INVALID:
            notes.append(Reason(e.category, f"Optional scanner: {e.problems[0].message}", e.scanner))

    reasons: List[Reason] = []
    for e in invalid_required:
        for p in e.problems:
            reasons.append(Reason(p.category, p.message, e.scanner))

    exit_signal = []
    if strategy == "S0":
        blocking_ids = {id(f) for f in blocking}
        exit_signal = [e for e in evidences
                       if e.exit_indicates_findings and not any(id(f) in blocking_ids for f in e.findings)]

    scanner_of = {id(f): e.scanner for e in evidences for f in e.findings}
    for f in blocking:
        where = f"{f.file}:{f.line}" if f.file else "dependency"
        # Reason.scanner is always the scanner id (as in every other reason), never the display name.
        reasons.append(Reason("BLOCKING_FINDING",
                              f"{f.tool} {f.severity}: {f.rule_id or f.title} ({where})",
                              scanner_of.get(id(f), f.tool)))
    for e in exit_signal:
        reasons.append(Reason("EXIT_CODE_FINDINGS",
                              f"{e.display_name} exit code indicates findings", e.scanner))

    if invalid_required and strategy == "S3":
        verdict = INCOMPLETE
        exit_code = 0 if policy.on_incomplete == "warn" else EXIT_CODES[INCOMPLETE]
        if policy.on_incomplete == "review":
            notes.append(Reason("MANUAL_REVIEW", "Manual security review required before merging"))
    elif invalid_required or blocking or exit_signal:
        verdict, exit_code = BLOCK, EXIT_CODES[BLOCK]
    else:
        verdict, exit_code = PASS, EXIT_CODES[PASS]

    order = {c: i for i, c in enumerate(ev.CATEGORY_ORDER)}
    reasons.sort(key=lambda r: (r.code == "BLOCKING_FINDING", order.get(r.code, 99), r.scanner or "", r.message))
    return Verdict(verdict=verdict, exit_code=exit_code, strategy=strategy,
                   reasons=reasons, notes=notes, blocking_findings=blocking)
