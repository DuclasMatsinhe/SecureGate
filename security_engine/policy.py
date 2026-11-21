"""Versioned security policy (M4, FR-22).

The policy is a TOML file (Python's built-in `tomllib`, so no extra
dependency). Every field is validated; unknown keys are rejected so a typo
cannot silently weaken the gate.
"""

from __future__ import annotations

import copy
import hashlib
import json
import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional

from .evidence import SEVERITY_RANK

STRATEGIES = ("S0", "S1", "S2", "S3")
ON_INCOMPLETE = ("block", "warn", "review")
SCANNERS = ("semgrep", "pip-audit", "gitleaks")
MAX_TIMEOUT_S = 3600

DEFAULTS: dict = {
    "version": "1.0",
    "strategy": "S3",
    "on_incomplete": "block",
    "required_scanners": list(SCANNERS),
    "unknown_severity": "HIGH",
    "thresholds": {"default": "HIGH"},
    "scanners": {
        "semgrep": {
            "enabled": True,
            "timeout": 600,
            "config": "p/python",
            "executable": "",
            "extra_args": [],
            "parse_check": False,
        },
        "pip-audit": {
            "enabled": True,
            "timeout": 300,
            "requirements": "requirements.txt",
            "executable": "",
            "extra_args": [],
        },
        "gitleaks": {
            "enabled": True,
            "timeout": 300,
            "leak_exit_code": 3,
            "config": "",
            "executable": "",
            "extra_args": [],
        },
    },
    "suppressions": [],
}

SCANNER_KEYS = {
    "semgrep": {"enabled", "timeout", "config", "executable", "extra_args", "parse_check"},
    "pip-audit": {"enabled", "timeout", "requirements", "executable", "extra_args"},
    "gitleaks": {"enabled", "timeout", "leak_exit_code", "config", "executable", "extra_args"},
}
TOP_KEYS = set(DEFAULTS)
SUPPRESSION_KEYS = {"rule_id", "tool", "path", "reason", "expires"}


class PolicyError(ValueError):
    """The policy file is missing, unreadable or invalid."""


@dataclass
class Suppression:
    rule_id: str
    reason: str
    expires: date
    tool: Optional[str] = None
    path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "tool": self.tool,
            "path": self.path,
            "reason": self.reason,
            "expires": self.expires.isoformat(),
        }


@dataclass
class Policy:
    version: str
    strategy: str
    on_incomplete: str
    required_scanners: List[str]
    unknown_severity: str
    thresholds: Dict[str, str]
    scanners: Dict[str, dict]
    suppressions: List[Suppression] = field(default_factory=list)
    source: str = "built-in defaults"

    def threshold_for(self, scanner: str) -> str:
        return self.thresholds.get(scanner, self.thresholds["default"])

    def enabled_scanners(self) -> List[str]:
        return [s for s in SCANNERS if self.scanners[s]["enabled"]]

    def with_strategy(self, strategy: str) -> "Policy":
        if strategy not in STRATEGIES:
            raise PolicyError(f"strategy must be one of {', '.join(STRATEGIES)}; got {strategy!r}")
        clone = copy.deepcopy(self)
        clone.strategy = strategy
        return clone

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "strategy": self.strategy,
            "on_incomplete": self.on_incomplete,
            "required_scanners": list(self.required_scanners),
            "unknown_severity": self.unknown_severity,
            "thresholds": dict(self.thresholds),
            "scanners": copy.deepcopy(self.scanners),
            "suppressions": [s.to_dict() for s in self.suppressions],
        }

    def sha256(self) -> str:
        """Hash of the effective policy (defaults included), for the manifest."""
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def _severity(value, where: str) -> str:
    if not isinstance(value, str) or value.upper() not in SEVERITY_RANK:
        raise PolicyError(f"{where} must be one of {', '.join(SEVERITY_RANK)}; got {value!r}")
    return value.upper()


def _validate(raw: dict, source: str) -> Policy:
    unknown = set(raw) - TOP_KEYS
    if unknown:
        raise PolicyError(f"unknown policy key(s): {', '.join(sorted(unknown))}")

    merged = _merge(DEFAULTS, raw)

    if not isinstance(merged["version"], str) or not merged["version"].strip():
        raise PolicyError("version must be a non-empty string")
    if merged["strategy"] not in STRATEGIES:
        raise PolicyError(f"strategy must be one of {', '.join(STRATEGIES)}; got {merged['strategy']!r}")
    if merged["on_incomplete"] not in ON_INCOMPLETE:
        raise PolicyError(
            f"on_incomplete must be one of {', '.join(ON_INCOMPLETE)}; got {merged['on_incomplete']!r}"
        )

    scanners = merged["scanners"]
    if not isinstance(scanners, dict):
        raise PolicyError("scanners must be a table")
    extra_scanners = set(scanners) - set(SCANNERS)
    if extra_scanners:
        raise PolicyError(f"unknown scanner(s): {', '.join(sorted(extra_scanners))}")
    for name in SCANNERS:
        cfg = scanners[name]
        bad = set(cfg) - SCANNER_KEYS[name]
        if bad:
            raise PolicyError(f"unknown key(s) for scanner {name}: {', '.join(sorted(bad))}")
        if not isinstance(cfg["enabled"], bool):
            raise PolicyError(f"scanners.{name}.enabled must be true or false")
        timeout = cfg["timeout"]
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= MAX_TIMEOUT_S:
            raise PolicyError(f"scanners.{name}.timeout must be a number between 0 and {MAX_TIMEOUT_S} seconds")
        if not isinstance(cfg["executable"], str):
            raise PolicyError(f"scanners.{name}.executable must be a string")
        if not isinstance(cfg["extra_args"], list) or not all(isinstance(a, str) for a in cfg["extra_args"]):
            raise PolicyError(f"scanners.{name}.extra_args must be a list of strings")
    semgrep_config = scanners["semgrep"]["config"]
    configs = semgrep_config if isinstance(semgrep_config, list) else [semgrep_config]
    if not configs or not all(isinstance(c, str) and c.strip() for c in configs):
        raise PolicyError("scanners.semgrep.config must name a rule pack or rules file, or a list of them")
    if not isinstance(scanners["semgrep"]["parse_check"], bool):
        raise PolicyError("scanners.semgrep.parse_check must be true or false")
    if any(c.strip() == "auto" for c in configs):
        raise PolicyError("scanners.semgrep.config must be pinned; 'auto' changes rules between runs")
    if not isinstance(scanners["pip-audit"]["requirements"], str) or not scanners["pip-audit"]["requirements"]:
        raise PolicyError("scanners.pip-audit.requirements must be a file path")
    leak_code = scanners["gitleaks"]["leak_exit_code"]
    if isinstance(leak_code, bool) or not isinstance(leak_code, int) or not 2 <= leak_code <= 125:
        raise PolicyError("scanners.gitleaks.leak_exit_code must be an integer from 2 to 125 (0 and 1 are reserved)")
    if not isinstance(scanners["gitleaks"]["config"], str):
        raise PolicyError("scanners.gitleaks.config must be a string (empty = default rules)")

    required = merged["required_scanners"]
    if not isinstance(required, list) or not all(isinstance(s, str) for s in required):
        raise PolicyError("required_scanners must be a list of scanner names")
    for name in required:
        if name not in SCANNERS:
            raise PolicyError(f"required scanner {name!r} is not a known scanner")
        if not scanners[name]["enabled"]:
            raise PolicyError(f"required scanner {name!r} is disabled")

    unknown_severity = _severity(merged["unknown_severity"], "unknown_severity")

    thresholds = merged["thresholds"]
    if not isinstance(thresholds, dict) or "default" not in thresholds:
        raise PolicyError("thresholds must be a table with a 'default' entry")
    clean_thresholds = {}
    for key, value in thresholds.items():
        if key != "default" and key not in SCANNERS:
            raise PolicyError(f"thresholds.{key}: unknown scanner")
        clean_thresholds[key] = _severity(value, f"thresholds.{key}")

    suppressions = []
    raw_suppressions = merged["suppressions"]
    if not isinstance(raw_suppressions, list):
        raise PolicyError("suppressions must be a list of tables")
    for index, item in enumerate(raw_suppressions):
        where = f"suppressions[{index}]"
        if not isinstance(item, dict):
            raise PolicyError(f"{where} must be a table")
        bad = set(item) - SUPPRESSION_KEYS
        if bad:
            raise PolicyError(f"{where}: unknown key(s) {', '.join(sorted(bad))}")
        for key in ("rule_id", "reason"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise PolicyError(f"{where}.{key} is required")
        expires = item.get("expires")
        if isinstance(expires, str):
            try:
                expires = date.fromisoformat(expires)
            except ValueError as exc:
                raise PolicyError(f"{where}.expires must be a date (YYYY-MM-DD)") from exc
        if not isinstance(expires, date):
            raise PolicyError(f"{where}.expires is required (YYYY-MM-DD)")
        tool = item.get("tool")
        if tool is not None and tool not in SCANNERS:
            raise PolicyError(f"{where}.tool must be one of {', '.join(SCANNERS)}")
        suppressions.append(
            Suppression(rule_id=item["rule_id"], reason=item["reason"], expires=expires,
                        tool=tool, path=item.get("path"))
        )

    return Policy(
        version=merged["version"],
        strategy=merged["strategy"],
        on_incomplete=merged["on_incomplete"],
        required_scanners=list(required),
        unknown_severity=unknown_severity,
        thresholds=clean_thresholds,
        scanners=scanners,
        suppressions=suppressions,
        source=source,
    )


def load_policy(path: Optional[str] = None) -> Policy:
    """Load and validate a policy file; with no path, use the built-in defaults."""
    if path is None:
        return _validate({}, "built-in defaults")
    file = Path(path)
    try:
        raw = tomllib.loads(file.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"policy file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"policy file is not valid TOML: {exc}") from exc
    except OSError as exc:
        raise PolicyError(f"could not read policy file: {exc}") from exc
    return _validate(raw, file.name)


def policy_from_dict(raw: dict, source: str = "inline") -> Policy:
    """Validate a policy given as a dictionary (used by tests and the harness)."""
    return _validate(raw, source)
