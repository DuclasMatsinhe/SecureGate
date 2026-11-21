"""Traceability and static guarantees (FR-01, FR-09, FR-30, NFR-03, NFR-04)."""

import ast
import inspect
import json
import re
from datetime import date
from pathlib import Path

import pytest

from security_engine import adapters
from security_engine.gate import SecureGate

from gate_helpers import FakeRunner, policy
from traceability import REQUIREMENT_TESTS, VERIFIED_OUTSIDE_UNIT_TESTS

ROOT = Path(__file__).parents[1]
REQUIREMENTS_DOC = ROOT / "SecureGate_Project" / "docs" / "requirements" / "engine-requirements-v1.md"


def _requirement_ids():
    text = REQUIREMENTS_DOC.read_text(encoding="utf-8")
    return sorted(set(re.findall(r"^\| ((?:N?FR)-\d\d[a-z]?)", text, flags=re.M)))


def _collected_tests():
    names = set()
    for path in Path(__file__).parent.glob("test_*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names |= {f"{path.name}::{n.name}" for n in tree.body
                  if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")}
    return names


def test_every_requirement_is_traced():
    ids = _requirement_ids()
    assert len(ids) == 43, ids  # FR-01..FR-35, FR-20a (v1.2) and NFR-01..NFR-07
    missing = [i for i in ids if not REQUIREMENT_TESTS.get(i) and i not in VERIFIED_OUTSIDE_UNIT_TESTS]
    assert not missing, f"requirements without tests or justification: {missing}"


def test_traced_tests_exist():
    existing = _collected_tests()
    unknown = sorted({t for tests in REQUIREMENT_TESTS.values() for t in tests} - existing)
    assert not unknown, f"traceability names tests that do not exist: {unknown}"


def test_adapters_share_one_interface():
    for adapter in adapters.ADAPTERS.values():
        assert isinstance(adapter, adapters.Adapter)
        for method in ("command", "collect", "schema_problem", "parse", "coverage", "rule_sources"):
            assert callable(getattr(adapter, method))
        assert "record" in inspect.signature(adapter.coverage).parameters


def test_no_shell_execution_in_engine():
    for path in (ROOT / "security_engine").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                assert isinstance(node.value, ast.Constant) and node.value.value is False, path
            if isinstance(node, ast.Attribute) and node.attr in {"system", "popen"} and \
                    getattr(node.value, "id", None) == "os":
                pytest.fail(f"os.{node.attr} used in {path}")


def test_dockerfile_runs_as_non_root():
    users = re.findall(r"^USER\s+(\S+)", (ROOT / "Dockerfile").read_text(encoding="utf-8"), flags=re.M)
    assert users and users[-1] not in {"root", "0"}


def test_manifest_has_no_personal_fields(tmp_path):
    result = SecureGate(policy(), runner=FakeRunner(), today=date(2026, 11, 17)).run(
        target=str(tmp_path), out_dir=str(tmp_path / "out"))
    text = json.dumps(result.manifest).lower()
    for forbidden in ('"author', '"email', '"user"', str(Path.home()).lower()):
        assert forbidden not in text
