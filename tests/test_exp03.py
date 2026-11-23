"""EXP-03 held-out confirmation: the protocol is deterministic, complete, frozen and reuses EXP-02 unchanged."""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXP03 = ROOT / "SecureGate_Project" / "experiments" / "EXP-03"
EXP02 = ROOT / "SecureGate_Project" / "experiments" / "EXP-02"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"exp03_{name}", EXP03 / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_protocol_is_deterministic_and_complete():
    m = _load("heldout")
    assert m.protocol_bytes() == m.protocol_bytes()
    proto = json.loads(m.protocol_bytes())
    kinds = [c["kind"] for c in proto["cells"]]
    assert kinds.count("B") == 8 and kinds.count("F") == 72
    assert all(c["level"] == "H" and (c["kind"] == "B" or c["expected_category"]) for c in proto["cells"])
    assert proto["repetitions"] == 10


def test_heldout_projects_are_new_and_one_per_shard():
    m = _load("heldout")
    assert not set(m.HELDOUT_REPOS) & set(m.h.REAL_REPOS)
    shards = [m.shard_repos(m.HELDOUT_REPOS, f"{i}/8") for i in range(1, 9)]
    assert all(len(s) == 1 for s in shards)
    assert sorted(k for s in shards for k in s) == sorted(m.HELDOUT_REPOS)


def test_exp03_reuses_the_frozen_exp02_harness():
    m = _load("heldout")
    reuses = json.loads(m.protocol_bytes())["reuses"]
    assert reuses["exp02_protocol_sha256"] == (EXP02 / "FROZEN.sha256").read_text().split()[0]
    assert reuses["harness_sha256"] == hashlib.sha256((EXP02 / "harness.py").read_bytes()).hexdigest()


def test_frozen_digest_matches_protocol():
    m = _load("heldout")
    frozen = EXP03 / "FROZEN.sha256"
    digest = hashlib.sha256(m.protocol_bytes()).hexdigest()
    assert frozen.read_text().split()[0] == digest
    assert (EXP03 / "protocol.json").read_bytes() == m.protocol_bytes()
