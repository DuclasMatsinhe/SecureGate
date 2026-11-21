"""EXP-02 harness and analysis: the protocol is deterministic and the analysis reproduces EXP-01."""

import csv
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXP02 = ROOT / "SecureGate_Project" / "experiments" / "EXP-02"
PILOT = ROOT / "SecureGate_Project" / "experiments" / "EXP-01-pilot" / "results" / "run-44083865707"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"exp02_{name}", EXP02 / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_protocol_is_deterministic_and_complete():
    harness = _load("harness")
    assert harness.protocol_bytes() == harness.protocol_bytes()
    proto = json.loads(harness.protocol_bytes())
    counts = {level: len(cells) for level, cells in proto["cells"].items()}
    assert counts == {"L1": 59, "L2": 46, "R": 50}
    for level, cells in proto["cells"].items():
        for cell in cells:
            assert cell["ground_truth"] in ("PASS", "BLOCK", "NOT_PASS", "OBSERVED")
            if cell["kind"] in ("F", "FK"):
                assert cell["expected_category"], cell["cell_id"]
    assert set(proto["level_arms"]["L2"]) == {"S0", "S1", "S2", "S3", "S3P"}


def test_l1_shard_runs_and_s3_names_every_cause(tmp_path):
    harness = _load("harness")
    cells = harness.shard(harness.l1_cells(), "1/4")
    rows = harness.run_l1(cells, ("S0", "S3"), 1, tmp_path)
    faulted = [r for r in rows if r["kind"] in ("F", "FK") and r["arm"] == "S3"]
    assert faulted and all(r["verdict"] == "INCOMPLETE" and r["category_correct"] for r in faulted)


def test_analysis_reproduces_the_pilot_l2_numbers(tmp_path):
    analysis = _load("analysis")
    rows = analysis.load([PILOT / "L2"])
    m = analysis.level_metrics(rows, "L2")["per_arm"]
    assert (m["S0"]["SPR_runs"]["k"], m["S0"]["SPR_runs"]["n"]) == (39, 81)
    assert (m["S3"]["SPR_runs"]["k"], m["S3"]["CC_runs"]["k"]) == (3, 75)
    assert [m[s]["MAB_runs"]["k"] for s in ("S0", "S1", "S2", "S3")] == [36, 63, 72, 0]
    assert m["S3"]["SPR_cells"]["k"] == 1 and m["S3"]["SPR_cells"]["n"] == 27


def test_mcnemar_exact():
    analysis = _load("analysis")
    assert analysis.mcnemar_exact(0, 0) == 1.0
    assert analysis.mcnemar_exact(6, 0) == 0.03125
