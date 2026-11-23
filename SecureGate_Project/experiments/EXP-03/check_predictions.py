"""Evaluate the EXP-03 pre-registered predictions P1-P6 (PREREGISTRATION.md section 4).

Reads every shards/*/runs.csv and shards/*/runs.tar.gz (run manifests) below RESULTS and prints,
for each prediction, the observed value, the threshold and CONFIRMED / REFUTED. Writes the same as
predictions.json and predictions.md into --out. Written and tested on EXP-02 level R data
(--level R) before the EXP-03 final run; the thresholds are fixed here and in the pre-registration.

  python check_predictions.py RESULTS --out RESULTS/analysis [--level H]
"""
import argparse
import collections
import csv
import json
import statistics
import tarfile
from pathlib import Path

ARMS = ("S0", "S1", "S2", "S3", "S3P")
SCANNERS = ("semgrep", "pip-audit", "gitleaks")
THRESHOLDS = {"P4_correct_cause_min": 0.95, "P5_consistency_min": 0.99,
              "P6_validation_median_ms_S3": 50.0, "P6_validation_median_ms_S3P": 1000.0}


def load_rows(root, level):
    rows = []
    for f in sorted(Path(root).glob("shards/*/runs.csv")):
        rows += [r for r in csv.DictReader(open(f, newline="")) if r["level"] == level]
    return rows


def base_exit_codes(root, level):
    """Per project: exit code of each scanner in the unmodified project (S0 arm, all repetitions)."""
    codes = collections.defaultdict(lambda: collections.defaultdict(set))
    for tf in sorted(Path(root).glob("shards/*/runs.tar.gz")):
        with tarfile.open(tf) as tar:
            for m in tar.getmembers():
                p = m.name.split("/")
                if len(p) == 4 and p[3] == "run_manifest.json" and p[1].endswith("-base") and p[2].startswith("S0-"):
                    man = json.load(tar.extractfile(m))
                    for s in man["scanners"]:
                        codes[p[1]][s["scanner"]].add((s.get("execution") or {}).get("exit_code"))
    return codes


def modal(values):
    return collections.Counter(values).most_common(1)[0][0]


def evaluate(root, level):
    rows = load_rows(root, level)
    if not rows:
        raise SystemExit(f"no level {level} rows under {root}")
    cells = collections.defaultdict(list)
    for r in rows:
        cells[(r["cell_id"], r["arm"])].append(r)
    fault_cells = sorted({r["cell_id"] for r in rows if r["kind"] == "F"})
    base = base_exit_codes(root, level)
    res = {"level": level, "runs": len(rows), "fault_cells": len(fault_cells),
           "baseline_cells": len({r["cell_id"] for r in rows if r["kind"] == "B"}), "predictions": {}}

    def silent(arm):
        return sorted(c for c in fault_cells if modal(x["verdict"] for x in cells[(c, arm)]) == "PASS")

    # P1: S3 and S3P have no silent pass. P2: neither have S1 and S2.
    for pid, arms in (("P1", ("S3", "S3P")), ("P2", ("S1", "S2"))):
        obs = {a: silent(a) for a in arms}
        res["predictions"][pid] = {"claim": f"no fault cell passes under {' or '.join(arms)}",
                                   "observed": {a: f"{len(v)}/{len(fault_cells)}" for a, v in obs.items()},
                                   "cells": obs, "confirmed": all(not v for v in obs.values())}

    # P3: S0 passes a fault cell iff the faulted scanner exits 0 under the fault and the other two exit 0 unmodified.
    mismatches, predicted_pass = [], 0
    for c in fault_cells:
        r0 = cells[(c, "S0")][0]
        project = c[: c.index(f"-{r0['fault']}-")] + "-base"
        bad = r0["faulted"]
        b = base.get(project)
        if b is None or any(len(b[s]) != 1 for s in SCANNERS):
            mismatches.append((c, "baseline exit codes missing or not constant"))
            continue
        ex = {s: next(iter(b[s])) for s in SCANNERS}
        fault_exit_zero = {"F4": True, "F7": ex[bad] == 0, "F2": False}[r0["fault"]]
        pred = fault_exit_zero and all(ex[s] == 0 for s in SCANNERS if s != bad)
        predicted_pass += pred
        obs = modal(x["verdict"] for x in cells[(c, "S0")]) == "PASS"
        if pred != obs:
            mismatches.append((c, f"predicted {'PASS' if pred else 'not PASS'}, observed {'PASS' if obs else 'not PASS'}"))
    res["predictions"]["P3"] = {"claim": "S0 outcome of every fault cell follows from the unmodified exit codes",
                                "observed": f"{len(fault_cells) - len(mismatches)}/{len(fault_cells)} cells as predicted; "
                                            f"{predicted_pass} predicted silent passes",
                                "mismatches": mismatches, "confirmed": not mismatches}

    # P4: correct cause under S3 (modal category of the faulted scanner is an expected one).
    ok = [c for c in fault_cells if modal(x["category_correct"] == "True" for x in cells[(c, "S3")])]
    rate = len(ok) / len(fault_cells)
    res["predictions"]["P4"] = {"claim": f"S3 names an expected cause in >= {THRESHOLDS['P4_correct_cause_min']:.0%} of fault cells",
                                "observed": f"{len(ok)}/{len(fault_cells)} ({rate:.1%})",
                                "cells_wrong": sorted(set(fault_cells) - set(ok)),
                                "confirmed": rate >= THRESHOLDS["P4_correct_cause_min"]}

    # P5: verdict and category identical in all repetitions for >= 99% of cell-arm pairs.
    pairs = [k for k in cells if k[1] in ARMS]
    same = [k for k in pairs if len({(x["verdict"], x["all_categories"]) for x in cells[k]}) == 1]
    rate = len(same) / len(pairs)
    res["predictions"]["P5"] = {"claim": f">= {THRESHOLDS['P5_consistency_min']:.0%} of cell-arm pairs fully consistent",
                                "observed": f"{len(same)}/{len(pairs)} ({rate:.1%})",
                                "inconsistent": sorted(set(pairs) - set(same)),
                                "confirmed": rate >= THRESHOLDS["P5_consistency_min"]}

    # P6: median evidence-validation time per gate run.
    med = {a: 1000 * statistics.median(float(r["evidence_validation_s"]) for r in rows if r["arm"] == a)
           for a in ("S3", "S3P")}
    res["predictions"]["P6"] = {"claim": "median validation time below 50 ms (S3) and 1000 ms (S3P) per gate run",
                                "observed": {a: f"{v:.2f} ms" for a, v in med.items()},
                                "confirmed": med["S3"] < THRESHOLDS["P6_validation_median_ms_S3"]
                                and med["S3P"] < THRESHOLDS["P6_validation_median_ms_S3P"]}

    # Exploratory (no prediction): modal verdict of each unmodified project per arm.
    res["exploratory_baselines"] = {c: {a: modal(x["verdict"] for x in cells[(c, a)]) for a in ARMS if (c, a) in cells}
                                    for c in sorted({r["cell_id"] for r in rows if r["kind"] == "B"})}
    res["exploratory_s0_silent"] = f"{len(silent('S0'))}/{len(fault_cells)}"
    return res


def markdown(res):
    out = [f"# EXP-03 predictions (level {res['level']})", "",
           f"{res['runs']} runs; {res['fault_cells']} fault cells; {res['baseline_cells']} unmodified projects.", "",
           "| Prediction | Claim | Observed | Result |", "|---|---|---|---|"]
    for pid, p in res["predictions"].items():
        obs = p["observed"] if isinstance(p["observed"], str) else "; ".join(f"{k} {v}" for k, v in p["observed"].items())
        out.append(f"| {pid} | {p['claim']} | {obs} | {'CONFIRMED' if p['confirmed'] else 'REFUTED'} |")
    out += ["", f"Exploratory: S0 silent passes {res['exploratory_s0_silent']}.", "",
            "| Unmodified project | " + " | ".join(ARMS) + " |", "|---|" + "---|" * len(ARMS)]
    for c, v in res["exploratory_baselines"].items():
        out.append(f"| {c} | " + " | ".join(v.get(a, "") for a in ARMS) + " |")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--out", required=True)
    ap.add_argument("--level", default="H")
    a = ap.parse_args()
    res = evaluate(a.results, a.level)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "predictions.json").write_text(json.dumps(res, indent=2, default=list))
    (out / "predictions.md").write_text(markdown(res))
    print(markdown(res))


if __name__ == "__main__":
    main()
