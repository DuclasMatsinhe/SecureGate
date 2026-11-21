"""EXP-02 analysis: one command from raw runs.csv files to every number reported in the paper.

Usage:
  python analysis.py --out analysis/ results/L1-1 results/L2-1 ... results/R-5
  python analysis.py --out pilot-check/ path/to/EXP-01/L2        (also reads EXP-01 pilot files)

Levels are never pooled. Every rate is reported with its numerator, denominator and a Wilson
95% interval. Because cells are designed (not sampled) and deterministic, the condition (cell)
is the unit of analysis; run-level rates are reported alongside for continuity with EXP-01.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path

FAULT_KINDS = ("F", "FK")

METRIC_DEFINITIONS = {
    "SPR_cells": "Silent-pass rate (primary). Faulted cells (kind F or FK) whose modal verdict over repetitions is "
                 "PASS / all faulted cells of the level.",
    "SPR_runs": "Faulted runs with verdict PASS / all faulted runs (kind F or FK).",
    "CC_runs": "Correct cause. Faulted runs with verdict INCOMPLETE and every faulted scanner labelled with an "
               "expected category / all faulted runs. Meaningful for S3 and S3P only.",
    "CC_cells": "Faulted cells whose modal run is INCOMPLETE with the expected category / all faulted cells.",
    "MAB_runs": "Misattributed BLOCK. Runs of kind F (fault, no finding anywhere) with verdict BLOCK / all kind-F runs: "
                "the gate blames the code although only a tool failed.",
    "FBR_runs": "False-block rate. Clean-control runs (kind C) with any verdict other than PASS / all kind-C runs.",
    "TBR_runs": "True-block rate. Known-finding runs (kind K) with verdict BLOCK / all kind-K runs.",
    "FPP_runs": "Finding preservation. Partial-failure runs (kind FK) whose verdict lists the known finding as a "
                "BLOCKING_FINDING reason / all kind-FK runs.",
    "consistency": "(cell, arm) pairs whose repetitions all gave the same verdict / all (cell, arm) pairs.",
    "overhead": "Medians over clean, known-finding and baseline runs: evidence-validation time, its share of the "
                "engine's run time, and wall time per run.",
    "paired_tests": "Exact two-sided McNemar test on cell-level silent passes between two arms (discordant cells only).",
}


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return {"k": k, "n": n, "rate": round(p, 4), "ci95": [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]}


def mcnemar_exact(b, c):
    """Two-sided exact McNemar p-value from the discordant counts b and c."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return round(min(1.0, 2 * tail), 6)


def _bool(x):
    return x is True or str(x) == "True"


def load(paths):
    rows, seen = [], set()
    for p in paths:
        p = Path(p)
        f = p / "runs.csv" if p.is_dir() else p
        for r in csv.DictReader(open(f, newline="")):
            r.setdefault("arm", r.get("strategy"))
            r["arm"] = r.get("arm") or r.get("strategy")
            key = (r["level"], r["cell_id"], r["arm"], r["rep"])
            if key in seen:
                raise SystemExit(f"duplicate run {key} in {f}")
            seen.add(key)
            for k in ("wall_s", "duration_s", "scanner_execution_s", "evidence_validation_s", "decision_s"):
                r[k] = float(r[k]) if r.get(k) not in (None, "") else None
            rows.append(r)
    return rows


def modal(values):
    return Counter(values).most_common(1)[0][0]


def by_cell(rs):
    groups = defaultdict(list)
    for r in rs:
        groups[r["cell_id"]].append(r)
    return groups


def _q(values):
    values = sorted(v for v in values if v is not None)
    if not values:
        return None
    qs = statistics.quantiles(values, n=4) if len(values) > 1 else [values[0]] * 3
    return {"n": len(values), "median": round(statistics.median(values), 6),
            "iqr": [round(qs[0], 6), round(qs[2], 6)]}


def level_metrics(rows, level):
    rs_level = [r for r in rows if r["level"] == level]
    arms = sorted({r["arm"] for r in rs_level}, key=lambda a: (a.rstrip("P"), a))
    out = {"arms": arms, "per_arm": {}, "per_fault": {}, "paired_tests": [], "consistency": None, "cells": {}}
    cell_pass = {}
    for arm in arms:
        rs = [r for r in rs_level if r["arm"] == arm]
        F = [r for r in rs if r["kind"] in FAULT_KINDS]
        Fonly = [r for r in rs if r["kind"] == "F"]
        C = [r for r in rs if r["kind"] == "C"]
        K = [r for r in rs if r["kind"] == "K"]
        FK = [r for r in rs if r["kind"] == "FK"]
        fcells = by_cell(F)
        modal_verdict = {c: modal([r["verdict"] for r in v]) for c, v in fcells.items()}
        cc_cell = {c: modal([(r["verdict"] == "INCOMPLETE" and _bool(r["category_correct"])) for r in v])
                   for c, v in fcells.items()}
        cell_pass[arm] = {c: v == "PASS" for c, v in modal_verdict.items()}
        timing_rows = [r for r in rs if r["kind"] in ("C", "K", "B")]
        out["per_arm"][arm] = {
            "SPR_cells": wilson(sum(v == "PASS" for v in modal_verdict.values()), len(modal_verdict)),
            "SPR_runs": wilson(sum(r["verdict"] == "PASS" for r in F), len(F)),
            "CC_runs": wilson(sum(r["verdict"] == "INCOMPLETE" and _bool(r["category_correct"]) for r in F), len(F)),
            "CC_cells": wilson(sum(cc_cell.values()), len(cc_cell)),
            "MAB_runs": wilson(sum(r["verdict"] == "BLOCK" for r in Fonly), len(Fonly)),
            "FBR_runs": wilson(sum(r["verdict"] != "PASS" for r in C), len(C)),
            "TBR_runs": wilson(sum(r["verdict"] == "BLOCK" for r in K), len(K)),
            "FPP_runs": wilson(sum(_bool(r["findings_preserved"]) for r in FK), len(FK)),
            "verdicts_on_faults": {v: sum(r["verdict"] == v for r in F) for v in ("PASS", "BLOCK", "INCOMPLETE")},
            "silent_pass_cells": sorted(c for c, v in modal_verdict.items() if v == "PASS"),
            "overhead": {
                "evidence_validation_s": _q([r["evidence_validation_s"] for r in timing_rows]),
                "validation_share_of_run": _q([r["evidence_validation_s"] / r["duration_s"] for r in timing_rows
                                               if r["duration_s"] and r["evidence_validation_s"] is not None]),
                "wall_s": _q([r["wall_s"] for r in timing_rows]),
                "duration_s": _q([r["duration_s"] for r in timing_rows]),
            },
        }
        faults = sorted({r["fault"] for r in F}, key=lambda f: int(f[1:]) if f[1:].isdigit() else 99)
        for fault in faults:
            cells_f = {c: v for c, v in modal_verdict.items() if fcells[c][0]["fault"] == fault}
            out["per_fault"].setdefault(fault, {})[arm] = wilson(sum(v == "PASS" for v in cells_f.values()),
                                                                len(cells_f))
    for a, b in zip(arms, arms[1:]):
        common = sorted(set(cell_pass[a]) & set(cell_pass[b]))
        b_only = sum(cell_pass[a][c] and not cell_pass[b][c] for c in common)  # silent under a, caught under b
        c_only = sum(cell_pass[b][c] and not cell_pass[a][c] for c in common)
        out["paired_tests"].append({"arms": [a, b], "cells": len(common), "silent_only_first": b_only,
                                    "silent_only_second": c_only, "p_exact": mcnemar_exact(b_only, c_only)})
    groups = defaultdict(set)
    for r in rs_level:
        groups[(r["cell_id"], r["arm"])].add(r["verdict"])
    out["consistency"] = wilson(sum(len(v) == 1 for v in groups.values()), len(groups))
    for cell_id, crs in sorted(by_cell(rs_level).items()):
        per = {}
        for arm in arms:
            ars = [r for r in crs if r["arm"] == arm]
            if ars:
                per[arm] = {"verdicts": dict(Counter(r["verdict"] for r in ars)),
                            "categories": dict(Counter(r.get("all_categories") or r.get("faulted_categories")
                                                       for r in ars))}
        out["cells"][cell_id] = {"kind": crs[0]["kind"], "fault": crs[0]["fault"], "faulted": crs[0]["faulted"],
                                 "finding_in": crs[0]["finding_in"], "per_arm": per}
    return out


def fmt(x):
    return "n/a" if not x else f"{100 * x['rate']:.1f}% ({x['k']}/{x['n']}) [{100 * x['ci95'][0]:.1f}, {100 * x['ci95'][1]:.1f}]"


def summary(m, title):
    lines = [f"# {title}", "", "Rates: % (numerator/denominator) [Wilson 95% interval]. Levels are never pooled.", ""]
    for level, lm in m["levels"].items():
        arms = lm["arms"]
        lines += [f"## Level {level}", "", "| Metric | " + " | ".join(arms) + " |", "|---|" + "---|" * len(arms)]
        for key in ("SPR_cells", "SPR_runs", "CC_cells", "CC_runs", "MAB_runs", "FBR_runs", "TBR_runs", "FPP_runs"):
            lines.append(f"| {key} | " + " | ".join(fmt(lm["per_arm"][a][key]) for a in arms) + " |")
        lines += ["", f"Run-to-run consistency: {fmt(lm['consistency'])}", "",
                  "Silent-pass cells per fault class (modal verdict PASS / cells):", "",
                  "| Fault | " + " | ".join(arms) + " |", "|---|" + "---|" * len(arms)]
        for fault, per in lm["per_fault"].items():
            lines.append(f"| {fault} | " + " | ".join(
                f"{per[a]['k']}/{per[a]['n']}" if per.get(a) else "-" for a in arms) + " |")
        lines += ["", "Paired comparisons (exact McNemar on cell-level silent passes):", ""]
        for t in lm["paired_tests"]:
            lines.append(f"- {t['arms'][0]} vs {t['arms'][1]}: {t['cells']} cells; silent only under "
                         f"{t['arms'][0]}: {t['silent_only_first']}; only under {t['arms'][1]}: "
                         f"{t['silent_only_second']}; p = {t['p_exact']}")
        lines += ["", "Overhead (clean, known-finding and baseline runs; medians):", "",
                  "| Arm | evidence validation s | share of engine run | wall s |", "|---|---|---|---|"]
        for a in arms:
            o = lm["per_arm"][a]["overhead"]
            g = (lambda x: x["median"] if x else "n/a")
            lines.append(f"| {a} | {g(o['evidence_validation_s'])} | {g(o['validation_share_of_run'])} | "
                         f"{g(o['wall_s'])} |")
        lines += ["", "Silent-pass cells: " + "; ".join(
            f"{a}: {', '.join(lm['per_arm'][a]['silent_pass_cells']) or 'none'}" for a in arms), ""]
        if any(c["kind"] == "B" for c in lm["cells"].values()):
            lines += ["Real-project baselines (observed, no ground truth):", "",
                      "| Cell | " + " | ".join(arms) + " |", "|---|" + "---|" * len(arms)]
            for cid, c in lm["cells"].items():
                if c["kind"] == "B":
                    lines.append(f"| {cid} | " + " | ".join(
                        "/".join(sorted(c["per_arm"][a]["verdicts"])) + " `" +
                        "/".join(sorted(c["per_arm"][a]["categories"])) + "`"
                        if a in c["per_arm"] else "-" for a in arms) + " |")
            lines.append("")
    lines += ["## Metric definitions", ""] + [f"- **{k}**: {v}" for k, v in METRIC_DEFINITIONS.items()]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--title", default="EXP-02 results")
    ap.add_argument("inputs", nargs="+")
    args = ap.parse_args()
    rows = load(args.inputs)
    m = {"definitions": METRIC_DEFINITIONS, "runs": len(rows),
         "levels": {lvl: level_metrics(rows, lvl) for lvl in sorted({r["level"] for r in rows})}}
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(m, indent=2))
    (out / "summary.md").write_text(summary(m, args.title))
    with open(out / "runs_all.csv", "w", newline="") as fh:
        fields = sorted({k for r in rows for k in r})
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print((out / "summary.md").read_text())


if __name__ == "__main__":
    main()
