"""Compare your runs.csv files with the published runs: same verdict and categories per cell, arm and repetition?"""
import csv, sys
def load(paths):
    out = {}
    for p in paths:
        for r in csv.DictReader(open(p, newline="")):
            out[(r["level"], r["cell_id"], r.get("arm") or r["strategy"], r["rep"])] = (r["verdict"], r["all_categories"])
    return out
published = load([sys.argv[1]])
mine = load(sys.argv[2:])
diff = [k for k in mine if k in published and mine[k] != published[k]]
print(f"{len(mine)} of your runs compared; {len(diff)} differ")
for k in diff[:20]:
    print(k, "published:", published[k], "yours:", mine[k])
