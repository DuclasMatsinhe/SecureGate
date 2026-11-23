# EXP-03: pre-registered held-out confirmation

EXP-03 repeats the EXP-02 real-project level (R) on eight public projects that were never run
before, with the predictions written down first. See `PREREGISTRATION.md` for the question, the
selection rule, the design and the predictions P1–P6.

| File | What it is |
|---|---|
| `PREREGISTRATION.md` | Question, selection rule, design, predictions, reporting rules |
| `selection/candidates.txt` | The GitHub search snapshot the projects were selected from |
| `selection/selection_log.txt` | The decision for every candidate examined |
| `heldout.py` | Runs the EXP-02 harness on the held-out projects (level `H`); writes the protocol |
| `protocol.json`, `FROZEN.sha256` | The frozen protocol and its SHA-256 |
| `check_predictions.py` | Decides P1–P6 from the run results (CONFIRMED / REFUTED) |
| `run_config.json` | `smoke` or `final`, read by `.github/workflows/experiments-exp03.yml` |

## Sequence

1. **Freeze.** `protocol.json` and `FROZEN.sha256` are committed. The protocol embeds the SHA-256
   of `PREREGISTRATION.md`, of the selection files and of the EXP-02 harness, so changing any of
   them invalidates the freeze and the final run is refused.
2. **Archive.** The pre-registration, protocol, freeze file and selection folder are archived on
   Zenodo before the final run (done by the student).
3. **Smoke run.** `run_config.json` = `smoke`; push to `semester8-exp03-run`. Shard 1 runs one
   EXP-02 project (microblog) with 2 repetitions. No held-out project is touched.
4. **Final run.** `run_config.json` = `final`; push to `semester8-exp03-run`. Eight shards, one
   held-out project each, 10 repetitions: 4,000 gate runs. Done once.
5. **Results.** Added to `semester8-exp02-results` under `EXP-03/<mode>-run-<id>/`, with
   `analysis/predictions.md` (P1–P6) and the EXP-02 `analysis.py` summary.

## Testing the checker

`check_predictions.py` was tested before the run on the EXP-02 final level-R data:

    python check_predictions.py <EXP-02/final-run-44892918564> --out /tmp/chk --level R

All six predictions hold there (45 fault cells, 250 cell-arm pairs). P3's rule was derived from
those data, so this is a test of the checker, not evidence for P3.
