# Experiments

All experiments must be reproducible and documented.

## Experiment structure

Each experiment should contain:

- `README.md` — objective, hypothesis, environment and procedure
- `config/` — configuration used
- `data/` — experiment inputs or references
- `results/` — experiment-specific results

## Required experiment information

1. Experiment ID
2. Research question
3. Objective
4. Hypothesis
5. Environment
6. Inputs
7. Procedure
8. Expected result
9. Actual result
10. Raw measurements
11. Analysis
12. Conclusion

## Rules

- Never use real credentials or secrets in security tests.
- Preserve raw results.
- Record software/tool versions.
- Record configuration changes.
- Do not modify raw data to improve results.
- Make experiments reproducible whenever possible.

## Experiment index

| ID | Title | Status |
|---|---|---|
| [EXP-00](EXP-00-live-scanner-check/README.md) | Live scanner check (pilot for the fault catalogue) | Done, 17 Nov 2026 |
| [EXP-01](EXP-01-pilot/README.md) | Fault-injection pilot: S0–S3 × F1–F10, L1 simulated and L2 real binaries | Pilot run 17 Nov 2026; protocol not frozen |
