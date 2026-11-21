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
| [EXP-01](EXP-01-pilot/README.md) | Fault-injection pilot: S0–S3 × F1–F10, L1 simulated and L2 real binaries | Done and replicated, 17 Nov 2026 |
| [EXP-02](EXP-02/README.md) | Final study: S0–S3 and S3P × F1–F10 at L1, L2 and R (five pinned public projects), 10 repetitions | Final run 21 Nov 2026 (frozen protocol, DEC-018). Verify: [VERIFY.md](EXP-02/VERIFY.md) |
