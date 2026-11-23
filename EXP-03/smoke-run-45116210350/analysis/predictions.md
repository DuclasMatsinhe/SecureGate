# EXP-03 predictions (level H)

100 runs; 9 fault cells; 1 unmodified projects.

| Prediction | Claim | Observed | Result |
|---|---|---|---|
| P1 | no fault cell passes under S3 or S3P | S3 0/9; S3P 0/9 | CONFIRMED |
| P2 | no fault cell passes under S1 or S2 | S1 0/9; S2 0/9 | CONFIRMED |
| P3 | S0 outcome of every fault cell follows from the unmodified exit codes | 9/9 cells as predicted; 1 predicted silent passes | CONFIRMED |
| P4 | S3 names an expected cause in >= 95% of fault cells | 9/9 (100.0%) | CONFIRMED |
| P5 | >= 99% of cell-arm pairs fully consistent | 50/50 (100.0%) | CONFIRMED |
| P6 | median validation time below 50 ms (S3) and 1000 ms (S3P) per gate run | S3 0.72 ms; S3P 13.38 ms | CONFIRMED |

Exploratory: S0 silent passes 1/9.

| Unmodified project | S0 | S1 | S2 | S3 | S3P |
|---|---|---|---|---|---|
| H-microblog-base | BLOCK | BLOCK | BLOCK | BLOCK | BLOCK |
