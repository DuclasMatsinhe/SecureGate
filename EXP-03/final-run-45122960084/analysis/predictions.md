# EXP-03 predictions (level H)

4000 runs; 72 fault cells; 8 unmodified projects.

| Prediction | Claim | Observed | Result |
|---|---|---|---|
| P1 | no fault cell passes under S3 or S3P | S3 0/72; S3P 0/72 | CONFIRMED |
| P2 | no fault cell passes under S1 or S2 | S1 0/72; S2 0/72 | CONFIRMED |
| P3 | S0 outcome of every fault cell follows from the unmodified exit codes | 72/72 cells as predicted; 9 predicted silent passes | CONFIRMED |
| P4 | S3 names an expected cause in >= 95% of fault cells | 72/72 (100.0%) | CONFIRMED |
| P5 | >= 99% of cell-arm pairs fully consistent | 400/400 (100.0%) | CONFIRMED |
| P6 | median validation time below 50 ms (S3) and 1000 ms (S3P) per gate run | S3 0.47 ms; S3P 12.18 ms | CONFIRMED |

Exploratory: S0 silent passes 9/72.

| Unmodified project | S0 | S1 | S2 | S3 | S3P |
|---|---|---|---|---|---|
| H-cookiecutter-flask-base | PASS | PASS | PASS | PASS | INCOMPLETE |
| H-flask-ask-base | BLOCK | BLOCK | BLOCK | BLOCK | BLOCK |
| H-flask-jwt-extended-base | BLOCK | BLOCK | BLOCK | BLOCK | BLOCK |
| H-flask-oauthlib-base | BLOCK | BLOCK | BLOCK | BLOCK | BLOCK |
| H-git-webhook-base | BLOCK | BLOCK | BLOCK | BLOCK | INCOMPLETE |
| H-nyaa-base | BLOCK | BLOCK | BLOCK | BLOCK | BLOCK |
| H-rq-dashboard-base | BLOCK | BLOCK | BLOCK | BLOCK | INCOMPLETE |
| H-traefik-manager-base | BLOCK | BLOCK | BLOCK | BLOCK | BLOCK |
