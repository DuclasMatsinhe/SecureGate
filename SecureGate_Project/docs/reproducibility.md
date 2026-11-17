# Reproducibility guide

This guide says how to reproduce (a) a single SecureGate decision, (b) the CI validation runs and (c) the EXP-01 pilot. Results produced so far are **pilot results**; the protocol is not frozen until the guide approves it (target 6 Dec 2026).

## 1. What is frozen and where it is recorded

| Item | Value | Recorded in |
|---|---|---|
| Engine | `security_engine` 2.0.0.dev1, git commit of the run | manifest `engine`, `target.commit`; experiment `environment.json` |
| Python | 3.13 (CI: 3.13.x from `actions/setup-python` v7.1.0) | `environment.json` |
| Runner | GitHub-hosted `ubuntu-24.04` | `environment.json` (`image`, `image_version`) |
| Semgrep | 1.180.0 (pip, own venv) | manifest `scanners[].version` |
| pip-audit | 2.10.1 (pip, own venv) | manifest |
| Gitleaks | 8.30.1, tarball SHA-256 `551f6fc8…f2470eb` (checked before use) | manifest; workflow env |
| Actions | checkout `3d3c42e5…` (v7.0.1), setup-python `6d4fd22b…` (v7.1.0), upload-artifact `cf430e03…` (v7.0.2) | workflow files |
| Policy | TOML file; canonical SHA-256 | manifest `policy.sha256`; per-run `policy.toml` in experiments |
| Rules | Semgrep local rule file (experiments) or pinned pack name (CI); requirements file hash; `.gitleaksignore` hash | manifest `scanners[].rule_sources` |
| Commands | full argument lists | manifest `scanners[].execution.command` |

Not frozen by the engine: the pip-audit vulnerability database (online service, changes over time) and Semgrep registry packs (not versioned by Semgrep). Experiments therefore use committed local Semgrep rules; pip-audit results are tied to their run date.

## 2. Reproduce one decision

```bash
git checkout <commit from the manifest>
# install the pinned tools (install-and-usage.md)
python -m security_engine.cli --policy <policy used> --target <target> --out repro
diff <(jq -S .verdict original/run_manifest.json) <(jq -S .verdict repro/run_manifest.json)
```

Given the same evidence and policy the decision is deterministic (FR-25, `test_same_evidence_same_verdict`). To re-decide from recorded evidence without running scanners, replay the raw outputs with the L1 harness approach (`ReplayRunner` in `experiments/EXP-01-pilot/harness.py`).

## 3. Reproduce the CI validation

Each `semester8-ci-validate-*` branch is `semester8-completion` plus one commit that changes `securegate.toml`. Pushing a commit to such a branch reruns the workflow. Expected job results are in [ci-integration.md](ci-integration.md).

## 4. Reproduce EXP-01

```bash
# L1 (simulated; no scanners needed; deterministic)
python SecureGate_Project/experiments/EXP-01-pilot/harness.py L1 --out results/L1 --reps 2

# L2 (real binaries on PATH at the pinned versions; needs network for pip-audit)
python SecureGate_Project/experiments/EXP-01-pilot/harness.py L2 --out results/L2 --reps 3
```

or push the commit to the `semester8-experiments` branch: `.github/workflows/experiments.yml` installs the pinned tools, runs both levels and the D2 probes, validates every manifest against the schema, checks that no synthetic token is stored, and adds the results as a **new folder** `EXP-01/run-<run id>/` on the `semester8-completion-results` branch (never overwritten, never force-pushed). The harness refuses to write into a non-empty output folder.

Each results folder holds: `protocol.json` (cells and expected categories, written before the run), `runs.csv` (one row per run), `metrics.json`, `summary.md`, `environment.json`, `runs.tar.gz` (every manifest, report, policy and raw scanner output), plus `probes/` and `schema_validation.txt`.

## 5. Simulated versus real

| Label | Meaning | Where |
|---|---|---|
| Unit tests (fake runner) | Synthetic outputs; no scanner runs | `tests/test_gate.py`, `tests/test_completion.py` |
| Replay of real outputs | Outputs recorded from the real tools in EXP-00, replayed | `tests/test_live_outputs.py`, EXP-01 **L1** |
| Real subprocesses | Real processes (Python stand-ins) for timeout, crash, missing tool | `tests/test_gate.py::test_real_*` |
| Real binaries | Pinned Semgrep, pip-audit, Gitleaks | CI, EXP-00, EXP-01 **L2** |

Results from different rows are never pooled.
