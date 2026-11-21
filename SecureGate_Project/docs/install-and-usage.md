# Install and use SecureGate

## Requirements

- Python 3.13 (3.11+ works for the engine; CI and the experiments use 3.13).
- Linux or macOS for real scans (CI uses GitHub-hosted `ubuntu-24.04`).
- The scanners at the pinned versions:

| Tool | Version | Install |
|---|---|---|
| Semgrep | 1.180.0 | `pip install semgrep==1.180.0` (own virtual environment recommended) |
| pip-audit | 2.10.1 | `pip install pip-audit==2.10.1` |
| Gitleaks | 8.30.1 | Release binary `gitleaks_8.30.1_linux_x64.tar.gz`, SHA-256 `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |

## Install

```bash
git clone https://github.com/DuclasMatsinhe/SecureGate.git
cd SecureGate
git checkout semester8-completion
python -m pip install -r requirements-dev.txt          # app + tests (Flask, pytest, jsonschema)

python -m venv .scanners                               # scanners kept apart from the app
.scanners/bin/pip install semgrep==1.180.0 pip-audit==2.10.1
export PATH="$PWD/.scanners/bin:$PATH"

curl -sSfLO https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
echo "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb  gitleaks_8.30.1_linux_x64.tar.gz" | sha256sum -c -
tar -xzf gitleaks_8.30.1_linux_x64.tar.gz gitleaks && mv gitleaks .scanners/bin/
```

## Run

```bash
python -m security_engine.cli                        # scan ".", policy securegate.toml, output securegate-out/
python -m security_engine.cli --target path/to/project --out my-run
python -m security_engine.cli --policy other.toml
python -m security_engine.cli --strategy S0          # experiments only: override the policy's strategy
python -m security_engine.cli --legacy               # the unchanged Semester 7 engine
echo $?                                              # 0 PASS, 1 BLOCK, 2 INCOMPLETE, 3 policy/usage error
```

The command prints a JSON summary (verdict, reasons, per-scanner evidence status) and writes `run_manifest.json`, `report.md` and `raw/<run_id>/` in the output folder.

Gitleaks scans git history, so run it on a git repository with full history (`fetch-depth: 0` in CI). A folder that is not a repository gives NO_COVERAGE, not a silent pass.

## Read the result

- `report.md`: verdict, reasons, findings, per-scanner evidence table.
- `run_manifest.json`: everything needed to reproduce and audit the decision. Validate it with:

```bash
python - <<'EOF'
import json, jsonschema
jsonschema.validate(json.load(open("securegate-out/run_manifest.json")),
                    json.load(open("security_engine/schemas/run_manifest.schema.json")))
print("manifest valid")
EOF
```

## Tests

```bash
python -m pytest -q                                      # 164 tests
python tools/traceability_report.py SecureGate_Project/docs   # runs the tests, regenerates matrix + test report
```

## Library use (same decision as the CLI, FR-35)

```python
from security_engine.gate import SecureGate
from security_engine.policy import load_policy

result = SecureGate(load_policy("securegate.toml")).run(target=".", out_dir="securegate-out")
print(result.verdict.verdict, result.verdict.exit_code)
```
