"""Create one of the synthetic EXP-02 test projects (and its policy) for testing the SecureGate Action.

  python tools/make_fixture.py t-clean fixture            # writes fixture/t-clean and fixture/policy.toml
  python tools/make_fixture.py t-clean fixture --missing semgrep   # policy points Semgrep at a missing executable

The projects come from the EXP-02 harness (TARGETS); synthetic tokens are generated at random and are
never real credentials. The policy uses the committed EXP-02 Semgrep rules and pip-audit's
--no-deps --disable-pip, as in the experiments.
"""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("exp02_harness", ROOT / "SecureGate_Project/experiments/EXP-02/harness.py")
h = importlib.util.module_from_spec(spec)
sys.modules["exp02_harness"] = h
spec.loader.exec_module(h)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name", choices=sorted(h.TARGETS))
    ap.add_argument("dest")
    ap.add_argument("--missing", choices=h.SCANNERS, help="point this scanner at an executable that does not exist")
    ap.add_argument("--strategy", default="S3")
    a = ap.parse_args()
    dest = Path(a.dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    project = h.make_synthetic(dest, a.name)
    rules = dest / "rules.yml"
    rules.write_text(h.RULES)
    semgrep = {"config": str(rules)}
    if a.missing == "semgrep":
        semgrep["executable"] = str(dest / "not-installed" / "semgrep")
    lines = ['version = "action-selftest"', f'strategy = "{a.strategy}"', 'on_incomplete = "block"', "",
             "[scanners.semgrep]"] + [f"{k} = {json.dumps(v)}" for k, v in semgrep.items()]
    lines += ["", "[scanners.pip-audit]", f"extra_args = {json.dumps(h.PIP_AUDIT_ARGS)}"]
    if a.missing == "pip-audit":
        lines.append(f'executable = {json.dumps(str(dest / "not-installed" / "pip-audit"))}')
    lines += ["", "[scanners.gitleaks]", f"leak_exit_code = {h.LEAK_CODE}"]
    if a.missing == "gitleaks":
        lines.append(f'executable = {json.dumps(str(dest / "not-installed" / "gitleaks"))}')
    (dest / "policy.toml").write_text("\n".join(lines) + "\n")
    print(project)


if __name__ == "__main__":
    main()
