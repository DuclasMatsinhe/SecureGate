"""The reusable Action and the workflows are hardened: pinned actions, no expressions inside scripts.

`${{ }}` inside a `run:` script is expanded before the shell sees it, so a value such as a branch name
could inject commands; values go through `env:` instead (Semgrep's p/github-actions rules flag this,
DEC-009 / D2). Third-party actions are pinned to full commit SHAs.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [ROOT / "action.yml", *sorted((ROOT / ".github" / "workflows").glob("*.yml"))]
SHA_PINNED = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")
SELF_REFERENCES = {"./", "DuclasMatsinhe/SecureGate@semester8-final"}


def run_blocks(text):
    """Yield (line number, line) for every line inside a `run:` script."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(- )?run:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group(1)) + (2 if m.group(2) else 0)
        rest = m.group(3)
        if not rest:  # a job named "run", not a step script
            i += 1
            continue
        if rest not in ("|", ">", "|-", ">-"):
            yield i + 1, rest
            i += 1
            continue
        i += 1
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
            yield i + 1, lines[i]
            i += 1


def test_action_metadata_is_complete():
    text = (ROOT / "action.yml").read_text()
    for key in ("name:", "description:", "branding:", "inputs:", "outputs:", 'using: "composite"'):
        assert key in text
    for output in ("verdict:", "exit-code:", "manifest:", "report:"):
        assert output in text


def test_actions_are_pinned_to_commit_shas():
    for f in FILES:
        for ref in re.findall(r"^\s*(?:- )?uses:\s*(\S+)", f.read_text(), re.M):
            assert ref in SELF_REFERENCES or SHA_PINNED.match(ref), f"{f.name}: {ref} is not pinned to a commit SHA"


def test_no_expressions_inside_run_scripts():
    bad = [f"{f.name}:{n}: {line.strip()}" for f in FILES for n, line in run_blocks(f.read_text()) if "${{" in line]
    assert not bad, "move these values into env:\n" + "\n".join(bad)
