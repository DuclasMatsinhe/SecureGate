# Draft issue for semgrep/semgrep (not yet posted)

> **Before posting:** re-run the reproduction with the current Semgrep release (the behaviour was
> recorded with 1.180.0) and paste your real output. Semgrep's Python parser recovers from some
> errors on purpose, so ask whether this is intended and request a way to see it rather than
> calling it a crash. Search the tracker for "syntax error" + "paths.scanned" first; nothing
> matching was found on 23 Nov 2026, but that search was not exhaustive. Post from your own account.

---

**Title:** Python file with a syntax error is reported as scanned, with no error, even with `--strict` / `--verbose`

### Describe the bug

A Python file that does not parse is listed in `paths.scanned`, `errors` is empty, the exit code is 0 and the summary says the file was scanned. Rules are therefore silently not applied to that file, and nothing in the JSON or the console output shows it. For some other languages Semgrep does report "Syntax error at line …" as a warning, so we expected the same here.

### To reproduce (Semgrep 1.180.0)

```bash
mkdir repro && cd repro && git init -q
printf 'def broken(:\n    return 1\n' > broken.py
printf 'import os\nos.system(input())\n' > ok.py
git add . && git commit -qm repro
semgrep --config p/python --json --metrics=off . > out.json; echo "exit=$?"
python3 -c "import json; d=json.load(open('out.json')); print(d['paths']['scanned'], d['errors'])"
semgrep --config p/python --json --metrics=off --strict --verbose . > out2.json; echo "exit=$?"
```

What we recorded (EXP-00 case SG04/SG05, and again with `--strict` and `--verbose` in EXP-01): exit 0; `broken.py` in `paths.scanned`; `errors: []`; any finding in the other file is still reported. Please replace with your real output.

`python3 -c "import ast; ast.parse(open('broken.py').read())"` raises `SyntaxError`, so the file is not valid Python 3.

### Expected behavior

The file is reported, for example as an entry in `errors` (level warn, type "Syntax error") or in `paths.skipped`, so that users can tell that rules were not applied to it. If error recovery means part of the file was analysed, a "partially analysed" note as for other languages would also work.

### Why it matters

CI security gates use Semgrep's JSON report to decide whether a scan is complete. In our evaluation (SecureGate, https://github.com/DuclasMatsinhe/SecureGate; data https://doi.org/10.5281/zenodo.24454737) this was the only scanner fault that no report-based check could detect: a file with a syntax error is silently unanalysed. We now work around it by parsing the listed files ourselves, which is slower and depends on the Python version.

### Environment

- Semgrep 1.180.0 (`pip install semgrep==1.180.0`), Python 3.13, Ubuntu 24.04 (GitHub-hosted runner) and local Linux
- Config: recorded with a local rules file (the SecureGate experiment rules); please confirm with `p/python` as in the reproduction
