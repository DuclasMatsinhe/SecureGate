# Draft issue for pypa/pip-audit (not yet posted)

> **Before posting:** run the minimal reproduction below on your machine with the current pip-audit
> release and paste the real output in place of the "expected to show" lines. Search the issue
> tracker for "no-deps" and "nested requirements" first; nothing matching was found on 23 Nov 2026,
> but that search was not exhaustive. Post from your own GitHub account.

---

**Title:** `--no-deps` / `--disable-pip`: nested `-r` includes are not audited, and the run reports "No known vulnerabilities found"

### Bug description

When a requirements file only includes other files (`-r other.txt`), `pip-audit -r requirements.txt --no-deps --disable-pip` audits **zero** dependencies, prints "No known vulnerabilities found" and exits 0. The packages pinned in the included files are not audited, and nothing in the output says so. In CI this looks exactly like a clean audit.

Without `--no-deps`, pip resolution does follow the include (in our case it then failed to build an old package, which is a separate and expected problem).

### Observed (pip-audit 2.10.1, Python 3.13, ubuntu-24.04 GitHub-hosted runner)

Project: `miguelgrinberg/flasky` at commit `3beedd640b9146b0bd65c8c2ecf402b01798bc33`.
`requirements.txt` contains only `-r requirements/heroku.txt`; `heroku.txt` contains `-r prod.txt` plus 3 pins; the chain ends in `common.txt` with 30 pins.

| Command (run in the folder of the file) | Dependencies audited | Exit |
|---|---|---|
| `pip-audit -r requirements.txt --format json --no-deps --disable-pip` | 0 (`{"dependencies": [], "fixes": []}`) | 0, "No known vulnerabilities found" |
| `pip-audit -r heroku.txt --format json --no-deps --disable-pip` (in `requirements/`) | 3 (only the pins written in `heroku.txt`) | 1 (4 vulnerabilities) |
| `pip-audit -r requirements.txt --format json` | — (pip failed to build `dominate`) | 1 |

### Minimal reproduction

```bash
mkdir repro && cd repro
printf -- '-r inner.txt\n' > requirements.txt
printf 'urllib3==1.26.5\n' > inner.txt        # a version with published advisories
pip-audit -r requirements.txt --no-deps --disable-pip --format json; echo "exit=$?"
pip-audit -r inner.txt        --no-deps --disable-pip --format json; echo "exit=$?"
```

Expected to show (please replace with your real output): the first command audits 0 dependencies and exits 0; the second finds the urllib3 advisories and exits 1.

### Expected behavior

Either (a) follow `-r` / `--requirement` includes in `--no-deps` mode, as pip does, or (b) if includes are deliberately not followed, emit a warning (and ideally a non-zero exit under `--strict`) that the included files were not audited, and list them as skipped in the JSON output.

### Why it matters

A CI security gate that trusts the exit code, or even reads the JSON report, sees a successful audit with no vulnerabilities. We found this while evaluating CI security gates on public projects (SecureGate, https://github.com/DuclasMatsinhe/SecureGate; data: https://doi.org/10.5281/zenodo.24454737). Our gate only noticed because it treats "0 dependencies audited" as missing coverage.

### Platform information

- pip-audit 2.10.1 (installed with `pip install pip-audit==2.10.1`)
- Python 3.13, Ubuntu 24.04 (GitHub-hosted runner)
