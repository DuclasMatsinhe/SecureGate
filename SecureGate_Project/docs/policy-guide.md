# Policy guide (`securegate.toml`)

The policy is a TOML file (DEC-002). It is validated strictly: an unknown key, a wrong type or an invalid value stops the run with exit code 3 and a message naming the field. Its canonical SHA-256 is written to every manifest, so a result can always be matched to the exact policy that produced it.

## Top-level keys

| Key | Values | Default | Meaning |
|---|---|---|---|
| `version` | string | `"1.0"` | Your policy's own version label (recorded in the manifest) |
| `strategy` | `S0` `S1` `S2` `S3` | `S3` | How evidence is checked and what invalid evidence becomes (below) |
| `on_incomplete` | `block` `warn` `review` | `block` | What INCOMPLETE does to the job: exit 2; exit 0 with a warning; exit 2 with a MANUAL_REVIEW note. A run that also has a confirmed blocking finding always exits 2, whatever this setting (FR-20a) |
| `required_scanners` | list of `semgrep`, `pip-audit`, `gitleaks` | all three | A failure of a scanner not in the list is a note, not a reason |
| `unknown_severity` | `LOW` `MEDIUM` `HIGH` `CRITICAL` | `HIGH` | Severity given to findings with an unrecognised severity (never ignored; a SEVERITY_MAPPED note is added) |
| `[thresholds]` | `default = "HIGH"`, optional per scanner (`semgrep = "MEDIUM"`) | `HIGH` | Findings at or above the threshold block |

## Strategies (DEC-006)

| Strategy | Checks | Invalid evidence | Use |
|---|---|---|---|
| S0 | execution, exit code | BLOCK | Baseline for experiments (what most pipelines do) |
| S1 | + presence, JSON, schema | BLOCK | Experiments |
| S2 | + exit/report consistency, coverage | BLOCK | Experiments; strict fail-closed |
| **S3** | same as S2 | **INCOMPLETE** | **Recommended for real use** |

## Scanner sections

```toml
[scanners.semgrep]
timeout = 600                       # seconds; the process group is killed when it is exceeded
config = "p/python"                 # or a list: ["p/python", "p/github-actions"], or a local rules file
# executable = "/opt/semgrep/bin/semgrep"   # optional; otherwise found on PATH
# extra_args = []                           # optional extra arguments (list of strings)
# parse_check = false   # FR-14a: S2/S3 also parse every .py file Semgrep lists as scanned;
#                       # unparsable files give PARTIAL_COVERAGE (Semgrep does not report them)

[scanners.pip-audit]
timeout = 300
requirements = "requirements.txt"   # its SHA-256 is recorded as a rule source

[scanners.gitleaks]
timeout = 300
leak_exit_code = 3                  # keeps "leaks found" apart from Gitleaks' error exit code 1
# config = "gitleaks.toml"          # optional custom rules; hashed in the manifest
```

`enabled = false` turns a scanner off (it must then not be in `required_scanners`). Semgrep `config = "auto"` is rejected: its rules change between runs (DEC-004).

## Suppressions (accepted risks)

```toml
[[suppressions]]
rule_id = "python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host"
path = "run.py"                     # optional; tool = "semgrep" is also optional
reason = "Dev server only; production uses a WSGI server"
expires = 2027-01-31                # required; after this date the finding blocks again
```

A suppression needs a reason and an expiry date. Suppressed findings stay in the manifest, marked `suppressed`. An expired suppression stops working and adds a SUPPRESSION_EXPIRED note.

## Changing the policy

1. Edit `securegate.toml` and commit it in its own reviewed commit.
2. `python -m pytest -q tests/test_gate.py -k policy` checks that the repository policy still loads (the CI Tests job does this too, so an invalid policy never reaches the gate step).
3. The new `policy.sha256` appears in the next manifest.

`.gitleaksignore` (repository root) is read by Gitleaks itself. It is recorded in the manifest as a rule source (hash and entry count). Every entry needs a written reason in the file (DEC-011).
