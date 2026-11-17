"""SecureGate command line.

Exit codes: 0 PASS, 1 BLOCK, 2 INCOMPLETE, 3 invalid policy or usage.
`--legacy` runs the unchanged Semester 7 engine (exit 0 pass / 1 fail).
"""

import argparse
import json
import os
import sys
from pathlib import Path

from .engine import SecurityValidationEngine
from .gate import SecureGate
from .policy import STRATEGIES, PolicyError, load_policy
from .verdict import EXIT_CONFIG_ERROR

DEFAULT_POLICY_FILE = "securegate.toml"


def legacy_main():
    """The Semester 7 engine, unchanged (reference baseline)."""
    engine = SecurityValidationEngine()

    findings = engine.run_all_scanners()
    summary = engine.summary()

    print(json.dumps(summary, indent=2))

    if findings:
        print("\nFindings:")
        for finding in findings:
            print(json.dumps(finding.to_dict(), indent=2))

    # Fail closed: blocking findings OR scanner errors must block the gate.
    if not summary["security_gate_passed"]:
        print("\nSECURITY GATE: FAILED")

        if summary["blocking_findings"]:
            print("Blocking security findings were detected.")

        if summary["scanner_errors"]:
            print("One or more security scanners failed.")

        return 1

    print("\nSECURITY GATE: PASSED")
    print("All scanners succeeded and no blocking findings were detected.")
    return 0


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"securegate: error: {message}", file=sys.stderr)
        sys.exit(EXIT_CONFIG_ERROR)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="securegate", description="Evidence-aware CI/CD security gate.")
    parser.add_argument("--target", default=".", help="folder to scan (default: current folder)")
    parser.add_argument("--policy", help=f"policy file (default: {DEFAULT_POLICY_FILE} if present, "
                                         "otherwise built-in defaults)")
    parser.add_argument("--out", default="securegate-out", help="output folder for the manifest and report")
    parser.add_argument("--strategy", choices=STRATEGIES, help="override the policy's handling strategy "
                                                               "(for experiments)")
    parser.add_argument("--no-summary", action="store_true",
                        help="do not append the report to the GitHub Actions job summary")
    parser.add_argument("--legacy", action="store_true", help="run the Semester 7 engine instead")
    return parser


def main(argv=None, runner=None) -> int:
    args = build_parser().parse_args(argv)
    if args.legacy:
        return legacy_main()

    policy_path = args.policy
    if policy_path is None and Path(DEFAULT_POLICY_FILE).is_file():
        policy_path = DEFAULT_POLICY_FILE
    try:
        policy = load_policy(policy_path)
        if args.strategy:
            policy = policy.with_strategy(args.strategy)
    except PolicyError as exc:
        print(f"securegate: invalid policy: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    result = SecureGate(policy, runner=runner).run(target=args.target, out_dir=args.out)

    summary = {
        "verdict": result.verdict.verdict,
        "exit_code": result.verdict.exit_code,
        "security_gate_passed": result.verdict.verdict == "PASS",
        "strategy": policy.strategy,
        "reasons": [r.to_dict() for r in result.verdict.reasons],
        "scanners": [{"scanner": e.scanner, "evidence": e.status, "category": e.category,
                      "findings": len(e.findings)} for e in result.evidences],
        "manifest": str(result.manifest_path),
        "report": str(result.report_path),
    }
    print(json.dumps(summary, indent=2))

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary and not args.no_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(result.report_markdown)

    return result.verdict.exit_code


if __name__ == "__main__":
    sys.exit(main())
