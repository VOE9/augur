"""Require a passing JUnit report and actual execution of named critical tests."""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def evaluate_report(report: Path, required_cases: list[str]) -> dict:
    root = ET.parse(report).getroot()
    cases = list(root.iter("testcase"))
    issues = []
    if not cases:
        issues.append("report contains no test cases")
    for case in cases:
        identity = f"{case.get('classname', '')}::{case.get('name', '')}"
        if case.find("failure") is not None or case.find("error") is not None:
            issues.append(f"test failed: {identity}")
    # A setup/collection error can be attached to a suite, without a testcase.
    if any(True for _ in root.iter("error")) and not any("test failed:" in item for item in issues):
        issues.append("report contains a suite/collection error")
    for suite in root.iter("testsuite"):
        if any(int(suite.get(name, "0")) > 0 for name in ("failures", "errors")) and not issues:
            issues.append("suite reports failures/errors")
    if not any(case.find("skipped") is None for case in cases):
        issues.append("no test actually executed")
    for required in required_cases:
        matches = [case for case in cases
                   if f"{case.get('classname', '')}::{case.get('name', '')}" == required]
        if len(matches) != 1:
            issues.append(f"required test must occur exactly once: {required}; found {len(matches)}")
        elif matches[0].find("skipped") is not None:
            issues.append(f"required test skipped: {required}")
    return {"passed": not issues, "test_cases": len(cases),
            "skipped": sum(case.find("skipped") is not None for case in cases),
            "required_cases": required_cases, "issues": issues}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--require-case", action="append", required=True)
    args = parser.parse_args()
    try:
        result = evaluate_report(args.report, args.require_case)
    except (OSError, ValueError, ET.ParseError) as error:
        result = {"passed": False, "issues": [f"invalid or unavailable report: {error}"]}
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
