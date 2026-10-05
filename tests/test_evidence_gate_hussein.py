"""The ASan evidence gate must distinguish skipped, missing and failed tests."""
from pathlib import Path

import pytest

from scripts.check_test_evidence_hussein import evaluate_report


@pytest.mark.parametrize("xml,passed", [
    ('<testsuite><testcase classname="critical" name="real"/> '
     '<testcase classname="optional" name="extra"><skipped message="no clang"/></testcase></testsuite>', True),
    ('<testsuite><testcase classname="critical" name="real"><skipped message="different reason"/>'
     '</testcase><testcase classname="other" name="pass"/></testsuite>', False),
    ('<testsuite><testcase classname="other" name="pass"/></testsuite>', False),
    ('<testsuite><testcase classname="critical" name="real"/>'
     '<testcase classname="other" name="failed"><failure/></testcase></testsuite>', False),
    ('<testsuite errors="1"><error message="collection failed"/></testsuite>', False),
    ('<testsuite><testcase classname="critical" name="real"/>'
     '<testcase classname="critical" name="real"/></testsuite>', False),
])
def test_evidence_gate_rejects_false_green_reports(tmp_path: Path, xml, passed):
    report = tmp_path / "report.xml"
    report.write_text(xml, encoding="utf-8")
    result = evaluate_report(report, ["critical::real"])
    assert result["passed"] is passed
    assert bool(result["issues"]) is (not passed)
