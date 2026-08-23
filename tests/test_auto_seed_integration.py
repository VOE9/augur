"""Integration test for HarnessPipeline.analyze_auto: confirms the real
RTCON regression fix with ZERO human-supplied seed content -- the
mechanically-derived prefix ('#0 ', read out of the function's own
snprintf/strstr logic) plus an automatic length sweep is enough on its
own. This is the concrete capability this pipeline addition set out to
prove: closing the "you must supply a realistic example" gap documented
as a limitation in the original harness design."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from augur.harness.pipeline import HarnessPipeline, Verdict

FIXTURES = Path(__file__).parent / "fixtures"
GCC_MISSING = shutil.which("gcc") is None


@pytest.mark.skipif(GCC_MISSING, reason="gcc not available")
def test_confirms_real_rtcon_fix_with_zero_human_supplied_seed():
    old_source = (FIXTURES / "rtcon_crash_old.c").read_text()
    new_source = (FIXTURES / "rtcon_crash_new.c").read_text()

    with tempfile.TemporaryDirectory() as tmp:
        result = HarnessPipeline().analyze_auto(
            old_source=old_source,
            new_source=new_source,
            function_name="getCrashAddress",
            other_param_defaults={"index": "0"},
            workdir=Path(tmp),
        )

    assert result.verdict == Verdict.CONFIRMED_REGRESSION_FIX
    assert "'#0 '" in result.detail  # confirms the prefix was derived, not supplied
    old_crashes = [r for r in result.old_results if r.crashed]
    new_crashes = [r for r in result.new_results if r.crashed]
    assert old_crashes and not new_crashes


def test_seed_derivation_failed_when_function_lacks_the_shape():
    source = "void f(const char *x, int n) {\n  char buf[10];\n  memcpy(buf, x, n);\n}\n"
    with tempfile.TemporaryDirectory() as tmp:
        result = HarnessPipeline().analyze_auto(
            old_source=source, new_source=source, function_name="f",
            other_param_defaults={"n": "5"}, workdir=Path(tmp),
        )
    assert result.verdict == Verdict.SEED_DERIVATION_FAILED
