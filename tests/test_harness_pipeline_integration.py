"""Integration test for the full harness pipeline: extraction -> pattern
detection -> generation -> compile -> run, against real ground truth
(RTCON's getCrashAddress, kaist-hacking/RTCON PR #2 -- already merged,
independently hand-verified with ASan earlier in this project's history).
Needs gcc; not offline, but this is the one test that actually proves
the tool works end to end, so it belongs in the suite regardless."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from augur.harness.pipeline import HarnessPipeline, Verdict

FIXTURES = Path(__file__).parent / "fixtures"
GCC_MISSING = shutil.which("gcc") is None


@pytest.mark.skipif(GCC_MISSING, reason="gcc not available")
def test_confirms_real_rtcon_regression_fix():
    old_source = (FIXTURES / "rtcon_crash_old.c").read_text()
    new_source = (FIXTURES / "rtcon_crash_new.c").read_text()
    seed = "#0 0x556ab456789a in vulnerable_func crash.c:100:5\n"

    with tempfile.TemporaryDirectory() as tmp:
        result = HarnessPipeline().analyze(
            old_source=old_source,
            new_source=new_source,
            function_name="getCrashAddress",
            seed=seed,
            other_param_defaults={"index": "0"},
            workdir=Path(tmp),
        )

    assert result.verdict == Verdict.CONFIRMED_REGRESSION_FIX
    old_crashes = [r for r in result.old_results if r.crashed]
    new_crashes = [r for r in result.new_results if r.crashed]
    assert old_crashes, "expected the old implementation to crash at some truncation length"
    assert not new_crashes, "the fixed implementation must never crash across the same sweep"
    # The real bug requires at least "#0 " (3 bytes) + fewer than 20 bytes
    # remaining -- so the shortest crashing length must be well under 23.
    assert old_crashes[0].length < 23


@pytest.mark.skipif(GCC_MISSING, reason="gcc not available")
def test_no_difference_found_when_seed_never_reaches_the_sink():
    """If the seed doesn't contain the '#<index> ' prefix the function
    searches for, strstr() returns NULL and the vulnerable memcpy is
    never reached at any truncation length -- must report
    NO_DIFFERENCE_FOUND, not a false CONFIRMED verdict."""
    old_source = (FIXTURES / "rtcon_crash_old.c").read_text()
    new_source = (FIXTURES / "rtcon_crash_new.c").read_text()
    seed = "no matching prefix here at all"

    with tempfile.TemporaryDirectory() as tmp:
        result = HarnessPipeline().analyze(
            old_source=old_source,
            new_source=new_source,
            function_name="getCrashAddress",
            seed=seed,
            other_param_defaults={"index": "0"},
            workdir=Path(tmp),
        )

    assert result.verdict == Verdict.NO_DIFFERENCE_FOUND


def test_needs_manual_review_for_unsupported_signature():
    source = "void f(struct Thing *t) {\n  int x = 1;\n}\n"
    with tempfile.TemporaryDirectory() as tmp:
        result = HarnessPipeline().analyze(
            old_source=source, new_source=source, function_name="f",
            seed="x", other_param_defaults={}, workdir=Path(tmp),
        )
    assert result.verdict == Verdict.NEEDS_MANUAL_REVIEW


def test_not_found_for_missing_function():
    with tempfile.TemporaryDirectory() as tmp:
        result = HarnessPipeline().analyze(
            old_source="int x;", new_source="int x;", function_name="doesNotExist",
            seed="x", other_param_defaults={}, workdir=Path(tmp),
        )
    assert result.verdict == Verdict.NOT_FOUND
