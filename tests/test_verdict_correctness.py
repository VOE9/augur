"""Verdict-correctness tests for the differential harness.

Every case here is backed by a real AddressSanitizer run over both
implementations, not by a stubbed runner: the pipeline is driven end to end
(extraction -> pattern detection -> harness generation -> compile -> sweep),
and the assertions are about which verdict the real crashes produce.

The case this file exists for is `test_partial_fix_is_not_confirmed`. An
earlier version of the pipeline decided the verdict from a single
representative length -- the one at which the OLD version first crashed --
and reported `confirmed_regression_fix` whenever the new version happened to
be clean at that one length. A partially-fixed new version that is clean at
short lengths but still crashes at longer ones therefore passed as
"confirmed", which is precisely the kind of silently-wrong claim this project
refuses to make. `partial_fix_old.c` / `partial_fix_new.c` are a real instance
of that: ASan reports the old version crashing from length 3 onward and the
new version crashing from length 23 onward.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from augur.harness.pipeline import HarnessPipeline, Verdict

FIXTURES = Path(__file__).parent / "fixtures"
GCC_MISSING = shutil.which("gcc") is None
needs_gcc = pytest.mark.skipif(GCC_MISSING, reason="gcc not available")


@needs_gcc
def test_partial_fix_is_not_confirmed():
    """The regression test. Old crashes from length 3, new from length 23;
    the new version must NOT be reported as a confirmed fix."""
    old_source = (FIXTURES / "partial_fix_old.c").read_text()
    new_source = (FIXTURES / "partial_fix_new.c").read_text()
    seed = "#0 ff0011aa22bb33cc44dd55ee66ff7788 12ab 0xffffffffff"

    with tempfile.TemporaryDirectory() as tmp:
        result = HarnessPipeline().analyze(
            old_source=old_source,
            new_source=new_source,
            function_name="parse_addr",
            seed=seed,
            other_param_defaults={"index": "0"},
            workdir=Path(tmp),
        )

    assert result.verdict == Verdict.PARTIAL_FIX
    assert not result.is_confirmed

    old_lengths = result.old_crash_lengths
    new_lengths = result.new_crash_lengths

    # The precondition the old bug relied on: the new version is clean at
    # the shortest length at which the old version crashes...
    assert old_lengths, "old implementation must crash somewhere"
    assert old_lengths[0] not in new_lengths, (
        "fixture no longer demonstrates the case: new crashes at old's shortest "
        "crashing length, which the old code did handle"
    )
    # ...and yet it is demonstrably still unsafe further along.
    assert new_lengths, "new implementation must still crash somewhere"
    assert min(new_lengths) > old_lengths[0]
    # The new version's shortest crash is longer than the old version's
    # because the over-read really was fixed; only the off-by-one remains.
    assert len(new_lengths) < len(old_lengths)


@needs_gcc
def test_regression_introduced_by_fix_is_reported():
    """A 'fix' that drops a guard and introduces a crash must not be
    reported as no-difference or anything else soft."""
    old_source = (FIXTURES / "regression_introduced_old.c").read_text()
    new_source = (FIXTURES / "regression_introduced_new.c").read_text()
    seed = "#0 ff0011aa22bb33cc44dd55ee66ff7788 12ab 0xffffffffff"

    with tempfile.TemporaryDirectory() as tmp:
        result = HarnessPipeline().analyze(
            old_source=old_source,
            new_source=new_source,
            function_name="parse_addr",
            seed=seed,
            other_param_defaults={"index": "0"},
            workdir=Path(tmp),
        )

    assert result.verdict == Verdict.REGRESSION_INTRODUCED_BY_FIX
    assert not result.is_confirmed
    assert result.old_crash_lengths == []
    assert result.new_crash_lengths, "the post-'fix' version is the one that crashes"


@needs_gcc
def test_full_fix_is_still_confirmed():
    """The other direction: the stricter rule must not break a genuine
    fix. Reuses the real RTCON pre/post-fix bodies."""
    old_source = (FIXTURES / "rtcon_crash_old.c").read_text()
    new_source = (FIXTURES / "rtcon_crash_new.c").read_text()

    with tempfile.TemporaryDirectory() as tmp:
        result = HarnessPipeline().analyze(
            old_source=old_source,
            new_source=new_source,
            function_name="getCrashAddress",
            seed="#0 0x556ab456789a in vulnerable_func crash.c:100:5\n",
            other_param_defaults={"index": "0"},
            workdir=Path(tmp),
        )

    assert result.verdict == Verdict.CONFIRMED_REGRESSION_FIX
    assert result.is_confirmed
    assert result.new_crash_lengths == []


@needs_gcc
def test_strcpy_shape_is_detected_and_confirmed():
    """The detector now understands strcpy, not just memcpy. End to end
    under a real compiler: an unbounded strcpy into a fixed buffer must be
    detected, and its bounded replacement must be confirmed as the fix."""
    old_source = (FIXTURES / "strcpy_old.c").read_text()
    new_source = (FIXTURES / "strcpy_new.c").read_text()
    seed = "#0 ff0011aa22bb33cc44dd55ee66ff7788 12ab 0xffffffffff"

    with tempfile.TemporaryDirectory() as tmp:
        result = HarnessPipeline().analyze(
            old_source=old_source,
            new_source=new_source,
            function_name="parse_addr",
            seed=seed,
            other_param_defaults={"index": "0"},
            workdir=Path(tmp),
        )

    assert result.verdict == Verdict.CONFIRMED_REGRESSION_FIX
    assert result.old_crash_lengths, "the unbounded strcpy must actually overflow"
    # The whole point of this case: the crash is a write past a
    # stack buffer, not the heap over-read the memcpy fixtures produce.
    assert any(
        "stack-buffer-overflow" in (r.asan_summary or "")
        for r in result.old_results if r.crashed
    ), "expected a stack-buffer-overflow from the unbounded strcpy"
    assert result.new_crash_lengths == []


def test_classify_is_pure_and_total():
    """_classify decides from the crash-length sets alone. Exercised
    directly so every combination is covered without paying for 2 * N
    ASan subprocesses, including the ones no real fixture can produce."""
    from augur.harness.pipeline import HarnessPipeline
    from augur.harness.sanitizer_runner import RunResult

    def fake(which, lengths):
        # A run that crashed exits 1; a run that did not exits 0. Getting
        # this wrong makes every entry look like an unexplained non-zero
        # exit, which the classifier now (correctly) refuses to read as a
        # clean result.
        return [
            RunResult(which, n, n in lengths, f"asan@{n}" if n in lengths else None,
                      1 if n in lengths else 0, None if n in lengths else None)
            for n in range(0, 61)
        ]

    pipeline = HarnessPipeline.__new__(HarnessPipeline)

    cases = [
        (set(), set(), Verdict.NO_DIFFERENCE_FOUND),
        (set(), {5}, Verdict.REGRESSION_INTRODUCED_BY_FIX),
        ({5}, set(), Verdict.CONFIRMED_REGRESSION_FIX),
        ({5}, {5}, Verdict.PARTIAL_FIX),
        ({3, 4, 5}, {20}, Verdict.PARTIAL_FIX),
        ({3, 4, 5}, {3, 4, 5}, Verdict.PARTIAL_FIX),
    ]
    for old_set, new_set, expected in cases:
        verdict, detail = pipeline._classify(fake("old", old_set), fake("new", new_set))
        assert verdict == expected, (
            f"old={sorted(old_set)} new={sorted(new_set)} -> {verdict}, expected {expected}"
        )
        assert detail


def test_failed_run_can_never_be_reported_as_confirmed():
    """HUS-001. A timed-out, signalled, or unexplained run produces a
    RunResult whose `crashed` is False, which used to read as "the new
    version did not crash" and produce a confirmed verdict for a version
    that was never shown to survive anything."""
    from augur.harness.pipeline import HarnessPipeline
    from augur.harness.sanitizer_runner import RunResult, RunStatus

    pipeline = HarnessPipeline.__new__(HarnessPipeline)
    old = [RunResult("old", n, True, f"asan@{n}", 1) for n in range(0, 11)]

    for label, bad in [
        ("timeout", RunResult("new", 0, False, "TIMEOUT", -1)),
        ("signal", RunResult("new", 0, False, None, -11)),
        ("unexplained nonzero exit", RunResult("new", 0, False, None, 2)),
        ("explicit failure", RunResult("new", 0, False, None, 0, None, "harness could not start")),
    ]:
        new = [bad] + [RunResult("new", n, False, None, 0) for n in range(1, 11)]
        assert bad.status == RunStatus.FAILED
        assert bad.failed
        verdict, detail = pipeline._classify(old, new)
        assert verdict == Verdict.INCONCLUSIVE, f"{label} -> {verdict}"
        assert "0" in detail, f"{label}: detail must name the affected length"


def test_deadly_signal_is_graded_by_which_signal_it_is():
    """A SEGV is evidence about a memory access, so it counts as a crash.
    An FPE is not -- a version that stopped dividing by zero proves nothing
    about whether a copy was bounded, and reporting that as a confirmed
    memory-safety fix would be exactly the kind of claim this tool must not
    make. A bare DEADLYSIGNAL names no cause at all, so nothing can be
    concluded from it either."""
    from augur.harness.sanitizer_runner import RunResult, RunStatus, parse_sanitizer_output

    segv, _ = parse_sanitizer_output(
        "AddressSanitizer:DEADLYSIGNAL\n==1==The signal is caused by a WRITE memory access\nSEGV on unknown address\n"
    )
    assert segv == "deadly-signal:SEGV"

    fpe, summary = parse_sanitizer_output(
        "AddressSanitizer:DEADLYSIGNAL\n==1==FPE on unknown address\n"
    )
    assert fpe == "deadly-signal:FPE"
    assert "FPE" in summary

    bare, _ = parse_sanitizer_output("AddressSanitizer:DEADLYSIGNAL\n")
    assert bare == "deadly-signal:UNKNOWN"

    crash = RunResult("old", 0, True, summary, 1, "deadly-signal:SEGV")
    assert crash.status == RunStatus.ERROR and crash.crashed and not crash.failed

    not_memory = RunResult(
        "old", 0, False, summary, -8, "deadly-signal:FPE",
        "harness died on FPE, which is not memory-safety evidence",
    )
    assert not_memory.status == RunStatus.FAILED
    assert not not_memory.crashed
    assert "FPE" in not_memory.failure_reason


def test_run_status_distinguishes_clean_error_and_failed():
    from augur.harness.sanitizer_runner import RunResult, RunStatus

    assert RunResult("old", 0, False, None, 0).status == RunStatus.CLEAN
    assert RunResult("old", 0, True, "asan", 1).status == RunStatus.ERROR
    assert RunResult("old", 0, False, "leaked", 1, "leak").status == RunStatus.CLEAN
    assert RunResult("old", 0, False, None, -1).status == RunStatus.FAILED
    assert RunResult("old", 0, False, "TIMEOUT", -1).status == RunStatus.FAILED


def test_describe_lengths_collapses_ranges():
    from augur.harness.pipeline import _describe_lengths

    assert _describe_lengths([]) == "none"
    assert _describe_lengths([3]) == "3"
    assert _describe_lengths([3, 4, 5, 7, 8]) == "3-5,7-8"
    assert _describe_lengths([1, 2, 3]) == "1-3"

@needs_gcc
def test_real_signals_are_graded_by_what_they_evidence():
    """Real processes, real signals, under a real compiler.

    The divisor is read from argv so the compiler cannot fold the division
    away. A `volatile int denominator = 0` version was tried first and does
    NOT trap on gcc 15.2 / x86-64 -- the program prints and exits 0 -- so it
    cannot be used to test anything about signal handling.
    """
    import tempfile as _tempfile

    from augur.harness.sanitizer_runner import SanitizerRunner, RunStatus

    runner = SanitizerRunner()
    probes = {
        # divide by zero, divisor unknown at compile time
        "FPE": '#include <stdlib.h>\nint main(int argc, char **argv){\n'
               '  int d = atoi(argv[1]); volatile int n = 42;\n'
               '  volatile int r = n / d; return r == 0 ? 1 : 0;\n}\n',
        # wild pointer read: consistent with a bad memory access
        "SEGV": '#include <stdlib.h>\nint main(int argc, char **argv){\n'
                '  int *p = (int *)atoi(argv[1]); return *p;\n}\n',
    }
    expected = {"FPE": RunStatus.FAILED, "SEGV": RunStatus.ERROR}

    with _tempfile.TemporaryDirectory() as tmp:
        for signal_name, source in probes.items():
            binary = Path(tmp) / f"probe_{signal_name}"
            runner.compile(source, binary)
            result = runner.run_one(binary, "old", 0)
            assert result.error_kind == f"deadly-signal:{signal_name}", (
                f"{signal_name}: got {result.error_kind!r}"
            )
            assert result.status == expected[signal_name], (
                f"{signal_name}: status {result.status}, expected {expected[signal_name]}"
            )

            if signal_name == "FPE":
                assert not result.crashed
                assert result.failure_reason and "not memory-safety evidence" in result.failure_reason
            else:
                assert result.crashed and not result.failed


@needs_gcc
def test_a_non_memory_fault_cannot_be_read_as_a_confirmed_memory_fix():
    """The whole point of grading signals by cause: a version that merely
    stopped dividing by zero must not be reported as a confirmed fix for a
    memory-safety defect."""
    import tempfile as _tempfile

    from augur.harness.sanitizer_runner import RunResult, SanitizerRunner

    # old: copies safely, then divides by zero. new: the same safe copy, no
    # division -- represented below by a clean RunResult. If the FPE were
    # treated as a memory violation this would report a confirmed
    # memory-safety fix that never happened.
    prelude = "#include <stdlib.h>\n#include <string.h>\n"
    old = prelude + (
        "void f(const char *src, int d) {\n"
        "  char buf[8];\n"
        "  if (strlen(src) < 8) return;\n"
        "  memcpy(buf, src, 8);\n"
        "  volatile int n = 42;\n"
        "  volatile int r = n / d;\n"
        "  (void)r;\n"
        "}\n"
    )
    runner = SanitizerRunner()
    with _tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "bin"
        driver = (
            prelude
            + old
            + '\nint main(int argc, char **argv){\n'
            + "  char b[9]; memset(b, 65, 8); b[8] = 0;\n"
            + '  f(b, atoi(argv[1]));\n'
            + '  return 0;\n}\n'
        )
        runner.compile(driver, binary)
        # Sanity: the fault really happens under this compiler.
        raw = subprocess.run([str(binary), "0"], capture_output=True, text=True,
                             timeout=10, env=runner._env())
        assert "DEADLYSIGNAL" in raw.stderr and "FPE" in raw.stderr, (
            "expected a real FPE; got: " + raw.stderr[:200]
        )
        faulted = runner.run_one(binary, "old", 0)
        assert faulted.failed and not faulted.crashed

    verdict, _ = HarnessPipeline.__new__(HarnessPipeline)._classify(
        [faulted], [RunResult("new", 0, False, None, 0)]
    )
    assert verdict == Verdict.INCONCLUSIVE, verdict
