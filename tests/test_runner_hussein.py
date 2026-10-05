"""Independent real-process checks for HUS-001, including an actual timeout."""
from pathlib import Path
import shutil

import pytest

from augur.harness.pipeline import HarnessPipeline, Verdict
from augur.harness.sanitizer_runner import SanitizerRunner

needs_gcc = pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc unavailable")


def test_missing_executable_is_failed_not_clean(tmp_path: Path):
    result = SanitizerRunner().run_one(tmp_path / "absent-harness.exe", "new", 0)
    assert result.failed
    assert not result.crashed
    assert "could not execute" in result.failure_reason


@needs_gcc
def test_real_unexplained_exit_is_failed_not_clean(tmp_path: Path):
    runner = SanitizerRunner()
    binary = tmp_path / "nonzero"
    runner.compile("int main(void) { return 7; }", binary)
    result = runner.run_one(binary, "new", 0)
    assert result.exit_code == 7
    assert result.failed
    assert not result.crashed
    assert result.error_kind is None


@needs_gcc
def test_actual_new_timeout_cannot_confirm_actual_old_asan_error(tmp_path: Path):
    runner = SanitizerRunner(timeout_seconds=0.25)
    binary = tmp_path / "timeout-differential"
    runner.compile(
        '#include <stdlib.h>\n#include <string.h>\n'
        'int main(int argc, char **argv) {\n'
        '  if (argc == 3 && strcmp(argv[1], "old") == 0) {\n'
        "    char *p = malloc(1); if (!p) return 3; p[1] = 'A'; free(p); return 0;\n"
        '  }\n  for (;;) {}\n}\n', binary,
    )
    old = runner.run_one(binary, "old", 0)
    new = runner.run_one(binary, "new", 0)
    assert old.crashed and old.error_kind == "heap-buffer-overflow"
    assert new.failed and not new.crashed
    assert "timed out" in new.failure_reason
    verdict, detail = HarnessPipeline()._classify([old], [new])
    assert verdict == Verdict.INCONCLUSIVE
    assert "timed out" in detail and "new" in detail


@needs_gcc
def test_real_fpe_after_safe_copy_does_not_confirm_memory_fix(tmp_path: Path):
    """Integer division is removed; the guarded eight-byte copy is unchanged."""
    old = '''void f(const char *src) {
        char buf[8];
        if (strlen(src) < 8) return;
        memcpy(buf, src, 8);
        volatile int numerator=42, denominator=0;
        volatile int result=numerator/denominator;
        (void)result;
    }'''
    new = '''void f(const char *src) {
        char buf[8];
        if (strlen(src) < 8) return;
        memcpy(buf, src, 8);
    }'''
    result = HarnessPipeline().analyze(old, new, "f", "A" * 8, {}, tmp_path)
    assert result.verdict != Verdict.CONFIRMED_REGRESSION_FIX, (
        "A non-memory FPE report cannot establish a copy memory-safety fix: " + result.detail
    )
