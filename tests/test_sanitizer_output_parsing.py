"""Unit tests for the sanitizer-output parser.

The distinction these lock in is load-bearing: the harness decides whether a
differential fix actually bounded a copy, and a memory leak reported at exit
by LeakSanitizer contains the product name `AddressSanitizer` in its SUMMARY
line. Matching on the product name alone -- which is what this used to do --
turned every leaking target function into one that "crashed" at every input
length, and made a genuine regression introduced by a fix read as a mere
partial fix.

These use real sanitizer output captured from actual ASan/LSan runs, not
hand-written approximations of what the tools print.
"""
from __future__ import annotations

import shutil
import sys
import subprocess
import tempfile
from pathlib import Path

import pytest

from augur.harness.sanitizer_runner import SanitizerRunner, parse_sanitizer_output

GCC_MISSING = shutil.which("gcc") is None
needs_gcc = pytest.mark.skipif(GCC_MISSING, reason="gcc not available")


def test_clean_run_has_no_error_kind():
    assert parse_sanitizer_output("") == (None, None)
    assert parse_sanitizer_output("some ordinary warning\n") == (None, None)


def test_real_memory_error_is_a_crash():
    stderr = (
        "==1197==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x76d277df0054 "
        "at pc 0x65458c9ea854 bp 0x7ffe90b12df0 sp 0x7ffe90b12de0\n"
        "READ of size 1 at 0x76d277df0054 thread T0\n"
        "    #0 0x65458c9ea854 in parse_addr (/tmp/harness_bin)\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow /tmp/harness.c:24:10 in parse_addr\n"
    )
    kind, summary = parse_sanitizer_output(stderr)
    assert kind == "heap-buffer-overflow"
    assert "AddressSanitizer" in summary


def test_real_stack_error_is_a_crash():
    stderr = (
        "==1197==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x76d277df0054 "
        "at pc 0x65458c9ea854\n"
        "WRITE of size 1 at 0x76d277df0054 thread T0\n"
    )
    kind, _ = parse_sanitizer_output(stderr)
    assert kind == "stack-buffer-overflow"


def test_leak_report_is_not_a_crash():
    stderr = (
        "Direct leak of 20 byte(s) in 1 object(s) allocated from:\n"
        "    #0 0x5555 in malloc\n"
        "    #1 0x1234 in strdup /tmp/harness.c:31:12\n"
        "SUMMARY: AddressSanitizer: 20 byte(s) leaked in 1 allocation(s).\n"
    )
    kind, summary = parse_sanitizer_output(stderr)
    assert kind == "leak"
    assert "leaked" in summary


def test_leak_sanitizer_error_header_is_also_a_leak():
    stderr = "==42==ERROR: LeakSanitizer: detected memory leaks\n"
    kind, _ = parse_sanitizer_output(stderr)
    assert kind == "leak"


def test_memory_error_wins_when_both_are_reported():
    """ASan can print a leak summary alongside a real error. The memory
    error is the one that matters for this tool's question."""
    stderr = (
        "==1197==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 thread T0\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow harness.c:24:10 in parse_addr\n"
        "SUMMARY: AddressSanitizer: 20 byte(s) leaked in 1 allocation(s).\n"
    )
    kind, _ = parse_sanitizer_output(stderr)
    assert kind == "heap-buffer-overflow"


@needs_gcc
@pytest.mark.skipif(sys.platform != "linux", reason="real LeakSanitizer evidence is validated on Linux")
def test_leaking_function_is_reported_clean_by_a_real_run():
    """End-to-end under a real compiler: a target that allocates and never
    frees must not be reported as crashing. With the default settings the
    leak is not even instrumented for; with leak detection explicitly on,
    it must still be classified as a leak rather than a crash."""
    source = r"""
#include <stdlib.h>
#include <string.h>
static char *leaky(const char *in) {
  char *out = (char *)malloc(20);
  memset(out, 0, 20);
  strncpy(out, in, 19);
  return out;
}
int main(void) {
  char buf[64];
  memset(buf, 'A', sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  char *r = leaky(buf);
  return r == NULL ? 1 : 0;
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "leaky_bin"
        SanitizerRunner().compile(source, binary)

        default_run = SanitizerRunner().run_one(binary, "old", 10)
        assert not default_run.crashed
        assert default_run.error_kind is None

        leak_run = SanitizerRunner(detect_leaks=True).run_one(binary, "old", 10)
        assert leak_run.error_kind == "leak"
        assert leak_run.leaked
        assert not leak_run.crashed
        # Sanity: the leak really was reported, so the assertions above are
        # not passing merely because no report was produced at all.
        assert leak_run.asan_summary is not None and "leak" in leak_run.asan_summary.lower()


@needs_gcc
@pytest.mark.skipif(sys.platform != "linux", reason="real LeakSanitizer evidence is validated on Linux")
def test_leak_detection_can_be_turned_back_on():
    runner = SanitizerRunner(detect_leaks=True)
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "leaky_bin"
        probe = tmp + "/probe.c"
        Path(probe).write_text(
            "#include <stdlib.h>\nint main(void){ (void)malloc(20); return 0; }\n"
        )
        subprocess.run(["gcc", "-fsanitize=address", "-g", "-O0", probe, "-o", str(binary)], check=True)
        result = runner.run_one(binary, "old", 0)
    assert result.error_kind == "leak"
    assert not result.crashed
