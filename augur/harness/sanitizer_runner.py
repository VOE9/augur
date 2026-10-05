"""Compiles a generated harness with AddressSanitizer and runs it against
a range of truncation lengths, one subprocess invocation per (impl,
length) pair -- ASan aborts the whole process on the first detected
error by default, so testing many candidates in a single run isn't
reliable; a fresh process per candidate is simple and unambiguous."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


class CompileError(RuntimeError):
    pass


class RunStatus:
    """The outcome of one harness run, as opposed to `crashed`.

    `crashed` is a single boolean, and it conflates three situations that
    must never be read the same way:

      CLEAN  -- the process ran and the sanitizer found nothing.
      ERROR  -- the sanitizer found a memory-safety violation.
      FAILED -- nothing can be concluded: the process timed out, died on a
                signal without a sanitizer report, or failed to start.

    Reading a FAILED run as CLEAN is what let a timed-out or signalled run
    pass as `confirmed_regression_fix`: the verdict logic saw "old crashed,
    new did not" and had no way to know that "new did not" meant "new never
    finished".
    """

    CLEAN = "clean"
    ERROR = "error"
    FAILED = "failed"


@dataclass(frozen=True)
class RunResult:
    which: str  # "old" | "new"
    length: int
    crashed: bool
    asan_summary: str | None
    exit_code: int
    # The sanitizer's own classification of the violation, e.g.
    # "heap-buffer-overflow". None when there was no memory error.
    # "leak" is a value that can appear here while `crashed` is False --
    # see parse_sanitizer_output.
    error_kind: str | None = None
    # Set when the process could not be evaluated at all. Kept as an
    # explicit field rather than inferred, because an unexplained non-zero
    # exit and a clean run are indistinguishable without one.
    failure_reason: str | None = None

    @property
    def leaked(self) -> bool:
        """True when the only thing the sanitizer reported was memory
        leaked at exit. Not a memory-safety violation of the shape this
        tool analyses, so it never counts as a crash."""
        return self.error_kind == "leak"

    @property
    def failed(self) -> bool:
        """True when nothing can be concluded from this run.

        Delegates to `status` rather than reading `failure_reason`
        directly, so that a hand-constructed RunResult with an unexplained
        non-zero exit -- the shape a caller builds when they have no real
        run to hand -- is classified exactly as the corresponding real run
        would be. Reading only the explicit field left those runs looking
        clean, which is the whole defect this property exists to close.
        """
        return self.status == RunStatus.FAILED

    @property
    def status(self) -> str:
        """Derived so that a hand-constructed RunResult is classified the
        same way as one produced by a real run. A non-zero exit with no
        sanitizer explanation and no recorded reason is treated as failed
        rather than clean: an unexplained exit is not evidence of safety."""
        if self.failure_reason is not None:
            return RunStatus.FAILED
        if self.crashed:
            return RunStatus.ERROR
        if self.error_kind is not None:
            return RunStatus.CLEAN if self.error_kind == "leak" else RunStatus.ERROR
        return RunStatus.CLEAN if self.exit_code == 0 else RunStatus.FAILED


# "ERROR: AddressSanitizer: heap-buffer-overflow" is how a real memory
# error is announced. A leak is announced as "ERROR: LeakSanitizer:" and
# summarised as "SUMMARY: AddressSanitizer: 20 byte(s) leaked in ..." --
# which contains the same product name, so matching on "AddressSanitizer"
# alone silently reclassifies an ordinary leak as a crash.
_ERROR_RE = re.compile(r"ERROR:\s+(AddressSanitizer|LeakSanitizer):\s*(.+)$", re.MULTILINE)
_LEAK_SUMMARY_RE = re.compile(r"SUMMARY:\s*AddressSanitizer:\s*[\d,]+ byte\(s\) leaked", re.MULTILINE)
# ASan reports a fatal signal it intercepted as "AddressSanitizer:DEADLYSIGNAL",
# followed by the signal name. Whether that is evidence of anything depends
# entirely on WHICH signal it was:
#
#   SEGV, BUS   consistent with a bad memory access -- a wild pointer or an
#               out-of-bounds write is exactly what this tool looks for, so
#               these count as crashes.
#   FPE         integer divide by zero. Not a memory error. An old version
#   ILL         that divides by zero while the new one does not proves
#   ABRT        nothing about whether a copy was bounded -- it only proves
#   TRAP        the arithmetic changed.
#
# A bare "DEADLYSIGNAL" with no signal named identifies no cause at all, so
# nothing can be concluded from it and the run is recorded as failed rather
# than as a crash. Counting it as a crash would let a version that merely
# stopped dividing by zero be reported as a confirmed memory-safety fix.
_MEMORY_SIGNALS = {"SEGV", "BUS"}
_NON_MEMORY_SIGNALS = {"FPE", "ILL", "ABRT", "TRAP"}
_DEADLY_SIGNAL_RE = re.compile(
    r"AddressSanitizer:\s*DEADLYSIGNAL"
    r"(?:[\s\S]*?\b(SEGV|BUS|ABRT|ILL|FPE|TRAP)\b)?",
    re.IGNORECASE,
)


def parse_sanitizer_output(stderr: str) -> tuple[str | None, str | None]:
    """Returns (error_kind, summary_line) for one sanitizer run.

    error_kind is the sanitizer's own classification of a real memory
    error ("heap-buffer-overflow", "stack-buffer-overflow",
    "deadly-signal", ...), or "leak" when the only report was memory
    leaked at exit, or None when the run produced no sanitizer output at
    all. A leak is deliberately kept distinct from a memory error: this
    tool decides whether a fix bounds a copy, and a function that
    allocates without freeing says nothing either way about that.
    Treating a leak as a crash made an otherwise-safe pre-fix
    implementation look like it crashed, which in turn made a real
    regression read as a mere partial fix.
    """
    # Checked BEFORE the generic error-header match. A fatal signal makes
    # ASan print "AddressSanitizer:DEADLYSIGNAL" and then, on its own line,
    # "ERROR: AddressSanitizer: <SIGNAL> on unknown address ..." -- so the
    # generic pattern happily matches that line, returns the entire
    # "FPE on unknown address 0x... (pc ...)" tail as if it were a memory
    # error class, and an arithmetic fault gets filed as a memory-safety
    # violation. Order matters here.
    deadly = _DEADLY_SIGNAL_RE.search(stderr)
    if deadly:
        signal = deadly.group(1)
        if signal is None:
            # The marker alone names no cause, so it decides nothing.
            return "deadly-signal:UNKNOWN", "AddressSanitizer:DEADLYSIGNAL (signal not reported)"
        return f"deadly-signal:{signal.upper()}", f"AddressSanitizer:DEADLYSIGNAL ({signal.upper()})"

    for match in _ERROR_RE.finditer(stderr):
        product, detail = match.group(1), match.group(2).strip()
        if product == "LeakSanitizer":
            return "leak", f"ERROR: LeakSanitizer: {detail}"
        return detail.split(" on address")[0].strip(), match.group(0).strip()

    leak_summary = _LEAK_SUMMARY_RE.search(stderr)
    if leak_summary:
        return "leak", leak_summary.group(0).strip()
    return None, None


class SanitizerRunner:
    def __init__(
        self,
        compiler: str = "gcc",
        timeout_seconds: float = 5.0,
        detect_leaks: bool = False,
    ):
        self.compiler = compiler
        self.timeout_seconds = timeout_seconds
        self.detect_leaks = detect_leaks

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        env["ASAN_OPTIONS"] = (
            f"detect_leaks={'1' if self.detect_leaks else '0'}:"
            "abort_on_error=0:exitcode=1:log_to_stderr=1"
        )
        return env

    def compile(self, source: str, binary_path: Path) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".c", delete=False) as f:
            f.write(source)
            source_path = Path(f.name)
        try:
            result = subprocess.run(
                [self.compiler, "-fsanitize=address", "-g", "-O0", str(source_path), "-o", str(binary_path)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
            )
            if result.returncode != 0:
                raise CompileError(result.stderr)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CompileError(f"could not compile harness: {exc}") from exc
        finally:
            source_path.unlink(missing_ok=True)

    def run_one(self, binary_path: Path, which: str, length: int) -> RunResult:
        try:
            result = subprocess.run(
                [str(binary_path), which, str(length)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=self.timeout_seconds, env=self._env(),
            )
        except subprocess.TimeoutExpired:
            return RunResult(
                which, length, crashed=False, asan_summary=None, exit_code=-1,
                failure_reason=f"timed out after {self.timeout_seconds}s",
            )
        except OSError as e:
            return RunResult(
                which, length, crashed=False, asan_summary=None, exit_code=-1,
                failure_reason=f"could not execute harness: {e}",
            )

        error_kind, summary = parse_sanitizer_output(result.stderr)

        # A fatal signal that is not a memory fault tells us nothing about
        # whether a copy was bounded, and a signal whose name ASan did not
        # report is not identifiable at all. Both are recorded as failures
        # so that no verdict rests on them.
        if error_kind and error_kind.startswith("deadly-signal:"):
            signal = error_kind.split(":", 1)[1]
            if signal in _MEMORY_SIGNALS:
                return RunResult(
                    which, length, crashed=True, asan_summary=summary,
                    exit_code=result.returncode, error_kind=error_kind,
                )
            reason = (
                f"harness died on {signal}, which is not memory-safety evidence"
                if signal != "UNKNOWN"
                else "harness died on an unidentified signal, cause unknown"
            )
            return RunResult(
                which, length, crashed=False, asan_summary=summary,
                exit_code=result.returncode, error_kind=error_kind,
                failure_reason=reason,
            )

        # An unexplained non-zero exit is not a clean run and is not a
        # sanitizer error either. Recording that explicitly is what stops
        # it being read downstream as evidence that the new version is safe.
        if error_kind is None and result.returncode != 0:
            return RunResult(
                which, length, crashed=False, asan_summary=None,
                exit_code=result.returncode,
                failure_reason=f"harness exited {result.returncode} with no sanitizer report",
            )

        return RunResult(
            which, length,
            crashed=error_kind is not None and error_kind != "leak",
            asan_summary=summary,
            exit_code=result.returncode,
            error_kind=error_kind,
        )

    def sweep(self, binary_path: Path, which: str, max_length: int) -> list[RunResult]:
        """Runs length 0..max_length inclusive, ascending -- so the first
        crashing result in the returned list is the SHORTEST truncation
        that triggers it, which is the most convincing minimal case."""
        return [self.run_one(binary_path, which, length) for length in range(0, max_length + 1)]
