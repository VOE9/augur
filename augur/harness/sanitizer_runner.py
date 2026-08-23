"""Compiles a generated harness with AddressSanitizer and runs it against
a range of truncation lengths, one subprocess invocation per (impl,
length) pair -- ASan aborts the whole process on the first detected
error by default, so testing many candidates in a single run isn't
reliable; a fresh process per candidate is simple and unambiguous."""
from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


class CompileError(RuntimeError):
    pass


@dataclass(frozen=True)
class RunResult:
    which: str  # "old" | "new"
    length: int
    crashed: bool
    asan_summary: str | None
    exit_code: int


class SanitizerRunner:
    def __init__(self, compiler: str = "gcc", timeout_seconds: float = 5.0):
        self.compiler = compiler
        self.timeout_seconds = timeout_seconds

    def compile(self, source: str, binary_path: Path) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(source)
            source_path = Path(f.name)
        try:
            result = subprocess.run(
                [self.compiler, "-fsanitize=address", "-g", "-O0", str(source_path), "-o", str(binary_path)],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                raise CompileError(result.stderr)
        finally:
            source_path.unlink(missing_ok=True)

    def run_one(self, binary_path: Path, which: str, length: int) -> RunResult:
        try:
            result = subprocess.run(
                [str(binary_path), which, str(length)],
                capture_output=True, text=True, timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return RunResult(which, length, crashed=False, asan_summary="TIMEOUT", exit_code=-1)

        crashed = "AddressSanitizer" in result.stderr
        summary = None
        if crashed:
            for line in result.stderr.splitlines():
                if "AddressSanitizer:" in line:
                    summary = line.strip()
                    break
        return RunResult(which, length, crashed=crashed, asan_summary=summary, exit_code=result.returncode)

    def sweep(self, binary_path: Path, which: str, max_length: int) -> list[RunResult]:
        """Runs length 0..max_length inclusive, ascending -- so the first
        crashing result in the returned list is the SHORTEST truncation
        that triggers it, which is the most convincing minimal case."""
        return [self.run_one(binary_path, which, length) for length in range(0, max_length + 1)]
