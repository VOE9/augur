"""Independent guard counterexamples; optionally compile/run them under ASan.

Run from any directory: python scripts/verify_guard_hussein.py [--compiler gcc]
This reports evidence without editing the detector or its existing tests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from augur.harness.sanitizer_runner import SanitizerRunner, parse_sanitizer_output
from augur.pattern.unbounded_copy import UnboundedCopyDetector

CASES = [
    ("logging_only", 'if (strlen(src) < 8) puts("short");\nmemcpy(buf, src, 8);', 0, False),
    ("wrong_direction", "if (strlen(src) > 8) return;\nmemcpy(buf, src, 8);", 0, False),
    ("insufficient_bound", "if (strlen(src) < 2) return;\nmemcpy(buf, src, 8);", 2, False),
    ("nested_branch", "if (flag) { if (strlen(src) < 8) return; }\nmemcpy(buf, src, 8);", 0, False),
    ("goto_before_copy", "if (strlen(src) < 8) goto copy;\ncopy: memcpy(buf, src, 8);", 0, False),
    ("break_before_copy", "while (1) { if (strlen(src) < 8) break; break; }\nmemcpy(buf, src, 8);", 0, False),
    ("moved_pointer", "if (strlen(src) < 8) return;\nchar *p = (char *)src; p += 7;\nmemcpy(buf, p, 8);", 8, False),
    ("guard_in_comment", "/* if (strlen(src) < 8) return; */\nmemcpy(buf, src, 8);", 0, False),
    ("strcpy_lower_bound", "if (strlen(src) < 8) return;\nstrcpy(buf, src);", 12, False),
    ("outer_if_without_braces", "if (flag) if (strlen(src) < 8) return;\nmemcpy(buf, src, 8);", 0, False),
    ("sibling_else", "if (flag) { if (strlen(src) < 8) return; } else { memcpy(buf, src, 8); }", 0, False),
    ("sibling_blocks", "if (flag) { if (strlen(src) < 8) return; }\nif (!flag) { memcpy(buf, src, 8); }", 0, False),
    ("jump_over_guard", "goto copy;\nif (strlen(src) < 8) return;\ncopy: memcpy(buf, src, 8);", 0, False),
    ("destination_too_small", "if (strlen(src) < 16) return;\nmemcpy(buf, src, 16);", 16, False),
    ("switch_sibling_cases", "switch (flag) { case 1: if (strlen(src) < 8) return; break; case 0: memcpy(buf, src, 8); break; }", 0, False),
    ("safe_control", "if (strlen(src) < 8) return;\nmemcpy(buf, src, 8);", 0, True),
]


def run(compiler: str | None) -> dict:
    detector_path = PROJECT / "augur/pattern/unbounded_copy.py"
    before = hashlib.sha256(detector_path.read_bytes()).hexdigest()
    results = []
    for name, body, length, expected in CASES:
        function = "void f(const char *src, int flag) {\nchar buf[8];\n" + body + "\n}\n"
        findings = UnboundedCopyDetector().find_all(function, {"src"})
        row = {
            "case": name, "function": function, "length": length, "flag": 0,
            "expected_guarded": expected,
            "observed_guarded": findings[0].guarded if findings else None,
            "guard_detail": findings[0].guard_detail if findings else None,
        }
        row["matches_expectation"] = row["observed_guarded"] == expected
        if compiler:
            source = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n" + function
            source += (
                f"int main(void) {{ char *src = malloc({length + 1}); "
                f"if (!src) return 3; memset(src, 'A', {length}); "
                f"src[{length}] = '\\0'; f(src, 0); free(src); return 0; }}\n"
            )
            with tempfile.TemporaryDirectory(prefix="hussein-guard-") as temp:
                binary = Path(temp) / "probe"
                runner = SanitizerRunner(compiler=compiler)
                try:
                    runner.compile(source, binary)
                    completed = subprocess.run(
                        [str(binary)], capture_output=True, text=True,
                        timeout=5, env=runner._env(),
                    )
                    row["asan_exit_code"] = completed.returncode
                    row["asan_stderr"] = completed.stderr
                    row["asan_error_kind"] = parse_sanitizer_output(completed.stderr)[0]
                    # Retain the whole report; a bare DEADLYSIGNAL is not
                    # promoted to proof of this fixture's specific defect.
                    row["asan_bounds_error"] = any(
                        f"ERROR: AddressSanitizer: {kind}" in completed.stderr
                        for kind in ("heap-buffer-overflow", "stack-buffer-overflow")
                    )
                except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
                    row["execution_failure"] = str(exc)
        results.append(row)
    return {
        "reviewer": "Hussein", "compiler": compiler,
        "detector_sha256_before": before,
        "detector_sha256_after": hashlib.sha256(detector_path.read_bytes()).hexdigest(),
        "mismatches": sum(not r["matches_expectation"] for r in results),
        "cases": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", help="optional real ASan compiler, e.g. gcc")
    parser.add_argument("--out", type=Path, help="save full JSON evidence")
    args = parser.parse_args()
    report = run(args.compiler)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = {k: v for k, v in report.items() if k != "cases"}
    summary["cases"] = [
        {k: v for k, v in row.items() if k not in {"function", "asan_stderr"}}
        for row in report["cases"]
    ]
    print(json.dumps(summary, indent=2))
    return 1 if report["mismatches"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
