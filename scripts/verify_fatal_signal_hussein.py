"""Check whether a non-memory ASan report is promoted to memory-fix confirmation."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from augur.harness.pipeline import HarnessPipeline
from augur.harness.sanitizer_runner import SanitizerRunner


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--compiler", default="gcc")
    args = parser.parse_args()
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
    paths = ["augur/harness/pipeline.py", "augur/harness/sanitizer_runner.py"]
    before = {path: hashlib.sha256((PROJECT / path).read_bytes()).hexdigest() for path in paths}
    with tempfile.TemporaryDirectory(prefix="augur-signal-") as temporary:
        runner = SanitizerRunner(compiler=args.compiler)
        result = HarnessPipeline(runner=runner).analyze(old, new, "f", "A"*8, {}, Path(temporary))
        raw = subprocess.run([str(Path(temporary) / "harness_bin"), "old", "8"],
                             env=runner._env(), capture_output=True, text=True, timeout=5)
        evidence = {
            "old_source": old, "new_source": new, "seed": "A"*8,
            "verdict": result.verdict, "detail": result.detail,
            "old_results": [r.__dict__ for r in result.old_results],
            "new_results": [r.__dict__ for r in result.new_results],
            "raw_old_at_8": {"exit_code": raw.returncode, "stderr": raw.stderr},
            "source_before_sha256": before,
            "source_after_sha256": {path: hashlib.sha256((PROJECT / path).read_bytes()).hexdigest() for path in paths},
            "scope": "Integer division by zero after a bounds-safe copy; a real ASan FPE report is not a copy memory-error report.",
        }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"verdict": result.verdict, "old_error_kinds": sorted({r.error_kind for r in result.old_results if r.error_kind}),
                      "new_crashes": len(result.new_crash_lengths), "raw_stderr": raw.stderr[:1200]}, indent=2))


if __name__ == "__main__":
    main()
