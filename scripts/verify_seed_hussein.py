"""Real-compiler diagnostics for generated seed bytes and truncation coverage."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from augur.harness.generator import DifferentialHarnessGenerator
from augur.pattern.function_extractor import FunctionExtractor
from augur.pattern.unbounded_copy import UnboundedCopyDetector


def run(compiler: str) -> dict:
    core_files = ["augur/harness/generator.py", "augur/harness/pipeline.py"]
    fingerprints = {name: hashlib.sha256((PROJECT / name).read_bytes()).hexdigest() for name in core_files}
    old = "void f(const char *src) { char buf[8]; memcpy(buf, src, 8); }"
    new = '''void f(const char *src) {
        char buf[8];
        printf("%zu:", strlen(src));
        for (size_t i=0; i<strlen(src); i++) printf("%02x", (unsigned char)src[i]);
        puts("");
        if (strlen(src) < 8) return;
        memcpy(buf, src, 8);
    }'''
    extractor = FunctionExtractor()
    old_fn = extractor.find_function(old, "f")
    new_fn = extractor.find_function(new, "f")
    finding = UnboundedCopyDetector().find(old_fn.full_text, {"src"})
    rows = []
    for seed in ("ABCD", "حسين", "é", "A\x00BC"):
        row = {"seed": seed, "python_length": len(seed), "utf8_hex": seed.encode("utf-8").hex(),
               "utf8_length": len(seed.encode("utf-8"))}
        try:
            generated = DifferentialHarnessGenerator().generate(old_fn, new_fn, finding, seed, {})
        except (ValueError, TypeError) as error:
            row["rejected"] = str(error)
            rows.append(row)
            continue
        row["generated_source_sha256"] = hashlib.sha256(generated.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory(prefix="augur-seed-") as temporary:
            root = Path(temporary)
            source, binary = root / "probe.c", root / ("probe.exe" if os.name == "nt" else "probe")
            source.write_text(generated, encoding="utf-8")
            compiled = subprocess.run([compiler, "-Wall", "-Wextra", str(source), "-o", str(binary)],
                                      capture_output=True, text=True, timeout=30)
            row["compiler_exit_code"] = compiled.returncode
            row["compiler_stderr"] = compiled.stderr
            if compiled.returncode == 0:
                observed = []
                for length in range(len(seed) + 1):
                    completed = subprocess.run([str(binary), "new", str(length)], capture_output=True,
                                               text=True, timeout=5)
                    observed.append({"requested_length": length, "exit_code": completed.returncode,
                                     "stdout": completed.stdout.strip(), "stderr": completed.stderr})
                row["pipeline_length_sweep"] = observed
                row["full_requested"] = subprocess.run(
                    [str(binary), "new", str(len(seed.encode("utf-8")))], capture_output=True,
                    text=True, timeout=5).stdout.strip()
        rows.append(row)
    return {"schema_version": 1, "compiler": compiler,
            "compiler_version": subprocess.run([compiler, "--version"], capture_output=True, text=True).stdout.splitlines()[0],
            "source_before_sha256": fingerprints,
            "source_after_sha256": {name: hashlib.sha256((PROJECT / name).read_bytes()).hexdigest() for name in core_files},
            "cases": rows,
            "scope": "Seed construction diagnostics with a real C compiler; not ASan vulnerability evidence. "
                     "UTF-8 columns describe a proposed encoding contract, not an already documented guarantee."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", default="gcc")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    evidence = run(args.compiler)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"cases": [{key: row[key] for key in ("seed", "python_length", "utf8_hex", "full_requested", "rejected") if key in row}
                               for row in evidence["cases"]]}, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
