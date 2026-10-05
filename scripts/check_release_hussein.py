"""Offline wheel installation and CLI smoke checks in an isolated environment."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import venv
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


def check_release() -> dict:
    started = time.monotonic()
    evidence = {"schema_version": 1, "python": sys.version, "checks": []}
    env = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME"):
        env.pop(name, None)
    env.update(PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1", PIP_DISABLE_PIP_VERSION_CHECK="1",
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    evidence["execution_environment"] = {
        "PYTHONUTF8": "1", "PYTHONPATH": "removed", "PYTHONHOME": "removed",
        "scope": "Tests isolated installation and Unicode metadata with UTF-8 enabled; "
                 "does not establish compatibility with every legacy Windows locale.",
    }

    def run(label: str, command: list[str], cwd: Path, expected: int = 0, required: bool = True):
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=180)
        evidence["checks"].append({"name": label, "exit_code": result.returncode,
                                   "passed": result.returncode == expected,
                                   "stdout": result.stdout[-5000:], "stderr": result.stderr[-5000:]})
        if result.returncode != expected and required:
            raise RuntimeError(f"{label}: expected exit {expected}, got {result.returncode}")
        return result.stdout

    try:
        with tempfile.TemporaryDirectory(prefix="augur-release-") as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            hashes = {}
            files = [PROJECT / filename for filename in ("pyproject.toml", "README.md", "LICENSE")]
            files.extend(sorted((PROJECT / "augur").rglob("*.py")))
            for source in files:
                relative = source.relative_to(PROJECT)
                data = source.read_bytes()
                hashes[relative.as_posix()] = hashlib.sha256(data).hexdigest()
                destination = snapshot / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
            evidence["source_sha256"] = hashes
            wheels = root / "wheels"
            run("build wheel without network", [sys.executable, "-m", "pip", "wheel", "--no-deps",
                "--no-build-isolation", "--no-index", "--wheel-dir", str(wheels), str(snapshot)], root)
            wheel, = wheels.glob("*.whl")
            evidence["wheel_sha256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
            evidence["wheel_filename"] = wheel.name

            environment = root / "environment"
            venv.EnvBuilder(with_pip=True).create(environment)
            bin_dir = environment / ("Scripts" if os.name == "nt" else "bin")
            python = bin_dir / ("python.exe" if os.name == "nt" else "python")
            cli = bin_dir / ("augur.exe" if os.name == "nt" else "augur")
            unrelated = root / "مسار مستقل spaces"
            unrelated.mkdir()
            run("install wheel without network", [str(python), "-m", "pip", "install",
                "--no-index", "--no-deps", str(wheel)], unrelated)
            run("installed version matches metadata", [str(python), "-c",
                "import augur,importlib.metadata,json; v=importlib.metadata.version('augur'); "
                "print(json.dumps({'code_version':augur.__version__,'distribution_version':v})); "
                "assert augur.__version__ == v"], unrelated)
            run("console version", [str(cli), "--version"], unrelated)
            for mode in (None, "radar", "harness", "provenance"):
                run(f"help {mode or 'main'}", [str(cli), *([mode] if mode else []), "--help"], unrelated)

            git = shutil.which("git")
            if not git:
                raise RuntimeError("Git is required for the real repository smoke check")
            repository = unrelated / "مستودع تجريبي"
            repository.mkdir()
            for args in (("init", "-q"), ("config", "user.name", "حسين review"),
                         ("config", "user.email", "review@example.invalid"),
                         ("config", "commit.gpgsign", "false")):
                run("fixture git " + args[0], [git, "-C", str(repository), *args], unrelated)
            (repository / "auth").mkdir()
            source = repository / "auth" / "session.py"
            source.write_text("def check(token):\n    return True\n", encoding="utf-8")
            run("fixture initial add", [git, "-C", str(repository), "add", "."], unrelated)
            run("fixture initial commit", [git, "-C", str(repository), "commit", "-qm", "initial"], unrelated)
            source.write_text("def check(token):\n    validate(token)\n    return True\n", encoding="utf-8")
            run("fixture repair add", [git, "-C", str(repository), "add", "."], unrelated)
            run("fixture repair commit", [git, "-C", str(repository), "commit", "-qm", "minor cleanup تحسين"], unrelated)
            sha = run("fixture repair revision", [git, "-C", str(repository), "rev-parse", "HEAD"], unrelated).strip()

            def strict_constant(value):
                raise ValueError(f"invalid JSON numeric constant: {value}")

            output = run("installed radar JSON", [str(cli), "radar", str(repository),
                          "--limit", "2", "--format", "json"], unrelated)
            payload = json.loads(output, parse_constant=strict_constant)
            assert payload["schema_version"] == "1.0"
            assert payload["qualified_count"] == len(payload["findings"])
            match, = [finding for finding in payload["findings"] if finding["commit"]["sha"] == sha]
            assert "تحسين" in match["commit"]["message"]
            assert "حسين" in match["commit"]["author"]
            assert "defensive_diff_shape" in {s["name"] for s in match["signals"] if s["fired"]}
            evidence["checks"].append({"name": "strict JSON and Unicode metadata", "passed": True})

            report_path = unrelated / "تقرير radar.json"
            run("installed radar JSON file", [str(cli), "radar", str(repository), "--limit", "2",
                "--format", "json", "--out", str(report_path)], unrelated)
            saved = json.loads(report_path.read_text(encoding="utf-8"), parse_constant=strict_constant)
            assert saved == payload
            evidence["checks"].append({"name": "stdout and saved JSON agree", "passed": True})
            evidence["source_changed_during_run"] = any(
                hashlib.sha256((PROJECT / relative).read_bytes()).hexdigest() != digest
                for relative, digest in hashes.items())
            if evidence["source_changed_during_run"]:
                raise RuntimeError("source changed during release verification; rerun against a stable tree")
    except (OSError, RuntimeError, ValueError, AssertionError, subprocess.TimeoutExpired) as error:
        evidence["error"] = f"{type(error).__name__}: {error}"
    evidence["passed"] = "error" not in evidence and all(row["passed"] for row in evidence["checks"])
    evidence["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    evidence = check_release()
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": evidence["passed"], "checks": len(evidence["checks"]),
                      "elapsed_seconds": evidence["elapsed_seconds"], "error": evidence.get("error"),
                      "source_changed_during_run": evidence.get("source_changed_during_run")}, indent=2))
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
