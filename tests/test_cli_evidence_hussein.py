"""Independent CLI acceptance checks against a real, disposable Git repository."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from augur.radar.commit import Commit
from augur.radar.engine import RadarEngine
from augur.radar.signal import is_loudly_disclosed

PROJECT = Path(__file__).resolve().parents[1]


@pytest.fixture
def cli_repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git unavailable")
    repo = tmp_path / "repository spaces"
    repo.mkdir()
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    commands = [("init", "-q"), ("config", "user.name", "review"),
                ("config", "user.email", "review@example.invalid"),
                ("config", "commit.gpgsign", "false")]
    for args in commands:
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)
    (repo / "auth").mkdir()
    (repo / "auth/session.py").write_text("validate(token)\n", encoding="utf-8")
    for args in [("add", "."), ("commit", "-qm", "minor cleanup")]:
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)
    return repo


def _cli(repo, *arguments):
    return subprocess.run([sys.executable, "-m", "augur", "radar", str(repo),
                           "--format", "json", *arguments], cwd=PROJECT,
                          capture_output=True, text=True, timeout=15)


@pytest.mark.parametrize("arguments", [
    ("--high-threshold", "nan"), ("--high-threshold", "inf"),
    ("--medium-threshold", "nan"), ("--medium-threshold=-inf",),
    ("--weight", "defensive_diff_shape=nan"),
    ("--weight", "defensive_diff_shape=inf"),
    ("--weight", "unknown_signal=1"),
    ("--weight", "memory_safety_diff=1"),
    ("--limit", "0"), ("--limit", "-1"),
    ("--high-threshold", "1", "--medium-threshold", "2"),
])
def test_invalid_radar_configuration_is_rejected_cleanly(cli_repo, arguments):
    result = _cli(cli_repo, *arguments)
    assert result.returncode != 0, f"invalid configuration accepted: {arguments}"
    assert "Traceback" not in result.stderr, result.stderr
    assert not result.stdout.strip(), "invalid configuration must not emit a success report"
    assert result.stderr.strip(), "users need an error explaining the rejected configuration"


def test_configured_variant_emits_strict_json(cli_repo):
    result = _cli(cli_repo, "--variant", "memory-safety", "--weight", "memory_safety_diff=2.25")
    assert result.returncode == 0, result.stderr

    def invalid_constant(value):
        pytest.fail(f"non-standard JSON numeric constant: {value}")

    report = json.loads(result.stdout, parse_constant=invalid_constant)
    assert report["configuration"]["weight_overrides"]["memory_safety_diff"] == 2.25
    assert report["qualified_count"] == len(report["findings"])


@pytest.mark.parametrize("message,disclosed", [
    ("update resource handling", False), ("format source", False), ("forces valid input", False),
    ("fix RCE", True), ("fix XSS", True), ("CVE-2026-1234", True), ("GHSA-abcd", True),
])
def test_disclosure_boundaries_do_not_hide_ordinary_words(message, disclosed):
    commit = Commit("a" * 40, message, "review", "2026-10-02",
                    "diff --git a/auth/session.py b/auth/session.py\n"
                    "--- a/auth/session.py\n+++ b/auth/session.py\n"
                    "@@ -1 +1 @@\n-    pass\n+    validate(token)\n")
    assert is_loudly_disclosed(commit) is disclosed
    assert (RadarEngine().evaluate_commit(commit) is None) is disclosed
