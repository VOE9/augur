"""Edge cases for the provenance module, offline where possible."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from augur.provenance.pipeline import ProvenancePipeline
from augur.radar.repository import GitRepository

GIT_MISSING = subprocess.run(["which", "git"], capture_output=True).returncode != 0


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.mark.skipif(GIT_MISSING, reason="git not available")
def test_no_tags_in_repo_returns_empty_range_not_a_crash(tmp_path: Path):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    _git(repo_path, "init", "-q")
    _git(repo_path, "config", "user.email", "t@e.com")
    _git(repo_path, "config", "user.name", "T")

    (repo_path / "crash.c").write_text(
        "void f(const char *report, int index) {\n"
        "  char addr[20];\n"
        "  char *pc = report;\n"
        "  memcpy(addr, pc, 20);\n"
        "}\n"
    )
    _commit(repo_path, "add vulnerable function")
    (repo_path / "crash.c").write_text(
        "void f(const char *report, int index) {\n"
        "  char addr[20];\n"
        "  char *pc = report;\n"
        "  size_t n = strlen(pc);\n"
        "  memcpy(addr, pc, n < 19 ? n : 19);\n"
        "}\n"
    )
    sha_fix = _commit(repo_path, "fix")

    repo = GitRepository(repo_path)
    result = ProvenancePipeline().analyze(repo, "crash.c", "f", sha_fix, "report")

    assert result.introduction.found
    assert result.version_range is not None
    assert result.version_range.vulnerable_tags == []
    assert result.version_range.first_fixed_tag is None


@pytest.mark.skipif(GIT_MISSING, reason="git not available")
def test_pattern_not_present_before_fix_reports_not_found_honestly(tmp_path: Path):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    _git(repo_path, "init", "-q")
    _git(repo_path, "config", "user.email", "t@e.com")
    _git(repo_path, "config", "user.name", "T")

    (repo_path / "crash.c").write_text("void f(const char *report, int index) {}\n")
    _commit(repo_path, "no vulnerable pattern ever")
    (repo_path / "crash.c").write_text("void f(const char *report, int index) { /* unrelated change */ }\n")
    sha_fix = _commit(repo_path, "unrelated change, not actually a fix")

    repo = GitRepository(repo_path)
    result = ProvenancePipeline().analyze(repo, "crash.c", "f", sha_fix, "report")

    assert not result.introduction.found
    assert result.version_range is None
