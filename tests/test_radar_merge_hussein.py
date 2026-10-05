"""Hussein's independent checks against a real, merged Git history."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from augur.radar.engine import RadarEngine
from augur.radar.repository import GitRepository
import augur.radar.repository as repository_module

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git unavailable")


def _git(path: Path, *args: str) -> str:
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    return subprocess.run(
        ["git", "-C", str(path), *args], check=True,
        capture_output=True, text=True, env=env,
    ).stdout.strip()


@pytest.fixture
def merged_fix_repo(tmp_path: Path):
    repo = tmp_path / "merged-history"
    repo.mkdir()
    _git(repo, "init", "-q", "--initial-branch=main")
    _git(repo, "config", "user.name", "Hussein review fixture")
    _git(repo, "config", "user.email", "review@example.invalid")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / "auth").mkdir()
    source = repo / "auth" / "session.py"
    source.write_text("def check(token):\n    return True\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "initial implementation")

    _git(repo, "switch", "-qc", "repair")
    source.write_text(
        "def check(token):\n    validate(token)\n    return True\n", encoding="utf-8"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "small cleanup")
    repair_sha = _git(repo, "rev-parse", "HEAD")

    _git(repo, "switch", "-q", "main")
    (repo / "notes.txt").write_text("independent main change\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "update notes")
    _git(repo, "merge", "-q", "--no-ff", "repair", "-m", "minor adjustment")
    merge_sha = _git(repo, "rev-parse", "HEAD")
    return GitRepository(repo), repair_sha, merge_sha


def test_merge_carries_the_fix_diff_and_qualifies(merged_fix_repo):
    repo, _, merge_sha = merged_fix_repo
    commits = repo.recent_commits(limit=20)
    merge = next(c for c in commits if c.sha == merge_sha)
    assert "validate(token)" in merge.added_lines()
    assert {f.filename for f in merge.changed_files} == {"auth/session.py"}
    finding = RadarEngine().evaluate_commit(merge)
    assert finding is not None
    assert "defensive_diff_shape" in {s.name for s in finding.fired_signals()}


def test_default_scan_preserves_reachable_side_branch_commits(merged_fix_repo):
    """Merge-diff support must not silently narrow an all-HEAD history scan."""
    repo, repair_sha, merge_sha = merged_fix_repo
    expected = set(_git(repo.path, "rev-list", "--max-count=20", "HEAD").splitlines())
    actual = [c.sha for c in repo.recent_commits(limit=20)]
    assert merge_sha in actual
    assert repair_sha in actual, "the actual repair on the merged branch was omitted"
    assert set(actual) == expected
    assert len(actual) == len(set(actual)), "one commit must not become duplicate findings"


def test_legacy_git_path_keeps_one_first_parent_merge_diff(merged_fix_repo, monkeypatch):
    """Force old-version selection, then run its Git commands on the real history.

    This validates fallback semantics with installed Git, not execution on
    an actual historical Git binary.
    """
    repo, repair_sha, merge_sha = merged_fix_repo
    monkeypatch.setattr(repository_module, "_git_version", lambda: (2, 30))
    commits = repo.recent_commits(limit=20)
    merges = [c for c in commits if c.sha == merge_sha]
    assert len(merges) == 1, "one merge must not be emitted once per parent"
    assert "validate(token)" in merges[0].added_lines()
    assert {f.filename for f in merges[0].changed_files} == {"auth/session.py"}
    assert repair_sha in {c.sha for c in commits}, "compatibility must retain side history"


@pytest.mark.parametrize("git_version", [(2, 31), (2, 30)], ids=["modern", "legacy"])
def test_merge_with_empty_first_parent_diff(merged_fix_repo, monkeypatch, git_version):
    """Git -m suppresses empty parent diffs; its first record can be parent 2."""
    repo, _, _ = merged_fix_repo
    _git(repo.path, "switch", "-qc", "discarded-repair")
    source = repo.path / "auth" / "session.py"
    source.write_text(
        "def check(token):\n    validate(token)\n    verifySignature(token)\n    return True\n",
        encoding="utf-8",
    )
    _git(repo.path, "add", ".")
    _git(repo.path, "commit", "-qm", "minor cleanup")
    branch_sha = _git(repo.path, "rev-parse", "HEAD")
    _git(repo.path, "switch", "-q", "main")
    _git(repo.path, "merge", "-q", "--no-ff", "-s", "ours", "discarded-repair", "-m", "minor adjustment")
    merge_sha = _git(repo.path, "rev-parse", "HEAD")
    assert _git(repo.path, "diff", "HEAD^1", "HEAD") == ""

    monkeypatch.setattr(repository_module, "_git_version", lambda: git_version)
    commits = repo.recent_commits(limit=20)
    merge = next(c for c in commits if c.sha == merge_sha)
    assert branch_sha in {c.sha for c in commits}
    assert merge.changed_files == [], "legacy -m selected a non-first-parent diff"
    assert RadarEngine().evaluate_commit(merge) is None
