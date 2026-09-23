"""Integration test for the radar module against a REAL git repository
built on the fly with subprocess calls to the actual `git` binary --
not mocked commit objects. Exercises GitRepository's log parsing and
RadarEngine's scoring together, the same way it would run against any
real clone."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import pytest

from augur.radar.commit import Commit
from augur.radar.engine import RadarEngine
from augur.radar.repository import GitRepository
from augur.radar.signal import MemorySafetyDiffSignal

GIT_MISSING = subprocess.run(["which", "git"], capture_output=True).returncode != 0


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _write(repo: Path, filename: str, content: str) -> None:
    path = repo / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")

    # 1. A silent-shaped fix: touches an auth path, adds a validation
    #    call, message is vague and never says "security"/"fix".
    _write(repo, "auth/session.py", "def check(): pass\n")
    _commit(repo, "initial commit")
    _write(repo, "auth/session.py", "def check():\n    validate(token)\n    return True\n")
    _commit(repo, "small cleanup")

    # 2. A loudly-disclosed fix: same shape, but says so -- must be excluded.
    _write(repo, "auth/login.py", "def login(): pass\n")
    _commit(repo, "add login stub")
    _write(repo, "auth/login.py", "def login():\n    validate(token)\n    return True\n")
    _commit(repo, "security fix: validate token before login")

    # 3. A brand-new feature: has a "defensive" shape but is explicitly
    #    typed as a new feature -- nothing prior to silently correct.
    _write(repo, "auth/mfa.py", "def verify_mfa():\n    validate(code)\n    return True\n")
    _commit(repo, "feat(auth): add MFA verification")

    # 4. Unrelated, non-security commit -- must not qualify.
    _write(repo, "README.md", "# Project\n")
    _commit(repo, "docs: add README")

    return repo


@pytest.mark.skipif(GIT_MISSING, reason="git not available")
def test_radar_ranks_the_silent_fix_above_everything_else(sample_repo: Path):
    """A bare "touches an auth/ path" commit (e.g. "initial commit",
    which only creates a file there) legitimately gets a low-confidence
    mention too -- the radar is broad-recall-by-design, ranked by
    confidence, not a hard content filter (see RadarEngine docstring).
    What must hold is that the actual silent fix ranks clearly on top,
    and that loud/feature/unrelated commits never qualify at all."""
    repo = GitRepository(sample_repo)
    findings = RadarEngine().scan(repo, limit=20)

    subjects = {f.commit.subject for f in findings}
    assert "security fix: validate token before login" not in subjects
    assert "feat(auth): add MFA verification" not in subjects
    assert "docs: add README" not in subjects

    assert findings, "expected at least one finding"
    assert findings[0].commit.subject == "small cleanup"
    assert findings[0].confidence in ("medium", "high")


@pytest.mark.skipif(GIT_MISSING, reason="git not available")
def test_flagged_commit_has_expected_signals_fired(sample_repo: Path):
    repo = GitRepository(sample_repo)
    findings = RadarEngine().scan(repo, limit=20)
    finding = next(f for f in findings if f.commit.subject == "small cleanup")

    fired_names = {r.name for r in finding.fired_signals()}
    assert "sensitive_path" in fired_names
    assert "defensive_diff_shape" in fired_names
    assert "vague_message_defensive_diff" in fired_names
    assert finding.confidence in ("medium", "high")


def test_memory_safety_variant_is_opt_in_and_qualifies_an_added_guard():
    raw_diff = """diff --git a/src/copy.c b/src/copy.c
index 1111111..2222222 100644
--- a/src/copy.c
+++ b/src/copy.c
@@ -1,2 +1,3 @@
 void copy(char *dst, const char *src, size_t n) {
+    if (n <= capacity) return;
 }
"""
    commit = Commit("a" * 40, "small cleanup", "tester", "2026-01-01", raw_diff)

    assert RadarEngine().evaluate_commit(commit) is None

    variant = RadarEngine(
        extra_signals=[MemorySafetyDiffSignal()],
        qualifying_signal_names={MemorySafetyDiffSignal.name},
    )
    finding = variant.evaluate_commit(commit)
    assert finding is not None
    assert "memory_safety_diff" in {r.name for r in finding.fired_signals()}

    python_diff = raw_diff.replace("src/copy.c", "docs/example.py").replace("if (n <= capacity) return;", "if (n <= capacity): return")
    python_commit = Commit("b" * 40, "small cleanup", "tester", "2026-01-01", python_diff)
    assert variant.evaluate_commit(python_commit) is None


def test_configured_weights_and_thresholds_are_reflected_in_evidence(sample_repo: Path):
    repo = GitRepository(sample_repo)
    baseline = next(f for f in RadarEngine().scan(repo, limit=20) if f.commit.subject == "small cleanup")
    configured = RadarEngine(
        weight_overrides={"vague_message_defensive_diff": 0.0},
        high_threshold=2.0,
        medium_threshold=1.0,
    )
    finding = next(f for f in configured.scan(repo, limit=20) if f.commit.subject == "small cleanup")

    assert finding.score < baseline.score
    assert finding.confidence == "high"
    vague = next(r for r in finding.signal_results if r.name == "vague_message_defensive_diff")
    assert vague.fired is True
    assert vague.weight == 0.0
    payload = finding.to_dict()
    assert payload["commit"]["sha"] == finding.commit.sha
    assert any(signal["name"] == "vague_message_defensive_diff" for signal in payload["signals"])
