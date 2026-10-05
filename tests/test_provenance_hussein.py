"""Known-history regression: removing a real guard introduces the pattern."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from augur.provenance.pipeline import ProvenancePipeline
from augur.radar.repository import GitRepository

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git unavailable")


def test_introduction_and_tags_exclude_the_guarded_revision(tmp_path: Path):
    repo = tmp_path / "guard-history"
    repo.mkdir()
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

    def git(*args):
        return subprocess.run(
            ["git", "-C", str(repo), *args], check=True,
            capture_output=True, text=True, env=env,
        ).stdout.strip()

    git("init", "-q")
    git("config", "user.name", "Hussein review fixture")
    git("config", "user.email", "review@example.invalid")
    git("config", "commit.gpgsign", "false")
    safe = (
        "#include <string.h>\nvoid f(const char *src) {\n"
        "char buf[8];\nif (strlen(src) < 8) return;\nmemcpy(buf, src, 8);\n}\n"
    )
    file = repo / "copy.c"
    file.write_text(safe, encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "A: protected implementation")
    git("tag", "v1-safe")
    file.write_text(safe.replace("if (strlen(src) < 8) return;\n", ""), encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "B: remove the bound")
    introduced = git("rev-parse", "HEAD")
    git("tag", "v2-vulnerable")
    file.write_text(safe, encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "C: restore the bound")
    fixed = git("rev-parse", "HEAD")
    git("tag", "v3-fixed")

    result = ProvenancePipeline().analyze(GitRepository(repo), "copy.c", "f", fixed, "src")
    assert result.introduction.found
    assert result.introduction.introduction_commit == introduced
    assert result.version_range.vulnerable_tags == ["v2-vulnerable"]
    assert result.version_range.first_fixed_tag == "v3-fixed"
