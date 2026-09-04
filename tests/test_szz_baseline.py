"""Real, git-backed test of ClassicSZZ against the SAME repository used
in test_provenance_integration.py (tests/conftest.py's `history_repo`) --
specifically to check the exact claim this project's docs have repeated
without direct proof until now: that classic SZZ is fooled by a purely
cosmetic rename, while Augur's structural provenance finder is not."""
from __future__ import annotations

import pytest

from augur.provenance.szz_baseline import ClassicSZZ
from augur.radar.repository import GitRepository
from conftest import GIT_MISSING


@pytest.mark.skipif(GIT_MISSING, reason="git not available")
def test_classic_szz_is_fooled_by_the_cosmetic_rename_commit(history_repo):
    """The real introduction is commit B. Commit D only renamed a local
    variable inside the same function -- no semantic change. Because the
    memcpy line's exact text changed at D (the renamed variable appears
    in it), `git blame` on that line as of D's parent reports D itself as
    the line's most recent author, not B. This is the textbook SZZ
    failure mode this project's docs have described -- reproduced here
    against a real git history, not asserted from theory."""
    repo_path, sha_b, sha_d, sha_e = history_repo
    repo = GitRepository(repo_path)

    result = ClassicSZZ().find_introducing_commit(repo, filename="crash.c", fix_commit=sha_e)

    assert result.found
    assert result.introducing_commit == sha_d, (
        f"expected classic SZZ to be fooled by the rename and report D ({sha_d[:10]}), "
        f"got {result.introducing_commit[:10] if result.introducing_commit else None} instead -- "
        f"if this now correctly finds B, the fixture or the algorithm changed and the docs "
        f"repeating the classic SZZ weakness claim need re-checking, not this assertion."
    )
    assert result.introducing_commit != sha_b


@pytest.mark.skipif(GIT_MISSING, reason="git not available")
def test_returns_not_found_for_a_pure_addition(history_repo):
    """Commit B is itself a pure file addition (crash.c didn't exist
    before) -- SZZ has no prior revision to blame, and must say so
    honestly rather than guessing at the commit before it."""
    repo_path, sha_b, sha_d, sha_e = history_repo
    repo = GitRepository(repo_path)

    result = ClassicSZZ().find_introducing_commit(repo, filename="crash.c", fix_commit=sha_b)

    assert result.found is False
    assert "nothing to blame" in result.reason
