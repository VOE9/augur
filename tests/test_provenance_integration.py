"""Integration test for the provenance module against a REAL git
repository with a fully controlled, known-ground-truth history -- see
tests/conftest.py's `history_repo` fixture for the exact commit graph.

Ground truth to check: introduction commit == B (not A, C, or D);
vulnerable tags == {v1.1.0, v1.2.0} (not v1.0.0, not v2.0.0);
first_fixed_tag == v2.0.0."""
from __future__ import annotations

import subprocess

import pytest

from augur.provenance.pipeline import ProvenancePipeline
from augur.radar.repository import GitRepository
from conftest import GIT_MISSING


@pytest.mark.skipif(GIT_MISSING, reason="git not available")
def test_finds_the_true_introduction_commit_not_the_cosmetic_one(history_repo):
    repo_path, sha_b, sha_d, sha_e = history_repo
    repo = GitRepository(repo_path)

    result = ProvenancePipeline().analyze(
        repo, filename="crash.c", function_name="getCrashAddress",
        fix_commit=sha_e, tainted_param="report",
    )

    assert result.introduction.found
    assert result.introduction.introduction_commit == sha_b


@pytest.mark.skipif(GIT_MISSING, reason="git not available")
def test_maps_the_correct_vulnerable_tag_range(history_repo):
    repo_path, sha_b, sha_d, sha_e = history_repo
    repo = GitRepository(repo_path)

    result = ProvenancePipeline().analyze(
        repo, filename="crash.c", function_name="getCrashAddress",
        fix_commit=sha_e, tainted_param="report",
    )

    assert set(result.version_range.vulnerable_tags) == {"v1.1.0", "v1.2.0"}
    assert result.version_range.first_fixed_tag == "v2.0.0"
