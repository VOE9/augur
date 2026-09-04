"""Shared fixtures. `history_repo` builds a REAL git repository (not a
mock) with fully controlled, known-ground-truth history, used by both
the provenance integration tests and the SZZ-baseline comparison tests:

  A (v1.0.0) -- function doesn't exist yet
  B          -- TRUE introduction: adds getCrashAddress with the
                vulnerable memcpy(addr, pc, 20) pattern
  C (v1.1.0) -- unrelated: touches a different file entirely
  D (v1.2.0) -- cosmetic: renames an unrelated local variable inside
                the SAME function, pattern signature unchanged -- the
                real test of "structural, not textual" matching
  E          -- TRUE fix: bounds the copy
  F (v2.0.0) -- unrelated, after the fix
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

GIT_MISSING = subprocess.run(["which", "git"], capture_output=True).returncode != 0

VULNERABLE_SOURCE = '''#include <string.h>
#include <stdlib.h>

static void *
getCrashAddress(const char *report, int index) {
  char addr[20];
  char index_str[6];

  memset(index_str, 0, 6);
  snprintf(index_str, 6, "#%d ", index);
  char *pc = strstr(report, index_str);
  if (pc == NULL) return NULL;
  pc += strlen(index_str);

  memset(addr, 0, 20);
  memcpy(addr, pc, 20);

  char *end = strchr(addr, ' ');
  if (end != NULL) { end[0] = '\\0'; } else { return NULL; }

  return (void *)strtoul(addr, NULL, 16);
}
'''

# Same vulnerable pattern, but with the local var `pc` renamed to `cursor`
# throughout -- a cosmetic change that must NOT look like a different
# vulnerability to the structural detector, since dest_buffer/dest_size/
# copy_length are unchanged and the taint chain is equivalent.
COSMETIC_VARIANT_SOURCE = VULNERABLE_SOURCE.replace("pc", "cursor")

FIXED_SOURCE = '''#include <string.h>
#include <stdlib.h>

static void *
getCrashAddress(const char *report, int index) {
  char addr[20];
  char index_str[6];

  memset(index_str, 0, 6);
  snprintf(index_str, 6, "#%d ", index);
  char *pc = strstr(report, index_str);
  if (pc == NULL) return NULL;
  pc += strlen(index_str);

  memset(addr, 0, 20);
  size_t pc_len = strlen(pc);
  size_t copy_len = pc_len < 19 ? pc_len : 19;
  memcpy(addr, pc, copy_len);

  char *end = strchr(addr, ' ');
  if (end != NULL) { end[0] = '\\0'; } else { return NULL; }

  return (void *)strtoul(addr, NULL, 16);
}
'''


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def history_repo(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")

    (repo / "README.md").write_text("placeholder\n")
    _commit(repo, "A: initial commit, no crash.c yet")
    _git(repo, "tag", "v1.0.0")

    (repo / "crash.c").write_text(VULNERABLE_SOURCE)
    sha_b = _commit(repo, "B: add getCrashAddress")

    (repo / "unrelated.txt").write_text("some other file\n")
    _commit(repo, "C: unrelated change")
    _git(repo, "tag", "v1.1.0")

    (repo / "crash.c").write_text(COSMETIC_VARIANT_SOURCE)
    sha_d = _commit(repo, "D: rename local variable (cosmetic, no semantic change)")
    _git(repo, "tag", "v1.2.0")

    (repo / "crash.c").write_text(FIXED_SOURCE.replace("pc", "cursor"))
    sha_e = _commit(repo, "E: bound the copy to the real string length")

    (repo / "unrelated.txt").write_text("changed after the fix\n")
    _commit(repo, "F: unrelated change after fix")
    _git(repo, "tag", "v2.0.0")

    return repo, sha_b, sha_d, sha_e
