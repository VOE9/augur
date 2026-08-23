"""Wraps the local `git` binary so the rest of Augur never shells out
directly. Works against any local clone -- no GitHub API, no token,
no rate limit, no dependency on a repo being hosted on GitHub at all."""
from __future__ import annotations

import subprocess
from pathlib import Path

from .commit import Commit

_LOG_FIELD_SEP = "\x1f"  # unit separator: won't collide with real commit text
_LOG_RECORD_SEP = "\x1e"  # record separator


class GitCommandError(RuntimeError):
    pass


class GitRepository:
    def __init__(self, path: Path):
        self.path = Path(path)
        if not (self.path / ".git").is_dir():
            raise ValueError(f"{self.path} is not a git repository (no .git directory)")

    def _run(self, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.path), *args],
            capture_output=True, text=True, errors="replace",
        )
        if result.returncode != 0:
            raise GitCommandError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
        return result.stdout

    def recent_commits(self, limit: int = 200) -> list[Commit]:
        """Returns the last `limit` commits reachable from HEAD, each with
        its own full diff already attached -- one `git log` call, not one
        `git show` per commit, so scanning a few hundred commits stays fast.

        The record separator is a PREFIX on the format string, not a
        suffix: with `-p`, git appends each commit's diff AFTER its
        pretty-printed header and BEFORE the next commit's header, so a
        trailing separator would land between one commit's own header and
        its own diff, not between commits -- splitting on it would pair
        each diff with the following commit's header instead of its own."""
        fmt = f"{_LOG_RECORD_SEP}%H{_LOG_FIELD_SEP}%an{_LOG_FIELD_SEP}%ad{_LOG_FIELD_SEP}%B"
        raw = self._run(
            "log", f"-{limit}", f"--pretty=format:{fmt}", "--date=short", "-p", "--no-color",
        )
        commits = []
        for record in raw.split(_LOG_RECORD_SEP):
            if not record.strip():
                continue
            # %B (full commit body) can itself contain newlines, so it's
            # not safe to split "header" from "diff" on the first '\n' --
            # that would truncate any multi-line commit message. Split on
            # the three field separators instead (message is never split
            # further), then find where the message ends and the diff
            # begins by locating the literal "diff --git " marker git
            # always emits before a file's diff.
            parts = record.split(_LOG_FIELD_SEP, 3)
            if len(parts) < 4:
                continue
            sha, author, date, message_and_diff = parts
            marker = message_and_diff.find("\ndiff --git ")
            if marker == -1:
                message, diff = message_and_diff, ""
            else:
                message, diff = message_and_diff[:marker], message_and_diff[marker + 1:]
            commits.append(Commit(sha=sha, message=message.strip("\n"), author=author, date=date, raw_diff=diff))
        return commits

    def show_file_at(self, ref: str, filename: str) -> str | None:
        """Full file content at a given ref, or None if the file didn't
        exist at that ref (e.g. it was added by the commit in question)."""
        try:
            return self._run("show", f"{ref}:{filename}")
        except GitCommandError:
            return None

    def parent_of(self, commit_sha: str) -> str | None:
        """The first parent's SHA, or None for a root commit (no parent)."""
        try:
            return self._run("rev-parse", f"{commit_sha}^").strip()
        except GitCommandError:
            return None

    def file_history_before(self, filename: str, before_commit: str) -> list[str]:
        """SHAs of every commit that touched `filename`, reachable from
        `before_commit`'s parent, oldest first -- i.e. the file's history
        strictly *before* the commit being investigated (typically a fix),
        so the caller can walk backward from a known-vulnerable state
        without the fix itself in the list. `--follow` tracks the file
        across renames."""
        parent = self.parent_of(before_commit)
        if parent is None:
            return []
        raw = self._run("log", "--format=%H", "--follow", "--reverse", parent, "--", filename)
        return [line for line in raw.splitlines() if line.strip()]

    def is_ancestor(self, ancestor_sha: str, descendant_sha: str) -> bool:
        result = subprocess.run(
            ["git", "-C", str(self.path), "merge-base", "--is-ancestor", ancestor_sha, descendant_sha],
            capture_output=True,
        )
        return result.returncode == 0

    def tags_sorted_by_date(self) -> list[tuple[str, str]]:
        """(tag_name, commit_sha) pairs, oldest first. An annotated tag's
        `%(objectname)` is the tag OBJECT's own SHA, not the commit it
        points to -- `%(*objectname)` (the "peeled" ref) resolves that,
        and is only non-empty for annotated tags, so lightweight tags
        fall back to `%(objectname)` correctly."""
        raw = self._run(
            "for-each-ref", "--sort=committerdate",
            "--format=%(refname:short)" + _LOG_FIELD_SEP + "%(objectname)" + _LOG_FIELD_SEP + "%(*objectname)",
            "refs/tags",
        )
        pairs = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            parts = line.split(_LOG_FIELD_SEP)
            name, direct_sha = parts[0], parts[1]
            peeled_sha = parts[2] if len(parts) > 2 else ""
            pairs.append((name, peeled_sha or direct_sha))
        return pairs
