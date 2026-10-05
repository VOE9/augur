"""Wraps the local `git` binary so the rest of Augur never shells out
directly. Works against any local clone -- no GitHub API, no token,
no rate limit, no dependency on a repo being hosted on GitHub at all."""
from __future__ import annotations

import functools
import subprocess
import tempfile
from pathlib import Path

from .commit import Commit

_LOG_FIELD_SEP = "\x1f"  # unit separator: won't collide with real commit text
_LOG_RECORD_SEP = "\x1e"  # record separator


class GitCommandError(RuntimeError):
    pass


@functools.lru_cache(maxsize=1)
def _git_version() -> tuple[int, int] | None:
    """(major, minor) of the local git, or None if it cannot be determined.

    Module-level and cached, rather than a cached method: `lru_cache` on a
    method keys on `self`, which both pins every GitRepository instance in
    memory for the cache's lifetime and behaves differently per call site.
    """
    try:
        result = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    parts = result.stdout.split()
    # "git version 2.53.0" -> ['git', 'version', '2.53.0']. The product
    # name is parts[0] and the version string is parts[2]; indexing these
    # off by two makes the check fail for every git build, which silently
    # sends every caller down the fallback path.
    if len(parts) < 3 or parts[0] != "git" or parts[1] != "version":
        return None
    token = parts[2].lstrip("v").split(".")
    try:
        return int(token[0]), int(token[1])
    except (ValueError, IndexError):
        return None


# `git log -p` prints NO diff at all for a merge commit. Without an
# explicit instruction, a silent fix that landed on a branch and was
# integrated with a merge commit is therefore carried by a commit whose
# diff is empty, which cannot match any diff-shaped signal. Verified on a
# real repository: the merge's whole fix is simply absent from
# `git log -p` output.
#
# `--diff-merges=first-parent` (git 2.31+, March 2021) diffs a merge
# against its first parent while leaving traversal alone, so side-branch
# commits are still listed. It is the right answer and it is one flag.
#
# There is no equivalent single flag before 2.31. `-m` is the tempting
# substitute and it is wrong in two distinct ways:
#
#   * it emits one record per parent, so a single merge becomes several
#     commits;
#   * it SUPPRESSES an empty parent diff. With `-s ours` the first-parent
#     diff is empty, so git prints only the second-parent diff and the
#     "first record wins" rule silently selects the wrong parent -- the
#     merge then appears to introduce changes it actually discarded.
#
# So on the legacy path the merge diffs are filled in explicitly below
# instead of being approximated. The cost is one `git diff` per merge
# commit, and merges are a minority of any history.
def _supports_diff_merges_flag() -> bool:
    version = _git_version()
    return version is not None and version >= (2, 31)


def _log_diff_merge_args() -> tuple[str, ...]:
    return ("--diff-merges=first-parent",) if _supports_diff_merges_flag() else ()


class GitRepository:
    def __init__(self, path: Path):
        self.path = Path(path)
        if not self.path.is_dir():
            raise ValueError(f"{self.path} is not a git repository (directory does not exist)")
        try:
            inside = self._run("rev-parse", "--is-inside-work-tree").strip()
        except (OSError, GitCommandError) as exc:
            raise ValueError(f"{self.path} is not a git working tree: {exc}") from exc
        if inside != "true":
            raise ValueError(f"{self.path} is not a git working tree")

    def _run(self, *args: str) -> str:
        result = subprocess.run(
            ["git", "-c", "core.quotepath=false", "-C", str(self.path), *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if result.returncode != 0:
            raise GitCommandError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
        return result.stdout

    def recent_commits(self, limit: int = 200) -> list[Commit]:
        """Returns the last `limit` commits reachable from HEAD, each with its
        own full diff already attached -- one `git log` call, not one
        `git show` per commit.

        git's output is CONSUMED AS A STREAM rather than captured whole.
        `git log -1000 -p` on curl produces on the order of a hundred
        megabytes of diff text; capturing that into one string and then
        running `str.split` over it holds the raw bytes and the split
        result in memory at once, and a scan of a large real repository
        does not come back. Records are delimited by a PREFIX separator in
        the format string, which means each one starts its own line, so a
        record boundary is detectable line by line and the peak working
        set stays proportional to the largest single commit rather than to
        the whole window.

        The separator is a prefix, not a suffix, for the reason given on
        `_LOG_RECORD_SEP` below."""
        fmt = f"{_LOG_RECORD_SEP}%H{_LOG_FIELD_SEP}%an{_LOG_FIELD_SEP}%ad{_LOG_FIELD_SEP}%P{_LOG_FIELD_SEP}%B"
        args = [
            "git", "-c", "core.quotepath=false", "-C", str(self.path), "log", f"-{limit}",
            f"--pretty=format:{fmt}", "--date=short", "-p", "--no-color",
            *_log_diff_merge_args(),
        ]
        commits: list[Commit] = []
        by_sha: dict[str, Commit] = {}
        buffer: list[str] = []

        def flush(lines: list[str]) -> None:
            record = "".join(lines)
            if not record.strip():
                return
            commit = self._parse_record(record)
            if commit is None or commit.sha in by_sha:
                return
            by_sha[commit.sha] = commit
            commits.append(commit)

        # stderr goes to a file, not a pipe: it is only read after stdout is
        # drained, and a pipe nobody reads blocks git once its buffer fills,
        # which would leave this loop waiting on stdout forever.
        with tempfile.TemporaryFile() as stderr_file:
            try:
                process = subprocess.Popen(
                    args, stdout=subprocess.PIPE, stderr=stderr_file,
                    text=True, encoding="utf-8", errors="replace", bufsize=1,
                )
            except OSError as exc:
                raise GitCommandError(f"could not run git log: {exc}") from exc

            assert process.stdout is not None
            try:
                for line in process.stdout:
                    if line.startswith(_LOG_RECORD_SEP):
                        flush(buffer)
                        buffer = [line[len(_LOG_RECORD_SEP):]]
                    else:
                        buffer.append(line)
                flush(buffer)
            except BaseException:
                process.kill()
                raise
            finally:
                process.stdout.close()
                process.wait()
            stderr_file.seek(0)
            stderr = stderr_file.read().decode("utf-8", errors="replace")
        if process.returncode != 0:
            raise GitCommandError(f"git log failed: {stderr.strip()}")
        return commits

    def _parse_record(self, record: str) -> Commit | None:
        """One `git log -p` record -> one Commit, or None if malformed.

        %B (the full commit body) can itself contain newlines, so it is not
        safe to split "header" from "diff" on the first '\\n' -- that would
        truncate any multi-line commit message. Split on the field
        separators instead (the message is never split further), then find
        where the message ends and the diff begins by locating the literal
        "diff --git " marker git always emits before a file's diff."""
        parts = record.split(_LOG_FIELD_SEP, 4)
        if len(parts) < 5:
            return None
        sha, author, date, parents, message_and_diff = parts
        marker = message_and_diff.find("\ndiff --git ")
        if marker == -1:
            message, diff = message_and_diff, ""
        else:
            message, diff = message_and_diff[:marker], message_and_diff[marker + 1:]

        # On the legacy path no merge diff was requested at all, so a merge
        # arrives here with an empty diff. Fill it in from the first parent
        # explicitly -- the same thing `--diff-merges=first-parent`
        # computes, and the same thing an `-m` record would have been
        # expected to mean without its empty-diff suppression.
        parent_list = parents.split()
        if len(parent_list) > 1 and not diff.strip():
            diff = self._run("diff", parent_list[0], sha, "--no-color")

        return Commit(sha=sha, message=message.strip("\n"), author=author, date=date, raw_diff=diff)

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
        return [sha for sha, _ in reversed(self.file_history_with_paths_before(filename, before_commit))]

    def file_history_with_paths_before(self, filename: str, before_commit: str) -> list[tuple[str, str]]:
        """Newest-first (commit, path at that commit), following renames.

        --follow must walk backwards; --reverse changes its rename tracking.
        Keep name-status records to read each older revision by its actual path.
        NUL-separated paths support whitespace and Git-quoted filenames.
        """
        parent = self.parent_of(before_commit)
        if parent is None:
            return []
        raw = self._run("log", "--follow", "--format=%x1e%H", "--name-status", "-z", "-M", parent, "--", filename)
        history = []
        current_path = filename
        for record in raw.split("\x1e"):
            if not record:
                continue
            fields = record.split("\0")
            sha = fields[0].strip()
            history.append((sha, current_path))
            index = 1
            while index < len(fields):
                status = fields[index].strip()
                index += 1
                if not status:
                    continue
                if status.startswith(("R", "C")) and index + 1 < len(fields):
                    old_path, new_path = fields[index:index + 2]
                    if status.startswith("R") and new_path == current_path:
                        current_path = old_path
                    index += 2
                else:
                    index += 1
        return history

    def is_ancestor(self, ancestor_sha: str, descendant_sha: str) -> bool:
        result = subprocess.run(
            ["git", "-C", str(self.path), "merge-base", "--is-ancestor", ancestor_sha, descendant_sha],
            capture_output=True,
        )
        return result.returncode == 0

    def removed_line_ranges(self, commit_sha: str, filename: str) -> list[tuple[int, int]]:
        """(start, end) inclusive line ranges, in the PARENT revision's
        numbering, that `commit_sha` removed or changed in `filename` --
        the input classic SZZ blames to find a bug-introducing commit.
        A pure addition (no old-side lines at all) contributes no range,
        since there's nothing to blame; SZZ has no answer for that case,
        by design, not as a bug in this method."""
        parent = self.parent_of(commit_sha)
        if parent is None:
            return []
        try:
            raw = self._run("diff", "--unified=0", parent, commit_sha, "--", filename)
        except GitCommandError:
            return []
        ranges: list[tuple[int, int]] = []
        for line in raw.splitlines():
            if not line.startswith("@@"):
                continue
            # "@@ -start[,count] +start2[,count2] @@..." -- only the
            # old side (-start,count) matters for finding what was there
            # before the fix.
            old_part = line.split(" ")[1]  # "-start,count" or "-start"
            old_part = old_part.lstrip("-")
            if "," in old_part:
                start_s, count_s = old_part.split(",", 1)
                start, count = int(start_s), int(count_s)
            else:
                start, count = int(old_part), 1
            if count == 0:
                continue  # pure addition at this hunk -- nothing removed to blame
            ranges.append((start, start + count - 1))
        return ranges

    def blame_range(self, ref: str, filename: str, start: int, end: int) -> list[tuple[str, str]]:
        """(commit_sha, author-date) for every line in [start, end] as of
        `ref`. One `git blame` per range instead of one per line: blame's
        cost is dominated by walking history, which is shared across the
        whole range, so asking for 200 lines at once is ~85x cheaper than
        asking for them one at a time (measured on a real clone of curl:
        1.8s vs ~157s). Returns [] if the file or range doesn't exist at
        that ref."""
        try:
            raw = self._run("blame", "--porcelain", "-L", f"{start},{end}", ref, "--", filename)
        except GitCommandError:
            return []

        results: list[tuple[str, str]] = []
        pending_sha: str | None = None
        author_time = "0"
        for line in raw.splitlines():
            if line.startswith("\t"):
                # the content line closes the current entry
                if pending_sha is not None:
                    results.append((pending_sha, author_time))
                    pending_sha = None
                continue
            parts = line.split(" ")
            # a header line starts with a 40-char sha; other keys are words
            if pending_sha is None and len(parts[0]) == 40 and all(
                c in "0123456789abcdef" for c in parts[0]
            ):
                pending_sha = parts[0]
                author_time = "0"
            elif line.startswith("author-time "):
                author_time = line.split(" ", 1)[1].strip()
        return results

    def blame_line(self, ref: str, filename: str, line: int) -> tuple[str, str] | None:
        """(commit_sha, author-date) that last touched `filename`'s given
        line number as of `ref`, or None if the line/file doesn't exist
        there (e.g. the file was shorter at that point in history)."""
        try:
            raw = self._run("blame", "--porcelain", "-L", f"{line},{line}", ref, "--", filename)
        except GitCommandError:
            return None
        lines = raw.splitlines()
        if not lines:
            return None
        sha = lines[0].split(" ")[0]
        author_time = None
        for l in lines[1:]:
            if l.startswith("author-time "):
                author_time = l.split(" ", 1)[1].strip()
                break
        return (sha, author_time or "0")

    def tags_containing(self, commit_sha: str) -> set[str]:
        """Every tag whose commit has `commit_sha` as an ancestor (or is
        it). One `git tag --contains` instead of one `merge-base
        --is-ancestor` per tag -- on a repo with a few hundred tags that
        is the difference between one git invocation and several hundred."""
        try:
            raw = self._run("tag", "--contains", commit_sha)
        except GitCommandError:
            return set()
        return {line.strip() for line in raw.splitlines() if line.strip()}

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
