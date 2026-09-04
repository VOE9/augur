"""Classic B-SZZ (Śliwerski, Zimmermann & Zeller, 2005): the textbook
baseline this project's own docs have repeatedly cited as "well
documented to be fooled by pure reformatting/renaming commits" -- built
here directly, not vendored from a third-party implementation, so a
comparison against Augur's structural `provenance` finder rests on a
transparent, auditable algorithm rather than an opaque dependency.

Algorithm: for every line a fix commit removed or changed, `git blame`
the immediately preceding revision to find who last touched that line;
the most recently authored of those blamed commits is the classic
"youngest bug-introducing commit" B-SZZ reports. A fix that only adds
lines (nothing removed) has no answer under this algorithm -- a real,
known SZZ limitation, not a bug in this implementation of it."""
from __future__ import annotations

from dataclasses import dataclass

from ..radar.repository import GitRepository

_MAX_LINES_BLAMED = 200  # a pathologically large hunk isn't worth hundreds of blame calls


@dataclass
class SzzResult:
    found: bool
    reason: str
    introducing_commit: str | None = None
    lines_blamed: int = 0


class ClassicSZZ:
    def find_introducing_commit(self, repo: GitRepository, filename: str, fix_commit: str) -> SzzResult:
        ranges = repo.removed_line_ranges(fix_commit, filename)
        if not ranges:
            return SzzResult(False, "fix commit only added lines in this file -- nothing to blame")

        parent = repo.parent_of(fix_commit)
        if parent is None:
            return SzzResult(False, "fix commit has no parent (root commit)")

        blamed: list[tuple[str, str]] = []
        for start, end in ranges:
            for line in range(start, end + 1):
                if len(blamed) >= _MAX_LINES_BLAMED:
                    break
                result = repo.blame_line(parent, filename, line)
                if result is not None:
                    blamed.append(result)

        if not blamed:
            return SzzResult(False, "none of the removed/changed lines could be blamed at the parent revision")

        # Classic B-SZZ reports the youngest (most recently authored) of
        # the blamed commits as THE bug-introducing commit.
        youngest_sha, _ = max(blamed, key=lambda pair: pair[1])
        return SzzResult(True, f"blamed {len(blamed)} line(s); reporting the most recently authored source commit",
                          introducing_commit=youngest_sha, lines_blamed=len(blamed))
