"""Maps a commit range (introduction .. fix) to the actual released
version tags it falls within, using real ancestry queries instead of
trusting a hand-written advisory's version range -- see METHODOLOGY.md
for a real case (Log4Shell) where NVD's own published range was
malformed."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..radar.repository import GitRepository


@dataclass
class VersionRangeResult:
    introduction_commit: str
    fix_commit: str
    vulnerable_tags: list[str] = field(default_factory=list)
    first_fixed_tag: str | None = None


class VersionRangeMapper:
    def map_to_tags(self, repo: GitRepository, introduction_commit: str, fix_commit: str) -> VersionRangeResult:
        """A tag is vulnerable if its commit is a descendant of (or equal
        to) `introduction_commit` but NOT a descendant of `fix_commit` --
        i.e. it contains the vulnerable code but not yet the fix."""
        all_tags = repo.tags_sorted_by_date()
        vulnerable_tags: list[str] = []
        first_fixed: str | None = None

        for tag_name, tag_sha in all_tags:
            has_intro = tag_sha == introduction_commit or repo.is_ancestor(introduction_commit, tag_sha)
            has_fix = tag_sha == fix_commit or repo.is_ancestor(fix_commit, tag_sha)
            if has_intro and not has_fix:
                vulnerable_tags.append(tag_name)
            elif has_fix and first_fixed is None:
                first_fixed = tag_name

        return VersionRangeResult(
            introduction_commit=introduction_commit,
            fix_commit=fix_commit,
            vulnerable_tags=vulnerable_tags,
            first_fixed_tag=first_fixed,
        )
