"""Finds the commit that first introduced a specific vulnerable code
PATTERN -- not just "the last commit that touched this line," which is
classic SZZ's well-documented weak point (a pure reformatting or
refactoring commit gets blamed instead of the commit that actually
introduced the unsafe logic).

Works by walking a file's history backward from a known-vulnerable
commit (typically the fix's parent) and re-running the SAME structural
pattern detector (UnboundedCopyDetector) against every historical
revision of the target function. As long as the exact same vulnerable
shape (same destination buffer, same copy length, same source
expression) is still detected, the walk continues further back; the
first commit where it stops matching -- pattern changed, function
didn't exist yet, or the file didn't exist yet -- means the previous
commit examined is where this exact vulnerable shape was introduced."""
from __future__ import annotations

from dataclasses import dataclass

from ..pattern.function_extractor import FunctionExtractor
from ..pattern.unbounded_copy import UnboundedCopyDetector, UnboundedCopyFinding
from ..radar.repository import GitRepository


@dataclass
class IntroductionResult:
    found: bool
    reason: str
    introduction_commit: str | None = None
    fix_commit: str | None = None
    commits_examined: int = 0


class VulnerabilityIntroductionFinder:
    def __init__(self, extractor: FunctionExtractor | None = None, detector: UnboundedCopyDetector | None = None):
        self.extractor = extractor or FunctionExtractor()
        self.detector = detector or UnboundedCopyDetector()

    def find_introduction_commit(
        self,
        repo: GitRepository,
        filename: str,
        function_name: str,
        fix_commit: str,
        tainted_param: str,
    ) -> IntroductionResult:
        parent = repo.parent_of(fix_commit)
        if parent is None:
            return IntroductionResult(False, "fix commit has no parent (root commit) -- nothing to walk back from")

        reference = self._detect_at(repo, parent, filename, function_name, tainted_param)
        if reference is None:
            return IntroductionResult(
                False,
                "the vulnerable pattern isn't detected in the commit right before the fix -- "
                "can't establish a signature to search history for",
            )

        history = repo.file_history_before(filename, fix_commit)
        if not history:
            return IntroductionResult(False, "no file history found before the fix commit")

        last_matching = parent
        examined = 0
        for commit_sha in reversed(history):  # newest to oldest
            examined += 1
            finding = self._detect_at(repo, commit_sha, filename, function_name, tainted_param)
            if finding is None or not self._same_signature(finding, reference):
                break
            last_matching = commit_sha

        return IntroductionResult(
            True,
            f"pattern first detected here; matched continuously across {examined} earlier commit(s) examined before it stopped matching or history ran out",
            introduction_commit=last_matching,
            fix_commit=fix_commit,
            commits_examined=examined,
        )

    def _detect_at(self, repo: GitRepository, commit_sha: str, filename: str, function_name: str, tainted_param: str) -> UnboundedCopyFinding | None:
        source = repo.show_file_at(commit_sha, filename)
        if source is None:
            return None
        fn = self.extractor.find_function(source, function_name)
        if fn is None:
            return None
        return self.detector.find(fn.full_text, {tainted_param})

    @staticmethod
    def _same_signature(a: UnboundedCopyFinding, b: UnboundedCopyFinding) -> bool:
        """Deliberately ignores `dest_buffer`/`source_expr` -- those are
        just local variable *names*, and a purely cosmetic rename (caught
        by this project's own integration test) must not look like a
        different vulnerability. `dest_size`/`copy_length` are the
        semantically meaningful, renaming-independent part of the shape."""
        return a.dest_size == b.dest_size and a.copy_length == b.copy_length
