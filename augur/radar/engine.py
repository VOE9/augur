"""RadarEngine: runs the signal strategies against every recent commit in
a local repository and returns the ones that qualify as possible silent
fixes, ranked by score.

Thresholds and the qualifying-signal set are unchanged from
silent-patch-finder, where they were picked by hand against the signal
weights and sanity-checked against a real repository scan. Treat "high"
as "read this one first," never as "this is a vulnerability.\""""
from __future__ import annotations

import math

from .commit import Commit
from .finding import Finding
from .repository import GitRepository
from .signal import (
    NON_FIX_CONVENTIONAL_TYPES,
    STRONG_SENSITIVE_PATH_KEYWORDS,
    WEAK_SENSITIVE_PATH_KEYWORDS,
    DefensiveDiffShapeSignal,
    SensitivePathSignal,
    Signal,
    SmallFocusedDiffSignal,
    VagueMessageSignal,
    is_loudly_disclosed,
)


class RadarEngine:
    HIGH_THRESHOLD = 4.5
    MEDIUM_THRESHOLD = 2.5

    # A commit needs at least one of these fired to be shown at all.
    # no_associated_pr doesn't exist in Augur (no GitHub API dependency by
    # design); small_focused_diff is deliberately excluded here too, for
    # the same reason silent-patch-finder excludes it: alone it would fire
    # on nearly every small commit in a repo where the maintainer commits
    # directly and often, flooding the report with noise about nothing.
    QUALIFYING_SIGNAL_NAMES = {"sensitive_path", "defensive_diff_shape"}

    def __init__(
        self,
        extra_signals: list[Signal] | None = None,
        qualifying_signal_names: set[str] | None = None,
        weight_overrides: dict[str, float] | None = None,
        high_threshold: float | None = None,
        medium_threshold: float | None = None,
    ):
        self._diff_shape_signal = DefensiveDiffShapeSignal()
        self._vague_message_signal = VagueMessageSignal()
        self._path_signal = SensitivePathSignal()
        self._other_signals: list[Signal] = [self._path_signal, SmallFocusedDiffSignal()]
        self._other_signals.extend(extra_signals or [])
        self._qualifying_signal_names = set(self.QUALIFYING_SIGNAL_NAMES)
        if qualifying_signal_names:
            self._qualifying_signal_names.update(qualifying_signal_names)
        self._weight_overrides = dict(weight_overrides or {})
        self.high_threshold = self.HIGH_THRESHOLD if high_threshold is None else high_threshold
        self.medium_threshold = self.MEDIUM_THRESHOLD if medium_threshold is None else medium_threshold
        if not all(math.isfinite(value) for value in [self.high_threshold, self.medium_threshold, *self._weight_overrides.values()]):
            raise ValueError("thresholds and weights must be finite numbers")
        if self.medium_threshold > self.high_threshold:
            raise ValueError("medium_threshold cannot exceed high_threshold")

    @staticmethod
    def path_keyword_frequencies(commits, signal: SensitivePathSignal) -> dict[str, float]:
        """Fraction of commits whose changed paths match each keyword.

        Measured over the window about to be scanned, so a keyword that is
        common in THIS repository is discounted while one that is rare stays
        at full strength. Without it the report degenerates on real projects:
        in openssl `crypto` matches 642 changed paths in a 400-commit window
        because the whole project lives under `crypto/`, and the signal fired
        on 132 of 138 candidates -- 96% of the report, saying nothing.

        Returns an empty map for windows too small to estimate from, so the
        signal behaves exactly as it did before this existed.
        """
        if len(commits) < 50:
            return {}
        keywords = STRONG_SENSITIVE_PATH_KEYWORDS + WEAK_SENSITIVE_PATH_KEYWORDS
        hits = {kw: 0 for kw in keywords}
        for commit in commits:
            lowered = " ".join(f.filename.lower() for f in commit.changed_files)
            for kw in keywords:
                if kw in lowered:
                    hits[kw] += 1
        return {kw: count / len(commits) for kw, count in hits.items() if count}

    def _confidence(self, score: float) -> str:
        if score >= self.high_threshold:
            return "high"
        if score >= self.medium_threshold:
            return "medium"
        return "low"

    def _with_configured_weights(self, results):
        return [
            result.__class__(
                name=result.name,
                weight=self._weight_overrides.get(result.name, result.weight),
                fired=result.fired,
                detail=result.detail,
            )
            for result in results
        ]

    def evaluate_commit(self, commit: Commit) -> Finding | None:
        if is_loudly_disclosed(commit):
            return None
        if commit.conventional_type() in NON_FIX_CONVENTIONAL_TYPES:
            # A commit explicitly typed as a new feature can't be silently
            # fixing a pre-existing issue -- the code it touches didn't
            # exist before. The ported vague_message signal already
            # encoded this reasoning but only exempted itself from firing;
            # sensitive_path/defensive_diff_shape could still qualify the
            # commit on their own, which defeats the same reasoning at the
            # engine level. Excluded here instead, before any signal runs.
            return None

        diff_shape_result = self._diff_shape_signal.evaluate(commit)
        vague_result = self._vague_message_signal.evaluate(commit, diff_shape_result.fired)
        results = [s.evaluate(commit) for s in self._other_signals] + [diff_shape_result, vague_result]
        results = self._with_configured_weights(results)

        if not any(r.fired and r.name in self._qualifying_signal_names for r in results):
            return None

        score = sum(r.weight for r in results if r.fired)
        return Finding(commit=commit, signal_results=results, score=score, confidence=self._confidence(score))

    def scan(self, repo: GitRepository, limit: int = 200,
             discount_common_path_keywords: bool = False) -> list[Finding]:
        """Ranks commits in the window. `discount_common_path_keywords`
        estimates how often each path keyword occurs in this window and
        discounts the ones that match nearly everything, which is what makes
        the report usable on a project whose layout puts most of its files
        under one security-sounding directory. Off by default so the baseline
        stays comparable; `recent_path_keyword_frequencies` reports what it
        would have used."""
        commits = repo.recent_commits(limit)
        if discount_common_path_keywords:
            self._path_signal.keyword_frequencies = self.path_keyword_frequencies(
                commits, self._path_signal
            )
        else:
            self._path_signal.keyword_frequencies = {}
        findings = [f for c in commits if (f := self.evaluate_commit(c)) is not None]
        findings.sort(key=lambda f: f.score, reverse=True)
        return findings

    def recent_path_keyword_frequencies(self, repo: GitRepository, limit: int = 200):
        """The discount factors scan() would apply, without scanning."""
        commits = repo.recent_commits(limit)
        return self.path_keyword_frequencies(commits, self._path_signal)
