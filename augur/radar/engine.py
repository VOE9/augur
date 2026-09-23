"""RadarEngine: runs the signal strategies against every recent commit in
a local repository and returns the ones that qualify as possible silent
fixes, ranked by score.

Thresholds and the qualifying-signal set are unchanged from
silent-patch-finder, where they were picked by hand against the signal
weights and sanity-checked against a real repository scan. Treat "high"
as "read this one first," never as "this is a vulnerability.\""""
from __future__ import annotations

from .commit import Commit
from .finding import Finding
from .repository import GitRepository
from .signal import (
    NON_FIX_CONVENTIONAL_TYPES,
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
    ):
        self._diff_shape_signal = DefensiveDiffShapeSignal()
        self._vague_message_signal = VagueMessageSignal()
        self._other_signals: list[Signal] = [SensitivePathSignal(), SmallFocusedDiffSignal()]
        self._other_signals.extend(extra_signals or [])
        self._qualifying_signal_names = set(self.QUALIFYING_SIGNAL_NAMES)
        if qualifying_signal_names:
            self._qualifying_signal_names.update(qualifying_signal_names)

    def _confidence(self, score: float) -> str:
        if score >= self.HIGH_THRESHOLD:
            return "high"
        if score >= self.MEDIUM_THRESHOLD:
            return "medium"
        return "low"

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

        if not any(r.fired and r.name in self._qualifying_signal_names for r in results):
            return None

        score = sum(r.weight for r in results if r.fired)
        return Finding(commit=commit, signal_results=results, score=score, confidence=self._confidence(score))

    def scan(self, repo: GitRepository, limit: int = 200) -> list[Finding]:
        commits = repo.recent_commits(limit)
        findings = [f for c in commits if (f := self.evaluate_commit(c)) is not None]
        findings.sort(key=lambda f: f.score, reverse=True)
        return findings
