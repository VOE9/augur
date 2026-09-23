"""The Finding entity: one commit that qualified as a possible silent fix,
together with why."""
from __future__ import annotations

from .commit import Commit
from .signal import SignalResult


class Finding:
    def __init__(self, commit: Commit, signal_results: list[SignalResult], score: float, confidence: str):
        self.commit = commit
        self.signal_results = signal_results
        self.score = score
        self.confidence = confidence

    def fired_signals(self) -> list[SignalResult]:
        return [r for r in self.signal_results if r.fired]

    def to_dict(self) -> dict:
        """Stable machine-readable evidence for evaluation and reproduction."""
        c = self.commit
        return {
            "commit": {
                "sha": c.sha,
                "subject": c.subject,
                "message": c.message,
                "author": c.author,
                "date": c.date,
                "changed_files": [f.filename for f in c.changed_files],
            },
            "score": self.score,
            "confidence": self.confidence,
            "signals": [
                {
                    "name": result.name,
                    "weight": result.weight,
                    "fired": result.fired,
                    "detail": result.detail,
                }
                for result in self.signal_results
            ],
        }

    def to_markdown(self) -> str:
        c = self.commit
        lines = [
            f"### {c.sha[:10]} — {c.subject}",
            f"- Author: {c.author} · Date: {c.date} · Confidence: **{self.confidence}** (score {self.score:.1f})",
            f"- Files: {', '.join(f.filename for f in c.changed_files[:6])}",
            "",
        ]
        for r in self.fired_signals():
            lines.append(f"  - **{r.name}** (+{r.weight}): {r.detail}")
        return "\n".join(lines)
