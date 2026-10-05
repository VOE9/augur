"""Orchestrates extraction -> pattern detection -> harness generation ->
compilation -> execution into one call, and turns the raw results into
one of a small set of honest verdicts. Every verdict other than
CONFIRMED_REGRESSION_FIX is a request for a human to look, not a claim."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..pattern.format_string_prefix import FormatStringPrefixDeriver
from ..pattern.function_extractor import FunctionExtractor
from ..pattern.unbounded_copy import UnboundedCopyDetector
from .generator import DifferentialHarnessGenerator, UnsupportedSignatureError
from .sanitizer_runner import RunResult, SanitizerRunner


class Verdict:
    # The only verdict that asserts the new version is safe. It requires
    # the new implementation to be clean across the ENTIRE sweep, and
    # every input in that sweep to have actually been evaluated -- a timed
    # out or unexplained run is not evidence of safety -- see _classify().
    CONFIRMED_REGRESSION_FIX = "confirmed_regression_fix"

    # Both versions crashed, and the new one crashed at lengths the old
    # one also crashed at. The fix removed the crash at some lengths but
    # the new code is still unsafe on others.
    PARTIAL_FIX = "partial_fix"

    # The old version never crashed but the new one did: the "fix"
    # introduced a crash the pre-fix code did not have.
    REGRESSION_INTRODUCED_BY_FIX = "regression_introduced_by_fix"

    # At least one input could not be evaluated (timeout, unexplained
    # exit, harness could not start). Nothing can be concluded, in
    # particular nothing can be confirmed.
    INCONCLUSIVE = "inconclusive"

    NO_DIFFERENCE_FOUND = "no_difference_found"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"
    NOT_FOUND = "not_found"
    SEED_DERIVATION_FAILED = "seed_derivation_failed"

# How much filler content to append after a mechanically-derived prefix
# when no human seed is supplied. Long enough that the sweep also covers
# a "normal, full-length input" data point (mirroring the manual
# RTCON verification's own cross-check), short enough to keep the sweep
# (one subprocess per length) fast.
_AUTO_SEED_TOTAL_LENGTH = 60
_AUTO_SEED_FILLER_CHAR = "A"


@dataclass
class PipelineResult:
    verdict: str
    detail: str
    function_name: str
    old_results: list[RunResult] = field(default_factory=list)
    new_results: list[RunResult] = field(default_factory=list)
    generated_source: str | None = None

    @property
    def is_confirmed(self) -> bool:
        return self.verdict == Verdict.CONFIRMED_REGRESSION_FIX

    @property
    def old_crash_lengths(self) -> list[int]:
        return [r.length for r in self.old_results if r.crashed]

    @property
    def new_crash_lengths(self) -> list[int]:
        return [r.length for r in self.new_results if r.crashed]


class HarnessPipeline:
    def __init__(
        self,
        extractor: FunctionExtractor | None = None,
        detector: UnboundedCopyDetector | None = None,
        generator: DifferentialHarnessGenerator | None = None,
        runner: SanitizerRunner | None = None,
    ):
        self.extractor = extractor or FunctionExtractor()
        self.detector = detector or UnboundedCopyDetector()
        self.generator = generator or DifferentialHarnessGenerator()
        self.runner = runner or SanitizerRunner()
        self.prefix_deriver = FormatStringPrefixDeriver()

    def analyze_auto(
        self,
        old_source: str,
        new_source: str,
        function_name: str,
        other_param_defaults: dict[str, str],
        workdir: Path,
    ) -> PipelineResult:
        """Same as analyze(), but derives the seed mechanically from the
        function's own source instead of requiring one from the caller --
        see FormatStringPrefixDeriver. Falls back to an honest
        SEED_DERIVATION_FAILED verdict (never a guessed seed) if the
        function doesn't match the narrow snprintf-then-strstr shape this
        derivation needs."""
        old_fn = self.extractor.find_function(old_source, function_name)
        if old_fn is None or old_fn.signature is None:
            return PipelineResult(Verdict.NOT_FOUND, f"could not locate `{function_name}` in the old source", function_name)

        string_params = [p for p in old_fn.signature.parameters if p.is_string_like()]
        if len(string_params) != 1:
            return PipelineResult(
                Verdict.NEEDS_MANUAL_REVIEW,
                f"expected exactly one string-like parameter, found {len(string_params)}",
                function_name,
            )

        prefix = self.prefix_deriver.derive(old_fn.full_text, string_params[0].name, other_param_defaults)
        if prefix is None:
            return PipelineResult(
                Verdict.SEED_DERIVATION_FAILED,
                "could not mechanically derive a matching prefix from the source "
                "(needs a snprintf(...)-built needle searched via strstr() against the string parameter) "
                "-- supply --seed manually instead",
                function_name,
            )

        filler_needed = max(0, _AUTO_SEED_TOTAL_LENGTH - len(prefix.literal_bytes.encode("utf-8")))
        seed = prefix.literal_bytes + _AUTO_SEED_FILLER_CHAR * filler_needed

        result = self.analyze(old_source, new_source, function_name, seed, other_param_defaults, workdir)
        result.detail = f"[auto-derived prefix {prefix.literal_bytes!r}] {result.detail}"
        return result

    def analyze(
        self,
        old_source: str,
        new_source: str,
        function_name: str,
        seed: str,
        other_param_defaults: dict[str, str],
        workdir: Path,
    ) -> PipelineResult:
        old_fn = self.extractor.find_function(old_source, function_name)
        new_fn = self.extractor.find_function(new_source, function_name)
        if old_fn is None or new_fn is None:
            missing = function_name if old_fn is None else f"{function_name} (new version)"
            return PipelineResult(Verdict.NOT_FOUND, f"could not locate `{missing}` in the given source", function_name)

        if old_fn.signature is None or not old_fn.signature.is_simple():
            return PipelineResult(
                Verdict.NEEDS_MANUAL_REVIEW,
                "signature is not a supported simple shape (needs exactly primitive/char* parameters)",
                function_name,
            )

        string_params = [p for p in old_fn.signature.parameters if p.is_string_like()]
        if len(string_params) != 1:
            return PipelineResult(
                Verdict.NEEDS_MANUAL_REVIEW,
                f"expected exactly one string-like parameter, found {len(string_params)}",
                function_name,
            )

        finding = self.detector.find(old_fn.full_text, tainted_params={string_params[0].name})
        if finding is None:
            return PipelineResult(
                Verdict.NEEDS_MANUAL_REVIEW,
                "no fixed-size memcpy-from-tainted-pointer pattern detected -- outside this tool's narrow scope",
                function_name,
            )

        try:
            source = self.generator.generate(old_fn, new_fn, finding, seed, other_param_defaults)
        except UnsupportedSignatureError as e:
            return PipelineResult(Verdict.NEEDS_MANUAL_REVIEW, str(e), function_name)

        binary_path = workdir / "harness_bin"
        self.runner.compile(source, binary_path)

        seed_length = len(seed.encode("utf-8"))
        old_results = self.runner.sweep(binary_path, "old", seed_length)
        new_results = self.runner.sweep(binary_path, "new", seed_length)

        verdict, detail = self._classify(old_results, new_results, expected_max_length=seed_length)
        return PipelineResult(verdict, detail, function_name, old_results, new_results, source)

    def _classify(self, old_results: list[RunResult], new_results: list[RunResult], expected_max_length: int | None = None) -> tuple[str, str]:
        """Turns two full sweeps into exactly one verdict.

        The decision is made from the COMPLETE crash-length sets of both
        implementations, not from a single representative length. An
        earlier version compared only the length at which the old version
        FIRST crashed, which let a partially-fixed new version pass as
        `confirmed_regression_fix` even while it still crashed at every
        longer length -- see the partial-fix regression test for a real,
        ASan-verified instance of exactly that. `confirmed_regression_fix`
        is the one verdict that asserts the new version is safe, so it is
        gated on the new version being clean at every length tested.

        A run that could not be evaluated is separated out first. A
        timeout, an unexplained non-zero exit, or a harness that failed to
        start all produce a RunResult with crashed=False, and reading
        those as "the new version did not crash" produced a confirmed
        verdict for a version that was never actually shown to survive
        anything. Confirmation is therefore additionally gated on every
        input having been evaluated.
        """
        all_runs = list(old_results) + list(new_results)
        failed = [r for r in all_runs if r.failed]
        if failed:
            return self._classify_with_failures(old_results, new_results, failed)

        old_coverage = sorted(r.length for r in old_results)
        new_coverage = sorted(r.length for r in new_results)
        maximum = expected_max_length if expected_max_length is not None else max(old_coverage, default=-1)
        expected = list(range(maximum + 1))
        if (not expected or old_coverage != expected or new_coverage != expected
                or any(r.which != "old" for r in old_results)
                or any(r.which != "new" for r in new_results)):
            return Verdict.INCONCLUSIVE, "sweep evidence is incomplete, duplicated, or mismatched between implementations"

        old_crashes = [r for r in old_results if r.crashed]
        new_crashes = [r for r in new_results if r.crashed]
        swept = len(old_results)
        old_lengths = sorted(r.length for r in old_crashes)
        new_lengths = sorted(r.length for r in new_crashes)

        if not old_crashes:
            if new_crashes:
                return (
                    Verdict.REGRESSION_INTRODUCED_BY_FIX,
                    f"the new implementation crashed at {len(new_lengths)} of {swept} tested length(s) "
                    f"({_describe_lengths(new_lengths)}) while the old one crashed at none -- "
                    f"the fix introduced a crash the pre-fix code did not have "
                    f"(first at length {new_lengths[0]}: {new_crashes[0].asan_summary})",
                )
            return (
                Verdict.NO_DIFFERENCE_FOUND,
                f"neither implementation crashed across truncation lengths 0..{swept - 1} of the given seed -- "
                f"either the seed never reaches the bug, or there is no bug at this shape",
            )

        if not new_crashes:
            return (
                Verdict.CONFIRMED_REGRESSION_FIX,
                f"the old implementation crashed at {len(old_lengths)} of {swept} tested length(s) "
                f"({_describe_lengths(old_lengths)}) and the new one crashed at none of them; "
                f"first old crash at length {old_lengths[0]} ({old_crashes[0].asan_summary})",
            )

        shared = sorted(set(old_lengths) & set(new_lengths))
        if shared:
            return (
                Verdict.PARTIAL_FIX,
                f"the old implementation crashed at {len(old_lengths)} length(s) and the new one still crashed at "
                f"{len(new_lengths)}, overlapping at {len(shared)} of them ({_describe_lengths(shared)}) -- "
                f"the fix addressed some cases but the new code is still unsafe "
                f"(first shared crash at length {shared[0]}: {_summary_at(new_crashes, shared[0])})",
            )
        return (
            Verdict.PARTIAL_FIX,
            f"the old implementation crashed at {len(old_lengths)} length(s) ({_describe_lengths(old_lengths)}), "
            f"but the new one crashed only at lengths the old one survived ({_describe_lengths(new_lengths)}) -- "
            f"the fix removed the original crash and left a different one behind; "
            f"not a confirmed fix (first new-only crash at length {new_lengths[0]}: {new_crashes[0].asan_summary})",
        )

    def _classify_with_failures(
        self,
        old_results: list[RunResult],
        new_results: list[RunResult],
        failed: list[RunResult],
    ) -> tuple[str, str]:
        """At least one input was not evaluated. Says which, on which side,
        and why, and refuses to conclude anything about the fix."""
        by_side: dict[str, list[RunResult]] = {}
        for r in failed:
            by_side.setdefault(r.which, []).append(r)
        parts = []
        for which in sorted(by_side):
            runs = by_side[which]
            reasons = sorted({r.failure_reason or "unknown" for r in runs})
            parts.append(
                f"{which}: {len(runs)} input(s) at length(s) {_describe_lengths(sorted(r.length for r in runs))} "
                f"({'; '.join(reasons)})"
            )
        return (
            Verdict.INCONCLUSIVE,
            f"{len(failed)} of {len(old_results) + len(new_results)} runs could not be evaluated, "
            f"so nothing can be concluded about the fix -- " + " | ".join(parts),
        )


def _describe_lengths(lengths: list[int]) -> str:
    """Renders a sorted length list as compact ranges, so a 50-entry list
    reads as `3-14, 16-21, 23-53` instead of 50 separate numbers."""
    if not lengths:
        return "none"
    parts: list[str] = []
    start = prev = lengths[0]
    for value in lengths[1:]:
        if value == prev + 1:
            prev = value
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = value
    parts.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(parts)


def _summary_at(results: list[RunResult], length: int) -> str | None:
    for r in results:
        if r.length == length:
            return r.asan_summary
    return None
