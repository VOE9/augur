"""Orchestrates extraction -> pattern detection -> harness generation ->
compilation -> execution into one call, and turns the raw results into
one of a small set of honest verdicts. Every verdict other than
CONFIRMED_REGRESSION_FIX is a request for a human to look, not a claim."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..pattern.format_string_prefix import FormatStringPrefixDeriver
from ..pattern.function_extractor import ExtractedFunction, FunctionExtractor
from ..pattern.unbounded_copy import UnboundedCopyDetector
from .generator import DifferentialHarnessGenerator, UnsupportedSignatureError
from .sanitizer_runner import RunResult, SanitizerRunner


class Verdict:
    CONFIRMED_REGRESSION_FIX = "confirmed_regression_fix"
    NO_DIFFERENCE_FOUND = "no_difference_found"
    INCONCLUSIVE = "inconclusive"
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

        filler_needed = max(0, _AUTO_SEED_TOTAL_LENGTH - len(prefix.literal_bytes))
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

        old_results = self.runner.sweep(binary_path, "old", len(seed))
        new_results = self.runner.sweep(binary_path, "new", len(seed))

        old_crash = next((r for r in old_results if r.crashed), None)
        if old_crash is None:
            return PipelineResult(
                Verdict.NO_DIFFERENCE_FOUND,
                f"old implementation never crashed across truncation lengths 0..{len(seed)} of the given seed",
                function_name, old_results, new_results, source,
            )

        new_crash_same_length = next((r for r in new_results if r.length == old_crash.length and r.crashed), None)
        if new_crash_same_length is not None:
            return PipelineResult(
                Verdict.INCONCLUSIVE,
                f"new implementation ALSO crashed at length {old_crash.length} -- fix may be incomplete, or harness may be wrong",
                function_name, old_results, new_results, source,
            )

        return PipelineResult(
            Verdict.CONFIRMED_REGRESSION_FIX,
            f"old crashes at truncation length {old_crash.length} ({old_crash.asan_summary}); "
            f"new runs cleanly at the same length",
            function_name, old_results, new_results, source,
        )
