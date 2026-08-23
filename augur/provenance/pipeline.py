"""Orchestrates introduction-finding and version-mapping into one call."""
from __future__ import annotations

from dataclasses import dataclass

from ..radar.repository import GitRepository
from .introduction_finder import IntroductionResult, VulnerabilityIntroductionFinder
from .version_mapper import VersionRangeMapper, VersionRangeResult


@dataclass
class ProvenanceResult:
    introduction: IntroductionResult
    version_range: VersionRangeResult | None = None


class ProvenancePipeline:
    def __init__(
        self,
        introduction_finder: VulnerabilityIntroductionFinder | None = None,
        version_mapper: VersionRangeMapper | None = None,
    ):
        self.introduction_finder = introduction_finder or VulnerabilityIntroductionFinder()
        self.version_mapper = version_mapper or VersionRangeMapper()

    def analyze(
        self,
        repo: GitRepository,
        filename: str,
        function_name: str,
        fix_commit: str,
        tainted_param: str,
    ) -> ProvenanceResult:
        introduction = self.introduction_finder.find_introduction_commit(
            repo, filename, function_name, fix_commit, tainted_param,
        )
        if not introduction.found:
            return ProvenanceResult(introduction=introduction, version_range=None)

        version_range = self.version_mapper.map_to_tags(repo, introduction.introduction_commit, fix_commit)
        return ProvenanceResult(introduction=introduction, version_range=version_range)
