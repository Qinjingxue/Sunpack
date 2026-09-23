"""Single-file TAR and compression-stream confirmation."""

from dataclasses import dataclass
from typing import Any

from sunpack.analysis import ArchiveAnalyzer
from sunpack.contracts.discovery import DiscoveryCandidate
from sunpack.contracts.rules import RuleDecision
from sunpack.detection.formats import CONFIRMERS


@dataclass(frozen=True)
class DetectionResult:
    candidate: DiscoveryCandidate
    decision: RuleDecision
    format: str = ""


class DetectionScheduler:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.analyzer = ArchiveAnalyzer(config)

    def validate_config(self) -> list[str]:
        return []

    def evaluate_candidate(self, candidate: DiscoveryCandidate) -> DetectionResult:
        return self._confirm(candidate)

    def evaluate_candidates(self, candidates: list[DiscoveryCandidate]) -> list[DetectionResult]:
        return [self._confirm(candidate) for candidate in candidates]

    def evaluate_extractable_candidates(
        self,
        candidates: list[DiscoveryCandidate],
    ) -> list[DetectionResult]:
        return [
            result
            for result in self.evaluate_candidates(candidates)
            if result.decision.should_extract
        ]

    def _confirm(self, candidate: DiscoveryCandidate) -> DetectionResult:
        archive_format = str(candidate.format_hint or "").lower()
        confirmer = CONFIRMERS.get(archive_format)
        if not candidate.entry_path or confirmer is None:
            return DetectionResult(candidate, _not_archive())
        try:
            accepted = confirmer.confirm(candidate.entry_path, self.analyzer)
        except (OSError, ValueError):
            return DetectionResult(candidate, _not_archive())
        if not accepted:
            return DetectionResult(candidate, _not_archive())
        return DetectionResult(
            candidate,
            RuleDecision(
                should_extract=True,
                matched_rules=["single_file_format"],
                stop_reason=f"Confirmed {archive_format} structure",
                decision="archive",
                decision_stage="detection",
                deciding_rule="single_file_format",
            ),
            archive_format,
        )


def _not_archive() -> RuleDecision:
    return RuleDecision(False, [], decision="not_archive", decision_stage="detection")
