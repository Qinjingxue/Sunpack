"""Confirm routed TAR and compression streams."""

from sunpack.core.contracts.discovery import (
    DiscoveryCandidate,
    StageResult,
)
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.discovery.detection.scheduler import DetectionScheduler


class FormatConfirmation:
    def __init__(self, detector: DetectionScheduler):
        self.detector = detector

    def confirm(self, candidates: list[DiscoveryCandidate]) -> StageResult:
        result = StageResult()
        for candidate in candidates:
            accepted, reason = self.detector.confirm(candidate)
            if not accepted:
                result.add_residual(candidate, source="detection")
                continue

            descriptor = candidate.archive_input
            result.add_resolved(
                ArchiveTask.from_archive_input(
                    descriptor,
                    discovery_source="detection",
                    carrier_path=candidate.carrier_path,
                    cleanup_paths=candidate.cleanup_paths,
                    discovery_evidence={"format": candidate.format_hint},
                ),
                reason=reason,
            )
        result.validate()
        return result
