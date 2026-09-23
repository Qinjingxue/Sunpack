"""Confirm routed TAR and compression streams."""

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.discovery import (
    DiscoveryCandidate,
    ResolvedArchiveInput,
    StageResult,
)
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

            descriptor = candidate.archive_input or ArchiveInputDescriptor.from_parts(
                archive_path=candidate.entry_path,
                part_paths=list(candidate.member_paths or (candidate.entry_path,)),
                format_hint=candidate.format_hint,
                logical_name=candidate.logical_name,
            )
            result.add_resolved(
                ResolvedArchiveInput(
                    archive_input=descriptor,
                    source="detection",
                    carrier_path=candidate.carrier_path,
                    cleanup_paths=candidate.cleanup_paths,
                    evidence={"format": candidate.format_hint},
                ),
                reason=reason,
            )
        result.validate()
        return result
