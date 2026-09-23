"""Confirm one routed TAR or compression stream at a time."""

from sunpack.contracts.discovery import (
    DiscoveryCandidate,
    ResolvedArchiveInput,
    StageResult,
    candidate_paths,
)
from sunpack.detection.scheduler import DetectionResult, DetectionScheduler


class FormatConfirmation:
    def __init__(self, detector: DetectionScheduler):
        self.detector = detector

    def confirm(
        self,
        candidates: list[DiscoveryCandidate],
        *,
        scan_session=None,
    ) -> tuple[StageResult, list[DetectionResult]]:
        del scan_session
        result = StageResult()
        decisions: list[DetectionResult] = []
        for item in self.detector.evaluate_candidates(candidates):
            candidate = item.candidate
            if item.decision.should_extract:
                resolved = ResolvedArchiveInput.from_candidate(
                    candidate,
                    "detection",
                    {
                        "format": item.format,
                        "reason": item.decision.stop_reason,
                    },
                    reasons=(item.decision.stop_reason or "",),
                )
                result.add_resolved(resolved)
                decisions.append(DetectionResult(
                    candidate,
                    item.decision,
                    item.format,
                    resolved,
                ))
            else:
                result.residual_paths.update(candidate_paths(candidate))
                decisions.append(item)
        result.validate()
        return result, decisions
