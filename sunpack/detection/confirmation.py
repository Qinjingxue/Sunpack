"""Confirm one routed TAR or compression stream at a time."""

from sunpack.contracts.discovery import ResolvedArchiveInput, StageResult, candidate_paths
from sunpack.contracts.detection import FactBag
from sunpack.detection.scheduler import DetectionResult, DetectionScheduler


class FormatConfirmation:
    def __init__(self, detector: DetectionScheduler):
        self.detector = detector

    def confirm(self, bags: list[FactBag], *, scan_session=None) -> tuple[StageResult, list[DetectionResult]]:
        result = StageResult()
        decisions = self.detector.evaluate_bags(bags, scan_session=scan_session)
        for item in decisions:
            bag = item.fact_bag
            if item.decision.should_extract:
                result.add_resolved(ResolvedArchiveInput.from_bag(bag, "detection", {
                    "format": bag.get("filesystem.format_hint"),
                    "reason": item.decision.stop_reason,
                }))
            else:
                result.residual_paths.update(candidate_paths(bag))
        result.validate()
        return result, decisions
