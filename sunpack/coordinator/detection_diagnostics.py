"""Read-only detection diagnostics for the CLI inspect command."""

from dataclasses import dataclass
from typing import Any

from sunpack.coordinator.task_provider import ArchiveTaskProvider
from sunpack.detection.options import DetectionOptions


@dataclass
class DetectionDiagnostic:
    path: str
    should_extract: bool
    stop_reason: str
    matched_rules: list[str]
    detected_ext: str
    split_role: str
    fact_bag: object
    decision: str
    decision_stage: str
    discarded_at: str
    deciding_rule: str


class DetectionDiagnostics:
    def __init__(self, config: dict[str, Any], detection_options: DetectionOptions | None = None):
        self.detector = ArchiveTaskProvider(config, detection_options=detection_options)

    def collect(self, paths: list[str]) -> list[DetectionDiagnostic]:
        results = []

        for detection in self.detector.detect_targets(paths):
            bag = detection.fact_bag
            file_path_str = bag.get("file.path")
            if not file_path_str:
                continue
            split_role = bag.get("file.split_role") or ""

            decision = detection.decision

            results.append(DetectionDiagnostic(
                path=file_path_str,
                should_extract=decision.should_extract,
                stop_reason=decision.stop_reason or "",
                matched_rules=decision.matched_rules,
                detected_ext=bag.get("file.detected_ext", ""),
                split_role=split_role or "",
                fact_bag=bag,
                decision=decision.decision,
                decision_stage=decision.decision_stage,
                discarded_at=decision.discarded_at or "",
                deciding_rule=decision.deciding_rule or "",
            ))

        return results
