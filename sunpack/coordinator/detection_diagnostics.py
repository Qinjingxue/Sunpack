"""Read-only discovery diagnostics for the CLI inspect command."""

from dataclasses import dataclass
from typing import Any

from sunpack.contracts.discovery import DiscoveryCandidate, ResolvedArchiveInput
from sunpack.coordinator.task_provider import ArchiveTaskProvider
from sunpack.embedded.options import EmbeddedOptions


@dataclass
class DetectionDiagnostic:
    path: str
    should_extract: bool
    stop_reason: str
    matched_rules: list[str]
    format: str
    discovery_source: str
    split_role: str
    candidate: DiscoveryCandidate
    resolved: ResolvedArchiveInput | None
    decision: str
    decision_stage: str
    discarded_at: str
    deciding_rule: str


class DetectionDiagnostics:
    def __init__(
        self,
        config: dict[str, Any],
        detection_options: EmbeddedOptions | None = None,
    ):
        self.detector = ArchiveTaskProvider(
            config,
            detection_options=detection_options,
        )

    def collect(self, paths: list[str]) -> list[DetectionDiagnostic]:
        results: list[DetectionDiagnostic] = []
        for detection in self.detector.detect_targets(paths):
            candidate = detection.candidate
            decision = detection.decision
            split_role = ""
            if candidate.is_split:
                split_role = "first" if candidate.relation_index in {0, 1} else "member"
            results.append(DetectionDiagnostic(
                path=candidate.entry_path,
                should_extract=decision.should_extract,
                stop_reason=decision.stop_reason or "",
                matched_rules=list(decision.matched_rules or []),
                format=detection.format,
                discovery_source=(
                    detection.resolved.source
                    if detection.resolved is not None
                    else candidate.route
                ),
                split_role=split_role,
                candidate=candidate,
                resolved=detection.resolved,
                decision=decision.decision,
                decision_stage=decision.decision_stage,
                discarded_at=decision.discarded_at or "",
                deciding_rule=decision.deciding_rule or "",
            ))
        return results
