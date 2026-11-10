from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.contracts.failures import FailureKind
from sunpack.core.contracts.results import OutcomeKind
from sunpack.core.contracts.content_recovery import (
    CONTENT_REQUIREMENT_COMPLETE, CONTENT_REQUIREMENT_ALLOW_PARTIAL, CONTENT_REQUIREMENTS,
)


@dataclass(frozen=True)
class ContentRecoveryDecision:
    outcome_kind: OutcomeKind = OutcomeKind.FAILURE
    rejected_partial_output: bool = False


@dataclass(frozen=True)
class ContentRecoveryPolicy:
    requirement: str = CONTENT_REQUIREMENT_COMPLETE

    def decide(self, result: ExtractionResult) -> ContentRecoveryDecision:
        """Use the final execution result, never infer success from output bytes."""
        if result.success:
            return ContentRecoveryDecision(OutcomeKind.COMPLETE_SUCCESS)
        failure = result.failure
        if self.requirement == CONTENT_REQUIREMENT_ALLOW_PARTIAL:
            manifest = result.progress_manifest_payload
            if (failure is not None
                    and failure.kind in {FailureKind.DAMAGED, FailureKind.MISSING_VOLUME}
                    and not failure.causes
                    and manifest is not None
                    and manifest.worker_status == "failed"
                    and manifest.summary["complete"] > 0):
                return ContentRecoveryDecision(OutcomeKind.PARTIAL_SUCCESS)
            return ContentRecoveryDecision()
        if result.has_complete_inputs:
            return ContentRecoveryDecision()
        return ContentRecoveryDecision(rejected_partial_output=result.partial_outputs)

    @classmethod
    def from_config(cls, config: dict[str, Any] | None) -> "ContentRecoveryPolicy":
        extraction = (config or {}).get("extraction")
        if not isinstance(extraction, dict):
            extraction = {}
        requirement = str(
            extraction.get("content_requirement") or CONTENT_REQUIREMENT_COMPLETE
        ).strip().lower()
        if requirement not in CONTENT_REQUIREMENTS:
            raise ValueError(
                "extraction.content_requirement must be 'complete' or 'allow_partial'"
            )
        return cls(requirement=requirement)
