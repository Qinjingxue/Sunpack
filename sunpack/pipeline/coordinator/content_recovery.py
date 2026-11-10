from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.contracts.results import OutcomeKind
from sunpack.core.contracts.content_recovery import (
    CONTENT_REQUIREMENT_COMPLETE, CONTENT_REQUIREMENT_ALLOW_PARTIAL, CONTENT_REQUIREMENTS,
)


@dataclass(frozen=True)
class ContentRecoveryDecision:
    outcome_kind: OutcomeKind = OutcomeKind.FAILURE
    rejected_partial_output: bool = False
    complete_files: int = 0


@dataclass(frozen=True)
class ContentRecoveryPolicy:
    requirement: str = CONTENT_REQUIREMENT_COMPLETE

    def decide(self, result: ExtractionResult) -> ContentRecoveryDecision:
        """Use the final execution result, never infer success from output bytes."""
        if result.success:
            inventory = result.output_inventory
            return ContentRecoveryDecision(OutcomeKind.COMPLETE_SUCCESS, complete_files=(
                inventory.stats.file_count if inventory is not None else result.files_written
            ))
        if result.input_results:
            complete_files = 0
            failed = False
            partial = False
            for item in result.input_results:
                decision = self.decide(item.result)
                item.content_outcome = decision.outcome_kind
                complete_files += decision.complete_files
                failed |= decision.outcome_kind == OutcomeKind.FAILURE
                partial |= decision.outcome_kind == OutcomeKind.PARTIAL_SUCCESS
            if not failed and partial:
                return ContentRecoveryDecision(OutcomeKind.PARTIAL_SUCCESS, complete_files=complete_files)
        elif self.requirement == CONTENT_REQUIREMENT_ALLOW_PARTIAL:
            complete_files = result.recoverable_complete_files
            if complete_files > 0:
                return ContentRecoveryDecision(OutcomeKind.PARTIAL_SUCCESS, complete_files=complete_files)
        if self.requirement == CONTENT_REQUIREMENT_ALLOW_PARTIAL:
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
