from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.contracts.failures import FailureKind
from sunpack.core.contracts.results import OutcomeKind
from sunpack.core.contracts.verification import (
    CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
    CONTENT_INTEGRITY_VERIFIED_PARTIAL,
    DECISION_ACCEPT,
    DECISION_ACCEPT_PARTIAL,
    VerificationResult,
)


CONTENT_REQUIREMENT_COMPLETE = "complete"
CONTENT_REQUIREMENT_ALLOW_PARTIAL = "allow_partial"
CONTENT_REQUIREMENTS = frozenset({
    CONTENT_REQUIREMENT_COMPLETE,
    CONTENT_REQUIREMENT_ALLOW_PARTIAL,
})


@dataclass(frozen=True)
class ContentRecoveryDecision:
    outcome_kind: OutcomeKind = OutcomeKind.FAILURE
    rejected_partial_output: bool = False


@dataclass(frozen=True)
class ContentRecoveryPolicy:
    requirement: str = CONTENT_REQUIREMENT_COMPLETE

    def decide(
        self, result: ExtractionResult, verification: VerificationResult | None,
    ) -> ContentRecoveryDecision:
        """Apply the user's content requirement once, after final verification.

        Verification remains evidence, including when it identifies recoverable
        content in an unsuccessful extraction. All consumers use this decision
        rather than applying their own acceptance or output-retention policy.
        """
        hint = verification.decision_hint if verification is not None else ""
        if result.success and hint == DECISION_ACCEPT:
            return ContentRecoveryDecision(OutcomeKind.COMPLETE_SUCCESS)
        if self.requirement == CONTENT_REQUIREMENT_ALLOW_PARTIAL:
            # Recoverable damage does not excuse authentication/execution
            # failures or an unresolved independent input in a carrier.
            failure = result.failure
            if hint == DECISION_ACCEPT_PARTIAL and (
                failure is None or failure.kind in {FailureKind.DAMAGED, FailureKind.MISSING_VOLUME}
            ):
                return ContentRecoveryDecision(OutcomeKind.PARTIAL_SUCCESS)
            return ContentRecoveryDecision()

        # Complete siblings are independent logical archives, not disposable
        # partial files. Keep their existing continuation/output ownership.
        if (result.failure is not None
                and result.failure.contains(FailureKind.INPUTS_FAILED)
                and result.has_complete_inputs):
            return ContentRecoveryDecision()
        partial_output = bool(
            result.partial_outputs
            or hint == DECISION_ACCEPT_PARTIAL
            or (verification.content_integrity if verification is not None else "")
            in {CONTENT_INTEGRITY_VERIFIED_PARTIAL, CONTENT_INTEGRITY_PAYLOAD_DAMAGED}
        )
        return ContentRecoveryDecision(rejected_partial_output=partial_output)

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
