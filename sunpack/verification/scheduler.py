from contextlib import nullcontext
from typing import Any, Callable

from sunpack.contracts.tasks import ArchiveTask
from sunpack.contracts.extraction import ExtractionResult
from sunpack.passwords import PasswordSession
from sunpack.verification.evidence import build_verification_evidence
from sunpack.verification.knowledge import write_verification_result
from sunpack.verification.pipeline import VerificationPipeline, aggregate_payload_verifications
from sunpack.contracts.verification import (
    ASSESSMENT_DISABLED,
    DECISION_ACCEPT,
    DECISION_FAIL,
    DECISION_REQUEST_PASSWORD,
    CONTENT_INTEGRITY_UNKNOWN,
    CONTAINER_INTEGRITY_UNKNOWN,
    VERIFICATION_STRENGTH_EXTRACTION,
    VerificationResult,
)


class VerificationScheduler:
    def __init__(self, config: dict[str, Any] | None = None, password_session: PasswordSession | None = None):
        self.config = self._verification_config(config or {})
        self.password_session = password_session

    def verify(self, task: ArchiveTask, extraction_result: ExtractionResult, *, phase_timer: Callable[..., Any] | None = None, phase_prefix: str = "verify") -> VerificationResult:
        embedded_results = list(extraction_result.embedded_results or [])
        if embedded_results:
            payloads = []
            for index, (segment, segment_result) in enumerate(embedded_results, start=1):
                payloads.append((
                    segment,
                    self._verify_one(
                        task,
                        segment_result,
                        phase_timer=phase_timer,
                        phase_prefix=f"{phase_prefix}_embedded_{index}",
                    ),
                ))
            result = aggregate_payload_verifications(payloads)
        else:
            result = self._verify_one(
                task,
                extraction_result,
                phase_timer=phase_timer,
                phase_prefix=phase_prefix,
            )
        with _phase(phase_timer, f"{phase_prefix}_write_knowledge"):
            write_verification_result(task, result, phase_timer=phase_timer, phase_prefix=f"{phase_prefix}_write_knowledge")
        return result

    def _verify_one(
        self,
        task: ArchiveTask,
        extraction_result: ExtractionResult,
        *,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "verify",
    ) -> VerificationResult:
        with _phase(phase_timer, f"{phase_prefix}_build_evidence"):
            evidence = build_verification_evidence(
                task,
                extraction_result,
                self.password_session,
                phase_timer=phase_timer,
                phase_prefix=f"{phase_prefix}_build_evidence",
            )
        if not self.config.get("enabled", False):
            if not extraction_result.success:
                password_failure = extraction_result.failure is not None and extraction_result.failure.is_password_failure
                result = VerificationResult(
                    completeness=0.0,
                    recoverable_upper_bound=1.0,
                    assessment_status=ASSESSMENT_DISABLED,
                    content_integrity=CONTENT_INTEGRITY_UNKNOWN,
                    container_integrity=CONTAINER_INTEGRITY_UNKNOWN,
                    decision_hint=DECISION_REQUEST_PASSWORD if password_failure else DECISION_FAIL,
                )
                return result
            result = VerificationResult(
                completeness=1.0,
                recoverable_upper_bound=1.0,
                assessment_status=ASSESSMENT_DISABLED,
                content_integrity=CONTENT_INTEGRITY_UNKNOWN,
                container_integrity=CONTAINER_INTEGRITY_UNKNOWN,
                verification_strength=VERIFICATION_STRENGTH_EXTRACTION,
                decision_hint=DECISION_ACCEPT,
            )
            return result
        with _phase(phase_timer, f"{phase_prefix}_pipeline"):
            result = VerificationPipeline(self.config).run(
                evidence,
                phase_timer=phase_timer,
                phase_prefix=f"{phase_prefix}_pipeline",
            )
        return result

    def _verification_config(self, config: dict[str, Any]) -> dict:
        if "verification" in config and isinstance(config.get("verification"), dict):
            return dict(config["verification"])
        return dict(config or {})


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
