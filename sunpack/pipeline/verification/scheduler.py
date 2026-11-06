from contextlib import nullcontext
from dataclasses import replace
from typing import Any, Callable

from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.contracts.input_plan import InputCheckpoint, InputRecovery, source_generation
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.passwords import PasswordSession
from sunpack.pipeline.verification.evidence import build_verification_evidence
from sunpack.pipeline.verification.knowledge import write_verification_result
from sunpack.pipeline.verification.pipeline import VerificationPipeline, aggregate_payload_verifications
from sunpack.core.contracts.verification import (
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
    def __init__(self, config: dict[str, Any], password_session: PasswordSession | None = None):
        self.config = config["verification"]
        self.password_session = password_session

    def verify(self, task: ArchiveTask, extraction_result: ExtractionResult, *, phase_timer: Callable[..., Any] | None = None, phase_prefix: str = "verify") -> VerificationResult:
        input_results = extraction_result.input_results
        if input_results or task.recovery.checkpoints:
            payloads = []
            executed = set()
            for index, item in enumerate(input_results, start=1):
                segment_result = item.result
                verification = self._verify_one(
                    task, segment_result, phase_timer=phase_timer,
                    phase_prefix=f"{phase_prefix}_embedded_{index}",
                )
                item.verified_complete = bool(segment_result.success and verification.decision_hint == DECISION_ACCEPT)
                payloads.append((item.projection(), verification))
                executed.add(item.input.input_id)
            for checkpoint in task.recovery.checkpoints:
                if checkpoint.input.input_id in executed:
                    continue
                payloads.append(({"success": checkpoint.complete}, VerificationResult(
                    completeness=1.0 if checkpoint.complete else 0.0,
                    decision_hint=DECISION_ACCEPT if checkpoint.complete else (
                        DECISION_REQUEST_PASSWORD if "password" in checkpoint.blockers else DECISION_FAIL),
                    output_file_count=checkpoint.files_written,
                    output_total_bytes=checkpoint.bytes_written,
                    output_empty=checkpoint.files_written == 0,
                )))
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
        self._checkpoint_inputs(task, extraction_result, result)
        return result

    @staticmethod
    def _checkpoint_inputs(task, extraction_result, verification):
        generation = task.runtime.get("input_generation", ())
        if not generation:
            return
        generation = {row[0]: tuple(row) for row in generation}
        checkpoints = {item.input.input_id: item for item in task.recovery.checkpoints}
        children = extraction_result.input_results
        current = ((item.input, item.result, bool(item.verified_complete))
                   for item in children) if children else (
                       (extraction_result.logical_input, extraction_result,
                        extraction_result.success and verification.decision_hint == DECISION_ACCEPT),)
        for node, result, complete in current:
            if node is not None:
                failure = result.failure
                if failure is None and not complete:
                    failure = FailureInfo(FailureKind.DAMAGED, "verification", "Archive verification failed")
                checkpoints[node.input_id] = InputCheckpoint(
                    node, source_generation(node, generation), result.out_dir, complete, failure,
                    result.files_written, result.bytes_written,
                )
        recovery = InputRecovery(tuple(checkpoints.values()), extraction_result.out_dir,
                                 task.recovery.input_count or len(task.inputs))
        task.recovery = recovery
        if extraction_result.failure is not None:
            extraction_result.failure = replace(extraction_result.failure, details={
                **extraction_result.failure.details, "input_recovery": recovery.to_dict(),
            })

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


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
