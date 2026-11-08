from sunpack.pipeline.verification.evidence import VerificationEvidence
from sunpack.pipeline.verification.error_classification import classify_verification_error
from sunpack.pipeline.verification.methods._output_stats import progress_observations
from sunpack.pipeline.verification.registry import register_verification_method
from sunpack.core.contracts.verification import (
    DECISION_ACCEPT_PARTIAL,
    DECISION_RETRY_EXTRACT,
    DECISION_REQUEST_PASSWORD,
    CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
    CONTENT_INTEGRITY_UNKNOWN,
    CONTENT_INTEGRITY_VERIFIED_PARTIAL,
    VERIFICATION_STRENGTH_EXTRACTION,
    FileVerificationObservation,
    VerificationIssue,
    VerificationStep,
)


@register_verification_method("extraction_exit_signal")
class ExtractionExitSignalMethod:
    name = "extraction_exit_signal"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStep:
        result = evidence.extraction_result
        if not result.success:
            if result.failure is not None and result.failure.is_password_failure:
                return VerificationStep(
                    method=self.name,
                    status="failed",
                    completeness_hint=0.0,
                    content_integrity_hint=CONTENT_INTEGRITY_UNKNOWN,
                    decision_hint=DECISION_REQUEST_PASSWORD,
                    issues=[
                        VerificationIssue(
                            method=self.name,
                            code="fail.password_required",
                            message=result.failure.message,
                            path=evidence.archive_path,
                            actual=result.failure.to_dict(),
                        )
                    ],
                )
            observations = progress_observations(evidence, self.name, include_failure_details=True)
            partial_outputs = bool(result.partial_outputs or observations)
            error_class = _error_class(result.diagnostics, evidence.progress_manifest)
            content_integrity = error_class.content_integrity
            if partial_outputs:
                return VerificationStep(
                    method=self.name,
                    status="partial",
                    completeness_hint=_manifest_completeness(evidence.progress_manifest, observations),
                    recoverable_upper_bound_hint=_recoverable_upper_bound(evidence.progress_manifest, observations),
                    content_integrity_hint=content_integrity,
                    container_integrity_hint=error_class.container_integrity,
                    verification_strength=VERIFICATION_STRENGTH_EXTRACTION,
                    decision_hint=DECISION_ACCEPT_PARTIAL if content_integrity in {
                        CONTENT_INTEGRITY_VERIFIED_PARTIAL,
                        CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
                    } else DECISION_RETRY_EXTRACT,
                    file_observations=observations,
                    issues=[
                        VerificationIssue(
                            method=self.name,
                            code="warning.partial_extraction_available",
                            message=result.error or "Extraction failed after producing partial output",
                            path=evidence.archive_path,
                            actual={
                                "partial_outputs": True,
                            },
                        )
                    ],
                )
            return VerificationStep(
                method=self.name,
                status="failed",
                completeness_hint=0.0,
                content_integrity_hint=content_integrity,
                container_integrity_hint=error_class.container_integrity,
                decision_hint=DECISION_RETRY_EXTRACT,
                issues=[
                    VerificationIssue(
                        method=self.name,
                        code="fail.extraction_failed",
                        message=result.error or "Extraction result is not successful",
                        path=evidence.archive_path,
                    )
                ],
            )

        issues: list[VerificationIssue] = []
        if result.error:
            issues.append(VerificationIssue(
                method=self.name,
                code="warning.success_with_error",
                message=result.error,
                path=evidence.archive_path,
            ))
        manifest = evidence.progress_manifest
        files_written = int(getattr(result, "files_written", 0) or (manifest.files_written if manifest is not None else 0))
        bytes_written = int(getattr(result, "bytes_written", 0) or (manifest.bytes_written if manifest is not None else 0))
        if files_written <= 0 and bytes_written <= 0 and not (manifest is not None and len(manifest)):
            return VerificationStep(
                method=self.name,
                status="failed",
                completeness_hint=0.0,
                content_integrity_hint=CONTENT_INTEGRITY_UNKNOWN,
                decision_hint=DECISION_RETRY_EXTRACT,
                issues=[
                    *issues,
                    VerificationIssue(
                        method=self.name,
                        code="fail.extraction_success_empty",
                        message="Extraction reported success but produced no output files",
                        path=evidence.archive_path,
                        actual={"files_written": files_written, "bytes_written": bytes_written},
                    ),
                ],
            )

        return VerificationStep(
            method=self.name,
            status="warning" if issues else "passed",
            issues=issues,
            completeness_hint=1.0,
            content_integrity_hint=CONTENT_INTEGRITY_UNKNOWN,
            verification_strength=VERIFICATION_STRENGTH_EXTRACTION,
        )


def _error_class(diagnostics: dict, manifest):
    result = diagnostics.get("result", {})
    failure_kind = str(
        result.get("failure_kind")
        or diagnostics.get("failure_kind")
        or (manifest.failure_kind if manifest is not None else "")
        or ""
    )
    failure_stage = str(
        result.get("failure_stage")
        or diagnostics.get("failure_stage")
        or (manifest.failure_stage if manifest is not None else "")
        or ""
    )
    return classify_verification_error(failure_kind, failure_stage)


def _manifest_completeness(manifest, observations: list[FileVerificationObservation]) -> float:
    if observations:
        total = 0.0
        for item in observations:
            if item.progress is not None:
                total += item.progress
            elif item.state == "complete":
                total += 1.0
            elif item.state == "partial":
                total += 0.5
        return total / max(1, len(observations))
    summary = manifest.summary if manifest is not None else {}
    total = int(summary.get("total", 0) or 0)
    if total <= 0:
        return 0.0
    return (int(summary.get("complete", 0) or 0) + 0.5 * int(summary.get("partial", 0) or 0)) / total


def _recoverable_upper_bound(manifest, observations: list[FileVerificationObservation]) -> float:
    summary = manifest.summary if manifest is not None else {}
    total = int(summary.get("total", 0) or 0) or len(observations)
    if total <= 0:
        return 0.0
    recoverable = int(summary.get("complete", 0) or 0) + int(summary.get("partial", 0) or 0) + int(summary.get("unverified", 0) or 0)
    if recoverable <= 0 and observations:
        recoverable = sum(1 for item in observations if item.state in {"complete", "partial", "unverified"})
    return min(1.0, max(0.0, recoverable / total))
