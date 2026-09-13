from sunpack.verification.evidence import VerificationEvidence
from sunpack.verification.error_classification import classify_verification_error
from sunpack.verification.registry import register_verification_method
from sunpack.contracts.verification import (
    DECISION_ACCEPT_PARTIAL,
    DECISION_RETRY_EXTRACT,
    DECISION_REQUEST_PASSWORD,
    CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
    CONTENT_INTEGRITY_UNKNOWN,
    CONTENT_INTEGRITY_VERIFIED_PARTIAL,
    VERIFICATION_STRENGTH_EXTRACTION,
    FileVerificationObservation,
    VerificationIssue,
    VerificationStepResult,
)


@register_verification_method("extraction_exit_signal")
class ExtractionExitSignalMethod:
    name = "extraction_exit_signal"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        result = evidence.extraction_result
        if not result.success:
            if result.failure is not None and result.failure.is_password_failure:
                return VerificationStepResult(
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
                            path=result.archive or evidence.archive_path,
                            actual=result.failure.to_dict(),
                        )
                    ],
                )
            observations = _observations_from_manifest(evidence)
            partial_outputs = bool(result.partial_outputs or observations)
            error_class = _error_class(result.diagnostics, evidence.progress_manifest)
            content_integrity = error_class.content_integrity
            if partial_outputs:
                return VerificationStepResult(
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
                            path=result.archive or evidence.archive_path,
                            actual={
                                "partial_outputs": True,
                                "progress_manifest": result.progress_manifest,
                            },
                        )
                    ],
                )
            return VerificationStepResult(
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
                        path=result.archive or evidence.archive_path,
                    )
                ],
            )

        issues: list[VerificationIssue] = []
        if result.error:
            issues.append(VerificationIssue(
                method=self.name,
                code="warning.success_with_error",
                message=result.error,
                path=result.archive or evidence.archive_path,
            ))
        manifest = evidence.progress_manifest or {}
        files_written = int(getattr(result, "files_written", 0) or manifest.get("files_written") or 0)
        bytes_written = int(getattr(result, "bytes_written", 0) or manifest.get("bytes_written") or 0)
        if files_written <= 0 and bytes_written <= 0 and not _observations_from_manifest(evidence):
            return VerificationStepResult(
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
                        path=result.archive or evidence.archive_path,
                        actual={"files_written": files_written, "bytes_written": bytes_written},
                    ),
                ],
            )

        return VerificationStepResult(
            method=self.name,
            status="warning" if issues else "passed",
            issues=issues,
            completeness_hint=1.0,
            content_integrity_hint=CONTENT_INTEGRITY_UNKNOWN,
            verification_strength=VERIFICATION_STRENGTH_EXTRACTION,
        )


def _error_class(diagnostics: dict, manifest: dict | None):
    payload = manifest or {}
    result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    failure_kind = str(
        result.get("failure_kind")
        or diagnostics.get("failure_kind")
        or payload.get("failure_kind")
        or ""
    )
    failure_stage = str(
        result.get("failure_stage")
        or diagnostics.get("failure_stage")
        or payload.get("failure_stage")
        or ""
    )
    return classify_verification_error(failure_kind, failure_stage)


def _observations_from_manifest(evidence: VerificationEvidence) -> list[FileVerificationObservation]:
    manifest = evidence.progress_manifest or {}
    observations: list[FileVerificationObservation] = []
    for item in manifest.get("files") or []:
        if not isinstance(item, dict):
            continue
        state = str(item.get("status") or "unverified")
        expected = item.get("expected_size")
        bytes_written = int(item.get("bytes_written", 0) or 0)
        progress = None
        if expected not in {None, "", 0}:
            try:
                progress = min(1.0, max(0.0, bytes_written / int(expected)))
            except (TypeError, ValueError, ZeroDivisionError):
                progress = None
        elif state == "complete":
            progress = 1.0
        elif state == "failed":
            progress = 0.0
        elif state == "partial":
            progress = 0.5
        observations.append(FileVerificationObservation(
            path=str(item.get("path") or item.get("archive_path") or ""),
            archive_path=str(item.get("archive_path") or ""),
            state=state if state in {"complete", "partial", "failed", "missing", "unverified"} else "unverified",
            method="extraction_exit_signal",
            bytes_written=bytes_written,
            expected_size=_optional_int(expected),
            progress=progress,
            details={
                "failure_stage": item.get("failure_stage"),
                "failure_kind": item.get("failure_kind"),
                "message": item.get("message"),
            },
        ))
    return observations


def _manifest_completeness(manifest: dict | None, observations: list[FileVerificationObservation]) -> float:
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
    summary = (manifest or {}).get("summary") if isinstance((manifest or {}).get("summary"), dict) else {}
    total = int(summary.get("total", 0) or 0)
    if total <= 0:
        return 0.0
    return (int(summary.get("complete", 0) or 0) + 0.5 * int(summary.get("partial", 0) or 0)) / total


def _recoverable_upper_bound(manifest: dict | None, observations: list[FileVerificationObservation]) -> float:
    summary = (manifest or {}).get("summary") if isinstance((manifest or {}).get("summary"), dict) else {}
    total = int(summary.get("total", 0) or 0) or len(observations)
    if total <= 0:
        return 0.0
    recoverable = int(summary.get("complete", 0) or 0) + int(summary.get("partial", 0) or 0) + int(summary.get("unverified", 0) or 0)
    if recoverable <= 0 and observations:
        recoverable = sum(1 for item in observations if item.state in {"complete", "partial", "unverified"})
    return min(1.0, max(0.0, recoverable / total))


def _optional_int(value) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
