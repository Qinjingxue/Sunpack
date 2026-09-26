from typing import Any

from sunpack.pipeline.verification.archive_input_manifest import (
    STATUS_BACKEND_UNAVAILABLE,
    STATUS_DAMAGED,
    STATUS_OK,
    STATUS_UNSUPPORTED,
    STATUS_WRONG_PASSWORD,
    archive_input_manifest_for_evidence,
)
from sunpack.pipeline.verification.evidence import VerificationEvidence
from sunpack.pipeline.verification.error_classification import classify_verification_error
from sunpack.pipeline.verification.methods._archive_output_match import coverage_from_native_inventory
from sunpack.pipeline.verification.methods._output_stats import output_inventory_for_evidence, should_emit_file_observations
from sunpack.pipeline.verification.registry import register_verification_method
from sunpack.core.contracts.verification import (
    DECISION_RETRY_EXTRACT,
    FileVerificationObservation,
    CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
    CONTENT_INTEGRITY_UNKNOWN,
    CONTENT_INTEGRITY_VERIFIED_COMPLETE,
    CONTENT_INTEGRITY_VERIFIED_PARTIAL,
    VERIFICATION_STRENGTH_CRC,
    VerificationIssue,
    VerificationStep,
)


@register_verification_method("archive_test_crc")
class ArchiveTestCrcMethod:
    name = "archive_test_crc"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStep:
        max_items = max(0, int(config.get("max_items", 200000) or 0))
        archive_manifest = archive_input_manifest_for_evidence(evidence, max_items=max_items)

        archive_status_result = self._archive_status_result(archive_manifest, evidence)
        if archive_status_result is not None:
            return archive_status_result

        archive_files = [
            item for item in archive_manifest.files
            if isinstance(item, dict) and item.get("path") and not bool(item.get("shadowed"))
        ]
        inventory = output_inventory_for_evidence(evidence)
        if not archive_files:
            if archive_manifest.archive_walk_complete and inventory.worker_inventory_complete:
                return _verified_manifest_result(self.name, archive_manifest, inventory)
            return VerificationStep(method=self.name, status="skipped")

        max_reported_items = max(1, int(config.get("max_reported_items", 20) or 20))
        emit_observations = should_emit_file_observations(evidence, self.name)
        detail_limit = (
            min(len(archive_files), max(1, int(config.get("detail_page_size", 128) or 128)))
            if emit_observations
            else 0
        )
        coverage_result, match_result = coverage_from_native_inventory(
            archive_files,
            inventory,
            method=self.name,
            verify_crc=True,
            basename_mode="unique",
            include_observations=emit_observations,
            detail_limit=detail_limit,
            max_issue_items=max_reported_items,
        )

        status = str(match_result.get("status") or "")
        if status != "ok":
            return VerificationStep(method=self.name, status="skipped")

        mismatches = list(match_result.get("mismatches") or [])
        missing = list(match_result.get("missing") or [])
        mismatch_count = int(match_result.get("mismatch_count", len(mismatches)) or 0)
        missing_count = int(match_result.get("missing_count", len(missing)) or 0)
        coverage = dict(match_result.get("coverage") or {})
        if mismatch_count == 0 and missing_count == 0:
            coverage = _promote_verified_manifest_coverage(coverage, archive_manifest, inventory)
        issue_by_path: dict[str, list[VerificationIssue]] = {}

        issues: list[VerificationIssue] = []
        if mismatch_count:
            issue = VerificationIssue(
                method=self.name,
                code="fail.archive_crc_mismatch",
                message="Output file CRC does not match archive manifest CRC",
                path=evidence.output_dir,
                expected=len(archive_files),
                actual=mismatches,
            )
            issues.append(issue)
            for item in mismatches:
                issue_by_path.setdefault(str(item.get("path") or ""), []).append(issue)
        if missing_count:
            issue = VerificationIssue(
                method=self.name,
                code="fail.archive_crc_file_missing",
                message="Some archive CRC entries were not found in extraction output",
                path=evidence.output_dir,
                expected=len(archive_files),
                actual=missing,
            )
            issues.append(issue)
            for path in missing:
                issue_by_path.setdefault(str(path), []).append(issue)

        observations = coverage_result.observations
        if issue_by_path and observations:
            observations = [
                FileVerificationObservation(
                    path=item.path,
                    archive_path=item.archive_path,
                    state=item.state,
                    method=item.method,
                    bytes_written=item.bytes_written,
                    expected_size=item.expected_size,
                    progress=item.progress,
                    crc_expected=item.crc_expected,
                    crc_actual=item.crc_actual,
                    issues=list(issue_by_path.get(item.archive_path) or item.issues),
                    details=dict(item.details),
                )
                for item in observations
            ]
        completeness = _coverage_float(coverage, "completeness", 1.0)
        content_integrity = _content_integrity(
            archive_manifest,
            mismatch_count=mismatch_count,
            missing_count=missing_count,
            completeness=completeness,
        )
        summary = {
            "verification_strength": VERIFICATION_STRENGTH_CRC,
            "total_item_count": int(archive_manifest.item_count or 0),
            "verified_item_count": int(archive_manifest.verified_item_count or 0),
            "archive_walk_complete": bool(archive_manifest.archive_walk_complete),
            "manifest_entries_retained": len(archive_manifest.files),
            "manifest_entries_truncated": bool(archive_manifest.entries_truncated),
            "detail_total": int(match_result.get("detail_total", len(archive_files)) or 0),
            "detail_count": int(match_result.get("detail_count", len(observations)) or 0),
            "detail_truncated": bool(match_result.get("detail_truncated", False)),
            "worker_crc_reused": bool(match_result.get("used_worker_crc", False)),
            "crc_files_read": int(match_result.get("crc_files_read", 0) or 0),
        }

        if not issues:
            return VerificationStep(
                method=self.name,
                status="passed",
                completeness_hint=completeness,
                content_integrity_hint=content_integrity,
                verification_strength=VERIFICATION_STRENGTH_CRC,
                total_item_count=summary["total_item_count"],
                verified_item_count=summary["verified_item_count"],
                archive_walk_complete=summary["archive_walk_complete"],
                file_observations=observations,
                issues=[VerificationIssue(
                    method=self.name,
                    code="info.archive_output_coverage",
                    message="Archive-state files were matched against extraction output",
                    path=evidence.output_dir,
                    expected=int(coverage.get("expected_files", len(archive_files)) or 0),
                    actual={**_coverage_actual(coverage, archive_manifest, evidence), **summary},
                )],
            )
        issues.append(VerificationIssue(
            method=self.name,
            code="info.archive_output_coverage",
            message="Archive-state files were matched against extraction output",
            path=evidence.output_dir,
            expected=int(coverage.get("expected_files", len(archive_files)) or 0),
            actual={**_coverage_actual(coverage, archive_manifest, evidence), **summary},
        ))
        return VerificationStep(
            method=self.name,
            status="failed",
            issues=issues,
            completeness_hint=completeness,
            content_integrity_hint=content_integrity,
            verification_strength=VERIFICATION_STRENGTH_CRC,
            total_item_count=summary["total_item_count"],
            verified_item_count=summary["verified_item_count"],
            archive_walk_complete=summary["archive_walk_complete"],
            recoverable_upper_bound_hint=completeness,
            decision_hint=DECISION_RETRY_EXTRACT,
            file_observations=observations,
        )

    def _archive_status_result(self, archive_manifest, evidence: VerificationEvidence) -> VerificationStep | None:
        if archive_manifest.status == STATUS_OK and archive_manifest.ok:
            return None
        if archive_manifest.status in {STATUS_BACKEND_UNAVAILABLE, STATUS_UNSUPPORTED}:
            return VerificationStep(
                method=self.name,
                status="skipped",
                issues=[VerificationIssue(
                    method=self.name,
                    code="warning.archive_crc_state_unsupported",
                    message=archive_manifest.message,
                    path=evidence.archive_path,
                    actual={
                        "source_manifest": True,
                        "archive_type": getattr(archive_manifest, "archive_type", ""),
                    },
                )],
            )
        if archive_manifest.status == STATUS_WRONG_PASSWORD:
            return VerificationStep(
                method=self.name,
                status="failed",
                issues=[VerificationIssue(
                    method=self.name,
                    code="fail.archive_crc_wrong_password",
                    message=archive_manifest.message,
                    path=evidence.archive_path,
                )],
            )
        if (archive_manifest.status == STATUS_DAMAGED or archive_manifest.checksum_error or archive_manifest.damaged) and archive_manifest.files:
            return None
        if archive_manifest.status == STATUS_DAMAGED or archive_manifest.checksum_error or archive_manifest.damaged:
            return VerificationStep(
                method=self.name,
                status="failed",
                completeness_hint=None,
                content_integrity_hint=(
                    CONTENT_INTEGRITY_PAYLOAD_DAMAGED
                    if archive_manifest.checksum_error
                    else classify_verification_error(archive_manifest.failure_kind).content_integrity
                ),
                container_integrity_hint=classify_verification_error(archive_manifest.failure_kind).container_integrity,
                decision_hint=DECISION_RETRY_EXTRACT,
                issues=[VerificationIssue(
                    method=self.name,
                    code="fail.archive_crc_test_failed",
                    message=archive_manifest.message,
                    path=evidence.archive_path,
                )],
            )
        return VerificationStep(
            method=self.name,
            status="skipped",
            issues=[VerificationIssue(
                method=self.name,
                code="warning.archive_crc_unknown_status",
                message=archive_manifest.message,
                path=evidence.archive_path,
                actual=archive_manifest.status,
            )],
        )


def _coverage_actual(coverage: dict[str, Any], archive_manifest, evidence: VerificationEvidence) -> dict[str, Any]:
    actual = {
        "completeness": round(_coverage_float(coverage, "completeness", 1.0), 6),
        "file_coverage": round(_coverage_float(coverage, "file_coverage", 1.0), 6),
        "byte_coverage": round(_coverage_float(coverage, "byte_coverage", 1.0), 6),
        "expected_files": int(coverage.get("expected_files", 0) or 0),
        "matched_files": int(coverage.get("matched_files", 0) or 0),
        "complete_files": int(coverage.get("complete_files", 0) or 0),
        "partial_files": int(coverage.get("partial_files", 0) or 0),
        "failed_files": int(coverage.get("failed_files", 0) or 0),
        "missing_files": int(coverage.get("missing_files", 0) or 0),
        "expected_bytes": int(coverage.get("expected_bytes", 0) or 0),
        "matched_bytes": int(coverage.get("matched_bytes", 0) or 0),
        "complete_bytes": int(coverage.get("complete_bytes", 0) or 0),
    }
    actual.update({
        "source_manifest": True,
        "archive_type": getattr(archive_manifest, "archive_type", ""),
        "content_integrity": _content_integrity(archive_manifest),
    })
    return actual


def _verified_manifest_result(method: str, archive_manifest, inventory) -> VerificationStep:
    file_count = int(archive_manifest.file_count or inventory.stats.file_count or 0)
    total_items = int(archive_manifest.item_count or file_count)
    return VerificationStep(
        method=method,
        status="passed",
        completeness_hint=1.0,
        content_integrity_hint=CONTENT_INTEGRITY_VERIFIED_COMPLETE,
        verification_strength=VERIFICATION_STRENGTH_CRC,
        total_item_count=total_items,
        verified_item_count=int(archive_manifest.verified_item_count or total_items),
        archive_walk_complete=True,
        issues=[VerificationIssue(
            method=method,
            code="info.archive_output_coverage",
            message="The extraction worker verified the complete archive payload",
            expected=file_count,
            actual={
                "coverage": {
                    "completeness": 1.0,
                    "file_coverage": 1.0,
                    "byte_coverage": 1.0,
                    "expected_files": file_count,
                    "matched_files": file_count,
                    "complete_files": file_count,
                    "failed_files": 0,
                    "missing_files": 0,
                    "matched_bytes": int(inventory.stats.total_size or 0),
                    "complete_bytes": int(inventory.stats.total_size or 0),
                    "confidence": 1.0,
                },
                "archive_walk_complete": True,
                "total_item_count": total_items,
                "verified_item_count": int(archive_manifest.verified_item_count or total_items),
                "manifest_entries_retained": 0,
                "manifest_entries_truncated": bool(archive_manifest.entries_truncated),
            },
        )],
    )


def _promote_verified_manifest_coverage(coverage: dict[str, Any], archive_manifest, inventory) -> dict[str, Any]:
    if not (
        archive_manifest.archive_walk_complete
        and archive_manifest.verified_item_count >= archive_manifest.item_count
        and inventory.worker_inventory_complete
    ):
        return coverage
    promoted = dict(coverage)
    file_count = int(archive_manifest.file_count or inventory.stats.file_count or 0)
    total_bytes = int(inventory.stats.total_size or promoted.get("matched_bytes", 0) or 0)
    promoted.update({
        "completeness": 1.0,
        "file_coverage": 1.0,
        "byte_coverage": 1.0,
        "expected_files": file_count,
        "matched_files": file_count,
        "complete_files": file_count,
        "partial_files": 0,
        "failed_files": 0,
        "missing_files": 0,
        "matched_bytes": total_bytes,
        "complete_bytes": total_bytes,
        "confidence": 1.0,
    })
    return promoted


def _content_integrity(
    archive_manifest,
    *,
    mismatch_count: int = 0,
    missing_count: int = 0,
    completeness: float = 1.0,
) -> str:
    if getattr(archive_manifest, "checksum_error", False) or mismatch_count > 0:
        return CONTENT_INTEGRITY_PAYLOAD_DAMAGED
    if missing_count > 0 or completeness < 0.999:
        return CONTENT_INTEGRITY_VERIFIED_PARTIAL
    if (
        getattr(archive_manifest, "archive_walk_complete", False)
        and int(getattr(archive_manifest, "verified_item_count", 0) or 0)
        >= int(getattr(archive_manifest, "item_count", 0) or 0)
    ):
        return CONTENT_INTEGRITY_VERIFIED_COMPLETE
    return CONTENT_INTEGRITY_UNKNOWN


def _coverage_float(coverage: dict[str, Any], key: str, default: float) -> float:
    try:
        return float(coverage.get(key, default))
    except (TypeError, ValueError):
        return default
