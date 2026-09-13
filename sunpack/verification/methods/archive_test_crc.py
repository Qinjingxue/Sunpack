from typing import Any, Sequence

from sunpack.support.sevenzip_bridge import (
    STATUS_BACKEND_UNAVAILABLE,
    STATUS_DAMAGED,
    STATUS_OK,
    STATUS_UNSUPPORTED,
    STATUS_WRONG_PASSWORD,
)
from sunpack.verification.archive_state_manifest import archive_state_manifest_for_evidence
from sunpack.verification.evidence import VerificationEvidence
from sunpack.verification.error_classification import classify_verification_error
from sunpack.verification.methods._archive_output_match import ArchiveOutputCoverage, coverage_details, coverage_from_archive_and_output
from sunpack.verification.methods._output_stats import output_file_index_for_evidence, output_inventory_for_evidence, should_emit_file_observations
from sunpack.verification.registry import register_verification_method
from sunpack.contracts.verification import (
    DECISION_RETRY_EXTRACT,
    FileVerificationObservation,
    CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
    CONTENT_INTEGRITY_UNKNOWN,
    CONTENT_INTEGRITY_VERIFIED_COMPLETE,
    CONTENT_INTEGRITY_VERIFIED_PARTIAL,
    VERIFICATION_STRENGTH_CRC,
    VerificationIssue,
    VerificationStepResult,
)

from sunpack_native import match_archive_output_crc_coverage as _match_archive_output_crc_coverage


@register_verification_method("archive_test_crc")
class ArchiveTestCrcMethod:
    name = "archive_test_crc"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        max_items = max(0, int(config.get("max_items", 200000) or 0))
        archive_manifest = archive_state_manifest_for_evidence(evidence, max_items=max_items)

        archive_status_result = self._archive_status_result(archive_manifest, evidence)
        if archive_status_result is not None:
            return archive_status_result

        archive_files = [
            item for item in archive_manifest.files
            if isinstance(item, dict) and item.get("path") and not bool(item.get("shadowed"))
        ]
        inventory = output_inventory_for_evidence(evidence)
        output_files = inventory.materialize_files()
        if not archive_files:
            if archive_manifest.archive_walk_complete and inventory.worker_inventory_complete:
                return _verified_manifest_result(self.name, archive_manifest, inventory)
            return VerificationStepResult(method=self.name, status="skipped")
        if (
            inventory.worker_inventory_complete
            and inventory.identity_paths
            and len(archive_files) == len(output_files)
            and inventory.worker_crc_available
            and all(
                not source.get("has_crc", source.get("crc32") is not None)
                or output.get("output_crc32", output.get("crc32")) is not None
                for source, output in zip(archive_files, output_files)
            )
        ):
            match_result = _trusted_worker_crc_match_result(
                archive_files,
                output_files,
                include_observations=should_emit_file_observations(evidence, self.name),
            )
        else:
            output_index = output_file_index_for_evidence(evidence)
            if _can_use_worker_output_crc(archive_files, output_files, inventory.worker_crc_available, output_by_path=output_index.by_path):
                match_result = _worker_crc_match_result(
                    archive_files,
                    output_files,
                    include_observations=should_emit_file_observations(evidence, self.name),
                    output_index=output_index,
                )
            else:
                match_result = dict(_match_archive_output_crc_coverage(archive_files, evidence.output_dir, max_items))

        status = str(match_result.get("status") or "")
        if status != "ok":
            return VerificationStepResult(method=self.name, status="skipped")

        mismatches = list(match_result.get("mismatches") or [])
        missing = list(match_result.get("missing") or [])
        coverage = dict(match_result.get("coverage") or {})
        if not mismatches and not missing:
            coverage = _promote_verified_manifest_coverage(coverage, archive_manifest, inventory)
        issue_by_path: dict[str, list[VerificationIssue]] = {}

        issues: list[VerificationIssue] = []
        if mismatches:
            issue = VerificationIssue(
                method=self.name,
                code="fail.archive_crc_mismatch",
                message="Output file CRC does not match archive manifest CRC",
                path=evidence.output_dir,
                expected=len(archive_files),
                actual=mismatches[: int(config.get("max_reported_items", 20) or 20)],
            )
            issues.append(issue)
            for item in mismatches:
                issue_by_path.setdefault(str(item.get("path") or ""), []).append(issue)
        if missing:
            issue = VerificationIssue(
                method=self.name,
                code="fail.archive_crc_file_missing",
                message="Some archive CRC entries were not found in extraction output",
                path=evidence.output_dir,
                expected=len(archive_files),
                actual=missing[: int(config.get("max_reported_items", 20) or 20)],
            )
            issues.append(issue)
            for path in missing:
                issue_by_path.setdefault(str(path), []).append(issue)

        direct_observations = match_result.get("_file_observations")
        observations = list(direct_observations) if isinstance(direct_observations, list) else _native_observations(
            match_result.get("observations") or [], issue_by_path, self.name
        )
        completeness = _coverage_float(coverage, "completeness", 1.0)
        content_integrity = _content_integrity(
            archive_manifest,
            mismatches=mismatches,
            missing=missing,
            completeness=completeness,
        )
        summary = {
            "verification_strength": VERIFICATION_STRENGTH_CRC,
            "total_item_count": int(archive_manifest.item_count or 0),
            "verified_item_count": int(archive_manifest.verified_item_count or 0),
            "archive_walk_complete": bool(archive_manifest.archive_walk_complete),
            "manifest_entries_retained": len(archive_manifest.files),
            "manifest_entries_truncated": bool(archive_manifest.entries_truncated),
        }

        if not issues:
            return VerificationStepResult(
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
        return VerificationStepResult(
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

    def _archive_status_result(self, archive_manifest, evidence: VerificationEvidence) -> VerificationStepResult | None:
        if archive_manifest.status == STATUS_OK and archive_manifest.ok:
            return None
        if archive_manifest.status in {STATUS_BACKEND_UNAVAILABLE, STATUS_UNSUPPORTED}:
            return VerificationStepResult(
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
            return VerificationStepResult(
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
            return VerificationStepResult(
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
        return VerificationStepResult(
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


def _verified_manifest_result(method: str, archive_manifest, inventory) -> VerificationStepResult:
    file_count = int(archive_manifest.file_count or inventory.stats.file_count or 0)
    total_items = int(archive_manifest.item_count or file_count)
    return VerificationStepResult(
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


def _native_observations(
    raw_observations: list[Any],
    issues_by_path: dict[str, list[VerificationIssue]],
    method: str,
) -> list[FileVerificationObservation]:
    observations: list[FileVerificationObservation] = []
    for raw in raw_observations:
        if not isinstance(raw, dict):
            continue
        archive_path = str(raw.get("archive_path") or raw.get("path") or "")
        observations.append(FileVerificationObservation(
            path=str(raw.get("path") or archive_path),
            archive_path=archive_path,
            state=str(raw.get("state") or "unverified"),
            method=method,
            bytes_written=int(raw.get("bytes_written", 0) or 0),
            expected_size=_optional_int(raw.get("expected_size")),
            progress=_optional_float(raw.get("progress")),
            crc_expected=_optional_crc(raw.get("crc_expected")),
            crc_actual=_optional_crc(raw.get("crc_actual")),
            issues=list(issues_by_path.get(archive_path) or []),
            details=dict(raw.get("details") or {}),
        ))
    return observations


def _content_integrity(
    archive_manifest,
    *,
    mismatches: list[Any] | None = None,
    missing: list[Any] | None = None,
    completeness: float = 1.0,
) -> str:
    if getattr(archive_manifest, "checksum_error", False) or mismatches:
        return CONTENT_INTEGRITY_PAYLOAD_DAMAGED
    if missing or completeness < 0.999:
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


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _optional_crc(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value or 0) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None


def _can_use_worker_output_crc(
    archive_files: list[dict[str, Any]],
    output_files: tuple[dict[str, Any], ...],
    worker_crc_available: bool,
    output_by_path: dict[str, dict[str, Any]] | None = None,
) -> bool:
    if not worker_crc_available:
        return False
    from sunpack.support.path_names import normalize_match_path

    outputs = output_by_path or {
        normalize_match_path(str(item.get("output_path") or item.get("path") or "")): item
        for item in output_files
    }
    for item in archive_files:
        if not item.get("has_crc", item.get("crc32") is not None):
            continue
        output = outputs.get(normalize_match_path(str(item.get("path") or "")))
        if output is not None and output.get("output_crc32", output.get("crc32")) is None:
            return False
    return True


def _worker_crc_match_result(
    archive_files: list[dict[str, Any]],
    output_files: Sequence[dict[str, Any]],
    *,
    include_observations: bool = True,
    output_index=None,
) -> dict[str, Any]:
    coverage = coverage_from_archive_and_output(
        archive_files,
        output_files,
        method="archive_test_crc",
        include_observations=include_observations,
        output_index=output_index,
    )
    mismatches = [
        {
            "path": observation.archive_path,
            "expected_crc32": observation.crc_expected,
            "actual_crc32": observation.crc_actual,
        }
        for observation in coverage.observations
        if observation.crc_expected is not None
        and observation.crc_actual is not None
        and observation.crc_expected != observation.crc_actual
    ]
    missing = [
        observation.archive_path
        for observation in coverage.observations
        if observation.state == "missing"
    ]
    return {
        "status": "ok",
        "mismatches": mismatches,
        "missing": missing,
        "coverage": coverage_details(coverage),
        "_file_observations": coverage.observations,
        "source": "sevenzip_worker_write",
    }


def _trusted_worker_crc_match_result(
    archive_files: Sequence[dict[str, Any]],
    output_files: Sequence[dict[str, Any]],
    *,
    include_observations: bool,
) -> dict[str, Any]:
    observations: list[FileVerificationObservation] = []
    mismatches: list[dict[str, Any]] = []
    expected_bytes = 0
    matched_bytes = 0
    complete_bytes = 0
    for archive_item, output_item in zip(archive_files, output_files):
        path = str(archive_item.get("path") or "")
        expected_size = _optional_int(archive_item.get("size"))
        actual_size = _optional_int(output_item.get("size", output_item.get("bytes_written")))
        expected_crc = _optional_crc(archive_item.get("crc32")) if archive_item.get("has_crc") else None
        actual_crc = _optional_crc(output_item.get("output_crc32", output_item.get("crc32")))
        if expected_size is not None:
            expected_bytes += max(0, expected_size)
            matched_bytes += min(max(0, actual_size or 0), max(0, expected_size))
        elif actual_size is not None:
            matched_bytes += max(0, actual_size)
        if expected_crc is not None and actual_crc is not None and expected_crc != actual_crc:
            mismatches.append({"path": path, "expected_crc32": expected_crc, "actual_crc32": actual_crc})
        elif expected_size is not None:
            complete_bytes += max(0, expected_size)
        if include_observations:
            observations.append(FileVerificationObservation(
                path=str(output_item.get("output_path") or output_item.get("path") or path),
                archive_path=path,
                state="complete",
                method="archive_test_crc",
                bytes_written=max(0, actual_size or 0),
                expected_size=expected_size,
                progress=1.0,
                crc_expected=expected_crc,
                crc_actual=actual_crc,
                details={
                    "expected_has_crc": expected_crc is not None,
                    "crc_ok": expected_crc is None or actual_crc is None or expected_crc == actual_crc,
                    "matched_by": "identity_worker_inventory",
                },
            ))
    count = len(archive_files)
    byte_coverage = min(1.0, matched_bytes / expected_bytes) if expected_bytes else 1.0
    completeness = min(byte_coverage, (count - len(mismatches)) / max(1, count))
    coverage = ArchiveOutputCoverage(
        completeness=completeness,
        file_coverage=1.0,
        byte_coverage=byte_coverage,
        expected_files=count,
        matched_files=count,
        complete_files=count - len(mismatches),
        partial_files=0,
        failed_files=len(mismatches),
        missing_files=0,
        expected_bytes=expected_bytes,
        matched_bytes=matched_bytes,
        complete_bytes=complete_bytes,
        observations=observations,
    )
    return {
        "status": "ok",
        "mismatches": mismatches,
        "missing": [],
        "coverage": coverage_details(coverage),
        "_file_observations": observations,
        "source": "sevenzip_worker_write",
    }
