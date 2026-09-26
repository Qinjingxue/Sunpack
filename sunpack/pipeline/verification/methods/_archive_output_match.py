from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sunpack.core.contracts.verification import FileVerificationObservation, VerificationIssue
from sunpack.core.support.path_names import clean_relative_archive_path


@dataclass(frozen=True)
class ArchiveOutputCoverage:
    completeness: float
    file_coverage: float
    byte_coverage: float
    expected_files: int
    matched_files: int
    complete_files: int
    partial_files: int
    failed_files: int
    missing_files: int
    expected_bytes: int
    matched_bytes: int
    complete_bytes: int
    observations: list[FileVerificationObservation] = field(default_factory=list)


def coverage_from_native_inventory(
    archive_files: list[dict[str, Any]],
    inventory,
    *,
    method: str,
    verify_crc: bool = False,
    basename_mode: str = "unique",
    include_observations: bool = False,
    detail_offset: int = 0,
    detail_limit: int = 128,
    max_issue_items: int = 20,
    issues_by_path: dict[str, list[VerificationIssue]] | None = None,
) -> tuple[ArchiveOutputCoverage, dict[str, Any]]:
    raw = inventory.verification_match(
        archive_files,
        verify_crc=verify_crc,
        basename_mode=basename_mode,
        include_observations=include_observations,
        detail_offset=detail_offset,
        detail_limit=detail_limit,
        max_issue_items=max_issue_items,
    )
    coverage = dict(raw.get("coverage") or {})
    issues_by_path = issues_by_path or {}
    observations = [
        _native_inventory_observation(item, method, issues_by_path)
        for item in (raw.get("observations") or [])
        if isinstance(item, dict)
    ]
    return ArchiveOutputCoverage(
        completeness=_optional_float(coverage.get("completeness")) or 0.0,
        file_coverage=_optional_float(coverage.get("file_coverage")) or 0.0,
        byte_coverage=_optional_float(coverage.get("byte_coverage")) or 0.0,
        expected_files=int(coverage.get("expected_files", 0) or 0),
        matched_files=int(coverage.get("matched_files", 0) or 0),
        complete_files=int(coverage.get("complete_files", 0) or 0),
        partial_files=int(coverage.get("partial_files", 0) or 0),
        failed_files=int(coverage.get("failed_files", 0) or 0),
        missing_files=int(coverage.get("missing_files", 0) or 0),
        expected_bytes=int(coverage.get("expected_bytes", 0) or 0),
        matched_bytes=int(coverage.get("matched_bytes", 0) or 0),
        complete_bytes=int(coverage.get("complete_bytes", 0) or 0),
        observations=observations,
    ), raw


def archive_files_from_names(names: list[str]) -> list[dict[str, Any]]:
    return [{"path": name} for name in names if clean_relative_archive_path(name)]


def coverage_details(coverage: ArchiveOutputCoverage) -> dict[str, Any]:
    return {
        "completeness": round(float(coverage.completeness), 6),
        "file_coverage": round(float(coverage.file_coverage), 6),
        "byte_coverage": round(float(coverage.byte_coverage), 6),
        "expected_files": coverage.expected_files,
        "matched_files": coverage.matched_files,
        "complete_files": coverage.complete_files,
        "partial_files": coverage.partial_files,
        "failed_files": coverage.failed_files,
        "missing_files": coverage.missing_files,
        "expected_bytes": coverage.expected_bytes,
        "matched_bytes": coverage.matched_bytes,
        "complete_bytes": coverage.complete_bytes,
    }


def _native_inventory_observation(
    raw: dict[str, Any],
    method: str,
    issues_by_path: dict[str, list[VerificationIssue]],
) -> FileVerificationObservation:
    archive_path = str(raw.get("archive_path") or raw.get("path") or "")
    return FileVerificationObservation(
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
    )


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
        return int(value) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None
