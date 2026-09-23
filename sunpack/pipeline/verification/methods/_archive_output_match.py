from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from sunpack.core.support.path_names import clean_relative_archive_path, normalize_match_path
from sunpack.core.contracts.verification import FileVerificationObservation, VerificationIssue
from sunpack.pipeline.verification.methods._output_stats import OutputFileIndex


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


def coverage_from_archive_and_output(
    archive_files: list[dict[str, Any]],
    output_files: Sequence[dict[str, Any]],
    *,
    method: str,
    issues_by_path: dict[str, list[VerificationIssue]] | None = None,
    include_observations: bool = True,
    output_index: OutputFileIndex | None = None,
) -> ArchiveOutputCoverage:
    expected = [
        _archive_item(item)
        for item in archive_files
        if isinstance(item, dict) and not bool(item.get("shadowed"))
    ]
    expected = [item for item in expected if item["path"]]
    output_by_path = output_index.by_path if output_index is not None else _index_output_files(output_files)
    issues_by_path = issues_by_path or {}

    observations: list[FileVerificationObservation] = []
    expected_bytes = 0
    matched_bytes = 0
    complete_bytes = 0
    matched_files = 0
    complete_files = 0
    partial_files = 0
    failed_files = 0
    missing_files = 0

    for item in expected:
        expected_path = item["path"]
        unsafe_path = bool(item.get("unsafe"))
        expected_size = item["size"]
        expected_crc = item["crc32"]
        expected_has_crc = item["has_crc"]
        if expected_size is not None:
            expected_bytes += max(0, expected_size)

        item_issues = list(issues_by_path.get(expected_path) or [])
        if unsafe_path:
            failed_files += 1
            if include_observations:
                observations.append(FileVerificationObservation(
                path=expected_path,
                archive_path=expected_path,
                state="failed",
                method=method,
                expected_size=expected_size,
                crc_expected=expected_crc,
                progress=0.0,
                issues=item_issues,
                details={
                    "expected_has_crc": expected_has_crc,
                    "path_blocked": True,
                    "raw_archive_path": item.get("raw_path") or expected_path,
                    "failure_kind": "output_filesystem",
                },
                ))
            continue

        output_item = output_by_path.get(normalize_match_path(expected_path))
        if output_item is None:
            state = "missing"
            missing_files += 1
            if include_observations:
                observations.append(FileVerificationObservation(
                path=expected_path,
                archive_path=expected_path,
                state=state,
                method=method,
                expected_size=expected_size,
                crc_expected=expected_crc,
                progress=0.0,
                issues=item_issues,
                details={
                    "expected_has_crc": expected_has_crc,
                    "path_blocked": False,
                    "raw_archive_path": item.get("raw_path") or expected_path,
                    "failure_kind": "",
                },
                ))
            continue

        matched_files += 1
        actual_size = _optional_int(output_item.get("size", output_item.get("bytes_written")))
        actual_crc = _optional_crc(output_item.get("output_crc32", output_item.get("crc32")))
        size_progress = _size_progress(actual_size, expected_size)
        crc_ok = True
        if expected_has_crc and expected_crc is not None and actual_crc is not None:
            crc_ok = expected_crc == actual_crc
        if expected_size is not None and actual_size is not None:
            matched_bytes += min(max(0, actual_size), max(0, expected_size))
        elif expected_size is None and actual_size is not None:
            matched_bytes += max(0, actual_size)

        state = "complete"
        progress = size_progress
        output_status = str(output_item.get("status") or "")
        if output_status == "failed":
            state = "failed"
            progress = size_progress if size_progress is not None else 0.0
            failed_files += 1
        elif output_status == "partial":
            state = "partial"
            progress = size_progress if size_progress is not None else 0.5
            partial_files += 1
        elif expected_has_crc and not crc_ok:
            state = "failed"
            progress = 0.0
            failed_files += 1
        elif expected_size is not None and actual_size is not None and actual_size < expected_size:
            state = "partial"
            partial_files += 1
        elif expected_has_crc and actual_crc is None:
            state = "unverified"
        else:
            complete_files += 1
            if expected_size is not None:
                complete_bytes += expected_size
            elif actual_size is not None:
                complete_bytes += actual_size

        if include_observations:
            observations.append(FileVerificationObservation(
            path=str(output_item.get("output_path") or output_item.get("path") or expected_path),
            archive_path=expected_path,
            state=state,
            method=method,
            bytes_written=max(0, actual_size or 0),
            expected_size=expected_size,
            progress=progress,
            crc_expected=expected_crc,
            crc_actual=actual_crc,
            issues=item_issues,
            details={
                "expected_has_crc": expected_has_crc,
                "crc_ok": crc_ok if expected_has_crc and actual_crc is not None else None,
                "matched_by": str(output_item.get("_matched_by") or "path"),
            },
            ))

    expected_count = len(expected)
    file_coverage = matched_files / max(1, expected_count)
    if expected_bytes > 0:
        byte_coverage = min(1.0, max(0.0, matched_bytes / expected_bytes))
    else:
        byte_coverage = file_coverage
    completeness = min(1.0, max(0.0, (file_coverage + byte_coverage) / 2.0))
    if expected_count and failed_files:
        completeness = min(completeness, max(0.0, (expected_count - failed_files - missing_files) / expected_count))

    return ArchiveOutputCoverage(
        completeness=completeness,
        file_coverage=file_coverage,
        byte_coverage=byte_coverage,
        expected_files=expected_count,
        matched_files=matched_files,
        complete_files=complete_files,
        partial_files=partial_files,
        failed_files=failed_files,
        missing_files=missing_files,
        expected_bytes=expected_bytes,
        matched_bytes=matched_bytes,
        complete_bytes=complete_bytes,
        observations=observations,
    )


def output_files_from_directory(output_dir: str) -> list[dict[str, Any]]:
    from sunpack.pipeline.verification.methods._output_stats import collect_output_inventory

    return [dict(item) for item in collect_output_inventory(output_dir).files]


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


def _archive_item(item: dict[str, Any]) -> dict[str, Any]:
    projected_path = str(item.get("output_path") or item.get("path") or item.get("name") or "")
    raw_path = str(item.get("raw_path") or item.get("archive_path") or projected_path)
    cleaned = clean_relative_archive_path(projected_path)
    return {
        "path": cleaned,
        "raw_path": raw_path,
        "unsafe": _unsafe_archive_path(raw_path, clean_relative_archive_path(raw_path)),
        "size": _optional_int(item.get("size", item.get("unpacked_size"))),
        "has_crc": bool(item.get("has_crc", item.get("crc32") is not None)),
        "crc32": _optional_crc(item.get("crc32")),
    }


def _unsafe_archive_path(raw_path: str, cleaned: str) -> bool:
    text = str(raw_path or "").replace("\\", "/")
    if not text:
        return False
    if text.startswith("/") or text.startswith("//"):
        return True
    if len(text) >= 3 and text[1] == ":" and text[2] == "/":
        return True
    parts = [part for part in text.split("/") if part]
    if any(part == ".." for part in parts):
        return True
    if any(_windows_reserved_path_part(part) for part in parts):
        return True
    if any(":" in part for part in parts):
        return True
    return bool(cleaned and cleaned != text.strip().strip("/"))


def _windows_reserved_path_part(part: str) -> bool:
    stem = str(part or "").split(".")[0].strip().rstrip(" .").casefold()
    if not stem:
        return False
    return stem in {"con", "prn", "aux", "nul"} or stem in {f"com{index}" for index in range(1, 10)} or stem in {f"lpt{index}" for index in range(1, 10)}


def _index_output_files(files: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_path: dict[str, dict[str, Any]] = {}
    for raw in files:
        if not isinstance(raw, dict):
            continue
        path = clean_relative_archive_path(raw.get("output_path") or raw.get("path"))
        if not path or ".sunpack/" in path:
            continue
        by_path[normalize_match_path(path)] = raw
    return by_path


def _size_progress(actual_size: int | None, expected_size: int | None) -> float | None:
    if expected_size is None or expected_size <= 0:
        return 1.0 if actual_size is not None else None
    if actual_size is None:
        return None
    return min(1.0, max(0.0, actual_size / expected_size))


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_crc(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None
