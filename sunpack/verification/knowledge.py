from __future__ import annotations

from contextlib import nullcontext
from typing import Any

from sunpack.contracts.tasks import ArchiveTask
from sunpack.contracts.verification import VerificationResult
from sunpack.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, prepare_knowledge_value, write_flags, write_payload, write_prepared_payload
from sunpack.support.collections import dedupe_values


def write_verification_result(
    task: ArchiveTask,
    result: VerificationResult,
    *,
    phase_timer: Any | None = None,
    phase_prefix: str = "write_verification",
) -> None:
    with _phase(phase_timer, f"{phase_prefix}_ensure_knowledge"):
        knowledge = ensure_knowledge(task)
    with _phase(phase_timer, f"{phase_prefix}_build_summary"):
        output_quality = {
            "score": float(result.output_quality_score),
            "file_count": int(result.output_file_count),
            "total_bytes": int(result.output_total_bytes),
            "complete_ratio": float(result.output_complete_ratio),
            "failed_ratio": float(result.output_failed_ratio),
            "empty": bool(result.output_empty),
            "confidence": float(result.output_confidence),
        }
        summary = {
            "methods_run": list(result.methods_run),
            "completeness": float(result.completeness),
            "recoverable_upper_bound": float(result.recoverable_upper_bound),
            "assessment_status": result.assessment_status,
            "content_integrity": result.content_integrity,
            "container_integrity": result.container_integrity,
            "verification_strength": result.verification_strength,
            "total_item_count": int(result.total_item_count),
            "verified_item_count": int(result.verified_item_count),
            "archive_walk_complete": bool(result.archive_walk_complete),
            "decision_hint": result.decision_hint,
            "complete_files": int(result.complete_files),
            "partial_files": int(result.partial_files),
            "failed_files": int(result.failed_files),
            "missing_files": int(result.missing_files),
            "unverified_files": int(result.unverified_files),
            "output_quality_score": output_quality["score"],
            "output_file_count": output_quality["file_count"],
            "output_total_bytes": output_quality["total_bytes"],
            "output_complete_ratio": output_quality["complete_ratio"],
            "output_failed_ratio": output_quality["failed_ratio"],
            "output_empty": output_quality["empty"],
            "output_confidence": output_quality["confidence"],
            "output_quality": output_quality,
            "archive_coverage": _archive_coverage_payload(result.archive_coverage),
            "coverage_breakdown": _coverage_breakdown(result),
        }
    with _phase(phase_timer, f"{phase_prefix}_write_summary"):
        prepared_summary = prepare_knowledge_value(summary)
        write_prepared_payload(knowledge, "verification.summary", prepared_summary, source_layer="verification", source_module="scheduler")
        write_prepared_payload(knowledge, "verification", {"coverage_breakdown": prepared_summary["coverage_breakdown"]}, source_layer="verification", source_module="scheduler")
    with _phase(phase_timer, f"{phase_prefix}_write_observations"):
        write_prepared_payload(
            knowledge,
            "verification",
            {
                "issues": [_issue_payload(item) for item in result.issues],
                "file_observations": [_observation_payload(item) for item in result.file_observations],
            },
            source_layer="verification",
            source_module="scheduler",
        )
    with _phase(phase_timer, f"{phase_prefix}_residual_flags"):
        residual = _residual_flags(result)
    if residual:
        with _phase(phase_timer, f"{phase_prefix}_write_residual_flags"):
            write_flags(knowledge, "verification.residual", residual, source_layer="verification", source_module="scheduler")
    with _phase(phase_timer, f"{phase_prefix}_commit"):
        commit_task_knowledge(task, knowledge, phase_timer=phase_timer, phase_prefix=f"{phase_prefix}_commit")


def _residual_flags(result: VerificationResult) -> list[str]:
    flags: list[str] = []
    if result.completeness < 1.0:
        flags.append("partial_entries_remaining")
    if result.failed_files or result.partial_files:
        flags.append("content_integrity_bad_or_unknown")
    if result.content_integrity == "payload_damaged":
        flags.extend(["content_integrity_bad_or_unknown", "checksum_error", "crc_error"])
    elif result.content_integrity == "verified_partial":
        flags.extend(["content_integrity_bad_or_unknown", "partial_entries_remaining"])
    if result.container_integrity == "noncanonical":
        flags.append("container_noncanonical")
    elif result.container_integrity == "structurally_damaged":
        flags.append("container_structurally_damaged")
    if result.missing_files:
        flags.append("missing_entries")
    for issue in result.issues:
        text = f"{issue.code} {issue.message}".lower()
        if "crc" in text or "checksum" in text:
            flags.extend(["checksum_error", "crc_error", "payload_hash_mismatch"])
    return _dedupe(flags)


def _issue_payload(issue: Any) -> dict[str, Any]:
    return {
        "method": issue.method,
        "code": issue.code,
        "message": issue.message,
        "path": issue.path,
        "expected": prepare_knowledge_value(issue.expected),
        "actual": prepare_knowledge_value(issue.actual),
    }


def _observation_payload(observation: Any) -> dict[str, Any]:
    return {
        "path": observation.path,
        "state": observation.state,
        "method": observation.method,
        "archive_path": observation.archive_path,
        "bytes_written": observation.bytes_written,
        "expected_size": observation.expected_size,
        "progress": observation.progress,
        "crc_expected": observation.crc_expected,
        "crc_actual": observation.crc_actual,
        "issues": [_issue_payload(issue) for issue in observation.issues],
        "details": prepare_knowledge_value(observation.details),
    }


def _archive_coverage_payload(coverage: Any) -> dict[str, Any]:
    return {
        "completeness": coverage.completeness,
        "file_coverage": coverage.file_coverage,
        "byte_coverage": coverage.byte_coverage,
        "expected_files": coverage.expected_files,
        "matched_files": coverage.matched_files,
        "complete_files": coverage.complete_files,
        "partial_files": coverage.partial_files,
        "failed_files": coverage.failed_files,
        "missing_files": coverage.missing_files,
        "unverified_files": coverage.unverified_files,
        "expected_bytes": coverage.expected_bytes,
        "matched_bytes": coverage.matched_bytes,
        "complete_bytes": coverage.complete_bytes,
        "confidence": coverage.confidence,
        "sources": prepare_knowledge_value(coverage.sources),
    }


def _coverage_breakdown(result: VerificationResult) -> dict[str, Any]:
    coverage = result.archive_coverage
    expected_files = int(coverage.expected_files or result.output_file_count or 0)
    complete_files = int(coverage.complete_files or result.complete_files or 0)
    partial_files = int(coverage.partial_files or result.partial_files or 0)
    failed_files = int(coverage.failed_files or result.failed_files or 0)
    missing_files = int(coverage.missing_files or result.missing_files or 0)
    unverified_files = int(coverage.unverified_files or result.unverified_files or 0)
    observed_total = expected_files or complete_files + partial_files + failed_files + missing_files + unverified_files
    issue_counts = _issue_counts(result)
    observation_counts = _observation_counts(result)
    crc_mismatch = max(issue_counts["crc_mismatch_count"], observation_counts["crc_mismatch_count"])
    size_mismatch = max(issue_counts["size_mismatch_count"], observation_counts["size_mismatch_count"])
    output_missing = max(issue_counts["output_missing_count"], missing_files)
    coverage_confident = float(coverage.confidence or 0.0) > 0.0
    completeness = float(coverage.completeness if coverage_confident else result.completeness or 0.0)
    file_coverage = float(coverage.file_coverage if coverage_confident else 0.0)
    byte_coverage = float(coverage.byte_coverage if coverage_confident else 0.0)
    return {
        "expected_files": expected_files,
        "matched_files": int(coverage.matched_files or 0),
        "complete_files": complete_files,
        "partial_files": partial_files,
        "failed_files": failed_files,
        "missing_files": missing_files,
        "unverified_files": unverified_files,
        "complete_ratio": _ratio(complete_files, observed_total),
        "partial_ratio": _ratio(partial_files, observed_total),
        "failed_ratio": _ratio(failed_files, observed_total),
        "missing_ratio": _ratio(missing_files, observed_total),
        "unverified_ratio": _ratio(unverified_files, observed_total),
        "expected_bytes": int(coverage.expected_bytes or 0),
        "matched_bytes": int(coverage.matched_bytes or 0),
        "complete_bytes": int(coverage.complete_bytes or 0),
        "file_coverage": file_coverage,
        "byte_coverage": byte_coverage,
        "completeness": completeness,
        "coverage_confidence": float(coverage.confidence or 0.0),
        "crc_mismatch_count": crc_mismatch,
        "size_mismatch_count": size_mismatch,
        "output_missing_count": output_missing,
        "payload_hash_mismatch_count": issue_counts["payload_hash_mismatch_count"],
        "archive_crc_file_missing_count": issue_counts["archive_crc_file_missing_count"],
        "archive_crc_test_failed_count": issue_counts["archive_crc_test_failed_count"],
    }


def _issue_counts(result: VerificationResult) -> dict[str, int]:
    counts = {
        "crc_mismatch_count": 0,
        "size_mismatch_count": 0,
        "output_missing_count": 0,
        "payload_hash_mismatch_count": 0,
        "archive_crc_file_missing_count": 0,
        "archive_crc_test_failed_count": 0,
    }
    for issue in result.issues:
        code = str(issue.code or "").lower()
        message = str(issue.message or "").lower()
        text = f"{code} {message}"
        if "crc" in text or "checksum" in text:
            counts["crc_mismatch_count"] += 1
        if "size" in text or "length" in text:
            counts["size_mismatch_count"] += 1
        if "missing" in text or "output_missing" in text:
            counts["output_missing_count"] += 1
        if "payload_hash" in text or "hash_mismatch" in text:
            counts["payload_hash_mismatch_count"] += 1
        if "archive_crc_file_missing" in code:
            counts["archive_crc_file_missing_count"] += 1
        if "archive_crc_test_failed" in code:
            counts["archive_crc_test_failed_count"] += 1
    return counts


def _observation_counts(result: VerificationResult) -> dict[str, int]:
    counts = {"crc_mismatch_count": 0, "size_mismatch_count": 0}
    for item in result.file_observations:
        if item.crc_expected is not None and item.crc_actual is not None and item.crc_expected != item.crc_actual:
            counts["crc_mismatch_count"] += 1
        if item.expected_size is not None and item.bytes_written and int(item.bytes_written) != int(item.expected_size):
            counts["size_mismatch_count"] += 1
        for issue in item.issues:
            text = f"{issue.code} {issue.message}".lower()
            if "crc" in text or "checksum" in text:
                counts["crc_mismatch_count"] += 1
            if "size" in text or "length" in text:
                counts["size_mismatch_count"] += 1
    return counts


def _ratio(value: int, total: int) -> float:
    return float(value) / float(max(1, int(total or 0)))


_dedupe = dedupe_values


def _phase(timer: Any | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
