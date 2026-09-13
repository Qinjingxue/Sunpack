from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from sunpack.analysis.result import ArchiveAnalysisReport
from sunpack.analysis.result import ArchiveFormatEvidence
from sunpack.contracts.tasks import ArchiveTask
from sunpack.support.runtime_route_evidence import normalize_runtime_route_evidence
from sunpack.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, prepare_knowledge_value, write_flags, write_payload, write_prepared_payload
from sunpack.support.collections import dedupe_strings as _dedupe


def write_inspection_report(task: ArchiveTask, report: ArchiveAnalysisReport) -> None:
    knowledge = ensure_knowledge(task)
    selected = _best_selected(report)
    write_prepared_payload(
        knowledge,
        "inspection",
        prepare_knowledge_value({
            "status": "extractable" if report.has_extractable else "not_extractable",
            "report_path": report.path,
            "read_bytes": report.read_bytes,
            "cache_hits": report.cache_hits,
            "prepass": dict(report.prepass or {}),
            "fuzzy": dict(report.fuzzy or {}),
            "selected_format": getattr(selected, "format", "") if selected is not None else "",
            "confidence": float(getattr(selected, "confidence", 0.0) or 0.0) if selected is not None else 0.0,
            "evidences": [_evidence_payload(item) for item in report.evidences],
        }),
        source_layer="inspection",
        source_module="inspection_projector",
    )
    if selected is not None:
        write_payload(
            knowledge,
            "inspection.summary",
            {
                "format": getattr(selected, "format", "") or "",
                "confidence": float(getattr(selected, "confidence", 0.0) or 0.0),
                "status": getattr(selected, "status", "") or "",
            },
            source_layer="inspection",
            source_module="inspection_projector",
        )
        _write_format_evidence(knowledge, selected, task=task)
    commit_task_knowledge(task, knowledge)


def write_inspection_refresh(
    task: ArchiveTask,
    report: ArchiveAnalysisReport,
) -> None:
    knowledge = ensure_knowledge(task)
    selected = _best_selected(report)
    write_prepared_payload(
        knowledge,
        "inspection",
        prepare_knowledge_value({
            "status": "extractable" if report.has_extractable else "not_extractable",
            "report_path": report.path,
            "read_bytes": report.read_bytes,
            "cache_hits": report.cache_hits,
            "prepass": dict(report.prepass or {}),
            "fuzzy": dict(report.fuzzy or {}),
            "selected_format": getattr(selected, "format", "") if selected is not None else "",
            "confidence": float(getattr(selected, "confidence", 0.0) or 0.0) if selected is not None else 0.0,
            "evidences": [_evidence_payload(item) for item in report.evidences],
        }),
        source_layer="inspection",
        source_module="inspection_projector",
    )
    if selected is not None:
        write_payload(
            knowledge,
            "inspection.summary",
            {
                "format": getattr(selected, "format", "") or "",
                "confidence": float(getattr(selected, "confidence", 0.0) or 0.0),
                "status": getattr(selected, "status", "") or "",
            },
            source_layer="inspection",
            source_module="inspection_projector",
        )
        _write_format_evidence(knowledge, selected, task=task)
    commit_task_knowledge(task, knowledge)


def write_inspection_error(task: ArchiveTask, error: str) -> None:
    knowledge = ensure_knowledge(task)
    write_payload(
        knowledge,
        "inspection",
        {"status": "error", "error": str(error or "")},
        source_layer="inspection",
        source_module="inspection_projector",
    )
    commit_task_knowledge(task, knowledge)


def write_zip_structure_facts(task: ArchiveTask) -> dict[str, Any]:
    structure = _merge_zip_structure_facts({}, task)
    if not structure:
        return {}
    knowledge = ensure_knowledge(task)
    write_payload(
        knowledge,
        "format.zip",
        {"structure": structure},
        source_layer="inspection",
        source_module="zip_structure_facts",
    )
    commit_task_knowledge(task, knowledge)
    return structure


def write_zip_runtime_evidence_facts(task: ArchiveTask) -> dict[str, Any]:
    knowledge = ensure_knowledge(task)
    structure = _dict_at(knowledge, "format.zip.structure")
    if not structure:
        return {}
    runtime_full = _zip_runtime_evidence_payload(knowledge, structure)
    if not runtime_full:
        return {}
    merged = _dedup_zip_structure(dict(structure))
    merged["runtime"] = _zip_runtime_public_payload(runtime_full, knowledge)
    _append_runtime_zip_graph_explanations(merged, runtime_full)
    write_payload(
        knowledge,
        "format.zip",
        {"structure": merged},
        source_layer="verification",
        source_module="zip_runtime_evidence",
    )
    commit_task_knowledge(task, knowledge)
    return merged["runtime"]


def _write_format_evidence(knowledge: Any, evidence: ArchiveFormatEvidence, *, task: ArchiveTask | None = None) -> None:
    details = dict(evidence.details or {})
    format_key = "7z" if evidence.format in {"7z", "seven_zip"} else evidence.format
    write_payload(
        knowledge,
        f"format.{format_key}",
        {
            "evidence": _evidence_payload(evidence),
            "structure": _format_structure_payload(evidence.format, details, task=task),
            "container_tags": _format_container_tags(evidence.format, details),
        },
        source_layer="inspection",
        source_module="inspection_projector",
        confidence=float(evidence.confidence or 0.0),
    )
    if evidence.format in {"7z", "seven_zip"}:
        route_flags = _seven_zip_route_flags_from_details(details)
        if route_flags:
            write_flags(
                knowledge,
                "format.7z.route_evidence",
                route_flags,
                source_layer="inspection",
                source_module="inspection_projector",
                confidence=float(evidence.confidence or 0.0),
            )
            write_payload(
                knowledge,
                "format.7z",
                {"route_evidence_flags": route_flags},
                source_layer="inspection",
                source_module="inspection_projector",
            )
        return
    if evidence.format != "zip":
        return
    route_payload = normalize_runtime_route_evidence({
        "format": evidence.format,
        "inspection_evidence": {"details": details},
        "source_derivation": {
            "zip_structure_features": _format_structure_payload(evidence.format, details, task=task),
            "zip_container_tags": details.get("zip_container_tags") or [],
        },
    })
    route_flags = [str(flag) for flag in route_payload.get("route_evidence_flags") or [] if str(flag)]
    if route_flags:
        write_flags(
            knowledge,
            f"format.{evidence.format}.route_evidence",
            route_flags,
            source_layer="inspection",
            source_module="inspection_projector",
            confidence=float(evidence.confidence or 0.0),
        )
        write_payload(
            knowledge,
            f"format.{evidence.format}",
            {"route_evidence_flags": route_flags},
            source_layer="inspection",
            source_module="inspection_projector",
        )


def _format_structure_payload(fmt: str, details: dict[str, Any], *, task: ArchiveTask | None = None) -> dict[str, Any]:
    if fmt in {"7z", "seven_zip"}:
        return dict(details.get("seven_zip_structure") or details.get("7z_structure") or details.get("structure") or {})
    if fmt != "zip":
        private = details.get(f"{fmt}_structure_features") or details.get("structure")
        if isinstance(private, dict) and private:
            return dict(private)
        # The native RAR/TAR/stream probes return their structural fields at
        # the top level. Preserve them under format.<fmt>.structure so the
        # Format-specific consumers can observe the structural fields they model.
        return {
            key: value
            for key, value in details.items()
            if key not in {"format", "suggested_extension"}
        }
    structure = dict(details.get("zip_structure_features") or details.get("structure") or {})
    if task is not None:
        structure = _merge_zip_structure_facts(structure, task)
    return structure


def _merge_zip_structure_facts(structure: dict[str, Any], task: ArchiveTask) -> dict[str, Any]:
    output = _dedup_zip_structure(dict(structure or {}))
    fact_bag = getattr(task, "fact_bag", None)
    get = getattr(fact_bag, "get", None)
    if not callable(get):
        return output
    graph = get("zip.structure_graph")
    if isinstance(graph, dict) and graph:
        graph_payload = dict(graph)
        summary = graph_payload.get("summary") if isinstance(graph_payload.get("summary"), dict) else {}
        output["graph"] = graph_payload
        output["summary"] = dict(summary or {})
    return output


def _dedup_zip_structure(structure: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in ("graph", "summary", "runtime"):
        value = structure.get(key)
        if isinstance(value, dict) and value:
            output[key] = dict(value)
    # Keep the bounded encryption fact at the format projection boundary.  It
    # is structural routing data, not runtime payload verification, and must
    # remain available after the ZIP graph is normalized.
    for key in (
        "password_required",
        "password_state",
        "central_directory_encrypted_entries",
        "encryption_scan_complete",
    ):
        if key in structure:
            output[key] = structure[key]
    return output


def _enrich_zip_directory_consistency(directory: dict[str, Any]) -> dict[str, Any]:
    checked = max(0, _as_int(directory.get("cd_entries_checked")))
    crc = max(0, _as_int(directory.get("central_local_crc_mismatch_count")))
    compressed = max(0, _as_int(directory.get("central_local_compressed_size_mismatch_count")))
    uncompressed = max(0, _as_int(directory.get("central_local_uncompressed_size_mismatch_count")))
    flags = max(0, _as_int(directory.get("central_local_flags_mismatch_count")))
    method = max(0, _as_int(directory.get("central_local_method_mismatch_count")))
    name = max(0, _as_int(directory.get("central_local_name_mismatch_count")))
    extra = max(0, _as_int(directory.get("local_extra_len_mismatch_count")))
    offset = max(0, _as_int(directory.get("central_local_offset_suspicious_count")))
    any_mismatch = max(crc, compressed, uncompressed, flags, method, name, extra, offset)
    directory.setdefault("crc_mismatch_entry_count", crc)
    directory.setdefault("compressed_size_mismatch_entry_count", compressed)
    directory.setdefault("uncompressed_size_mismatch_entry_count", uncompressed)
    directory.setdefault("field_mismatch_entry_count", any_mismatch)
    directory.setdefault("mismatch_entry_ratio", float(any_mismatch) / float(max(1, checked)))
    directory.setdefault("single_entry_mismatch", checked > 0 and any_mismatch == 1)
    directory.setdefault("multi_entry_mismatch", any_mismatch > 1)
    descriptor = directory.get("descriptor") if isinstance(directory.get("descriptor"), dict) else {}
    descriptor = dict(descriptor)
    spurious_descriptor = max(0, _as_int(descriptor.get("spurious_descriptor_candidate_count")))
    offset_suspicious = max(0, _as_int(directory.get("central_local_offset_suspicious_count")))
    descriptor.setdefault("descriptor_candidate_span_overlap_count", spurious_descriptor)
    descriptor.setdefault("descriptor_payload_end_to_next_local_delta_min", 0)
    descriptor.setdefault("cd_compressed_size_points_into_descriptor_count", spurious_descriptor)
    descriptor.setdefault("compressed_size_ends_before_descriptor_count", 0)
    descriptor.setdefault("compressed_size_ends_inside_descriptor_count", 0)
    descriptor.setdefault("compressed_size_ends_after_next_local_count", 0)
    descriptor.setdefault("descriptor_span_between_payload_and_next_local_count", spurious_descriptor)
    descriptor.setdefault("cd_entry_span_conflict_count", max(spurious_descriptor, offset_suspicious))
    descriptor.setdefault("wrong_local_header_target_count", offset_suspicious)
    descriptor.setdefault("local_header_offset_points_to_other_entry_count", 0)
    descriptor.setdefault("local_header_offset_points_to_descriptor_or_payload_count", offset_suspicious)
    directory["descriptor"] = descriptor
    directory.setdefault("descriptor_flag_on_mismatch_count", max(0, _as_int(descriptor.get("descriptor_flag_mismatch_count"))))
    return directory


def _zip_runtime_evidence_payload(knowledge: Any, structure: dict[str, Any]) -> dict[str, Any]:
    graph = structure.get("graph") if isinstance(structure.get("graph"), dict) else {}
    graph_summary = graph.get("summary") if isinstance(graph.get("summary"), dict) else {}
    structure_summary = structure.get("summary") if isinstance(structure.get("summary"), dict) else {}
    summary = {**dict(graph_summary or {}), **dict(structure_summary or {})}
    directory = structure.get("directory_consistency") if isinstance(structure.get("directory_consistency"), dict) else {}
    directory = _enrich_zip_directory_consistency(dict(directory))
    eocd = structure.get("eocd") if isinstance(structure.get("eocd"), dict) else {}
    local_header = structure.get("local_header") if isinstance(structure.get("local_header"), dict) else {}
    prefix = directory.get("prefix") if isinstance(directory.get("prefix"), dict) else {}
    if summary and not directory:
        directory = dict(summary)
    if summary and not eocd:
        eocd = dict(summary)
    if summary and not local_header:
        local_header = {
            "offset": summary.get("local_header_offset"),
            "plausible": summary.get("local_header_plausible"),
            "error": summary.get("local_header_error"),
        }
    if summary and not prefix:
        prefix = {
            "prefix_bytes_before_first_local": summary.get("sfx_prefix_len") or summary.get("first_local_header_offset"),
            "first_local_header_offset": summary.get("first_local_header_offset"),
        }
    extraction = _dict_at(knowledge, "extraction.entry_outcomes")
    coverage = _dict_at(knowledge, "verification.coverage_breakdown")
    source = _dict_at(knowledge, "source.input")
    result = _dict_at(knowledge, "extraction.result")

    split_parts = _source_parts(source, result)
    checked = max(1, _as_int(directory.get("cd_entries_checked")))
    cd_local_crc = _as_int(directory.get("central_local_crc_mismatch_count"))
    cd_local_size = max(
        _as_int(directory.get("central_local_compressed_size_mismatch_count")),
        _as_int(directory.get("central_local_uncompressed_size_mismatch_count")),
    )
    extraction_crc = _as_int(extraction.get("crc_error_count"))
    extraction_data_error = _as_int(extraction.get("data_error_count"))
    extraction_unexpected_end = _as_int(extraction.get("unexpected_end_count"))
    verification_crc = _as_int(coverage.get("crc_mismatch_count")) + _as_int(coverage.get("payload_hash_mismatch_count"))
    payload_crc = extraction_crc + verification_crc
    failed = _as_int(extraction.get("entry_failed_count")) + _as_int(coverage.get("failed_files"))
    missing = _as_int(extraction.get("missing_volume_count")) + _as_int(coverage.get("missing_files"))
    declared_cd_end = _as_int(eocd.get("physical_central_directory_offset") or directory.get("physical_central_directory_offset")) + _as_int(
        eocd.get("declared_central_directory_size") or directory.get("declared_central_directory_size")
    )
    file_size = _as_int(directory.get("file_size"))
    trailing_after_eocd = _as_int(eocd.get("trailing_bytes_after_eocd"))
    eocd_offset = _as_int(eocd.get("eocd_offset") or directory.get("eocd_offset"))
    archive_offset = _as_int(eocd.get("archive_offset") or directory.get("archive_offset"))
    declared_cd_offset = _as_int(_first_present(eocd, directory, "declared_central_directory_offset", "declared_cd_offset"))
    physical_cd_offset = _as_int(_first_present(eocd, directory, "physical_central_directory_offset", "physical_cd_offset"))
    declared_cd_size = _as_int(_first_present(eocd, directory, "declared_central_directory_size", "declared_cd_size"))
    physical_cd_size = _as_int(_first_present(eocd, directory, "physical_central_directory_size", "walked_central_directory_size"))
    cd_size_delta_value = _first_present(eocd, directory, "central_directory_size_delta")
    cd_offset_delta_value = _first_present(eocd, directory, "central_directory_offset_delta")
    cd_size_delta = _as_int(cd_size_delta_value if cd_size_delta_value is not None else (declared_cd_size - physical_cd_size if declared_cd_size or physical_cd_size else 0))
    cd_offset_delta = _as_int(cd_offset_delta_value if cd_offset_delta_value is not None else (declared_cd_offset - physical_cd_offset if declared_cd_offset or physical_cd_offset else 0))
    sfx_prefix_len = max(0, _as_int(prefix.get("prefix_bytes_before_first_local") if prefix else local_header.get("offset")))
    adjusted_cd_delta = physical_cd_offset - (declared_cd_offset + sfx_prefix_len) if physical_cd_offset or declared_cd_offset or sfx_prefix_len else 0
    descriptor = directory.get("descriptor") if isinstance(directory.get("descriptor"), dict) else {}
    local_link_errors = max(
        _as_int(eocd.get("local_header_links_error_count")),
        _as_int(directory.get("local_header_links_error_count")),
        _as_int(directory.get("local_header_missing_count")) + _as_int(directory.get("local_header_bad_signature_count")),
    )
    coverage_complete = _coverage_breakdown_complete(coverage)
    payload_content_failure = bool(verification_crc or (extraction_crc and not coverage_complete and failed))
    payload_failure_but_coverage_complete = bool(extraction_crc and coverage_complete and not verification_crc)
    checksum_structural_not_payload = bool(
        extraction_crc
        and not verification_crc
        and (coverage_complete or cd_local_crc or cd_local_size or local_link_errors or str(eocd.get("error") or directory.get("error") or ""))
    )
    cd_offset_delta_with_zero_cd_size_delta = bool(cd_offset_delta and not cd_size_delta)
    local_header_link_error_without_payload_crc = bool(local_link_errors and not payload_content_failure)
    declared_cd_offset_matches_without_prefix = bool(physical_cd_offset and declared_cd_offset and physical_cd_offset == declared_cd_offset)
    declared_cd_offset_matches_with_prefix = bool(sfx_prefix_len and physical_cd_offset and declared_cd_offset and physical_cd_offset == declared_cd_offset + sfx_prefix_len)
    cd_offset_delta_equals_prefix_len = bool(sfx_prefix_len and abs(cd_offset_delta) == sfx_prefix_len)
    cd_offset_error_explained_by_prefix = bool(declared_cd_offset_matches_with_prefix and not declared_cd_offset_matches_without_prefix)
    prefix_adjustment_ratio = _safe_float(prefix.get("local_offset_prefix_adjustment_success_ratio")) if prefix else 0.0
    local_offset_only_valid_with_prefix = max(0, _as_int(prefix.get("local_offset_only_valid_with_prefix_count"))) if prefix else 0
    prefix_explains_local_offsets = bool(sfx_prefix_len and (prefix_adjustment_ratio >= 0.5 or local_offset_only_valid_with_prefix > 0))
    cd_pointer_raw = bool(
        _as_int(directory.get("central_local_offset_suspicious_count"))
        or _as_int(descriptor.get("local_header_offset_points_to_descriptor_or_payload_count"))
        or cd_offset_delta_with_zero_cd_size_delta
        or local_header_link_error_without_payload_crc
    )
    cd_pointer_error_likely = bool(cd_pointer_raw and not (cd_offset_error_explained_by_prefix or prefix_explains_local_offsets))
    eocd_entry_count_delta = _as_int(eocd.get("entry_count_delta"))
    directory_entry_count_delta = _as_int(directory.get("entry_count_delta"))
    entry_count_delta_explained_by_cd_pointer = bool(eocd_entry_count_delta and not directory_entry_count_delta and cd_pointer_error_likely)
    cd_offset_matches_after_sfx = declared_cd_offset_matches_with_prefix
    sfx_cd_offset_shift_likely = bool(sfx_prefix_len and (cd_offset_delta_equals_prefix_len or cd_offset_matches_after_sfx))
    local_header_error_explained_by_sfx_offset = bool(sfx_cd_offset_shift_likely and (local_link_errors or prefix_explains_local_offsets))
    split_sidecars_available = len(split_parts) > 1
    likely_missing_range = bool(
        split_sidecars_available
        or missing
        or "missing" in str(extraction.get("first_failure_kind") or "").lower()
        or "volume" in str(extraction.get("first_failure_kind") or "").lower()
        or (cd_offset_delta and abs(cd_offset_delta) > max(64, sfx_prefix_len * 2))
    )
    local_offset_points_into_payload = _as_int(descriptor.get("local_header_offset_points_inside_payload_count")) + _as_int(descriptor.get("local_header_offset_points_to_descriptor_or_payload_count"))
    local_offset_outside_archive = _as_int(descriptor.get("local_header_offset_points_outside_archive_count"))
    cd_offset_delta_matches_deleted_range = bool(likely_missing_range and cd_offset_delta and local_offset_points_into_payload)
    local_offset_error_explained_by_missing_range = bool(likely_missing_range and (local_offset_points_into_payload or local_offset_outside_archive or local_link_errors))
    payload_partial_explained_by_missing_range = bool(likely_missing_range and (_as_int(extraction.get("entry_partial_count")) or _as_int(extraction.get("data_error_count")) or failed))
    missing_range_likely_structural_cause = bool(likely_missing_range and (local_offset_error_explained_by_missing_range or payload_partial_explained_by_missing_range or cd_offset_delta_matches_deleted_range))
    no_payload_hash_crc_failure = not (
        _as_int(coverage.get("crc_mismatch_count"))
        or _as_int(coverage.get("payload_hash_mismatch_count"))
        or _as_int(coverage.get("archive_crc_test_failed_count"))
    )
    payload_observed = _payload_verification_observed(coverage)
    coverage_payload_failure_observed = _coverage_has_payload_failure(coverage)
    extraction_item_failure_observed = bool(extraction_crc or extraction_data_error or extraction_unexpected_end or failed)
    payload_failure_explained_by_missing_range = bool(
        missing_range_likely_structural_cause
        or payload_partial_explained_by_missing_range
        or local_offset_error_explained_by_missing_range
        or cd_offset_delta_matches_deleted_range
    )
    payload_failure_explained_by_cd_pointer = bool(cd_pointer_error_likely or cd_pointer_raw or entry_count_delta_explained_by_cd_pointer)
    payload_failure_explained_by_sfx_or_split = bool(
        split_sidecars_available
        or sfx_cd_offset_shift_likely
        or local_header_error_explained_by_sfx_offset
        or prefix_explains_local_offsets
    )
    payload_failure_explained_by_structure = bool(
        payload_failure_explained_by_missing_range
        or payload_failure_explained_by_cd_pointer
        or payload_failure_explained_by_sfx_or_split
    )
    payload_direct_crc_or_hash_failure_observed = bool(coverage_payload_failure_observed and not no_payload_hash_crc_failure)
    payload_size_or_content_mismatch_observed = bool(
        _as_int(coverage.get("size_mismatch_count"))
        or _as_int(coverage.get("output_missing_count"))
        or (coverage_payload_failure_observed and not payload_failure_explained_by_structure)
    )
    payload_extraction_content_failure_observed = bool(extraction_crc or extraction_data_error or extraction_unexpected_end)
    payload_content_failure_observed = bool(
        payload_direct_crc_or_hash_failure_observed
        or payload_size_or_content_mismatch_observed
        or (
            payload_extraction_content_failure_observed
            and not payload_observed
            and not no_payload_hash_crc_failure
            and not payload_failure_explained_by_structure
        )
    )
    if no_payload_hash_crc_failure and payload_observed:
        payload_direct_crc_or_hash_failure_observed = False
    payload_failure_absent = not payload_content_failure_observed
    payload_verified_intact = bool(payload_observed and payload_failure_absent)
    payload_unverified_but_no_failure = bool(not payload_observed and payload_failure_absent)
    eocd_error = str(eocd.get("error") or directory.get("error") or "")
    eocd_missing = eocd_error in {"eocd_not_found", "eocd_missing", "missing_eocd"}
    evidence = {
        "split_part_count": len(split_parts),
        "has_split_sidecars": split_sidecars_available,
        "declared_cd_end": declared_cd_end,
        "physical_size_delta_to_cd_end": file_size - declared_cd_end if file_size or declared_cd_end else 0,
        "eocd_after_physical_end": bool(file_size and eocd_offset and eocd_offset > file_size),
        "tail_truncation_likely": bool(file_size and declared_cd_end and file_size < declared_cd_end),
        "trailing_bytes_after_eocd": trailing_after_eocd,
        "cd_local_mismatch_with_crc_failure": bool(cd_local_crc and payload_crc),
        "cd_local_mismatch_with_size_failure": bool(cd_local_size and failed),
        "payload_failure_without_header_mismatch": bool(payload_content_failure_observed and not cd_local_crc and not cd_local_size),
        "payload_failure_but_archive_coverage_complete": payload_failure_but_coverage_complete,
        "checksum_error_likely_structural_not_payload": checksum_structural_not_payload,
        "eocd_missing_with_payload_intact": bool(eocd_missing and coverage_complete and not payload_content_failure),
        "tail_truncation_explains_eocd_error": bool(file_size and declared_cd_end and file_size < declared_cd_end and eocd_error),
        "split_truncation_explains_payload_failure": bool(split_sidecars_available and (missing or failed or payload_crc)),
        "local_offset_error_explained_by_missing_range": local_offset_error_explained_by_missing_range,
        "payload_partial_explained_by_missing_range": payload_partial_explained_by_missing_range,
        "cd_offset_delta_matches_deleted_range": cd_offset_delta_matches_deleted_range,
        "missing_range_likely_structural_cause": missing_range_likely_structural_cause,
        "cd_local_mismatch_ratio": float(max(cd_local_crc, cd_local_size, _as_int(directory.get("field_mismatch_entry_count")))) / float(checked),
        "descriptor_candidate_span_overlap_count": max(0, _as_int(descriptor.get("descriptor_candidate_span_overlap_count"))),
        "descriptor_payload_end_to_next_local_delta_min": _as_int(descriptor.get("descriptor_payload_end_to_next_local_delta_min")),
        "cd_compressed_size_points_into_descriptor_count": max(0, _as_int(descriptor.get("cd_compressed_size_points_into_descriptor_count"))),
        "compressed_size_ends_before_descriptor_count": max(0, _as_int(descriptor.get("compressed_size_ends_before_descriptor_count"))),
        "compressed_size_ends_inside_descriptor_count": max(0, _as_int(descriptor.get("compressed_size_ends_inside_descriptor_count"))),
        "compressed_size_ends_after_next_local_count": max(0, _as_int(descriptor.get("compressed_size_ends_after_next_local_count"))),
        "descriptor_span_between_payload_and_next_local_count": max(0, _as_int(descriptor.get("descriptor_span_between_payload_and_next_local_count"))),
        "cd_entry_span_conflict_count": max(0, _as_int(descriptor.get("cd_entry_span_conflict_count"))),
        "wrong_local_header_target_count": max(0, _as_int(descriptor.get("wrong_local_header_target_count"))),
        "local_header_offset_points_to_other_entry_count": max(0, _as_int(descriptor.get("local_header_offset_points_to_other_entry_count"))),
        "local_header_offset_points_to_descriptor_or_payload_count": max(0, _as_int(descriptor.get("local_header_offset_points_to_descriptor_or_payload_count"))),
        "cd_offset_delta_with_zero_cd_size_delta": cd_offset_delta_with_zero_cd_size_delta,
        "local_header_link_error_without_payload_crc": local_header_link_error_without_payload_crc,
        "cd_pointer_error_likely": cd_pointer_error_likely,
        "cd_pointer_raw_likely": cd_pointer_raw,
        "entry_count_delta_explained_by_cd_pointer_error": entry_count_delta_explained_by_cd_pointer,
        "eocd_entry_count_delta_unexplained": 0 if entry_count_delta_explained_by_cd_pointer else eocd_entry_count_delta,
        "directory_entry_count_delta": directory_entry_count_delta,
        "sfx_prefix_len": sfx_prefix_len,
        "first_local_header_found": bool(prefix.get("first_local_header_found")) if prefix else False,
        "first_local_header_offset": max(0, _as_int(prefix.get("first_local_header_offset"))) if prefix else 0,
        "prefix_bytes_before_first_local": max(0, _as_int(prefix.get("prefix_bytes_before_first_local"))) if prefix else 0,
        "prefix_has_non_zip_bytes": bool(prefix.get("prefix_has_non_zip_bytes")) if prefix else False,
        "prefix_has_executable_signature": bool(prefix.get("prefix_has_executable_signature")) if prefix else False,
        "local_offset_valid_without_prefix_count": max(0, _as_int(prefix.get("local_offset_valid_without_prefix_count"))) if prefix else 0,
        "local_offset_valid_with_prefix_count": max(0, _as_int(prefix.get("local_offset_valid_with_prefix_count"))) if prefix else 0,
        "local_offset_only_valid_with_prefix_count": local_offset_only_valid_with_prefix,
        "local_offset_invalid_after_prefix_adjustment_count": max(0, _as_int(prefix.get("local_offset_invalid_after_prefix_adjustment_count"))) if prefix else 0,
        "local_offset_prefix_adjustment_success_ratio": prefix_adjustment_ratio,
        "declared_cd_offset_matches_without_prefix": declared_cd_offset_matches_without_prefix,
        "declared_cd_offset_matches_with_prefix": declared_cd_offset_matches_with_prefix,
        "cd_offset_delta_equals_prefix_len": cd_offset_delta_equals_prefix_len,
        "cd_offset_error_explained_by_prefix": cd_offset_error_explained_by_prefix,
        "declared_cd_offset_plus_archive_offset_delta": adjusted_cd_delta,
        "cd_offset_matches_after_sfx_adjustment": cd_offset_matches_after_sfx,
        "sfx_cd_offset_shift_likely": sfx_cd_offset_shift_likely,
        "local_header_error_explained_by_sfx_offset": local_header_error_explained_by_sfx_offset,
        "local_header_error_explained_by_prefix": local_header_error_explained_by_sfx_offset,
        "payload_verification_observed": payload_observed,
        "payload_verified_intact": payload_verified_intact,
        "payload_unverified_but_no_failure": payload_unverified_but_no_failure,
        "no_payload_hash_crc_failure": no_payload_hash_crc_failure,
        "payload_coverage_content_failure_observed": coverage_payload_failure_observed,
        "extraction_item_failure_observed": extraction_item_failure_observed,
        "payload_direct_crc_or_hash_failure_observed": payload_direct_crc_or_hash_failure_observed,
        "payload_size_or_content_mismatch_observed": payload_size_or_content_mismatch_observed,
        "payload_failure_explained_by_missing_range": payload_failure_explained_by_missing_range,
        "payload_failure_explained_by_cd_pointer": payload_failure_explained_by_cd_pointer,
        "payload_failure_explained_by_sfx_or_split": payload_failure_explained_by_sfx_or_split,
        "payload_extraction_content_failure_observed": payload_extraction_content_failure_observed,
        "extraction_crc_error_count": extraction_crc,
        "extraction_data_error_count": extraction_data_error,
        "extraction_unexpected_end_count": extraction_unexpected_end,
        "payload_content_failure_observed": payload_content_failure_observed,
        "payload_failure_absent": payload_failure_absent,
    }
    return evidence


def _append_runtime_zip_graph_explanations(structure: dict[str, Any], runtime: dict[str, Any]) -> None:
    graph = structure.get("graph") if isinstance(structure.get("graph"), dict) else None
    if graph is None:
        return
    explanations = graph.get("explanations")
    if not isinstance(explanations, list):
        explanations = []
        graph["explanations"] = explanations
    if runtime.get("missing_range_likely_structural_cause") and not any(
        isinstance(item, dict) and item.get("kind") == "missing_range_adjustment"
        for item in explanations
    ):
        explanations.append({
            "kind": "missing_range_adjustment",
            "applies": True,
            "field": "split_volume.missing_range",
            "delta": runtime.get("physical_size_delta_to_cd_end", 0),
            "reason": "runtime split or missing-range evidence explains partial structure failures",
        })


def _zip_runtime_public_payload(runtime: dict[str, Any], knowledge: Any) -> dict[str, Any]:
    split_count = max(0, _as_int(runtime.get("split_part_count")))
    payload = {
        "split_part_count": split_count,
        "has_split_sidecars": bool(runtime.get("has_split_sidecars")),
        "split_parts": [{"index": index, "role": "part"} for index in range(split_count)],
        "payload_verification_observed": bool(runtime.get("payload_verification_observed")),
        "payload_verified_intact": bool(runtime.get("payload_verified_intact")),
        "payload_unverified_but_no_failure": bool(runtime.get("payload_unverified_but_no_failure")),
        "payload_content_failure_observed": bool(runtime.get("payload_content_failure_observed")),
        "payload_coverage_content_failure_observed": bool(runtime.get("payload_coverage_content_failure_observed")),
        "extraction_item_failure_observed": bool(runtime.get("extraction_item_failure_observed")),
        "payload_direct_crc_or_hash_failure_observed": bool(runtime.get("payload_direct_crc_or_hash_failure_observed")),
        "payload_size_or_content_mismatch_observed": bool(runtime.get("payload_size_or_content_mismatch_observed")),
        "payload_failure_explained_by_missing_range": bool(runtime.get("payload_failure_explained_by_missing_range")),
        "payload_failure_explained_by_cd_pointer": bool(runtime.get("payload_failure_explained_by_cd_pointer")),
        "payload_failure_explained_by_sfx_or_split": bool(runtime.get("payload_failure_explained_by_sfx_or_split")),
        "payload_extraction_content_failure_observed": bool(runtime.get("payload_extraction_content_failure_observed")),
        "extraction_crc_error_count": _as_int(runtime.get("extraction_crc_error_count")),
        "extraction_data_error_count": _as_int(runtime.get("extraction_data_error_count")),
        "extraction_unexpected_end_count": _as_int(runtime.get("extraction_unexpected_end_count")),
        "no_payload_hash_crc_failure": bool(runtime.get("no_payload_hash_crc_failure")),
    }
    extraction = _dict_at(knowledge, "extraction.entry_outcomes")
    coverage = _dict_at(knowledge, "verification.coverage_breakdown") or _dict_at(knowledge, "verification.summary.coverage_breakdown")
    if extraction:
        payload["extraction_entry_outcomes"] = extraction
    if coverage:
        payload["verification_coverage_breakdown"] = coverage
    return payload


def _payload_verification_observed(coverage: dict[str, Any]) -> bool:
    if not coverage:
        return False
    observed = sum(
        _as_int(coverage.get(key))
        for key in ("expected_files", "matched_files", "complete_files", "partial_files", "failed_files", "missing_files", "unverified_files")
    )
    bytes_seen = _as_int(coverage.get("expected_bytes")) + _as_int(coverage.get("matched_bytes")) + _as_int(coverage.get("complete_bytes"))
    return bool(observed or bytes_seen or _coverage_has_payload_failure(coverage))


def _coverage_has_payload_failure(coverage: dict[str, Any]) -> bool:
    return bool(
        _as_int(coverage.get("crc_mismatch_count"))
        or _as_int(coverage.get("payload_hash_mismatch_count"))
        or _as_int(coverage.get("size_mismatch_count"))
        or _as_int(coverage.get("output_missing_count"))
        or _as_int(coverage.get("failed_files"))
        or _as_int(coverage.get("missing_files"))
        or _as_int(coverage.get("archive_crc_test_failed_count"))
    )


def _coverage_breakdown_complete(coverage: dict[str, Any]) -> bool:
    if not coverage:
        return False
    if "coverage_confidence" in coverage and _safe_float(coverage.get("coverage_confidence")) <= 0.0:
        observed = sum(
            _as_int(coverage.get(key))
            for key in ("expected_files", "matched_files", "complete_files", "partial_files", "failed_files", "missing_files", "unverified_files")
        )
        if observed <= 0:
            return False
    mismatch_count = (
        _as_int(coverage.get("crc_mismatch_count"))
        + _as_int(coverage.get("payload_hash_mismatch_count"))
        + _as_int(coverage.get("size_mismatch_count"))
        + _as_int(coverage.get("output_missing_count"))
        + _as_int(coverage.get("failed_files"))
        + _as_int(coverage.get("missing_files"))
    )
    if mismatch_count:
        return False
    for key in ("completeness", "output_complete_ratio", "file_coverage_ratio", "byte_coverage_ratio"):
        value = coverage.get(key)
        try:
            if value is not None and float(value) >= 0.999:
                return True
        except (TypeError, ValueError):
            continue
    complete = _as_int(coverage.get("complete_files"))
    total = sum(_as_int(coverage.get(key)) for key in ("complete_files", "partial_files", "failed_files", "missing_files", "unverified_files"))
    return bool(total and complete == total)


def _first_present(primary: dict[str, Any], secondary: dict[str, Any], *keys: str) -> Any:
    for payload in (primary, secondary):
        for key in keys:
            if key in payload and payload.get(key) not in (None, ""):
                return payload.get(key)
    return None


def _source_parts(source: dict[str, Any], extraction_result: dict[str, Any]) -> list[str]:
    for key in ("part_paths", "parts", "all_parts"):
        raw = source.get(key)
        if isinstance(raw, list):
            paths = _part_paths(raw)
            if paths:
                return paths
    raw = extraction_result.get("all_parts")
    if isinstance(raw, list):
        return _part_paths(raw)
    return []


def _part_paths(raw: list[Any]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if isinstance(item, dict):
            path = str(item.get("path") or "")
        else:
            path = str(item or "")
        key = _path_identity(path)
        if path and key not in seen:
            seen.add(key)
            output.append(path)
    return output


def _path_identity(path: str) -> str:
    try:
        return str(Path(path).resolve()).lower()
    except Exception:
        return str(path).lower()


def _dict_at(knowledge: Any, path: str) -> dict[str, Any]:
    get = getattr(knowledge, "get", None)
    value = get(path) if callable(get) else None
    return dict(value) if isinstance(value, dict) else {}


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _format_container_tags(fmt: str, details: dict[str, Any]) -> list[str]:
    raw = details.get("container_tags")
    if fmt not in {"7z", "seven_zip"}:
        raw = details.get("zip_container_tags") or raw
    return [str(item) for item in raw or [] if str(item)] if isinstance(raw, list) else []


def _seven_zip_route_flags_from_details(details: dict[str, Any]) -> list[str]:
    structure = dict(details.get("seven_zip_structure") or details.get("7z_structure") or details.get("structure") or {})
    tags = {str(item).lower() for item in details.get("container_tags") or [] if str(item)}
    flags: list[str] = []
    if structure or details:
        flags.append("seven_zip_signature_found")
    if structure.get("has_carrier_prefix") or structure.get("carrier_prefix_bytes") or tags & {"carrier_prefix", "carrier_archive", "embedded_archive", "sfx"}:
        flags.extend(["carrier_prefix", "carrier_archive", "embedded_archive"])
    if int(structure.get("trailing_bytes") or 0) > 0:
        flags.append("trailing_junk")
    if structure.get("start_crc_ok") is False:
        flags.append("start_header_crc_bad")
    if structure.get("next_header_crc_ok") is False:
        flags.append("next_header_crc_bad")
    if structure.get("next_header_out_of_range") or structure.get("next_header_range_valid") is False:
        flags.append("next_header_out_of_range")
    if structure.get("encoded_header_candidate_found"):
        flags.append("encoded_header_candidate_found")
    if structure.get("encoded_header_present"):
        flags.append("encoded_header_present")
    if structure.get("encoded_header_decodable"):
        flags.append("encoded_header_decodable")
    if structure.get("encoded_header_stream_crc_bad"):
        flags.append("encoded_header_stream_crc_bad")
    if structure.get("next_header_nid_valid") is False:
        flags.append("encoded_header_unreadable")
    for key, flag in (
        ("pack_stream_offset_bad", "pack_stream_offset_bad"),
        ("pack_stream_size_bad", "pack_stream_size_bad"),
        ("unpack_size_bad", "unpack_size_bad"),
        ("stream_crc_bad", "stream_crc_bad"),
        ("substream_crc_bad", "substream_crc_bad"),
        ("empty_stream_flags_bad", "empty_stream_flags_bad"),
        ("empty_file_flags_bad", "empty_file_flags_bad"),
        ("anti_item_flags_bad", "anti_item_flags_bad"),
        ("folder_bind_pairs_bad", "folder_bind_pairs_bad"),
        ("folder_stream_counts_bad", "folder_stream_counts_bad"),
        ("file_count_metadata_bad", "file_count_metadata_bad"),
        ("signature_header_version_bad", "signature_header_version_bad"),
        ("file_names_utf16_bad", "file_names_utf16_bad"),
        ("names_utf16_bad", "names_utf16_bad"),
        ("file_name_metadata_bad", "file_name_metadata_bad"),
        ("unreferenced_folder", "unreferenced_folder"),
        ("unreferenced_folder_record", "unreferenced_folder_record"),
        ("unreferenced_file_record", "unreferenced_file_record"),
        ("file_record_unreferenced", "file_record_unreferenced"),
        ("invalid_stream_crc_defined_flag", "invalid_stream_crc_defined_flag"),
        ("stream_crc_defined_flag_bad", "stream_crc_defined_flag_bad"),
        ("bad_folder_detected", "bad_folder_detected"),
        ("verified_folder_available", "verified_folder_available"),
    ):
        if structure.get(key):
            flags.append(flag)
    if structure.get("solid_archive"):
        flags.append("solid_archive")
    if structure.get("non_solid_archive"):
        flags.append("non_solid_archive")
    return _dedupe(flags)


def _evidence_payload(evidence: ArchiveFormatEvidence) -> dict[str, Any]:
    return {
        "format": evidence.format,
        "confidence": float(evidence.confidence or 0.0),
        "status": evidence.status,
        "warnings": list(evidence.warnings),
        "details": dict(evidence.details),
        "segments": [asdict(segment) for segment in evidence.segments],
    }


def _best_selected(report: ArchiveAnalysisReport) -> ArchiveFormatEvidence | None:
    if not report.selected:
        return None
    return max(report.selected, key=lambda item: float(getattr(item, "confidence", 0.0) or 0.0))
