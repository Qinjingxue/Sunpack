from __future__ import annotations

from pathlib import Path
from typing import Any

from sunpack_native import (
    NativeProgressManifest,
    build_progress_manifest as _native_build_progress_manifest,
    complete_progress_manifest as _native_complete_progress_manifest,
    scan_output_inventory as _native_scan_output_inventory,
)
from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import (
    native_output_trace,
    native_worker_manifest,
)


CONTENT_FAILURE_KINDS = {
    "checksum_error",
    "corrupted_data",
    "data_error",
    "unexpected_end",
    "input_truncated",
    "stream_truncated",
}
CONTENT_FAILURE_STAGES = {
    "item_extract",
    "archive_extract",
    "archive_read",
}


def build_extraction_progress_manifest(
    *,
    archive: str,
    out_dir: str,
    diagnostics: dict[str, Any],
    round_index: int = 1,
) -> NativeProgressManifest:
    result = _worker_result(diagnostics)
    output_trace = _output_trace(result)
    return _native_build_progress_manifest(
        archive,
        out_dir,
        int(round_index),
        native_output_trace(result),
        native_worker_manifest(result),
        str(result.get("status") or "") == "ok",
        str(result.get("failure_stage") or diagnostics.get("failure_stage") or ""),
        str(result.get("failure_kind") or diagnostics.get("failure_kind") or ""),
        str(result.get("status") or ""),
        str(result.get("native_status") or ""),
        int(result.get("files_written", 0) or output_trace.get("files_written", 0) or 0),
        int(result.get("bytes_written", 0) or output_trace.get("total_bytes_written", 0) or 0),
    )


def write_extraction_progress_manifest_payload(
    *,
    archive: str,
    out_dir: str,
    diagnostics: dict[str, Any],
    round_index: int = 1,
    pretty: bool = False,
    write_file: bool = False,
) -> tuple[str, NativeProgressManifest]:
    if not write_file:
        compact = _compact_complete_progress_manifest(
            archive=archive,
            out_dir=out_dir,
            diagnostics=diagnostics,
        )
        if compact is not None:
            return "", compact
    manifest = build_extraction_progress_manifest(
        archive=archive,
        out_dir=out_dir,
        diagnostics=diagnostics,
        round_index=round_index,
    )
    if not write_file:
        return "", manifest
    target = Path(out_dir) / ".sunpack" / "extraction_manifest.json"
    manifest.write_json(str(target), pretty)
    return str(target), manifest


def _compact_complete_progress_manifest(
    *,
    archive: str,
    out_dir: str,
    diagnostics: dict[str, Any],
) -> NativeProgressManifest | None:
    result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    manifest = result.get("verified_manifest") if isinstance(result.get("verified_manifest"), dict) else {}
    inventory = manifest.get("inventory") if isinstance(manifest.get("inventory"), dict) else {}
    if result.get("status") != "ok" or not manifest.get("validated") or not inventory.get("complete"):
        return None
    file_count = int(inventory.get("file_count", manifest.get("file_count", 0)) or 0)
    total_size = int(inventory.get("total_size", result.get("bytes_written", 0)) or 0)
    return _native_complete_progress_manifest(
        archive,
        out_dir,
        str(result.get("native_status") or ""),
        int(result.get("files_written", 0) or file_count),
        int(result.get("bytes_written", 0) or total_size),
        file_count,
    )


def has_recoverable_partial_outputs(diagnostics: dict[str, Any], out_dir: str) -> bool:
    result = _worker_result(diagnostics)
    failure_stage = str(result.get("failure_stage") or diagnostics.get("failure_stage") or "")
    failure_kind = str(result.get("failure_kind") or diagnostics.get("failure_kind") or "")
    if failure_kind not in CONTENT_FAILURE_KINDS and failure_stage not in CONTENT_FAILURE_STAGES:
        return False
    if failure_kind in {"output_filesystem", "process_start", "process_timeout", "process_stall", "process_exit", "process_signal"}:
        return False
    trace = native_output_trace(result)
    if trace is not None and trace.has_progress():
        return True
    if int(result.get("files_written", 0) or 0) > 0 or int(result.get("bytes_written", 0) or 0) > 0:
        return True
    return len(_native_scan_output_inventory(str(out_dir))) > 0


def iter_progress_files(manifest: NativeProgressManifest | None, page_size: int = 1024):
    """Yield per-file records while only one bounded page is Python objects."""
    if manifest is None:
        return
    offset = 0
    while page := manifest.file_page(offset, page_size):
        yield from page
        offset += len(page)


def _worker_result(diagnostics: dict[str, Any]) -> dict[str, Any]:
    result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    return dict(result)


def _output_trace(result: dict[str, Any]) -> dict[str, Any]:
    native = result.get("diagnostics") if isinstance(result.get("diagnostics"), dict) else {}
    trace = native.get("output_trace") if isinstance(native.get("output_trace"), dict) else {}
    return dict(trace)
