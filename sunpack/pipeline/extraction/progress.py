from __future__ import annotations

from typing import Any

from sunpack_native import (
    NativeProgressManifest,
    build_progress_manifest as _native_build_progress_manifest,
    complete_progress_manifest as _native_complete_progress_manifest,
)
from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import (
    native_output_trace,
    native_worker_manifest,
)
from sunpack.pipeline.extraction.output_inventory import OutputInventory, collect_output_inventory


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
    output_inventory: OutputInventory,
    diagnostics: dict[str, Any],
) -> NativeProgressManifest:
    result = _worker_result(diagnostics)
    if output_inventory.worker_inventory_complete:
        stats = output_inventory.stats
        return _native_complete_progress_manifest(
            archive,
            output_inventory.root,
            str(result.get("native_status") or ""),
            stats.file_count,
            stats.total_size,
            stats.file_count,
        )
    output_trace = _output_trace(result)
    return _native_build_progress_manifest(
        archive,
        output_inventory.root,
        native_output_trace(result),
        native_worker_manifest(result),
        output_inventory._native,
        str(result.get("status") or "") == "ok",
        str(result.get("failure_stage") or diagnostics.get("failure_stage") or ""),
        str(result.get("failure_kind") or diagnostics.get("failure_kind") or ""),
        str(result.get("status") or ""),
        str(result.get("native_status") or ""),
        int(result.get("files_written", 0) or output_trace.get("files_written", 0) or 0),
        int(result.get("bytes_written", 0) or output_trace.get("total_bytes_written", 0) or 0),
    )


def recoverable_partial_inventory(diagnostics: dict[str, Any], out_dir: str) -> OutputInventory | None:
    result = _worker_result(diagnostics)
    failure_stage = str(result.get("failure_stage") or diagnostics.get("failure_stage") or "")
    failure_kind = str(result.get("failure_kind") or diagnostics.get("failure_kind") or "")
    if failure_kind not in CONTENT_FAILURE_KINDS and failure_stage not in CONTENT_FAILURE_STAGES:
        return None
    if failure_kind in {"output_filesystem", "process_start", "process_timeout", "process_stall", "process_exit", "process_signal"}:
        return None
    inventory = collect_output_inventory(out_dir)
    if inventory.stats.file_count > 0:
        return inventory
    trace = native_output_trace(result)
    if trace is not None and trace.has_progress():
        return inventory
    if int(result.get("files_written", 0) or 0) > 0 or int(result.get("bytes_written", 0) or 0) > 0:
        return inventory
    return None


def iter_progress_files(manifest: NativeProgressManifest | None, page_size: int = 1024):
    """Yield per-file records while only one bounded page is Python objects."""
    if manifest is None:
        return
    offset = 0
    while page := manifest.file_page(offset, page_size):
        yield from page
        offset += len(page)


def _worker_result(diagnostics: dict[str, Any]) -> dict[str, Any]:
    result = diagnostics.get("result")
    return result if isinstance(result, dict) else {}


def _output_trace(result: dict[str, Any]) -> dict[str, Any]:
    native = result.get("diagnostics") if isinstance(result.get("diagnostics"), dict) else {}
    trace = native.get("output_trace")
    return trace if isinstance(trace, dict) else {}
