from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from sunpack_native import scan_output_tree as _native_scan_output_tree
from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import worker_manifest_files
from sunpack.pipeline.postprocess.output_cleanup import DEFAULT_OUTPUT_CLEANUP_MANAGER
from sunpack.core.support.resource_lifecycle import read_task_text, write_task_text


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
) -> dict[str, Any]:
    result = _worker_result(diagnostics)
    output_trace = _output_trace(result)
    source_items = output_trace.get("items") or _verified_manifest_files(result)
    items = [
        _manifest_item(item, out_dir=out_dir, round_index=round_index)
        for item in source_items
        if isinstance(item, dict) and not bool(item.get("is_dir"))
    ]
    items = _merge_untraced_files(items, out_dir, round_index=round_index, worker_ok=str(result.get("status") or "") == "ok")
    summary = _summary(items)
    return {
        "version": 1,
        "archive": archive,
        "out_dir": out_dir,
        "partial_outputs": bool(summary["partial"] or summary["complete"] or summary["failed"]),
        "failure_stage": str(result.get("failure_stage") or diagnostics.get("failure_stage") or ""),
        "failure_kind": str(result.get("failure_kind") or diagnostics.get("failure_kind") or ""),
        "worker_status": str(result.get("status") or ""),
        "native_status": str(result.get("native_status") or ""),
        "files_written": int(result.get("files_written", 0) or output_trace.get("files_written", 0) or summary["complete"] + summary["partial"]),
        "bytes_written": int(result.get("bytes_written", 0) or output_trace.get("total_bytes_written", 0) or _sum_bytes(items)),
        "summary": summary,
        "files": items,
    }


def write_extraction_progress_manifest(
    *,
    archive: str,
    out_dir: str,
    diagnostics: dict[str, Any],
    round_index: int = 1,
    pretty: bool = False,
) -> str:
    path, _manifest = write_extraction_progress_manifest_payload(
        archive=archive,
        out_dir=out_dir,
        diagnostics=diagnostics,
        round_index=round_index,
        pretty=pretty,
        write_file=True,
    )
    return path


def write_extraction_progress_manifest_payload(
    *,
    archive: str,
    out_dir: str,
    diagnostics: dict[str, Any],
    round_index: int = 1,
    pretty: bool = False,
    write_file: bool = False,
) -> tuple[str, dict[str, Any]]:
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
    target.parent.mkdir(parents=True, exist_ok=True)
    write_task_text(target, _json_text(manifest, pretty=pretty), encoding="utf-8")
    return str(target), manifest


def _compact_complete_progress_manifest(
    *,
    archive: str,
    out_dir: str,
    diagnostics: dict[str, Any],
) -> dict[str, Any] | None:
    result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    manifest = result.get("verified_manifest") if isinstance(result.get("verified_manifest"), dict) else {}
    inventory = manifest.get("inventory") if isinstance(manifest.get("inventory"), dict) else {}
    if result.get("status") != "ok" or not manifest.get("validated") or not inventory.get("complete"):
        return None
    file_count = int(inventory.get("file_count", manifest.get("file_count", 0)) or 0)
    total_size = int(inventory.get("total_size", result.get("bytes_written", 0)) or 0)
    return {
        "version": 1,
        "archive": archive,
        "out_dir": out_dir,
        "partial_outputs": bool(file_count),
        "failure_stage": "",
        "failure_kind": "",
        "worker_status": "ok",
        "native_status": str(result.get("native_status") or ""),
        "files_written": int(result.get("files_written", 0) or file_count),
        "bytes_written": int(result.get("bytes_written", 0) or total_size),
        "summary": {
            "total": file_count,
            "complete": file_count,
            "partial": 0,
            "failed": 0,
            "unverified": 0,
        },
        "files": [],
    }


def filter_extraction_outputs(manifest_path: str, *, partial_keep_ratio: float = 0.2) -> dict[str, Any]:
    path = Path(manifest_path)
    manifest = json.loads(read_task_text(path, encoding="utf-8"))
    manifest = filter_extraction_manifest_payload(
        manifest,
        partial_keep_ratio=partial_keep_ratio,
        output_root=str(manifest.get("out_dir") or path.parent.parent),
    )
    write_task_text(path, _json_text(manifest), encoding="utf-8")
    return manifest


def filter_extraction_manifest_payload(
    manifest: dict[str, Any],
    *,
    partial_keep_ratio: float = 0.2,
    output_root: str = "",
) -> dict[str, Any]:
    files = [dict(item) for item in manifest.get("files") or [] if isinstance(item, dict)]
    cleanup_root = _manifest_output_root(manifest, files, output_root=output_root)
    complete = [item for item in files if item.get("status") == "complete"]
    kept: list[dict[str, Any]] = []
    discarded: list[dict[str, Any]] = []

    if complete:
        keep_paths = {str(item.get("path") or "") for item in complete}
        for item in files:
            if str(item.get("path") or "") in keep_paths:
                kept.append({**item, "retention": "kept_complete"})
            else:
                _discard_file(item, output_root=cleanup_root)
                discarded.append({**item, "retention": "discarded_incomplete_after_complete_output"})
    else:
        partials = [item for item in files if item.get("status") in {"partial", "unverified"} and int(item.get("bytes_written", 0) or 0) > 0]
        best_by_name: dict[str, dict[str, Any]] = {}
        for item in partials:
            key = str(item.get("archive_path") or item.get("path") or "")
            if key not in best_by_name or int(item.get("bytes_written", 0) or 0) > int(best_by_name[key].get("bytes_written", 0) or 0):
                best_by_name[key] = item
        best_bytes = max([int(item.get("bytes_written", 0) or 0) for item in partials] or [0])
        min_bytes = max(1, int(best_bytes * max(0.0, float(partial_keep_ratio))))
        keep_paths = {
            str(item.get("path") or "")
            for item in best_by_name.values()
            if int(item.get("bytes_written", 0) or 0) >= min_bytes
        }
        for item in files:
            item_path = str(item.get("path") or "")
            if item_path in keep_paths:
                kept.append({**item, "retention": "kept_best_partial"})
            else:
                _discard_file(item, output_root=cleanup_root)
                discarded.append({**item, "retention": "discarded_low_progress_partial"})

    manifest["files"] = kept
    manifest["discarded_files"] = discarded
    manifest["summary"] = _summary(kept)
    manifest["filter"] = {
        "complete_outputs_present": bool(complete),
        "partial_keep_ratio": partial_keep_ratio,
        "kept": len(kept),
        "discarded": len(discarded),
    }
    return manifest


def has_recoverable_partial_outputs(diagnostics: dict[str, Any], out_dir: str) -> bool:
    result = _worker_result(diagnostics)
    failure_stage = str(result.get("failure_stage") or diagnostics.get("failure_stage") or "")
    failure_kind = str(result.get("failure_kind") or diagnostics.get("failure_kind") or "")
    if failure_kind not in CONTENT_FAILURE_KINDS and failure_stage not in CONTENT_FAILURE_STAGES:
        return False
    if failure_kind in {"output_filesystem", "process_start", "process_timeout", "process_stall", "process_exit", "process_signal"}:
        return False
    output_trace = _output_trace(result)
    if _trace_has_progress(output_trace):
        return True
    if int(result.get("files_written", 0) or 0) > 0 or int(result.get("bytes_written", 0) or 0) > 0:
        return True
    return any(_iter_files(Path(out_dir)))


def _worker_result(diagnostics: dict[str, Any]) -> dict[str, Any]:
    result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    return dict(result)


def _output_trace(result: dict[str, Any]) -> dict[str, Any]:
    native = result.get("diagnostics") if isinstance(result.get("diagnostics"), dict) else {}
    trace = native.get("output_trace") if isinstance(native.get("output_trace"), dict) else {}
    return dict(trace)


def _verified_manifest_files(result: dict[str, Any]) -> list[dict[str, Any]]:
    return worker_manifest_files(result)


def _trace_has_progress(output_trace: dict[str, Any]) -> bool:
    for item in output_trace.get("items") or []:
        if not isinstance(item, dict):
            continue
        if int(item.get("bytes_written", 0) or 0) > 0:
            return True
        if item.get("path") and not item.get("failed"):
            return True
    return False


def _manifest_item(item: dict[str, Any], *, out_dir: str, round_index: int) -> dict[str, Any]:
    failed = bool(item.get("failed"))
    bytes_written = int(item.get("bytes_written", 0) or 0)
    status = "complete"
    if failed:
        status = "partial" if bytes_written > 0 else "failed"
    return {
        "path": _output_path_from_trace(item, out_dir),
        "archive_path": _archive_path_from_trace(item, out_dir),
        "status": str(item.get("status") or status),
        "source_round": round_index,
        "bytes_written": bytes_written,
        "expected_size": _optional_int(item.get("expected_size", item.get("size"))),
        "crc_ok": item.get("crc_ok"),
        "failure_stage": str(item.get("failure_stage") or ""),
        "failure_kind": str(item.get("failure_kind") or ""),
        "message": str(item.get("message") or item.get("error") or ""),
    }


def _output_path_from_trace(item: dict[str, Any], out_dir: str) -> str:
    path = str(item.get("output_path") or item.get("path") or "")
    if not path:
        return ""
    item_path = Path(path)
    if item_path.is_absolute():
        return str(item_path)
    return str(Path(out_dir) / item_path)


def _archive_path_from_trace(item: dict[str, Any], out_dir: str) -> str:
    explicit = item.get("archive_path") or item.get("name")
    if explicit:
        return str(explicit).replace("\\", "/")
    path = str(item.get("path") or item.get("output_path") or "")
    if not path:
        return ""
    if not Path(path).is_absolute():
        return path.replace("\\", "/")
    root = Path(out_dir)
    try:
        return str(Path(path).relative_to(root)).replace("\\", "/")
    except ValueError:
        return Path(path).name


def _merge_untraced_files(items: list[dict[str, Any]], out_dir: str, *, round_index: int, worker_ok: bool = False) -> list[dict[str, Any]]:
    seen = {str(item.get("path") or "") for item in items if item.get("path")}
    for file_item in _iter_files(out_dir):
        text = str(file_item.get("abs_path") or "")
        if text in seen:
            continue
        status = "complete" if worker_ok else "unverified"
        items.append({
            "path": text,
            "archive_path": str(file_item.get("path") or ""),
            "status": status,
            "source_round": round_index,
            "bytes_written": int(file_item.get("size", 0) or 0),
            "expected_size": None,
            "crc_ok": None,
            "failure_stage": "",
            "failure_kind": "",
            "message": "file was present after extraction but was not reported by worker output trace",
        })
    return items


def _discard_file(item: dict[str, Any], *, output_root: str) -> None:
    path = str(item.get("path") or "")
    if not path or not output_root:
        return
    DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_partial_file(path, output_root=output_root)


def _manifest_output_root(
    manifest: dict[str, Any],
    files: list[dict[str, Any]],
    *,
    output_root: str,
) -> str:
    explicit = str(output_root or manifest.get("out_dir") or "")
    if explicit:
        return os.path.abspath(explicit)
    paths = [
        os.path.abspath(str(item.get("path") or ""))
        for item in files
        if item.get("path") and Path(str(item.get("path"))).is_absolute()
    ]
    if not paths:
        return ""
    try:
        common = os.path.commonpath(paths)
    except ValueError:
        return ""
    if common in paths:
        common = os.path.dirname(common)
    return common


def _iter_files(root: str):
    scan = dict(_native_scan_output_tree(str(root)))
    for item in scan.get("files") or []:
        if isinstance(item, dict):
            yield item


def _summary(items: list[dict[str, Any]]) -> dict[str, int]:
    statuses = {"complete": 0, "partial": 0, "failed": 0, "skipped": 0, "unverified": 0}
    for item in items:
        status = str(item.get("status") or "unverified")
        statuses[status if status in statuses else "unverified"] += 1
    statuses["total"] = len(items)
    return statuses


def _sum_bytes(items: list[dict[str, Any]]) -> int:
    return sum(int(item.get("bytes_written", 0) or 0) for item in items)


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _json_text(payload: Any, *, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(payload, ensure_ascii=False, indent=2)
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
