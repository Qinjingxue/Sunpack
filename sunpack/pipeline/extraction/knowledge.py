from __future__ import annotations

from contextlib import nullcontext
from typing import Any, Callable

from sunpack_native import NativeProgressManifest

from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, write_payload


def write_extraction_result(task: ArchiveTask, result: ExtractionResult, *, phase_timer: Callable[..., Any] | None = None, phase_prefix: str = "write_extraction") -> None:
    with _phase(phase_timer, f"{phase_prefix}_ensure_knowledge"):
        knowledge = ensure_knowledge(task)
    with _phase(phase_timer, f"{phase_prefix}_build_payload"):
        diagnostics = _compact_diagnostics(result.diagnostics)
        if result.input_results:
            # Execution keeps one typed result per input. Expand only the
            # bounded diagnostic preview, after the whole carrier has settled.
            inputs = []
            count = 0
            for item in result.input_results:
                if item.retained:
                    continue
                count += 1
                if count > 20:
                    continue
                child = item.result
                inputs.append(_compact_mapping({
                    **item.input.projection(),
                    "out_dir": child.out_dir, "success": child.success,
                    "partial_outputs": child.partial_outputs or child.files_written > 0,
                    "error": child.error,
                    "failure": child.failure.to_dict() if child.failure is not None else None,
                    "password_used": child.password_used,
                    "selected_codepage": child.selected_codepage,
                    "diagnostics": child.diagnostics,
                    "files_written": child.files_written,
                    "bytes_written": child.bytes_written,
                }, max_items=20))
            if count > 20:
                inputs.append({"truncated_count": count - 20})
            diagnostics["inputs"] = inputs
        worker = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
        payload = {
            "result": _result_payload(task, result),
            "diagnostics": diagnostics,
            "failure": _failure_payload(result, worker),
            "progress_manifest": _compact_progress_manifest(result.progress_manifest_payload),
        }
    with _phase(phase_timer, f"{phase_prefix}_write_payload"):
        write_payload(
            knowledge,
            "extraction",
            payload,
            source_layer="extraction",
            source_module="scheduler",
        )
        if result.password_used is not None:
            write_payload(
                knowledge,
                "archive",
                {
                    "password": result.password_used,
                    "password_present": bool(str(result.password_used)),
                },
                source_layer="extraction",
                source_module="scheduler",
            )
    with _phase(phase_timer, f"{phase_prefix}_commit"):
        commit_task_knowledge(task, knowledge, phase_timer=phase_timer, phase_prefix=f"{phase_prefix}_commit")


def _result_payload(task: ArchiveTask, result: ExtractionResult) -> dict[str, Any]:
    return {
        "success": bool(result.success),
        "archive": task.main_path,
        "out_dir": result.out_dir,
        "all_parts": list(task.all_parts),
        "error": result.error,
        "password_used": result.password_used,
        "selected_codepage": result.selected_codepage,
        "partial_outputs": bool(result.partial_outputs),
        "files_written": int(getattr(result, "files_written", 0) or 0),
        "bytes_written": int(getattr(result, "bytes_written", 0) or 0),
    }


def _failure_payload(result: ExtractionResult, worker: dict[str, Any]) -> dict[str, Any]:
    if result.success:
        return {}
    if result.failure is not None:
        payload = result.failure.to_dict()
        payload.update({
            "status": str(worker.get("status") or "failed"),
            "error": result.error,
            "partial_outputs": bool(result.partial_outputs),
            "failed_item": worker.get("failed_item"),
        })
        return payload
    return {
        "status": str(worker.get("status") or "failed"),
        "failure_stage": str(worker.get("failure_stage") or ""),
        "failure_kind": str(worker.get("failure_kind") or ""),
        "native_status": str(worker.get("native_status") or ""),
        "error": result.error,
        "partial_outputs": bool(result.partial_outputs),
        "failed_item": worker.get("failed_item"),
    }


def _compact_diagnostics(diagnostics: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in (
        "status",
        "failure_stage",
        "failure_kind",
        "native_status",
        "returncode",
        "files_written",
        "bytes_written",
        "error",
        "message",
        "partial_outputs",
        "failure",
    ):
        if key in diagnostics:
            output[key] = diagnostics.get(key)
    result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    if result:
        output["result"] = _compact_worker_result(result)
    return output


def _compact_worker_result(result: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in (
        "status",
        "failure_stage",
        "failure_kind",
        "native_status",
        "returncode",
        "files_written",
        "bytes_written",
        "failed_item",
        "message",
        "damaged",
        "checksum_error",
        "crc_error",
        "wrong_password",
        "missing_volume",
        "unsupported_method",
        "output_filesystem",
    ):
        if key in result:
            output[key] = result.get(key)
    native = result.get("diagnostics") if isinstance(result.get("diagnostics"), dict) else {}
    if native:
        output["diagnostics"] = _compact_native_diagnostics(native)
    return output


def _compact_native_diagnostics(native: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in (
        "failure_stage",
        "failure_kind",
        "native_status",
        "operation_result_name",
        "process_failure",
        "damaged",
        "checksum_error",
        "crc_error",
        "wrong_password",
        "missing_volume",
        "unsupported_method",
        "output_filesystem",
        "files_written",
        "bytes_written",
        "stderr_tail",
        "stdout_tail",
    ):
        if key in native:
            value = native.get(key)
            if isinstance(value, str) and key in {"stderr_tail", "stdout_tail"}:
                value = value[-4000:]
            output[key] = value
    if isinstance(native.get("last_progress_event"), dict):
        output["last_progress_event"] = _compact_mapping(native["last_progress_event"], max_items=20)
    progress_events = native.get("progress_events") if isinstance(native.get("progress_events"), list) else []
    if progress_events:
        output["progress_event_count"] = int(native.get("progress_event_count", len(progress_events)))
        if isinstance(progress_events[-1], dict):
            output["last_progress_event"] = _compact_mapping(progress_events[-1], max_items=20)
    return output


def _compact_progress_manifest(manifest: NativeProgressManifest | None) -> dict[str, Any]:
    if not isinstance(manifest, NativeProgressManifest):
        return {}
    files = list(manifest.file_page(0, 50))
    if len(manifest) > 50:
        files.append({"truncated_count": len(manifest) - 50})
    return {
        "summary": manifest.summary,
        "files_written": manifest.files_written,
        "bytes_written": manifest.bytes_written,
        "failure_stage": manifest.failure_stage,
        "failure_kind": manifest.failure_kind,
        "files": files,
    }


def _compact_mapping(value: dict[str, Any], *, max_items: int) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for index, (key, item) in enumerate(value.items()):
        if index >= max_items:
            output["truncated_count"] = len(value) - max_items
            break
        text_key = str(key)
        if text_key in {"request_payload", "job"}:
            output[text_key] = _large_placeholder(item)
        elif isinstance(item, dict):
            output[text_key] = _compact_mapping(item, max_items=max_items)
        elif isinstance(item, list):
            output[text_key] = [_compact_mapping(child, max_items=10) if isinstance(child, dict) else child for child in item[:20]]
            if len(item) > 20:
                output[text_key].append({"truncated_count": len(item) - 20})
        elif isinstance(item, str) and len(item) > 4000:
            output[text_key] = item[:4000]
        else:
            output[text_key] = item
    return output


def _large_placeholder(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {"omitted": True, "kind": "dict", "keys": sorted(str(key) for key in value.keys())[:20], "key_count": len(value)}
    if isinstance(value, list):
        return {"omitted": True, "kind": "list", "count": len(value)}
    return {"omitted": True, "kind": type(value).__name__}


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
