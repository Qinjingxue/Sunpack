from __future__ import annotations

from pathlib import Path
from typing import Any, TYPE_CHECKING

from sunpack_native import fast_hash128

from sunpack.core.contracts.archive_knowledge import ArchiveKnowledge

if TYPE_CHECKING:
    from sunpack.core.contracts.tasks import ArchiveTask


def task_knowledge(task: ArchiveTask | ArchiveKnowledge) -> ArchiveKnowledge:
    return task if isinstance(task, ArchiveKnowledge) else task.knowledge()


def get(task_or_knowledge: ArchiveTask | ArchiveKnowledge, path: str, default: Any = None) -> Any:
    knowledge = task_knowledge(task_or_knowledge)
    value = knowledge.get(path, default)
    return default if value is None else value


def source_password_probe_input(task: ArchiveTask) -> dict[str, Any]:
    return _dict(get(task, "source.password_probe_input", {}))


def source_fingerprint(task: ArchiveTask) -> dict[str, Any]:
    return _task_source_fingerprint(task)


def source_selected_segment(task: ArchiveTask) -> dict[str, Any]:
    return _dict(get(task, "source.selected_segment", {}))


def source_extractable_segments(task: ArchiveTask) -> list[dict[str, Any]]:
    value = get(task, "source.extractable_segments", [])
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def inspection_prepass(task: ArchiveTask) -> dict[str, Any]:
    return _dict(get(task, "inspection.prepass", {}))


def inspection_status(task: ArchiveTask) -> str:
    return str(get(task, "inspection.status", "") or get(task, "inspection.summary.status", "") or "")


def inspection_error(task: ArchiveTask) -> str:
    return str(get(task, "inspection.error", "") or get(task, "inspection.summary.error", "") or "")


def selected_format(task: ArchiveTask) -> str:
    descriptor = task.archive_input()
    return str(
        get(task, "inspection.selected_format", "")
        or get(task, "inspection.summary.format", "")
        or descriptor.format_hint
        or ""
    )


def verification_summary(task: ArchiveTask) -> dict[str, Any]:
    return _dict(get(task, "verification.summary", {}))


def zip_runtime_facts(task: ArchiveTask) -> dict[str, Any]:
    return _format_runtime_facts_uncached(task_knowledge(task), "zip")


def archive_password(task: ArchiveTask) -> str | None:
    value = get(task, "archive.password")
    return str(value) if value is not None else None


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _format_runtime_facts_uncached(knowledge: ArchiveKnowledge, format_name: str) -> dict[str, Any]:
    prefix = f"format.{format_name}"
    structure = _dict(knowledge.get(f"{prefix}.structure", {}))
    tags = knowledge.get(f"{prefix}.container_tags", [])
    route_flags = knowledge.get(f"{prefix}.route_evidence_flags", [])
    return {
        "structure": structure,
        "container_tags": [str(item) for item in tags if str(item)] if isinstance(tags, list) else [],
        "route_evidence_flags": [str(item) for item in route_flags if str(item)] if isinstance(route_flags, list) else [],
    }


def _task_source_fingerprint(task: ArchiveTask) -> dict[str, Any]:
    descriptor = task.archive_input()
    return _source_input_fingerprint(descriptor.to_dict())


def _source_input_fingerprint(source_input: dict[str, Any]) -> dict[str, Any]:
    kind = str(source_input.get("kind") or source_input.get("open_mode") or "file")
    if kind in {"bytes", "memory"}:
        data = source_input.get("data", b"")
        if isinstance(data, bytearray):
            data = bytes(data)
        if isinstance(data, bytes):
            return {"kind": kind, "xxh128": fast_hash128(data), "size": len(data), "format_hint": source_input.get("format_hint")}
        return {"kind": kind, "data": str(data), "format_hint": source_input.get("format_hint")}
    if kind in {"file", ""}:
        return {"kind": "file", **_path_fingerprint(str(source_input.get("path") or source_input.get("entry_path") or "")), "format_hint": source_input.get("format_hint") or source_input.get("format")}
    if kind == "file_range":
        return {
            "kind": "file_range",
            **_path_fingerprint(str(source_input.get("path") or source_input.get("entry_path") or "")),
            "start": int(source_input.get("start") or 0),
            "end": source_input.get("end"),
            "format_hint": source_input.get("format_hint") or source_input.get("format"),
        }
    if kind == "concat_ranges":
        return {
            "kind": "concat_ranges",
            "ranges": [
                {**_path_fingerprint(str(item.get("path") or "")), "start": int(item.get("start") or 0), "end": item.get("end")}
                for item in source_input.get("ranges") or []
                if isinstance(item, dict)
            ],
            "format_hint": source_input.get("format_hint") or source_input.get("format"),
        }
    parts = source_input.get("parts")
    return {
        "kind": kind,
        "parts": [
            {**_path_fingerprint(str(item.get("path") or "")), "role": item.get("role"), "volume_number": item.get("volume_number")}
            for item in parts or []
            if isinstance(item, dict)
        ],
        "format_hint": source_input.get("format_hint") or source_input.get("format"),
    }


def _path_fingerprint(path: str) -> dict[str, Any]:
    if not path:
        return {"path": ""}
    candidate = Path(path)
    try:
        stat = candidate.stat()
        return {"path": str(candidate), "size": int(stat.st_size), "mtime_ns": int(stat.st_mtime_ns)}
    except OSError:
        return {"path": str(candidate), "missing": True}
