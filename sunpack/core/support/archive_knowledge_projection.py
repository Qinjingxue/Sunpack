from __future__ import annotations

import copy
import hashlib
import json
import threading
from collections import OrderedDict, Counter
from pathlib import Path
from typing import Any

from sunpack.core.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.core.support.json_values import stable_json_value as _jsonable

_PROJECTION_CACHE_MAX = 512
_PROJECTION_CACHE: OrderedDict[tuple[str, str, str], Any] = OrderedDict()
_PROJECTION_HITS: Counter[str] = Counter()
_PROJECTION_MISSES: Counter[str] = Counter()
_PROJECTION_CACHE_LOCK = threading.RLock()


def task_knowledge(task: Any) -> ArchiveKnowledge:
    if isinstance(task, ArchiveKnowledge):
        return task
    if isinstance(task, dict):
        return ArchiveKnowledge.from_any(task)
    if hasattr(task, "knowledge") and callable(task.knowledge):
        return task.knowledge()
    return ArchiveKnowledge()


def get(task_or_knowledge: Any, path: str, default: Any = None) -> Any:
    knowledge = task_knowledge(task_or_knowledge)
    value = knowledge.get(path, default)
    return default if value is None else value


def source_password_probe_input(task: Any) -> dict[str, Any]:
    return _dict(get(task, "source.password_probe_input", {}))


def source_fingerprint(task: Any) -> dict[str, Any]:
    knowledge = task_knowledge(task)
    identity = _task_source_fingerprint(task)
    return _cached_projection(
        knowledge,
        "source_fingerprint",
        lambda: identity,
        identity=identity,
    )


def source_selected_segment(task: Any) -> dict[str, Any]:
    return _dict(get(task, "source.selected_segment", {}))


def source_extractable_segments(task: Any) -> list[dict[str, Any]]:
    value = get(task, "source.extractable_segments", [])
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def inspection_prepass(task: Any) -> dict[str, Any]:
    return _dict(get(task, "inspection.prepass", {}))


def inspection_status(task: Any) -> str:
    return str(get(task, "inspection.status", "") or get(task, "inspection.summary.status", "") or "")


def inspection_error(task: Any) -> str:
    return str(get(task, "inspection.error", "") or get(task, "inspection.summary.error", "") or "")


def selected_format(task: Any) -> str:
    descriptor = _task_archive_input(task)
    return str(
        get(task, "inspection.selected_format", "")
        or get(task, "inspection.summary.format", "")
        or (getattr(descriptor, "format_hint", "") if descriptor is not None else "")
        or ""
    )


def verification_summary(task: Any) -> dict[str, Any]:
    return _dict(get(task, "verification.summary", {}))


def zip_runtime_facts(task: Any) -> dict[str, Any]:
    knowledge = task_knowledge(task)
    identity = _task_source_fingerprint(task)
    return _cached_projection(
        knowledge,
        "zip_runtime_facts",
        lambda: _format_runtime_facts_uncached(knowledge, "zip"),
        identity=identity,
    )


def archive_password(task: Any) -> str | None:
    value = get(task, "archive.password")
    return str(value) if value is not None else None


def projection_cache_stats() -> dict[str, Any]:
    with _PROJECTION_CACHE_LOCK:
        hits = dict(_PROJECTION_HITS)
        misses = dict(_PROJECTION_MISSES)
        entries = len(_PROJECTION_CACHE)
    return {
        "entries": entries,
        "max_entries": _PROJECTION_CACHE_MAX,
        "hits": sum(hits.values()),
        "misses": sum(misses.values()),
        "by_projection": {
            name: {"hits": int(hits.get(name, 0)), "misses": int(misses.get(name, 0))}
            for name in sorted(set(hits) | set(misses))
        },
    }


def clear_projection_cache() -> dict[str, Any]:
    with _PROJECTION_CACHE_LOCK:
        entries = len(_PROJECTION_CACHE)
        _PROJECTION_CACHE.clear()
        _PROJECTION_HITS.clear()
        _PROJECTION_MISSES.clear()
    return {"entries": entries}


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _cached_projection(
    knowledge: ArchiveKnowledge,
    name: str,
    compute,
    *,
    identity: dict[str, Any] | None = None,
) -> Any:
    revision_value = knowledge.revision() if hasattr(knowledge, "revision") else int(knowledge.get("_meta.revision", 0) or 0)
    if revision_value <= 0:
        return compute()
    revision = str(revision_value)
    identity_key = _stable_digest(identity or {})
    cache_key = (revision, str(name), identity_key)
    with _PROJECTION_CACHE_LOCK:
        if cache_key in _PROJECTION_CACHE:
            value = _PROJECTION_CACHE.pop(cache_key)
            _PROJECTION_CACHE[cache_key] = value
            _PROJECTION_HITS[str(name)] += 1
            return copy.deepcopy(value)
        _PROJECTION_MISSES[str(name)] += 1
    value = compute()
    with _PROJECTION_CACHE_LOCK:
        _PROJECTION_CACHE[cache_key] = copy.deepcopy(value)
        _PROJECTION_CACHE.move_to_end(cache_key)
        while len(_PROJECTION_CACHE) > _PROJECTION_CACHE_MAX:
            _PROJECTION_CACHE.popitem(last=False)
    return value


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


def _task_archive_input(task: Any):
    getter = getattr(task, "archive_input", None)
    if not callable(getter):
        return None
    try:
        return getter()
    except Exception:
        return None


def _task_source_fingerprint(task: Any) -> dict[str, Any]:
    descriptor = _task_archive_input(task)
    if descriptor is None or not hasattr(descriptor, "to_dict"):
        return {}
    return _source_input_fingerprint(descriptor.to_dict())


def _source_input_fingerprint(source_input: dict[str, Any]) -> dict[str, Any]:
    kind = str(source_input.get("kind") or source_input.get("open_mode") or "file")
    if kind in {"bytes", "memory"}:
        data = source_input.get("data", b"")
        if isinstance(data, bytearray):
            data = bytes(data)
        if isinstance(data, bytes):
            return {"kind": kind, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "format_hint": source_input.get("format_hint")}
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


def _stable_digest(payload: Any) -> str:
    return hashlib.sha256(json.dumps(_jsonable(payload), ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
