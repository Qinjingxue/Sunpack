from __future__ import annotations

from contextlib import nullcontext
from datetime import datetime, timezone
from typing import Any

from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.support.json_values import jsonable_value as _jsonable


def ensure_knowledge(target: Any) -> ArchiveKnowledge:
    if isinstance(target, ArchiveKnowledge):
        return target
    if hasattr(target, "knowledge") and callable(target.knowledge):
        return target.knowledge()
    return ArchiveKnowledge.from_any(target)


def commit_task_knowledge(
    task: Any,
    knowledge: ArchiveKnowledge | dict[str, Any],
    *,
    phase_timer: Any | None = None,
    phase_prefix: str = "commit_task_knowledge",
) -> ArchiveKnowledge:
    with _phase(phase_timer, f"{phase_prefix}_ensure_payload"):
        payload = ensure_knowledge(knowledge)
    existing = ArchiveKnowledge()
    with _phase(phase_timer, f"{phase_prefix}_existing_knowledge"):
        if hasattr(task, "knowledge") and callable(task.knowledge):
            existing = task.knowledge()
        current_meta = existing.get("_meta") if isinstance(existing.get("_meta"), dict) else {}
    try:
        revision = int(current_meta.get("revision", 0) or 0) + 1
    except (TypeError, ValueError):
        revision = 1
    meta = payload.get("_meta") if isinstance(payload.get("_meta"), dict) else {}
    payload.set("_meta", {**meta, "revision": revision})
    with _phase(phase_timer, f"{phase_prefix}_set_knowledge"):
        previous_payload = task.fact_bag.get("archive.knowledge") if hasattr(task, "fact_bag") else None
        payload_dict = payload.incremental_snapshot(previous_payload if isinstance(previous_payload, dict) else None)
        if hasattr(task, "_replace_knowledge_payload") and callable(task._replace_knowledge_payload):
            task._replace_knowledge_payload(payload_dict, knowledge_cache=payload)
        elif hasattr(task, "fact_bag") and hasattr(task.fact_bag, "set"):
            task.fact_bag.set("archive.knowledge", payload_dict)
        elif hasattr(task, "set_knowledge") and callable(task.set_knowledge):
            task.set_knowledge(payload_dict)
    return payload


def write_value(
    target: Any,
    path: str,
    value: Any,
    *,
    source_layer: str,
    source_module: str = "",
    confidence: float | None = None,
) -> ArchiveKnowledge:
    knowledge = ensure_knowledge(target)
    knowledge.set(
        path,
        value,
        source_layer=source_layer,
        source_module=source_module,
        confidence=confidence,
    )
    return knowledge


def write_payload(
    target: Any,
    namespace: str,
    payload: dict[str, Any],
    *,
    source_layer: str,
    source_module: str = "",
    confidence: float | None = None,
) -> ArchiveKnowledge:
    knowledge = ensure_knowledge(target)
    for key, value in dict(payload or {}).items():
        if value in (None, "", [], {}):
            continue
        write_value(
            knowledge,
            f"{namespace}.{key}" if namespace else str(key),
            value,
            source_layer=source_layer,
            source_module=source_module,
            confidence=confidence,
        )
    return knowledge


def write_prepared_payload(
    target: Any,
    namespace: str,
    payload: dict[str, Any],
    *,
    source_layer: str,
    source_module: str = "",
    confidence: float | None = None,
) -> ArchiveKnowledge:
    """Write a newly built JSON-safe payload without recursively normalizing it again."""
    knowledge = ensure_knowledge(target)
    for key, value in payload.items():
        if value in (None, "", [], {}):
            continue
        knowledge.set_prepared(
            f"{namespace}.{key}" if namespace else str(key),
            value,
            source_layer=source_layer,
            source_module=source_module,
            confidence=confidence,
        )
    return knowledge


def prepare_knowledge_value(value: Any) -> Any:
    """Normalize a value once before one or more prepared Knowledge writes."""
    return _jsonable(value)


def write_flags(
    target: Any,
    namespace: str,
    flags: list[str] | tuple[str, ...] | set[str],
    *,
    source_layer: str,
    source_module: str = "",
    confidence: float | None = None,
) -> ArchiveKnowledge:
    knowledge = ensure_knowledge(target)
    knowledge.add_flags(
        namespace,
        [str(flag) for flag in flags or [] if str(flag)],
        source_layer=source_layer,
        source_module=source_module,
    )
    if confidence is not None:
        write_evidence(
            knowledge,
            path=f"{namespace}.flags",
            value=[str(flag) for flag in flags or [] if str(flag)],
            source_layer=source_layer,
            source_module=source_module,
            confidence=confidence,
        )
    return knowledge


def append_history(
    target: Any,
    path: str,
    item: dict[str, Any],
    *,
    source_layer: str,
    source_module: str = "",
    max_items: int = 200,
) -> ArchiveKnowledge:
    knowledge = ensure_knowledge(target)
    history = knowledge.get(path)
    values = list(history) if isinstance(history, list) else []
    values.append(_jsonable(item))
    knowledge.set(
        path,
        values[-max_items:],
        source_layer=source_layer,
        source_module=source_module,
    )
    return knowledge


def write_evidence(
    target: Any,
    *,
    path: str,
    value: Any,
    source_layer: str,
    source_module: str = "",
    confidence: float | None = None,
) -> ArchiveKnowledge:
    knowledge = ensure_knowledge(target)
    evidence = knowledge.get("_evidence")
    rows = list(evidence) if isinstance(evidence, list) else []
    provenance: dict[str, Any] = {
        "source_layer": source_layer,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if source_module:
        provenance["source_module"] = source_module
    if confidence is not None:
        provenance["confidence"] = float(confidence)
    rows.append({"path": path, "value": _compact_evidence_value(value), "provenance": provenance})
    knowledge.set("_evidence", rows[-500:])
    return knowledge


def _compact_evidence_value(value: Any) -> Any:
    if isinstance(value, ArchiveKnowledge):
        return {"kind": "archive_knowledge", "revision": value.revision(), "source_identity": value.source_identity()}
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            text_key = str(key)
            if text_key == "archive_state":
                output[text_key] = _compact_large_value(text_key, item)
            elif text_key in {"stdout", "stderr"} and isinstance(item, str):
                output[text_key] = item[:4000]
            else:
                output[text_key] = _compact_evidence_value(item)
        return output
    if isinstance(value, (list, tuple, set)):
        values = list(value)
        output = [_compact_evidence_value(item) for item in values[:50]]
        if len(values) > 50:
            output.append({"truncated_count": len(values) - 50})
        return output
    return _jsonable(value)


def _compact_large_value(key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return {"kind": key, "keys": sorted(str(item) for item in value.keys())[:50]}
    if isinstance(value, list):
        return {"kind": key, "count": len(value)}
    return _jsonable(value)


def _phase(timer: Any | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
