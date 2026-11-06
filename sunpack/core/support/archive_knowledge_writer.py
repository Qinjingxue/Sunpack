from __future__ import annotations

from contextlib import nullcontext
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from sunpack.core.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.core.support.json_values import jsonable_value as _jsonable


if TYPE_CHECKING:
    from sunpack.core.contracts.tasks import ArchiveTask


def ensure_knowledge(target: ArchiveTask | ArchiveKnowledge) -> ArchiveKnowledge:
    return target if isinstance(target, ArchiveKnowledge) else target.knowledge()


def commit_task_knowledge(
    task: ArchiveTask,
    knowledge: ArchiveKnowledge,
    *,
    phase_timer: Any | None = None,
    phase_prefix: str = "commit_task_knowledge",
) -> ArchiveKnowledge:
    payload = knowledge
    with _phase(phase_timer, f"{phase_prefix}_existing_knowledge"):
        existing = task.knowledge()
    payload.set("_meta", {**payload.get("_meta", {}), "revision": existing.revision() + 1})
    with _phase(phase_timer, f"{phase_prefix}_set_knowledge"):
        # The task owns this mutable Knowledge object. Exported dictionaries are
        # isolated by to_dict(); committing does not need an intermediate tree.
        task._knowledge = payload
    return payload


def write_value(
    target: ArchiveTask | ArchiveKnowledge,
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
    target: ArchiveTask | ArchiveKnowledge,
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
    target: ArchiveTask | ArchiveKnowledge,
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
    target: ArchiveTask | ArchiveKnowledge,
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


def write_evidence(
    target: ArchiveTask | ArchiveKnowledge,
    *,
    path: str,
    value: Any,
    source_layer: str,
    source_module: str = "",
    confidence: float | None = None,
) -> ArchiveKnowledge:
    knowledge = ensure_knowledge(target)
    provenance: dict[str, Any] = {
        "source_layer": source_layer,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if source_module:
        provenance["source_module"] = source_module
    if confidence is not None:
        provenance["confidence"] = float(confidence)
    return knowledge.add_evidence(path, value, provenance=provenance)


def _phase(timer: Any | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
