from __future__ import annotations

from typing import Any

from sunpack.contracts.tasks import ArchiveTask
from sunpack.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, write_payload


def write_relation_task(task: ArchiveTask) -> None:
    knowledge = ensure_knowledge(task)
    split_info = task.split_info
    relation_payload: dict[str, Any] = {
        "kind": str(task.fact_bag.get("candidate.kind") or ("split_archive" if split_info.is_split else "file")),
        "is_split": bool(split_info.is_split),
        "is_sfx_stub": bool(split_info.is_sfx_stub),
        "archive_input": task.archive_input().to_dict(),
        "source": str(split_info.source or ""),
        "carrier_path": str(task.carrier_path or ""),
        "companion_paths": list(task.fact_bag.get("candidate.companion_paths") or []),
        "cleanup_paths": list(task.cleanup_parts or []),
    }
    write_payload(knowledge, "relations", relation_payload, source_layer="relations", source_module="task")
    source_derivation = _source_derivation_payload(task, relation_payload)
    write_payload(
        knowledge,
        "source.derivation",
        source_derivation,
        source_layer="relations",
        source_module="task",
    )
    tags = source_derivation.get("zip_container_tags") if isinstance(source_derivation.get("zip_container_tags"), list) else []
    if tags:
        write_payload(knowledge, "format.zip", {"container_tags": tags}, source_layer="relations", source_module="task")
    commit_task_knowledge(task, knowledge)


def _source_derivation_payload(task: ArchiveTask, relation_payload: dict[str, Any]) -> dict[str, Any]:
    tags: list[str] = []
    if relation_payload.get("is_split"):
        tags.append("split_archive")
    if relation_payload.get("is_sfx_stub"):
        tags.extend(["sfx", "carrier_archive"])
    return {
        "source": relation_payload.get("source") or "",
        "zip_container_tags": tags,
        "parts": list(task.all_parts or []),
        "cleanup_parts": list(task.cleanup_parts or []),
        "carrier_path": str(task.carrier_path or ""),
        "companion_paths": list(task.fact_bag.get("candidate.companion_paths") or []),
    }
