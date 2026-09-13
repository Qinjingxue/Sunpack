from __future__ import annotations

from typing import Any

from sunpack.contracts.tasks import ArchiveTask
from sunpack.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, write_payload


def write_detection_task(task: ArchiveTask) -> None:
    knowledge = ensure_knowledge(task)
    decision = task.decision
    if not isinstance(decision, str):
        decision = getattr(task.decision, "decision", "")
    payload: dict[str, Any] = {
        "decision": str(decision or ""),
        "stop_reason": str(task.stop_reason or ""),
        "matched_rules": list(task.matched_rules or []),
        "detected_ext": str(task.detected_ext or task.fact_bag.get("file.detected_ext") or ""),
        "candidate_entry_path": str(task.fact_bag.get("candidate.entry_path") or task.main_path or ""),
        "candidate_member_paths": list(task.fact_bag.get("candidate.member_paths") or task.all_parts or []),
        "candidate_carrier_path": str(task.fact_bag.get("candidate.carrier_path") or task.carrier_path or ""),
        "candidate_companion_paths": list(task.fact_bag.get("candidate.companion_paths") or []),
        "candidate_cleanup_paths": list(task.fact_bag.get("candidate.cleanup_paths") or task.cleanup_parts or []),
        "candidate_logical_name": str(task.fact_bag.get("candidate.logical_name") or task.logical_name or ""),
    }
    write_payload(knowledge, "detection", payload, source_layer="detection", source_module="task_provider")
    if payload["detected_ext"]:
        write_payload(
            knowledge,
            "archive",
            {"format_hint": payload["detected_ext"]},
            source_layer="detection",
            source_module="task_provider",
        )
    commit_task_knowledge(task, knowledge)
