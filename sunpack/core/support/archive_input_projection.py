from __future__ import annotations

from dataclasses import asdict

from sunpack.core.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.support.archive_knowledge_writer import (
    commit_task_knowledge,
    ensure_knowledge,
    write_payload,
    write_value,
)


def write_source_extractable_segments(task: ArchiveTask, segments: list[dict]) -> None:
    knowledge = ensure_knowledge(task)
    values = list(segments or [])
    write_value(
        knowledge,
        "source.extractable_segments",
        values,
        source_layer="detection",
        source_module="archive_input_planner",
    )
    write_value(
        knowledge,
        "source.extractable_segment_count",
        len(values),
        source_layer="detection",
        source_module="archive_input_planner",
    )
    commit_task_knowledge(task, knowledge)


def write_source_password_probe_input(task: ArchiveTask, archive_input: dict | None) -> None:
    """Publish the logical archive view used only for bounded password probes."""
    knowledge = ensure_knowledge(task)
    write_value(
        knowledge,
        "source.password_probe_input",
        dict(archive_input or {}),
        source_layer="detection",
        source_module="archive_input_planner",
    )
    commit_task_knowledge(task, knowledge)


def write_source_selected_segment(
    task: ArchiveTask,
    evidence: ArchiveFormatEvidence,
    segment: ArchiveSegment,
    *,
    index: int,
) -> None:
    knowledge = ensure_knowledge(task)
    write_payload(
        knowledge,
        "source.selected_segment",
        {
            "index": int(index),
            "format": evidence.format,
            "confidence": float(evidence.confidence or 0.0),
            "status": evidence.status,
            "segment": asdict(segment),
        },
        source_layer="detection",
        source_module="archive_input_planner",
        confidence=float(evidence.confidence or 0.0),
    )
    commit_task_knowledge(task, knowledge)
