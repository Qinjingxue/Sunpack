from __future__ import annotations

from dataclasses import asdict

from sunpack.core.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.input_plan import LogicalArchiveInput
from sunpack.core.support.archive_knowledge_writer import (
    commit_task_knowledge,
    ensure_knowledge,
    write_payload,
)


def write_source_inputs(task: ArchiveTask, inputs: list[LogicalArchiveInput]) -> None:
    if inputs:
        task.set_inputs(tuple(inputs))


def write_source_password_probe_input(task: ArchiveTask, archive_input: ArchiveInputDescriptor | None) -> None:
    """Publish the logical archive view used only for bounded password probes."""
    task.password_probe_input = archive_input


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
            "status": evidence.status,
            "segment": asdict(segment),
        },
        source_layer="detection",
        source_module="archive_input_planner",
    )
    commit_task_knowledge(task, knowledge)
