from __future__ import annotations

from pathlib import Path
from typing import Any

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.tasks import ArchiveTask


def make_archive_task(
    path,
    *,
    parts=None,
    format_hint: str = "",
    logical_name: str = "",
    key: str = "",
    discovery_source: str = "test",
    relation_kind: str = "file",
    analysis: dict[str, Any] | None = None,
) -> ArchiveTask:
    entry_path = str(path)
    part_paths = [str(item) for item in (parts or [entry_path])]
    if len(part_paths) != 1:
        raise ValueError("make_archive_task only accepts a single physical input; use a structured descriptor for volumes")
    descriptor = ArchiveInputDescriptor(
        entry_path=entry_path,
        open_mode="file",
        format_hint=format_hint,
        logical_name=logical_name or Path(entry_path).stem,
        parts=[],
        analysis=dict(analysis or {}),
    )
    task = ArchiveTask.from_archive_input(
        descriptor,
        discovery_source=discovery_source,
        relation_kind=relation_kind,
        discovery_reason="test_fixture",
    )
    if key:
        task.key = key
    return task


def make_task_from_descriptor(
    descriptor: ArchiveInputDescriptor,
    *,
    key: str = "",
    discovery_source: str = "test",
    relation_kind: str = "file",
) -> ArchiveTask:
    task = ArchiveTask.from_archive_input(
        descriptor,
        discovery_source=discovery_source,
        relation_kind=relation_kind,
        discovery_reason="test_fixture",
    )
    if key:
        task.key = key
    return task


def merge_task_knowledge(task: ArchiveTask, payload: dict[str, Any]) -> ArchiveTask:
    knowledge = task.knowledge()
    knowledge.merge(payload, source_layer="tests", source_module="archive_tasks")
    task.set_knowledge(knowledge)
    return task
