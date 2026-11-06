from __future__ import annotations

from pathlib import Path
from typing import Any, TYPE_CHECKING

from sunpack.core.contracts.archive_knowledge import ArchiveKnowledge

if TYPE_CHECKING:
    from sunpack.core.contracts.tasks import ArchiveTask


def task_knowledge(task: ArchiveTask | ArchiveKnowledge) -> ArchiveKnowledge:
    return task if isinstance(task, ArchiveKnowledge) else task.knowledge()


def get(task_or_knowledge: ArchiveTask | ArchiveKnowledge, path: str, default: Any = None) -> Any:
    knowledge = task_knowledge(task_or_knowledge)
    value = knowledge.get(path, default)
    return default if value is None else value


def source_fingerprint(task: ArchiveTask) -> tuple:
    """Hashable physical layout; stat each source once, without serializing it."""
    descriptor = task.archive_input()
    paths = {path: _path_fingerprint(path)
             for path in dict.fromkeys((descriptor.entry_path, *descriptor.part_paths()))}
    return (
        descriptor.open_mode, descriptor.format_hint, descriptor.volume_style,
        paths[descriptor.entry_path],
        tuple((paths[part.path], part.extent.start, part.extent.end,
               part.role, part.volume_number, part.canonical_name) for part in descriptor.parts),
        tuple((paths[extent.path], extent.start, extent.end) for extent in descriptor.extents),
    )


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


def _path_fingerprint(path: str) -> tuple:
    candidate = Path(path)
    try:
        stat = candidate.stat()
        return str(candidate), stat.st_size, stat.st_mtime_ns
    except OSError:
        return str(candidate), None, None
