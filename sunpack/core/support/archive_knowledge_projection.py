from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from sunpack.core.contracts.tasks import ArchiveTask


def inspection_prepass(task: ArchiveTask) -> dict[str, Any]:
    value = task.knowledge().get("inspection.prepass")
    return value if isinstance(value, dict) else {}


def archive_password(task: ArchiveTask) -> str | None:
    value = task.knowledge().get("archive.password")
    return str(value) if value is not None else None
