from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sunpack.contracts.tasks import ArchiveTask
from sunpack.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, write_payload


def write_filesystem_task(task: ArchiveTask) -> None:
    knowledge = ensure_knowledge(task)
    main_path = str(task.main_path or "")
    carrier_path = str(task.carrier_path or main_path)
    stat = _stat_payload(carrier_path)
    payload: dict[str, Any] = {
        "path": carrier_path,
        "absolute_path": os.path.abspath(carrier_path) if carrier_path else "",
        "carrier_path": carrier_path,
        "detected_ext": str(task.detected_ext or task.fact_bag.get("file.detected_ext") or ""),
        "split_members": list(task.all_parts or []),
        "cleanup_paths": list(task.cleanup_parts or []),
        **stat,
    }
    write_payload(knowledge, "filesystem", payload, source_layer="filesystem", source_module="task")
    write_payload(
        knowledge,
        "source.input",
        task.archive_input().to_dict(),
        source_layer="filesystem",
        source_module="task",
    )
    commit_task_knowledge(task, knowledge)


def _stat_payload(path: str) -> dict[str, Any]:
    if not path:
        return {}
    try:
        stat = Path(path).stat()
    except OSError:
        return {"exists": False}
    return {
        "exists": True,
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
    }
