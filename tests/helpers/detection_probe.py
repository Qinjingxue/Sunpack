from __future__ import annotations

from pathlib import Path

from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider


def detection_pipeline_config() -> dict:
    return {"detection": {"enabled": True}, "embedded_scan": {"enabled": True}}


def detect_archive_hits(path: Path):
    result = ArchiveTaskProvider(detection_pipeline_config()).discover_targets([str(path)])
    return list(result.resolved_tasks)
