from __future__ import annotations

from pathlib import Path

from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from tests.helpers.config_factory import make_config


def detection_pipeline_config() -> dict:
    return make_config({"detection": {"enabled": True}, "embedded_scan": {"enabled": True}})


def detect_archive_hits(path: Path):
    result = ArchiveTaskProvider(detection_pipeline_config()).discover_targets([str(path)])
    return list(result.resolved_tasks)
