from __future__ import annotations

from pathlib import Path

from sunpack.coordinator.task_provider import ArchiveTaskProvider
from tests.helpers.detection_config import with_detection_pipeline


def detection_pipeline_config() -> dict:
    return {"detection": {"enabled": True}, "embedded_scan": {"enabled": True}}


def detect_archive_hits(path: Path):
    results = ArchiveTaskProvider(detection_pipeline_config()).detect_targets([str(path)])
    return [item for item in results if item.decision.should_extract]
