from __future__ import annotations

from pathlib import Path

from sunpack.coordinator.task_provider import ArchiveTaskProvider
from tests.helpers.detection_config import with_detection_pipeline


def detection_pipeline_config() -> dict:
    """Detection-only pipeline config shared by real-archive detection probes."""
    return with_detection_pipeline(
        {"thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3}},
        precheck=[
            {"name": "zip_structure_accept", "enabled": True},
            {"name": "tar_structure_accept", "enabled": True},
            {"name": "seven_zip_structure_accept", "enabled": True},
            {"name": "rar_structure_accept", "enabled": True},
            {"name": "compression_stream_accept", "enabled": True},
            {
                "name": "embedded_payload_identity",
                "enabled": True,
                "deep_scan_single_candidate_ratio": 0.3,
            },
        ],
    )


def detect_archive_hits(path: Path):
    results = ArchiveTaskProvider(detection_pipeline_config()).detect_targets([str(path)])
    return [item for item in results if item.decision.should_extract]
