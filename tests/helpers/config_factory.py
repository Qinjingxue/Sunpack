from copy import deepcopy
from typing import Any

from tests.helpers.detection_config import with_detection_pipeline


CONFIGS: dict[str, dict[str, Any]] = {
    "minimal": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
    ]),
    "embedded_archive_loose": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
        {
            "name": "embedded_payload_identity",
            "enabled": True,
            "deep_scan_single_candidate_ratio": 1e-9,
        },
    ]),
    "embedded_archive_carrier_tail": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
        {"name": "embedded_payload_identity", "enabled": True, "deep_scan_single_candidate_ratio": 1e-9},
    ]),
    "archive_scan_full": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
    }, processors=[
        {"name": "embedded_archive", "enabled": True},
        {"name": "pe_overlay_structure", "enabled": True},
        {"name": "executable_carrier", "enabled": True},
        {"name": "zip_eocd_structure", "enabled": True},
        {"name": "compression_stream_structure", "enabled": True},
        {"name": "seven_zip_structure", "enabled": True},
        {"name": "rar_structure", "enabled": True},
    ], precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
        {"name": "zip_structure_accept", "enabled": True},
        {"name": "seven_zip_structure_accept", "enabled": True},
        {"name": "rar_structure_accept", "enabled": True},
        {"name": "compression_stream_accept", "enabled": True},
        {"name": "embedded_payload_identity", "enabled": True},
    ]),
    "archive_scan_deep_embedded": with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
    }, processors=[
        {"name": "embedded_archive", "enabled": True},
        {"name": "pe_overlay_structure", "enabled": True},
        {"name": "executable_carrier", "enabled": True},
        {"name": "zip_eocd_structure", "enabled": True},
        {"name": "compression_stream_structure", "enabled": True},
        {"name": "seven_zip_structure", "enabled": True},
        {"name": "rar_structure", "enabled": True},
    ], precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
        {"name": "zip_structure_accept", "enabled": True},
        {"name": "seven_zip_structure_accept", "enabled": True},
        {"name": "rar_structure_accept", "enabled": True},
        {"name": "compression_stream_accept", "enabled": True},
        {"name": "embedded_payload_identity", "enabled": True, "deep_scan_single_candidate_ratio": 1e-9},
    ]),
}


def get_config(name: str = "minimal", overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    config = deepcopy(CONFIGS[name])
    if overrides:
        deep_merge(config, overrides)
    return config


def deep_merge(target: dict[str, Any], source: dict[str, Any]):
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            deep_merge(target[key], value)
        else:
            target[key] = deepcopy(value)

