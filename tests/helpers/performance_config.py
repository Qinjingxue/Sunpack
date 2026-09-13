"""Configuration shared by integration tests and opt-in benchmark scenarios."""

from sunpack.config.schema import normalize_config
from tests.helpers.detection_config import with_detection_pipeline


def archive_pressure_config(passwords: list[str] | None = None) -> dict:
    return normalize_config(with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": "2",
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
        "user_passwords": passwords or [],
        "builtin_passwords": [],
        "max_retries": 1,
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
        {"name": "embedded_payload_identity", "enabled": True},
        {"name": "zip_structure_accept", "enabled": True},
        {"name": "seven_zip_structure_accept", "enabled": True},
        {"name": "rar_structure_accept", "enabled": True},
        {"name": "tar_structure_accept", "enabled": True},
        {"name": "compression_stream_accept", "enabled": True},
    ]))
