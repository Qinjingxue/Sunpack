from typing import Any

from sunpack.core.config.fields.filesystem import (
    DIRECTORY_SCAN_CURRENT_DIR_ONLY,
)


def detection_config(config: dict[str, Any]) -> dict[str, Any]:
    return config["detection"]


def filesystem_config(config: dict[str, Any]) -> dict[str, Any]:
    return config["filesystem"]


def discovery_run_config(config: dict[str, Any], *, deep_detect: bool) -> dict[str, Any]:
    """Apply detection policy to one request without changing its config source."""
    if not deep_detect or not scan_filters_enabled(config):
        return config
    return {
        **config,
        "filesystem": {**filesystem_config(config), "scan_filters_enabled": False},
    }


def directory_scan_mode(config: dict[str, Any]) -> str:
    return filesystem_config(config)["directory_scan_mode"]


def directory_scan_is_recursive(config: dict[str, Any]) -> bool:
    return directory_scan_mode(config) != DIRECTORY_SCAN_CURRENT_DIR_ONLY


def scan_filters_config(config: dict[str, Any]) -> list[dict[str, Any]]:
    if not scan_filters_enabled(config):
        return []
    return filesystem_config(config)["scan_filters"]


def scan_filters_enabled(config: dict[str, Any]) -> bool:
    return filesystem_config(config)["scan_filters_enabled"]


def scan_filter_config(config: dict[str, Any], name: str) -> dict[str, Any]:
    for item in scan_filters_config(config):
        if item["name"] == name:
            return item
    return {}
