from typing import Any

from sunpack.config.schema import normalize_config_value
from sunpack.config.fields.filesystem import (
    DIRECTORY_SCAN_CURRENT_DIR_ONLY,
    DIRECTORY_SCAN_MODES,
    DIRECTORY_SCAN_RECURSIVE,
)


DIRECTORY_SCAN_MODE_PATH = ("filesystem", "directory_scan_mode")
SCAN_FILTERS_ENABLED_PATH = ("filesystem", "scan_filters_enabled")


def detection_config(config: dict[str, Any]) -> dict[str, Any]:
    value = config.get("detection")
    return value if isinstance(value, dict) else {}


def filesystem_config(config: dict[str, Any]) -> dict[str, Any]:
    value = config.get("filesystem")
    return value if isinstance(value, dict) else {}


def directory_scan_mode(config: dict[str, Any]) -> str:
    value = filesystem_config(config).get("directory_scan_mode")
    if value in DIRECTORY_SCAN_MODES:
        return value
    return normalize_config_value(DIRECTORY_SCAN_MODE_PATH, value)


def directory_scan_is_recursive(config: dict[str, Any]) -> bool:
    return directory_scan_mode(config) != DIRECTORY_SCAN_CURRENT_DIR_ONLY


def scan_filters_config(config: dict[str, Any]) -> list[dict[str, Any]]:
    if not scan_filters_enabled(config):
        return []
    filters = filesystem_config(config).get("scan_filters")
    return filters if isinstance(filters, list) else []


def scan_filters_enabled(config: dict[str, Any]) -> bool:
    value = filesystem_config(config).get("scan_filters_enabled")
    if value is None:
        return True
    return bool(value)


def scan_filter_config(config: dict[str, Any], name: str) -> dict[str, Any]:
    for item in scan_filters_config(config):
        if isinstance(item, dict) and item.get("name") == name:
            return item
    return {}
