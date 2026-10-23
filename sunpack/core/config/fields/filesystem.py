from typing import Any

from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.core.config.schema import ConfigField, require_boolean


def normalize_scan_filters_enabled(value: Any) -> bool:
    return require_boolean(value, "filesystem.scan_filters_enabled")


def normalize_scan_filters(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("filesystem.scan_filters must be a list")
    filters = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"filesystem.scan_filters[{index}] must be an object")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"filesystem.scan_filters[{index}].name must not be empty")
        normalized = {
            **item,
            "name": name.strip(),
            "enabled": require_boolean(item.get("enabled", False), f"filesystem.scan_filters[{index}].enabled"),
        }
        if normalized["name"] == "size_range":
            from sunpack.pipeline.discovery.filesystem.filters.modules.size_range import size_bounds
            size_bounds(normalized)
        elif normalized["name"] == "mtime_range":
            from sunpack.pipeline.discovery.filesystem.filters.modules.mtime_range import time_bounds
            time_bounds(normalized)
        filters.append(normalized)
    return filters


CONFIG_FIELDS = (
    ConfigField(
        path=("filesystem", "scan_filters"),
        default=advanced_config_value(("filesystem", "scan_filters")),
        normalize=normalize_scan_filters,
        owner=__name__,
    ),
    ConfigField(
        path=("filesystem", "scan_filters_enabled"),
        default=advanced_config_value(("filesystem", "scan_filters_enabled")),
        normalize=normalize_scan_filters_enabled,
        owner=__name__,
    ),
)
