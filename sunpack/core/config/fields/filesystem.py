from typing import Any

from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.core.config.schema import ConfigField, require_boolean


DIRECTORY_SCAN_RECURSIVE = "recursive"
DIRECTORY_SCAN_CURRENT_DIR_ONLY = "current_dir_only"
DIRECTORY_SCAN_MODES = {DIRECTORY_SCAN_RECURSIVE, DIRECTORY_SCAN_CURRENT_DIR_ONLY}

_DIRECTORY_SCAN_ALIASES = {
    "*": DIRECTORY_SCAN_RECURSIVE,
    "-": DIRECTORY_SCAN_CURRENT_DIR_ONLY,
}


def normalize_scan_filters_enabled(value: Any) -> bool:
    return require_boolean(value, "filesystem.scan_filters_enabled")


def normalize_directory_scan_mode(value: Any) -> str:
    raw = str(value).strip().lower()
    mode = _DIRECTORY_SCAN_ALIASES.get(raw)
    if mode is None:
        raise ValueError("filesystem.directory_scan_mode must be one of: *, -")
    return mode


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
        filters.append({
            **item,
            "name": name.strip(),
            "enabled": require_boolean(item.get("enabled", False), f"filesystem.scan_filters[{index}].enabled"),
        })
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
    ConfigField(
        path=("filesystem", "directory_scan_mode"),
        default=advanced_config_value(("filesystem", "directory_scan_mode")),
        normalize=normalize_directory_scan_mode,
        owner=__name__,
    ),
)
