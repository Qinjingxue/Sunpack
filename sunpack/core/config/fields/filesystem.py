from typing import Any

from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.core.config.schema import ConfigField


DIRECTORY_SCAN_RECURSIVE = "recursive"
DIRECTORY_SCAN_CURRENT_DIR_ONLY = "current_dir_only"
DIRECTORY_SCAN_MODES = {DIRECTORY_SCAN_RECURSIVE, DIRECTORY_SCAN_CURRENT_DIR_ONLY}

_DIRECTORY_SCAN_ALIASES = {
    "*": DIRECTORY_SCAN_RECURSIVE,
    "-": DIRECTORY_SCAN_CURRENT_DIR_ONLY,
}


def normalize_directory_scan_mode(value: Any) -> str:
    raw = str(value).strip().lower()
    mode = _DIRECTORY_SCAN_ALIASES.get(raw)
    if mode is None:
        raise ValueError("filesystem.directory_scan_mode must be one of: *, -")
    return mode


CONFIG_FIELDS = (
    ConfigField(
        path=("filesystem", "scan_filters_enabled"),
        default=advanced_config_value(("filesystem", "scan_filters_enabled")),
        normalize=bool,
        owner=__name__,
    ),
    ConfigField(
        path=("filesystem", "directory_scan_mode"),
        default=advanced_config_value(("filesystem", "directory_scan_mode")),
        normalize=normalize_directory_scan_mode,
        owner=__name__,
    ),
)
