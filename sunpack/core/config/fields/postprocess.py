from typing import Any

from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.core.config.schema import ConfigField


_ARCHIVE_CLEANUP_ALIASES = {
    "d": "delete",
    "r": "recycle",
    "k": "keep",
}


def normalize_archive_cleanup_mode(value: Any) -> str:
    raw = str(value).strip().lower()
    mode = _ARCHIVE_CLEANUP_ALIASES.get(raw)
    if mode is None:
        raise ValueError("archive_cleanup_mode must be one of: d, r, k")
    return mode


CONFIG_FIELDS = (
    ConfigField(
        path=("post_extract", "archive_cleanup_mode"),
        default=advanced_config_value(("post_extract", "archive_cleanup_mode")),
        normalize=normalize_archive_cleanup_mode,
        owner=__name__,
    ),
    ConfigField(
        path=("post_extract", "flatten_single_directory"),
        default=advanced_config_value(("post_extract", "flatten_single_directory")),
        normalize=bool,
        owner=__name__,
    ),
)
