from typing import Any

from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.core.config.schema import ConfigField


def normalize_detection_enabled(value: Any) -> bool:
    return bool(value)


CONFIG_FIELDS = (
    ConfigField(
        path=("detection", "enabled"),
        default=advanced_config_value(("detection", "enabled")),
        normalize=normalize_detection_enabled,
        owner=__name__,
    ),
)
