from typing import Any

from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.core.config.schema import ConfigField, require_boolean


def normalize_detection_config(value: Any) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise ValueError("detection must be an object")
    if unknown := set(value) - {"enabled"}:
        raise ValueError(f"Unknown detection field(s): {', '.join(sorted(unknown))}")
    return {"enabled": require_boolean(value.get("enabled", True), "detection.enabled")}


CONFIG_FIELDS = (
    ConfigField(
        path=("detection",),
        default=advanced_config_value(("detection",)),
        normalize=normalize_detection_config,
        owner=__name__,
    ),
)
