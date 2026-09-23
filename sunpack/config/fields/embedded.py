from typing import Any

from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.config.schema import ConfigField


DEFAULT_EMBEDDED_SCAN = advanced_config_value(("embedded_scan",))


def normalize_embedded_scan(value: Any) -> dict[str, bool | float]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("embedded_scan must be an object")
    unknown = set(value) - {"enabled", "recursive_candidate_ratio"}
    if unknown:
        raise ValueError(f"embedded_scan has unknown fields: {', '.join(sorted(unknown))}")
    enabled = value.get("enabled", DEFAULT_EMBEDDED_SCAN["enabled"])
    if not isinstance(enabled, bool):
        raise ValueError("embedded_scan.enabled must be boolean")
    ratio = value.get("recursive_candidate_ratio", DEFAULT_EMBEDDED_SCAN.get("recursive_candidate_ratio", 0.3))
    if isinstance(ratio, bool) or not isinstance(ratio, (int, float)) or not 0.0 <= ratio <= 1.0:
        raise ValueError("embedded_scan.recursive_candidate_ratio must be between 0 and 1")
    return {"enabled": enabled, "recursive_candidate_ratio": float(ratio)}


CONFIG_FIELDS = (
    ConfigField(
        path=("embedded_scan",),
        default=DEFAULT_EMBEDDED_SCAN,
        normalize=normalize_embedded_scan,
        owner=__name__,
    ),
)
