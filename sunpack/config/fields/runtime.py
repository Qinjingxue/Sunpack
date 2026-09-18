from typing import Any

from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.config.schema import ConfigField


DEFAULT_RUNTIME_CONFIG = advanced_config_value(("runtime",))


def normalize_runtime_config(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("runtime must be an object")
    config = dict(DEFAULT_RUNTIME_CONFIG)
    config.update(value)
    process_mode = str(config.get("process_mode") or "normal").strip().lower()
    if process_mode not in {"background", "normal", "high"}:
        raise ValueError("runtime.process_mode must be background, normal, or high")
    config["process_mode"] = process_mode
    return config


CONFIG_FIELDS = (
    ConfigField(
        path=("runtime",),
        default=DEFAULT_RUNTIME_CONFIG,
        normalize=normalize_runtime_config,
        owner=__name__,
    ),
)
