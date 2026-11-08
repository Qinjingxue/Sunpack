from typing import Any

from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.core.config.schema import ConfigField, require_boolean


VERIFICATION_DEFAULTS = advanced_config_value(("verification",))
METHOD_DEFAULTS = {item["name"]: item for item in VERIFICATION_DEFAULTS["methods"]}


def normalize_verification_config(value: Any) -> dict[str, Any]:
    if value is None:
        raise ValueError("Missing required config object: verification")
    if not isinstance(value, dict):
        raise ValueError("verification must be an object")
    unknown = set(value) - set(VERIFICATION_DEFAULTS)
    if unknown:
        raise ValueError(
            f"verification has unknown fields: {', '.join(sorted(unknown))}"
        )
    config = {**VERIFICATION_DEFAULTS, **value}
    config["enabled"] = require_boolean(config["enabled"], "verification.enabled")
    config["methods"] = _normalize_methods(config.get("methods"))
    return config


def _normalize_methods(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("verification.methods must be a list")
    methods = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"verification.methods[{index}] must be an object")
        name = str(item.get("name") or "").strip()
        if not name:
            raise ValueError(f"verification.methods[{index}].name must not be empty")
        defaults = METHOD_DEFAULTS.get(name)
        if defaults is not None:
            unknown = item.keys() - defaults.keys()
            if unknown:
                raise ValueError(
                    f"verification.methods[{index}] has unknown fields: {', '.join(sorted(unknown))}"
                )
        normalized = {**(defaults or {}), **item}
        normalized["name"] = name
        normalized["enabled"] = require_boolean(
            item.get("enabled", True),
            f"verification.methods[{index}].enabled",
        )
        methods.append(normalized)
    return methods


CONFIG_FIELDS = (
    ConfigField(
        path=("verification",),
        default=None,
        normalize=normalize_verification_config,
        owner=__name__,
    ),
)
