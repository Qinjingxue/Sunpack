from typing import Any

from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.core.config.schema import ConfigField, require_boolean


DEFAULT_PASSWORDS_CONFIG = advanced_config_value(("passwords",))


def normalize_passwords_config(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("passwords must be an object")
    config = dict(DEFAULT_PASSWORDS_CONFIG)
    config.update(value)
    config["clipboard_passwords_enabled"] = require_boolean(
        config["clipboard_passwords_enabled"],
        "passwords.clipboard_passwords_enabled",
    )
    return config


CONFIG_FIELDS = (
    ConfigField(
        path=("passwords",),
        default=DEFAULT_PASSWORDS_CONFIG,
        normalize=normalize_passwords_config,
        owner=__name__,
    ),
)
