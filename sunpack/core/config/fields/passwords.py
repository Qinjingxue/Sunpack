from typing import Any

from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.core.config.schema import ConfigField


DEFAULT_PASSWORDS_CONFIG = advanced_config_value(("passwords",))


def normalize_passwords_config(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("passwords must be an object")
    config = dict(DEFAULT_PASSWORDS_CONFIG)
    config.update(value)
    config["clipboard_passwords_enabled"] = bool(config["clipboard_passwords_enabled"])
    config["directory_passwords_enabled"] = bool(config["directory_passwords_enabled"])
    config["directory_passwords_max_file_bytes"] = _positive_int(
        config["directory_passwords_max_file_bytes"], "passwords.directory_passwords_max_file_bytes"
    )
    config["directory_passwords_max_password_length"] = _positive_int(
        config["directory_passwords_max_password_length"], "passwords.directory_passwords_max_password_length"
    )
    return config


def _positive_int(value: Any, path: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{path} must be a positive integer") from exc
    if parsed <= 0:
        raise ValueError(f"{path} must be a positive integer")
    return parsed


CONFIG_FIELDS = (
    ConfigField(
        path=("passwords",),
        default=DEFAULT_PASSWORDS_CONFIG,
        normalize=normalize_passwords_config,
        owner=__name__,
    ),
)
