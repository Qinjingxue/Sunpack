from pathlib import Path
from typing import Any

from sunpack.core.config.fields.cli import DEFAULT_CLI_LANGUAGE
from sunpack.core.config.loader import load_raw_config_payload
from sunpack.core.i18n import normalize_language


DEFAULT_CLI_LANG = DEFAULT_CLI_LANGUAGE


def normalize_cli_language(value: Any) -> str:
    return normalize_language(value)


def load_cli_language_from_config(request_cwd: str | Path | None = None) -> str:
    try:
        _config_path, payload = load_raw_config_payload(request_cwd)
    except Exception:
        return DEFAULT_CLI_LANG
    cli_settings = payload.get("cli") if isinstance(payload, dict) else None
    if not isinstance(cli_settings, dict):
        return DEFAULT_CLI_LANG
    return normalize_cli_language(cli_settings.get("language"))
