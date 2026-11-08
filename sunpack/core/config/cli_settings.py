from pathlib import Path

from sunpack.core.config.fields.cli import DEFAULT_CLI_LANGUAGE
from sunpack.core.config.loader import _config_snapshot
from sunpack.core.i18n import normalize_language


def load_cli_language_from_config(request_cwd: str | Path | None = None) -> str:
    try:
        cli_settings = _config_snapshot(request_cwd).raw.get("cli")
    except Exception:
        return DEFAULT_CLI_LANGUAGE
    if not isinstance(cli_settings, dict):
        return DEFAULT_CLI_LANGUAGE
    return normalize_language(cli_settings.get("language"))
