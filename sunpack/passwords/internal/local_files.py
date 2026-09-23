from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.passwords.internal.lists import dedupe_passwords, read_password_file


DIRECTORY_PASSWORD_CONTEXT_KEY = "directory_password_context"
DIRECTORY_PASSWORD_FILE_NAME = "sunpack-passwords.txt"
def discover_directory_passwords_for_archive(archive_path: str, config: dict | None = None) -> list[str]:
    directory = os.path.dirname(os.path.abspath(archive_path or ""))
    if not directory or not os.path.isdir(directory):
        return []
    password_config = _password_config(config)
    if not password_config["directory_passwords_enabled"]:
        return []
    max_bytes = int(password_config["directory_passwords_max_file_bytes"])
    max_password_length = int(password_config["directory_passwords_max_password_length"])

    path = Path(directory) / DIRECTORY_PASSWORD_FILE_NAME

    passwords: list[str] = []
    if _is_readable_password_file(path, max_bytes=max_bytes):
        try:
            passwords.extend(_plausible_passwords(read_password_file(str(path)), max_password_length=max_password_length))
        except Exception:
            pass
    return dedupe_passwords(passwords)


def is_directory_password_file(path: str, config: dict | None = None) -> bool:
    if not path:
        return False
    password_config = _password_config(config)
    if not password_config["directory_passwords_enabled"]:
        return False
    return Path(path).name == DIRECTORY_PASSWORD_FILE_NAME


def directory_password_context_from_task(task: Any) -> list[str]:
    runtime = getattr(task, "runtime", None)
    if not isinstance(runtime, dict):
        return []
    values = runtime.get(DIRECTORY_PASSWORD_CONTEXT_KEY)
    if not isinstance(values, list):
        return []
    return [str(value) for value in values if isinstance(value, str)]


def _password_config(config: dict | None) -> dict:
    defaults = advanced_config_value(("passwords",))
    if not isinstance(config, dict):
        return defaults
    password_config = config.get("passwords")
    if isinstance(password_config, dict):
        defaults.update(password_config)
    return defaults


def _is_readable_password_file(path: Path, *, max_bytes: int) -> bool:
    try:
        if not path.is_file():
            return False
        return path.stat().st_size <= max_bytes
    except OSError:
        return False


def _plausible_passwords(passwords: list[str], *, max_password_length: int) -> list[str]:
    result = []
    for password in passwords:
        if not password or len(password) > max_password_length:
            continue
        if any(ord(ch) < 32 and ch != "\t" for ch in password):
            continue
        result.append(password)
    return result
