from pathlib import Path

from sunpack.config.cli_settings import load_cli_language_from_config
from sunpack.i18n import I18nContext
from sunpack.support.resource_lifecycle import open_service_file, read_task_text, write_task_text

from sunpack.passwords.internal.lists import dedupe_passwords, read_password_file
from sunpack.support.resources import get_resource_path


DEFAULT_BUILTIN_PASSWORDS = ["123456", "123", "0000", "789"]
WATCH_CLIPBOARD_BLOCK_BEGIN = "# BEGIN SUNPACK WATCH CLIPBOARD PASSWORDS"
WATCH_CLIPBOARD_BLOCK_END = "# END SUNPACK WATCH CLIPBOARD PASSWORDS"


def get_builtin_passwords() -> list[str]:
    builtin_path = builtin_password_path()
    if not builtin_path.exists():
        _ensure_builtin_password_file(builtin_path)
        return list(DEFAULT_BUILTIN_PASSWORDS)

    try:
        passwords = read_password_file(str(builtin_path))
    except Exception:
        return list(DEFAULT_BUILTIN_PASSWORDS)
    return passwords or list(DEFAULT_BUILTIN_PASSWORDS)


def builtin_password_path() -> Path:
    return get_resource_path("builtin_passwords.txt")


def merge_watch_clipboard_passwords(passwords: list[str], *, max_entries: int = 30) -> bool:
    """Persist recent watch clipboard passwords in a managed builtin-password block."""
    if max_entries <= 0:
        return False
    builtin_path = builtin_password_path()
    if not builtin_path.exists():
        _ensure_builtin_password_file(builtin_path)
    try:
        original = read_task_text(builtin_path, encoding="utf-8")
    except Exception:
        original = ""
    existing = _read_watch_clipboard_block(original)
    merged = dedupe_passwords([*existing, *passwords])
    managed = merged[-max_entries:]
    updated = _replace_watch_clipboard_block(original, managed)
    if updated == original:
        return False
    try:
        builtin_path.parent.mkdir(parents=True, exist_ok=True)
        temp = builtin_path.with_name(f".{builtin_path.name}.tmp")
        write_task_text(temp, updated, encoding="utf-8")
        temp.replace(builtin_path)
        return True
    except Exception:
        return False


def _ensure_builtin_password_file(path: Path) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open_service_file(path, "w", encoding="utf-8") as handle:
            i18n = I18nContext(load_cli_language_from_config())
            handle.write(i18n.t("passwords.builtin_file_header") + "\n")
            for password in DEFAULT_BUILTIN_PASSWORDS:
                handle.write(password + "\n")
    except Exception:
        pass


def _read_watch_clipboard_block(text: str) -> list[str]:
    lines = text.splitlines()
    try:
        begin = lines.index(WATCH_CLIPBOARD_BLOCK_BEGIN)
        end = lines.index(WATCH_CLIPBOARD_BLOCK_END, begin + 1)
    except ValueError:
        return []
    return [line for line in lines[begin + 1:end] if line and not line.lstrip().startswith("#")]


def _replace_watch_clipboard_block(text: str, passwords: list[str]) -> str:
    lines = text.splitlines()
    block = [WATCH_CLIPBOARD_BLOCK_BEGIN, *passwords, WATCH_CLIPBOARD_BLOCK_END]
    try:
        begin = lines.index(WATCH_CLIPBOARD_BLOCK_BEGIN)
        end = lines.index(WATCH_CLIPBOARD_BLOCK_END, begin + 1)
        lines[begin:end + 1] = block
    except ValueError:
        if lines and lines[-1] != "":
            lines.append("")
        lines.extend(block)
    return "\n".join(lines).rstrip("\n") + "\n"
