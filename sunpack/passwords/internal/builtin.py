from pathlib import Path

from sunpack.config.cli_settings import load_cli_language_from_config
from sunpack.i18n import I18nContext
from sunpack.support.resource_lifecycle import open_service_file, read_task_text, write_task_text

from sunpack.passwords.internal.lists import dedupe_passwords
from sunpack.support.resources import get_resource_path


DEFAULT_BUILTIN_PASSWORDS = ["123456", "123", "0000", "789"]
WATCH_CLIPBOARD_BLOCK_BEGIN = "#!SUNPACK-WATCH-CLIPBOARD-BEGIN"
WATCH_CLIPBOARD_BLOCK_END = "#!SUNPACK-WATCH-CLIPBOARD-END"

_LEGACY_WATCH_CLIPBOARD_MARKERS = {
    "# BEGIN SUNPACK WATCH CLIPBOARD PASSWORDS",
    "# END SUNPACK WATCH CLIPBOARD PASSWORDS",
    "# 开始 SUNPACK 监控剪贴板密码",
    "# 结束 SUNPACK 监控剪贴板密码",
}


def get_builtin_passwords() -> list[str]:
    builtin_path = builtin_password_path()
    if not builtin_path.exists():
        _ensure_builtin_password_file(builtin_path)
        return list(DEFAULT_BUILTIN_PASSWORDS)

    try:
        passwords = read_builtin_password_file(builtin_path)
    except Exception:
        return list(DEFAULT_BUILTIN_PASSWORDS)
    return passwords or list(DEFAULT_BUILTIN_PASSWORDS)


def builtin_password_path() -> Path:
    return get_resource_path("builtin_passwords.txt")


def read_builtin_password_file(path: str | Path) -> list[str]:
    return _parse_builtin_passwords(read_task_text(Path(path), encoding="utf-8"))


def merge_watch_clipboard_passwords(passwords: list[str], *, max_entries: int = 30) -> bool:
    """Persist recent Watch clipboard passwords inside the installer-owned block."""
    if max_entries <= 0:
        return False
    builtin_path = builtin_password_path()
    if not builtin_path.exists():
        _ensure_builtin_password_file(builtin_path)
    try:
        original = read_task_text(builtin_path, encoding="utf-8")
    except Exception:
        return False
    if _find_watch_clipboard_block(original.splitlines()) is None:
        # The installer owns the file structure. Do not invent or migrate
        # markers here based on the current CLI language.
        return False
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
            handle.write("\n")
            handle.write(i18n.t("passwords.watch_clipboard_managed_note") + "\n")
            handle.write(WATCH_CLIPBOARD_BLOCK_BEGIN + "\n")
            handle.write(WATCH_CLIPBOARD_BLOCK_END + "\n")
    except Exception:
        pass


def _reserved_builtin_lines() -> set[str]:
    reserved = {
        WATCH_CLIPBOARD_BLOCK_BEGIN,
        WATCH_CLIPBOARD_BLOCK_END,
        *_LEGACY_WATCH_CLIPBOARD_MARKERS,
    }
    for language in ("en", "zh"):
        i18n = I18nContext(language)
        reserved.add(i18n.t("passwords.builtin_file_header"))
        reserved.add(i18n.t("passwords.watch_clipboard_managed_note"))
    return reserved


def _parse_builtin_passwords(text: str) -> list[str]:
    reserved = _reserved_builtin_lines()
    return [line for line in (text or "").splitlines() if line != "" and line not in reserved]


def _find_watch_clipboard_block(lines: list[str]) -> tuple[int, int] | None:
    try:
        begin = lines.index(WATCH_CLIPBOARD_BLOCK_BEGIN)
        end = lines.index(WATCH_CLIPBOARD_BLOCK_END, begin + 1)
    except ValueError:
        return None
    return begin, end


def _read_watch_clipboard_block(text: str) -> list[str]:
    lines = text.splitlines()
    bounds = _find_watch_clipboard_block(lines)
    if bounds is None:
        return []
    begin, end = bounds
    return [line for line in lines[begin + 1:end] if line != ""]


def _replace_watch_clipboard_block(text: str, passwords: list[str]) -> str:
    lines = text.splitlines()
    bounds = _find_watch_clipboard_block(lines)
    if bounds is None:
        return text
    begin, end = bounds
    lines[begin + 1:end] = passwords
    return "\n".join(lines).rstrip("\n") + "\n"
