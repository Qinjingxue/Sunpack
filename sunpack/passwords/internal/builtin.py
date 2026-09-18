from pathlib import Path

from sunpack.config.cli_settings import load_cli_language_from_config
from sunpack.i18n import I18nContext
from sunpack.support.resource_lifecycle import open_service_file, read_task_text, write_task_text

from sunpack.passwords.internal.lists import dedupe_passwords, read_password_file
from sunpack.support.resources import get_resource_path


DEFAULT_BUILTIN_PASSWORDS = ["123456", "123", "0000", "789"]
WATCH_CLIPBOARD_BLOCK_BEGIN = "# BEGIN SUNPACK WATCH CLIPBOARD PASSWORDS"
WATCH_CLIPBOARD_BLOCK_END = "# END SUNPACK WATCH CLIPBOARD PASSWORDS"
WATCH_CLIPBOARD_BLOCK_BEGIN_ZH = "# 开始 SUNPACK 监控剪贴板密码"
WATCH_CLIPBOARD_BLOCK_END_ZH = "# 结束 SUNPACK 监控剪贴板密码"
WATCH_CLIPBOARD_BLOCK_MARKERS = (
    (WATCH_CLIPBOARD_BLOCK_BEGIN, WATCH_CLIPBOARD_BLOCK_END),
    (WATCH_CLIPBOARD_BLOCK_BEGIN_ZH, WATCH_CLIPBOARD_BLOCK_END_ZH),
)


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


def _watch_clipboard_block_markers() -> tuple[str, str]:
    i18n = I18nContext(load_cli_language_from_config())
    return (
        i18n.t("passwords.watch_clipboard_block_begin"),
        i18n.t("passwords.watch_clipboard_block_end"),
    )


def _find_watch_clipboard_block(lines: list[str]) -> tuple[int, int] | None:
    for begin_marker, end_marker in WATCH_CLIPBOARD_BLOCK_MARKERS:
        try:
            begin = lines.index(begin_marker)
            end = lines.index(end_marker, begin + 1)
        except ValueError:
            continue
        return begin, end
    return None


def _read_watch_clipboard_block(text: str) -> list[str]:
    lines = text.splitlines()
    bounds = _find_watch_clipboard_block(lines)
    if bounds is None:
        return []
    begin, end = bounds
    return [line for line in lines[begin + 1:end] if line and not line.lstrip().startswith("#")]


def _replace_watch_clipboard_block(text: str, passwords: list[str]) -> str:
    lines = text.splitlines()
    begin_marker, end_marker = _watch_clipboard_block_markers()
    block = [begin_marker, *passwords, end_marker]
    bounds = _find_watch_clipboard_block(lines)
    if bounds is not None:
        begin, end = bounds
        lines[begin:end + 1] = block
    else:
        if lines and lines[-1] != "":
            lines.append("")
        lines.extend(block)
    return "\n".join(lines).rstrip("\n") + "\n"
