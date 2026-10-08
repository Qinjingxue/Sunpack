from types import SimpleNamespace

import sunpack.core.passwords.internal.clipboard as clipboard_module
import sunpack.runtime.cli.cli_runtime as cli_runtime
import sunpack.runtime.cli.commands.passwords as passwords_command
from sunpack.runtime.cli.cli_context import CliContext


def _password_args() -> SimpleNamespace:
    return SimpleNamespace(
        password=[],
        password_file=None,
        prompt_passwords=False,
        no_builtin_passwords=True,
        json=True,
    )


def test_collect_clipboard_passwords_skips_when_config_disabled(monkeypatch):
    called = False

    def _read_clipboard():
        nonlocal called
        called = True
        return ["clip-secret"]

    monkeypatch.setattr(cli_runtime, "read_clipboard_passwords", _read_clipboard)

    assert cli_runtime.collect_clipboard_passwords({"passwords": {"clipboard_passwords_enabled": False}}) == []
    assert called is False


def test_passwords_command_includes_config_enabled_clipboard_password(monkeypatch):
    monkeypatch.setattr(
        passwords_command,
        "load_request_config",
        lambda _cwd: {"passwords": {"clipboard_passwords_enabled": True}},
    )
    monkeypatch.setattr(
        clipboard_module, "_read_windows_unicode_clipboard",
        lambda *, max_chars: "\r\nfirst\n\nsecond\rfirst\r\n",
    )

    code, result = passwords_command.handle(_password_args(), CliContext(language="en"))

    assert code == 0
    assert result.summary["clipboard_password_count"] == 2
    assert result.items[0]["clipboard_passwords"] == ["first", "second"]
    assert result.items[0]["combined_passwords"] == ["first", "second"]
