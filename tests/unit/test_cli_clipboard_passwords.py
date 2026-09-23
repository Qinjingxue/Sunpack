from types import SimpleNamespace

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


def test_collect_clipboard_passwords_reads_when_config_enabled(monkeypatch):
    monkeypatch.setattr(cli_runtime, "read_clipboard_passwords", lambda: ["clip-secret"])

    assert cli_runtime.collect_clipboard_passwords({"passwords": {"clipboard_passwords_enabled": True}}) == ["clip-secret"]


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
    monkeypatch.setattr(cli_runtime, "read_clipboard_passwords", lambda: ["clip-secret"])

    code, result = passwords_command.handle(_password_args(), CliContext(language="en"))

    assert code == 0
    assert result.summary["clipboard_password_count"] == 1
    assert result.items[0]["clipboard_passwords"] == ["clip-secret"]
    assert result.items[0]["combined_passwords"] == ["clip-secret"]
