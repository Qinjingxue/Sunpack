from argparse import Namespace
import asyncio

from sunpack.runtime.cli.cli import maybe_pause
from sunpack.runtime.cli.cli_constants import EXIT_OK, EXIT_TASK_FAILED
from sunpack.runtime.cli.cli_context import CliContext
from sunpack.runtime.cli.cli_types import CliCommandResult


def _result(errors=None):
    return CliCommandResult(command="extract", inputs={}, summary={}, errors=errors or [])


def test_successful_extract_does_not_pause(monkeypatch, capsys):
    pause_calls = []
    monkeypatch.setattr("sunpack.runtime.cli.cli.os.system", pause_calls.append)

    asyncio.run(maybe_pause(Namespace(command="extract", pause_on_exit=True), CliContext(), EXIT_OK, _result()))

    assert pause_calls == []
    assert capsys.readouterr().out == ""


def test_failed_extract_still_pauses(monkeypatch):
    pause_calls = []

    asyncio.run(maybe_pause(
        Namespace(command="extract", pause_on_exit=True),
        CliContext(input_reader=lambda prompt: pause_calls.append(prompt) or ""),
        EXIT_TASK_FAILED,
        _result(["extraction failed"]),
    ))

    assert len(pause_calls) == 1
