import asyncio
import io
from types import SimpleNamespace

import pytest

from sunpack.runtime.cli import cli, runtime_state
from sunpack.runtime.cli.cli_types import CliCommandResult


@pytest.mark.parametrize("argv, expected", [(["e", "sample.zip"], 1), (["s", "."], 1), (["w", "status"], 0)])
def test_workload_priority_is_applied_before_dispatch(monkeypatch, tmp_path, argv, expected):
    calls = 0

    async def set_override():
        nonlocal calls
        calls += 1

    async def dispatch(args, ctx):
        assert calls == expected
        return 0, CliCommandResult(args.command, {}, {})

    monkeypatch.setattr(cli, "_should_submit_to_persistent_server", lambda _argv: False)
    monkeypatch.setattr(cli, "dispatch_command", dispatch)
    monkeypatch.setattr(runtime_state, "_HOST", SimpleNamespace(set_cli_process_mode_override=set_override))

    assert asyncio.run(cli.async_main(argv, cwd=str(tmp_path), stdout=io.StringIO(), stderr=io.StringIO())) == 0
