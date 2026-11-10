import asyncio
from collections import OrderedDict
from io import StringIO
from types import SimpleNamespace

import pytest

from sunpack.core.config import loader
from sunpack.core.passwords.internal import builtin
from sunpack.runtime.cli import persistent_runtime as runtime
from sunpack.runtime.cli.cli_constants import EXIT_USAGE
from sunpack.runtime.cli.cli_context import CliContext
from sunpack.runtime.cli.cli_reporter import CliReporter
from sunpack.runtime.cli.commands import config, doctor


def test_cold_snapshot_reads_the_sources_it_registered(tmp_path, monkeypatch):
    preferred = tmp_path / "preferred.json"
    fallback = tmp_path / "fallback.json"
    fallback.write_text('{"cli":{"language":"en"}}', encoding="utf-8")
    monkeypatch.delenv(loader.OVERRIDES_ENV_VAR, raising=False)
    monkeypatch.setattr(loader, "_searched_config_paths", lambda filename, cwd=None:
        [preferred, fallback] if filename == loader.SIMPLE_CONFIG_FILENAME else [])
    monkeypatch.setattr(runtime, "server_runtime_active", lambda: True)
    monkeypatch.setattr(runtime, "_CONFIG_SNAPSHOTS", OrderedDict())
    monkeypatch.setattr(runtime, "_CONFIG_DIRTY_SOURCES", set())
    monkeypatch.setattr(builtin, "password_file_source", lambda: SimpleNamespace(snapshot=None))
    monkeypatch.setattr(runtime, "_observe_config_sources", lambda:
        preferred.write_text('{"cli":{"language":"zh"}}', encoding="utf-8"))

    # A higher-priority file can appear while the cold reader arms its watcher.
    assert runtime.load_request_config()["cli"]["language"] == "en"
    assert runtime.load_request_config()["cli"]["language"] == "zh"
    preferred.unlink()
    assert runtime.load_request_config()["cli"]["language"] == "en"


@pytest.mark.parametrize("invalid", ['{"cli":', '{"verification":{},"embedded_scan":{"recursive_candidate_ratio":"many"}}'])
def test_explicit_diagnostics_reject_current_file_without_losing_last_good_config(tmp_path, monkeypatch, invalid):
    """A retained runtime snapshot must not make explicit diagnostics pass.

    Cover partial writes, schema failures, and recovery through the real loader
    and command boundaries together, without starting a worker or observer.
    """
    path = tmp_path / loader.SIMPLE_CONFIG_FILENAME
    path.write_text('{"cli":{"language":"en"}}', encoding="utf-8")
    monkeypatch.delenv(loader.OVERRIDES_ENV_VAR, raising=False)
    monkeypatch.setattr(loader, "_searched_config_paths", lambda filename, request_cwd=None: [tmp_path / filename])
    monkeypatch.setattr(runtime, "server_runtime_active", lambda: True)
    monkeypatch.setattr(runtime, "_CONFIG_SNAPSHOTS", OrderedDict())
    monkeypatch.setattr(runtime, "_CONFIG_DIRTY_SOURCES", set())
    monkeypatch.setattr(runtime, "_observe_config_sources", lambda: None)
    monkeypatch.setattr(builtin, "password_file_source", lambda: SimpleNamespace(snapshot=None))
    stdout, stderr = StringIO(), StringIO()
    ctx = CliContext(
        language="en", cwd=str(tmp_path), stdout=stdout, stderr=stderr,
        reporter=CliReporter(stdout=stdout, stderr=stderr),
    )

    def run_config(action):
        return asyncio.run(config.handle(SimpleNamespace(config_action=action, json=True, quiet=True), ctx))

    loader.clear_config_cache()
    try:
        assert runtime.load_request_config(ctx.cwd)["cli"]["language"] == "en"
        assert run_config("validate")[0] == 0
        assert doctor._config_check(ctx)[0]["status"] == "ok"

        path.write_text(invalid, encoding="utf-8")
        runtime._CONFIG_DIRTY_SOURCES.add(runtime.resolve_config_sources(ctx.cwd))
        assert runtime.load_request_config(ctx.cwd)["cli"]["language"] == "en"
        for action in ("show", "validate"):
            code, result = run_config(action)
            assert code == EXIT_USAGE
            assert result.errors
        check, payload, valid = doctor._config_check(ctx)
        assert check["status"] == "fail" and check["detail"]
        assert payload is None and not valid
        assert runtime.load_request_config(ctx.cwd)["cli"]["language"] == "en"

        # No event is required for an explicit diagnostic to see the repair.
        path.write_text('{"cli":{"language":"zh"}}', encoding="utf-8")
        code, result = run_config("show")
        assert code == 0 and result.items[0]["cli"]["language"] == "zh"
        assert run_config("validate")[0] == 0
        assert doctor._config_check(ctx)[0]["status"] == "ok"
        assert runtime.load_request_config(ctx.cwd)["cli"]["language"] == "zh"
    finally:
        loader.clear_config_cache()
