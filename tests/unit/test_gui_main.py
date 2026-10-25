import json

import sunpack.runtime.gui.main as gui_main


def test_gui_main_runs_shared_watch_service(monkeypatch):
    calls = []
    monkeypatch.setattr(
        gui_main,
        "_run_watch_service",
        lambda *, once, no_tray: calls.append((once, no_tray)) or 0,
    )

    assert gui_main.main([]) == 0
    assert calls == [(False, False)]


def test_gui_main_logs_bootstrap_failure(tmp_path, monkeypatch):
    def fail(*, once, no_tray):
        raise RuntimeError("startup failed")

    monkeypatch.setattr(gui_main, "_run_watch_service", fail)
    monkeypatch.setattr(gui_main, "get_resource_path", lambda _name: tmp_path / ".sunpack_watch")

    assert gui_main.main([]) == 1
    from tests.display_history import records
    record = records(tmp_path / ".sunpack_watch" / "bootstrap.events.json")[0]
    assert record["event"] == "gui_bootstrap_error"
    assert record["error_type"] == "RuntimeError"
    assert record["error"] == "startup failed"
