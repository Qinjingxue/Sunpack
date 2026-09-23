import json

import sunpack.runtime.gui.main as gui_main


def test_gui_main_runs_shared_watch_service(monkeypatch):
    calls = []
    monkeypatch.setattr(
        gui_main,
        "_run_watch_service",
        lambda *, once, no_tray, initial_scan: calls.append((once, no_tray, initial_scan)) or 0,
    )

    assert gui_main.main([]) == 0
    assert calls == [(False, False, False)]


def test_gui_main_logs_bootstrap_failure(tmp_path, monkeypatch):
    def fail(*, once, no_tray, initial_scan):
        raise RuntimeError("startup failed")

    monkeypatch.setattr(gui_main, "_run_watch_service", fail)
    monkeypatch.setattr(gui_main, "get_resource_path", lambda _name: tmp_path / ".sunpack_watch")

    assert gui_main.main([]) == 1
    record = json.loads((tmp_path / ".sunpack_watch" / "events.jsonl").read_text(encoding="utf-8"))
    assert record["event"] == "gui_bootstrap_error"
    assert record["error_type"] == "RuntimeError"
    assert record["error"] == "startup failed"
