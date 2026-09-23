from __future__ import annotations

import sunpack.runtime.gui.main as gui_main


def test_watch_gui_main_forwards_to_the_shared_runtime_host(monkeypatch, tmp_path):
    captured = {}
    monkeypatch.setattr(gui_main, "runtime_working_directory", lambda: str(tmp_path))
    monkeypatch.setattr(gui_main.os, "chdir", lambda path: captured.setdefault("cwd", path))
    monkeypatch.setattr(
        gui_main,
        "_run_watch_service",
        lambda *, once, no_tray, initial_scan: captured.update(
            once=once,
            no_tray=no_tray,
            initial_scan=initial_scan,
        ) or 7,
    )

    assert gui_main.main(["--once", "--no-tray"]) == 7
    assert captured == {
        "cwd": str(tmp_path),
        "once": True,
        "no_tray": True,
        "initial_scan": False,
    }
