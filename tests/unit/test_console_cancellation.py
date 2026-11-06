from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sunpack.core.platform.windows import console_cancel


@pytest.mark.parametrize("failure_stage", ["register", "start", "prompt"])
def test_console_startup_failures_release_resources(monkeypatch, failure_stage):
    # Stream protocol tests do not fail OS setup or listener restarts. Exercise
    # both ownership boundaries without a console, sleeps, or background input.
    handles = set()
    handlers = set()
    starts = []

    def acquire(handle):
        handles.add(handle)
        return handle

    def register(handler, enabled):
        if enabled:
            if failure_stage == "register":
                return False
            handlers.add(id(handler))
        else:
            if id(handler) not in handlers:
                return False
            handlers.remove(id(handler))
        return True

    kernel = Mock()
    kernel.GetConsoleMode.return_value = True
    kernel.CreateEventW.side_effect = lambda *_: acquire(101)
    kernel.OpenThread.side_effect = lambda *_: acquire(102)
    kernel.SetConsoleCtrlHandler.side_effect = register
    kernel.CloseHandle.side_effect = handles.remove
    monkeypatch.setattr(console_cancel.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel)
    monkeypatch.setattr(console_cancel.ctypes, "WinError", lambda *_: OSError("registration failed"))

    class Thread:
        started = False

        def __init__(self, **_kwargs):
            pass

        def start(self):
            starts.append(self)
            if failure_stage == "start" or (failure_stage == "prompt" and len(starts) == 2):
                raise RuntimeError("listener start failed")
            self.started = True

        def join(self):
            assert self.started, "attempted to join an unstarted thread"
            self.started = False

    monkeypatch.setattr(console_cancel, "threading", SimpleNamespace(Thread=Thread, Event=console_cancel.threading.Event))
    controls = console_cancel.ConsoleCancellation(lambda: None)
    error = OSError if failure_stage == "register" else RuntimeError
    with pytest.raises(error, match="registration failed|listener start failed"):
        with controls:
            if failure_stage == "prompt":
                with controls.prompt():
                    assert not any(thread.started for thread in starts)

    assert handles == set()
    assert handlers == set()
    assert not any(thread.started for thread in starts)
    assert controls._thread is None
    assert controls._handler is None
    assert controls._stop is None
    assert controls._main_thread is None
    controls.__exit__()
