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


@pytest.mark.parametrize("already_enabled, fail_start", [(False, False), (True, False), (False, True)])
def test_resize_reuses_console_listener_and_restores_only_its_mode_bit(monkeypatch, already_enabled, fail_start):
    # Transport mocks do not exercise console mode ownership or resize input
    # dispatch. Check listener reuse and failure cleanup without OS waits.
    mode = 7 | (8 if already_enabled else 0)
    kernel = Mock()
    kernel.GetStdHandle.return_value = 100
    kernel.CreateEventW.return_value = 101
    kernel.OpenThread.return_value = 102
    kernel.SetConsoleCtrlHandler.return_value = True

    def get_mode(_handle, pointer):
        pointer._obj.value = mode
        return True

    def set_mode(_handle, value):
        nonlocal mode
        mode = value
        return True

    kernel.GetConsoleMode.side_effect = get_mode
    kernel.SetConsoleMode.side_effect = set_mode
    monkeypatch.setattr(console_cancel.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel)
    threads = []

    class Thread:
        def __init__(self, *, target, **_kwargs):
            self.target = target
            self.started = False
            threads.append(self)

        def start(self):
            if fail_start:
                raise RuntimeError("listener start failed")
            self.started = True

        def join(self):
            assert self.started
            self.started = False

    monkeypatch.setattr(console_cancel, "threading", SimpleNamespace(Thread=Thread, Event=console_cancel.threading.Event))
    changes, cancels = [], []
    controls = console_cancel.ConsoleCancellation(lambda: cancels.append(True), on_resize=lambda: changes.append(mode))
    if fail_start:
        with pytest.raises(RuntimeError, match="listener start failed"):
            controls.__enter__()
    else:
        with controls:
            assert len(threads) == 1 and mode & 8
            assert len(changes) == 1
            kernel.WaitForMultipleObjects.side_effect = [1, 1, 0]
            events = iter((4, 1))

            def read_event(_input, record, _count, count):
                record._obj.kind = next(events)
                record._obj.event.key.down = True
                record._obj.event.key.char = "Q"
                count._obj.value = 1
                return True

            kernel.ReadConsoleInputW.side_effect = read_event
            controls._listen()
            assert len(changes) == 2 and cancels == [True]
            assert len(threads) == 1
            with controls.prompt():
                assert not threads[0].started
            assert len(changes) == 3
            mode |= 0x20  # An unrelated mode change is not ours to undo.
    assert bool(mode & 8) == already_enabled
    if not fail_start:
        assert mode & 0x20
    assert all(not thread.started for thread in threads)
    assert controls._stop is None
    assert controls._main_thread is None
