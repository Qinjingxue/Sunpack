import ctypes
import threading
from types import SimpleNamespace

import pytest

from sunpack.core.passwords.internal.clipboard_monitor import ClipboardPasswordMonitor, _WindowsClipboardLoop
from sunpack.runtime.gui.tray import WindowsTrayIcon


@pytest.mark.parametrize("kind", ["tray", "clipboard"])
def test_window_lifecycle_waits_for_startup_and_owner_cleanup(kind, monkeypatch):
    # Existing window recreation tests cover ordinary shutdown only. Gate real
    # window creation and cleanup to cover stop during startup and reference
    # release before owner-thread exit, without sleeps or long-running fixtures.
    creating, create_allowed = threading.Event(), threading.Event()
    cleaning, cleanup_allowed = threading.Event(), threading.Event()
    failures = []
    if kind == "tray":
        owner = WindowsTrayIcon(SimpleNamespace(config={}, log=None))
        original_create = owner._create_window
        original_cleanup = owner._delete_icon

        def create():
            creating.set()
            create_allowed.wait()
            return original_create()

        def cleanup(hwnd):
            cleaning.set()
            cleanup_allowed.wait()
            original_cleanup(hwnd)

        owner._create_window = create
        owner._delete_icon = cleanup
        owner._add_icon = lambda _hwnd: setattr(owner, "_icon_registered", True)
    else:
        owner = ClipboardPasswordMonitor(enabled=False, volume_changed=lambda *_: None)
        original_create = _WindowsClipboardLoop._create_window
        original_cleanup = _WindowsClipboardLoop._unregister_window_class

        def create(loop):
            creating.set()
            create_allowed.wait()
            return original_create(loop)

        def cleanup(loop):
            cleaning.set()
            cleanup_allowed.wait()
            original_cleanup(loop)

        monkeypatch.setattr(_WindowsClipboardLoop, "_create_window", create)
        monkeypatch.setattr(_WindowsClipboardLoop, "_unregister_window_class", cleanup)

    def call(action):
        try:
            action()
        except BaseException as error:
            failures.append(error)

    starter = threading.Thread(target=call, args=(owner.start,), daemon=True)
    stopper = threading.Thread(target=call, args=(owner.stop,), daemon=True)
    starter.start()
    try:
        assert creating.wait(5)
        window_thread = owner._thread
        stopper.start()
        assert owner._thread is window_thread and window_thread.is_alive()
        create_allowed.set()
        assert cleaning.wait(5)
        assert owner._thread is window_thread and window_thread.is_alive()
        assert stopper.is_alive()
    finally:
        create_allowed.set()
        cleanup_allowed.set()
        starter.join(5)
        if stopper.ident is not None:
            stopper.join(5)
    assert not starter.is_alive() and not stopper.is_alive()
    assert failures == []
    assert owner._thread is None and owner._hwnd is None


@pytest.mark.parametrize("kind", ["tray", "clipboard"])
def test_window_close_failure_keeps_live_owner_and_can_be_retried(kind, monkeypatch):
    # Ordinary cleanup never makes PostMessage fail. This detects losing the
    # only owner reference on a failed close, and covers a successful retry.
    if kind == "tray":
        owner = WindowsTrayIcon(SimpleNamespace(config={}, log=None))
        owner._add_icon = lambda _: None
    else:
        owner = ClipboardPasswordMonitor(enabled=False, volume_changed=lambda *_: None)
    owner.start()
    owner._ready.wait()
    thread = owner._thread
    try:
        with monkeypatch.context() as patch:
            patch.setattr(ctypes.windll.user32, "PostMessageW", lambda *_: 0)
            with pytest.raises(OSError):
                owner.stop()
            assert owner._thread is thread and thread.is_alive()
    finally:
        owner.stop()
    assert owner._thread is None and not thread.is_alive()


@pytest.mark.parametrize("kind", ["tray", "clipboard"])
def test_window_startup_failure_publishes_completion_and_windows_error(kind, monkeypatch):
    # A failed creation must wake lifecycle waiters and preserve its OS error;
    # normal create/destroy tests cannot exercise this path.
    error = OSError(5, "window creation denied")

    def fail(*_):
        raise error

    if kind == "tray":
        owner = WindowsTrayIcon(SimpleNamespace(config={}, log=None))
        owner._create_window = fail
        with pytest.raises(OSError, match="window creation denied"):
            owner.start()
        owner.stop()
    else:
        owner = ClipboardPasswordMonitor()
        monkeypatch.setattr(_WindowsClipboardLoop, "_create_window", fail)
        owner.start()
        with pytest.raises(OSError, match="window creation denied"):
            owner.stop()
    assert owner._thread is None and owner._ready.is_set()
