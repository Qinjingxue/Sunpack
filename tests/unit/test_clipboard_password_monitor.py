from __future__ import annotations

import sunpack.passwords.internal.builtin as builtin_module
import sunpack.passwords.internal.clipboard_monitor as clipboard_monitor_module
from sunpack.passwords.internal.clipboard_monitor import ClipboardPasswordMonitor
from sunpack.passwords.internal.clipboard_monitor import _WindowsClipboardLoop


def test_clipboard_monitor_persists_clipboard_passwords_and_notifies(tmp_path, monkeypatch):
    builtin_path = tmp_path / "builtin_passwords.txt"
    builtin_path.write_text("existing\n", encoding="utf-8")
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)
    single_line_calls = []

    def _read_clipboard_passwords(*, single_line):
        single_line_calls.append(single_line)
        return [f"clip-{index}" for index in range(35)]

    monkeypatch.setattr(clipboard_monitor_module, "read_clipboard_passwords", _read_clipboard_passwords)
    notifications = []

    monitor = ClipboardPasswordMonitor(
        on_passwords_changed=notifications.append,
        max_entries=30,
        enabled=True,
    )

    monitor._handle_clipboard_update()

    passwords = builtin_module.get_builtin_passwords()
    assert single_line_calls == [True]
    assert notifications == ["clipboard"]
    assert "existing" in passwords
    assert "clip-0" not in passwords
    assert "clip-5" in passwords
    assert "clip-34" in passwords


def test_windows_clipboard_loop_reads_current_clipboard_after_listener_registration():
    handled = []
    cleanup = []

    class FakeStopEvent:
        def is_set(self):
            return False

    class FakeMonitor:
        _stop_event = FakeStopEvent()
        _hwnd = None

        def _handle_clipboard_update(self):
            handled.append("clipboard")

    class FakeUser32:
        def AddClipboardFormatListener(self, _hwnd):
            return True

        def GetMessageW(self, _msg, _hwnd, _minimum, _maximum):
            return 0

        def RemoveClipboardFormatListener(self, hwnd):
            cleanup.append(("listener", hwnd))
            return True

        def DestroyWindow(self, hwnd):
            cleanup.append(("window", hwnd))
            return True

    loop = object.__new__(_WindowsClipboardLoop)
    loop.monitor = FakeMonitor()
    loop.user32 = FakeUser32()
    loop._create_window = lambda: 123
    loop._unregister_window_class = lambda: cleanup.append(("class", loop.class_name))
    loop.class_name = "test-class"

    loop.run()

    assert handled == ["clipboard"]
    assert loop.monitor._hwnd is None
    assert cleanup == [
        ("listener", 123),
        ("window", 123),
        ("class", "test-class"),
    ]


def test_windows_clipboard_loop_does_not_create_window_after_class_registration_failure(monkeypatch):
    create_calls = []

    class FakeKernel32:
        def GetModuleHandleW(self, _name):
            return 1

    class FakeUser32:
        def RegisterClassW(self, _wndclass):
            return 0

        def CreateWindowExW(self, *_args):
            create_calls.append(True)
            return 123

    loop = object.__new__(_WindowsClipboardLoop)
    loop.monitor = object()
    loop.user32 = FakeUser32()
    loop.kernel32 = FakeKernel32()
    loop.class_name = "test-class"
    loop._wndproc_ref = None
    loop._hinstance = None
    loop._class_registered = False

    monkeypatch.setattr(
        clipboard_monitor_module.ctypes,
        "WINFUNCTYPE",
        lambda *_args: lambda callback: callback,
        raising=False,
    )
    monkeypatch.setattr(
        clipboard_monitor_module.ctypes,
        "cast",
        lambda *_args: clipboard_monitor_module.ctypes.c_void_p(1),
    )

    assert loop._create_window() is None
    assert create_calls == []
    assert loop._wndproc_ref is None
    assert loop._hinstance is None
    assert loop._class_registered is False


def test_windows_clipboard_loop_unregisters_class_before_releasing_wndproc():
    unregister_calls = []

    class FakeUser32:
        def UnregisterClassW(self, class_name, hinstance):
            unregister_calls.append((class_name, hinstance))
            return True

    loop = object.__new__(_WindowsClipboardLoop)
    loop.user32 = FakeUser32()
    loop.class_name = "test-class"
    loop._hinstance = 7
    loop._class_registered = True
    loop._wndproc_ref = object()

    loop._unregister_window_class()

    assert unregister_calls == [("test-class", 7)]
    assert loop._class_registered is False
    assert loop._hinstance is None
    assert loop._wndproc_ref is None
