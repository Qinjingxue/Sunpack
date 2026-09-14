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

        def RemoveClipboardFormatListener(self, _hwnd):
            return True

        def DestroyWindow(self, _hwnd):
            return True

    loop = object.__new__(_WindowsClipboardLoop)
    loop.monitor = FakeMonitor()
    loop.user32 = FakeUser32()
    loop._create_window = lambda: 123

    loop.run()

    assert handled == ["clipboard"]
