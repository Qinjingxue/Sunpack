from __future__ import annotations

import subprocess
import sys
import textwrap
from types import SimpleNamespace

import sunpack.filesystem.watcher.service as service_module
import sunpack.gui.tray as tray_module
from sunpack.gui.tray import WindowsTrayIcon, _tray_language_from_service


def test_tray_open_watch_roots_file_creates_and_opens_txt(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    opened = []
    tray = object.__new__(WindowsTrayIcon)
    tray._open_path = opened.append
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(tray_module, "watch_roots_path", lambda: roots_path)

    tray._open_watch_roots_file()

    assert roots_path.exists()
    assert opened == [str(roots_path)]


def test_tray_open_builtin_passwords_file_creates_and_opens_txt(tmp_path, monkeypatch):
    passwords_path = tmp_path / "builtin_passwords.txt"
    opened = []
    tray = object.__new__(WindowsTrayIcon)
    tray._open_path = opened.append

    monkeypatch.setattr(tray_module, "builtin_password_path", lambda: passwords_path)

    def create_passwords_file():
        passwords_path.write_text("123456\n", encoding="utf-8")
        return ["123456"]

    monkeypatch.setattr(tray_module, "get_builtin_passwords", create_passwords_file)

    tray._open_builtin_passwords_file()

    assert passwords_path.exists()
    assert opened == [str(passwords_path)]


def test_tray_builtin_password_command_opens_passwords_file():
    calls = []
    tray = object.__new__(WindowsTrayIcon)
    tray._open_builtin_passwords_file = lambda: calls.append("open")

    tray._handle_command(tray_module.ID_OPEN_BUILTIN_PASSWORDS)

    assert calls == ["open"]


def test_tray_uses_chinese_text_when_cli_language_is_zh():
    service = SimpleNamespace(config={"cli": {"language": "zh"}})

    assert _tray_language_from_service(service) == "zh"

    tray = object.__new__(WindowsTrayIcon)
    tray.language = "zh"

    assert tray._text("open_config") == "打开配置文件"
    assert tray._text("open_watch_roots") == "打开监控目录列表"
    assert tray._text("open_builtin_passwords") == "打开内置密码文件"
    assert tray._text("exit") == "退出"


def test_tray_defaults_to_english_text():
    service = SimpleNamespace(config={"cli": {"language": "en"}})

    assert _tray_language_from_service(service) == "en"

    tray = object.__new__(WindowsTrayIcon)
    tray.language = "en"

    assert tray._text("open_config") == "Open config"
    assert tray._text("open_watch_roots") == "Open watch folders file"
    assert tray._text("open_builtin_passwords") == "Open built-in passwords file"
    assert tray._text("exit") == "Exit"


def test_tray_close_and_destroy_have_distinct_responsibilities():
    calls = []

    class User32:
        def DestroyWindow(self, hwnd):
            calls.append(("destroy", hwnd))

        def PostQuitMessage(self, code):
            calls.append(("quit", code))

    tray = object.__new__(WindowsTrayIcon)
    tray.user32 = User32()

    assert tray._wndproc(123, tray_module.WM_CLOSE, 0, 0) == 0
    assert calls == [("destroy", 123)]

    assert tray._wndproc(123, tray_module.WM_DESTROY, 0, 0) == 0
    assert calls == [("destroy", 123), ("quit", 0)]


def test_tray_message_window_uses_toolwindow_extended_style(monkeypatch):
    calls = []

    class Kernel32:
        def GetModuleHandleW(self, _name):
            return 456

    class User32:
        def CreateWindowExW(self, *args):
            calls.append(args)
            return 123

    tray = object.__new__(WindowsTrayIcon)
    tray.kernel32 = Kernel32()
    tray.user32 = User32()
    monkeypatch.setattr(tray_module, "_ensure_tray_class_registered", lambda *_args: None)

    assert tray._create_window() == 123
    assert calls[0][0] == tray_module.WS_EX_TOOLWINDOW


def test_owned_icon_is_destroyed_after_successful_shell_notification():
    destroyed = []

    class User32:
        def DestroyIcon(self, icon):
            destroyed.append(icon)
            return True

    class Shell32:
        def Shell_NotifyIconW(self, _operation, _data):
            return True

    tray = object.__new__(WindowsTrayIcon)
    tray.user32 = User32()
    tray.shell32 = Shell32()
    tray._load_icon = lambda: (321, True)
    tray._notification_data = lambda _hwnd, flags, icon: tray_module.NOTIFYICONDATA()
    tray._log_callback_error = lambda *_args: None

    tray._notify_with_icon(tray_module.NIM_ADD, 123)

    assert destroyed == [321]


def test_owned_icon_is_destroyed_when_shell_rejects_notification(monkeypatch):
    destroyed = []

    class User32:
        def DestroyIcon(self, icon):
            destroyed.append(icon)
            return True

    class Shell32:
        def Shell_NotifyIconW(self, _operation, _data):
            return False

    tray = object.__new__(WindowsTrayIcon)
    tray.user32 = User32()
    tray.shell32 = Shell32()
    tray._load_icon = lambda: (321, True)
    tray._notification_data = lambda _hwnd, flags, icon: tray_module.NOTIFYICONDATA()
    tray._log_callback_error = lambda *_args: None
    monkeypatch.setattr(tray_module.ctypes, "GetLastError", lambda: 5, raising=False)
    monkeypatch.setattr(
        tray_module.ctypes,
        "WinError",
        lambda code: OSError(code, "shell unavailable"),
        raising=False,
    )

    try:
        tray._notify_with_icon(tray_module.NIM_ADD, 123)
    except OSError as exc:
        assert exc.errno == 5
    else:
        raise AssertionError("Shell failure must remain visible to the tray recovery state machine")

    assert destroyed == [321]


def test_shared_fallback_icon_is_not_destroyed(monkeypatch):
    class User32:
        def LoadIconW(self, _instance, _name):
            return 654

        def DestroyIcon(self, _icon):
            raise AssertionError("shared LoadIconW handle must not be destroyed")

    class Shell32:
        def Shell_NotifyIconW(self, _operation, _data):
            return True

    tray = object.__new__(WindowsTrayIcon)
    tray.user32 = User32()
    tray.shell32 = Shell32()
    tray._tray_icon_size = lambda: (16, 16)
    tray._notification_data = lambda _hwnd, flags, icon: tray_module.NOTIFYICONDATA()
    tray._log_callback_error = lambda *_args: None
    monkeypatch.setattr(tray_module, "_candidate_icon_paths", lambda: [])

    tray._notify_with_icon(tray_module.NIM_ADD, 123)


def test_custom_icon_uses_current_taskbar_dpi_size(tmp_path, monkeypatch):
    icon_path = tmp_path / "sunpack.ico"
    icon_path.touch()
    calls = []

    class User32:
        def FindWindowW(self, class_name, window_name):
            calls.append(("find", class_name, window_name))
            return 123

        def GetDpiForWindow(self, hwnd):
            calls.append(("dpi", hwnd))
            return 192

        def GetSystemMetricsForDpi(self, metric, dpi):
            calls.append(("metric", metric, dpi))
            return {tray_module.SM_CXSMICON: 32, tray_module.SM_CYSMICON: 30}[metric]

        def LoadImageW(self, instance, path, image_type, width, height, flags):
            calls.append(("load", instance, path, image_type, width, height, flags))
            return 789

    tray = object.__new__(WindowsTrayIcon)
    tray.user32 = User32()
    monkeypatch.setattr(tray_module, "_candidate_icon_paths", lambda: [icon_path])

    assert tray._load_icon() == (789, True)
    assert ("dpi", 123) in calls
    assert ("metric", tray_module.SM_CXSMICON, 192) in calls
    assert ("metric", tray_module.SM_CYSMICON, 192) in calls
    assert (
        "load",
        None,
        str(icon_path),
        tray_module.IMAGE_ICON,
        32,
        30,
        tray_module.LR_LOADFROMFILE,
    ) in calls


def test_display_changes_refresh_only_a_registered_icon():
    calls = []
    tray = object.__new__(WindowsTrayIcon)
    tray._taskbar_created_message = 0xC123
    tray._icon_registered = True
    tray._modify_icon = calls.append
    tray._log_callback_error = lambda *_args: None

    assert tray._wndproc(123, tray_module.WM_DISPLAYCHANGE, 0, 0) == 0
    assert tray._wndproc(123, tray_module.WM_DPICHANGED, 0, 0) == 0
    assert calls == [123, 123]

    tray._icon_registered = False
    assert tray._wndproc(123, tray_module.WM_DISPLAYCHANGE, 0, 0) == 0
    assert calls == [123, 123]


def test_taskbar_created_message_restores_tray_icon():
    calls = []
    tray = object.__new__(WindowsTrayIcon)
    tray._taskbar_created_message = 0xC123
    tray._icon_registered = True

    def ensure_icon(hwnd, *, modify_fallback=False):
        calls.append((hwnd, modify_fallback))
        tray._icon_registered = True

    tray._ensure_icon = ensure_icon

    assert tray._wndproc(123, tray._taskbar_created_message, 0, 0) == 0
    assert calls == [(123, True)]
    assert tray._icon_registered is True


def test_initial_add_failure_is_nonfatal_and_leaves_icon_pending():
    errors = []
    tray = object.__new__(WindowsTrayIcon)
    tray._taskbar_created_message = 0xC123
    tray._icon_registered = True
    tray._add_icon = lambda _hwnd: (_ for _ in ()).throw(OSError("add failed"))
    tray._modify_icon = lambda _hwnd: (_ for _ in ()).throw(
        AssertionError("initial registration must not try MODIFY")
    )
    tray._log_callback_error = lambda exc, msg: errors.append((str(exc), msg))

    assert tray._ensure_icon(123) is False
    assert errors == [("add failed", None)]
    assert tray._icon_registered is False


def test_taskbar_restore_falls_back_to_modify_when_add_fails():
    calls = []
    errors = []
    tray = object.__new__(WindowsTrayIcon)
    tray._taskbar_created_message = 0xC123
    tray._icon_registered = True
    tray._add_icon = lambda hwnd: calls.append(("add", hwnd)) or (_ for _ in ()).throw(
        OSError("already exists")
    )
    tray._modify_icon = lambda hwnd: calls.append(("modify", hwnd))
    tray._log_callback_error = lambda exc, msg: errors.append((str(exc), msg))

    tray._restore_icon(123)

    assert calls == [("add", 123), ("modify", 123)]
    assert errors == [("already exists", 0xC123)]


def test_taskbar_restore_keeps_icon_pending_when_add_and_modify_fail():
    errors = []
    tray = object.__new__(WindowsTrayIcon)
    tray._taskbar_created_message = 0xC123
    tray._icon_registered = True
    tray._add_icon = lambda _hwnd: (_ for _ in ()).throw(OSError("add failed"))
    tray._modify_icon = lambda _hwnd: (_ for _ in ()).throw(OSError("modify failed"))
    tray._log_callback_error = lambda exc, msg: errors.append((str(exc), msg))

    tray._restore_icon(123)

    assert tray._icon_registered is False
    assert errors == [("add failed", 0xC123), ("modify failed", 0xC123)]


def test_global_tray_callback_contains_python_exceptions(monkeypatch):
    errors = []
    instance = SimpleNamespace(
        _wndproc=lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt()),
        _log_callback_error=lambda exc, msg: errors.append((type(exc), msg)),
    )
    monkeypatch.setattr(tray_module, "_default_window_proc", lambda *_args: 77)
    with tray_module._TRAY_INSTANCES_LOCK:
        tray_module._TRAY_INSTANCES[123] = instance
    try:
        assert tray_module._dispatch_window_message(123, 456, 0, 0) == 77
    finally:
        with tray_module._TRAY_INSTANCES_LOCK:
            tray_module._TRAY_INSTANCES.pop(123, None)

    assert errors == [(KeyboardInterrupt, 456)]


def test_ffi_tray_callback_never_leaks_even_default_handler_failure(monkeypatch):
    monkeypatch.setattr(
        tray_module,
        "_dispatch_window_message",
        lambda *_args: (_ for _ in ()).throw(SystemExit()),
    )

    assert tray_module._ffi_window_proc(123, 456, 0, 0) == 0


def test_tray_stop_timeout_keeps_thread_reference():
    class Thread:
        def is_alive(self):
            return True

    tray = object.__new__(WindowsTrayIcon)
    tray._thread = Thread()
    tray._hwnd = None
    tray._closed = SimpleNamespace(wait=lambda timeout: False)

    try:
        tray.stop()
    except RuntimeError as exc:
        assert "did not close" in str(exc)
    else:
        raise AssertionError("stop must report a tray lifecycle timeout")

    assert isinstance(tray._thread, Thread)


def test_tray_window_can_be_recreated_without_stale_callback_crash():
    script = textwrap.dedent(
        """
        import gc
        from types import SimpleNamespace
        from sunpack.gui.tray import WindowsTrayIcon

        WindowsTrayIcon._add_icon = lambda self, hwnd: None
        service = SimpleNamespace(config={"cli": {"language": "en"}}, log=None)
        for _ in range(50):
            tray = WindowsTrayIcon(service)
            tray.start()
            tray.stop()
            del tray
            gc.collect()
        """
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
