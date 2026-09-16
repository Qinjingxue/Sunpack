from __future__ import annotations

import ctypes
import os
import threading
from ctypes import wintypes
from pathlib import Path

from sunpack.config.payload_io import read_config_payload
from sunpack.filesystem.watcher.service import watch_roots_path
from sunpack.i18n import I18nContext
from sunpack.passwords.internal.builtin import builtin_password_path, get_builtin_passwords
from sunpack.platform.windows.startup import disable_startup, enable_startup, startup_status
from sunpack.support.process_executable import current_process_executable

WM_NULL = 0x0000
WM_DESTROY = 0x0002
WM_NCDESTROY = 0x0082
WM_COMMAND = 0x0111
WM_USER = 0x0400
WM_TRAYICON = WM_USER + 20
WM_CLOSE = 0x0010
NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002
NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
LR_LOADFROMFILE = 0x00000010
IMAGE_ICON = 1
MF_STRING = 0x00000000
TPM_RIGHTBUTTON = 0x0002
WM_RBUTTONUP = 0x0205
WM_LBUTTONDBLCLK = 0x0203
IDI_APPLICATION = 32512
SW_SHOWNORMAL = 1
MSGFLT_ALLOW = 1
LRESULT = getattr(wintypes, "LRESULT", ctypes.c_ssize_t)
WPARAM = getattr(wintypes, "WPARAM", ctypes.c_size_t)
LPARAM = getattr(wintypes, "LPARAM", ctypes.c_void_p)

ID_OPEN_CONFIG = 1001
ID_OPEN_WATCH_ROOTS = 1002
ID_RELOAD = 1003
ID_EXIT = 1004
ID_TOGGLE_STARTUP = 1005
ID_OPEN_BUILTIN_PASSWORDS = 1006

TASKBAR_CREATED_MESSAGE_NAME = "TaskbarCreated"


class WNDCLASS(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", ctypes.c_void_p),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HANDLE),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HANDLE),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


class NOTIFYICONDATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HANDLE),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", ctypes.c_byte * 16),
        ("hBalloonIcon", wintypes.HANDLE),
    ]


_TRAY_CLASS_NAME = "SunpackWatchServiceTray"
_TRAY_CLASS_LOCK = threading.Lock()
_TRAY_CLASS_REGISTERED = False
_TRAY_INSTANCES_LOCK = threading.RLock()
_TRAY_INSTANCES: dict[int, "WindowsTrayIcon"] = {}


def _default_window_proc(hwnd, msg, wparam, lparam):
    return ctypes.windll.user32.DefWindowProcW(hwnd, msg, wparam, lparam)


def _dispatch_window_message(hwnd, msg, wparam, lparam):
    hwnd_key = int(hwnd or 0)
    with _TRAY_INSTANCES_LOCK:
        instance = _TRAY_INSTANCES.get(hwnd_key)
    try:
        if instance is None:
            return _default_window_proc(hwnd, msg, wparam, lparam)
        return instance._wndproc(hwnd, msg, wparam, lparam)
    except BaseException as exc:
        if instance is not None:
            instance._log_callback_error(exc, msg)
        return _default_window_proc(hwnd, msg, wparam, lparam)
    finally:
        if msg == WM_NCDESTROY:
            with _TRAY_INSTANCES_LOCK:
                _TRAY_INSTANCES.pop(hwnd_key, None)


def _ffi_window_proc(hwnd, msg, wparam, lparam):
    try:
        return _dispatch_window_message(hwnd, msg, wparam, lparam)
    except BaseException:
        return 0


_WNDPROC_TYPE = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, WPARAM, LPARAM)
_GLOBAL_WNDPROC = _WNDPROC_TYPE(_ffi_window_proc)


def _ensure_tray_class_registered(user32, hinstance) -> None:
    global _TRAY_CLASS_REGISTERED
    with _TRAY_CLASS_LOCK:
        if _TRAY_CLASS_REGISTERED:
            return
        wndclass = WNDCLASS()
        wndclass.lpfnWndProc = ctypes.cast(_GLOBAL_WNDPROC, ctypes.c_void_p)
        wndclass.hInstance = hinstance
        wndclass.lpszClassName = _TRAY_CLASS_NAME
        if not user32.RegisterClassW(ctypes.byref(wndclass)):
            raise ctypes.WinError(ctypes.GetLastError())
        _TRAY_CLASS_REGISTERED = True


class WindowsTrayIcon:
    def __init__(self, service):
        self.service = service
        self.i18n = I18nContext(_tray_language_from_service(service))
        self.user32 = ctypes.windll.user32
        self.shell32 = ctypes.windll.shell32
        self.kernel32 = ctypes.windll.kernel32
        self.kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        self.kernel32.GetModuleHandleW.restype = wintypes.HINSTANCE
        self.user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASS)]
        self.user32.RegisterClassW.restype = wintypes.ATOM
        self.user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
        self.user32.RegisterWindowMessageW.restype = wintypes.UINT
        self.user32.ChangeWindowMessageFilterEx.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.DWORD,
            wintypes.LPVOID,
        ]
        self.user32.ChangeWindowMessageFilterEx.restype = wintypes.BOOL
        self.user32.CreateWindowExW.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.HMENU,
            wintypes.HINSTANCE,
            wintypes.LPVOID,
        ]
        self.user32.CreateWindowExW.restype = wintypes.HWND
        self.user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, LPARAM]
        self.user32.DefWindowProcW.restype = LRESULT
        self.user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, LPARAM]
        self.user32.PostMessageW.restype = wintypes.BOOL
        self.user32.DestroyWindow.argtypes = [wintypes.HWND]
        self.user32.DestroyWindow.restype = wintypes.BOOL
        self.user32.IsWindow.argtypes = [wintypes.HWND]
        self.user32.IsWindow.restype = wintypes.BOOL
        self.user32.GetMessageW.argtypes = [
            ctypes.POINTER(wintypes.MSG),
            wintypes.HWND,
            wintypes.UINT,
            wintypes.UINT,
        ]
        self.user32.GetMessageW.restype = wintypes.BOOL
        self.user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        self.user32.TranslateMessage.restype = wintypes.BOOL
        self.user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        self.user32.DispatchMessageW.restype = LRESULT
        self.user32.PostQuitMessage.argtypes = [ctypes.c_int]
        self.user32.PostQuitMessage.restype = None
        self.shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATA)]
        self.shell32.Shell_NotifyIconW.restype = wintypes.BOOL
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._closed = threading.Event()
        self._startup_error: BaseException | None = None
        self._hwnd = None
        self._icon = None
        self._icon_registered = False
        self._taskbar_created_message = self.user32.RegisterWindowMessageW(
            TASKBAR_CREATED_MESSAGE_NAME
        )
        if not self._taskbar_created_message:
            raise ctypes.WinError()

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = None
        self._ready.clear()
        self._closed.clear()
        self._startup_error = None
        self._thread = threading.Thread(target=self._run, name="sunpack-tray", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=2.0):
            raise RuntimeError("Tray window did not become ready within 2 seconds.")
        if self._startup_error is not None:
            raise RuntimeError("Tray window failed to start.") from self._startup_error
        if not self._hwnd:
            raise RuntimeError("Tray window exited before startup completed.")

    def stop(self) -> None:
        thread = self._thread
        if thread is None:
            return
        hwnd = self._hwnd
        if hwnd:
            if not self.user32.PostMessageW(hwnd, WM_CLOSE, 0, 0):
                raise ctypes.WinError(ctypes.GetLastError())
        if not self._closed.wait(timeout=2.0):
            raise RuntimeError("Tray thread did not close within 2 seconds.")
        thread.join(timeout=0.1)
        if thread.is_alive():
            raise RuntimeError("Tray thread remained alive after its window closed.")
        self._thread = None

    def _run(self) -> None:
        hwnd = None
        try:
            hwnd = self._create_window()
            if not hwnd:
                raise ctypes.WinError(ctypes.GetLastError())
            self._hwnd = hwnd
            with _TRAY_INSTANCES_LOCK:
                _TRAY_INSTANCES[int(hwnd)] = self
            self._allow_taskbar_created_message(hwnd)
            self._ensure_icon(hwnd)
            self._ready.set()
            msg = wintypes.MSG()
            while True:
                result = self.user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if result == 0:
                    break
                if result == -1:
                    raise ctypes.WinError(ctypes.GetLastError())
                self.user32.TranslateMessage(ctypes.byref(msg))
                self.user32.DispatchMessageW(ctypes.byref(msg))
        except BaseException as exc:
            self._startup_error = exc
            self._log_callback_error(exc, None)
        finally:
            self._ready.set()
            if hwnd:
                try:
                    if self._icon_registered:
                        self._delete_icon(hwnd)
                    if self.user32.IsWindow(hwnd):
                        self.user32.DestroyWindow(hwnd)
                except BaseException as exc:
                    self._log_callback_error(exc, None)
                finally:
                    with _TRAY_INSTANCES_LOCK:
                        _TRAY_INSTANCES.pop(int(hwnd), None)
            self._hwnd = None
            self._closed.set()

    def _create_window(self):
        hinstance = self.kernel32.GetModuleHandleW(None)
        _ensure_tray_class_registered(self.user32, hinstance)
        return self.user32.CreateWindowExW(
            0,
            _TRAY_CLASS_NAME,
            _TRAY_CLASS_NAME,
            0,
            0,
            0,
            0,
            0,
            None,
            None,
            hinstance,
            None,
        )

    def _notification_data(self, hwnd, *, flags: int) -> NOTIFYICONDATA:
        data = NOTIFYICONDATA()
        data.cbSize = ctypes.sizeof(NOTIFYICONDATA)
        data.hWnd = hwnd
        data.uID = 1
        data.uFlags = flags
        if flags & NIF_MESSAGE:
            data.uCallbackMessage = WM_TRAYICON
        if flags & NIF_ICON:
            data.hIcon = self._load_icon()
        if flags & NIF_TIP:
            data.szTip = self._text("tip")
        return data

    def _add_icon(self, hwnd) -> None:
        data = self._notification_data(hwnd, flags=NIF_MESSAGE | NIF_ICON | NIF_TIP)
        if not self.shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(data)):
            raise ctypes.WinError(ctypes.GetLastError())
        self._icon_registered = True

    def _modify_icon(self, hwnd) -> None:
        data = self._notification_data(hwnd, flags=NIF_MESSAGE | NIF_ICON | NIF_TIP)
        if not self.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(data)):
            raise ctypes.WinError(ctypes.GetLastError())
        self._icon_registered = True

    def _ensure_icon(self, hwnd, *, modify_fallback: bool = False) -> bool:
        self._icon_registered = False
        try:
            self._add_icon(hwnd)
            return True
        except OSError as exc:
            self._log_callback_error(exc, self._taskbar_created_message if modify_fallback else None)
        if modify_fallback:
            try:
                self._modify_icon(hwnd)
                return True
            except OSError as exc:
                self._log_callback_error(exc, self._taskbar_created_message)
        return False

    def _allow_taskbar_created_message(self, hwnd) -> None:
        if not self.user32.ChangeWindowMessageFilterEx(
            hwnd,
            self._taskbar_created_message,
            MSGFLT_ALLOW,
            None,
        ):
            self._log_callback_error(ctypes.WinError(ctypes.GetLastError()), None)

    def _delete_icon(self, hwnd) -> None:
        data = NOTIFYICONDATA()
        data.cbSize = ctypes.sizeof(NOTIFYICONDATA)
        data.hWnd = hwnd
        data.uID = 1
        self.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(data))
        self._icon_registered = False

    def _restore_icon(self, hwnd) -> None:
        # Explorer discards notification-area icons when it recreates the
        # taskbar. Some display changes broadcast the same message without
        # removing the old icon, so fall back to MODIFY when ADD reports that
        # the icon already exists.
        self._ensure_icon(hwnd, modify_fallback=True)

    def _load_icon(self):
        for icon_path in _candidate_icon_paths():
            if icon_path.exists():
                icon = self.user32.LoadImageW(None, str(icon_path), IMAGE_ICON, 0, 0, LR_LOADFROMFILE)
                if icon:
                    self._icon = icon
                    return icon
        return self.user32.LoadIconW(None, ctypes.c_wchar_p(IDI_APPLICATION))

    def _wndproc(self, hwnd, msg, wparam, lparam):
        if msg == getattr(self, "_taskbar_created_message", None):
            self._restore_icon(hwnd)
            return 0
        if msg == WM_TRAYICON and lparam in {WM_RBUTTONUP, WM_LBUTTONDBLCLK}:
            self._show_menu(hwnd)
            return 0
        if msg == WM_COMMAND:
            self._handle_command(int(wparam) & 0xFFFF)
            return 0
        if msg == WM_CLOSE:
            self.user32.DestroyWindow(hwnd)
            return 0
        if msg == WM_DESTROY:
            self.user32.PostQuitMessage(0)
            return 0
        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def refresh(self) -> None:
        self.i18n = I18nContext(_tray_language_from_service(self.service))
        hwnd = self._hwnd
        if not hwnd or not self._icon_registered:
            return
        data = self._notification_data(hwnd, flags=NIF_TIP)
        if not self.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(data)):
            raise ctypes.WinError(ctypes.GetLastError())

    def _log_callback_error(self, exc: BaseException, msg: int | None) -> None:
        log = getattr(self.service, "log", None)
        if log is None:
            return
        try:
            log.write(
                "tray_callback_error",
                error=str(exc),
                error_type=type(exc).__name__,
                message=msg,
            )
        except BaseException:
            pass

    def _show_menu(self, hwnd) -> None:
        menu = self.user32.CreatePopupMenu()
        try:
            self.user32.AppendMenuW(
                menu, MF_STRING, ID_OPEN_CONFIG,
                self._text("open_config"),
            )
            self.user32.AppendMenuW(
                menu, MF_STRING, ID_OPEN_WATCH_ROOTS,
                self._text("open_watch_roots"),
            )
            self.user32.AppendMenuW(
                menu, MF_STRING, ID_OPEN_BUILTIN_PASSWORDS,
                self._text("open_builtin_passwords"),
            )
            self.user32.AppendMenuW(
                menu, MF_STRING, ID_TOGGLE_STARTUP,
                self._startup_menu_label(),
            )
            self.user32.AppendMenuW(
                menu, MF_STRING, ID_RELOAD,
                self._text("reload"),
            )
            self.user32.AppendMenuW(
                menu, MF_STRING, ID_EXIT,
                self._text("exit"),
            )

            point = wintypes.POINT()
            self.user32.GetCursorPos(ctypes.byref(point))
            self.user32.SetForegroundWindow(hwnd)

            self.user32.TrackPopupMenu(
                menu,
                TPM_RIGHTBUTTON,
                point.x,
                point.y,
                0,
                hwnd,
                None,
            )

            self.user32.PostMessageW(hwnd, WM_NULL, 0, 0)
        finally:
            self.user32.DestroyMenu(menu)

    def _handle_command(self, command_id: int) -> None:
        if command_id == ID_OPEN_CONFIG:
            config_path, _ = read_config_payload()
            self._open_path(str(config_path))
        elif command_id == ID_OPEN_WATCH_ROOTS:
            self._open_watch_roots_file()
        elif command_id == ID_OPEN_BUILTIN_PASSWORDS:
            self._open_builtin_passwords_file()
        elif command_id == ID_TOGGLE_STARTUP:
            self._toggle_startup()
        elif command_id == ID_RELOAD:
            self.service.request_reload()
        elif command_id == ID_EXIT:
            self.service.request_stop()
            if self._hwnd:
                self.user32.PostMessageW(self._hwnd, WM_CLOSE, 0, 0)

    def _open_path(self, path: str) -> None:
        self.shell32.ShellExecuteW(None, "open", path, None, None, SW_SHOWNORMAL)

    def _open_watch_roots_file(self) -> None:
        roots_path = watch_roots_path()
        try:
            roots_path.parent.mkdir(parents=True, exist_ok=True)
            roots_path.touch(exist_ok=True)
        except OSError:
            return
        self._open_path(str(roots_path))

    def _open_builtin_passwords_file(self) -> None:
        passwords_path = builtin_password_path()
        if not passwords_path.exists():
            get_builtin_passwords()
        if passwords_path.exists():
            self._open_path(str(passwords_path))

    def _startup_menu_label(self) -> str:
        try:
            enabled, _ = startup_status()
        except Exception:
            enabled = False
        return self._text("disable_startup" if enabled else "enable_startup")

    def _text(self, key: str) -> str:
        i18n = getattr(self, "i18n", None) or I18nContext(getattr(self, "language", "en"))
        return i18n.t(f"tray.{key}")

    def _toggle_startup(self) -> None:
        try:
            enabled, _ = startup_status()
            if enabled:
                disable_startup()
            else:
                enable_startup()
        except Exception:
            return

def _candidate_icon_paths() -> list[Path]:
    executable_dir = current_process_executable().parent
    return [
        executable_dir / "sunpack.ico",
        Path(__file__).resolve().parents[3] / "sunpack.ico",
    ]


def _tray_language_from_service(service) -> str:
    config = getattr(service, "config", {}) if service is not None else {}
    cli_config = config.get("cli") if isinstance(config, dict) and isinstance(config.get("cli"), dict) else {}
    return "zh" if str(cli_config.get("language") or "").strip().lower() == "zh" else "en"
