from __future__ import annotations

import ctypes
import threading
from ctypes import wintypes
from typing import Callable

from sunpack.core.passwords.internal.builtin import merge_watch_clipboard_passwords
from sunpack.core.passwords.internal.clipboard import read_clipboard_passwords


LRESULT = getattr(wintypes, "LRESULT", ctypes.c_ssize_t)
WPARAM = getattr(wintypes, "WPARAM", ctypes.c_size_t)
LPARAM = getattr(wintypes, "LPARAM", ctypes.c_void_p)


class ClipboardPasswordMonitor:
    def __init__(
        self,
        *,
        on_passwords_changed: Callable[[str], None],
        max_entries: int = 30,
        enabled: bool = True,
    ):
        self.on_passwords_changed = on_passwords_changed
        self.max_entries = max(1, int(max_entries))
        self.enabled = bool(enabled)
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._hwnd = None

    def start(self) -> None:
        if not self.enabled or self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_windows_loop, name="sunpack-clipboard-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        hwnd = self._hwnd
        if hwnd:
            try:
                ctypes.windll.user32.PostMessageW(hwnd, 0x0010, 0, 0)
            except Exception:
                pass
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2.0)
        self._thread = None
        self._hwnd = None

    def _handle_clipboard_update(self) -> None:
        passwords = read_clipboard_passwords(single_line=True)
        if not passwords:
            return
        if merge_watch_clipboard_passwords(passwords, max_entries=self.max_entries):
            self.on_passwords_changed("clipboard")

    def _run_windows_loop(self) -> None:
        try:
            _WindowsClipboardLoop(self).run()
        except Exception:
            return


class _WindowsClipboardLoop:
    WM_CLIPBOARDUPDATE = 0x031D
    WM_CLOSE = 0x0010
    WM_DESTROY = 0x0002
    HWND_MESSAGE = ctypes.c_void_p(-3)

    def __init__(self, monitor: ClipboardPasswordMonitor):
        self.monitor = monitor
        self.user32 = ctypes.windll.user32
        self.kernel32 = ctypes.windll.kernel32
        self.kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        self.kernel32.GetModuleHandleW.restype = wintypes.HINSTANCE
        self.user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASS)]
        self.user32.RegisterClassW.restype = wintypes.ATOM
        self.user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
        self.user32.UnregisterClassW.restype = wintypes.BOOL
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
        self.class_name = f"SunpackClipboardPasswordMonitor_{id(self):x}"
        self._wndproc_ref = None
        self._hinstance = None
        self._class_registered = False

    def run(self) -> None:
        hwnd = self._create_window()
        if not hwnd:
            return
        self.monitor._hwnd = hwnd
        listener_registered = False
        try:
            listener_registered = bool(self.user32.AddClipboardFormatListener(hwnd))
            if not listener_registered:
                return
            # Close the startup race between launching the watch service and
            # registering for clipboard notifications.  A copy made during that
            # window does not produce another WM_CLIPBOARDUPDATE, so read the
            # current clipboard once after the listener is active.
            self.monitor._handle_clipboard_update()
            msg = wintypes.MSG()
            while not self.monitor._stop_event.is_set():
                result = self.user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if result <= 0:
                    break
                self.user32.TranslateMessage(ctypes.byref(msg))
                self.user32.DispatchMessageW(ctypes.byref(msg))
        finally:
            if listener_registered:
                self.user32.RemoveClipboardFormatListener(hwnd)
            if self.monitor._hwnd == hwnd:
                self.monitor._hwnd = None
            self.user32.DestroyWindow(hwnd)
            self._unregister_window_class()

    def _create_window(self):
        wndproc_type = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, WPARAM, LPARAM)
        self._wndproc_ref = wndproc_type(self._wndproc)
        self._hinstance = self.kernel32.GetModuleHandleW(None)
        wndclass = WNDCLASS()
        wndclass.lpfnWndProc = ctypes.cast(self._wndproc_ref, ctypes.c_void_p)
        wndclass.hInstance = self._hinstance
        wndclass.lpszClassName = self.class_name
        atom = self.user32.RegisterClassW(ctypes.byref(wndclass))
        if not atom:
            self._wndproc_ref = None
            self._hinstance = None
            return None
        self._class_registered = True
        hwnd = self.user32.CreateWindowExW(
            0,
            self.class_name,
            self.class_name,
            0,
            0,
            0,
            0,
            0,
            self.HWND_MESSAGE,
            None,
            self._hinstance,
            None,
        )
        if not hwnd:
            self._unregister_window_class()
        return hwnd

    def _unregister_window_class(self) -> None:
        if not self._class_registered or self._hinstance is None:
            return
        if self.user32.UnregisterClassW(self.class_name, self._hinstance):
            self._class_registered = False
            self._hinstance = None
            self._wndproc_ref = None

    def _wndproc(self, hwnd, msg, wparam, lparam):
        if msg == self.WM_CLIPBOARDUPDATE:
            self.monitor._handle_clipboard_update()
            return 0
        if msg in {self.WM_CLOSE, self.WM_DESTROY}:
            self.user32.PostQuitMessage(0)
            return 0
        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)


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
