"""Event-driven console stop key, with prompt ownership of stdin."""

from __future__ import annotations

import ctypes
import threading
from contextlib import contextmanager
from ctypes import wintypes


class ConsoleCancellation:
    def __init__(self, cancel, *, enabled=True):
        self._cancel = cancel
        self._enabled = enabled
        self._thread = None
        self._stop = None
        self._handler = None
        self._sent = threading.Event()
        self._prompt = False
        self._main_thread = None

    def __enter__(self):
        if not self._enabled:
            return self
        kernel = self._kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel.GetStdHandle.restype = wintypes.HANDLE
        kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        kernel.CreateEventW.restype = wintypes.HANDLE
        kernel.SetEvent.argtypes = kernel.ResetEvent.argtypes = kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.WaitForMultipleObjects.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.BOOL, wintypes.DWORD]
        kernel.ReadConsoleInputW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        kernel.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenThread.restype = wintypes.HANDLE
        kernel.CancelSynchronousIo.argtypes = [wintypes.HANDLE]
        self._input = kernel.GetStdHandle(-10 & 0xFFFFFFFF)
        mode = wintypes.DWORD()
        if not kernel.GetConsoleMode(self._input, ctypes.byref(mode)):
            return self
        self._stop = kernel.CreateEventW(None, True, False, None)
        if not self._stop:
            raise ctypes.WinError(ctypes.get_last_error())
        self._main_thread = kernel.OpenThread(1, False, kernel.GetCurrentThreadId())
        handler_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
        kernel.SetConsoleCtrlHandler.argtypes = [handler_type, wintypes.BOOL]

        def control(kind):
            if kind not in (0, 1):
                return False
            self._request_cancel()
            if self._prompt and self._main_thread:
                kernel.CancelSynchronousIo(self._main_thread)
            return True

        self._handler = handler_type(control)
        kernel.SetConsoleCtrlHandler(self._handler, True)
        self._start()
        return self

    def _request_cancel(self):
        if not self._sent.is_set():
            self._sent.set()
            try:
                self._cancel()
            except OSError:
                pass

    def request_cancel(self):
        self._request_cancel()

    def _start(self):
        if self._stop:
            self._kernel.ResetEvent(self._stop)
            self._thread = threading.Thread(target=self._listen, name="sunpack-console-stop")
            self._thread.start()

    def _join(self):
        if self._thread is not None:
            self._kernel.SetEvent(self._stop)
            self._thread.join()
            self._thread = None

    @contextmanager
    def prompt(self):
        self._join()
        self._prompt = True
        try:
            yield
        finally:
            self._prompt = False
            self._start()

    def _listen(self):
        class Key(ctypes.Structure):
            _fields_ = [("down", wintypes.BOOL), ("repeat", wintypes.WORD),
                        ("virtual", wintypes.WORD), ("scan", wintypes.WORD),
                        ("char", wintypes.WCHAR), ("modifiers", wintypes.DWORD)]
        class Event(ctypes.Union):
            _fields_ = [("key", Key), ("padding", wintypes.DWORD * 4)]
        class Record(ctypes.Structure):
            _fields_ = [("kind", wintypes.WORD), ("event", Event)]
        handles = (wintypes.HANDLE * 2)(self._stop, self._input)
        record, count = Record(), wintypes.DWORD()
        while self._kernel.WaitForMultipleObjects(2, handles, False, 0xFFFFFFFF) == 1:
            if not self._kernel.ReadConsoleInputW(self._input, ctypes.byref(record), 1, ctypes.byref(count)):
                return
            if count.value and record.kind == 1 and record.event.key.down and record.event.key.char in ("q", "Q"):
                self._request_cancel()

    def __exit__(self, *_):
        self._join()
        if self._handler is not None:
            self._kernel.SetConsoleCtrlHandler(self._handler, False)
            self._handler = None
        if self._stop:
            self._kernel.CloseHandle(self._stop)
            self._stop = None
        if self._main_thread:
            self._kernel.CloseHandle(self._main_thread)
            self._main_thread = None
