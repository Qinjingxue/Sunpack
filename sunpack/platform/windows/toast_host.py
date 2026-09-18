from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import threading
import time
from functools import lru_cache
from pathlib import Path

from sunpack.platform.windows.toast_protocol import ToastSnapshot, ToastSnapshotKind, encode_snapshot
from sunpack.support.process_executable import current_process_executable
from sunpack.support.resources import get_toast_library_path


_TOAST_APP_ID_KEY = r"Software\Classes\AppUserModelId\SunPack.Watch.Toast"


def _runtime_argv(argument: str) -> list[str]:
    if getattr(sys, "frozen", False) or "__compiled__" in globals():
        return [str(current_process_executable()), argument]
    executable = current_process_executable().with_name("pythonw.exe")
    script = Path(__file__).resolve().parents[3] / "sunpack.py"
    return [str(executable), str(script), argument]


def _activation_command() -> tuple[str, str]:
    argv = _runtime_argv("--toast-activated")
    return argv[0], subprocess.list2cmdline(argv[1:])


def _remove_current_user_toast_identity() -> None:
    import winreg

    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, _TOAST_APP_ID_KEY)
    except FileNotFoundError:
        pass


def _unregister_toast() -> None:
    from sunpack.platform.windows.elevation import is_process_elevated

    if not is_process_elevated():
        _remove_current_user_toast_identity()
        return

    library = _load_library()
    _check_hresult(library.sunpack_toast_unregister())

    from sunpack.platform.windows.process_launch import launch_unelevated

    argv = _runtime_argv("--unregister-toast-current-user")
    process = launch_unelevated(argv, cwd=str(current_process_executable().parent))
    try:
        try:
            exit_code = process.wait(timeout=30.0)
        except subprocess.TimeoutExpired:
            exit_code = None
        if exit_code is None:
            try:
                process.terminate()
                process.wait(timeout=5.0)
            except Exception:
                pass
            raise OSError("current-user Toast cleanup timed out")
        if int(exit_code) != 0:
            raise OSError(f"current-user Toast cleanup failed with exit code {int(exit_code)}")
    finally:
        close = getattr(process, "close", None)
        if callable(close):
            close()


def _check_hresult(result: int) -> None:
    if result < 0:
        raise OSError(f"Windows toast call failed (HRESULT 0x{result & 0xFFFFFFFF:08X})")


@lru_cache(maxsize=None)
def _load_library(path: str | None = None):
    # ctypes.CDLL releases the GIL during calls. Loading is deferred until watch
    # starts (or an explicit registration/activation bootstrap is requested).
    # Keep one module reference across watch reloads and late COM callbacks.
    library = ctypes.CDLL(os.path.abspath(path or get_toast_library_path()))
    signatures = {
        "create": [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)],
        "show": [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint64],
        "clear": [ctypes.c_void_p],
        "destroy": [ctypes.c_void_p],
        "register": [ctypes.c_wchar_p, ctypes.c_wchar_p],
        "unregister": [],
        "activate": [],
        "self_test": [],
    }
    for name, arguments in signatures.items():
        function = getattr(library, "sunpack_toast_" + name)
        function.argtypes = arguments
        function.restype = ctypes.c_int32
    return library


def self_test_toast() -> None:
    library = _load_library()
    _check_hresult(library.sunpack_toast_self_test())


class _NativeToastPresenter:
    def __init__(self, *, library_path=None, diagnostic_log_path=None):
        self._library = _load_library(library_path)
        self._context = ctypes.c_void_p()
        executable, arguments = _activation_command()
        _check_hresult(self._library.sunpack_toast_create(
            executable, arguments, diagnostic_log_path or "", ctypes.byref(self._context),
        ))

    def show(self, payload: bytes, sequence: int) -> None:
        _check_hresult(self._library.sunpack_toast_show(self._context, payload, len(payload), sequence))

    def clear(self) -> None:
        _check_hresult(self._library.sunpack_toast_clear(self._context))

    def close(self) -> None:
        if self._context.value:
            _check_hresult(self._library.sunpack_toast_destroy(self._context))
            self._context = ctypes.c_void_p()


def handle_toast_argv(argv: list[str]) -> int | None:
    if not argv or argv[0] not in {
        "--register-toast",
        "--unregister-toast",
        "--unregister-toast-current-user",
        "--toast-activated",
    }:
        return None
    if argv[0] == "--unregister-toast-current-user":
        _remove_current_user_toast_identity()
        return 0
    if argv[0] == "--unregister-toast":
        _unregister_toast()
        return 0

    library = _load_library()
    if argv[0] == "--register-toast":
        result = library.sunpack_toast_register(*_activation_command())
    else:
        result = library.sunpack_toast_activate()
    _check_hresult(result)
    return 0


class ToastManager:
    """Coalesce watch snapshots and own WinRT on one thread in the main process."""

    def __init__(self, *, library_path=None, diagnostic_log_path=None,
                 update_interval_ms: int = 50, logger=None, presenter_factory=None):
        self._library_path = library_path
        self._diagnostic_log_path = diagnostic_log_path
        self._update_interval = max(0.01, min(1.0, int(update_interval_ms) / 1000.0))
        self._logger = logger
        self._presenter_factory = presenter_factory or _NativeToastPresenter
        self._condition = threading.Condition()
        self._snapshot: ToastSnapshot | None = None
        self._revision = 0
        self._stopping = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        with self._condition:
            if self._thread is not None:
                return
            self._stopping = False
            self._thread = threading.Thread(target=self._run, name="sunpack-toast", daemon=True)
            self._thread.start()

    def publish(self, snapshot: ToastSnapshot) -> None:
        with self._condition:
            if self._stopping:
                return
            self._snapshot = snapshot
            self._revision += 1
            self._condition.notify_all()

    def clear(self) -> None:
        with self._condition:
            if self._stopping:
                return
            self._snapshot = None
            self._revision += 1
            self._condition.notify_all()

    def stop(self) -> None:
        with self._condition:
            thread = self._thread
            if thread is None:
                return
            self._stopping = True
            self._condition.notify_all()
        # The owning thread must release the COM objects and apartment before
        # watch reload can register a new activator. Never abandon that thread.
        thread.join()
        with self._condition:
            self._thread = None
            self._snapshot = None

    def _run(self) -> None:
        presenter = None
        sent_revision = -1
        next_progress_send = 0.0
        expires_at = 0.0
        sequence = 0
        failures = 0
        try:
            while True:
                with self._condition:
                    if self._stopping:
                        break
                    snapshot, revision = self._snapshot, self._revision
                    now = time.monotonic()
                    # Expiry applies to the delivered snapshot, even while a
                    # newer progress update is waiting for its throttle slot.
                    expire = bool(expires_at and now >= expires_at)
                    changed = revision != sent_revision
                    due = changed and (
                        snapshot is None or snapshot.kind != ToastSnapshotKind.PROGRESS
                        or now >= next_progress_send
                    )
                    if not expire and not due and presenter is not None:
                        deadlines = [expires_at] if expires_at else []
                        if changed:
                            deadlines.append(next_progress_send)
                        timeout = max(0.0, min(deadlines) - now) if deadlines else None
                        self._condition.wait_for(
                            lambda: self._stopping or self._revision != revision, timeout=timeout,
                        )
                        continue
                try:
                    if presenter is None:
                        presenter = self._presenter_factory(
                            library_path=self._library_path,
                            diagnostic_log_path=self._diagnostic_log_path,
                        )
                        sent_revision = -1
                        self._log("toast_started", pid=os.getpid())
                    if expire:
                        presenter.clear()
                        expires_at = 0.0
                        with self._condition:
                            if self._revision == sent_revision:
                                self._snapshot = None
                        if not due:
                            continue
                    if due:
                        if snapshot is None:
                            presenter.clear()
                        else:
                            payload = encode_snapshot(snapshot)
                            sequence += 1
                            presenter.show(payload, sequence)
                        sent_revision = revision
                        # Start the visible TTL only after Show succeeded.
                        ttl_ms = max(0, min(0xFFFFFFFF, int(snapshot.ttl_ms))) if snapshot else 0
                        expires_at = time.monotonic() + ttl_ms / 1000.0 if ttl_ms else 0.0
                        if snapshot is None or snapshot.kind == ToastSnapshotKind.PROGRESS:
                            next_progress_send = time.monotonic() + self._update_interval
                    failures = 0
                except ValueError as exc:
                    self._log("toast_snapshot_rejected", error=str(exc))
                    with self._condition:
                        if revision == self._revision:
                            self._snapshot = None
                            self._revision += 1
                except Exception as exc:
                    failures += 1
                    self._log("toast_error", error=str(exc), attempt=failures)
                    if presenter is not None:
                        presenter.close()
                        presenter = None
                    # A delivered terminal must not reappear after its TTL.
                    with self._condition:
                        if expires_at and time.monotonic() >= expires_at and self._revision == sent_revision:
                            self._snapshot = None
                    self._wait_for_stop(min(30.0, 0.25 * (2 ** min(failures - 1, 7))))
        finally:
            if presenter is not None:
                presenter.close()

    def _wait_for_stop(self, seconds: float) -> None:
        with self._condition:
            self._condition.wait_for(lambda: self._stopping, timeout=seconds)

    def _log(self, event: str, **payload) -> None:
        try:
            if self._logger is not None:
                self._logger.write(event, **payload)
        except Exception:
            pass
