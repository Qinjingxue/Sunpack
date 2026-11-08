from __future__ import annotations

import ctypes
import os
import threading
import time
from functools import lru_cache

from sunpack.core.platform.windows.toast_protocol import ToastSnapshot, ToastSnapshotKind, encode_snapshot
from sunpack.core.support.process_executable import current_process_executable
from sunpack.core.support.resources import get_toast_library_path


def _check_hresult(result: int) -> None:
    if result < 0:
        raise OSError(f"Windows toast call failed (HRESULT 0x{result & 0xFFFFFFFF:08X})")


@lru_cache(maxsize=1)
def _load_library():
    # ctypes.CDLL releases the GIL during calls. Loading is deferred until watch
    # starts (or an explicit registration/activation bootstrap is requested).
    # Keep one module reference across watch reloads and late COM callbacks.
    library = ctypes.CDLL(os.path.abspath(get_toast_library_path()))
    signatures = {
        "create_presenter": [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)],
        "show": [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint64],
        "clear": [ctypes.c_void_p],
        "destroy": [ctypes.c_void_p],
        "activate": [],
        "cancel_batch": [ctypes.c_wchar_p, ctypes.c_uint32],
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
    def __init__(self, *, diagnostic_log_path=None):
        self._library = _load_library()
        self._context = ctypes.c_void_p()
        _check_hresult(self._library.sunpack_toast_create_presenter(
            str(current_process_executable()), diagnostic_log_path or "", ctypes.byref(self._context),
        ))

    def show(self, payload: bytes, sequence: int) -> None:
        _check_hresult(self._library.sunpack_toast_show(self._context, payload, len(payload), sequence))

    def clear(self) -> None:
        _check_hresult(self._library.sunpack_toast_clear(self._context))

    def close(self) -> None:
        if self._context.value:
            _check_hresult(self._library.sunpack_toast_destroy(self._context))
            self._context = ctypes.c_void_p()


def activate_toast() -> int:
    library = _load_library()
    _check_hresult(library.sunpack_toast_activate())
    batch = ctypes.create_unicode_buffer(33)
    _check_hresult(library.sunpack_toast_cancel_batch(batch, len(batch)))
    if batch.value:
        from sunpack.runtime.cli.persistent_process import _try_send
        response = _try_send({"argv": ["--cancel-watch-batch", batch.value], "cwd": os.getcwd()})
        exit_code = int(response.get("exit_code", 1)) if response is not None else 1
        if exit_code:
            from sunpack.core.config.cli_settings import load_cli_language_from_config
            from sunpack.core.i18n import I18nContext

            i18n = I18nContext(load_cli_language_from_config())
            presenter = _NativeToastPresenter()
            try:
                presenter.show(encode_snapshot(ToastSnapshot(
                    kind=ToastSnapshotKind.FAILURE,
                    batch_id=batch.value + "-cancel",
                    title=i18n.t("interrupt.stop_failed_title"),
                    body=i18n.t("interrupt.stop_failed"),
                )), 1)
            finally:
                presenter.close()
        return exit_code
    return 0


class ToastManager:
    """Coalesce watch snapshots and own WinRT on one thread in the main process."""

    def __init__(self, *, diagnostic_log_path=None,
                 logger=None, presenter_factory=None):
        self._diagnostic_log_path = diagnostic_log_path
        self._update_interval = 0.05
        self._logger = logger
        self._presenter_factory = presenter_factory or _NativeToastPresenter
        self._condition = threading.Condition()
        self._snapshot: ToastSnapshot | None = None
        self._revision = 0
        self._stopping = False
        self._unavailable = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        with self._condition:
            if self._thread is not None:
                return
            self._stopping = False
            self._unavailable = False
            self._thread = threading.Thread(target=self._run, name="sunpack-toast", daemon=True)
            self._thread.start()

    def publish(self, snapshot: ToastSnapshot) -> None:
        with self._condition:
            if self._stopping or self._unavailable:
                return
            self._snapshot = snapshot
            self._revision += 1
            self._condition.notify_all()

    def clear(self) -> None:
        with self._condition:
            if self._stopping or self._unavailable:
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
            if self._thread is thread:
                self._thread = None
                self._snapshot = None
                self._revision = 0

    def _run(self) -> None:
        presenter = None
        consumed_revision = 0
        next_progress_send = 0.0
        sequence = 0
        active_progress = False
        try:
            while True:
                with self._condition:
                    if self._stopping:
                        break
                    revision = self._revision
                    now = time.monotonic()
                    changed = revision != consumed_revision
                    due = changed and (
                        self._snapshot is None or self._snapshot.kind != ToastSnapshotKind.PROGRESS
                        or now >= next_progress_send
                    )
                    if not due:
                        timeout = max(0.0, next_progress_send - now) if changed else None
                        self._condition.wait_for(
                            lambda: self._stopping or self._revision != revision, timeout=timeout,
                        )
                        continue
                    # Once accepted, only the in-flight send needs this snapshot.
                    # A newer publish can independently fill the pending slot.
                    consumed_revision = revision
                    snapshot = self._snapshot
                    self._snapshot = None
                try:
                    if snapshot is None:
                        if presenter is not None:
                            presenter.clear()
                            next_progress_send = time.monotonic() + self._update_interval
                        active_progress = False
                        continue
                    try:
                        payload = encode_snapshot(snapshot)
                    except ValueError as exc:
                        self._log("toast_snapshot_rejected", error=str(exc))
                        with self._condition:
                            if revision == self._revision:
                                self._revision += 1  # Clear existing progress only if still current.
                        continue
                    if presenter is None:
                        try:
                            presenter = self._presenter_factory(
                                diagnostic_log_path=self._diagnostic_log_path,
                            )
                        except Exception as exc:
                            # A new snapshot cannot repair component initialization.
                            with self._condition:
                                self._unavailable = True
                                self._snapshot = None
                            self._log("toast_unavailable", error=str(exc))
                            return
                        self._log("toast_started", pid=os.getpid())
                    sequence += 1
                    presenter.show(payload, sequence)
                    active_progress = snapshot.kind == ToastSnapshotKind.PROGRESS
                    if active_progress:
                        next_progress_send = time.monotonic() + self._update_interval
                except Exception as exc:
                    self._log("toast_error", error=str(exc))
                    active_progress = False
                    if presenter is not None:
                        self._close_presenter(presenter)
                        presenter = None
                finally:
                    snapshot = payload = None
        finally:
            if presenter is not None:
                if active_progress:
                    try:
                        presenter.clear()
                    except Exception as exc:
                        self._log("toast_error", error=str(exc))
                self._close_presenter(presenter)

    def _close_presenter(self, presenter) -> None:
        try:
            presenter.close()
        except Exception as exc:
            self._log("toast_error", error=str(exc))

    def _log(self, event: str, **payload) -> None:
        try:
            if self._logger is not None:
                self._logger.write(event, **payload)
        except Exception:
            pass
