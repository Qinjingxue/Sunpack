"""Native report contracts not covered by toast timing/state-machine tests."""
from __future__ import annotations

import json
import tracemalloc
from collections.abc import Sequence
from pathlib import Path

import pytest

from sunpack_native import (
    NativeCancellation,
    NativeOperationCancelled,
    append_failure_report,
    publish_failure_report,
)


def _append(path, payloads, *, errors=("failed",)):
    append_failure_report(str(path), "Failure 1", "Error: ", errors, "unknown", "Details: ", payloads)


def test_large_diagnostics_stream_without_full_utf8_or_json_copies(tmp_path):
    # A normal final-report test misses JSONEncoder's full escaped token and
    # PyUnicode's full UTF-8 cache. Build input before tracing, then independently
    # exercise huge scalar strings and lazy containers through the real extension.
    path = tmp_path / "report.tmp"
    _append(path, [{"warmup": "ok"}])
    path.unlink()
    text = ('中🙂"\\\n' * (512 * 1024)) + "tail"
    tracemalloc.start()
    try:
        _append(path, [{"text": text}])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 2 * 1024 * 1024
    # Parsing is deliberately outside the memory measurement; validation itself
    # is allowed to construct the complete result.
    details = path.read_text(encoding="utf-8").split("Details: ", 1)[1]
    assert json.loads(details) == [{"text": text}]
    del details, text
    path.unlink()

    live = maximum = 0

    class Row(dict):
        def __init__(self, index):
            nonlocal live, maximum
            super().__init__(index=index, diagnostic="x" * 1024)
            live += 1
            maximum = max(maximum, live)

        def __del__(self):
            nonlocal live
            live -= 1

    class Rows(Sequence):
        def __len__(self):
            return 5_000

        def __getitem__(self, index):
            if index >= len(self):
                raise IndexError(index)
            return Row(index)

    tracemalloc.start()
    try:
        _append(path, Rows())
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert maximum <= 3 and live == 0
    assert peak < 2 * 1024 * 1024
    assert path.stat().st_size > 5_000 * 1024
    with path.open("rb") as handle:
        handle.seek(-1200, 2)
        assert b'4999' in handle.read()


def test_streamed_unicode_and_failed_append_are_lossless_and_atomic(tmp_path):
    # Cover chunk-boundary escaping plus failure halfway through an iterator.
    # A pre-cancel-only test cannot catch rollback of already-written buffers.
    path = tmp_path / "batch.tmp"
    text = "a" * 16383 + '"\\\x00\t\n\r中🙂\ud800'
    _append(path, [{"text": text, "value": [None, True, 1, 1.5]}])
    saved = path.read_bytes()
    assert json.loads(saved.decode("utf-8").split("Details: ", 1)[1])[0]["text"] == text

    class Broken(Sequence):
        def __len__(self):
            return 2

        def __getitem__(self, index):
            if index == 0:
                return "x" * (256 * 1024)
            raise ValueError("diagnostic iterator failed")

    with pytest.raises(ValueError, match="iterator failed"):
        _append(path, Broken())
    assert path.read_bytes() == saved
    cycle = {}
    cycle["self"] = cycle
    with pytest.raises(ValueError, match="Circular"):
        _append(path, [cycle])
    assert path.read_bytes() == saved
    cancellation = NativeCancellation()
    cancellation.cancel()
    with cancellation, pytest.raises(NativeOperationCancelled):
        _append(path, [{"new": "data"}])
    assert path.read_bytes() == saved

    cancellation = NativeCancellation()

    class CancelAfterFlush(Sequence):
        def __len__(self):
            return 2

        def __getitem__(self, index):
            if index == 0:
                return "x" * (256 * 1024)
            if index == 1:
                cancellation.cancel()
                return "cancelled after data reached the file"
            raise IndexError(index)

    # Unlike pre-cancellation, this also verifies that cancellation rolls back
    # bytes that already passed through both the encoder and file buffers.
    with cancellation, pytest.raises(NativeOperationCancelled):
        _append(path, CancelAfterFlush())
    assert path.read_bytes() == saved


def test_publish_failure_never_replaces_output_or_leaks_temporary(tmp_path):
    # Cancellation/error must preserve an already published report. Tests that
    # only check successful atomic rename miss temp ownership and partial copies.
    output = tmp_path / "failed.txt"
    output.write_text("previous report", encoding="utf-8")
    temporary = tmp_path / "publish.tmp"
    with pytest.raises(OSError):
        publish_failure_report(str(tmp_path / "missing"), str(temporary), str(output), ("header\n",))
    assert output.read_text(encoding="utf-8") == "previous report"
    assert not temporary.exists()
    cancellation = NativeCancellation()
    cancellation.cancel()
    with cancellation, pytest.raises(NativeOperationCancelled):
        publish_failure_report(None, str(temporary), str(output), ("header\n",))
    assert not temporary.exists()
    assert output.read_text(encoding="utf-8") == "previous report"
    details = tmp_path / "details.tmp"
    details.write_text("complete details", encoding="utf-8")
    publish_failure_report(str(details), str(temporary), str(output), ("header\n",))
    assert output.read_text(encoding="utf-8") == "header\ncomplete details"
    assert not temporary.exists()


def test_locked_publication_can_cancel_without_losing_previous_report(tmp_path):
    # The Windows replace helper retries sharing conflicts indefinitely. A
    # pre-cancel test cannot detect a stop that arrives during that retry loop.
    import ctypes
    import threading
    import time
    from ctypes import wintypes

    if not hasattr(ctypes, "WinDLL"):
        pytest.skip("Windows sharing-lock semantics")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    output = tmp_path / "failed.txt"
    output.write_text("previous", encoding="utf-8")
    handle = create(str(output), 0x80000000, 1, None, 3, 0, None)  # Read, share-read only.
    assert handle != ctypes.c_void_p(-1).value
    temporary = tmp_path / "publication.tmp"
    cancellation = NativeCancellation()
    completed = threading.Event()
    outcomes = []

    def publish():
        try:
            with cancellation:
                publish_failure_report(None, str(temporary), str(output), ("new report",))
        except BaseException as exc:
            outcomes.append(exc)
        finally:
            completed.set()

    worker = threading.Thread(target=publish)
    worker.start()
    try:
        # Wait only for the owned temporary to appear, not a timing-only sleep.
        deadline = time.monotonic() + 3
        while not temporary.exists() and not completed.is_set():
            assert time.monotonic() < deadline
            completed.wait(0.01)
        assert temporary.exists() and not completed.is_set()
        cancellation.cancel()
        assert completed.wait(3), "sharing-lock retry ignored cancellation"
        assert len(outcomes) == 1 and isinstance(outcomes[0], NativeOperationCancelled)
        assert output.read_text(encoding="utf-8") == "previous"
        assert not temporary.exists()
    finally:
        close(handle)
        cancellation.cancel()
        worker.join(3)
        assert not worker.is_alive()
