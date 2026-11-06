import os
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext

import pytest

from sunpack.core.analysis.embedded import scan_embedded_archives
from sunpack.core.support.global_cache_manager import clear_cache_namespace


def test_shared_embedded_scanner_generation_and_borrow_lifecycle(tmp_path, monkeypatch):
    # Ordinary single-flight tests miss metadata collisions and eviction while
    # scanning. Exercise both with real native sessions in one cache lifecycle.
    from sunpack.core.support import archive_sessions

    path = tmp_path / "carrier.jpg"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("payload.txt", "payload")
    other = tmp_path / "other.bin"
    other.write_bytes(b"other")
    stamp = path.stat()
    calls = 0
    started = threading.Event()
    release = threading.Event()
    scanned = []
    native_session = archive_sessions.NativeArchiveSession

    class Session:
        def __init__(self, path):
            self.native = native_session(path)

        def __getattr__(self, name):
            return getattr(self.native, name)

        def scan_embedded_archives(self):
            nonlocal calls
            calls += 1
            scanned.append(self)
            started.set()
            assert release.wait(10), "test did not release the native scan"
            return self.native.scan_embedded_archives()

    archive_sessions.clear_archive_sessions()
    clear_cache_namespace("embedded_archive_scan_v4")
    monkeypatch.setattr(archive_sessions, "NativeArchiveSession", Session)
    monkeypatch.setattr(archive_sessions, "_MAX_SESSIONS", 1)
    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(scan_embedded_archives, str(path)) for _ in range(8)]
            try:
                assert started.wait(10), "native scan did not start"
                archive_sessions.get_archive_session(str(other))
                assert not scanned[0].closed
            finally:
                release.set()
            results = [future.result() for future in futures]

        assert calls == 1
        assert scanned[0].closed
        assert all(result is results[0] for result in results)
        assert results[0].candidates[0].format == "zip"
        with pytest.raises(ValueError, match="file_size mismatch"):
            scan_embedded_archives(str(path), expected_size=stamp.st_size + 1)
        assert calls == 1

        path.rename(tmp_path / "retired.bin")
        path.write_bytes(b"\0" * stamp.st_size)
        os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        current = scan_embedded_archives(str(path), expected_size=stamp.st_size)
        assert calls == 2
        assert current.candidates == ()
        from sunpack.core.support.global_cache_manager import global_cache_stats
        assert global_cache_stats()["namespaces"]["embedded_archive_scan_v4"] == 1
    finally:
        archive_sessions.clear_archive_sessions()
        clear_cache_namespace("embedded_archive_scan_v4")


def test_embedded_scanner_preserves_native_budget_exhaustion(monkeypatch):
    class Session:
        generation_token = "budget-exhausted-generation"

        def scan_embedded_archives(self):
            return {
                "found": False,
                "complete": False,
                "signature_scan_complete": False,
                "logical_resolution_complete": False,
                "budget_exhausted": True,
                "raw_hit_count": 1_000_001,
                "candidates": [],
                "hits": [],
                "read_bytes": 4096,
                "file_size": 4096,
            }

    clear_cache_namespace("embedded_archive_scan_v4")
    monkeypatch.setattr("sunpack.core.analysis.embedded.scanner.borrow_archive_sessions", lambda paths: nullcontext((Session(),)))

    result = scan_embedded_archives(
        "dense-signatures.bin",
        expected_size=4096,
    )

    assert result.complete is False
    assert result.logical_resolution_complete is False
    assert result.budget_exhausted is True
    assert result.raw_hit_count == 1_000_001
    assert result.candidates == ()
