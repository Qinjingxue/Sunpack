import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from sunpack.core.analysis.embedded import scan_embedded_archives
from sunpack.core.support.global_cache_manager import clear_cache_namespace


def test_shared_embedded_scanner_is_single_flight_per_file_identity(monkeypatch):
    calls = 0

    class Session:
        def scan_embedded_archives(self):
            nonlocal calls
            calls += 1
            time.sleep(0.03)
            return {
                "found": True,
                "complete": True,
                "signature_scan_complete": True,
                "logical_resolution_complete": True,
                "raw_hit_count": 1,
                "budget_exhausted": False,
                "candidates": [{
                    "format": "zip",
                    "detected_ext": ".zip",
                    "offset": 128,
                    "end_offset": 512,
                    "confidence": 0.99,
                    "validation": "zip_structure",
                    "candidate_kind": "logical_archive",
                    "boundary_kind": "exact",
                    "extractable": True,
                }],
                "hits": [{"name": "zip_local", "offset": 128}],
                "read_bytes": 1024,
                "file_size": 1024,
            }

    clear_cache_namespace("embedded_archive_scan_v4")
    monkeypatch.setattr("sunpack.core.analysis.embedded.scanner.get_archive_session", lambda path: Session())
    identity = ("same-file", 1024, 1)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(
            lambda _: scan_embedded_archives("same-file", expected_size=1024, identity=identity),
            range(8),
        ))

    assert calls == 1
    assert all(result is results[0] for result in results)
    assert all(result.candidates[0].offset == 128 for result in results)


def test_embedded_scanner_preserves_native_budget_exhaustion(monkeypatch):
    class Session:
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

    clear_cache_namespace("embedded_archive_scan_v3")
    monkeypatch.setattr("sunpack.core.analysis.embedded.scanner.get_archive_session", lambda path: Session())

    result = scan_embedded_archives(
        "dense-signatures.bin",
        expected_size=4096,
        identity=("dense-signatures", 4096, 1),
    )

    assert result.complete is False
    assert result.logical_resolution_complete is False
    assert result.budget_exhausted is True
    assert result.raw_hit_count == 1_000_001
    assert result.candidates == ()


def test_embedded_scanner_rejects_legacy_native_schema(monkeypatch):
    class Session:
        def scan_embedded_archives(self):
            return {
                "complete": True,
                "candidates": [],
                "hits": [],
                "read_bytes": 0,
                "file_size": 0,
            }

    clear_cache_namespace("embedded_archive_scan_v3")
    monkeypatch.setattr("sunpack.core.analysis.embedded.scanner.get_archive_session", lambda path: Session())

    with pytest.raises(TypeError, match="missing required fields"):
        scan_embedded_archives("legacy.bin", identity=("legacy", 0, 1))
