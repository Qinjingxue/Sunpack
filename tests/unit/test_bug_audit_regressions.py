"""Targeted regressions for file generations, output identity and idle caches."""

import asyncio
import subprocess
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import sunpack_native

from sunpack.core.support.archive_sessions import (
    clear_archive_sessions,
    get_archive_session,
)
from sunpack.core.support.output_reservation import OutputReservationRegistry
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.pipeline.verification.methods.expected_name_presence import (
    ExpectedNamePresenceMethod,
)


def _powershell(script):
    subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ErrorActionPreference='Stop'; " + script,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("replace", [True, False])
def test_bug_regression_session_refreshes_equal_size_restored_timestamp_input(
    tmp_path, replace
):
    path = str(tmp_path / "source.dat")
    literal = path.replace("'", "''")
    clear_archive_sessions()
    try:
        _powershell(f"[IO.File]::WriteAllBytes('{literal}', [byte[]](65,66,67,68))")
        original = get_archive_session(path)
        assert original.read_at(0, 4) == b"ABCD"
        generation = original.generation_token
        move = "Move-Item -LiteralPath $p -Destination ($p+'.old');" if replace else ""
        _powershell(
            f"$p='{literal}'; $m=[IO.File]::GetLastWriteTimeUtc($p); $c=[IO.File]::GetCreationTimeUtc($p);"
            f"{move} [IO.File]::WriteAllBytes($p,[byte[]](87,88,89,90));"
            "[IO.File]::SetCreationTimeUtc($p,$c); [IO.File]::SetLastWriteTimeUtc($p,$m)"
        )
        current = get_archive_session(path)
        assert current is not original
        assert current.generation_token != generation
        assert current.read_at(0, 4) == b"WXYZ"
        with ThreadPoolExecutor(max_workers=8) as executor:
            sessions = list(
                executor.map(lambda _: get_archive_session(path), range(32))
            )
        assert all(session is current for session in sessions)
    finally:
        clear_archive_sessions()


def _inventory(files):
    return sunpack_native.output_inventory_from_serialized(
        "C:/unused",
        files,
        True,
        True,
        len(files),
        0,
        len(files),
        0,
        0,
        True,
        False,
        False,
    )


def _output(path, crc, **kwargs):
    return dict(
        path=path,
        size=1,
        bytes_written=1,
        status="complete",
        has_output_crc=True,
        output_crc32=crc,
        **kwargs,
    )


def test_bug_regression_unicode_inventory_uses_distinct_outputs():
    names = ["\u00e9.txt", "e\u0301.txt"]
    outputs = [_output(names[0], 100), _output(names[1], 200)]
    expected = [
        {"path": name, "size": 1, "has_crc": True, "crc32": crc}
        for name, crc in zip(names, [100, 200])
    ]
    result = sunpack_native.match_output_inventory_coverage(
        expected, _inventory(outputs), True, "none", True
    )
    assert result["mismatch_count"] == 0
    assert result["coverage"]["complete_files"] == 2
    assert [item["path"] for item in result["observations"]] == names
    expected[1]["crc32"] = 100
    result = sunpack_native.match_output_inventory_coverage(
        expected, _inventory(outputs[:1]), True, "any", True
    )
    assert result["coverage"]["complete_files"] == 1
    assert result["missing_count"] == 1


def test_bug_regression_worker_renamed_output_paths_are_reused():
    expected = [
        {
            "path": "name.txt",
            "output_path": "name(1).txt",
            "size": 1,
            "has_crc": True,
            "crc32": 200,
        }
    ]
    outputs = [
        _output("name.txt", 100),
        _output("name.txt", 200, output_path="name(1).txt"),
    ]
    result = sunpack_native.match_output_inventory_coverage(
        expected, _inventory(outputs), True, "none", True
    )
    assert result["mismatch_count"] == 0
    assert result["coverage"]["complete_files"] == 1
    assert result["observations"][0]["path"] == "name(1).txt"


def test_bug_regression_expected_names_do_not_merge_unicode_forms():
    names = ["\u00e9.txt", "e\u0301.txt"]
    assert (
        ExpectedNamePresenceMethod()._expected_names({"expected_names": names}) == names
    )


def test_bug_regression_idle_allocator_cleanup_preserves_active_owners(tmp_path):
    registry = OutputReservationRegistry()
    default = str(tmp_path / "archive")
    with patch(
        "sunpack.core.support.output_paths.os.path.exists",
        side_effect=lambda p: "(" not in p,
    ):
        first = registry.reserve(default, "first", set())
        second = registry.reserve(default, "second", set())
        assert first != second
        assert registry.clear_idle_cache() == {"skipped": True}
        registry.release("first")
        assert registry.clear_idle_cache() == {"skipped": True}
        registry.release("second")
        report = registry.clear_idle_cache()
        assert report["families"] > 0
        assert report["slots"] == 0
        assert registry.clear_idle_cache() == {"families": 0, "slots": 0}
        assert registry.reserve(default, "third", set()) == first
        registry.release("third")


def test_bug_regression_engine_idle_cleanup_includes_output_allocator(
    tmp_path, monkeypatch
):
    import sunpack.core.support.runtime_cache_cleanup as cleanup

    registry = OutputReservationRegistry()
    with patch(
        "sunpack.core.support.output_paths.os.path.exists",
        side_effect=lambda p: "(" not in p,
    ):
        registry.reserve(str(tmp_path / "archive"), "owner", set())
        registry.release("owner")

    class Broker:
        async def run(self, stage, key, action, **kwargs):
            return action()

    engine = PipelineEngine.__new__(PipelineEngine)
    engine._services = SimpleNamespace(output_reservations=registry)
    engine._broker = Broker()
    engine.is_idle = lambda: True
    monkeypatch.setattr(cleanup, "runtime_cache_stats", dict)
    monkeypatch.setattr(cleanup, "clear_all_runtime_caches", dict)
    report = asyncio.run(engine.clear_runtime_caches())
    assert report["cleared"]["output_reservations"]["families"] == 1
    assert registry.clear_idle_cache() == {"families": 0, "slots": 0}
    engine.is_idle = lambda: False
    assert asyncio.run(engine.clear_runtime_caches()) == {"skipped": "engine_busy"}
