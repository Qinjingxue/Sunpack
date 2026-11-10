"""Targeted regressions for file generations, output identity and idle caches."""

import asyncio
import subprocess
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from sunpack.core.support.archive_sessions import (
    clear_archive_sessions,
    get_archive_session,
)
from sunpack.core.support.output_reservation import OutputReservationRegistry
from sunpack.pipeline.coordinator.engine import PipelineEngine, _PathLeaseRegistry


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


def test_bug_regression_idle_allocator_cleanup_preserves_active_owners(tmp_path):
    registry = OutputReservationRegistry()
    default = str(tmp_path / "archive")
    with patch(
        "sunpack.core.support.output_paths.os.path.exists",
        side_effect=lambda p: "(" not in p,
    ):
        first = registry.reserve(default, "first")
        second = registry.reserve(default, "second")
        assert first != second
        assert registry.clear_idle_cache() == {"skipped": True}
        registry.release("first")
        assert registry.clear_idle_cache() == {"skipped": True}
        registry.release("second")
        report = registry.clear_idle_cache()
        assert report["families"] > 0
        assert report["slots"] == 0
        assert registry.clear_idle_cache() == {"families": 0, "slots": 0}
        assert registry.reserve(default, "third") == first
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
        registry.reserve(str(tmp_path / "archive"), "owner")
        registry.release("owner")

    class Broker:
        async def run(self, stage, key, action, **kwargs):
            return action()

    engine = PipelineEngine.__new__(PipelineEngine)
    engine._path_leases = _PathLeaseRegistry({})
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
