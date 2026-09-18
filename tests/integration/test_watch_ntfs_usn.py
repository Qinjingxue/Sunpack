from __future__ import annotations

import os
import asyncio
import sys
import time
from pathlib import Path

import pytest
import sunpack_native

from sunpack.filesystem.watcher.scheduler import WatchScheduler
from sunpack.filesystem.watcher.scanner import _candidate_for
from tests.helpers.fake_pipeline_engine import FakePipelineEngine


pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="NTFS USN tests require Windows"),
    pytest.mark.requires_watch_broker,
]


@pytest.fixture(scope="module", autouse=True)
def _watch_broker_lease():
    sunpack_native.watch_broker_acquire()
    try:
        yield
    finally:
        sunpack_native.watch_broker_release()


def _watcher(root: Path, *, cold_start_seconds: float = 0.05) -> WatchScheduler:
    return WatchScheduler(
        {
            "watch": {
                "clipboard_monitor_enabled": False,
                "quiet_min_seconds": 0.05,
                "quiet_max_seconds": 0.25,
            }
        },
        [str(root)],
        out_dir=str(root / "out"),
        state_path=str(root / ".watch-state" / "state.json"),
        cold_start_seconds=cold_start_seconds,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(lambda _config: None),
    )


def test_watch_root_is_ntfs_and_has_file_usn(tmp_path):
    assert sunpack_native.watch_filesystem_type(str(tmp_path)).upper() == "NTFS"
    sunpack_native.validate_ntfs_watch_root(str(tmp_path))

    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK\x03\x04payload")
    candidate = _candidate_for(str(archive))

    assert candidate is not None
    assert candidate.file_id
    assert candidate.change_usn > 0


def test_same_size_same_mtime_in_place_overwrite_changes_usn(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"A" * 1024 * 1024)
    original_mtime_ns = archive.stat().st_mtime_ns
    before = _candidate_for(str(archive))

    with archive.open("r+b") as stream:
        stream.seek(128 * 1024)
        stream.write(b"B" * 64 * 1024)
        stream.flush()
        os.fsync(stream.fileno())
    os.utime(archive, ns=(original_mtime_ns, original_mtime_ns))
    after = _candidate_for(str(archive))

    assert after.size == before.size
    assert after.mtime == before.mtime
    assert after.file_id == before.file_id
    assert after.change_usn != before.change_usn


def test_exclusive_readiness_waits_for_open_writer(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK\x03\x04payload")

    with archive.open("r+b") as writer:
        assert not sunpack_native.watch_file_is_ready(str(archive))
        writer.seek(0, os.SEEK_END)
        writer.write(b"more")
        writer.flush()
        os.fsync(writer.fileno())

    assert sunpack_native.watch_file_is_ready(str(archive))


def test_duplicate_noise_does_not_restart_generation_but_overwrite_does(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"A" * 256 * 1024)
    original_mtime_ns = archive.stat().st_mtime_ns
    watcher = _watcher(tmp_path)
    watcher.enqueue(str(archive), event_type="created")

    for event_type in ("modified", "created", "unknown") * 100:
        watcher.enqueue(str(archive), event_type=event_type)
    assert watcher._active_states[str(archive)].generation == 1

    with archive.open("r+b") as stream:
        stream.seek(0)
        stream.write(b"B" * 32 * 1024)
        stream.flush()
        os.fsync(stream.fileno())
    os.utime(archive, ns=(original_mtime_ns, original_mtime_ns))
    watcher.enqueue(str(archive), event_type="modified")
    changed_generation = watcher._active_states[str(archive)].generation

    for _ in range(300):
        watcher.enqueue(str(archive), event_type="modified")
    assert changed_generation == 2
    assert watcher._active_states[str(archive)].generation == changed_generation


def test_restoring_an_older_mtime_does_not_restart_content_quiet_window(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"A" * 256 * 1024)
    watcher = _watcher(tmp_path)
    watcher.enqueue(str(archive), event_type="created")
    baseline_event_at = watcher._active_states[str(archive)].last_event_at

    stat = archive.stat()
    restored_mtime_ns = stat.st_mtime_ns - 60_000_000_000
    os.utime(archive, ns=(stat.st_atime_ns, restored_mtime_ns))
    watcher.enqueue(str(archive), event_type="modified")

    assert watcher._active_states[str(archive)].last_event_at == baseline_event_at


def test_slow_writes_busy_handle_move_and_event_storm_reach_ready(tmp_path):
    temporary = tmp_path / "slow.zip.baiduyun.p.downloading"
    final = tmp_path / "slow.zip"
    watcher = _watcher(tmp_path)
    async def scenario():
      await watcher.start()
      try:
        with temporary.open("wb") as writer:
            for index in range(8):
                writer.write(bytes([index]) * 128 * 1024)
                writer.flush()
                os.fsync(writer.fileno())
                watcher.enqueue(str(temporary), event_type="modified")
                for _ in range(20):
                    watcher.enqueue(str(temporary), event_type="modified")
                time.sleep(0.02)
            assert watcher._pop_ready(float("inf")) == []

        os.replace(temporary, final)
        watcher.notify_path_departed(str(temporary))
        watcher.enqueue(str(final), event_type="moved", src_path=str(temporary))
        time.sleep(0.05)
        baseline_generation = watcher._active_states[str(final)].generation

        for event_type in ("modified", "unknown", "created") * 200:
            watcher.enqueue(str(final), event_type=event_type)
        assert watcher._active_states[str(final)].generation == baseline_generation

        time.sleep(0.3)
        ready = watcher._pop_ready(time.time())
        assert [Path(candidate.path).name for candidate in ready] == ["slow.zip"]
      finally:
        await watcher.stop()
    asyncio.run(scenario())
