from __future__ import annotations

import os
import asyncio
import sys
import time
from pathlib import Path

import pytest
import sunpack_native

from sunpack.runtime.watch.scheduler import WatchScheduler
from sunpack.runtime.watch.scanner import _candidate_for
from tests.helpers.config_factory import make_config
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
        make_config({
            "watch": {
                "clipboard_monitor_enabled": False,
                "quiet_min_seconds": 0.05,
                "quiet_max_seconds": 0.25,
            }
        }),
        [str(root)],
        out_dir=str(root / "out"),
        state_path=str(root / ".watch-state" / "state.json"),
        cold_start_seconds=cold_start_seconds,
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


def test_volume_recovery_pages_scopes_moves_and_replays_failed_commit(tmp_path, monkeypatch):
    """Catch lost Journal prefixes and per-root rereads with one real volume.

    File observation tests cannot detect either recovery fault. One batch corpus
    also covers deep moves, shallow exclusion and replay after a WAL failure.
    """
    from sunpack.runtime.watch.roots import WatchRootEntry
    from sunpack.core.support.path_keys import path_key

    first, second = tmp_path / "recursive", tmp_path / "shallow"
    first.mkdir()
    second.mkdir()
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    carried = incoming / "already-present.opaque"
    carried.write_bytes(b"x")
    vanished = first / "deleted.opaque"
    vanished.write_bytes(b"x")
    watcher = WatchScheduler(make_config({"filesystem": {"scan_filters_enabled": False}}),
        [str(first), str(second)], root_entries=[
            WatchRootEntry(str(first), str(first), recursive=True),
            WatchRootEntry(str(second), str(second), recursive=False)],
        state_path=str(tmp_path / "state" / "state.json"),
        pipeline_engine=FakePipelineEngine(lambda _config: None))
    try:
        watcher._scan_candidates([str(first), str(second)], recursive=True)
        watcher._prepare_usn_startup_baseline()
        volume, journal_id, start = sunpack_native.watch_volume_cursor(str(first))
        deep = first / ("deep-" + "x" * 80)
        deep.mkdir()
        expected = set()
        for index in range(600):
            path = deep / f"part{index:04d}.disguised"
            path.write_bytes(b"x")
            expected.add(path_key(str(path)))
        moved = first / "moved"
        incoming.rename(moved)
        expected.add(path_key(str(moved / carried.name)))
        allowed = second / "allowed.opaque"
        allowed.write_bytes(b"x")
        expected.add(path_key(str(allowed)))
        excluded = second / "deeper"
        excluded.mkdir()
        (excluded / "outside-scope.opaque").write_bytes(b"x")
        vanished.unlink()
        _, _, end = sunpack_native.watch_volume_cursor(str(first))
        scopes = [scope.native for scope in watcher.scopes.values()]
        cursor, pages, seen = start, 0, set()
        while cursor < end:
            batch = sunpack_native.watch_volume_changes(volume, cursor, end)
            assert batch.journal_id == journal_id
            assert cursor < batch.next_usn <= end
            seen.update(path_key(path) for path, _ in batch.paths_for_scopes(scopes))
            cursor = batch.next_usn
            pages += 1
        assert pages > 1
        assert expected - {path_key(str(moved / carried.name))} <= seen
        assert path_key(str(vanished)) in seen
        assert path_key(str(excluded / "outside-scope.opaque")) not in seen

        saved = watcher.state.watch_cursor(volume)
        with monkeypatch.context() as patch:
            patch.setattr(watcher.state, "queue_recovery_batch", lambda *a, **k: (_ for _ in ()).throw(OSError("WAL unavailable")))
            watcher._recover_usn_startup_gap()
        assert watcher.state.watch_cursor(volume) == saved
        watcher._recover_usn_startup_gap()
        queued = {path_key(item.path) for item in watcher.state.pending_work_items()}
        assert queued == expected
        assert watcher.state.watch_cursor(volume)["next_usn"] >= end
        assert not watcher.state._native.runtime_keys("file|" + path_key(str(first)) + "|deleted|")
    finally:
        watcher.state.close()


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
