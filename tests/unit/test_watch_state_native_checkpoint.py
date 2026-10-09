import json

import pytest

from sunpack.runtime.watch.scanner import WatchCandidate
from sunpack.runtime.watch.state import WatchStateStore


def test_native_checkpoint_persists_only_declared_dataclass_fields(tmp_path):
    state_path = tmp_path / "state.json"
    state = WatchStateStore(str(state_path))
    archive = tmp_path / "archive.7z"
    state.mark(
        str(archive),
        7,
        12.0,
        status="failed_password",
        failure_payload={"blockers": ["password"]},
    )
    entry = state.latest_entry_for_path(str(archive))
    assert entry is not None
    entry.runtime_only_probe = {"must_not_persist": True}

    state.save()

    payload = json.loads(state_path.read_text(encoding="utf-8"))
    [persisted] = payload["entries"].values()
    assert "runtime_only_probe" not in persisted
    assert persisted["path"] == str(archive)
    assert WatchStateStore(str(state_path)).latest_entry_for_path(str(archive)) is not None


@pytest.mark.parametrize("storage", ["journal", "checkpoint"])
def test_native_state_replay_preserves_fractional_mtime_identity(tmp_path, storage):
    state_path = tmp_path / "state.json"
    state = WatchStateStore(str(state_path))
    # Real timestamp from the split-volume recovery failure: default JSON
    # float decoding changed this value by one binary64 precision unit.
    candidate = WatchCandidate(
        str(tmp_path / "archive.7z.001"), 65536, 1791458483.9542453,
        file_id="same-file", change_usn=600524574000,
    )
    state.queue_active(candidate, durable_owner=True, durable=True)
    state.mark(
        candidate.path, candidate.size, candidate.mtime,
        file_id=candidate.file_id, change_usn=candidate.change_usn,
        status="suspended_missing_volume",
    )
    if storage == "checkpoint":
        state.save()
    else:
        state.flush()

    recovered = WatchStateStore(str(state_path))
    assert recovered.pending_work_for_path(candidate.path).mtime.hex() == candidate.mtime.hex()
    assert recovered.latest_entry_for_path(candidate.path).mtime.hex() == candidate.mtime.hex()
    recovered.complete_work_if_matches(candidate)
    assert recovered.pending_work_count == 0


def test_idle_trim_releases_peak_capacity_without_losing_live_or_frozen_state(tmp_path):
    from sunpack_native import NativeWatchState

    state = WatchStateStore(str(tmp_path / "state.json"))
    candidates = [WatchCandidate(str(tmp_path / f"{index}.bin"), index, 1.0) for index in range(512)]
    for candidate in candidates:
        state.queue_active(candidate, persist=False)
    for candidate in candidates[:32]:
        state.mark(candidate.path, candidate.size, candidate.mtime, status="failed_password")
    state.merge_watch_cursors({"c:": {"journal_id": 1, "next_usn": 2}})
    state.mark_password_source_changed("password-set")
    frozen = state._native.capture(state.applied_seq)
    peak = state._native.storage_capacities()
    state.complete_work(candidate.path for candidate in candidates[1:])
    state.clear_entries(candidate.path for candidate in candidates[1:32])
    state.trim_idle_storage()
    assert state._native.storage_capacities()[0] < peak[0]
    assert state.pending_work_count == state.entry_count == 1
    assert state.watch_cursor_snapshot()["c:"] == {"journal_id": 1, "next_usn": 2}
    assert state.password_source_signature == "password-set"
    snapshot = tmp_path / "frozen.json"
    snapshot.touch()
    frozen.write(str(snapshot))
    restored = NativeWatchState()
    restored.load_snapshot(str(snapshot))
    assert restored.pending_count == 512
    assert restored.entry_count == 32
    state.complete_work([candidates[0].path])
    state.clear_entries([candidates[0].path])
    state.trim_idle_storage()
    assert state._native.storage_capacities() == (0, 0)
    state.close()
