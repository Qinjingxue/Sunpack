from types import SimpleNamespace

from sunpack.filesystem.watcher.journal_commit import journal_stats
from sunpack.filesystem.watcher.state import WatchStateStore


def _candidate(path, index):
    return SimpleNamespace(
        path=str(path.resolve()),
        size=1000 + index,
        mtime=1780000000.0 + index,
        file_id=f"native-frontier-{index}",
        change_usn=index,
    )


def test_durable_frontier_covers_prior_nondurable_writes(tmp_path):
    state_path = tmp_path / "state.json"
    state = WatchStateStore(str(state_path))
    first = _candidate(tmp_path / "first.zip", 1)
    second = _candidate(tmp_path / "second.zip", 2)

    state.queue_active(first, durable=False)
    state.queue_active(second, durable=True)

    stats = journal_stats(state._writer_stream)
    assert stats["written_seq"] >= state.applied_seq
    assert stats["durable_seq"] >= state.applied_seq
    assert {item.path for item in WatchStateStore(str(state_path)).pending_work_items()} == {
        first.path,
        second.path,
    }


def test_clean_explicit_flush_does_not_repeat_physical_sync(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.json"))
    state.queue_active(_candidate(tmp_path / "queued.zip", 1), durable=False)
    state.flush()
    first = journal_stats(state._writer_stream)

    state.flush()
    second = journal_stats(state._writer_stream)

    assert second["durable_seq"] >= state.applied_seq
    assert second["flush_calls"] == first["flush_calls"]
    assert second["flush_rounds"] == first["flush_rounds"]
