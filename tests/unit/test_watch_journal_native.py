from types import SimpleNamespace
import gc
import weakref

from sunpack_native import watch_journal_flush_all, watch_journal_request_flush

from sunpack.runtime.watch.journal_commit import journal_stats
from sunpack.runtime.watch.state import WatchStateStore


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


def test_last_stream_owner_releases_resources_and_old_tickets_survive_reopen(tmp_path):
    # Length/frontier tests cannot detect ownership leaks or a ticket reading a
    # newly opened stream. This exercises both through the real WAL writer.
    for index in range(4):
        path = tmp_path / f"state-{index}.json"
        first = WatchStateStore(str(path))
        candidate = _candidate(tmp_path / f"queued-{index}.zip", index + 1)
        first.queue_active(candidate, durable=False)
        second = WatchStateStore(str(path))
        coordinator = weakref.ref(first._path_coordinator)
        ticket = watch_journal_request_flush(first._writer_stream, first.applied_seq)
        first.close()
        assert journal_stats(second._writer_stream)["owners"] == 1
        second.queue_active(_candidate(tmp_path / f"other-{index}.zip", index + 10), durable=False)
        stream = second._writer_stream
        second.close()
        second.close()
        assert coordinator() is None
        assert not journal_stats(stream)["registered"]
        assert journal_stats(stream)["segments"] == 0
        # Reopening starts a new stream; old tickets still observe their own
        # completed durable frontier and do not wait on the new incarnation.
        reopened = WatchStateStore(str(path))
        ticket.wait()
        assert reopened.pending_work_count == 2
        owner = weakref.ref(reopened)
        del reopened
        gc.collect()
        # The GC release is queued; immediate ownership admission must follow
        # it without requiring the caller to run a global flush first.
        successor = WatchStateStore(str(path))
        assert successor.pending_work_count == 2
        successor.close()
        watch_journal_flush_all()
        assert owner() is None
        assert not journal_stats(stream)["registered"]
