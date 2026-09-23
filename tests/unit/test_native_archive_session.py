from __future__ import annotations

import os
import threading

import pytest

from sunpack.core.support.archive_sessions import (
    clear_archive_sessions,
    get_archive_session,
    release_archive_sessions_under,
)
from sunpack.core.analysis.view import MultiVolumeBinaryView, SharedBinaryView
from sunpack.core.support.resource_lifecycle import TaskResourceScope, promotion_barrier
from sunpack_native import (
    NativeArchiveSession,
    native_begin_promotion,
    native_end_promotion,
    native_resource_snapshot,
    native_wait_for_resources,
    reader_cache_stats,
    release_reader_resources_under,
)


@pytest.fixture(autouse=True)
def _clear_python_sessions():
    clear_archive_sessions()
    yield
    clear_archive_sessions()


def test_python_lifecycle_reuses_session_and_invalidates_changed_file(tmp_path):
    path = tmp_path / "lifecycle.bin"
    path.write_bytes(b"abcdefgh")

    first = get_archive_session(os.fspath(path))
    assert get_archive_session(os.fspath(path)) is first
    assert bytes(first.read_at(2, 4)) == b"cdef"

    path.write_bytes(b"new-content")
    second = get_archive_session(os.fspath(path))
    assert second is not first
    assert bytes(second.read_at(0, 11)) == b"new-content"


def test_rust_manager_reuses_blocks_and_handle_across_python_calls(tmp_path):
    path = tmp_path / "shared-cache.bin"
    path.write_bytes(bytes(range(256)) * 1024)

    before = dict(reader_cache_stats())
    first = NativeArchiveSession(os.fspath(path))
    assert bytes(first.read_at(17, 128)) == path.read_bytes()[17:145]
    after_first = dict(reader_cache_stats())
    del first

    second = NativeArchiveSession(os.fspath(path))
    assert bytes(second.read_at(17, 128)) == path.read_bytes()[17:145]
    after_second = dict(reader_cache_stats())

    assert after_first["physical_bytes"] > before["physical_bytes"]
    assert after_second["physical_bytes"] == after_first["physical_bytes"]
    assert after_second["cache_hits"] > after_first["cache_hits"]
    assert after_second["handle_hits"] > after_first["handle_hits"]
    assert after_second["cache_shards"] == 64


def test_clear_archive_sessions_releases_native_blocks_and_handles(tmp_path):
    path = tmp_path / "request-cache.bin"
    path.write_bytes(bytes(range(256)) * 1024)
    session = get_archive_session(os.fspath(path))
    assert bytes(session.read_at(17, 128)) == path.read_bytes()[17:145]
    del session
    populated = dict(reader_cache_stats())
    assert populated["open_handles"] >= 1
    assert populated["cache_entries"] >= 1
    assert populated["hot_cache_bytes"] + populated["general_cache_bytes"] > 0

    clear_archive_sessions()

    cleared = dict(reader_cache_stats())
    assert cleared["open_handles"] == 0
    assert cleared["cache_entries"] == 0
    assert cleared["hot_cache_bytes"] == 0
    assert cleared["general_cache_bytes"] == 0


def test_session_analysis_view_preserves_cache_budget_and_eof_semantics(tmp_path):
    path = tmp_path / "analysis-view.bin"
    path.write_bytes(b"abcdefgh")
    session = get_archive_session(os.fspath(path))
    view = session.analysis_view(cache_bytes=8, max_read_bytes=4, max_concurrent_reads=1)

    assert bytes(view.read_at(0, 4)) == b"abcd"
    assert bytes(view.read_at(0, 4)) == b"abcd"
    stats = dict(view.stats())
    assert stats == {"read_bytes": 4, "cache_hits": 1}
    with pytest.raises(RuntimeError, match="read budget exceeded"):
        view.read_at(4, 1)

    eof_view = session.analysis_view(cache_bytes=0)
    assert bytes(eof_view.read_at(6, 8)) == b"gh"


def test_release_boundary_allows_windows_pipeline_directory_promotion(tmp_path):
    source = tmp_path / "work"
    target = tmp_path / "promoted"
    source.mkdir()
    path = source / "payload.bin"
    path.write_bytes(b"payload")
    assert bytes(get_archive_session(os.fspath(path)).read_at(0, 7)) == b"payload"

    release_archive_sessions_under(os.fspath(source))
    os.replace(source, target)
    assert (target / "payload.bin").read_bytes() == b"payload"


def test_release_boundary_closes_retained_session_and_analysis_view(tmp_path):
    source = tmp_path / "work"
    target = tmp_path / "promoted"
    source.mkdir()
    path = source / "payload.bin"
    path.write_bytes(b"payload")
    session = get_archive_session(os.fspath(path))
    view = SharedBinaryView(os.fspath(path))
    assert view.read_at(0, 7) == b"payload"

    with promotion_barrier((source,), cache_releasers=(release_archive_sessions_under,)):
        assert session.closed
        assert view.closed
        os.replace(source, target)

    assert (target / "payload.bin").read_bytes() == b"payload"
    with pytest.raises((OSError, RuntimeError), match="closed"):
        session.read_at(0, 1)
    with pytest.raises(RuntimeError, match="closed"):
        view.read_at(0, 1)


def test_multi_volume_view_registers_and_releases_every_member(tmp_path):
    source = tmp_path / "volumes"
    target = tmp_path / "promoted"
    source.mkdir()
    first = source / "archive.zip.001"
    second = source / "archive.zip.002"
    first.write_bytes(b"abc")
    second.write_bytes(b"def")
    view = MultiVolumeBinaryView((first, second))
    assert view.read_at(1, 4) == b"bcde"

    with promotion_barrier((source,), cache_releasers=(release_archive_sessions_under,)):
        assert view.closed
        os.replace(source, target)

    assert (target / first.name).read_bytes() == b"abc"
    assert (target / second.name).read_bytes() == b"def"
    with pytest.raises(RuntimeError, match="closed"):
        view.read_at(0, 1)


def test_shared_session_cache_waits_for_all_task_borrowers(tmp_path):
    path = tmp_path / "shared.bin"
    path.write_bytes(b"payload")
    first_scope = TaskResourceScope("first-borrower", files=(path,))
    second_scope = TaskResourceScope("second-borrower", files=(path,))
    with first_scope.activate():
        first = get_archive_session(os.fspath(path))
    with second_scope.activate():
        second = get_archive_session(os.fspath(path))
    assert first is second
    released = threading.Event()

    def release() -> None:
        release_archive_sessions_under(os.fspath(tmp_path))
        released.set()

    worker = threading.Thread(target=release)
    worker.start()
    assert not released.wait(0.05)
    first_scope.close()
    assert not released.wait(0.05)
    second_scope.close()
    worker.join(1.0)

    assert released.is_set()
    assert first.closed


def test_native_registry_reports_reader_until_object_and_pool_are_released(tmp_path):
    path = tmp_path / "native-registry.bin"
    path.write_bytes(b"payload")
    session = NativeArchiveSession(os.fspath(path))

    snapshot = [dict(item) for item in native_resource_snapshot([os.fspath(tmp_path)])]
    assert any(item["kind"] == "reader_file" for item in snapshot)

    session.close()
    release_archive_sessions_under(os.fspath(tmp_path))

    assert list(native_resource_snapshot([os.fspath(tmp_path)])) == []


def test_native_registry_wait_is_notified_when_reader_is_released(tmp_path):
    path = tmp_path / "native-wait.bin"
    path.write_bytes(b"payload")
    session = NativeArchiveSession(os.fspath(path))
    waiting = threading.Event()
    completed = threading.Event()
    result = []

    def wait_for_release() -> None:
        waiting.set()
        result.extend(native_wait_for_resources([os.fspath(tmp_path)], 1.0))
        completed.set()

    worker = threading.Thread(target=wait_for_release)
    worker.start()
    assert waiting.wait(1.0)
    assert not completed.wait(0.05)

    session.close()
    release_reader_resources_under(os.fspath(tmp_path))
    worker.join(1.0)

    assert completed.is_set()
    assert result == []


def test_reader_pool_release_closes_file_behind_retained_native_view(tmp_path):
    path = tmp_path / "retained-native-view.bin"
    path.write_bytes(b"payload")
    session = NativeArchiveSession(os.fspath(path))
    view = session.analysis_view()
    assert bytes(view.read_at(0, 7)) == b"payload"

    session.close()
    report = dict(release_reader_resources_under(os.fspath(tmp_path)))

    assert report["handles"] == 1
    assert list(native_resource_snapshot([os.fspath(tmp_path)])) == []
    with pytest.raises((OSError, RuntimeError), match="resource closed"):
        view.read_at(0, 1)


def test_native_promotion_gate_rejects_new_overlapping_file_handles(tmp_path):
    path = tmp_path / "native-gated.bin"
    path.write_bytes(b"payload")
    token = native_begin_promotion([os.fspath(tmp_path)])
    try:
        with pytest.raises((BlockingIOError, OSError), match="blocked by promotion"):
            NativeArchiveSession(os.fspath(path))
    finally:
        native_end_promotion(token)

    session = NativeArchiveSession(os.fspath(path))
    assert bytes(session.read_at(0, 7)) == b"payload"
    session.close()
