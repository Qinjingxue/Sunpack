import os

import pytest

from sunpack.core.support import archive_sessions
from sunpack.core.analysis.view import SharedBinaryView
from sunpack.core.support.resource_lifecycle import ResourceLifecycleError, TaskResourceScope


def test_archive_session_eviction_keeps_live_borrow_and_reopens_new_generation(tmp_path, monkeypatch):
    path = tmp_path / "archive.bin"
    other = tmp_path / "other.bin"
    path.write_bytes(b"old data")
    other.write_bytes(b"other")
    stamp = path.stat()

    archive_sessions.clear_archive_sessions()
    monkeypatch.setattr(archive_sessions, "_MAX_SESSIONS", 1)
    try:
        with archive_sessions.borrow_archive_sessions((path,)) as (borrowed,):
            archive_sessions.get_archive_session(str(other))
            assert not borrowed.closed
            path.rename(tmp_path / "retired.bin")
            path.write_bytes(b"new data")
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            with archive_sessions.borrow_archive_sessions((path,)) as (current,):
                assert current.generation_token != borrowed.generation_token
        assert borrowed.closed
    finally:
        archive_sessions.clear_archive_sessions()


def test_replaced_session_retires_when_borrow_registration_fails(tmp_path, monkeypatch):
    path = tmp_path / "archive.bin"
    path.write_bytes(b"old data")
    prior = archive_sessions.get_archive_session(str(path))
    path.rename(tmp_path / "retired.bin")
    path.write_bytes(b"new data")
    def fail_registration(*args, **kwargs):
        raise ResourceLifecycleError("cannot register")

    monkeypatch.setattr(archive_sessions, "register_resource", fail_registration)
    try:
        with pytest.raises(ResourceLifecycleError, match="cannot register"):
            with archive_sessions.borrow_archive_sessions((path,)):
                pass
        assert prior.closed
    finally:
        archive_sessions.clear_archive_sessions()


def test_analysis_view_does_not_pin_evicted_session_to_request(tmp_path, monkeypatch):
    path = tmp_path / "archive.bin"
    other = tmp_path / "other.bin"
    path.write_bytes(b"archive")
    other.write_bytes(b"other")

    monkeypatch.setattr(archive_sessions, "_MAX_SESSIONS", 1)
    scope = TaskResourceScope("archive-view-owner")
    try:
        with scope.activate(), SharedBinaryView(str(path)) as view:
            session = archive_sessions.get_archive_session(str(path))
            archive_sessions.get_archive_session(str(other))
            assert session.closed
            assert view.read_at(0, 7) == b"archive"
    finally:
        scope.close()
        archive_sessions.clear_archive_sessions()
