import os

import pytest

from sunpack.core.support import archive_sessions
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


def test_replaced_session_retires_when_borrow_registration_fails(tmp_path):
    path = tmp_path / "archive.bin"
    path.write_bytes(b"old data")
    prior = archive_sessions.get_archive_session(str(path))
    path.rename(tmp_path / "retired.bin")
    path.write_bytes(b"new data")
    scope = TaskResourceScope("archive-session-closed-owner")
    scope.close()
    try:
        with scope.activate(), pytest.raises(ResourceLifecycleError, match="cannot register"):
            archive_sessions.get_archive_session(str(path))
        assert prior.closed
    finally:
        archive_sessions.clear_archive_sessions()
