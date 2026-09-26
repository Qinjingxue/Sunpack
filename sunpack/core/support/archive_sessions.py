from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Iterable

import sunpack_native
from sunpack_native import NativeArchiveSession, clear_reader_resources

from sunpack.core.support.resource_lifecycle import (
    ResourceBusyError,
    ResourceKind,
    ResourceLease,
    current_task_resource_scope,
    lifecycle_registration,
    register_process_cache_resource,
)


_MAX_SESSIONS = 128
_BORROW_RELEASE_TIMEOUT_SECONDS = 30.0
_LOCK = threading.RLock()
_CHANGED = threading.Condition(_LOCK)


@dataclass
class _SessionEntry:
    key: tuple[str, int, int]
    session: NativeArchiveSession
    borrowers: set[str] = field(default_factory=set)
    process_lease: ResourceLease | None = None
    retired: bool = False
    closed: bool = False


_SESSIONS: OrderedDict[tuple[str, int, int], _SessionEntry] = OrderedDict()


def _identity(path: str) -> tuple[str, int, int]:
    normalized = os.path.abspath(os.path.normpath(path))
    stat = os.stat(normalized)
    return normalized, int(stat.st_size), int(stat.st_mtime_ns)


def _native_close(owner: Any) -> None:
    close = getattr(owner, "close", None)
    if close is not None:
        close()


def _release_borrow(entry: _SessionEntry, task_id: str) -> None:
    with _CHANGED:
        entry.borrowers.discard(task_id)
        close_retired = entry.retired and not entry.borrowers and not entry.closed
        _CHANGED.notify_all()
    if close_retired and entry.process_lease is not None:
        entry.process_lease.close()


def _attach_task_borrow_locked(entry: _SessionEntry) -> None:
    scope = current_task_resource_scope()
    if scope is None or scope.task_id in entry.borrowers:
        return
    task_id = scope.task_id
    scope.register(
        entry.session,
        (entry.key[0],),
        lambda entry=entry, task_id=task_id: _release_borrow(entry, task_id),
        kind=ResourceKind.ARCHIVE_SESSION_BORROW,
        registration_held=True,
    )
    entry.borrowers.add(task_id)


def _close_entry(entry: _SessionEntry) -> None:
    deadline = time.monotonic() + _BORROW_RELEASE_TIMEOUT_SECONDS
    with _CHANGED:
        entry.retired = True
        while entry.borrowers:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ResourceBusyError(
                    f"archive session {entry.key[0]} is still borrowed by tasks "
                    f"{sorted(entry.borrowers)}"
                )
            _CHANGED.wait(remaining)
        if entry.closed:
            return
    _native_close(entry.session)
    with _CHANGED:
        entry.closed = True
        _CHANGED.notify_all()


def _close_entries(entries: list[_SessionEntry]) -> int:
    closed = 0
    for entry in entries:
        lease = entry.process_lease
        if lease is not None:
            closed += int(lease.close())
        else:
            _close_entry(entry)
            closed += 1
    return closed


def _retire_entries(entries: list[_SessionEntry]) -> None:
    ready: list[_SessionEntry] = []
    with _CHANGED:
        for entry in entries:
            entry.retired = True
            if not entry.borrowers and not entry.closed:
                ready.append(entry)
        _CHANGED.notify_all()
    _close_entries(ready)


def get_archive_session(path: str) -> NativeArchiveSession:
    key = _identity(path)
    stale_entries: list[_SessionEntry] = []
    duplicate: NativeArchiveSession | None = None
    with lifecycle_registration((key[0],)):
        with _CHANGED:
            entry = _SESSIONS.get(key)
            if entry is not None and not entry.retired:
                _SESSIONS.move_to_end(key)
                _attach_task_borrow_locked(entry)
                return entry.session

        session = NativeArchiveSession(key[0])
        with _CHANGED:
            existing = _SESSIONS.get(key)
            if existing is not None and not existing.retired:
                duplicate = session
                _SESSIONS.move_to_end(key)
                _attach_task_borrow_locked(existing)
                result = existing.session
            else:
                stale_keys = [item for item in _SESSIONS if item[0] == key[0] and item != key]
                stale_entries.extend(_SESSIONS.pop(item) for item in stale_keys)
                entry = _SessionEntry(key=key, session=session)
                entry.process_lease = register_process_cache_resource(
                    session,
                    (key[0],),
                    lambda entry=entry: _close_entry(entry),
                    kind=ResourceKind.NATIVE_ARCHIVE_SESSION,
                    registration_held=True,
                )
                _SESSIONS[key] = entry
                _attach_task_borrow_locked(entry)
                while len(_SESSIONS) > _MAX_SESSIONS:
                    _old_key, old_entry = _SESSIONS.popitem(last=False)
                    stale_entries.append(old_entry)
                result = session

    if duplicate is not None:
        _native_close(duplicate)
    _retire_entries(stale_entries)
    return result


def retain_archive_sessions(paths) -> None:
    for path in dict.fromkeys(str(path) for path in paths if path):
        get_archive_session(path)


def clear_archive_sessions() -> dict:
    with _CHANGED:
        entries = list(_SESSIONS.values())
        _SESSIONS.clear()
    sessions = _close_entries(entries)
    return {
        "sessions": sessions,
        "reader": dict(clear_reader_resources()),
    }


def _is_under(candidate: str, root: str) -> bool:
    try:
        return os.path.commonpath((candidate, root)) == root
    except ValueError:
        return False


def _merge_release_roots(
    paths: Iterable[os.PathLike[str] | str],
) -> tuple[str, ...]:
    normalized = tuple(
        dict.fromkeys(
            os.path.abspath(os.path.normpath(os.fspath(path)))
            for path in paths
            if path
        )
    )
    return tuple(
        root
        for root in normalized
        if not any(
            other != root and _is_under(root, other)
            for other in normalized
        )
    )


def release_archive_sessions_under_roots(
    paths: Iterable[os.PathLike[str] | str],
) -> dict[str, Any]:
    roots = _merge_release_roots(paths)
    with _CHANGED:
        stale = [
            key
            for key in _SESSIONS
            if any(_is_under(key[0], root) for root in roots)
        ]
        entries = [_SESSIONS.pop(key) for key in stale]
    sessions = _close_entries(entries)
    reader = dict(sunpack_native.release_reader_resources_under_roots(list(roots)))
    return {"sessions": sessions, "reader": reader}
