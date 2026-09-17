from __future__ import annotations

from dataclasses import dataclass, field
import os
import queue
import threading
import time
from typing import Any, Final

from sunpack.support.resource_lifecycle import open_service_file


# Small enough to be invisible to a single request, large enough to merge a burst
# of concurrent ArchiveTask commit barriers into one physical FlushFileBuffers.
GROUP_COMMIT_WINDOW_SECONDS: Final[float] = 0.0002


@dataclass
class JournalTicket:
    _done: threading.Event = field(default_factory=threading.Event)
    _error: BaseException | None = None

    def wait(self) -> None:
        self._done.wait()
        if self._error is not None:
            raise self._error


@dataclass
class _Request:
    path: str
    payload: bytes
    durable: bool
    close: bool
    ticket: JournalTicket


class _GroupCommitter:
    """Process-global append-only journal writer with per-path group commit.

    Callers enqueue while holding only their in-memory bookkeeping locks, then
    wait after releasing those locks.  All durable records for one journal that
    arrive in the same micro-batch share one fsync/FlushFileBuffers boundary.
    """

    def __init__(self) -> None:
        self._queue: queue.Queue[_Request] = queue.Queue()
        self._thread = threading.Thread(
            target=self._run,
            name='sunpack-watch-journal',
            daemon=True,
        )
        self._thread.start()

    def submit(self, path: str, payload: bytes, *, durable: bool, close: bool = False) -> JournalTicket:
        ticket = JournalTicket()
        self._queue.put(
            _Request(
                path=os.path.abspath(path),
                payload=bytes(payload),
                durable=bool(durable),
                close=bool(close),
                ticket=ticket,
            )
        )
        return ticket

    @staticmethod
    def _write_all(handle: Any, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = handle.write(view)
            if written is None or written <= 0:
                raise OSError('short watch journal write')
            view = view[written:]

    def _run(self) -> None:
        handles: dict[str, Any] = {}
        while True:
            first = self._queue.get()
            batch = [first]
            deadline = time.perf_counter() + GROUP_COMMIT_WINDOW_SECONDS
            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    break
                try:
                    batch.append(self._queue.get(timeout=remaining))
                except queue.Empty:
                    break

            errors: dict[str, BaseException] = {}
            durable_paths: set[str] = set()
            close_paths: set[str] = set()
            for request in batch:
                path = request.path
                if path in errors:
                    continue
                try:
                    if request.payload:
                        handle = handles.get(path)
                        if handle is None:
                            os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
                            handle = open_service_file(path, 'ab', buffering=0)
                            handles[path] = handle
                        self._write_all(handle, request.payload)
                    if request.durable:
                        durable_paths.add(path)
                    if request.close:
                        close_paths.add(path)
                        durable_paths.add(path)
                except BaseException as exc:  # propagated to every request for this path
                    errors[path] = exc

            for path in durable_paths:
                if path in errors:
                    continue
                try:
                    handle = handles.get(path)
                    if handle is not None:
                        os.fsync(handle.fileno())
                except BaseException as exc:
                    errors[path] = exc

            for path in close_paths:
                handle = handles.pop(path, None)
                if handle is not None:
                    try:
                        handle.close()
                    except BaseException as exc:
                        errors.setdefault(path, exc)

            for request in batch:
                request.ticket._error = errors.get(request.path)
                request.ticket._done.set()


_COMMITTER = _GroupCommitter()


def submit_journal_append(path: str, payload: bytes, *, durable: bool) -> JournalTicket:
    return _COMMITTER.submit(path, payload, durable=durable)


def submit_journal_close(path: str) -> JournalTicket:
    return _COMMITTER.submit(path, b'', durable=True, close=True)
