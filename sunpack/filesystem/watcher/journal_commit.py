from __future__ import annotations

from dataclasses import dataclass, field
import os
import queue
import threading
import time
from typing import Final


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
    def _write_all(fd: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError('short watch journal write')
            view = view[written:]

    def _run(self) -> None:
        handles: dict[str, int] = {}
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
                        fd = handles.get(path)
                        if fd is None:
                            os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
                            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
                            if hasattr(os, 'O_BINARY'):
                                flags |= os.O_BINARY
                            fd = os.open(path, flags, 0o666)
                            handles[path] = fd
                        self._write_all(fd, request.payload)
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
                    fd = handles.get(path)
                    if fd is not None:
                        os.fsync(fd)
                except BaseException as exc:
                    errors[path] = exc

            for path in close_paths:
                fd = handles.pop(path, None)
                if fd is not None:
                    try:
                        os.close(fd)
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
