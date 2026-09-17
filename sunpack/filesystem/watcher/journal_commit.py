from __future__ import annotations

import atexit
from dataclasses import dataclass, field
import json
import os
import queue
import threading
import time
from typing import Any, Callable, Final

from sunpack.support.resource_lifecycle import open_service_file


# Keep the existing tiny batching window: it is enough to merge concurrent
# durability barriers without adding a Windows timer tick to every transaction.
GROUP_COMMIT_WINDOW_SECONDS: Final[float] = 0.0002


@dataclass
class JournalTicket:
    _done: threading.Event = field(default_factory=threading.Event)
    _error: BaseException | None = None
    bytes_written: int = 0

    def wait(self) -> None:
        self._done.wait()
        if self._error is not None:
            raise self._error


@dataclass
class _AppendRequest:
    stream: str
    path: str
    segment_start: int
    seq: int
    version: int
    operations: list[dict[str, Any]]
    durable: bool
    ticket: JournalTicket
    on_written: Callable[[int, int], None] | None
    on_error: Callable[[BaseException], None] | None


@dataclass
class _SealRequest:
    stream: str
    old_path: str
    new_path: str
    ticket: JournalTicket
    on_error: Callable[[BaseException], None] | None


@dataclass
class _FlushRequest:
    stream: str
    path: str
    ticket: JournalTicket
    on_error: Callable[[BaseException], None] | None


@dataclass
class _FlushAllRequest:
    ticket: JournalTicket


_Request = _AppendRequest | _SealRequest | _FlushRequest | _FlushAllRequest


class _JournalWriter:
    """Single FIFO owner for all Watch journal handles.

    State sequencing is decided before requests reach this thread.  Keeping all
    physical appends, fsyncs and segment closes here means checkpoint code never
    needs a journal I/O lock and can only operate on sealed files.
    """

    def __init__(self) -> None:
        self._queue: queue.Queue[_Request] = queue.Queue()
        self._thread = threading.Thread(
            target=self._run,
            name="sunpack-watch-journal",
            daemon=True,
        )
        self._thread.start()

    def submit_append(
        self,
        *,
        stream: str,
        path: str,
        segment_start: int,
        seq: int,
        version: int,
        operations: list[dict[str, Any]],
        durable: bool,
        on_written: Callable[[int, int], None] | None,
        on_error: Callable[[BaseException], None] | None,
    ) -> JournalTicket:
        ticket = JournalTicket()
        self._queue.put(
            _AppendRequest(
                stream=str(stream),
                path=os.path.abspath(path),
                segment_start=int(segment_start),
                seq=int(seq),
                version=int(version),
                operations=operations,
                durable=bool(durable),
                ticket=ticket,
                on_written=on_written,
                on_error=on_error,
            )
        )
        return ticket

    def submit_seal(
        self,
        *,
        stream: str,
        old_path: str,
        new_path: str,
        on_error: Callable[[BaseException], None] | None,
    ) -> JournalTicket:
        ticket = JournalTicket()
        self._queue.put(
            _SealRequest(
                stream=str(stream),
                old_path=os.path.abspath(old_path),
                new_path=os.path.abspath(new_path),
                ticket=ticket,
                on_error=on_error,
            )
        )
        return ticket

    def submit_flush(
        self,
        *,
        stream: str,
        path: str,
        on_error: Callable[[BaseException], None] | None,
    ) -> JournalTicket:
        ticket = JournalTicket()
        self._queue.put(
            _FlushRequest(
                stream=str(stream),
                path=os.path.abspath(path),
                ticket=ticket,
                on_error=on_error,
            )
        )
        return ticket

    def flush_all(self) -> None:
        ticket = JournalTicket()
        self._queue.put(_FlushAllRequest(ticket=ticket))
        ticket.wait()

    @staticmethod
    def _write_all(handle: Any, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = handle.write(view)
            if written is None or written <= 0:
                raise OSError("short watch journal write")
            view = view[written:]

    @staticmethod
    def _notify_error(request: _Request, error: BaseException) -> None:
        callback = getattr(request, "on_error", None)
        if callback is not None:
            try:
                callback(error)
            except BaseException:
                pass

    def _run(self) -> None:
        handles: dict[str, Any] = {}
        stream_errors: dict[str, BaseException] = {}

        while True:
            first = self._queue.get()
            batch = [first]
            deadline = time.perf_counter() + GROUP_COMMIT_WINDOW_SECONDS
            while True:
                try:
                    batch.append(self._queue.get_nowait())
                    continue
                except queue.Empty:
                    pass
                if time.perf_counter() >= deadline:
                    break
                time.sleep(0)

            durable_paths: set[str] = set()
            append_payloads: dict[int, bytes] = {}
            request_errors: dict[int, BaseException] = {}

            for request in batch:
                if isinstance(request, _FlushAllRequest):
                    for path, handle in list(handles.items()):
                        try:
                            os.fsync(handle.fileno())
                        except BaseException as exc:
                            request_errors[id(request)] = exc
                            break
                    continue

                prior_error = stream_errors.get(request.stream)
                if prior_error is not None:
                    request_errors[id(request)] = prior_error
                    continue

                try:
                    if isinstance(request, _AppendRequest):
                        payload = (
                            json.dumps(
                                {
                                    "version": request.version,
                                    "seq": request.seq,
                                    "operations": request.operations,
                                },
                                ensure_ascii=True,
                                separators=(",", ":"),
                            )
                            + "\n"
                        ).encode("utf-8")
                        handle = handles.get(request.path)
                        if handle is None:
                            os.makedirs(os.path.dirname(request.path) or ".", exist_ok=True)
                            handle = open_service_file(request.path, "ab", buffering=0)
                            handles[request.path] = handle
                        self._write_all(handle, payload)
                        append_payloads[id(request)] = payload
                        request.ticket.bytes_written = len(payload)
                        if request.durable:
                            durable_paths.add(request.path)
                        if request.on_written is not None:
                            request.on_written(request.segment_start, len(payload))
                        continue

                    if isinstance(request, _SealRequest):
                        handle = handles.pop(request.old_path, None)
                        if handle is not None:
                            # A sealed segment is a durable checkpoint fallback.
                            os.fsync(handle.fileno())
                            durable_paths.discard(request.old_path)
                            handle.close()
                        os.makedirs(os.path.dirname(request.new_path) or ".", exist_ok=True)
                        if request.new_path not in handles:
                            handles[request.new_path] = open_service_file(
                                request.new_path,
                                "ab",
                                buffering=0,
                            )
                        continue

                    if isinstance(request, _FlushRequest):
                        handle = handles.get(request.path)
                        if handle is not None:
                            os.fsync(handle.fileno())
                        continue
                except BaseException as exc:
                    if not isinstance(request, _FlushAllRequest):
                        stream_errors[request.stream] = exc
                    request_errors[id(request)] = exc
                    self._notify_error(request, exc)

            path_errors: dict[str, BaseException] = {}
            for path in durable_paths:
                handle = handles.get(path)
                if handle is None:
                    continue
                try:
                    os.fsync(handle.fileno())
                except BaseException as exc:
                    path_errors[path] = exc

            for request in batch:
                error = request_errors.get(id(request))
                if error is None and isinstance(request, _AppendRequest):
                    error = path_errors.get(request.path)
                    if error is not None:
                        stream_errors[request.stream] = error
                        self._notify_error(request, error)
                elif error is None and isinstance(request, _FlushRequest):
                    error = path_errors.get(request.path)
                request.ticket._error = error
                request.ticket._done.set()


_WRITER = _JournalWriter()


def submit_state_transaction(
    *,
    stream: str,
    path: str,
    segment_start: int,
    seq: int,
    version: int,
    operations: list[dict[str, Any]],
    durable: bool,
    on_written: Callable[[int, int], None] | None = None,
    on_error: Callable[[BaseException], None] | None = None,
) -> JournalTicket:
    return _WRITER.submit_append(
        stream=stream,
        path=path,
        segment_start=segment_start,
        seq=seq,
        version=version,
        operations=operations,
        durable=durable,
        on_written=on_written,
        on_error=on_error,
    )


def submit_segment_seal(
    *,
    stream: str,
    old_path: str,
    new_path: str,
    on_error: Callable[[BaseException], None] | None = None,
) -> JournalTicket:
    return _WRITER.submit_seal(
        stream=stream,
        old_path=old_path,
        new_path=new_path,
        on_error=on_error,
    )


def submit_stream_flush(
    *,
    stream: str,
    path: str,
    on_error: Callable[[BaseException], None] | None = None,
) -> JournalTicket:
    return _WRITER.submit_flush(
        stream=stream,
        path=path,
        on_error=on_error,
    )


def _flush_at_exit() -> None:
    try:
        _WRITER.flush_all()
    except BaseException:
        pass


atexit.register(_flush_at_exit)
