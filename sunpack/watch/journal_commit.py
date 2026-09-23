from __future__ import annotations

import atexit
from typing import Any, Callable

from sunpack_native import (
    watch_journal_flush_all as _native_flush_all,
    watch_journal_request_flush as _native_request_flush,
    watch_journal_seed as _native_seed,
    watch_journal_stats as _native_stats,
    watch_journal_submit_append as _native_submit_append,
    watch_journal_submit_seal as _native_submit_seal,
)


class JournalTicket:
    """Python facade over the native written/durable frontier ticket."""

    def __init__(
        self,
        native_ticket,
        *,
        segment_start: int = 0,
        on_written: Callable[[int, int], None] | None = None,
        on_error: Callable[[BaseException], None] | None = None,
    ) -> None:
        self._native_ticket = native_ticket
        self._segment_start = int(segment_start)
        self._on_written = on_written
        self._on_error = on_error
        self._written_notified = False
        self._error_notified = False
        self.bytes_written = 0

    def _notify_error(self, error: BaseException) -> None:
        if self._error_notified:
            return
        self._error_notified = True
        if self._on_error is not None:
            try:
                self._on_error(error)
            except BaseException:
                pass

    def wait(self) -> None:
        try:
            if self._on_written is not None and not self._written_notified:
                self._native_ticket.wait_written()
                self.bytes_written = int(self._native_ticket.bytes_written)
                self._on_written(self._segment_start, self.bytes_written)
                self._written_notified = True
            self._native_ticket.wait()
            if not self._written_notified:
                self.bytes_written = int(self._native_ticket.bytes_written)
                self._written_notified = True
        except BaseException as exc:
            self._notify_error(exc)
            raise


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
    native = _native_submit_append(
        str(stream),
        str(path),
        int(segment_start),
        int(seq),
        int(version),
        operations,
        bool(durable),
    )
    return JournalTicket(
        native,
        segment_start=segment_start,
        on_written=on_written,
        on_error=on_error,
    )


def submit_segment_seal(
    *,
    stream: str,
    old_path: str,
    new_path: str,
    old_start: int,
    boundary: int,
    on_error: Callable[[BaseException], None] | None = None,
) -> JournalTicket:
    # The new segment is created lazily by the writer on its first append.  The
    # sequence coordinator already switched all future transactions to it before
    # this fence is submitted, so there is no correctness reason to open an empty
    # file here.
    del new_path
    native = _native_submit_seal(
        str(stream),
        str(old_path),
        int(old_start),
        int(boundary),
    )
    return JournalTicket(native, on_error=on_error)


def submit_stream_flush(
    *,
    stream: str,
    target_seq: int,
    on_error: Callable[[BaseException], None] | None = None,
) -> JournalTicket:
    native = _native_request_flush(str(stream), int(target_seq))
    return JournalTicket(native, on_error=on_error)


def seed_state_stream(*, stream: str, seq: int) -> None:
    _native_seed(str(stream), int(seq))


def journal_stats(stream: str) -> dict[str, Any]:
    return dict(_native_stats(str(stream)))


def _flush_at_exit() -> None:
    try:
        _native_flush_all()
    except BaseException:
        pass


atexit.register(_flush_at_exit)
