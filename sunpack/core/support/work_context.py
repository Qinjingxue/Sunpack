from __future__ import annotations

import asyncio
import contextvars
import threading
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class WorkContext:
    request_id: str
    file_id: str
    stage: str
    attempt_id: int = 0
    origin: str = "foreground"


CURRENT_WORK: contextvars.ContextVar[WorkContext | None] = contextvars.ContextVar(
    "sunpack_current_work",
    default=None,
)

CURRENT_ORIGIN: contextvars.ContextVar[str] = contextvars.ContextVar(
    "sunpack_current_origin",
    default="foreground",
)


CURRENT_CANCELLATION: contextvars.ContextVar[CancellationToken | None] = contextvars.ContextVar(
    "sunpack_cancellation", default=None,
)


class CancellationToken:
    """Cooperative cancellation shared by one request and its worker jobs."""

    def __init__(self) -> None:
        self._cancelled = threading.Event()
        self._lock = threading.Lock()
        self._callbacks: set[Callable[[], None]] = set()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        with self._lock:
            if self.cancelled:
                return
            self._cancelled.set()
            callbacks = tuple(self._callbacks)
            self._callbacks.clear()
        for callback in callbacks:
            callback()

    def subscribe(self, callback: Callable[[], None]) -> Callable[[], None]:
        with self._lock:
            cancelled = self.cancelled
            if not cancelled:
                self._callbacks.add(callback)
        if cancelled:
            callback()
        def unsubscribe():
            with self._lock:
                self._callbacks.discard(callback)
        return unsubscribe

    async def wait(self, operation):
        """Cancel this await; native operations retain their own drain handler.

        Shared operations must be shielded by their caller.
        """
        loop = asyncio.get_running_loop()
        task = asyncio.ensure_future(operation)
        remove = self.subscribe(lambda: loop.call_soon_threadsafe(task.cancel))
        try:
            result = await task
            self.raise_if_cancelled()
            return result
        finally:
            remove()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise asyncio.CancelledError
