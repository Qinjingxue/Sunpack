"""Drive benchmark ticks from the same wake sources as the Watch service."""

import asyncio
import threading


class WatchWakeup:
    def __init__(self):
        self.loop = asyncio.get_running_loop()
        self._event = asyncio.Event()
        self._lock = threading.Lock()
        self._pending = False

    def notify(self) -> None:
        # Observer events can come from another thread. A pending wake covers
        # all work published before the next tick.
        with self._lock:
            if not self._pending:
                self.loop.call_soon_threadsafe(self._event.set)
                self._pending = True

    async def wait(self, delay: float | None, deadline: float) -> None:
        when = deadline if delay is None else min(deadline, self.loop.time() + delay)
        timer = None if self._event.is_set() else self.loop.call_at(when, self._event.set)
        try:
            await self._event.wait()
        finally:
            if timer is not None:
                timer.cancel()
        with self._lock:
            self._event.clear()
            self._pending = False
