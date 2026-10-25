from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sunpack_native import NativeEventLog


DEFAULT_EVENTS_MAX_BYTES = 512 * 1024


class WatchLogStore:
    def __init__(
        self,
        path: str,
        *,
        max_bytes: int = DEFAULT_EVENTS_MAX_BYTES,
        wake_callback: Callable[[], None] | None = None,
    ):
        self.path = Path(path)
        self.max_bytes = max(1, int(max_bytes))
        # The limit budgets recent results/diagnostics; live state has no cap.
        self._native = NativeEventLog(str(self.path), max(1, self.max_bytes // 2), self.path.name.lower() == "events.jsonl")
        self._throttle_lock = threading.Lock()
        self._last_throttled_write: dict[tuple[str, str], tuple[float, float]] = {}
        self._next_throttle_expiry: float | None = None
        self._wake_callback = wake_callback

    @property
    def next_history_expiry(self) -> float | None:
        with self._throttle_lock:
            return self._next_throttle_expiry

    def clear_expired_history(self) -> None:
        with self._throttle_lock:
            self._clear_expired_history_locked(time.monotonic())

    def _clear_expired_history_locked(self, now: float) -> None:
        if self._next_throttle_expiry is None or now < self._next_throttle_expiry:
            return
        expired = [token for token, (_, expiry) in self._last_throttled_write.items() if expiry <= now]
        for token in expired:
            del self._last_throttled_write[token]
        if not self._last_throttled_write:
            self._last_throttled_write.clear()
        self._next_throttle_expiry = min(
            (expiry for _, expiry in self._last_throttled_write.values()), default=None,
        )

    def recover(self, state=None) -> None:
        self._native.recover(state)

    def flush(self) -> None:
        """Explicit drain for shutdown/tests; ordinary write never waits for I/O."""
        self._native.flush()

    @property
    def error(self) -> str | None:
        return self._native.error

    def close(self) -> None:
        with self._throttle_lock:
            self._wake_callback = None
            self._last_throttled_write.clear()
            self._next_throttle_expiry = None
        self._native.close()

    def write(self, event: str, **payload: Any) -> None:
        record = {
            "ts": time.time(),
            "time": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **payload,
        }
        self._native.write(record)

    def write_throttled(
        self,
        event: str,
        *,
        throttle_key: str,
        interval_seconds: float,
        **payload: Any,
    ) -> None:
        token = (event, str(throttle_key))
        interval = max(0.0, float(interval_seconds))
        wake_callback = None
        with self._throttle_lock:
            now = time.monotonic()
            self._clear_expired_history_locked(now)
            previous = self._last_throttled_write.get(token)
            if previous is not None and now - previous[0] < interval:
                self._last_throttled_write[token] = (previous[0], max(previous[1], previous[0] + interval))
                return
            if interval > 0.0:
                expiry = now + interval
                self._last_throttled_write[token] = (now, expiry)
                if len(self._last_throttled_write) > 2048:
                    oldest = min(self._last_throttled_write, key=lambda key: self._last_throttled_write[key][0])
                    del self._last_throttled_write[oldest]
                if self._next_throttle_expiry is None or expiry < self._next_throttle_expiry:
                    self._next_throttle_expiry = expiry
                    wake_callback = self._wake_callback
            else:
                self._last_throttled_write.pop(token, None)
                if not self._last_throttled_write:
                    self._last_throttled_write.clear()
                    self._next_throttle_expiry = None
        if wake_callback is not None:
            wake_callback()
        self.write(event, **payload)
