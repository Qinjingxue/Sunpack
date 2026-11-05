from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AdaptiveQuietPolicy:
    """Time-decayed empirical quantile, with a data-derived half-life."""

    window_size: int = 12
    interval_percentile: float = 0.9
    half_life_factor: float = 2.0
    pause_ratio: float = 8.0
    phase_confirmation_ratio: float = 2.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "window_size", max(1, int(self.window_size)))
        object.__setattr__(self, "interval_percentile", min(1.0, max(0.0, float(self.interval_percentile))))
        factor = float(self.half_life_factor)
        if not math.isfinite(factor) or factor <= 0.0:
            raise ValueError("half_life_factor must be finite and positive")
        object.__setattr__(self, "half_life_factor", factor)
        for name in ("pause_ratio", "phase_confirmation_ratio"):
            ratio = float(getattr(self, name))
            if not math.isfinite(ratio) or ratio <= 1.0:
                raise ValueError(f"{name} must be finite and greater than one")
            object.__setattr__(self, name, ratio)

    def effective_interval(self, samples: deque[tuple[float, float]]) -> float:
        # Each sample is (content interval, monotonic observation timestamp).
        # The tracker bounds this deque; do not copy its history on the hot path.
        if not samples:
            return 0.0
        if len(samples) == 1:
            return samples[0][0]
        recent = sorted(samples[-index][0] for index in range(1, min(3, len(samples)) + 1))
        middle = len(recent) // 2
        scale = recent[middle] if len(recent) % 2 else recent[0] + (recent[1] - recent[0]) / 2.0
        now = samples[-1][1]
        # Divide before multiplying by the dimensionless factor: no fixed
        # epsilon/floor, even at very small or very large time scales.
        weighted = sorted((value, 0.5 ** (((now - at) / scale) / self.half_life_factor))
                          for value, at in samples)
        threshold = self.interval_percentile * sum(weight for _, weight in weighted)
        cumulative = 0.0
        for value, weight in weighted:
            cumulative += weight
            if weight > 0.0 and cumulative >= threshold:
                return value
        return weighted[-1][0]

    def target_seconds(self, interval: float) -> float:
        # Frozen closed-loop search winner; see benchmarks/quiet_window/FUNCTION_SEARCH_RESULTS.md.
        scaled = interval / 0.84
        return 1.52 * math.log1p(0.5 * scaled + 0.5 * math.log1p(scaled))


@dataclass(slots=True)
class AdaptiveQuietTracker:
    policy: AdaptiveQuietPolicy
    quiet_seconds: float = field(default=0.0, init=False)
    # Bounded phase summary survives tracker retirement in the native catalog;
    # the twelve-sample distribution remains local to an active tracker.
    cadence_seconds: float = field(default=0.0, init=False)
    pending_interval_seconds: float = field(default=0.0, init=False)
    last_content_event_at: float | None = None
    last_size: int | None = None
    last_mtime: float | None = None
    last_change_usn: int | None = None
    _samples: deque[tuple[float, float]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._samples = deque(maxlen=self.policy.window_size)

    @property
    def intervals(self) -> tuple[float, ...]:
        return tuple(interval for interval, _ in self._samples)

    def observe(
        self,
        now: float,
        *,
        size: int,
        mtime: float,
        change_usn: int = 0,
        content_changed: bool | None = None,
        learn_interval: bool = True,
        phase_boundary: bool = False,
    ) -> float:
        size = int(size)
        mtime = float(mtime)
        change_usn = int(change_usn)
        detected_change = (
            self.last_size is None
            or self.last_size != size
            or self.last_mtime != mtime
            or (change_usn > 0 and self.last_change_usn != change_usn)
        )
        is_content_change = detected_change if content_changed is None else bool(content_changed)
        if phase_boundary:
            # A fresh journal CLOSE says this interval crosses a handle epoch,
            # not that the file is complete or that another writer cannot open.
            self.last_content_event_at = None
            self.pending_interval_seconds = 0.0
        if not is_content_change:
            self.last_size = size
            self.last_mtime = mtime
            self.last_change_usn = change_usn
            return self.quiet_seconds
        if self.last_size is not None and size < self.last_size:
            # A truncate/restart is not an interval in the old writing phase.
            self._samples.clear()
            self.quiet_seconds = self.cadence_seconds = self.pending_interval_seconds = 0.0
            self.last_content_event_at = None
        if self.last_content_event_at is not None and learn_interval:
            interval = float(now) - self.last_content_event_at
            if interval > 0.0 and math.isfinite(interval):
                self._observe_interval(interval, float(now))
        elif not learn_interval:
            # A boundary probe does not time a writer interval; it also breaks
            # the consecutive evidence required to confirm a tentative phase.
            self.pending_interval_seconds = 0.0
        self.last_content_event_at = None if phase_boundary else float(now)
        self.last_size = size
        self.last_mtime = mtime
        self.last_change_usn = change_usn
        return self.quiet_seconds

    def _observe_interval(self, interval: float, now: float) -> None:
        # A single gap cannot distinguish an idle writer from a slow writer.
        # Quarantine unknown/out-of-phase gaps without extending the deadline.
        # Repeated compatible intervals establish a real slower writing phase.
        cadence = self.cadence_seconds
        if cadence == 0.0 or interval > self.policy.pause_ratio * cadence:
            pending = self.pending_interval_seconds
            if not pending or max(interval, pending) > self.policy.phase_confirmation_ratio * min(interval, pending):
                self.pending_interval_seconds = interval
                return
            self._samples.clear()
            self._samples.append((pending, self.last_content_event_at))
        self.pending_interval_seconds = 0.0
        self._samples.append((interval, now))
        self.cadence_seconds = self.policy.effective_interval(self._samples)
        self.quiet_seconds = self.policy.target_seconds(self.cadence_seconds)
