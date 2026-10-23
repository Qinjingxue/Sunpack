from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AdaptiveQuietPolicy:
    """Maps observed content-write intervals to a per-file quiet window."""

    initial_seconds: float = 1.0
    minimum_seconds: float = 1.25
    maximum_seconds: float = 180.0
    window_size: int = 12
    interval_percentile: float = 0.9
    minimum_shrink_samples: int = 3
    linear_factor: float = 1.0
    logarithmic_scale: float = 0.75
    logarithmic_pivot_seconds: float = 2.0
    shrink_time_constant_seconds: float = 2.0

    def __post_init__(self) -> None:
        minimum = max(0.0, float(self.minimum_seconds))
        maximum = max(minimum, float(self.maximum_seconds))
        initial = min(max(0.0, float(self.initial_seconds)), maximum)
        object.__setattr__(self, "minimum_seconds", minimum)
        object.__setattr__(self, "maximum_seconds", maximum)
        object.__setattr__(self, "initial_seconds", initial)
        object.__setattr__(self, "window_size", max(1, int(self.window_size)))
        object.__setattr__(self, "interval_percentile", min(1.0, max(0.0, float(self.interval_percentile))))
        object.__setattr__(self, "minimum_shrink_samples", max(1, int(self.minimum_shrink_samples)))
        object.__setattr__(self, "linear_factor", max(0.0, float(self.linear_factor)))
        object.__setattr__(self, "logarithmic_scale", max(0.0, float(self.logarithmic_scale)))
        object.__setattr__(self, "logarithmic_pivot_seconds", max(1e-6, float(self.logarithmic_pivot_seconds)))
        object.__setattr__(self, "shrink_time_constant_seconds", max(1e-6, float(self.shrink_time_constant_seconds)))

    def effective_interval(self, intervals: list[float] | tuple[float, ...]) -> float | None:
        values = sorted(float(value) for value in intervals if value > 0.0 and math.isfinite(value))
        if not values:
            return None
        if len(values) == 1:
            return values[0]
        position = self.interval_percentile * (len(values) - 1)
        lower = math.floor(position)
        upper = math.ceil(position)
        if lower == upper:
            return values[lower]
        fraction = position - lower
        return values[lower] + (values[upper] - values[lower]) * fraction

    def target_seconds(self, intervals: list[float] | tuple[float, ...]) -> float:
        interval = self.effective_interval(intervals)
        if interval is None:
            return self.initial_seconds
        target = (
            self.minimum_seconds
            + self.linear_factor * interval
            + self.logarithmic_scale * math.log1p(interval / self.logarithmic_pivot_seconds)
        )
        return min(self.maximum_seconds, max(self.minimum_seconds, target))

    def adjusted_seconds(
        self,
        current: float,
        intervals: list[float] | tuple[float, ...],
        *,
        calibrated: bool,
    ) -> float:
        target = self.target_seconds(intervals)
        current = min(self.maximum_seconds, max(self.minimum_seconds, float(current)))
        # P90 ignores harmless isolated pauses, but once the newest interval
        # already exceeds the active window it represents a real premature
        # boundary. Learn it immediately so the same slowdown is not retried.
        if intervals and intervals[-1] > current:
            target = max(target, self.target_seconds([intervals[-1]]))
        if target >= current:
            return target
        if len(intervals) < self.minimum_shrink_samples:
            return current
        if not calibrated:
            # The initial window is a guess, not evidence of a slow writer.
            # Calibrate once instead of requiring dozens of write callbacks.
            return target
        # Only newly observed write intervals can shorten a learned window.
        # Busy/metadata checks never call this path. Cap credit so a pause
        # cannot count as sustained faster writing, and preserve long gaps
        # across short bursts regardless of how many callbacks they produce.
        elapsed = min(intervals[-1], target)
        time_constant = max(current, self.shrink_time_constant_seconds)
        alpha = -math.expm1(-elapsed / time_constant)
        return current + alpha * (target - current)


@dataclass(slots=True)
class AdaptiveQuietTracker:
    policy: AdaptiveQuietPolicy
    quiet_seconds: float = field(init=False)
    last_content_event_at: float | None = None
    last_size: int | None = None
    last_mtime: float | None = None
    last_change_usn: int | None = None
    calibrated: bool = False
    _intervals: deque[float] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.quiet_seconds = self.policy.initial_seconds
        self._intervals = deque(maxlen=self.policy.window_size)

    @property
    def intervals(self) -> tuple[float, ...]:
        return tuple(self._intervals)

    def observe(
        self,
        now: float,
        *,
        size: int,
        mtime: float,
        change_usn: int = 0,
        content_changed: bool | None = None,
        learn_interval: bool = True,
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
        if not is_content_change:
            self.last_size = size
            self.last_mtime = mtime
            self.last_change_usn = change_usn
            return self.quiet_seconds
        if self.last_content_event_at is not None and learn_interval:
            interval = float(now) - self.last_content_event_at
            if interval > 0.0 and math.isfinite(interval):
                self._intervals.append(interval)
                previous_quiet = self.quiet_seconds
                self.quiet_seconds = self.policy.adjusted_seconds(
                    previous_quiet, self.intervals, calibrated=self.calibrated,
                )
                if self.quiet_seconds > previous_quiet or len(self._intervals) >= self.policy.minimum_shrink_samples:
                    self.calibrated = True
        self.last_content_event_at = float(now)
        self.last_size = size
        self.last_mtime = mtime
        self.last_change_usn = change_usn
        return self.quiet_seconds
