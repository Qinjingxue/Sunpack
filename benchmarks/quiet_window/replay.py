from __future__ import annotations

import bisect
import heapq
import math
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Protocol

from sunpack.runtime.watch.quiet_policy import AdaptiveQuietPolicy, AdaptiveQuietTracker

from .corpus import Observation, Trace


class Estimator(Protocol):
    def observe(self, event: Observation) -> float: ...


class AdaptiveEstimator:
    def __init__(self):
        self.tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())

    def observe(self, event: Observation) -> float:
        return self.tracker.observe(event.at, size=event.size, mtime=event.mtime,
                                    change_usn=event.usn, content_changed=event.content_changed,
                                    learn_interval=event.learn_interval)


class FixedEstimator:
    def __init__(self, seconds: float):
        self.seconds = seconds

    def observe(self, event: Observation) -> float:
        return self.seconds


class EwmaEstimator:
    """RFC 6298-inspired SRTT+4*RTTVAR control, NOT a TCP implementation.

    Uses content intervals, zero initial wait, no TCP floor/backoff, no upper cap.
    """
    def __init__(self):
        self.last = None
        self.mean = None
        self.variation = 0.0

    def observe(self, event: Observation) -> float:
        if event.content_changed:
            if self.last is not None and event.learn_interval and event.at > self.last:
                interval = event.at - self.last
                if self.mean is None:
                    self.mean, self.variation = interval, interval / 2
                else:
                    self.variation = 0.75 * self.variation + 0.25 * abs(self.mean - interval)
                    self.mean = 0.875 * self.mean + 0.125 * interval
            self.last = event.at
        return 0.0 if self.mean is None else self.mean + 4 * self.variation


def estimators() -> dict[str, Callable[[], Estimator]]:
    return {"adaptive": AdaptiveEstimator, "ewma": EwmaEstimator,
            **{f"fixed-{seconds:g}s": lambda value=seconds: FixedEstimator(value)
               for seconds in (0.0, 0.05, 0.5, 2.0, 10.0, 180.0)}}


@dataclass(slots=True)
class FileResult:
    key: str
    shape: str
    completed: bool
    proposals: int = 0
    premature: int = 0
    busy_proposals: int = 0
    early_group_proposals: int = 0
    first_detection_latency: float | None = None
    first_usable_latency: float | None = None
    premature_exposure_seconds: float = 0.0
    proposal_times: list[float] = field(default_factory=list)


def replay(trace: Trace, factory: Callable[[], Estimator], *, tie_order: str = "observation_first") -> dict:
    """One proposal per observed content generation, rearmed by new content.

    The estimator sees only Observation; truth is read exclusively by scoring.
    This evaluates the quiet estimator, not WatchScheduler or archive analysis.
    """
    started = time.process_time_ns()
    truth = {file.key: file for file in trace.files}
    results = {file.key: FileResult(file.key, file.shape, file.complete_at is not None) for file in trace.files}
    models: dict[str, Estimator] = {}
    generations: dict[str, int] = {}
    pending: set[str] = set()
    heap = []
    serial = 0
    observation_priority = 0 if tie_order == "observation_first" else 1
    for event in trace.observations:
        heap.append((event.at, observation_priority, serial, event.key, event))
        serial += 1
    heapq.heapify(heap)
    peak_models = 0
    deadline_count = 0
    # Missing members are evaluated as a separate archive-group fact. They do
    # not turn a correctly stable individual volume into a false file decision.
    groups = {}
    for file in trace.files:
        groups.setdefault(file.group, []).append(file)
    group_ready = {key: None if any(file.complete_at is None or file.shape == "split_missing" for file in files)
                   else max(max(file.complete_at, file.visible_at, file.busy_until) for file in files)
                   for key, files in groups.items()}
    while heap:
        at, _, _, key, payload = heapq.heappop(heap)
        if at > trace.horizon:
            break
        if isinstance(payload, Observation):
            model = models.get(key)
            if model is None:
                model = models[key] = factory()
                peak_models = max(peak_models, len(models))
            seconds = model.observe(payload)
            if math.isnan(seconds) or seconds < 0:
                raise ValueError("estimator returned a negative or NaN deadline")
            if payload.content_changed:
                generation = generations[key] = generations.get(key, 0) + 1
                pending.add(key)
                heapq.heappush(heap, (at + seconds, 1 - observation_priority, serial, key, generation))
                serial += 1
                deadline_count += 1
            continue
        if generations.get(key) != payload or key not in pending:
            continue
        pending.remove(key)
        result, file = results[key], truth[key]
        result.proposals += 1
        result.proposal_times.append(at)
        if group_ready[file.group] is None or at < group_ready[file.group]:
            result.early_group_proposals += 1
        if at < file.busy_until:
            result.busy_proposals += 1
        if file.complete_at is None or at < file.complete_at:
            result.premature += 1
            # Each proposal is disarmed until new content, so these intervals
            # cannot overlap. A later physical write ends this false suspicion.
            mutations = [item.at for item in file.mutations]
            position = bisect.bisect_right(mutations, at)
            end = mutations[position] if position < len(mutations) else trace.horizon
            if file.complete_at is not None:
                end = min(end, file.complete_at)
            result.premature_exposure_seconds += max(0.0, end - at)
        else:
            if result.first_detection_latency is None:
                result.first_detection_latency = at - file.complete_at
            usable_at = max(file.complete_at, file.visible_at, file.busy_until)
            if at >= usable_at and result.first_usable_latency is None:
                result.first_usable_latency = at - usable_at
    return {"files": [asdict(result) for result in results.values()],
            "delivered_observations": len(trace.observations), "scheduled_deadlines": deadline_count,
            "peak_live_estimators": peak_models, "replay_cpu_ns": time.process_time_ns() - started}
