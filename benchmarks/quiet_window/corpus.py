from __future__ import annotations

import math
import random
from dataclasses import asdict, dataclass
from typing import Iterator


CONTRACT = "sunpack.quiet-window/1"
SPLITS = {"development": 0, "validation": 1_000_000, "heldout": 2_000_000}
CHANNELS = ("immediate", "batched", "noisy", "lossy_reconciled", "lost_terminal")
WIDTHS = (1, 8, 64)
SHAPES = ("disguised", "nested", "encrypted_candidates", "split_complete", "split_missing", "carrier")


@dataclass(frozen=True, slots=True)
class Mutation:
    at: float
    size: int
    mtime: float
    usn: int
    operation: str = "extend"
    offset: int = 0
    writer: int = 0


@dataclass(frozen=True, slots=True)
class FileTruth:
    key: str
    group: str
    shape: str
    mutations: tuple[Mutation, ...]
    complete_at: float | None
    visible_at: float
    busy_until: float


@dataclass(frozen=True, slots=True)
class Observation:
    at: float
    key: str
    kind: str
    size: int
    mtime: float
    usn: int
    content_changed: bool
    learn_interval: bool = True


@dataclass(frozen=True, slots=True)
class Trace:
    key: str
    split: str
    seed: int
    family: str
    channel: str
    width: int
    horizon: float
    files: tuple[FileTruth, ...]
    observations: tuple[Observation, ...]

    def record(self) -> dict:
        return {"contract": CONTRACT, **asdict(self)}

    @classmethod
    def from_record(cls, record: dict) -> "Trace":
        record = dict(record)
        if record.pop("contract") != CONTRACT:
            raise ValueError("unsupported quiet-window trace contract")
        record["files"] = tuple(FileTruth(**{**file, "mutations": tuple(
            Mutation(**item) for item in file["mutations"])}) for file in record["files"])
        record["observations"] = tuple(Observation(**item) for item in record["observations"])
        trace = cls(**record)
        trace.validate()
        return trace

    def validate(self) -> None:
        if self.split not in SPLITS or self.width != len(self.files) or not self.files:
            raise ValueError(f"invalid cohort/width: {self.key}")
        keys = {file.key for file in self.files}
        if len(keys) != len(self.files) or not math.isfinite(self.horizon) or self.horizon <= 0:
            raise ValueError(f"invalid identity/horizon: {self.key}")
        for file in self.files:
            times = [item.at for item in file.mutations]
            if not times or times != sorted(times) or any(not math.isfinite(t) or t < 0 for t in times):
                raise ValueError(f"invalid physical timeline: {self.key}/{file.key}")
            if file.complete_at is not None and not (times[-1] <= file.complete_at <= self.horizon):
                raise ValueError(f"completion precedes final mutation: {self.key}/{file.key}")
            if not (0 <= file.visible_at <= self.horizon and 0 <= file.busy_until <= self.horizon):
                raise ValueError(f"invalid visibility/busy interval: {self.key}/{file.key}")
        previous = -1.0
        for event in self.observations:
            if event.key not in keys or not math.isfinite(event.at) or not previous <= event.at <= self.horizon:
                raise ValueError(f"invalid delivered timeline: {self.key}")
            if event.kind not in {"content", "metadata", "duplicate", "arrival", "reconcile"}:
                raise ValueError(f"unknown observation kind: {event.kind}")
            if event.size < 0 or not math.isfinite(event.mtime):
                raise ValueError(f"invalid observation metadata: {self.key}")
            previous = event.at


FAMILIES = (
    "atomic_arrival", "initial_existing", "browser_rename", "cross_volume_copy",
    "constant_fast", "constant_medium", "constant_slow", "jitter_uniform",
    "exponential", "lognormal", "pareto_tail", "correlated_stalls",
    "bursty", "periodic_flush", "accelerating", "decelerating", "alternating_rates",
    "one_long_pause", "resume_after_hour", "close_reopen", "shared_handle",
    "exclusive_finalization", "preallocated", "random_ranges", "same_size_mtime",
    "truncate_rewrite", "metadata_tail", "zero_length_then_write", "cancelled_partial",
    "open_ended_writer", "replace_generation", "timestamp_backstep",
)


def _intervals(family: str, rng: random.Random) -> list[float]:
    if family in {"atomic_arrival", "initial_existing", "browser_rename"}:
        return []
    if family == "constant_fast":
        return [0.002] * 48
    if family == "constant_medium":
        return [0.5] * 32
    if family == "constant_slow":
        return [20.0] * 24
    if family == "jitter_uniform":
        return [rng.uniform(0.005, 2.0) for _ in range(48)]
    if family == "exponential":
        return [rng.expovariate(2.0) for _ in range(48)]
    if family == "lognormal":
        return [rng.lognormvariate(-1.0, 1.5) for _ in range(48)]
    if family == "pareto_tail":
        return [0.05 * rng.paretovariate(1.3) for _ in range(64)]
    if family == "correlated_stalls":
        slow = False
        result = []
        for _ in range(64):
            if rng.random() < 0.12:
                slow = not slow
            result.append(rng.uniform(4, 20) if slow else rng.uniform(0.01, 0.1))
        return result
    if family == "bursty":
        return ([0.01] * 8 + [3.0]) * 6
    if family == "periodic_flush":
        return ([0.002] * 15 + [0.8]) * 4
    if family == "accelerating":
        return [10 * 0.85 ** i for i in range(48)]
    if family == "decelerating":
        return [0.01 * 1.18 ** i for i in range(48)]
    if family == "alternating_rates":
        return ([0.02] * 10 + [4.0] * 10) * 3
    if family == "one_long_pause":
        return [0.1] * 16 + [rng.uniform(30, 300)] + [0.1] * 16
    if family == "resume_after_hour":
        return [0.1] * 8 + [rng.uniform(3600, 7200)] + [0.1] * 8
    if family == "zero_length_then_write":
        return [rng.uniform(2, 30)] + [0.05] * 24
    if family == "open_ended_writer":
        return [0.1] * 128
    return [rng.uniform(0.01, 0.2) for _ in range(32)]


def make_trace(family: str, split: str, seed: int, channel: str, width: int) -> Trace:
    family_index = FAMILIES.index(family)
    # Independent streams per file; channel/width never alter the shared prefix.
    files = []
    observations = []
    for index in range(width):
        rng = random.Random((SPLITS[split] + seed) * 1_000_003 + family_index * 1009 + index * 97)
        intervals = _intervals(family, rng)
        speed = rng.uniform(0.7, 1.3)
        at = index * 0.0001
        times = [at]
        for interval in intervals:
            at += interval * speed
            times.append(at)
        final = at
        busy_until = final + rng.uniform(0.5, 5) if family == "exclusive_finalization" else 0.0
        complete = final
        if family == "shared_handle":
            # The handle permits reads; close is not a completion oracle.
            busy_until = 0.0
        if family in {"cancelled_partial", "open_ended_writer"}:
            complete = None
        visible = final if family == "browser_rename" else times[0]
        key = f"file-{index}.opaque"
        shape = SHAPES[(seed + family_index + index // 4) % len(SHAPES)]
        fixed_size = family in {"preallocated", "random_ranges", "same_size_mtime"}
        mutations = []
        for part, moment in enumerate(times):
            size = 0 if family == "zero_length_then_write" and part == 0 else (len(times) if fixed_size else part + 1) * 65536
            if family == "truncate_rewrite" and part % 8 == 0:
                size = 0
            mtime = 100.0 if family == "same_size_mtime" else moment + 100.0
            if family == "timestamp_backstep":
                mtime = 10000.0 - part
            operation = "overwrite" if fixed_size else "extend"
            offset = rng.randrange(len(times)) * 65536 if family == "random_ranges" else part * 65536
            if family == "truncate_rewrite" and size == 0:
                operation = "truncate"
            if family == "replace_generation" and part == len(times) // 2:
                operation = "replace"
            mutations.append(Mutation(moment, size, mtime, part + 1, operation, offset,
                                      part % 4 if family == "random_ranges" else 0))
        files.append(FileTruth(key, f"archive-{index // 4}", shape, tuple(mutations), complete, visible, busy_until))
        deliveries: list[tuple[float, str]] = []
        for number, mutation in enumerate(mutations):
            if mutation.at < visible:
                continue
            if channel == "lost_terminal" and number == len(mutations) - 1 and number > 0:
                continue
            if channel == "lossy_reconciled" and number % 4 != 0 and number != len(mutations) - 1:
                continue
            moment = mutation.at
            if channel == "batched":
                moment = math.ceil(moment / 0.25) * 0.25 + 0.02
            elif channel == "lossy_reconciled":
                moment += rng.uniform(0.1, 1.0)
            deliveries.append((moment, "arrival" if number == 0 else "content"))
        if channel == "lossy_reconciled":
            deliveries.append((final + 1.0, "reconcile"))
        if family in {"close_reopen", "metadata_tail", "timestamp_backstep"} or channel == "noisy":
            for moment in times:
                deliveries.append((moment + 0.00001, "metadata"))
        if family == "metadata_tail":
            deliveries.extend((final + part * 0.1, "metadata") for part in range(1, 301))
        if channel == "noisy":
            # Many notifications for one content version, with an unchanged USN.
            deliveries.extend((moment + j * 0.000001, "duplicate") for moment in times for j in range(1, 9))
        # Snapshot at DELIVERY time, as stat/USN observation does; never replay
        # stale per-write snapshots from a delayed notification queue.
        last_seen = 0
        observed_usn = 0
        observed_mtime = 0.0
        for moment, kind in sorted(set(deliveries)):
            actual = next(item for item in reversed(mutations) if item.at <= moment)
            changed = actual.usn != last_seen
            if changed or kind == "metadata":
                observed_usn += 1
                observed_mtime = actual.mtime if changed else 10000.0 - moment
            observations.append(Observation(moment, key, kind, actual.size, observed_mtime,
                                            observed_usn, changed))
            last_seen = actual.usn
    horizon = max(max(file.mutations[-1].at, file.complete_at or 0, file.busy_until) for file in files) + 3600
    # An open writer continues beyond the recording window. Never assign the
    # last observed write a completion label merely because recording ended.
    trace = Trace(f"{split}/{seed}/{family}/{channel}/{width}", split, seed, family, channel,
                  width, horizon, tuple(files), tuple(sorted(observations, key=lambda e: (e.at, e.key, e.kind))))
    trace.validate()
    return trace


def generate(seeds: int, splits: tuple[str, ...], channels: tuple[str, ...], widths: tuple[int, ...]) -> Iterator[Trace]:
    for split in splits:
        for seed in range(seeds):
            for family in FAMILIES:
                for channel in channels:
                    for width in widths:
                        # Fractional design: concurrency is crossed with four
                        # representative cadences, not duplicated on every axis.
                        if width != 1 and family not in {"constant_fast", "bursty", "random_ranges", "metadata_tail"}:
                            continue
                        yield make_trace(family, split, seed, channel, width)
