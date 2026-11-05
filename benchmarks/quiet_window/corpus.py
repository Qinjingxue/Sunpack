from __future__ import annotations

import bisect
import math
import random
from dataclasses import asdict, dataclass
from typing import Iterator


CONTRACT = "sunpack.writer-behaviour/1"
SPLITS = {"development": 0, "validation": 1_000_000, "heldout": 2_000_000}
CHANNELS = ("immediate", "batched", "noisy", "lossy_reconciled")
WIDTHS = (1, 4, 8, 64)
FAMILIES = (
    "segmented_preallocated", "segmented_sparse", "segmented_straggler",
    "segmented_work_stealing", "segmented_retry_overlap", "segmented_resume",
    "segmented_restart", "segmented_finalize_rename", "torrent_rarest_first",
    "torrent_recheck_repair", "cached_piece_writeback", "fragment_assembly",
    "sync_reused_blocks", "sync_inplace_delta", "copy_restartable",
    "copy_restart_from_zero", "close_reopen_batches", "shared_handle_tail",
    "exclusive_commit_tail", "archive_directory_last", "archive_header_backpatch",
    "multipart_serial", "multipart_parallel", "multipart_late_volume",
    "mapped_page_batches", "cloud_hydration", "cancelled_holes", "paused_holes",
)
MULTIPART = frozenset({"multipart_serial", "multipart_parallel", "multipart_late_volume"})
CONCURRENT = frozenset({"segmented_straggler", "cached_piece_writeback", "sync_reused_blocks",
                        "close_reopen_batches", "multipart_parallel"})


@dataclass(frozen=True, slots=True)
class WriterAction:
    at: float
    kind: str
    offset: int = 0
    length: int = 0
    writer: int = 0
    phase: str = ""


@dataclass(frozen=True, slots=True)
class Mutation:
    at: float
    size: int
    mtime: float
    usn: int
    operation: str
    offset: int
    length: int
    writer: int
    content_usn: int


@dataclass(frozen=True, slots=True)
class FileTruth:
    key: str
    group: str
    shape: str
    expected_size: int
    actions: tuple[WriterAction, ...]
    mutations: tuple[Mutation, ...]
    complete_at: float | None
    visible_at: float
    blocked: tuple[tuple[float, float], ...]

    def readable(self, at: float) -> bool:
        return not any(start <= at < end for start, end in self.blocked)

    def readable_from(self, at: float) -> float:
        for start, end in self.blocked:
            if start <= at < end:
                at = end
        return at


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
            raise ValueError("unsupported writer-behaviour trace contract")
        record["files"] = tuple(FileTruth(**{**file,
            "actions": tuple(WriterAction(**item) for item in file["actions"]),
            "mutations": tuple(Mutation(**item) for item in file["mutations"]),
            "blocked": tuple(tuple(item) for item in file["blocked"])}) for file in record["files"])
        record["observations"] = tuple(Observation(**item) for item in record["observations"])
        trace = cls(**record)
        trace.validate()
        return trace

    def validate(self) -> None:
        if (self.split not in SPLITS or self.family not in FAMILIES or self.channel not in CHANNELS
                or self.width != len(self.files) or not self.files):
            raise ValueError(f"invalid cohort/width: {self.key}")
        keys = {file.key for file in self.files}
        if len(keys) != len(self.files) or not math.isfinite(self.horizon) or self.horizon <= 0:
            raise ValueError(f"invalid identity/horizon: {self.key}")
        for file in self.files:
            times = [item.at for item in file.mutations]
            if (not times or times != sorted(times) or file.expected_size <= 0
                    or any(not math.isfinite(t) or not 0 <= t <= self.horizon for t in times)):
                raise ValueError(f"invalid physical timeline: {self.key}/{file.key}")
            if file.complete_at is not None and not times[0] <= file.complete_at <= self.horizon:
                raise ValueError(f"invalid completion: {self.key}/{file.key}")
            if not 0 <= file.visible_at <= self.horizon:
                raise ValueError(f"invalid visibility: {self.key}/{file.key}")
            previous = 0.0
            for start, end in file.blocked:
                if not previous <= start < end <= self.horizon:
                    raise ValueError(f"invalid handle timeline: {self.key}/{file.key}")
                previous = end
        previous = -1.0
        for event in self.observations:
            if event.key not in keys or not math.isfinite(event.at) or not previous <= event.at <= self.horizon:
                raise ValueError(f"invalid delivered timeline: {self.key}")
            if event.kind not in {"content", "metadata", "duplicate", "arrival", "reconcile"}:
                raise ValueError(f"unknown observation kind: {event.kind}")
            if event.size < 0 or not math.isfinite(event.mtime):
                raise ValueError(f"invalid observation metadata: {self.key}")
            previous = event.at


def _observe(file: FileTruth, channel: str, rng: random.Random) -> list[Observation]:
    deliveries = []
    visible_changes = [item for item in file.mutations if item.at >= file.visible_at]
    # A rename publishes the current file even when all writes happened under
    # an ignored staging name. Close/verify/sidecar traffic is not target data.
    deliveries.append((file.visible_at, "arrival"))
    deliveries.extend((item.at, "duplicate") for item in file.actions
                      if item.kind == "close" and item.at >= file.visible_at)
    for number, item in enumerate(visible_changes):
        if channel == "lossy_reconciled" and number % 4 and number != len(visible_changes) - 1:
            continue
        deliveries.append((item.at, "content" if item.content_usn == item.usn else "metadata"))
    if channel == "noisy":
        deliveries.extend((at + j * 0.000001, "duplicate") for at, _ in tuple(deliveries) for j in range(1, 9))
    scheduled = []
    for at, kind in deliveries:
        if channel == "batched":
            at = math.ceil(at / 0.25) * 0.25 + 0.02
        elif channel == "lossy_reconciled":
            at += rng.uniform(0.1, 1.0)
        scheduled.append((at, kind))
    if channel == "lossy_reconciled":
        scheduled.append((max(file.visible_at, file.mutations[-1].at) + 1, "reconcile"))
    times = [item.at for item in file.mutations]
    last_content = 0
    result = []
    for at, kind in sorted(set(scheduled)):
        item = file.mutations[bisect.bisect_right(times, at) - 1]
        result.append(Observation(at, file.key, kind, item.size, item.mtime, item.usn,
                                  item.content_usn != last_content))
        last_content = item.content_usn
    return result


def make_trace(family: str, split: str, seed: int, channel: str, width: int) -> Trace:
    from .writers import build_file

    if family not in FAMILIES or channel not in CHANNELS or split not in SPLITS or width not in WIDTHS:
        raise ValueError("unsupported writer cohort")
    if family in MULTIPART and width < 4:
        raise ValueError("multipart writers require at least four volumes")
    family_index = FAMILIES.index(family)
    files, observations = [], []
    for index in range(width):
        # Channels never affect writer randomness. Four volumes share transfer
        # scale, with a separate per-volume RNG.
        base = (SPLITS[split] + seed) * 1_000_003 + family_index * 1009
        group_rng = random.Random(base + (index // 4) * 97)
        rng = random.Random(base + index * 97)
        file = build_file(family, index, rng, group_rng)
        files.append(file)
        observations.extend(_observe(file, channel, random.Random(base + index * 97 + 79_919)))
    horizon = max(max(file.visible_at, file.actions[-1].at,
                      max((end for _, end in file.blocked), default=0)) for file in files) + 3600
    trace = Trace(f"{split}/{seed}/{family}/{channel}/{width}", split, seed, family, channel,
                  width, horizon, tuple(files), tuple(sorted(observations, key=lambda e: (e.at, e.key, e.kind))))
    trace.validate()
    return trace


def generate(seeds: int, splits: tuple[str, ...], channels: tuple[str, ...], widths: tuple[int, ...],
             families: tuple[str, ...] = FAMILIES) -> Iterator[Trace]:
    for split in splits:
        for seed in range(seeds):
            for family in families:
                for channel in channels:
                    for width in widths:
                        if family in MULTIPART:
                            if width != 4 and not (family in CONCURRENT and width in (8, 64)):
                                continue
                        elif width != 1 and not (family in CONCURRENT and width in (8, 64)):
                            continue
                        yield make_trace(family, split, seed, channel, width)
