from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass, field

from .corpus import Trace


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


def proposal_boundaries(trace: Trace) -> tuple[dict, dict]:
    """Scoring truth only: complete arrival excludes handle-release time."""
    groups = {}
    for file in trace.files:
        groups.setdefault(file.group, []).append(file)
    group_arrivals = {
        key: None if any(file.complete_at is None for file in files)
        else max(max(file.complete_at, file.visible_at) for file in files)
        for key, files in groups.items()
    }
    group_ready = {
        key: None if group_arrivals[key] is None
        else readable_group_from(files, group_arrivals[key])
        for key, files in groups.items()
    }
    boundaries = {}
    for file in trace.files:
        if file.shape == "split_complete":
            boundaries[file.key] = (group_arrivals[file.group], group_ready[file.group])
        elif file.complete_at is None:
            boundaries[file.key] = (None, None)
        else:
            arrived = max(file.complete_at, file.visible_at)
            boundaries[file.key] = (arrived, file.readable_from(arrived))
    return group_ready, boundaries


def readable_group_from(files, at):
    for start, end in sorted(interval for file in files for interval in file.blocked):
        if start <= at < end:
            at = end
    return at


def add_valid_proposal_latency(files: list[dict], boundaries: dict) -> None:
    """Score actual proposal times against writer-only readiness boundaries.

    No proposal is synthesized at arrival/readability/group-completion time.
    A missing proposal stays censored, even if a readiness guard could retry.
    """
    for file in files:
        arrived, ready = boundaries[file["key"]]
        first = next((at for at in file["proposal_times"] if ready is not None and at >= ready), None)
        file.update(complete_arrival_at=arrived, processing_ready_at=ready, first_valid_proposal_at=first,
                    ready_to_valid_proposal_seconds=None if first is None else first - ready,
                    invalid_proposals=sum(ready is None or at < ready for at in file["proposal_times"]))


def record_proposal(result: FileResult, file, at: float, group_ready: dict, horizon: float) -> None:
    result.proposals += 1
    result.proposal_times.append(at)
    if group_ready[file.group] is None or at < group_ready[file.group]:
        result.early_group_proposals += 1
    if not file.readable(at):
        result.busy_proposals += 1
    if file.complete_at is None or at < file.complete_at:
        result.premature += 1
        mutations = [item.at for item in file.mutations]
        position = bisect.bisect_right(mutations, at)
        end = mutations[position] if position < len(mutations) else horizon
        if file.complete_at is not None:
            end = min(end, file.complete_at)
        result.premature_exposure_seconds += max(0.0, end - at)
    else:
        if result.first_detection_latency is None:
            result.first_detection_latency = at - file.complete_at
        usable_at = file.readable_from(max(file.complete_at, file.visible_at))
        if at >= usable_at and result.first_usable_latency is None:
            result.first_usable_latency = at - usable_at


def input_results(trace, files):
    """One complete input per archive family, not a second proposal per volume."""
    groups = defaultdict(list)
    truth = {file.key: file for file in trace.files}
    for file in files:
        source = truth[file["key"]]
        key = source.group if source.shape == "split_complete" else source.key
        groups[key].append(file)
    inputs = []
    for key, members in groups.items():
        sources = [truth[file["key"]] for file in members]
        complete = all(file.complete_at is not None for file in sources)
        arrived = max(max(file.complete_at, file.visible_at) for file in sources) if complete else None
        ready = readable_group_from(sources, arrived) if complete else None
        proposals = sorted(at for file in members for at in file["proposal_times"])
        first = next((at for at in proposals if ready is not None and at >= ready), None)
        first_detection = next((at for at in proposals if arrived is not None and at >= arrived), None)
        invalid = sum(ready is None or at < ready for at in proposals)
        inputs.append(dict(
            key=key, shape=sources[0].shape, members=[file["key"] for file in members], completed=complete,
            proposals=len(proposals), proposal_times=proposals,
            premature=sum(arrived is None or at < arrived for at in proposals),
            invalid_proposals=invalid,
            busy_proposals=sum(file["busy_proposals"] for file in members),
            early_group_proposals=sum(file["early_group_proposals"] for file in members),
            premature_exposure_seconds=sum(file["premature_exposure_seconds"] for file in members),
            first_detection_latency=None if first_detection is None else first_detection - arrived,
            first_usable_latency=None if first is None else first - ready,
            complete_arrival_at=arrived, processing_ready_at=ready, first_valid_proposal_at=first,
            ready_to_valid_proposal_seconds=None if first is None else first - ready,
        ))
    return inputs
