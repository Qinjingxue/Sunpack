"""Virtual filesystem/clock driving the production Watch admission methods.

No second scheduler or archive analyser: native metadata/readiness IO and WAL
are replaced at their boundaries. Pipeline duration is zero, and admission is
scored against writer truth. This is not an extraction-throughput benchmark.
"""
from __future__ import annotations

import bisect
import heapq
import os
import threading
import time
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from sunpack_native import NativeDirectoryScanOptions, NativeWatchCatalog, NativeWatchState

from sunpack.core.config.fields.watch import DEFAULT_WATCH_CONFIG
from sunpack.core.contracts.discovery_scope import DiscoveryScope
from sunpack.runtime.watch import scheduler
from sunpack.runtime.watch.scanner import WatchCandidate
from sunpack.runtime.watch.state import WatchStateStore

from .corpus import Observation, Trace
from .replay import FileResult, add_valid_proposal_latency, proposal_boundaries, readable_group_from, record_proposal


class _MemoryState(WatchStateStore):
    """Keep the real Rust state operations; omit only persistence/OS presence."""
    def __init__(self):
        self._native = NativeWatchState()
        self._state_lock = threading.RLock()
        self._closed = False
        self._closing = False
        self._persistence_fault = None

    def _commit_operations_locked(self, operations, **_kwargs):
        self._apply_in_memory_locked(operations)


class _Filesystem:
    def __init__(self, trace: Trace, metadata_root: Path):
        self.now = 0.0
        self.paths = {file.key: str(metadata_root / file.key) for file in trace.files}
        self.keys = {path: key for key, path in self.paths.items()}
        self.truth = {file.key: file for file in trace.files}
        self.snapshots = {}
        self.times = {}
        self.metadata_probes = 0
        self.readiness_probes = 0
        for file in trace.files:
            snapshots = []
            identity = 0
            for item in file.mutations:
                identity += item.operation == "replace"
                snapshots.append((item.at, item.size, item.mtime, item.usn, item.content_usn, identity))
            self.snapshots[file.key] = snapshots
            self.times[file.key] = [item[0] for item in snapshots]

    def candidate(self, path, *, since_usn=0):
        self.metadata_probes += 1
        key = self.keys[path]
        if self.now < self.truth[key].visible_at:
            return None
        position = bisect.bisect_right(self.times[key], self.now) - 1
        if position < 0:
            return None
        _, size, mtime, usn, content_usn, identity = self.snapshots[key][position]
        reasons = scheduler.USN_REASON_DATA_OVERWRITE if content_usn > since_usn else 0
        return WatchCandidate(path, size, mtime, f"{key}/{identity}", usn,
                              change_reasons=reasons, change_reasons_without_close=reasons,
                              change_reasons_known=True)

    def ready(self, path):
        self.readiness_probes += 1
        return self.truth[self.keys[path]].readable(self.now)


class _ControlTracker:
    """Adapt independent controls to the production tracker's lifecycle."""
    def __init__(self, estimator):
        self.estimator = estimator
        self.quiet_seconds = 0.0
        self.last_content_event_at = None
        self.last_size = self.last_mtime = self.last_change_usn = None

    def observe(self, now, *, size, mtime, change_usn=0, content_changed=None, learn_interval=True):
        changed = content_changed if content_changed is not None else (
            self.last_size is None or size != self.last_size or mtime != self.last_mtime
            or change_usn != self.last_change_usn)
        if changed:
            # EWMA's interval baseline survives retirement just like the real
            # tracker. Its distribution state does not survive retirement.
            if hasattr(self.estimator, "last"):
                self.estimator.last = self.last_content_event_at
            self.quiet_seconds = self.estimator.observe(Observation(
                now, "", "content", size, mtime, change_usn, True, learn_interval))
            self.last_content_event_at = now
        self.last_size, self.last_mtime, self.last_change_usn = size, mtime, change_usn
        return self.quiet_seconds


def _watcher(factory, metadata_root):
    # Same isolated production-method construction used by watch-source-claims
    # and watch-source-index-retention. No Broker, threads or disk payload IO.
    watcher = object.__new__(scheduler.WatchScheduler)
    watcher._lock = threading.Lock()
    watcher._claim_gate = threading.RLock()
    for name in ("_pending", "_pending_by_key", "_active_states", "_active_claims",
                 "_claims_by_owner", "_dirty_during_claim", "_source_probes",
                 "_inflight_path_counts", "_quiet_trackers"):
        setattr(watcher, name, {})
    watcher._inflight_requests = []
    watcher._active_epoch = 0
    watcher._ready_heap = []
    watcher._closed = False
    watcher._wake_callback = None
    watcher.watch_roots = []
    watcher.state = _MemoryState()
    watcher._catalog = NativeWatchCatalog(watcher.state._native)
    # Persistent catalog rows are essential: transient observations are deleted
    # on retirement and would accidentally turn adaptive into zero-wait.
    errors = NativeDirectoryScanOptions([], [], [], []).catalog_update(
        watcher._catalog, DiscoveryScope(str(metadata_root)).native)
    if errors:
        raise OSError(errors)
    watcher._quiet_policy = None  # factory owns the exact frozen policy.
    watcher.boundary_confirmation_seconds = DEFAULT_WATCH_CONFIG["boundary_confirmation_seconds"]
    watcher.should_ignore_event_path = lambda path: False
    watcher._is_under_watched_root = lambda path: True
    watcher._is_under_metadata_dir = lambda path: False
    watcher._source_input_root_for = lambda path: os.path.dirname(path)
    watcher._log_candidate_ignored = lambda *args, **kwargs: None

    def write(event, **fields):
        if event == "candidate_error":
            raise RuntimeError(f"production admission failed: {fields}")

    watcher.log = SimpleNamespace(write=write, write_throttled=write)

    def tracker(_policy):
        estimator = factory()
        return estimator.tracker if hasattr(estimator, "tracker") else _ControlTracker(estimator)

    return watcher, tracker


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
            complete_arrival_at=arrived, first_valid_proposal_at=first,
            complete_arrival_to_valid_proposal_seconds=None if first is None else first - arrived,
        ))
    return inputs


def prepare_metadata(root: Path, width=64):
    root.mkdir(parents=True, exist_ok=True)
    for index in range(width):
        (root / f"file-{index}.opaque").touch()
    return root.resolve()


def replay_scheduler(trace: Trace, factory, *, tie_order="observation_first", metadata_root=None):
    if metadata_root is None:
        with TemporaryDirectory(prefix="sunpack-quiet-replay-") as folder:
            return _replay_scheduler(trace, factory, tie_order, prepare_metadata(Path(folder)))
    return _replay_scheduler(trace, factory, tie_order, metadata_root)


def _replay_scheduler(trace: Trace, factory, tie_order, metadata_root):
    started = time.process_time_ns()
    filesystem = _Filesystem(trace, metadata_root)
    watcher, tracker = _watcher(factory, metadata_root)
    truth = {file.key: file for file in trace.files}
    results = {file.key: FileResult(file.key, file.shape, file.complete_at is not None) for file in trace.files}
    group_ready, boundaries = proposal_boundaries(trace)
    # Physical changes only wake an already spinning zero-delay busy probe;
    # they never enqueue an input or reveal completion to the estimator.
    events = [(event.at, 1, index, event, event.key) for index, event in enumerate(trace.observations)]
    serial = len(events)
    for file in trace.files:
        if file.blocked:
            for at in [*(item.at for item in file.mutations), *(end for _, end in file.blocked)]:
                events.append((at, 0, serial, None, file.key))
                serial += 1
    heapq.heapify(events)
    parked = {}
    coalesced_busy = 0
    peak_models = 0
    calls = 0
    with patch.object(scheduler, "_candidate_for_event_path", filesystem.candidate), \
         patch.object(scheduler, "watch_file_is_ready", filesystem.ready), \
         patch.object(scheduler, "AdaptiveQuietTracker", tracker), \
         patch.object(scheduler, "time", SimpleNamespace(monotonic=lambda: filesystem.now)):
        while events or watcher._ready_heap:
            with watcher._lock:
                entry = watcher._next_ready_entry_locked()
            deadline = max(filesystem.now, entry[0]) if entry is not None else float("inf")
            event_at = events[0][0] if events else float("inf")
            at = min(deadline, event_at)
            if at > trace.horizon or at == float("inf"):
                break
            filesystem.now = at
            if event_at < deadline or (event_at == deadline and tie_order == "observation_first"):
                _, _, _, event, key = heapq.heappop(events)
                if event is not None:
                    watcher.enqueue(filesystem.paths[event.key], event_type="modified")
                # Other files cannot change this path's readiness or content.
                # Waking every busy path for unrelated duplicate notifications
                # makes the virtual adapter's probe cost grow with width.
                item = parked.pop(filesystem.paths[key], None)
                if item is not None:
                    heapq.heappush(watcher._ready_heap, item)
            else:
                calls += 1
                for candidate in watcher._pop_ready(at):
                    key = filesystem.keys[candidate.path]
                    record_proposal(results[key], truth[key], at, group_ready, trace.horizon)
                    watcher.state.complete_work_if_matches(candidate)
                    # Production retires distribution history on completion;
                    # retaining it forever changes subsequent epochs markedly.
                    watcher._retire_quiet_tracker(candidate.path)
                # Native busy checks with quiet=0 can repeat without advancing
                # virtual time. Collapse only this state-invariant spin, up to
                # the next physical change/delivery/unlock. Record its presence;
                # no claim is made about its real probe count or CPU cost.
                while watcher._ready_heap:
                    item = watcher._next_ready_entry_locked()
                    if item is None or item[0] > at:
                        break
                    path = item[-1]
                    if filesystem.truth[filesystem.keys[path]].readable(at):
                        raise RuntimeError("zero-time non-busy scheduler cycle")
                    parked[path] = heapq.heappop(watcher._ready_heap)
                    coalesced_busy += 1
            peak_models = max(peak_models, len(watcher._quiet_trackers))
    files = [asdict(result) for result in results.values()]
    add_valid_proposal_latency(files, boundaries)
    inputs = input_results(trace, files)
    for item in inputs:
        if item["complete_arrival_at"] is None:
            item["missing_reason"] = "no_complete_arrival"
        elif item["first_valid_proposal_at"] is not None:
            item["missing_reason"] = None
        else:
            active = [watcher._active_states[filesystem.paths[key]] for key in item["members"]
                      if filesystem.paths[key] in watcher._active_states]
            item["pending_deadlines"] = [state.last_event_at + state.quiet_seconds for state in active]
            item["missing_reason"] = ("deadline_beyond_horizon" if active and all(
                deadline > trace.horizon for deadline in item["pending_deadlines"])
                else "no_pending_after_earlier_admission" if not active else "pending_at_horizon")
    return dict(files=files, inputs=inputs, delivered_observations=len(trace.observations),
                scheduled_deadlines=calls, peak_live_estimators=peak_models,
                metadata_probes=filesystem.metadata_probes, readiness_probes=filesystem.readiness_probes,
                coalesced_zero_delay_busy_checks=coalesced_busy,
                replay_cpu_ns=time.process_time_ns() - started)
