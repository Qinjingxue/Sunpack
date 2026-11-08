"""Virtual filesystem/clock driving the production Watch admission methods.

No second scheduler or archive analyser: native metadata/readiness IO and WAL
are replaced at their boundaries. Pipeline duration is zero, and admission is
scored against writer truth. This is not an extraction-throughput benchmark.
"""
from __future__ import annotations

import bisect
import heapq
import math
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
        self.journal = {}
        self.metadata_probes = 0
        self.readiness_probes = 0
        self.busy_paths = set()
        for file in trace.files:
            snapshots = []
            identity = 0
            for item in file.mutations:
                identity += item.operation == "replace"
                snapshots.append((item.at, item.size, item.mtime, item.usn, identity))
            self.snapshots[file.key] = snapshots
            self.times[file.key] = [item[0] for item in snapshots]
            self.journal[file.key] = [(item.usn, item.change_reasons) for item in file.mutations if item.change_reasons]

    def candidate(self, path, *, since_usn=0):
        self.metadata_probes += 1
        key = self.keys[path]
        if self.now < self.truth[key].visible_at:
            return None
        position = bisect.bisect_right(self.times[key], self.now) - 1
        if position < 0:
            return None
        _, size, mtime, usn, identity = self.snapshots[key][position]
        all_reasons = reasons = 0
        known = since_usn > 0
        if known:
            for record_usn, mask in self.journal[key]:
                if since_usn < record_usn <= usn:
                    all_reasons |= mask
                    # A CLOSE record repeats the epoch's accumulated reasons;
                    # it is not fresh content activity by itself.
                    if not mask & scheduler.USN_REASON_CLOSE:
                        reasons |= mask
        return WatchCandidate(path, size, mtime, f"{key}/{identity}", usn,
                              change_reasons=all_reasons, change_reasons_without_close=reasons,
                              change_reasons_known=known)

    def ready(self, path):
        self.readiness_probes += 1
        readable = self.truth[self.keys[path]].readable(self.now)
        if not readable:
            self.busy_paths.add(path)
        return readable


class _ControlTracker:
    """Adapt independent controls to the production tracker's lifecycle."""
    def __init__(self, estimator):
        self.estimator = estimator
        self.quiet_seconds = 0.0
        self.cadence_seconds = 0.0
        self.pending_interval_seconds = 0.0
        self.last_content_event_at = None
        self.last_size = self.last_mtime = self.last_change_usn = None

    def observe(self, now, *, size, mtime, change_usn=0, content_changed=None, learn_interval=True, phase_boundary=False):
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
    for name in ("_pending", "_pending_by_key", "_active_claims",
                 "_claims_by_owner", "_dirty_during_claim", "_source_probes",
                 "_inflight_path_counts", "_quiet_trackers"):
        setattr(watcher, name, {})
    watcher._inflight_requests = []
    watcher._active_epoch = 0
    watcher._ready_heap = []
    watcher._closed = False
    watcher._wake_callback = None
    watcher.root_entries = {}
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
            complete_arrival_at=arrived, processing_ready_at=ready, first_valid_proposal_at=first,
            ready_to_valid_proposal_seconds=None if first is None else first - ready,
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
                # Skip invariant busy timers analytically, retaining their
                # cadence/phase. A physical mutation/unlock always has a wake
                # event before delivery, so no changed snapshot is skipped.
                path = filesystem.paths[events[0][-1]]
                item = parked.pop(path, None)
                if item is not None:
                    state = watcher._active_states.get(path)
                    if state is not None and (state.epoch, state.generation) == item[1:3]:
                        step = state.quiet_seconds
                        due = item[0]
                        if step > 0.0 and due < at:
                            due += math.ceil((at - due) / step) * step
                            state.last_event_at = due - step
                        heapq.heappush(watcher._ready_heap, (due, *item[1:]))
                        if step > 0.0 and due <= at and tie_order == "timer_first":
                            continue
                _, _, _, event, key = heapq.heappop(events)
                if event is not None:
                    watcher.enqueue(filesystem.paths[event.key], event_type=event.event_type)
            else:
                calls += 1
                filesystem.busy_paths.clear()
                for candidate in watcher._pop_ready(at):
                    key = filesystem.keys[candidate.path]
                    record_proposal(results[key], truth[key], at, group_ready, trace.horizon)
                    watcher.state.complete_work_if_matches(candidate)
                    # Production retires distribution history on completion;
                    # retaining it forever changes subsequent epochs markedly.
                    watcher._retire_quiet_tracker(candidate.path)
                if filesystem.busy_paths:
                    kept = []
                    for item in watcher._ready_heap:
                        path = item[-1]
                        state = watcher._active_states.get(path)
                        if (path in filesystem.busy_paths and state is not None
                                and (state.epoch, state.generation) == item[1:3]):
                            parked[path] = item
                            coalesced_busy += 1
                        else:
                            kept.append(item)
                    watcher._ready_heap[:] = kept
                    heapq.heapify(watcher._ready_heap)
            peak_models = max(peak_models, len(watcher._quiet_trackers))
    files = [asdict(result) for result in results.values()]
    add_valid_proposal_latency(files, boundaries)
    inputs = input_results(trace, files)
    for item in inputs:
        if item["processing_ready_at"] is None:
            item["missing_reason"] = "no_processing_ready_input"
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
                coalesced_busy_timer_runs=coalesced_busy,
                replay_cpu_ns=time.process_time_ns() - started)
