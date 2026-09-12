from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Iterable

from sunpack.config.fields.watch import DEFAULT_WATCH_CONFIG
from sunpack.contracts.failures import FailureKind, PASSWORD_FAILURE_KINDS
from sunpack.contracts.filesystem import FileEntry
from sunpack.contracts.results import OutcomeKind
from sunpack.contracts.pipeline import PipelineTarget
from sunpack.filesystem.directory_scanner import (
    apply_ordered_filters_to_entries,
    rejected_only_by_size_range,
    split_size_family_keys,
)
from sunpack.filesystem.filters import build_filters
from sunpack.filesystem.watcher.log import WatchLogStore
from sunpack.filesystem.watcher.group_dispatch import (
    DeferredWatch,
    NullWatchGroupResolver,
    plan_watch_dispatches,
)
from sunpack.filesystem.watcher.group_models import (
    BLOCKER_MISSING_VOLUME,
    BLOCKER_PASSWORD,
    WatchGroupSnapshot,
)
from sunpack.filesystem.watcher.quiet_policy import AdaptiveQuietPolicy, AdaptiveQuietTracker
from sunpack.filesystem.watcher.scanner import (
    WatchCandidate,
    scan_watch_candidates,
    validate_ntfs_watch_roots,
    watch_file_is_ready,
)
from sunpack.filesystem.watcher.scanner import _candidate_for as _watch_candidate_for_path
from sunpack.filesystem.watcher.state import WatchStateEntry, WatchStateStore
from sunpack.filesystem.watcher.toast import NullWatchNotificationSink
from sunpack.i18n import I18nContext
from sunpack.passwords.internal import builtin as builtin_passwords_module
from sunpack.passwords.internal.builtin import get_builtin_passwords
from sunpack.passwords.internal.clipboard_monitor import ClipboardPasswordMonitor
from sunpack.passwords.internal.lists import dedupe_passwords
from sunpack.passwords.internal.local_files import DIRECTORY_PASSWORD_FILE_NAME, is_directory_password_file
from sunpack.passwords.internal.store import MAX_RECENT_PASSWORDS
from sunpack.support.path_keys import path_key
from sunpack.support.collections import dedupe_normalized_paths
from sunpack.support.resource_lifecycle import (
    ResourceKind,
    lifecycle_registration,
    open_service_file,
    register_service_resource,
)

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer


USN_REASON_DATA_OVERWRITE = 0x00000001
USN_REASON_DATA_EXTEND = 0x00000002
USN_REASON_DATA_TRUNCATION = 0x00000004
USN_CONTENT_REASON_MASK = (
    USN_REASON_DATA_OVERWRITE
    | USN_REASON_DATA_EXTEND
    | USN_REASON_DATA_TRUNCATION
)
RESTORED_MTIME_MINIMUM_BACKSTEP_SECONDS = 2.0


class _CandidateChangeKind(Enum):
    UNCHANGED = auto()
    METADATA_ONLY = auto()
    CONTENT_CHANGED = auto()


@dataclass
class WatchRunResult:
    processed: int = 0
    succeeded: int = 0
    failed: int = 0
    pending: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class _ActiveCandidateState:
    last_event_at: float
    quiet_seconds: float
    filtered_size: int
    filtered_mtime: float
    generation: int = 1
    force: bool = False
    filter_revision: int = 0


@dataclass
class _ActivePipelineRequest:
    notification_id: str
    candidate: WatchCandidate
    group: WatchGroupSnapshot | None
    task: asyncio.Task
    registry_owner: str = ""


class WatchScheduler:
    def __init__(
        self,
        config: dict,
        watch_roots: list[str],
        *,
        output_roots: dict[str, str] | None = None,
        out_dir: str = ".",
        state_path: str,
        quiet_seconds: float | None = None,
        initial_scan: bool | None = None,
        initial_scan_roots: Iterable[str] | None = None,
        observer_stop_timeout_seconds: float | None = None,
        pipeline_engine=None,
        group_coordinator=None,
        notification_sink=None,
        wake_callback: Callable[[], None] | None = None,
    ):
        self.config = config
        cli_config = config.get("cli") if isinstance(config.get("cli"), dict) else {}
        self.i18n = I18nContext(cli_config.get("language", "en"))
        watch_config = dict(DEFAULT_WATCH_CONFIG)
        if isinstance(config.get("watch"), dict):
            watch_config.update(config["watch"])
        self.watch_roots = [os.path.abspath(path) for path in watch_roots]
        validate_ntfs_watch_roots(self.watch_roots)
        expanded_out_dir = os.path.expanduser(out_dir)
        self.out_dir = os.path.normpath(expanded_out_dir) if not os.path.isabs(expanded_out_dir) else os.path.abspath(expanded_out_dir)
        # Every watch root has exactly one absolute output root, resolved here so no request path
        # ever chooses between a per-root and a global output directory.  out_dir only supplies the
        # roots the caller did not enumerate, and stays relative to its own input root.
        self.output_roots = {
            path_key(os.path.abspath(str(root))): os.path.abspath(os.path.expanduser(str(output)))
            for root, output in (output_roots or {}).items()
            if str(output or "").strip()
        }
        for root in self.watch_roots:
            self.output_roots.setdefault(
                path_key(root),
                os.path.abspath(os.path.join(root, self.out_dir)) if not os.path.isabs(expanded_out_dir) else self.out_dir,
            )
        self._validate_output_roots()
        configured_cold_start = watch_config.get(
            "cold_start_seconds",
            watch_config.get("quiet_seconds", DEFAULT_WATCH_CONFIG["cold_start_seconds"]),
        )
        self.cold_start_seconds = max(
            0.0,
            float(configured_cold_start if quiet_seconds is None else quiet_seconds),
        )
        self.quiet_seconds = self.cold_start_seconds
        self.recursive = False
        self.initial_scan = bool(initial_scan)
        self.initial_scan_roots = (
            None
            if initial_scan_roots is None
            else dedupe_normalized_paths(initial_scan_roots)
        )
        self.observer_stop_timeout_seconds = max(
            0.0,
            float(
                DEFAULT_WATCH_CONFIG["observer_stop_timeout_seconds"]
                if observer_stop_timeout_seconds is None
                else observer_stop_timeout_seconds
            ),
        )
        self._filter_revision = 0
        self._filters = []
        self.filters = build_filters(config)
        self.state = WatchStateStore(state_path)
        self.group_coordinator = group_coordinator or NullWatchGroupResolver()
        log_path = Path(state_path).with_name("events.jsonl")
        self.log = WatchLogStore(str(log_path))
        state_parent = Path(state_path).parent
        self.metadata_dir = os.path.abspath(str(state_parent)) if state_parent.name == ".sunpack_watch" else ""
        self.metadata_files = {
            os.path.abspath(str(Path(state_path))),
            os.path.abspath(str(self.state.journal_path)),
            os.path.abspath(str(log_path)),
        }
        self._lock = threading.Lock()
        self._password_source_lock = threading.RLock()
        self._pending: dict[str, WatchCandidate] = {}
        self._inflight_requests: list[_ActivePipelineRequest] = []
        self._active_states: dict[str, _ActiveCandidateState] = {}
        self._latest_observations: dict[str, WatchCandidate] = {}
        self._quiet_trackers: dict[str, AdaptiveQuietTracker] = {}
        self._password_dirty_dirs: dict[str, float] = {}
        self._observer = Observer()
        self._observer_resource = None
        self._started = False
        self._wake_callback = wake_callback
        self.notification_sink = notification_sink or NullWatchNotificationSink()
        self._notification_error_actions: set[str] = set()
        self.runtime_cache_cleanup_enabled = bool(
            watch_config.get("runtime_cache_cleanup_enabled", True)
        )
        self.runtime_cache_cleanup_idle_seconds = max(
            0.0,
            float(watch_config.get("runtime_cache_cleanup_idle_seconds", 10.0)),
        )
        self._cache_cleanup_deadline: float | None = None
        if pipeline_engine is None:
            raise ValueError("WatchScheduler requires a PipelineEngine")
        self.pipeline_engine = pipeline_engine
        quiet_min_seconds = max(
            0.0,
            float(watch_config.get("quiet_min_seconds", DEFAULT_WATCH_CONFIG["quiet_min_seconds"])),
        )
        quiet_max_seconds = (
            0.0
            if self.cold_start_seconds <= 0.0
            else max(
                self.cold_start_seconds,
                quiet_min_seconds,
                float(watch_config.get("quiet_max_seconds", DEFAULT_WATCH_CONFIG["quiet_max_seconds"])),
            )
        )
        if self.cold_start_seconds <= 0.0:
            quiet_min_seconds = 0.0
        self._quiet_policy = AdaptiveQuietPolicy(
            initial_seconds=self.cold_start_seconds,
            minimum_seconds=quiet_min_seconds,
            maximum_seconds=quiet_max_seconds,
        )
        self.boundary_confirmation_seconds = max(
            0.0,
            float(
                watch_config.get(
                    "boundary_confirmation_seconds",
                    DEFAULT_WATCH_CONFIG["boundary_confirmation_seconds"],
                )
            ),
        )
        self.password_retry_debounce_seconds = max(0.0, float(watch_config["password_retry_debounce_seconds"]))
        self.password_retry_include_subtree = bool(watch_config["password_retry_include_subtree"])
        self._configured_user_passwords = dedupe_passwords(list(config.get("user_passwords") or []))
        self._configured_builtin_passwords = dedupe_passwords(list(config.get("builtin_passwords") or []))
        self.builtin_password_file = os.path.abspath(str(builtin_passwords_module.builtin_password_path()))
        self._recent_passwords: list[str] = []
        self._password_source_signature = self._refresh_password_sources()
        self._sync_group_coordinator_passwords()
        set_password_callback = getattr(self.group_coordinator, "set_password_callback", None)
        if callable(set_password_callback):
            set_password_callback(self._remember_recent_passwords)
        if self.state.record_password_source_signature(self._password_source_signature):
            self._mark_all_password_failures_dirty()
        self._clipboard_monitor = ClipboardPasswordMonitor(
            on_passwords_changed=self.notify_password_source_changed,
            enabled=bool(watch_config["clipboard_monitor_enabled"]),
            max_entries=int(watch_config["clipboard_builtin_max_entries"]),
        )

    def _validate_output_roots(self) -> None:
        resolved = [
            (root, self.output_roots[path_key(root)])
            for root in self.watch_roots
        ]
        for index, (first_root, first_output) in enumerate(resolved):
            for second_root, second_output in resolved[index + 1:]:
                if path_key(first_output) == path_key(second_output):
                    continue
                if _is_relative_to(first_output, second_output) or _is_relative_to(second_output, first_output):
                    raise ValueError(
                        "watch output roots must not contain one another: "
                        f"{first_root} -> {first_output}; {second_root} -> {second_output}"
                    )

    async def start(self):
        await self.pipeline_engine.work_broker.run(
            "watch_start",
            "watch",
            self._start_blocking,
            request_id="watch",
        )

    def _start_blocking(self):
        if self._started:
            return
        self._ensure_directory_password_files()
        removed_entries, removed_groups = self.state.prune_missing_records()
        if removed_entries or removed_groups:
            self.log.write(
                "state_pruned_on_start",
                entries=removed_entries,
                groups=removed_groups,
            )
        handler = _WatchEventHandler(self)
        scheduled_paths: set[str] = set()
        for root in self.watch_roots:
            watch_path = root if os.path.isdir(root) else os.path.dirname(root)
            self._observer.schedule(handler, watch_path, recursive=self.recursive and os.path.isdir(root))
            scheduled_paths.add(os.path.normcase(os.path.abspath(watch_path)))
        builtin_password_dir = os.path.dirname(self.builtin_password_file)
        builtin_password_dir_key = os.path.normcase(os.path.abspath(builtin_password_dir))
        if os.path.isdir(builtin_password_dir) and builtin_password_dir_key not in scheduled_paths:
            self._observer.schedule(handler, builtin_password_dir, recursive=False)
        with lifecycle_registration(self.watch_roots):
            self._observer.start()
            try:
                self._observer_resource = register_service_resource(
                    self._observer,
                    self.watch_roots,
                    self._release_observer,
                    kind=ResourceKind.DIRECTORY_WATCH,
                    registration_held=True,
                    promotion_blocking=False,
                )
            except BaseException:
                self._release_observer()
                raise
        self._clipboard_monitor.start()
        self._started = True
        for pending in self.state.pending_work_items():
            if os.path.exists(pending.path):
                self.enqueue(pending.path, force=pending.force, event_type="recovery")
            else:
                self.state.forget_path(pending.path)
        if self.initial_scan or self.initial_scan_roots is not None:
            scan_roots = self.watch_roots if self.initial_scan_roots is None else self.initial_scan_roots
            for candidate in scan_watch_candidates(scan_roots, recursive=self.recursive):
                self.enqueue(candidate.path, event_type="initial_scan")
        self.log.write(
            "scheduler_started",
            roots=self.watch_roots,
            out_dir=self.out_dir,
            output_roots=self.output_roots,
            recursive=self.recursive,
            initial_scan=bool(self.initial_scan or self.initial_scan_roots is not None),
            initial_scan_roots=self.initial_scan_roots,
            pending=self.pending_count,
            cold_start_seconds=self.cold_start_seconds,
            quiet_min_seconds=self._quiet_policy.minimum_seconds,
            quiet_max_seconds=self._quiet_policy.maximum_seconds,
        )

    def _ensure_directory_password_files(self) -> None:
        for root in self.watch_roots:
            if not os.path.isdir(root):
                continue
            password_file = Path(root) / DIRECTORY_PASSWORD_FILE_NAME
            if not is_directory_password_file(str(password_file), self.config):
                continue
            try:
                open_service_file(password_file, "x", encoding="utf-8").close()
            except FileExistsError:
                pass

    async def stop(self):
        await self.pipeline_engine.work_broker.run(
            "watch_stop",
            "watch",
            self._stop_blocking,
            request_id="watch",
            origin="watch",
        )

    async def drain(self) -> WatchRunResult:
        """Finish already-submitted watch work without admitting new candidates."""

        result = WatchRunResult()
        while True:
            with self._lock:
                active = list(self._inflight_requests)
            if not active:
                return result
            await asyncio.gather(*(request.task for request in active), return_exceptions=True)
            self._merge_run_result(result, await self._harvest_completed_requests())

    def _stop_blocking(self):
        if not self._started:
            return
        if self._observer_resource is not None:
            self._observer_resource.close()
            self._observer_resource = None
        else:
            self._release_observer()
        self._clipboard_monitor.stop()
        self.state.compact_if_needed()
        with self._lock:
            self._cache_cleanup_deadline = None
        self._started = False

    def _release_observer(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=self.observer_stop_timeout_seconds)

    async def run_once(self) -> WatchRunResult:
        self._process_password_dirty_dirs(time.monotonic())
        result = await self._harvest_completed_requests()
        ready = self._pop_ready(time.time())
        with self._lock:
            active_paths = {
                os.path.normcase(os.path.abspath(path))
                for path in self._pending
            } | self._inflight_path_keys_locked()
        dispatches, waiting, deferred = plan_watch_dispatches(
            ready,
            active_paths=active_paths,
            coordinator=self.group_coordinator,
            state=self.state,
            prepare_candidate=self._prepare_group_head,
        )
        for item in deferred:
            if item.group is not None:
                # A different member of this split group is still pending or
                # in flight.  Keep the ready member pending with its quiet
                # clock aligned to the group's latest pending member so the
                # group dispatches together instead of deferring each other
                # indefinitely one quiet window at a time.
                self._defer_group_member(item.candidate, item.group)
            else:
                self.enqueue(item.candidate.path, force=True, event_type="modified")
        for snapshot in waiting:
            self.log.write(
                "split_group_suspended",
                group_id=snapshot.group_id,
                head_path=snapshot.head_path,
                input_paths=list(snapshot.input_paths),
                missing_reason=snapshot.missing_reason,
                missing_indices=list(snapshot.missing_indices),
            )
        active_requests = []
        for dispatch in dispatches:
            request = await self._submit_candidate(dispatch.candidate, group=dispatch.group)
            if request is not None:
                active_requests.append(request)
        with self._lock:
            self._inflight_requests.extend(active_requests)
        # Give newly submitted candidate coroutines one scheduling turn.  Fast
        # no-op/failure requests can be harvested in this tick without ever
        # waiting for slow candidates.
        if active_requests:
            await asyncio.sleep(0)
        self._merge_run_result(result, await self._harvest_completed_requests())
        result.pending = self.pending_count
        await self._maybe_clear_idle_caches()
        with self._lock:
            state_is_idle = not self._pending and not self._inflight_requests
        if state_is_idle:
            self.state.compact_if_needed()
        return result

    async def _harvest_completed_requests(self) -> WatchRunResult:
        with self._lock:
            completed = [request for request in self._inflight_requests if request.task.done()]
            if completed:
                completed_ids = {id(request) for request in completed}
                self._inflight_requests = [
                    request for request in self._inflight_requests if id(request) not in completed_ids
                ]
        result = WatchRunResult()
        if completed:
            finished = await asyncio.gather(
                *(self._finish_active_request(request) for request in completed),
            )
            for single in finished:
                self._merge_run_result(result, single)
        return result

    async def _finish_active_request(self, request: _ActivePipelineRequest) -> WatchRunResult:
        try:
            try:
                single = await self._complete_candidate(request)
            except Exception as exc:
                self._notify("aborted", request.notification_id)
                single = WatchRunResult(processed=1, failed=1, errors=[str(exc)])
                self.log.write(
                    "error",
                    path=request.candidate.path,
                    error=str(exc),
                    error_type=type(exc).__name__,
                    phase="pipeline_completion",
                )
                self.enqueue(
                    request.candidate.path,
                    force=True,
                    event_type="pipeline_completion_error",
                )
            else:
                self.state.complete_work_if_matches(request.candidate)
            self._arm_idle_cache_cleanup()
            return single
        finally:
            if request.registry_owner:
                from sunpack.cli.runtime_state import runtime_host

                host = runtime_host()
                if host is not None:
                    host.archive_registry.release(request.registry_owner)

    @staticmethod
    def _merge_run_result(target: WatchRunResult, source: WatchRunResult) -> None:
        target.processed += source.processed
        target.succeeded += source.succeeded
        target.failed += source.failed
        target.errors.extend(source.errors)

    def _inflight_path_keys_locked(self) -> set[str]:
        paths: set[str] = set()
        for request in self._inflight_requests:
            paths.add(os.path.normcase(os.path.abspath(request.candidate.path)))
            if request.group is not None:
                paths.update(
                    os.path.normcase(os.path.abspath(path))
                    for path in request.group.owned_paths
                )
        return paths

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    @property
    def filters(self):
        return self._filters

    @filters.setter
    def filters(self, value) -> None:
        self._filters = list(value or [])
        self._filter_revision += 1

    def next_delay_seconds(self) -> float | None:
        now = time.time()
        monotonic_now = time.monotonic()
        with self._lock:
            inflight_paths = self._inflight_path_keys_locked()
            schedulable_states = [
                state
                for path, state in self._active_states.items()
                if os.path.normcase(os.path.abspath(path)) not in inflight_paths
            ]
            if schedulable_states:
                delay = max(
                    0.0,
                    min(
                        state.quiet_seconds - (now - state.last_event_at)
                        for state in schedulable_states
                    ),
                )
            else:
                delay = None
            if self._password_dirty_dirs:
                password_delay = max(
                    0.0,
                    min(
                        changed_at + self.password_retry_debounce_seconds - monotonic_now
                        for changed_at in self._password_dirty_dirs.values()
                    ),
                )
                delay = password_delay if delay is None else min(delay, password_delay)
            if self.runtime_cache_cleanup_enabled and self._cache_cleanup_deadline is not None:
                cleanup_delay = max(0.0, self._cache_cleanup_deadline - monotonic_now)
                delay = cleanup_delay if delay is None else min(delay, cleanup_delay)
            return delay

    def _reset_idle_cache_cleanup(self) -> None:
        if not self.runtime_cache_cleanup_enabled:
            return
        with self._lock:
            self._cache_cleanup_deadline = None

    def _arm_idle_cache_cleanup(self) -> None:
        if not self.runtime_cache_cleanup_enabled:
            return
        with self._lock:
            self._cache_cleanup_deadline = (
                time.monotonic() + self.runtime_cache_cleanup_idle_seconds
            )
        self.log.write(
            "cache_cleanup_scheduled",
            idle_seconds=self.runtime_cache_cleanup_idle_seconds,
        )

    async def _maybe_clear_idle_caches(self) -> None:
        if not self.runtime_cache_cleanup_enabled:
            return
        now = time.monotonic()
        with self._lock:
            if self._cache_cleanup_deadline is None or now < self._cache_cleanup_deadline:
                return
            if self._pending or self._inflight_requests:
                return
            self._cache_cleanup_deadline = None
        self.log.write("cache_cleanup_started")
        started = time.perf_counter()
        report = await self.pipeline_engine.clear_runtime_caches()
        if report.get("skipped"):
            with self._lock:
                if (
                    self._cache_cleanup_deadline is None
                    and not self._pending
                    and not self._inflight_requests
                ):
                    self._cache_cleanup_deadline = (
                        time.monotonic() + self.runtime_cache_cleanup_idle_seconds
                    )
        self.log.write(
            "cache_cleanup_finished",
            elapsed_seconds=time.perf_counter() - started,
            report=report,
        )

    def enqueue(
        self,
        path: str,
        *,
        force: bool = False,
        event_type: str = "unknown",
        src_path: str = "",
        _password_retry_snapshot: WatchStateEntry | None = None,
    ):
        if self.should_ignore_event_path(path):
            return
        if is_directory_password_file(path, self.config):
            self._log_candidate_ignored(path, "directory_password_file")
            return
        lookup_path = os.path.abspath(path)
        with self._lock:
            previous_hint = self._candidate_baseline_locked(lookup_path)
        if previous_hint is None:
            previous_hint = _candidate_from_state_entry(self.state.latest_entry_for_path(lookup_path))
        candidate = _candidate_for_event_path(
            path,
            since_usn=previous_hint.change_usn if previous_hint is not None else 0,
        )
        if candidate is None:
            self._log_candidate_ignored(path, "not_a_file_or_unreadable")
            return
        if not self._is_under_watched_root(candidate.path):
            self._log_candidate_ignored(candidate.path, "outside_watched_roots")
            return
        if self._is_under_metadata_dir(candidate.path):
            self._log_candidate_ignored(candidate.path, "under_metadata_dir")
            return
        now = time.time()
        with self._lock:
            previous = self._candidate_baseline_locked(candidate.path) or previous_hint
            change_kind = _candidate_change_kind(previous, candidate)
            if not force and change_kind == _CandidateChangeKind.UNCHANGED:
                return
            if not force and change_kind == _CandidateChangeKind.METADATA_ONLY:
                self._accept_metadata_observation_locked(candidate, now)
                return
            state = self._active_states.get(candidate.path)
            if state is not None:
                state.force = state.force or force
                self._pending[candidate.path] = candidate
                self._latest_observations[candidate.path] = candidate
                quiet_seconds = self._observe_candidate_activity(
                    candidate,
                    now,
                    content_changed=True,
                )
                state.last_event_at = now
                state.quiet_seconds = quiet_seconds
                state.generation += 1
                state.filter_revision = self._filter_revision
                state.filtered_size = candidate.size
                state.filtered_mtime = candidate.mtime
                self._wake_service()
                return
        if not self._passes_filesystem_filters(candidate):
            self._log_candidate_ignored(candidate.path, "filtered_out")
            return
        became_active = False
        active_quiet_seconds = self.cold_start_seconds
        with self._lock:
            previous = self._candidate_baseline_locked(candidate.path)
            change_kind = _candidate_change_kind(previous, candidate)
            if not force and change_kind == _CandidateChangeKind.UNCHANGED:
                return
            if not force and change_kind == _CandidateChangeKind.METADATA_ONLY:
                self._accept_metadata_observation_locked(candidate, now)
                return
            state = self._active_states.get(candidate.path)
            if state is None:
                retry_is_unchanged = (
                    _password_retry_snapshot is not None
                    and _candidate_matches_password_failure(candidate, _password_retry_snapshot)
                )
                active_quiet_seconds = (
                    0.0
                    if retry_is_unchanged
                    else self._observe_candidate_activity(candidate, now)
                )
                self._pending[candidate.path] = candidate
                self._latest_observations[candidate.path] = candidate
                became_active = True
                self._active_states[candidate.path] = _ActiveCandidateState(
                    last_event_at=now,
                    quiet_seconds=active_quiet_seconds,
                    filtered_size=candidate.size,
                    filtered_mtime=candidate.mtime,
                    force=force,
                    filter_revision=self._filter_revision,
                )
            else:
                state.force = state.force or force
                self._pending[candidate.path] = candidate
                self._latest_observations[candidate.path] = candidate
                active_quiet_seconds = self._observe_candidate_activity(
                    candidate,
                    now,
                    content_changed=True,
                )
                state.last_event_at = now
                state.quiet_seconds = active_quiet_seconds
                state.generation += 1
                state.filter_revision = self._filter_revision
                state.filtered_size = candidate.size
                state.filtered_mtime = candidate.mtime
        if became_active:
            self.state.queue_active(candidate, force=force)
            self.log.write(
                "candidate_active",
                path=candidate.path,
                force=force,
                event_type=event_type,
                src_path=src_path,
                size=candidate.size,
                mtime=candidate.mtime,
                quiet_seconds=active_quiet_seconds,
                pending=self.pending_count,
            )
            self._wake_service()

    def should_ignore_event_path(self, path: str) -> bool:
        if not path:
            return True
        return self._is_under_metadata_dir(path)

    def _log_candidate_ignored(self, path: str, reason: str, **payload) -> None:
        normalized = os.path.normcase(os.path.abspath(str(path))) if path else ""
        self.log.write_throttled(
            "candidate_ignored",
            throttle_key=f"{normalized}|{reason}",
            interval_seconds=300.0,
            path=path,
            reason=reason,
            **payload,
        )

    def is_builtin_password_file(self, path: str) -> bool:
        if not path:
            return False
        return os.path.normcase(os.path.abspath(path)) == os.path.normcase(self.builtin_password_file)

    def enqueue_many(self, paths: Iterable[str]):
        for path in paths:
            self.enqueue(path)

    def notify_password_source_changed(self, reason: str, path: str = "") -> None:
        with self._password_source_lock:
            previous_signature = self._password_source_signature
            signature = self._refresh_password_sources()
            self._sync_group_coordinator_passwords()
            if reason in {"builtin_password_file", "clipboard"} and signature == previous_signature:
                return
            self._password_source_signature = signature
            generation = self.state.mark_password_source_changed(signature)
            self.log.write("password_source_changed", reason=reason, path=path, password_generation=generation)
            if path:
                self.notify_password_table_changed(path, bump_generation=False)
                return
            self._mark_all_password_failures_dirty()

    def notify_password_table_changed(self, path: str, *, bump_generation: bool = True) -> None:
        if bump_generation:
            self.notify_password_source_changed("directory_password_file", path)
            return
        directory = os.path.dirname(os.path.abspath(path))
        with self._lock:
            self._password_dirty_dirs[directory] = time.monotonic()
        self._wake_service()

    def notify_path_departed(self, path: str, *, recursive: bool = False) -> None:
        normalized = os.path.abspath(path)
        with self._lock:
            pending_paths = [
                candidate_path
                for candidate_path in self._pending
                if _paths_match(candidate_path, normalized, recursive=recursive)
            ]
            for candidate_path in pending_paths:
                self._pending.pop(candidate_path, None)
                self._active_states.pop(candidate_path, None)
            tracker_paths = [
                candidate_path
                for candidate_path in self._quiet_trackers
                if _paths_match(candidate_path, normalized, recursive=recursive)
            ]
            for candidate_path in tracker_paths:
                self._quiet_trackers.pop(candidate_path, None)
            observation_paths = [
                candidate_path
                for candidate_path in self._latest_observations
                if _paths_match(candidate_path, normalized, recursive=recursive)
            ]
            for candidate_path in observation_paths:
                self._latest_observations.pop(candidate_path, None)
        forgotten = self.state.forget_path(normalized, recursive=recursive)
        self.log.write(
            "candidate_departed",
            path=normalized,
            recursive=recursive,
            forgotten=forgotten,
            pending_removed=len(pending_paths),
        )
        if pending_paths:
            self._wake_service()

    def _wake_service(self) -> None:
        if self._wake_callback is not None:
            self._wake_callback()

    def _pop_ready(self, now: float) -> list[WatchCandidate]:
        ready: list[WatchCandidate] = []
        due: list[tuple[str, WatchCandidate, int, bool, int, int, float, float]] = []
        with self._lock:
            inflight_paths = self._inflight_path_keys_locked()
            for path, candidate in self._pending.items():
                if os.path.normcase(os.path.abspath(path)) in inflight_paths:
                    continue
                state = self._active_states[path]
                if now - state.last_event_at >= state.quiet_seconds:
                    due.append((
                        path,
                        candidate,
                        state.generation,
                        state.force,
                        state.filter_revision,
                        state.filtered_size,
                        state.filtered_mtime,
                        state.quiet_seconds,
                    ))

        for path, candidate, generation, force, filter_revision, filtered_size, filtered_mtime, quiet_seconds in due:
            refreshed = _candidate_for_event_path(path, since_usn=candidate.change_usn)
            if refreshed is None:
                self._drop_active(path, generation)
                self.state.forget_path(path)
                continue
            filter_stale = (
                filter_revision != self._filter_revision
                or filtered_size != refreshed.size
                or filtered_mtime != refreshed.mtime
            )
            if filter_stale and not self._passes_filesystem_filters(refreshed):
                self._drop_active(path, generation)
                self.state.complete_work([path])
                continue
            if _candidate_observation_changed(candidate, refreshed):
                if _candidate_content_changed(candidate, refreshed):
                    self._record_boundary_activity(path, generation, refreshed, now)
                    continue
                if not self._update_boundary_metadata(path, generation, refreshed):
                    continue
                candidate = refreshed
            if not watch_file_is_ready(path):
                self._record_boundary_activity(
                    path,
                    generation,
                    refreshed,
                    now,
                    content_changed=False,
                )
                self.log.write_throttled(
                    "candidate_busy",
                    throttle_key=os.path.normcase(os.path.abspath(path)),
                    interval_seconds=30.0,
                    path=path,
                )
                continue
            identified = refreshed
            with self._lock:
                state = self._active_states.get(path)
                if state is None or state.generation != generation:
                    continue
                self._pending.pop(path, None)
                self._active_states.pop(path, None)
            self.state.record_attempt(
                identified.path,
                identified.size,
                identified.mtime,
                identified.file_id,
                identified.change_usn,
            )
            self.log.write("candidate_quiet", path=path, generation=generation, quiet_seconds=quiet_seconds)
            ready.append(identified)
        return ready

    def _drop_active(self, path: str, generation: int) -> None:
        with self._lock:
            state = self._active_states.get(path)
            if state is None or state.generation != generation:
                return
            self._pending.pop(path, None)
            self._active_states.pop(path, None)

    def _record_boundary_activity(
        self,
        path: str,
        generation: int,
        candidate: WatchCandidate,
        now: float,
        *,
        content_changed: bool = True,
    ) -> None:
        with self._lock:
            state = self._active_states.get(path)
            if state is None or state.generation != generation:
                return
            self._pending[path] = candidate
            self._latest_observations[path] = candidate
            state.last_event_at = now
            learned_quiet_seconds = self._observe_candidate_activity(
                candidate,
                now,
                content_changed=content_changed,
                learn_interval=False,
            )
            state.quiet_seconds = min(learned_quiet_seconds, self.boundary_confirmation_seconds)
            state.generation += 1
            state.filter_revision = self._filter_revision
            state.filtered_size = candidate.size
            state.filtered_mtime = candidate.mtime

    def _update_boundary_metadata(
        self,
        path: str,
        generation: int,
        candidate: WatchCandidate,
    ) -> bool:
        with self._lock:
            state = self._active_states.get(path)
            if state is None or state.generation != generation:
                return False
            self._pending[path] = candidate
            self._latest_observations[path] = candidate
            self._observe_candidate_activity(candidate, time.time(), content_changed=False)
            state.filter_revision = self._filter_revision
            state.filtered_size = candidate.size
            state.filtered_mtime = candidate.mtime
            return True

    def _candidate_baseline_locked(self, path: str) -> WatchCandidate | None:
        normalized = os.path.abspath(path)
        return (
            self._pending.get(normalized)
            or self._pending.get(path)
            or self._latest_observations.get(normalized)
            or self._latest_observations.get(path)
        )

    def _accept_metadata_observation_locked(self, candidate: WatchCandidate, now: float) -> None:
        self._latest_observations[candidate.path] = candidate
        self.state.advance_entry_observation(candidate)
        state = self._active_states.get(candidate.path)
        if state is not None:
            self._pending[candidate.path] = candidate
            state.filter_revision = self._filter_revision
            state.filtered_size = candidate.size
            state.filtered_mtime = candidate.mtime
        self._observe_candidate_activity(candidate, now, content_changed=False)

    def _defer_group_member(
        self,
        candidate: WatchCandidate,
        snapshot: WatchGroupSnapshot,
    ) -> None:
        """Re-arm a ready split member without restarting its quiet clock.

        The candidate already passed its quiet boundary, but another member of
        the same split group is still pending (or in flight).  Re-enqueueing
        through ``enqueue()`` restarts the quiet window, so members whose
        deadlines differ by milliseconds can defer each other indefinitely.
        Instead, keep the candidate pending and align its deadline with the
        latest pending member so the whole group becomes ready in one tick and
        dispatches together.  When only in-flight members remain, fall back to
        the historical retry loop so the candidate is reconsidered after the
        request is harvested.
        """
        with self._lock:
            if candidate.path in self._pending or candidate.path in self._active_states:
                # A newer event already re-armed this path after it was popped.
                return
            member_keys = {path_key(member) for member in snapshot.owned_paths}
            own_key = path_key(candidate.path)
            pending_deadlines = [
                state.last_event_at + state.quiet_seconds
                for path, state in self._active_states.items()
                if path_key(path) in member_keys and path_key(path) != own_key
            ]
        if not pending_deadlines:
            self.enqueue(candidate.path, force=True, event_type="modified")
            return
        tracker = self._quiet_trackers.get(candidate.path)
        quiet_seconds = (
            float(tracker.quiet_seconds) if tracker is not None else self.cold_start_seconds
        )
        aligned_deadline = max(pending_deadlines)
        state = _ActiveCandidateState(
            last_event_at=aligned_deadline - quiet_seconds,
            quiet_seconds=quiet_seconds,
            filtered_size=candidate.size,
            filtered_mtime=candidate.mtime,
            filter_revision=self._filter_revision,
        )
        with self._lock:
            if candidate.path in self._pending or candidate.path in self._active_states:
                return
            self._pending[candidate.path] = candidate
            self._active_states[candidate.path] = state
            # Persist the armed attempt (the same as enqueue("modified")) so a
            # restart recovers this member for dispatch once the group is
            # ready, without keeping the in-memory force flag hot.
            self.state.queue_active(candidate, force=True)
        self._wake_service()

    def _observe_candidate_activity(
        self,
        candidate: WatchCandidate,
        now: float,
        *,
        content_changed: bool | None = None,
        learn_interval: bool = True,
    ) -> float:
        tracker = self._quiet_trackers.get(candidate.path)
        if tracker is None:
            tracker = AdaptiveQuietTracker(self._quiet_policy)
            self._quiet_trackers[candidate.path] = tracker
        return tracker.observe(
            now,
            size=candidate.size,
            mtime=candidate.mtime,
            change_usn=candidate.change_usn,
            content_changed=content_changed,
            learn_interval=learn_interval,
        )

    def _process_password_dirty_dirs(self, now: float) -> None:
        ready_dirs: list[str] = []
        with self._lock:
            for directory, changed_at in list(self._password_dirty_dirs.items()):
                if now - changed_at >= self.password_retry_debounce_seconds:
                    ready_dirs.append(directory)
                    self._password_dirty_dirs.pop(directory, None)
        for directory in ready_dirs:
            entries = self.state.failed_password_entries_under(
                directory,
                include_subtree=self.password_retry_include_subtree,
            )
            for entry in entries:
                if os.path.exists(entry.path):
                    self.log.write("retry_password_failure", path=entry.path, directory=directory)
                    self.enqueue(
                        entry.path,
                        force=True,
                        event_type="password_retry",
                        _password_retry_snapshot=entry,
                    )

    def _prepare_group_head(self, path: str) -> WatchCandidate | None:
        candidate = _candidate_for_event_path(path)
        if candidate is None or not self._passes_filesystem_filters(candidate):
            return None
        return candidate

    async def _submit_candidate(
        self,
        candidate: WatchCandidate,
        *,
        group: WatchGroupSnapshot | None = None,
    ) -> _ActivePipelineRequest | None:
        notification_id = uuid.uuid4().hex
        with self._password_source_lock:
            run_config = dict(self.config)
            self.pipeline_engine.update_password_sources(
                user_passwords=run_config.get("user_passwords", []),
                builtin_passwords=run_config.get("builtin_passwords", []),
            )
        output_root = self._output_root_for(candidate.path)
        run_config["output"] = {
            **(run_config.get("output", {}) if isinstance(run_config.get("output"), dict) else {}),
            "root": output_root,
            "common_root": self._common_root_for(candidate.path),
        }
        from sunpack.cli.runtime_state import runtime_host

        host = runtime_host()
        reservation_paths = [candidate.path, *(group.owned_paths if group is not None else ())]
        if host is not None:
            conflict = host.archive_registry.reserve(notification_id, "watch", reservation_paths)
            if conflict is not None:
                self.log.write(
                    "processing_deferred_active_owner",
                    path=candidate.path,
                    owner_origin=conflict.origin,
                    owner_paths=list(conflict.paths),
                )
                self.enqueue(candidate.path, force=True, event_type="active_owner_deferred")
                return None
        self._notify("submitted", notification_id, candidate.path)
        self.log.write("processing_started", path=candidate.path, size=candidate.size, mtime=candidate.mtime)
        try:
            task = asyncio.create_task(self.pipeline_engine.run(
                [PipelineTarget(candidate.path, output=run_config["output"])],
                progress_callback=lambda archive_task, event: self._notify(
                    "progress",
                    notification_id,
                    archive_task,
                    event,
                ),
                request_config=run_config,
                origin="watch",
            ))
        except BaseException:
            if host is not None:
                host.archive_registry.release(notification_id)
            raise
        self._reset_idle_cache_cleanup()
        task.add_done_callback(lambda _task: self._wake_service())
        return _ActivePipelineRequest(
            notification_id=notification_id,
            candidate=candidate,
            group=group,
            task=task,
            registry_owner=notification_id if host is not None else "",
        )

    async def _complete_candidate(self, request: _ActivePipelineRequest) -> WatchRunResult:
        candidate = request.candidate
        group = request.group
        response = await request.task
        summary = response.summary
        self._remember_recent_passwords(response.recent_passwords)
        target_result = _target_result_for_path(summary, candidate.path)
        outcome_kind = _summary_outcome_kind(summary, target_result)
        target_output_dir = (
            target_result.get("output_dir", "")
            if isinstance(target_result, dict)
            else getattr(target_result, "output_dir", "")
        ) if target_result is not None else ""
        generated_output_dirs = dedupe_normalized_paths([
            *response.artifacts.flatten_targets,
            *getattr(response.artifacts, "shell_refresh_paths", ()),
            *(
                str(item.get("out_dir") or "")
                for item in (getattr(summary, "recovered_outputs", []) or [])
                if isinstance(item, dict)
            ),
            str(target_output_dir or ""),
        ])

        summary_failures = list(getattr(summary, "failures", []) or [])
        target_failure = _target_result_failure(target_result)
        if target_failure is not None and target_failure not in summary_failures:
            summary_failures.append(target_failure)
        missing_volume_failures = _candidate_missing_volume_failures(
            target_result,
            summary_failures,
        )
        candidate_password_failures = _candidate_password_failures(
            target_result,
            summary_failures,
        )
        nested_missing_volume_failures = _nested_missing_volume_failures(
            target_result,
            summary_failures,
        )
        nested_password_failures = _nested_password_failures(
            target_result,
            summary_failures,
        )

        if outcome_kind == OutcomeKind.PARTIAL_SUCCESS and missing_volume_failures:
            failure_payloads = [_failure_to_dict(failure) for failure in missing_volume_failures]
            payload = {**failure_payloads[0], "blockers": [BLOCKER_MISSING_VOLUME]}
            error = str(
                getattr(missing_volume_failures[0], "message", "")
                or self.i18n.t("failure.possible_missing_volume")
            )
            if group is not None:
                self.state.record_group_suspended(
                    group,
                    blockers=[BLOCKER_MISSING_VOLUME],
                    failure_payload=payload,
                )
            self.state.mark(
                candidate.path,
                candidate.size,
                candidate.mtime,
                file_id=candidate.file_id,
                change_usn=candidate.change_usn,
                status="suspended_missing_volume",
                error=error,
                failure_payload=payload,
            )
            self.log.write(
                "suspended_missing_volume",
                path=candidate.path,
                error=error,
                failures=failure_payloads,
                partial_recovery=True,
            )
            self._notify("suppressed", request.notification_id)
            return WatchRunResult(processed=1, failed=1, errors=[error])

        if outcome_kind == OutcomeKind.PARTIAL_SUCCESS:
            nested_reasons = _nested_failure_reasons(
                nested_password_failures,
                nested_missing_volume_failures,
            )
            if nested_reasons:
                failed = list(summary.failed_tasks)
                nested_failures = _nested_related_failures(
                    nested_password_failures,
                    nested_missing_volume_failures,
                )
                primary_failure = nested_failures[0] if nested_failures else None
                raw_error = failed[0] if failed else ""
                error = _nested_failure_error(
                    nested_reasons[0],
                    primary_failure,
                    fallback=raw_error,
                    i18n=self.i18n,
                )
                failure_payloads = [_failure_to_dict(failure) for failure in nested_failures]
                blockers = [BLOCKER_PASSWORD] if "password" in nested_reasons else []
                status = (
                    "failed_password"
                    if blockers
                    else "failed_nested_missing_volume"
                )
                payload = _add_nested_failure_details(
                    {
                        **(failure_payloads[0] if failure_payloads else {}),
                        "blockers": list(blockers),
                    },
                    nested_reasons,
                )
                if failure_payloads:
                    failure_payloads[0] = payload
                if group is not None:
                    if blockers:
                        self.state.record_group_suspended(
                            group,
                            blockers=blockers,
                            failure_payload=payload,
                        )
                    else:
                        self.state.record_group_terminal(group, status=status, failure_payload=payload)
                self.state.mark(
                    candidate.path,
                    candidate.size,
                    candidate.mtime,
                    file_id=candidate.file_id,
                    change_usn=candidate.change_usn,
                    status=status,
                    error=error,
                    failure_payload=payload,
                )
                self.log.write(
                    status,
                    path=candidate.path,
                    error=error,
                    failures=failure_payloads,
                )
                self._notify("failed", request.notification_id, [error], failure_payloads)
                return WatchRunResult(processed=1, failed=1, errors=[error])

            error = self.i18n.t("watch.failure.partial_rejected")
            if group is not None:
                self.state.record_group_terminal(group, status="failed")
            self.state.mark(
                candidate.path,
                candidate.size,
                candidate.mtime,
                file_id=candidate.file_id,
                change_usn=candidate.change_usn,
                status="failed",
                error=error,
            )
            self.log.write(
                "partial_rejected",
                path=candidate.path,
                error=error,
            )
            self._notify("failed", request.notification_id, [error], [])
            return WatchRunResult(processed=1, failed=1, errors=[error])

        failed = list(summary.failed_tasks)
        if failed:
            error = failed[0] if failed else self.i18n.t("watch.failure.extraction_failed")
            failures = summary_failures
            failure_payloads = [_failure_to_dict(failure) for failure in failures]
            is_password_failure = bool(
                candidate_password_failures or nested_password_failures
            )
            is_missing_volume = bool(missing_volume_failures)
            nested_reasons = _nested_failure_reasons(
                nested_password_failures,
                nested_missing_volume_failures,
            )
            nested_notification = bool(nested_reasons) and not (
                candidate_password_failures or missing_volume_failures
            )
            blockers = []
            if is_missing_volume:
                blockers.append(BLOCKER_MISSING_VOLUME)
            if is_password_failure:
                blockers.append(BLOCKER_PASSWORD)
            status = (
                "failed_password"
                if is_password_failure
                else "suspended_missing_volume"
                if is_missing_volume
                else "failed_nested_missing_volume"
                if "missing_volume" in nested_reasons
                else "failed_terminal"
            )
            if nested_notification:
                error = _nested_failure_error(
                    nested_reasons[0],
                    _nested_related_failures(
                        nested_password_failures,
                        nested_missing_volume_failures,
                    )[0],
                    fallback=error,
                    i18n=self.i18n,
                )
            primary_failures = (
                candidate_password_failures
                or missing_volume_failures
                or nested_password_failures
                or nested_missing_volume_failures
                or failures
            )
            primary_payload = _failure_to_dict(primary_failures[0]) if primary_failures else {}
            payload = _add_nested_failure_details(
                {**primary_payload, "blockers": list(blockers)},
                nested_reasons,
            )
            if nested_reasons:
                primary_raw_payload = _failure_to_dict(primary_failures[0]) if primary_failures else {}
                for index, failure_payload in enumerate(failure_payloads):
                    if failure_payload == primary_raw_payload:
                        failure_payloads[index] = payload
                        break
                else:
                    failure_payloads.insert(0, payload)
            if group is not None:
                if blockers:
                    self.state.record_group_suspended(group, blockers=blockers, failure_payload=payload)
                else:
                    self.state.record_group_terminal(group, status=status, failure_payload=payload)
            self.state.mark(
                candidate.path,
                candidate.size,
                candidate.mtime,
                file_id=candidate.file_id,
                change_usn=candidate.change_usn,
                status=status,
                error=error,
                failure_payload=payload,
            )
            self.log.write(status, path=candidate.path, error=error, failures=failure_payloads)
            if blockers and not nested_notification:
                self._notify("suppressed", request.notification_id)
            else:
                self._notify(
                    "failed",
                    request.notification_id,
                    [error] if nested_notification else failed,
                    failure_payloads,
                )
            return WatchRunResult(
                processed=1,
                failed=1,
                errors=[error] if nested_notification else failed,
            )
        if _summary_processed_no_tasks(summary):
            if group is not None:
                self.state.record_group_terminal(group, status="ignored_no_tasks")
            self.state.mark(
                candidate.path,
                candidate.size,
                candidate.mtime,
                file_id=candidate.file_id,
                change_usn=candidate.change_usn,
                status="ignored_no_tasks",
            )
            self.log.write("no_tasks_found", path=candidate.path)
            self._notify("suppressed", request.notification_id)
            return WatchRunResult(processed=1)
        if outcome_kind != OutcomeKind.COMPLETE_SUCCESS:
            error = self.i18n.t("watch.failure.no_complete_outcome")
            if group is not None:
                self.state.record_group_terminal(group, status="failed_terminal")
            self.log.write("failed_terminal", path=candidate.path, error=error, failures=[])
            self._notify("failed", request.notification_id, [error], [])
            return WatchRunResult(processed=1, failed=1, errors=[error])

        if group is not None:
            completed_group = self._current_group_snapshot(group, candidate.path)
            if completed_group is None:
                self.state.clear_group(group.group_id)
            else:
                self.state.record_group_done(completed_group)
        self.state.mark(
            candidate.path,
            candidate.size,
            candidate.mtime,
            file_id=candidate.file_id,
            change_usn=candidate.change_usn,
            status="done",
        )
        self.log.write("done", path=candidate.path, success_count=summary.success_count, output_dirs=generated_output_dirs)
        cleanup_failed = [item for item in response.summary.cleanup_results if item.status == "failed"]
        self.log.write("cleanup", path=candidate.path,
                       results=[{"path": item.path, "status": item.status, "attempts": item.attempts,
                                 "error_code": item.error_code, "message": item.message}
                                for item in response.summary.cleanup_results],
                       retry_count=sum(max(0, item.attempts - 1) for item in response.summary.cleanup_results))
        if cleanup_failed:
            self._notify("succeeded", request.notification_id, generated_output_dirs,
                         [self.i18n.t("cleanup.incomplete", count=len(cleanup_failed))])
        else:
            self._notify("succeeded", request.notification_id, generated_output_dirs)
        return WatchRunResult(processed=1, succeeded=summary.success_count)

    def _notify(self, action: str, *args) -> None:
        try:
            getattr(self.notification_sink, action)(*args)
        except Exception as exc:
            if action not in self._notification_error_actions:
                self._notification_error_actions.add(action)
                self.log.write(
                    "notification_sink_error",
                    action=action,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )

    def _current_group_snapshot(
        self,
        submitted: WatchGroupSnapshot,
        candidate_path: str,
    ) -> WatchGroupSnapshot | None:
        """Return the still-present group only when it is the submitted input."""

        resolved = self.group_coordinator.resolve_paths([candidate_path])
        current = resolved.get(path_key(candidate_path))
        if (
            current is not None
            and current.group_id == submitted.group_id
            and current.input_fingerprint == submitted.input_fingerprint
        ):
            return current
        return None

    def _common_root_for(self, path: str) -> str:
        path = os.path.abspath(path)
        matched = _longest_matching_root(path, self.watch_roots)
        if matched and os.path.isdir(matched):
            return matched
        if matched and os.path.isfile(matched):
            return os.path.dirname(matched)
        return os.path.dirname(path)

    def _output_root_for(self, path: str) -> str:
        matched_root = _longest_matching_root(os.path.abspath(path), self.watch_roots)
        if matched_root is None:
            # Only reachable for a path outside every watch root, which enqueue already rejects.
            return self._common_root_for(path)
        return self.output_roots[path_key(matched_root)]

    def _is_under_watched_root(self, path: str) -> bool:
        normalized = os.path.normcase(os.path.abspath(path))
        for root in self.watch_roots:
            normalized_root = os.path.normcase(os.path.abspath(root))
            if os.path.isdir(root):
                if os.path.normcase(os.path.dirname(normalized)) == normalized_root:
                    return True
            elif normalized == normalized_root:
                return True
        return False

    def _is_under_metadata_dir(self, path: str) -> bool:
        normalized = os.path.abspath(path)
        if normalized in self.metadata_files:
            return True
        return bool(self.metadata_dir and _is_relative_to(normalized, self.metadata_dir))

    def _passes_filesystem_filters(self, candidate: WatchCandidate) -> bool:
        if not self.filters:
            return True
        entry = _file_entry_from_watch_candidate(candidate)
        if apply_ordered_filters_to_entries([entry], self.filters):
            return True
        if not rejected_only_by_size_range(entry, self.filters):
            return False
        if not split_size_family_keys(candidate.path):
            return False
        snapshot = self.group_coordinator.resolve_paths([candidate.path]).get(path_key(candidate.path))
        if snapshot is None or not snapshot.head_path:
            return False
        member_keys = {path_key(path) for path in snapshot.input_paths}
        return path_key(candidate.path) in member_keys

    def _refresh_password_sources(self) -> str:
        with self._password_source_lock:
            builtin_passwords = dedupe_passwords([*self._configured_builtin_passwords, *get_builtin_passwords()])
            user_passwords = dedupe_passwords([*self._recent_passwords, *self._configured_user_passwords])
            signature = _password_source_signature(
                self._configured_user_passwords,
                builtin_passwords,
            )
            self.config["user_passwords"] = user_passwords
            self.config["builtin_passwords"] = builtin_passwords
        return signature

    def _sync_group_coordinator_passwords(self) -> None:
        refresh = getattr(self.group_coordinator, "refresh_password_sources", None)
        if callable(refresh):
            refresh()

    def _remember_recent_passwords(self, passwords: Iterable[str] | None) -> None:
        incoming = dedupe_passwords([str(value) for value in list(passwords or []) if str(value)])
        with self._password_source_lock:
            updated = dedupe_passwords([*incoming, *self._recent_passwords])
            updated = updated[:MAX_RECENT_PASSWORDS]
            if updated == self._recent_passwords:
                return
            self._recent_passwords = updated
        self.notify_password_source_changed("recent_password")

    def _mark_all_password_failures_dirty(self) -> None:
        now = time.monotonic()
        marked = False
        entries = self.state.entry_items()
        with self._lock:
            for entry in entries:
                if entry.status == "failed_password":
                    self._password_dirty_dirs[os.path.dirname(entry.path)] = now
                    marked = True
        if marked:
            self._wake_service()


class _WatchEventHandler(FileSystemEventHandler):
    def __init__(self, scheduler: WatchScheduler):
        self.scheduler = scheduler

    def on_created(self, event: FileSystemEvent):
        self._handle(event, "created")

    def on_modified(self, event: FileSystemEvent):
        self._handle(event, "modified")

    def on_deleted(self, event: FileSystemEvent):
        self._handle_departure(event)

    def on_moved(self, event: FileSystemEvent):
        src_path = getattr(event, "src_path", "")
        is_directory = bool(getattr(event, "is_directory", False))
        if src_path:
            self._handle_departure_path(
                src_path,
                is_directory=is_directory,
            )
        if is_directory:
            return
        dest_path = getattr(event, "dest_path", "")
        if dest_path:
            self._handle_path(dest_path, event_type="moved", src_path=src_path)

    def _handle_departure(self, event: FileSystemEvent) -> None:
        src_path = getattr(event, "src_path", "")
        if src_path:
            self._handle_departure_path(
                src_path,
                is_directory=bool(getattr(event, "is_directory", False)),
            )

    def _handle_departure_path(self, path: str, *, is_directory: bool) -> None:
        if self.scheduler.is_builtin_password_file(path):
            self.scheduler.notify_password_source_changed("builtin_password_file", path="")
            return
        if is_directory_password_file(path, self.scheduler.config):
            self.scheduler.notify_password_table_changed(path)
            return
        self.scheduler.notify_path_departed(path, recursive=is_directory)

    def _handle(self, event: FileSystemEvent, event_type: str):
        if getattr(event, "is_directory", False):
            return
        src_path = getattr(event, "src_path", "")
        if src_path:
            self._handle_path(src_path, event_type=event_type)

    def _handle_path(self, path: str, *, event_type: str = "unknown", src_path: str = ""):
        if self.scheduler.is_builtin_password_file(path):
            self.scheduler.notify_password_source_changed("builtin_password_file", path="")
            return
        if self.scheduler.should_ignore_event_path(path):
            return
        if is_directory_password_file(path, self.scheduler.config):
            self.scheduler.notify_password_table_changed(path)
            return
        try:
            self.scheduler.enqueue(path, event_type=event_type, src_path=src_path)
        except OSError as exc:
            # File observations race with renames, deletion, and the native
            # promotion gate.  A single transient miss must not escape the
            # watchdog callback and terminate its dispatcher thread; a later
            # event or the active pipeline request will reconcile the path.
            self.scheduler._log_candidate_ignored(
                path,
                "observation_error",
                event_type=event_type,
                src_path=src_path,
                error=f"{type(exc).__name__}: {exc}",
            )


def _candidate_for_event_path(path: str, *, since_usn: int = 0) -> WatchCandidate | None:
    if not path:
        return None
    return _watch_candidate_for_path(path, since_usn=since_usn)


def _candidate_observation_changed(previous: WatchCandidate, current: WatchCandidate) -> bool:
    return (
        previous.size != current.size
        or previous.mtime != current.mtime
        or previous.file_id != current.file_id
        or previous.change_usn != current.change_usn
    )


def _candidate_matches_password_failure(candidate: WatchCandidate, entry: WatchStateEntry) -> bool:
    return (
        os.path.normcase(os.path.abspath(candidate.path)) == os.path.normcase(os.path.abspath(entry.path))
        and candidate.size == entry.size
        and candidate.mtime == entry.mtime
        and candidate.file_id == entry.file_id
        and candidate.change_usn == entry.change_usn
    )


def _candidate_change_kind(
    previous: WatchCandidate | None,
    current: WatchCandidate,
) -> _CandidateChangeKind:
    if previous is None:
        return _CandidateChangeKind.CONTENT_CHANGED
    if not _candidate_observation_changed(previous, current):
        return _CandidateChangeKind.UNCHANGED
    if previous.file_id != current.file_id or previous.size != current.size:
        return _CandidateChangeKind.CONTENT_CHANGED
    if previous.change_usn == current.change_usn:
        return _CandidateChangeKind.METADATA_ONLY
    if current.change_reasons_known:
        if current.change_reasons_without_close & USN_CONTENT_REASON_MASK:
            return _CandidateChangeKind.CONTENT_CHANGED
        return _CandidateChangeKind.METADATA_ONLY
    # Explorer and downloaders commonly restore the source/server timestamp as
    # their final metadata operation. If volume-journal access is unavailable,
    # optimistically ignore that one event; later same-size overwrites still
    # change the USN and take the conservative content-change path below.
    if current.mtime < previous.mtime - RESTORED_MTIME_MINIMUM_BACKSTEP_SECONDS:
        return _CandidateChangeKind.METADATA_ONLY
    return _CandidateChangeKind.CONTENT_CHANGED


def _candidate_content_changed(previous: WatchCandidate, current: WatchCandidate) -> bool:
    return _candidate_change_kind(previous, current) == _CandidateChangeKind.CONTENT_CHANGED


def _candidate_from_state_entry(entry: WatchStateEntry | None) -> WatchCandidate | None:
    if entry is None:
        return None
    return WatchCandidate(
        path=entry.path,
        size=entry.size,
        mtime=entry.mtime,
        file_id=entry.file_id,
        change_usn=entry.change_usn,
    )


def _file_entry_from_watch_candidate(candidate: WatchCandidate) -> FileEntry:
    path = Path(candidate.path)
    return FileEntry(
        path=path,
        is_dir=False,
        size=int(candidate.size),
        mtime_ns=int(candidate.mtime * 1_000_000_000),
    )

def _longest_matching_root(path: str, roots: list[str]) -> str | None:
    matches = [root for root in roots if _is_relative_to(path, root)]
    if not matches:
        return None
    return max(matches, key=len)


def _is_relative_to(path: str, root: str) -> bool:
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def _paths_match(path: str, expected: str, *, recursive: bool) -> bool:
    normalized = os.path.abspath(path)
    expected = os.path.abspath(expected)
    return os.path.normcase(normalized) == os.path.normcase(expected) or (
        recursive and _is_relative_to(normalized, expected)
    )


def _target_result_for_path(summary, path: str):
    expected = os.path.normcase(os.path.abspath(path))
    for item in list(getattr(summary, "target_results", []) or []):
        raw_path = item.get("input_path", "") if isinstance(item, dict) else getattr(item, "input_path", "")
        if raw_path and os.path.normcase(os.path.abspath(str(raw_path))) == expected:
            return item
    return None


def _summary_outcome_kind(summary, target_result) -> OutcomeKind:
    raw = (
        target_result.get("outcome_kind")
        if isinstance(target_result, dict)
        else getattr(target_result, "outcome_kind", None)
    ) if target_result is not None else None
    if isinstance(raw, OutcomeKind):
        return raw
    if raw:
        try:
            return OutcomeKind(str(raw))
        except ValueError:
            pass
    if int(getattr(summary, "partial_success_count", 0) or 0) > 0:
        return OutcomeKind.PARTIAL_SUCCESS
    if int(getattr(summary, "success_count", 0) or 0) > 0:
        return OutcomeKind.COMPLETE_SUCCESS
    return OutcomeKind.FAILURE


def _password_source_signature(
    user_passwords: list[str],
    builtin_passwords: list[str],
) -> str:
    payload = json.dumps(
        [user_passwords, builtin_passwords],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _failure_to_dict(failure) -> dict:
    if isinstance(failure, dict):
        return dict(failure)
    if hasattr(failure, "to_dict"):
        try:
            return failure.to_dict()
        except Exception:
            return {}
    return {}


def _failure_contains(failure, kind: FailureKind) -> bool:
    if isinstance(failure, dict):
        raw_kind = failure.get("kind")
        if raw_kind in {kind, kind.value, str(kind)}:
            return True
        return any(
            _failure_contains(cause, kind)
            for cause in (failure.get("causes") or [])
        )
    contains = getattr(failure, "contains", None)
    if callable(contains):
        try:
            return bool(contains(kind))
        except Exception:
            pass
    return getattr(failure, "kind", None) == kind


def _failure_is_password(failure) -> bool:
    if isinstance(failure, dict):
        raw_kind = failure.get("kind")
        try:
            if FailureKind(str(raw_kind)) in PASSWORD_FAILURE_KINDS:
                return True
        except (TypeError, ValueError):
            pass
        return any(_failure_is_password(cause) for cause in (failure.get("causes") or []))
    return bool(getattr(failure, "is_password_failure", False))


def _target_result_failure(target_result):
    if isinstance(target_result, dict):
        return target_result.get("failure")
    return getattr(target_result, "failure", None) if target_result is not None else None


def _candidate_failures(target_result, failures, predicate) -> list:
    """Return failures owned by the watched candidate itself."""
    target_failure = _target_result_failure(target_result)
    if target_result is None:
        return [failure for failure in failures if predicate(failure)]
    if target_failure is not None and predicate(target_failure):
        return [target_failure]
    return []


def _nested_failures(target_result, failures, predicate) -> list:
    """Return failures owned by recursively extracted child archives."""
    if target_result is None:
        return []
    if _candidate_failures(target_result, failures, predicate):
        return []
    return [failure for failure in failures if predicate(failure)]


def _candidate_missing_volume_failures(target_result, failures) -> list:
    """Return missing-volume failures owned by the watched candidate.

    A pipeline response may contain failures from recursively extracted child
    archives.  Those failures must not turn the parent archive into a split
    volume watch blocker.  Real responses carry a TargetRunResult for every
    archive, so use the current candidate's direct failure there.  The
    target-result-free fallback keeps lightweight scheduler fakes compatible.
    """
    return _candidate_failures(
        target_result,
        failures,
        lambda failure: _failure_contains(failure, FailureKind.MISSING_VOLUME),
    )


def _candidate_password_failures(target_result, failures) -> list:
    return _candidate_failures(target_result, failures, _failure_is_password)


def _nested_missing_volume_failures(target_result, failures) -> list:
    """Return missing-volume failures that belong to a recursively extracted child."""
    return _nested_failures(
        target_result,
        failures,
        lambda failure: _failure_contains(failure, FailureKind.MISSING_VOLUME),
    )


def _nested_password_failures(target_result, failures) -> list:
    return _nested_failures(target_result, failures, _failure_is_password)


def _nested_failure_reasons(password_failures, missing_volume_failures) -> list[str]:
    reasons = []
    if password_failures:
        reasons.append("password")
    if missing_volume_failures:
        reasons.append(FailureKind.MISSING_VOLUME.value)
    return reasons


def _nested_related_failures(password_failures, missing_volume_failures) -> list:
    return [*password_failures, *missing_volume_failures]


def _nested_failure_error(
    reason: str,
    failure,
    *,
    fallback: str = "",
    i18n: I18nContext | None = None,
) -> str:
    i18n = i18n or I18nContext()
    if fallback:
        message = fallback
    elif isinstance(failure, dict):
        message = failure.get("message") or ""
    else:
        message = getattr(failure, "message", "") if failure is not None else ""
    message = str(message or i18n.t("watch.failure.unknown_nested"))
    key = "watch.failure.nested_password" if reason == "password" else "watch.failure.nested_missing_volume"
    return i18n.t(key, message=message)


def _add_nested_failure_details(payload: dict, reasons: list[str]) -> dict:
    if not reasons:
        return payload
    details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
    details = {
        **details,
        "scope": "nested_archive",
        "reason": reasons[0],
    }
    if len(reasons) > 1:
        details["reasons"] = list(reasons)
    return {**payload, "details": details}


def _summary_processed_no_tasks(summary) -> bool:
    return (
        int(getattr(summary, "success_count", 0) or 0) <= 0
        and not list(getattr(summary, "failed_tasks", []) or [])
        and not list(getattr(summary, "processed_keys", []) or [])
        and not list(getattr(summary, "recovered_outputs", []) or [])
    )
