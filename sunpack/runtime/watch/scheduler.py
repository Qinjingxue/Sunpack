from __future__ import annotations

import asyncio
import heapq
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Iterable

from sunpack_native import fast_hash128

from sunpack.core.config.fields.watch import DEFAULT_WATCH_CONFIG
from sunpack.core.config.detection_view import discovery_run_config
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.retry_targets import (
    failure_contains,
    failure_is_password,
    result_error,
    result_failure,
    result_outcome,
    result_path,
    target_results,
)
from sunpack.core.contracts.results import OutcomeKind, RunSummary, TargetRunResult
from sunpack.core.contracts.pipeline import PipelineResponse, PipelineTarget
from sunpack.runtime.watch.log import WatchLogStore
from sunpack.runtime.watch.quiet_policy import AdaptiveQuietPolicy, AdaptiveQuietTracker
from sunpack.runtime.watch.scanner import (
    WatchCandidate,
    scan_watch_candidates,
    validate_ntfs_watch_roots,
    watch_file_is_ready,
    watch_root_changes,
    watch_volume_cursor,
)
from sunpack.runtime.watch.scanner import _candidate_for as _watch_candidate_for_path
from sunpack.runtime.watch.state import WatchStateEntry, WatchStateStore
from sunpack.runtime.watch.roots import WatchRootEntry
from sunpack.runtime.watch.toast import NullWatchNotificationSink
from sunpack.core.i18n import I18nContext
from sunpack.core.passwords.internal import builtin as builtin_passwords_module
from sunpack.core.passwords.internal.builtin import get_builtin_passwords
from sunpack.core.passwords.internal.clipboard_monitor import ClipboardPasswordMonitor
from sunpack.core.passwords.internal.lists import dedupe_passwords
from sunpack.core.passwords.internal.local_files import (
    DIRECTORY_PASSWORD_FILE_NAME,
    discover_directory_passwords_for_archive,
    is_directory_password_file,
)
from sunpack.core.passwords.internal.store import MAX_RECENT_PASSWORDS
from sunpack.core.support.path_keys import path_key
from sunpack.core.support.collections import dedupe_normalized_paths
from sunpack.core.support.resource_lifecycle import (
    ResourceKind,
    lifecycle_registration,
    open_service_file,
    register_service_resource,
)
from sunpack.pipeline.postprocess.output_cleanup import (
    DEFAULT_OUTPUT_CLEANUP_MANAGER,
    OutputCleanupEvent,
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
BLOCKER_MISSING_VOLUME = "missing_volume"
BLOCKER_PASSWORD = "password"


class _CandidateChangeKind(Enum):
    UNCHANGED = auto()
    METADATA_ONLY = auto()
    CONTENT_CHANGED = auto()


@dataclass(slots=True)
class _CandidateObservation:
    """Only the facts needed to reject delayed events for a retained source."""

    size: int
    mtime: float
    file_id: str
    change_usn: int
    quiet_seconds: float = 0.0
    last_content_event_at: float | None = None


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
    generation: int = 1
    epoch: int = 0


@dataclass
class _ActivePipelineRequest:
    notification_id: str
    candidate: WatchCandidate
    task: asyncio.Task
    password_generation: int
    registry_owner: str = ""
    source_input_root: str = ""
    deep_detect: bool = False


class WatchScheduler:
    def __init__(
        self,
        config: dict,
        watch_roots: list[str],
        *,
        output_roots: dict[str, str] | None = None,
        root_entries: Iterable[WatchRootEntry] | None = None,
        out_dir: str = ".",
        state_path: str,
        cold_start_seconds: float | None = None,
        initial_scan: bool | None = None,
        initial_scan_roots: Iterable[str] | None = None,
        observer_stop_timeout_seconds: float | None = None,
        pipeline_engine=None,
        notification_sink=None,
        wake_callback: Callable[[], None] | None = None,
    ):
        self.config = config
        self.i18n = I18nContext(config["cli"]["language"])
        watch_config = config["watch"]
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
        configured_entries = {path_key(entry.input_root): entry for entry in root_entries or ()}
        self.root_entries = {
            path_key(root): WatchRootEntry(
                root,
                self.output_roots[path_key(root)],
                configured_entries[path_key(root)].deep_detect if path_key(root) in configured_entries else False,
            )
            for root in self.watch_roots
        }
        configured_cold_start = watch_config.get(
            "cold_start_seconds",
            DEFAULT_WATCH_CONFIG["cold_start_seconds"],
        )
        self.cold_start_seconds = max(
            0.0,
            float(configured_cold_start if cold_start_seconds is None else cold_start_seconds),
        )
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
        self.state = WatchStateStore(state_path)
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
        # Serializes Watch file-observation admission with pipeline source-claim
        # publication. The lock is held only across short candidate/readiness
        # probes, so a claim is a true linearization point: an observation is
        # either fully admitted before the claim or cannot touch the source.
        self._claim_gate = threading.RLock()
        self._active_claims: dict[str, str] = {}
        self._claims_by_owner: dict[str, set[str]] = {}
        self._dirty_during_claim: dict[str, dict[str, str]] = {}
        self._password_source_lock = threading.RLock()
        self._pending: dict[str, WatchCandidate] = {}
        # All pending mutations use the helpers below under _lock. Keep every
        # spelling of a path so a normalized source claim retires all aliases.
        self._pending_by_key: dict[str, set[str]] = {}
        self._inflight_requests: list[_ActivePipelineRequest] = []
        self._inflight_path_counts: dict[str, int] = {}
        self._completion_batches: set[asyncio.Future] = set()
        self._active_states: dict[str, _ActiveCandidateState] = {}
        self._active_epoch = 0
        # Incremental ready index. Entries are invalidated lazily by active
        # lifecycle epoch + generation, avoiding heap delete/search.
        self._ready_heap: list[tuple[float, int, int, str, str]] = []
        self._latest_observations: dict[str, _CandidateObservation] = {}
        self._quiet_trackers: dict[str, AdaptiveQuietTracker] = {}
        self._closed = False
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
        self._runtime_cache_gate = asyncio.Lock()
        self._external_activity_gate_held = False
        self._external_activity_gate_acquiring = False
        self._external_activity_requested = False
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
        self.directory_password_file_auto_create = bool(watch_config["directory_password_file_auto_create"])
        self._configured_user_passwords = dedupe_passwords(list(config.get("user_passwords") or []))
        self._configured_builtin_passwords = dedupe_passwords(list(config.get("builtin_passwords") or []))
        self.builtin_password_file = os.path.abspath(str(builtin_passwords_module.builtin_password_path()))
        self._recent_passwords: list[str] = []
        self._password_source_signature = self._refresh_password_sources()
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
        if self._closed:
            raise RuntimeError("Watch scheduler is closed")
        if self._started:
            return
        self._ensure_directory_password_files()
        self._prepare_usn_startup_baseline()
        removed_entries = self.state.prune_missing_records()
        if removed_entries:
            self.log.write(
                "state_pruned_on_start",
                entries=removed_entries,
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
        self._recover_persisted_work()
        self._reconcile_persisted_blockers()
        self._recover_usn_startup_gap()
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

    def _watch_root_directory(self, root: str) -> str:
        root = os.path.abspath(root)
        return root if os.path.isdir(root) else os.path.dirname(root)

    def _prepare_usn_startup_baseline(self) -> None:
        """Durably establish first-run cursors before the observer can miss a gap."""
        missing: dict[str, dict[str, int]] = {}
        for root in self.watch_roots:
            directory = self._watch_root_directory(root)
            try:
                volume, journal_id, next_usn = watch_volume_cursor(directory)
            except Exception as exc:
                self.log.write("usn_cursor_unavailable", root=root, error=str(exc))
                continue
            if self.state.watch_cursor(volume) is None:
                missing[volume] = {"journal_id": journal_id, "next_usn": next_usn}
        if missing:
            self.state.merge_watch_cursors(missing, durable=True)

    def _recover_usn_startup_gap(self) -> None:
        """Replay only NTFS changes since the durable cursor; never poll."""
        cursor_updates: dict[str, dict[str, int]] = {}
        changed_paths: dict[str, str] = {}
        fallback_roots: set[str] = set()
        for root in self.watch_roots:
            directory = self._watch_root_directory(root)
            try:
                volume, journal_id, end_usn = watch_volume_cursor(directory)
                saved = self.state.watch_cursor(volume)
                if (
                    saved is None
                    or int(saved.get("journal_id", 0) or 0) != journal_id
                    or int(saved.get("next_usn", 0) or 0) > end_usn
                ):
                    fallback_roots.add(root)
                else:
                    start_usn = int(saved.get("next_usn", 0) or 0)
                    if end_usn > start_usn:
                        for path in watch_root_changes(directory, start_usn, end_usn):
                            absolute = os.path.abspath(path)
                            if os.path.isfile(root) and path_key(absolute) != path_key(root):
                                continue
                            changed_paths.setdefault(path_key(absolute), absolute)
                cursor_updates[volume] = {
                    "journal_id": journal_id,
                    "next_usn": end_usn,
                }
            except Exception as exc:
                fallback_roots.add(root)
                self.log.write("usn_recovery_fallback", root=root, error=str(exc))

        for root in sorted(fallback_roots):
            try:
                for candidate in scan_watch_candidates([root], recursive=False):
                    changed_paths.setdefault(path_key(candidate.path), candidate.path)
            except OSError as exc:
                self.log.write("usn_fallback_scan_failed", root=root, error=str(exc))

        for path in changed_paths.values():
            if _persisted_blocker_owns_retry(self.state, path):
                continue
            self.enqueue(path, force=True, event_type="startup_usn_recovery")

        with self._lock:
            recovered_candidates = list(self._pending.values())
        # Candidate owners and cursor advancement are one durable transaction.
        # A crash observes either the old cursor or every replay candidate.
        if cursor_updates:
            self.state.queue_recovery_batch(
                recovered_candidates,
                cursor_updates,
            )
        self.log.write(
            "usn_startup_recovered",
            changed=len(changed_paths),
            queued=len(recovered_candidates),
            fallback_roots=sorted(fallback_roots),
        )

    def _recover_persisted_work(self) -> None:
        """Recover only durable in-flight work; never scan unrelated Watch roots."""

        for pending in self.state.pending_work_items():
            active_outputs = dict(getattr(pending, "active_outputs", {}) or {})
            committed_roots = list(getattr(pending, "committed_roots", []) or [])
            completed_sources = {
                path_key(path)
                for path in list(getattr(pending, "completed_sources", []) or [])
                if path
            }
            scope_dir = str(getattr(pending, "password_scope_dir", "") or "")
            internal = bool(getattr(pending, "internal_recovery", False))
            if not active_outputs and not committed_roots:
                if os.path.exists(pending.path):
                    self.enqueue(
                        pending.path,
                        force=pending.force,
                        event_type="recovery",
                        _crash_recovery=internal,
                        _recovery_scope_dir=scope_dir,
                        _state_prequeued=True,
                    )
                else:
                    self.state.forget_path(pending.path)
                continue

            cleanup_failed = False
            for output_dir in dict.fromkeys(active_outputs.values()):
                result = DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_canonical(
                    output_dir,
                    event=OutputCleanupEvent.EXTRACTION_ABORT,
                    planned_output_dir=output_dir,
                )
                self.log.write(
                    "crash_output_cleanup",
                    owner_path=pending.path,
                    output_dir=output_dir,
                    cleaned=result.cleaned,
                    already_absent=result.already_absent,
                    reason=result.reason,
                    error=result.error,
                )
                if not (result.cleaned or result.already_absent):
                    cleanup_failed = True
            if cleanup_failed:
                # Keep the durable owner record. A later process start can retry
                # cleanup without ever writing into an unknown half-output.
                continue

            recovered: dict[str, WatchCandidate] = {}
            for task_path in active_outputs:
                if path_key(task_path) in completed_sources:
                    continue
                candidate = _candidate_for_event_path(task_path)
                if (
                    candidate is not None
                    and not _persisted_blocker_owns_retry(self.state, candidate.path)
                ):
                    recovered.setdefault(path_key(candidate.path), candidate)

            missing_committed_roots = [
                root for root in committed_roots if not os.path.isdir(root)
            ]
            if missing_committed_roots:
                candidate = _candidate_for_event_path(pending.path)
                if (
                    candidate is None
                    or _persisted_blocker_owns_retry(self.state, candidate.path)
                ):
                    self.log.write(
                        "crash_committed_output_missing",
                        owner_path=pending.path,
                        output_dirs=missing_committed_roots,
                    )
                    # The durable state says verified output existed, but neither
                    # that output nor a source that can rebuild it is available.
                    # Keep the owner record instead of silently retiring it.
                    continue
                recovered.setdefault(path_key(candidate.path), candidate)
                self.log.write(
                    "crash_committed_output_requeued",
                    owner_path=pending.path,
                    output_dirs=missing_committed_roots,
                )

            scan_failed = False
            for root in committed_roots:
                if not os.path.isdir(root):
                    continue
                try:
                    candidates = scan_watch_candidates([root], recursive=True)
                except OSError as exc:
                    self.log.write(
                        "crash_resume_scan_failed",
                        owner_path=pending.path,
                        root=root,
                        error=str(exc),
                    )
                    scan_failed = True
                    break
                for candidate in candidates:
                    if path_key(candidate.path) in completed_sources:
                        continue
                    if _persisted_blocker_owns_retry(self.state, candidate.path):
                        continue
                    recovered.setdefault(path_key(candidate.path), candidate)
            if scan_failed:
                continue

            if active_outputs and not recovered and not committed_roots:
                self.log.write(
                    "crash_recovery_source_missing",
                    owner_path=pending.path,
                    task_paths=list(active_outputs),
                )
                continue

            candidates = list(recovered.values())
            # Atomically replace the old owner with concrete recovery candidates
            # before rebuilding the in-memory queue. A second crash between the
            # two steps therefore restarts from the new durable candidates.
            self.state.rebase_pending_work(
                pending.path,
                candidates,
                password_scope_dir=scope_dir,
                source_input_root=pending.source_input_root,
            )
            for candidate in candidates:
                self.enqueue(
                    candidate.path,
                    force=True,
                    event_type="crash_recovery",
                    _crash_recovery=True,
                    _recovery_scope_dir=scope_dir,
                    _state_prequeued=True,
                )

    def _reconcile_persisted_blockers(self) -> None:
        """Re-evaluate only persisted blockers once at startup; no polling."""

        for entry in self.state.entry_items():
            if not os.path.exists(entry.path):
                continue
            if entry.status == "failed_password":
                payload = entry.failure_payload if isinstance(entry.failure_payload, dict) else {}
                previous = str(payload.get("password_scope_signature") or "")
                current = _directory_password_signature(entry.password_scope_dir, self.config)
                if entry.password_generation < self.state.password_generation or previous != current:
                    self.enqueue(
                        entry.path,
                        force=True,
                        event_type="startup_password_reconcile",
                        _password_retry_snapshot=entry,
                    )
                continue
            if entry.status == "suspended_missing_volume":
                # Re-submit the observed physical file through the full pipeline.
                # Relations may now discover additional volumes that arrived
                # while Watch was offline.
                self.enqueue(
                    entry.path,
                    force=True,
                    event_type="startup_missing_volume_reconcile",
                )

    def _ensure_directory_password_files(self) -> None:
        if not self.directory_password_file_auto_create:
            return
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
                if self._completion_batches:
                    await asyncio.gather(*tuple(self._completion_batches), return_exceptions=True)
                    continue
                return result
            await asyncio.gather(*(request.task for request in active), return_exceptions=True)
            self._merge_run_result(result, await self._harvest_completed_requests())

    async def aclose(self) -> None:
        async def close() -> None:
            try:
                await self.stop()
            finally:
                try:
                    await self.drain()
                finally:
                    await self.pipeline_engine.work_broker.run(
                        "watch_close", "watch", self._close_blocking,
                        request_id="watch", origin="watch",
                    )

        task = asyncio.create_task(close())
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            await task
            raise

    def _close_blocking(self) -> None:
        with self._claim_gate, self._lock:
            self._closed = True
        try:
            self.state.close()
        finally:
            with self._claim_gate, self._lock:
                self._pending.clear()
                self._pending_by_key.clear()
                self._active_states.clear()
                self._ready_heap.clear()
                self._quiet_trackers.clear()
                self._latest_observations.clear()
                self._active_claims.clear()
                self._claims_by_owner.clear()
                self._dirty_during_claim.clear()
                self._password_dirty_dirs.clear()

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
        active_requests = []
        for candidate in ready:
            request = await self._submit_candidate(candidate)
            if request is not None:
                active_requests.append(request)
        with self._lock:
            self._register_inflight_requests_locked(active_requests)
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
            finishing = asyncio.gather(
                *(self._finish_active_request(request) for request in completed),
            )
            self._completion_batches.add(finishing)
            try:
                try:
                    finished = await asyncio.shield(finishing)
                except asyncio.CancelledError:
                    await finishing
                    raise
            finally:
                with self._lock:
                    self._unregister_inflight_requests_locked(completed)
                for request in completed:
                    self._retire_quiet_tracker(request.candidate.path)
                self._completion_batches.discard(finishing)
                if not self._completion_batches:
                    self._completion_batches.clear()
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
            # PipelineEngine.run() is done here, so its path lease and any
            # source cleanup promotion have already ended. Hand off only paths
            # that actually changed while this request owned them.
            self._release_pipeline_source_claims(request.notification_id)
            if request.registry_owner:
                from sunpack.runtime.cli.runtime_state import runtime_host

                host = runtime_host()
                if host is not None:
                    host.archive_registry.release(request.registry_owner)

    @staticmethod
    def _merge_run_result(target: WatchRunResult, source: WatchRunResult) -> None:
        target.processed += source.processed
        target.succeeded += source.succeeded
        target.failed += source.failed
        target.errors.extend(source.errors)

    @staticmethod
    def _scheduler_path_key(path: str) -> str:
        return os.path.normcase(os.path.abspath(path))

    def _inflight_path_keys_locked(self) -> set[str]:
        return set(self._inflight_path_counts)

    def _register_inflight_requests_locked(
        self,
        requests: Iterable[_ActivePipelineRequest],
    ) -> None:
        for request in requests:
            self._inflight_requests.append(request)
            key = self._scheduler_path_key(request.candidate.path)
            self._inflight_path_counts[key] = self._inflight_path_counts.get(key, 0) + 1

    def _unregister_inflight_requests_locked(
        self,
        requests: Iterable[_ActivePipelineRequest],
    ) -> None:
        for request in requests:
            path = request.candidate.path
            key = self._scheduler_path_key(path)
            count = self._inflight_path_counts.get(key, 0)
            if count <= 1:
                self._inflight_path_counts.pop(key, None)
                state = self._active_states.get(path)
                if state is not None:
                    self._schedule_active_locked(path, state, path_key_value=key)
            else:
                self._inflight_path_counts[key] = count - 1

    def _new_active_state_locked(
        self,
        *,
        last_event_at: float,
        quiet_seconds: float,
    ) -> _ActiveCandidateState:
        self._active_epoch += 1
        return _ActiveCandidateState(
            last_event_at=last_event_at,
            quiet_seconds=quiet_seconds,
            epoch=self._active_epoch,
        )

    def _schedule_active_locked(
        self,
        path: str,
        state: _ActiveCandidateState,
        *,
        path_key_value: str | None = None,
    ) -> None:
        key = path_key_value or self._scheduler_path_key(path)
        if key in self._inflight_path_counts:
            return
        heapq.heappush(
            self._ready_heap,
            (
                state.last_event_at + state.quiet_seconds,
                state.epoch,
                state.generation,
                key,
                path,
            ),
        )

    def _next_ready_entry_locked(self) -> tuple[float, int, int, str, str] | None:
        while self._ready_heap:
            deadline, epoch, generation, key, path = self._ready_heap[0]
            state = self._active_states.get(path)
            if (
                state is None
                or state.epoch != epoch
                or state.generation != generation
                or key in self._inflight_path_counts
            ):
                heapq.heappop(self._ready_heap)
                continue
            return deadline, epoch, generation, key, path
        return None

    def _reschedule_generation(self, path: str, epoch: int, generation: int) -> None:
        with self._lock:
            state = self._active_states.get(path)
            if (
                state is None
                or state.epoch != epoch
                or state.generation != generation
            ):
                return
            self._schedule_active_locked(path, state)

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def next_delay_seconds(self) -> float | None:
        now = time.time()
        monotonic_now = time.monotonic()
        with self._lock:
            next_ready = self._next_ready_entry_locked()
            delay = (
                None
                if next_ready is None
                else max(0.0, next_ready[0] - now)
            )
            if self._password_dirty_dirs:
                password_delay = max(
                    0.0,
                    min(
                        changed_at + self.password_retry_debounce_seconds - monotonic_now
                        for changed_at in self._password_dirty_dirs.values()
                    ),
                )
                delay = password_delay if delay is None else min(delay, password_delay)
            if self._cache_cleanup_deadline is not None:
                cleanup_delay = max(0.0, self._cache_cleanup_deadline - monotonic_now)
                delay = cleanup_delay if delay is None else min(delay, cleanup_delay)
            return delay

    def _reset_idle_cache_cleanup(self) -> None:
        with self._lock:
            self._cache_cleanup_deadline = None

    def _arm_idle_cache_cleanup(self) -> None:
        with self._lock:
            self._cache_cleanup_deadline = (
                time.monotonic() + self.runtime_cache_cleanup_idle_seconds
            )
        self.log.write(
            "cache_cleanup_scheduled",
            idle_seconds=self.runtime_cache_cleanup_idle_seconds,
        )

    async def set_external_activity(self, active: bool) -> None:
        """Serialize foreground runtime work with idle maintenance.

        Idempotent per state: the latest request wins, so a release that
        arrives while an acquire is still waiting leaves the gate free.
        """
        self._external_activity_requested = bool(active)
        if active:
            self._reset_idle_cache_cleanup()
            if self._external_activity_gate_held or self._external_activity_gate_acquiring:
                return
            self._external_activity_gate_acquiring = True
            try:
                await self._runtime_cache_gate.acquire()
            finally:
                self._external_activity_gate_acquiring = False
            if self._external_activity_requested:
                self._external_activity_gate_held = True
            else:
                self._runtime_cache_gate.release()
            return
        try:
            self._arm_idle_cache_cleanup()
            self._wake_service()
        finally:
            if self._external_activity_gate_held:
                self._external_activity_gate_held = False
                self._runtime_cache_gate.release()

    async def _maybe_clear_idle_caches(self) -> None:
        now = time.monotonic()
        with self._lock:
            if self._cache_cleanup_deadline is None or now < self._cache_cleanup_deadline:
                return
            if self._pending or self._inflight_requests or self._inflight_path_counts:
                return
        if self._external_activity_requested:
            return
        async with self._runtime_cache_gate:
            if self._external_activity_requested:
                return
            now = time.monotonic()
            with self._lock:
                if self._cache_cleanup_deadline is None or now < self._cache_cleanup_deadline:
                    return
                if self._pending or self._inflight_requests or self._inflight_path_counts:
                    return
                self._cache_cleanup_deadline = None
                self._pending.clear()
                self._pending_by_key.clear()
                self._active_states.clear()
                self._ready_heap.clear()
                self._inflight_path_counts.clear()
            from sunpack.runtime.cli.runtime_state import runtime_host

            host = runtime_host()
            if host is not None:
                await host.expire_cli_process_mode_override()
            # Claims can retire pending siblings as well as the submitted seed.
            # Their trackers are released here without a per-family index.
            for path in tuple(self._quiet_trackers):
                self._retire_quiet_tracker(path)
            if not self.runtime_cache_cleanup_enabled:
                return
            self.state.trim_idle_storage()
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
        _crash_recovery: bool = False,
        _recovery_scope_dir: str = "",
        _state_prequeued: bool = False,
    ):
        if self.should_ignore_event_path(path):
            return
        if is_directory_password_file(path, self.config):
            self._log_candidate_ignored(path, "directory_password_file")
            return
        lookup_path = os.path.abspath(path)
        with self._claim_gate:
            if self._closed:
                return
            if self._defer_claimed_path_locked(lookup_path):
                return
            with self._lock:
                previous_hint = self._candidate_baseline_locked(lookup_path)
            if previous_hint is None:
                previous_hint = _candidate_from_state_entry(self.state.latest_entry_for_path(lookup_path))
            if event_type == "pipeline_claim_released":
                entry = self.state.latest_entry_for_path(lookup_path)
                # A deferred arrival may change split-family membership without
                # changing the failed anchor's bytes. Do not discard that event
                # when completion just recorded the anchor as missing a volume.
                force = force or (entry is not None and entry.status == "suspended_missing_volume")
            candidate = _candidate_for_event_path(
                path,
                since_usn=previous_hint.change_usn if previous_hint is not None else 0,
            )
            if candidate is None:
                self._log_candidate_ignored(path, "not_a_file_or_unreadable")
                return
            password_retry = (
                _password_retry_snapshot is not None
                and _candidate_matches_password_failure(candidate, _password_retry_snapshot)
            )
            internal_recovery = bool(_crash_recovery)
            if not self._is_under_watched_root(candidate.path) and not password_retry and not internal_recovery:
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
                    self._store_pending_locked(candidate.path, candidate)
                    self._remember_observation_locked(candidate)
                    quiet_seconds = self._observe_candidate_activity(
                        candidate,
                        now,
                        content_changed=True,
                    )
                    state.last_event_at = now
                    state.quiet_seconds = quiet_seconds
                    state.generation += 1
                    self._schedule_active_locked(candidate.path, state)
                    self._wake_service()
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
                    retry_is_unchanged = password_retry or internal_recovery
                    active_quiet_seconds = (
                        0.0
                        if retry_is_unchanged
                        else self._observe_candidate_activity(candidate, now)
                    )
                    # Persist before making the candidate visible to concurrent
                    # scheduler/event paths. If fsync fails there is no in-memory
                    # work that can proceed without a crash-recovery record.
                    if not _state_prequeued:
                        durable_owner = bool(password_retry or internal_recovery)
                        self.state.queue_active(
                            candidate,
                            force=force,
                            password_scope_dir=_recovery_scope_dir,
                            source_input_root=(
                                _password_retry_snapshot.source_input_root if password_retry
                                else self._source_input_root_for(candidate.path)
                            ),
                            internal_recovery=internal_recovery,
                            durable_owner=durable_owner,
                            persist=durable_owner,
                            durable=durable_owner,
                        )
                    self._store_pending_locked(candidate.path, candidate)
                    self._remember_observation_locked(candidate)
                    became_active = True
                    self._active_states[candidate.path] = self._new_active_state_locked(
                        last_event_at=now,
                        quiet_seconds=active_quiet_seconds,
                    )
                    self._schedule_active_locked(
                        candidate.path,
                        self._active_states[candidate.path],
                    )
                else:
                    self._store_pending_locked(candidate.path, candidate)
                    self._remember_observation_locked(candidate)
                    active_quiet_seconds = self._observe_candidate_activity(
                        candidate,
                        now,
                        content_changed=True,
                    )
                    state.last_event_at = now
                    state.quiet_seconds = active_quiet_seconds
                    state.generation += 1
                    self._schedule_active_locked(candidate.path, state)
        if became_active:
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

    def _store_pending_locked(self, path: str, candidate: WatchCandidate) -> None:
        if path not in self._pending:
            key = path_key(os.path.abspath(path))
            self._pending_by_key.setdefault(key, set()).add(path)
        self._pending[path] = candidate

    def _remove_pending_locked(
        self, path: str, *, normalized_key: str | None = None,
    ) -> WatchCandidate | None:
        candidate = self._pending.pop(path, None)
        if candidate is not None:
            key = normalized_key if normalized_key is not None else path_key(os.path.abspath(path))
            paths = self._pending_by_key[key]
            paths.remove(path)
            if not paths:
                del self._pending_by_key[key]
                if not self._pending_by_key:
                    # pop/del retain an empty dict's peak table allocation.
                    self._pending_by_key.clear()
        return candidate

    def _defer_claimed_path_locked(self, path: str) -> bool:
        normalized = os.path.abspath(path)
        key = path_key(normalized)
        owner = self._active_claims.get(key)
        if not owner:
            return False
        self._dirty_during_claim.setdefault(owner, {})[key] = normalized
        return True

    def _claim_pipeline_sources(self, owner: str, paths: Iterable[str]) -> None:
        normalized = dedupe_normalized_paths(
            os.path.abspath(str(path))
            for path in paths
            if str(path or "")
        )
        if not owner or not normalized:
            return
        retired_pending: list[tuple[str, str]] = []
        with self._claim_gate:
            claimed_keys = [path_key(path) for path in normalized]
            owned_keys = self._claims_by_owner.setdefault(owner, set())
            for key in claimed_keys:
                previous_owner = self._active_claims.get(key)
                if previous_owner and previous_owner != owner:
                    previous_keys = self._claims_by_owner[previous_owner]
                    previous_keys.remove(key)
                    if not previous_keys:
                        del self._claims_by_owner[previous_owner]
                    previous_dirty = self._dirty_during_claim.get(previous_owner)
                    if previous_dirty and key in previous_dirty:
                        self._dirty_during_claim.setdefault(owner, {})[key] = previous_dirty.pop(key)
                        if not previous_dirty:
                            self._dirty_during_claim.pop(previous_owner, None)
                self._active_claims[key] = owner
                owned_keys.add(key)
            with self._lock:
                retired_pending = [
                    (key, candidate_path)
                    for key in claimed_keys
                    for candidate_path in self._pending_by_key.get(key, ())
                ]
                for key, candidate_path in retired_pending:
                    self._remove_pending_locked(candidate_path, normalized_key=key)
                    self._active_states.pop(candidate_path, None)
        self.log.write(
            "pipeline_sources_claimed",
            owner=owner,
            path_count=len(normalized),
            retired_pending=len(retired_pending),
        )

    def _release_pipeline_source_claims(self, owner: str) -> None:
        if not owner:
            return
        reconcile: list[str] = []
        released = 0
        with self._claim_gate:
            owned_keys = self._claims_by_owner.pop(owner, ())
            if not self._claims_by_owner:
                self._claims_by_owner.clear()
            for key in owned_keys:
                self._active_claims.pop(key, None)
            released = len(owned_keys)
            dirty = self._dirty_during_claim.pop(owner, {})
            reconcile = [
                path
                for key, path in dirty.items()
                if key not in self._active_claims
            ]
        if released or reconcile:
            self.log.write(
                "pipeline_sources_released",
                owner=owner,
                released=released,
                dirty=len(reconcile),
            )
        for dirty_path in reconcile:
            self.enqueue(dirty_path, event_type="pipeline_claim_released")

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
        with self._claim_gate:
            claimed = [
                (claim_path, owner)
                for claim_path, owner in self._active_claims.items()
                if _paths_match(claim_path, normalized, recursive=recursive)
            ]
            with self._lock:
                # The submitted seed is only the initial Watch ownership. Once
                # pipeline discovery publishes its physical source claim, every
                # claimed sibling belongs to that in-flight request as well.
                inflight_owned = bool(claimed) or any(
                    _paths_match(request.candidate.path, normalized, recursive=recursive)
                    for request in self._inflight_requests
                )
                pending_paths = [
                    candidate_path
                    for candidate_path in self._pending
                    if _paths_match(candidate_path, normalized, recursive=recursive)
                ]
                for candidate_path in pending_paths:
                    self._remove_pending_locked(candidate_path)
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
                if not self._latest_observations:
                    self._latest_observations.clear()
                if not self._quiet_trackers:
                    self._quiet_trackers.clear()
            pending_record = self.state.pending_work_for_path(normalized)
            recovery_armed = bool(
                pending_record is not None
                and (pending_record.active_outputs or pending_record.committed_roots)
            )
            forgotten = (
                False
                if inflight_owned or recovery_armed
                else self.state.forget_path(normalized, recursive=recursive)
            )
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
        due: list[tuple[str, WatchCandidate, int, int, float]] = []
        due_paths: set[str] = set()
        with self._lock:
            while True:
                entry = self._next_ready_entry_locked()
                if entry is None or entry[0] > now:
                    break
                _, epoch, generation, _, path = heapq.heappop(self._ready_heap)
                if path in due_paths:
                    continue
                state = self._active_states.get(path)
                candidate = self._pending.get(path)
                if (
                    state is None
                    or candidate is None
                    or state.epoch != epoch
                    or state.generation != generation
                ):
                    continue
                due_paths.add(path)
                due.append((
                    path,
                    candidate,
                    epoch,
                    generation,
                    state.quiet_seconds,
                ))

        for path, candidate, epoch, generation, quiet_seconds in due:
            # Claim publication and source observation share this admission
            # gate. Therefore cleanup can never publish a claim in the middle
            # of a candidate/readiness probe and later reject that same probe.
            with self._claim_gate:
                try:
                    if path_key(os.path.abspath(path)) in self._active_claims:
                        self._reschedule_generation(path, epoch, generation)
                        continue
                    refreshed = _candidate_for_event_path(path, since_usn=candidate.change_usn)
                    if refreshed is None:
                        self._drop_active(path, epoch, generation)
                        self.state.forget_path(path)
                        continue
                    if _candidate_observation_changed(candidate, refreshed):
                        if _candidate_content_changed(candidate, refreshed):
                            self._record_boundary_activity(path, epoch, generation, refreshed, now)
                            continue
                        if not self._update_boundary_metadata(path, epoch, generation, refreshed):
                            continue
                        candidate = refreshed
                    try:
                        file_ready = watch_file_is_ready(path)
                    except FileNotFoundError:
                        # The source may disappear after its metadata probe.
                        # Only this candidate departs; the rest of due survives.
                        self._drop_active(path, epoch, generation)
                        self.state.forget_path(path)
                        continue
                    if not file_ready:
                        self._record_boundary_activity(
                            path,
                            epoch,
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
                        if (
                            state is None
                            or state.epoch != epoch
                            or state.generation != generation
                        ):
                            continue
                    # Keep the active generation recoverable until the attempt
                    # is recorded. The admission gate excludes source events;
                    # persistence does not need to hold the scheduler lock.
                    self.state.record_attempt(
                        identified.path,
                        identified.size,
                        identified.mtime,
                        identified.file_id,
                        identified.change_usn,
                    )
                    with self._lock:
                        ready.append(identified)
                        self._remove_pending_locked(path)
                        self._active_states.pop(path, None)
                    self.log.write("candidate_quiet", path=path, generation=generation, quiet_seconds=quiet_seconds)
                except Exception as exc:
                    # Reuse the existing boundary policy for a failed probe or
                    # state write. Generation checks preserve newer events, and
                    # a candidate already handed to ready cannot be requeued.
                    self._record_boundary_activity(
                        path, epoch, generation, candidate, now, content_changed=False,
                    )
                    try:
                        self.log.write_throttled(
                            "candidate_error", throttle_key=self._scheduler_path_key(path),
                            interval_seconds=30.0, path=path,
                            error=str(exc), error_type=type(exc).__name__,
                        )
                    except Exception:
                        # A diagnostic failure must not discard the batch.
                        pass
        return ready

    def _drop_active(self, path: str, epoch: int, generation: int) -> None:
        with self._lock:
            state = self._active_states.get(path)
            if (
                state is None
                or state.epoch != epoch
                or state.generation != generation
            ):
                return
            self._remove_pending_locked(path)
            self._active_states.pop(path, None)
            self._quiet_trackers.pop(path, None)
            self._latest_observations.pop(path, None)
            if not self._quiet_trackers:
                self._quiet_trackers.clear()
            if not self._latest_observations:
                self._latest_observations.clear()

    def _record_boundary_activity(
        self,
        path: str,
        epoch: int,
        generation: int,
        candidate: WatchCandidate,
        now: float,
        *,
        content_changed: bool = True,
    ) -> None:
        with self._lock:
            state = self._active_states.get(path)
            if (
                state is None
                or state.epoch != epoch
                or state.generation != generation
            ):
                return
            self._store_pending_locked(path, candidate)
            self._remember_observation_locked(candidate)
            state.last_event_at = now
            learned_quiet_seconds = self._observe_candidate_activity(
                candidate,
                now,
                content_changed=content_changed,
                learn_interval=False,
            )
            state.quiet_seconds = min(learned_quiet_seconds, self.boundary_confirmation_seconds)
            state.generation += 1
            self._schedule_active_locked(path, state)

    def _update_boundary_metadata(
        self,
        path: str,
        epoch: int,
        generation: int,
        candidate: WatchCandidate,
    ) -> bool:
        with self._lock:
            state = self._active_states.get(path)
            if (
                state is None
                or state.epoch != epoch
                or state.generation != generation
            ):
                return False
            self._store_pending_locked(path, candidate)
            self._remember_observation_locked(candidate)
            self._observe_candidate_activity(candidate, time.time(), content_changed=False)
            return True

    def _remember_observation_locked(self, candidate: WatchCandidate) -> None:
        previous = self._latest_observations.get(candidate.path)
        self._latest_observations[candidate.path] = _CandidateObservation(
            candidate.size, candidate.mtime, candidate.file_id, candidate.change_usn,
            previous.quiet_seconds if previous is not None else 0.0,
            previous.last_content_event_at if previous is not None else None,
        )

    def _retire_quiet_tracker(self, path: str) -> None:
        with self._claim_gate, self._lock:
            key = path_key(os.path.abspath(path))
            if (key in self._pending_by_key or key in self._inflight_path_counts
                    or key in self._active_claims):
                return
            tracker = self._quiet_trackers.pop(path, None)
            observation = self._latest_observations.get(path)
            if observation is not None and tracker is not None:
                # A later write may be the next chunk of a slow download. Keep
                # its last interval boundary and floor, but release the model.
                observation.quiet_seconds = tracker.quiet_seconds
                observation.last_content_event_at = tracker.last_content_event_at
            if not self._quiet_trackers:
                self._quiet_trackers.clear()

    def _candidate_baseline_locked(self, path: str) -> WatchCandidate | _CandidateObservation | None:
        normalized = os.path.abspath(path)
        return (
            self._pending.get(normalized)
            or self._pending.get(path)
            or self._latest_observations.get(normalized)
            or self._latest_observations.get(path)
        )

    def _accept_metadata_observation_locked(self, candidate: WatchCandidate, now: float) -> None:
        self._remember_observation_locked(candidate)
        self.state.advance_entry_observation(candidate)
        state = self._active_states.get(candidate.path)
        if state is not None:
            self._store_pending_locked(candidate.path, candidate)
        if candidate.path in self._active_states or candidate.path in self._quiet_trackers:
            self._observe_candidate_activity(candidate, now, content_changed=False)

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
            observation = self._latest_observations.get(candidate.path)
            if observation is not None:
                tracker.quiet_seconds = max(tracker.quiet_seconds, observation.quiet_seconds)
                tracker.last_content_event_at = observation.last_content_event_at
                tracker.last_size = observation.size
                tracker.last_mtime = observation.mtime
                tracker.last_change_usn = observation.change_usn
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

    async def _submit_candidate(
        self,
        candidate: WatchCandidate,
    ) -> _ActivePipelineRequest | None:
        source_input_root = self._source_input_root_for(candidate.path)
        root_entry = self.root_entries.get(path_key(source_input_root))
        if root_entry is None:
            self.log.write("processing_deferred_missing_input_root", path=candidate.path, source_input_root=source_input_root)
            return None
        options = EmbeddedOptions(force_scan=root_entry.deep_detect)
        self.state.bind_input_root(candidate.path, source_input_root)
        notification_id = uuid.uuid4().hex
        with self._password_source_lock:
            run_config = dict(self.config)
            password_generation = self.state.password_generation
            retry_entry = self.state.latest_entry_for_path(candidate.path)
            pending = self.state.pending_work_for_path(candidate.path)
            scope_dir = ""
            if retry_entry is not None and retry_entry.status == "failed_password":
                scope_dir = retry_entry.password_scope_dir
            elif pending is not None:
                scope_dir = str(pending.password_scope_dir or "")
            if scope_dir:
                scoped_passwords = discover_directory_passwords_for_archive(
                    os.path.join(scope_dir, "__sunpack_password_retry__"),
                    self.config,
                )
                run_config["user_passwords"] = dedupe_passwords([
                    *list(run_config.get("user_passwords") or []),
                    *scoped_passwords,
                ])
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
        run_config = discovery_run_config(run_config, deep_detect=options.force_scan)
        from sunpack.runtime.cli.runtime_state import runtime_host

        host = runtime_host()
        reservation_paths = [candidate.path]
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
                progress_callback=lambda archive_task, event: self._handle_pipeline_progress(
                    candidate.path,
                    notification_id,
                    archive_task,
                    event,
                ),
                request_config=run_config,
                origin="watch",
                detection_options=options,
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
            task=task,
            password_generation=password_generation,
            registry_owner=notification_id if host is not None else "",
            source_input_root=source_input_root,
            deep_detect=options.force_scan,
        )

    def _handle_pipeline_progress(
        self,
        owner_path: str,
        notification_id: str,
        archive_task,
        event: dict,
    ) -> None:
        name = str(event.get("event") or "")
        if name == "task_sources_claimed":
            source_paths = event.get("source_paths") or getattr(archive_task, "cleanup_parts", ()) or ()
            self._claim_pipeline_sources(notification_id, source_paths)
            return
        if name == "task_output_started":
            if not self.state.record_task_output_started(
                owner_path,
                str(event.get("task_path") or getattr(archive_task, "main_path", "") or ""),
                str(event.get("output_dir") or ""),
            ):
                raise RuntimeError("watch output start state transition rejected")
            return
        if name == "task_output_finished":
            if not self.state.record_task_output_finished(
                owner_path,
                str(event.get("task_path") or getattr(archive_task, "main_path", "") or ""),
                str(event.get("output_dir") or ""),
                keep_output=bool(event.get("keep_output")),
            ):
                raise RuntimeError("watch output finish state transition rejected")
            return
        self._notify("progress", notification_id, archive_task, event)

    async def _complete_candidate(self, request: _ActivePipelineRequest) -> WatchRunResult:
        candidate = request.candidate
        try:
            response = await request.task
        except FileNotFoundError:
            if os.path.exists(candidate.path):
                raise
            # The input departed during an older request (for example after
            # successful full-family cleanup). It has no remaining retry work.
            self._retire_claimed_paths([candidate.path], candidate)
            self._notify("suppressed", request.notification_id)
            return WatchRunResult(processed=1)
        summary = response.summary
        self._remember_recent_passwords(response.recent_passwords)
        claimed_paths = _response_claimed_paths(response, candidate.path)
        coalesced_from = response.discovery.coalesced_from_request_id
        if coalesced_from:
            # Coalescing transfers execution ownership to another pipeline
            # request; it is not a terminal result.  In particular, a password
            # retry may be coalesced with another member of the same split
            # family.  Retiring claimed paths here would erase the durable
            # failed_password blocker before the owner reports success or a
            # replacement blocker.
            self.log.write(
                "pipeline_request_coalesced",
                path=candidate.path,
                owner_request_id=coalesced_from,
                claimed_paths=claimed_paths,
            )
            self._notify("suppressed", request.notification_id)
            return WatchRunResult(processed=1)

        results = target_results(summary)
        target_result = _target_result_for_path(summary, candidate.path)
        if target_result is None and len(results) == 1:
            claimed_keys = {path_key(path) for path in claimed_paths}
            if path_key(candidate.path) in claimed_keys:
                target_result = results[0]
        outcome_kind = _summary_outcome_kind(summary, target_result)
        direct_outcome = result_outcome(target_result) or outcome_kind
        target_output_dir = target_result.output_dir if target_result is not None else ""
        generated_output_dirs = dedupe_normalized_paths([
            *response.artifacts.shell_refresh_paths,
            *(
                str(item.get("out_dir") or "")
                for item in summary.recovered_outputs
            ),
            str(target_output_dir or ""),
        ])

        failures = summary.failures
        for item in results:
            failure = result_failure(item)
            if failure is not None and failure not in failures:
                failures.append(failure)

        direct_failure = result_failure(target_result)
        if direct_failure is None and target_result is None and len(failures) == 1:
            direct_failure = failures[0]

        if direct_outcome == OutcomeKind.COMPLETE_SUCCESS:
            self._retire_claimed_paths(claimed_paths, request.candidate)

        waiting_failures: list = []
        recorded_password_failures: list = []
        retired_failures: list = []
        retry_results = results or ([None] if direct_failure is not None else [])
        for item in retry_results:
            failure = direct_failure if item is None else result_failure(item)
            retry_path = candidate.path if item is None else result_path(item)
            if failure is None or not retry_path:
                continue
            missing = failure_contains(failure, FailureKind.MISSING_VOLUME)
            password = failure_is_password(failure)
            if not (missing or password):
                continue
            retry_candidate = _candidate_for_event_path(retry_path)
            if retry_candidate is None:
                # A successful sibling family may have consumed this input
                # while an earlier incomplete request was still finishing.
                # Never resurrect a blocker for a deleted physical input.
                self.state.clear_entries([retry_path])
                retired_failures.append(failure)
                continue
            if self.pipeline_engine.completed_watch_family_output(
                retry_path, deep_detect=request.deep_detect,
            ):
                # A newer successful family still owns these exact bytes.
                # This synchronous check and state update cannot be interleaved
                # by another completion on the pipeline's event loop.
                self.state.clear_entries([retry_path])
                retired_failures.append(failure)
                continue
            scope_dir = os.path.dirname(os.path.abspath(retry_path))
            blockers = ([BLOCKER_MISSING_VOLUME] if missing else []) + ([BLOCKER_PASSWORD] if password else [])
            payload = _failure_payload(
                failure, path=retry_candidate.path, blockers=blockers,
                password_scope_dir=scope_dir if password else "",
                password_scope_signature=_directory_password_signature(scope_dir, self.config) if password else "",
                source_input_root=self._source_input_root_for(retry_path),
            )
            error = _failure_message(failure, self.i18n.t("watch.failure.extraction_failed"))
            status = "suspended_missing_volume" if missing else "failed_password"
            with self._password_source_lock:
                # Publish before comparing under the same lock used by password
                # updates: either this completion or the update queues a retry.
                self.state.mark(
                    retry_candidate.path, retry_candidate.size, retry_candidate.mtime,
                    file_id=retry_candidate.file_id, change_usn=retry_candidate.change_usn,
                    status=status, error=error, failure_payload=payload,
                    password_generation=request.password_generation,
                )
                retry_password = (
                    password and not missing
                    and request.password_generation < self.state.password_generation
                )
            if retry_password:
                self.notify_password_table_changed(
                    os.path.join(scope_dir, DIRECTORY_PASSWORD_FILE_NAME), bump_generation=False,
                )
            self.log.write(status, path=retry_candidate.path, error=error, failures=[payload])
            (waiting_failures if missing else recorded_password_failures).append(failure)

        terminal_failures = [
            failure
            for failure in failures
            if failure not in waiting_failures
            and failure not in recorded_password_failures
            and failure not in retired_failures
        ]
        failed = summary.failed_tasks

        if terminal_failures:
            payloads = [_failure_to_dict(failure) for failure in terminal_failures]
            terminal_errors = []
            for item in results:
                failure = result_failure(item)
                if failure not in terminal_failures:
                    continue
                task_path = result_path(item)
                message = result_error(item) or _failure_message(
                    failure,
                    self.i18n.t("watch.failure.extraction_failed"),
                )
                terminal_errors.append(
                    f"{os.path.basename(task_path)} [{message}]" if task_path else message
                )
            errors = terminal_errors or failed or [
                _failure_message(failure, self.i18n.t("watch.failure.extraction_failed"))
                for failure in terminal_failures
            ]
            error = errors[0] if errors else self.i18n.t("watch.failure.extraction_failed")
            self.log.write(
                "failed_terminal",
                path=candidate.path,
                error=error,
                failures=payloads,
            )
            self._notify("failed", request.notification_id, errors, payloads)
            return WatchRunResult(processed=1, failed=1, errors=errors)

        if waiting_failures:
            self._notify("suppressed", request.notification_id)
            return WatchRunResult(
                processed=1, failed=1,
                errors=[_failure_message(failure, self.i18n.t("failure.possible_missing_volume")) for failure in waiting_failures],
            )

        if recorded_password_failures:
            self._notify("suppressed", request.notification_id)
            errors = failed or [
                _failure_message(failure, self.i18n.t("watch.failure.extraction_failed"))
                for failure in recorded_password_failures
            ]
            return WatchRunResult(processed=1, failed=1, errors=errors)

        if retired_failures and not summary.scan_failed_tasks:
            self._notify("suppressed", request.notification_id)
            return WatchRunResult(processed=1)

        if failed:
            # Unstructured failures cannot participate in an automatic wait.
            error = failed[0]
            self.log.write("failed_terminal", path=candidate.path, error=error, failures=[])
            self._notify("failed", request.notification_id, failed, [])
            return WatchRunResult(processed=1, failed=1, errors=failed)

        if _summary_processed_no_tasks(summary):
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

        if direct_outcome == OutcomeKind.PARTIAL_SUCCESS:
            error = self.i18n.t("watch.failure.partial_rejected")
            self.log.write("partial_rejected", path=candidate.path, error=error)
            self._notify("failed", request.notification_id, [error], [])
            return WatchRunResult(processed=1, failed=1, errors=[error])

        if direct_outcome != OutcomeKind.COMPLETE_SUCCESS:
            error = self.i18n.t("watch.failure.no_complete_outcome")
            self.log.write("failed_terminal", path=candidate.path, error=error, failures=[])
            self._notify("failed", request.notification_id, [error], [])
            return WatchRunResult(processed=1, failed=1, errors=[error])

        self.log.write(
            "done",
            path=candidate.path,
            success_count=summary.success_count,
            output_dirs=generated_output_dirs,
        )
        cleanup_failed = [
            item for item in response.summary.cleanup_results
            if item.status == "failed"
        ]
        self.log.write(
            "cleanup",
            path=candidate.path,
            results=[
                {
                    "path": item.path,
                    "status": item.status,
                    "error_code": item.error_code,
                    "message": item.message,
                }
                for item in response.summary.cleanup_results
            ],
        )
        if cleanup_failed:
            self._notify(
                "succeeded",
                request.notification_id,
                generated_output_dirs,
                [self.i18n.t("cleanup.incomplete", count=len(cleanup_failed))],
            )
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

    def _retire_claimed_paths(self, paths: Iterable[str], candidate: WatchCandidate) -> None:
        normalized = dedupe_normalized_paths(paths)
        with self._lock:
            inflight_candidates = {path_key(request.candidate.path): request.candidate for request in self._inflight_requests}
            retired = [
                path for path in normalized
                if path_key(path) not in self._pending_by_key and path_key(path) not in inflight_candidates
            ]
            candidate_pending = path_key(os.path.abspath(candidate.path)) in self._pending_by_key
        cleared = list(retired)
        for path in normalized:
            inflight = inflight_candidates.get(path_key(path))
            if inflight is None:
                continue
            recorded = _candidate_from_state_entry(self.state.latest_entry_for_path(path))
            if recorded is not None and not _candidate_observation_changed(recorded, inflight):
                # Successful family ownership retires an older blocker even if
                # a sibling retry still needs its independent output record.
                cleared.append(path)
        if retired:
            self.state.complete_work(retired)
        if cleared:
            self.state.clear_entries(cleared)
        if not candidate_pending:
            self.state.complete_work_if_matches(candidate)

    def _source_input_root_for(self, path: str) -> str:
        entry = self.state.latest_entry_for_path(path)
        pending = self.state.pending_work_for_path(path)
        source_root = (pending.source_input_root if pending else "") or (entry.source_input_root if entry else "")
        if source_root:
            return source_root
        return _longest_matching_root(os.path.abspath(path), self.watch_roots) or ""

    def _common_root_for(self, path: str) -> str:
        path = os.path.abspath(path)
        matched = _longest_matching_root(path, self.watch_roots)
        if matched and os.path.isdir(matched):
            return matched
        if matched and os.path.isfile(matched):
            return os.path.dirname(matched)
        return os.path.dirname(path)

    def _output_root_for(self, path: str) -> str:
        normalized = os.path.abspath(path)
        matched_root = _longest_matching_root(normalized, self.watch_roots)
        if matched_root is not None:
            return self.output_roots[path_key(matched_root)]
        return self._common_root_for(path)

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
                    self._password_dirty_dirs[entry.password_scope_dir] = now
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


def _candidate_observation_changed(previous: WatchCandidate | _CandidateObservation, current: WatchCandidate) -> bool:
    return (
        previous.size != current.size
        or previous.mtime != current.mtime
        or previous.file_id != current.file_id
        or previous.change_usn != current.change_usn
    )


def _candidate_matches_password_failure(candidate: WatchCandidate, entry: WatchStateEntry) -> bool:
    return (
        os.path.normcase(os.path.abspath(candidate.path)) == os.path.normcase(os.path.abspath(entry.path))
        and _candidate_change_kind(_candidate_from_state_entry(entry), candidate)
        != _CandidateChangeKind.CONTENT_CHANGED
    )


def _candidate_change_kind(
    previous: WatchCandidate | _CandidateObservation | None,
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


def _response_claimed_paths(response: PipelineResponse, fallback_path: str) -> list[str]:
    return dedupe_normalized_paths([*response.discovery.claimed_paths, fallback_path])


def _target_result_for_path(summary: RunSummary, path: str) -> TargetRunResult | None:
    expected = path_key(os.path.abspath(path))
    return next((item for item in summary.target_results if path_key(os.path.abspath(item.input_path)) == expected), None)


def _summary_outcome_kind(summary: RunSummary, target_result: TargetRunResult | None) -> OutcomeKind:
    if target_result is not None:
        return target_result.outcome_kind
    if summary.partial_success_count:
        return OutcomeKind.PARTIAL_SUCCESS
    if summary.success_count:
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
    return fast_hash128(payload)


def _failure_to_dict(failure: FailureInfo | None) -> dict:
    return failure.to_dict() if failure is not None else {}


def _failure_message(failure: FailureInfo | None, fallback: str) -> str:
    return (failure.message or fallback) if failure is not None else fallback


def _failure_payload(
    failure,
    *,
    path: str = "",
    blockers: list[str] | None = None,
    password_scope_dir: str = "",
    password_scope_signature: str = "",
    source_input_root: str = "",
) -> dict:
    payload = _failure_to_dict(failure)
    if source_input_root:
        payload["source_input_root"] = source_input_root
    if blockers is not None:
        payload["blockers"] = list(blockers)
    if password_scope_dir:
        payload["password_scope_dir"] = os.path.abspath(password_scope_dir)
    if password_scope_signature:
        payload["password_scope_signature"] = password_scope_signature
    if path:
        details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
        payload["details"] = {**details, "path": os.path.abspath(path)}
    return payload


def _persisted_blocker_owns_retry(state: WatchStateStore, path: str) -> bool:
    entry = state.latest_entry_for_path(path)
    return bool(
        entry is not None
        and entry.status in {"failed_password", "suspended_missing_volume"}
    )


def _password_scope_for_path(state: WatchStateStore, path: str) -> str:
    entry = state.latest_entry_for_path(path)
    if entry is not None and entry.status == "failed_password":
        return entry.password_scope_dir
    pending = state.pending_work_for_path(path)
    return str(pending.password_scope_dir or "") if pending is not None else ""


def _directory_password_signature(scope_dir: str, config: dict) -> str:
    if not scope_dir:
        return ""
    path = os.path.join(os.path.abspath(scope_dir), DIRECTORY_PASSWORD_FILE_NAME)
    if not is_directory_password_file(path, config):
        return "disabled"
    try:
        stat_result = os.stat(path)
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        return f"unknown:{getattr(exc, 'winerror', None) or exc.errno or 0}"
    return ":".join((
        str(int(stat_result.st_size)),
        str(stat_result.st_mtime_ns),
        str(stat_result.st_ctime_ns),
    ))


def _summary_processed_no_tasks(summary: RunSummary) -> bool:
    return (
        summary.success_count <= 0
        and not summary.failed_tasks
        and not summary.processed_keys
        and not summary.recovered_outputs
    )
