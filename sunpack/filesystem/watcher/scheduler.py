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
from sunpack.contracts.failures import FailureKind
from sunpack.contracts.retry_targets import (
    failure_contains,
    failure_is_password,
    password_retry_results,
    result_error,
    result_failure,
    result_outcome,
    result_path,
    target_results,
)
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
    watch_path_identity,
    watch_root_changes,
    watch_volume_cursor,
)
from sunpack.filesystem.watcher.scanner import _candidate_for as _watch_candidate_for_path
from sunpack.filesystem.watcher.state import WatchStateEntry, WatchStateStore
from sunpack.filesystem.watcher.toast import NullWatchNotificationSink
from sunpack.i18n import I18nContext
from sunpack.passwords.internal import builtin as builtin_passwords_module
from sunpack.passwords.internal.builtin import get_builtin_passwords
from sunpack.passwords.internal.clipboard_monitor import ClipboardPasswordMonitor
from sunpack.passwords.internal.lists import dedupe_passwords
from sunpack.passwords.internal.local_files import (
    DIRECTORY_PASSWORD_FILE_NAME,
    discover_directory_passwords_for_archive,
    is_directory_password_file,
)
from sunpack.passwords.internal.store import MAX_RECENT_PASSWORDS
from sunpack.support.path_keys import path_key
from sunpack.support.collections import dedupe_normalized_paths
from sunpack.support.archive_sessions import release_archive_sessions_under
from sunpack.support.resource_lifecycle import (
    ResourceKind,
    lifecycle_registration,
    open_service_file,
    promotion_barrier,
    register_service_resource,
)
from sunpack.support.output_cleanup import (
    DEFAULT_OUTPUT_CLEANUP_MANAGER,
    OutputCleanupEvent,
)
from sunpack.support.watch_staging import (
    cleanup_staging_output,
    publish_staging_output,
)
from sunpack.postprocess.actions import PostProcessActions

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
        cold_start_seconds: float | None = None,
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
        self._runtime_cache_gate = asyncio.Lock()
        self._external_activity_gate_held = False
        self._startup_suppress_paths: set[str] = set()
        self._startup_retire_paths: set[str] = set()
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
        self._prepare_usn_startup_baseline()
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

        for key, path in changed_paths.items():
            if key in self._startup_suppress_paths:
                continue
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
                retire_paths=self._startup_retire_paths,
            )
        self._startup_retire_paths.clear()
        self.log.write(
            "usn_startup_recovered",
            changed=len(changed_paths),
            queued=len(recovered_candidates),
            fallback_roots=sorted(fallback_roots),
        )

    def _publication_identity_matches(self, path: str, expected_file_id: str) -> bool:
        if not expected_file_id:
            return True
        try:
            _volume, file_id, _usn = watch_path_identity(path)
        except Exception:
            return False
        return str(file_id or "").lower() == str(expected_file_id or "").lower()

    def _recover_committed_publications(self, pending) -> bool:
        publications = dict(getattr(pending, "publications", {}) or {})
        if not publications:
            return True
        for publication in publications.values():
            task_path = os.path.abspath(str(publication.get("task_path") or ""))
            staging = os.path.abspath(str(publication.get("staging_dir") or "")) if publication.get("staging_dir") else ""
            final = os.path.abspath(str(publication.get("output_dir") or ""))
            expected_id = str(publication.get("staging_file_id") or "")
            if not task_path or not final:
                return False
            staging_exists = bool(staging and os.path.isdir(staging))
            final_exists = os.path.isdir(final)
            if staging_exists and final_exists:
                self.log.write(
                    "crash_publish_conflict",
                    owner_path=pending.path,
                    task_path=task_path,
                    staging_dir=staging,
                    output_dir=final,
                )
                return False
            if final_exists:
                if not self._publication_identity_matches(final, expected_id):
                    self.log.write("crash_publish_identity_mismatch", path=final)
                    return False
            elif staging_exists:
                if not self._publication_identity_matches(staging, expected_id):
                    self.log.write("crash_staging_identity_mismatch", path=staging)
                    return False
                try:
                    publish_staging_output(staging, final)
                except Exception as exc:
                    self.log.write(
                        "crash_publish_failed",
                        task_path=task_path,
                        staging_dir=staging,
                        output_dir=final,
                        error=str(exc),
                    )
                    return False
            else:
                # Verified publication vanished before it could be published.
                # If the source survives, normal recovery can safely re-extract it.
                if os.path.isfile(task_path):
                    continue
                self.log.write(
                    "crash_committed_output_missing",
                    task_path=task_path,
                    output_dir=final,
                )
                return False

            self._startup_suppress_paths.add(path_key(task_path))
            if os.path.exists(task_path):
                try:
                    results = PostProcessActions(self.config, stdout=None).apply(
                        archives_to_clean=[[task_path]],
                        flatten_targets=[],
                    )
                except Exception as exc:
                    self.log.write("crash_source_cleanup_failed", path=task_path, error=str(exc))
                    return False
                if any(getattr(item, "status", "") == "failed" for item in results):
                    self.log.write("crash_source_cleanup_failed", path=task_path)
                    return False
            if staging and os.path.exists(staging):
                cleanup_staging_output(staging)
        return True

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
            publications = dict(getattr(pending, "publications", {}) or {})

            if publications and not self._recover_committed_publications(pending):
                continue

            if not active_outputs and not committed_roots and not publications:
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
            if publications and not candidates:
                self._startup_retire_paths.add(pending.path)
                continue
            # Atomically replace the old owner with concrete recovery candidates
            # before rebuilding the in-memory queue. A second crash between the
            # two steps therefore restarts from the new durable candidates.
            self.state.rebase_pending_work(
                pending.path,
                candidates,
                password_scope_dir=scope_dir,
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
                if previous != current:
                    self.enqueue(
                        entry.path,
                        force=True,
                        event_type="startup_password_reconcile",
                        _password_retry_snapshot=entry,
                    )
                continue
            if entry.status == "suspended_missing_volume":
                # Re-resolving this one known input lets the existing group
                # fingerprint gate decide whether an offline volume arrival made
                # it retryable. Unchanged groups remain suspended without extract.
                self.enqueue(
                    entry.path,
                    force=True,
                    event_type="startup_missing_volume_reconcile",
                )

        for group in self.state.group_items():
            if group.status != "waiting":
                continue
            # A pre-dispatch split group can be waiting before a canonical head
            # exists, so there may be no failure entry to reconcile. Re-enqueue
            # one persisted member only; the existing relation resolver scans
            # that split family directory and sees any volumes that arrived while
            # SunPack was offline. This is one startup event, not polling.
            candidate_path = next(
                (
                    value
                    for value in [group.head_path, *group.input_paths, *group.owned_paths]
                    if value and os.path.isfile(value)
                ),
                "",
            )
            if candidate_path:
                self.enqueue(
                    candidate_path,
                    force=True,
                    event_type="startup_group_reconcile",
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
        """Serialize foreground runtime work with idle maintenance."""
        if active:
            await self._runtime_cache_gate.acquire()
            self._external_activity_gate_held = True
            self._reset_idle_cache_cleanup()
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
            if self._pending or self._inflight_requests:
                return
        if self._external_activity_gate_held:
            return
        async with self._runtime_cache_gate:
            now = time.monotonic()
            with self._lock:
                if self._cache_cleanup_deadline is None or now < self._cache_cleanup_deadline:
                    return
                if self._pending or self._inflight_requests:
                    return
                self._cache_cleanup_deadline = None
            from sunpack.cli.runtime_state import runtime_host

            host = runtime_host()
            if host is not None:
                await host.expire_cli_process_mode_override()
            if not self.runtime_cache_cleanup_enabled:
                return
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
        if not password_retry and not internal_recovery and not self._passes_filesystem_filters(candidate):
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
                        internal_recovery=internal_recovery,
                        durable_owner=durable_owner,
                        persist=durable_owner,
                        durable=durable_owner,
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
            # Task-level cleanup is allowed to delete an input before the whole
            # recursive Watch request finishes. Those watcher delete events must
            # not erase the durable crash owner while the request still owns the
            # path/group; completion will retire it after all recovery anchors are
            # committed.
            inflight_owned = any(
                _paths_match(request.candidate.path, normalized, recursive=recursive)
                or any(
                    _paths_match(member, normalized, recursive=recursive)
                    for member in (request.group.owned_paths if request.group is not None else ())
                )
                for request in self._inflight_requests
            )
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
            pending_record = self.state.pending_work_for_path(path)
            internal_recovery = bool(
                pending_record is not None and pending_record.internal_recovery
            )
            if (
                filter_stale
                and not internal_recovery
                and not self._passes_filesystem_filters(refreshed)
            ):
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
            # Same write-ahead rule as enqueue(): do not expose deferred work
            # to memory until its crash queue record is durable.
            self.state.queue_active(candidate, force=True)
            self._pending[candidate.path] = candidate
            self._active_states[candidate.path] = state
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
                progress_callback=lambda archive_task, event: self._handle_pipeline_progress(
                    candidate.path,
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

    def _handle_pipeline_progress(
        self,
        owner_path: str,
        notification_id: str,
        archive_task,
        event: dict,
    ) -> None:
        name = str(event.get("event") or "")
        if name == "task_output_started":
            self.state.record_task_output_started(
                owner_path,
                str(getattr(archive_task, "main_path", "") or ""),
                str(event.get("staging_dir") or event.get("output_dir") or ""),
            )
            return
        if name == "task_output_committed":
            self.state.record_task_output_committed(
                owner_path,
                str(getattr(archive_task, "main_path", "") or ""),
                str(event.get("output_dir") or ""),
                staging_dir=str(event.get("staging_dir") or ""),
                staging_file_id=str(event.get("staging_file_id") or ""),
            )
            return
        self._notify("progress", notification_id, archive_task, event)

    async def _complete_candidate(self, request: _ActivePipelineRequest) -> WatchRunResult:
        candidate = request.candidate
        group = request.group
        response = await request.task
        summary = response.summary
        self._remember_recent_passwords(response.recent_passwords)

        target_result = _target_result_for_path(summary, candidate.path)
        outcome_kind = _summary_outcome_kind(summary, target_result)
        direct_outcome = result_outcome(target_result) or outcome_kind
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

        results = target_results(summary)
        failures = list(getattr(summary, "failures", []) or [])
        for item in results:
            failure = result_failure(item)
            if failure is not None and failure not in failures:
                failures.append(failure)

        direct_failure = result_failure(target_result)
        if direct_failure is None and target_result is None and len(failures) == 1:
            # Lightweight scheduler fakes historically expose only summary.failures.
            direct_failure = failures[0]

        direct_missing = bool(
            direct_failure is not None
            and failure_contains(direct_failure, FailureKind.MISSING_VOLUME)
        )
        direct_password = bool(
            direct_failure is not None and failure_is_password(direct_failure)
        )
        original_scope = _password_scope_for_path(self.state, candidate.path)
        password_scope_dir = original_scope or os.path.dirname(os.path.abspath(candidate.path))
        password_scope_signature = _directory_password_signature(password_scope_dir, self.config)

        # The watched input has its own lifecycle even when a recursively generated
        # archive fails later. A successful direct task leaves group/state now;
        # later recovery is anchored to the failed task itself.
        if direct_outcome == OutcomeKind.COMPLETE_SUCCESS:
            if group is not None:
                completed_group = self._current_group_snapshot(group, candidate.path)
                if completed_group is None:
                    self.state.clear_group(group.group_id)
                else:
                    self.state.record_group_done(completed_group)
                self.state.clear_entries(group.owned_paths)
            self.state.mark(
                candidate.path,
                candidate.size,
                candidate.mtime,
                file_id=candidate.file_id,
                change_usn=candidate.change_usn,
                status="done",
            )
            # Directory-swap flatten changes the output root identity. Retire
            # the durable Watch publication now; cosmetic flatten waits until all
            # retryable nested blockers have been classified below.
            self.state.complete_work_if_matches(request.candidate)

        waiting_failures: list = []
        if direct_missing:
            blockers = [BLOCKER_MISSING_VOLUME]
            if direct_password:
                blockers.append(BLOCKER_PASSWORD)
            payload = _failure_payload(
                direct_failure,
                path=candidate.path,
                blockers=blockers,
                password_scope_dir=password_scope_dir if direct_password else "",
                password_scope_signature=password_scope_signature if direct_password else "",
            )
            error = _failure_message(
                direct_failure,
                self.i18n.t("failure.possible_missing_volume"),
            )
            if group is not None:
                self.state.record_group_suspended(
                    group,
                    blockers=blockers,
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
                failures=[payload],
                partial_recovery=direct_outcome == OutcomeKind.PARTIAL_SUCCESS,
            )
            waiting_failures.append(direct_failure)

        recorded_password_failures: list = []
        recorded_password_payloads: dict[str, dict] = {}
        retry_results = password_retry_results(summary)
        if not results and direct_failure is not None:
            if (
                failure_is_password(direct_failure)
                and not failure_contains(direct_failure, FailureKind.MISSING_VOLUME)
            ):
                retry_results = [None]

        for item in retry_results:
            failure = direct_failure if item is None else result_failure(item)
            retry_path = candidate.path if item is None else result_path(item)
            if failure is None or not retry_path:
                continue
            retry_candidate = (
                candidate
                if path_key(retry_path) == path_key(candidate.path)
                else _candidate_for_event_path(retry_path)
            )
            if retry_candidate is None:
                # No surviving source means there is no task that can ever retry.
                continue
            payload = _failure_payload(
                failure,
                path=retry_candidate.path,
                blockers=[BLOCKER_PASSWORD],
                password_scope_dir=password_scope_dir,
                password_scope_signature=password_scope_signature,
            )
            error = _failure_message(failure, self.i18n.t("watch.failure.extraction_failed"))
            self.state.mark(
                retry_candidate.path,
                retry_candidate.size,
                retry_candidate.mtime,
                file_id=retry_candidate.file_id,
                change_usn=retry_candidate.change_usn,
                status="failed_password",
                error=error,
                failure_payload=payload,
            )
            self.log.write(
                "failed_password",
                path=retry_candidate.path,
                error=error,
                failures=[payload],
            )
            recorded_password_failures.append(failure)
            recorded_password_payloads[path_key(retry_candidate.path)] = payload

        direct_password_payload = recorded_password_payloads.get(path_key(candidate.path))
        if (
            group is not None
            and not direct_missing
            and direct_outcome != OutcomeKind.COMPLETE_SUCCESS
        ):
            if direct_password_payload is not None:
                self.state.record_group_suspended(
                    group,
                    blockers=[BLOCKER_PASSWORD],
                    failure_payload=direct_password_payload,
                )
            else:
                self.state.record_group_terminal(
                    group,
                    status="failed_terminal",
                    failure_payload=_failure_payload(
                        direct_failure,
                        path=candidate.path,
                    ) if direct_failure is not None else None,
                )

        terminal_failures = [
            failure
            for failure in failures
            if failure not in waiting_failures
            and failure not in recorded_password_failures
        ]
        failed = list(getattr(summary, "failed_tasks", []) or [])

        # Flatten is final cosmetic work once no future retry depends on the
        # current recursive paths. Terminal nested failures do not own a retry
        # anchor, so they must not strand an otherwise successful outer output
        # in its pre-flatten layout.
        should_flatten = (
            direct_outcome == OutcomeKind.COMPLETE_SUCCESS
            and not direct_missing
            and not recorded_password_failures
        )
        if should_flatten:
            self._run_deferred_flatten(response)

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

        if direct_missing:
            self._notify("suppressed", request.notification_id)
            return WatchRunResult(
                processed=1,
                failed=1,
                errors=[_failure_message(
                    direct_failure,
                    self.i18n.t("failure.possible_missing_volume"),
                )],
            )

        if recorded_password_failures:
            self._notify("suppressed", request.notification_id)
            errors = failed or [
                _failure_message(failure, self.i18n.t("watch.failure.extraction_failed"))
                for failure in recorded_password_failures
            ]
            return WatchRunResult(processed=1, failed=1, errors=errors)

        if failed:
            # Unstructured failures cannot participate in an automatic wait.
            error = failed[0]
            if group is not None and direct_outcome != OutcomeKind.COMPLETE_SUCCESS:
                self.state.record_group_terminal(group, status="failed_terminal")
            self.log.write("failed_terminal", path=candidate.path, error=error, failures=[])
            self._notify("failed", request.notification_id, failed, [])
            return WatchRunResult(processed=1, failed=1, errors=failed)

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

        if direct_outcome == OutcomeKind.PARTIAL_SUCCESS:
            error = self.i18n.t("watch.failure.partial_rejected")
            if group is not None:
                self.state.record_group_terminal(group, status="failed_terminal")
            self.log.write("partial_rejected", path=candidate.path, error=error)
            self._notify("failed", request.notification_id, [error], [])
            return WatchRunResult(processed=1, failed=1, errors=[error])

        if direct_outcome != OutcomeKind.COMPLETE_SUCCESS:
            error = self.i18n.t("watch.failure.no_complete_outcome")
            if group is not None:
                self.state.record_group_terminal(group, status="failed_terminal")
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
                    "attempts": item.attempts,
                    "error_code": item.error_code,
                    "message": item.message,
                }
                for item in response.summary.cleanup_results
            ],
            retry_count=sum(
                max(0, item.attempts - 1)
                for item in response.summary.cleanup_results
            ),
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

    def _run_deferred_flatten(self, response) -> None:
        if not self.config.get("post_extract", {}).get("flatten_single_directory", True):
            return
        targets = list(response.artifacts.flatten_targets)
        if not targets:
            return
        try:
            with promotion_barrier(
                targets,
                cache_releasers=(release_archive_sessions_under,),
            ):
                PostProcessActions(self.config).apply(
                    cleanup_archives=False,
                    flatten_targets=targets,
                )
        except Exception as exc:
            # The publication is already retired. Flatten is cosmetic here, so
            # a postprocess failure must not resurrect or re-extract the source.
            self.log.write(
                "deferred_flatten_failed",
                targets=targets,
                error=str(exc),
                error_type=type(exc).__name__,
            )

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
        normalized = os.path.abspath(path)
        matched_root = _longest_matching_root(normalized, self.watch_roots)
        if matched_root is not None:
            return self.output_roots[path_key(matched_root)]
        # Password retries may start from a recursively generated archive that
        # already lives under a configured output root.
        output_root = _longest_matching_root(normalized, list(self.output_roots.values()))
        return output_root or self._common_root_for(path)

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


def _failure_message(failure, fallback: str) -> str:
    if isinstance(failure, dict):
        message = failure.get("message")
    else:
        message = getattr(failure, "message", "") if failure is not None else ""
    return str(message or fallback)


def _failure_payload(
    failure,
    *,
    path: str = "",
    blockers: list[str] | None = None,
    password_scope_dir: str = "",
    password_scope_signature: str = "",
) -> dict:
    payload = _failure_to_dict(failure)
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
        str(int(getattr(stat_result, "st_mtime_ns", int(stat_result.st_mtime * 1_000_000_000)))),
        str(int(getattr(stat_result, "st_ctime_ns", int(stat_result.st_ctime * 1_000_000_000)))),
    ))


def _summary_processed_no_tasks(summary) -> bool:
    return (
        int(getattr(summary, "success_count", 0) or 0) <= 0
        and not list(getattr(summary, "failed_tasks", []) or [])
        and not list(getattr(summary, "processed_keys", []) or [])
        and not list(getattr(summary, "recovered_outputs", []) or [])
    )
