from __future__ import annotations

from sunpack_native import NativeWatchObservation

import asyncio
import heapq
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Iterable

from sunpack.core.support.path_keys import case_key, path_key, absolute_path_key, path_key_is_under
from sunpack_native import fast_hash128, NativeWatchCatalog

from sunpack.core.config.fields.watch import DEFAULT_WATCH_CONFIG
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.support.filesystem_scan_errors import filesystem_scan_failure
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
    watch_volume_cursor,
    watch_path_identity,
    watch_catalog_changes,
)
from sunpack.runtime.watch.scanner import _candidate_for as _watch_candidate_for_path
from sunpack.runtime.watch.state import WatchStateEntry, WatchStateStore, _recorded_file_presence
from sunpack.pipeline.postprocess.output_cleanup import DEFAULT_OUTPUT_CLEANUP_MANAGER, OutputCleanupEvent
from sunpack.runtime.watch.roots import WatchRootEntry, watch_path_available
from sunpack.core.contracts.discovery_scope import DiscoveryScope
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.runtime.watch.toast import NullWatchNotificationSink
from sunpack.core.i18n import I18nContext
from sunpack.core.passwords.internal import builtin as builtin_passwords_module
from sunpack.core.passwords.internal.builtin import password_file_source
from sunpack.core.passwords.internal.clipboard_monitor import ClipboardPasswordMonitor
from sunpack.core.passwords.internal.lists import dedupe_passwords

from sunpack.core.support.collections import dedupe_normalized_paths
from sunpack.core.support.resource_lifecycle import (
    ResourceKind,
    lifecycle_registration,
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
BLOCKER_MISSING_VOLUME = "missing_volume"
BLOCKER_PASSWORD = "password"


class _CandidateChangeKind(Enum):
    UNCHANGED = auto()
    METADATA_ONLY = auto()
    CONTENT_CHANGED = auto()


@dataclass(slots=True, eq=False)
class _SourceProbe:
    path: str
    allow_owned: bool = False
    recheck: bool = False


@dataclass(frozen=True, slots=True)
class _SourceClaim:
    owner: str
    promoted_nested_input: bool = False


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
    source_paths: tuple[str, ...] = ()
    password_scope_dir: str = ""
    source_groups: dict[str, dict] = field(default_factory=dict)


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
        observer_stop_timeout_seconds: float | None = None,
        pipeline_engine=None,
        notification_sink=None,
        wake_callback: Callable[[], None] | None = None,
    ):
        self.config = config
        self.i18n = I18nContext(config["cli"]["language"])
        watch_config = config["watch"]
        self.watch_roots = [os.path.abspath(path) for path in watch_roots]
        validate_ntfs_watch_roots([directory for root in self.watch_roots
                                  if (directory := _nearest_existing_directory(root)) is not None])
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
                recursive=configured_entries[path_key(root)].recursive if path_key(root) in configured_entries else False,
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
        self._scan_options = DirectoryScanner.compile_scan_options(config)
        from sunpack.core.config.detection_view import discovery_run_config
        self._deep_scan_options = (DirectoryScanner.compile_scan_options(
            discovery_run_config(config, deep_detect=True))
            if any(entry.deep_detect for entry in self.root_entries.values()) else None)
        from sunpack.runtime.watch.roots import discovery_scopes
        self.scopes = discovery_scopes(self.root_entries.values())
        self.observer_stop_timeout_seconds = max(
            0.0,
            float(
                DEFAULT_WATCH_CONFIG["observer_stop_timeout_seconds"]
                if observer_stop_timeout_seconds is None
                else observer_stop_timeout_seconds
            ),
        )
        self.state = WatchStateStore(state_path, retirement_callback=self._schedule_journal_retirement,
                                     scopes=self.scopes.values())
        self._catalog = NativeWatchCatalog(self.state._native, str(Path(state_path).parent))
        self._catalog.retain_roots(list(self.watch_roots))
        from sunpack.runtime.watch.output_roots import WatchOutputRoots
        self._outputs = WatchOutputRoots(self.state, tuple(self.scopes.values()))
        self._reservations = getattr(getattr(pipeline_engine, "_services", None), "output_reservations", None)
        if self._reservations is not None:
            self._reservations.watch_outputs = self._outputs
        log_path = Path(state_path).with_name("events.jsonl")
        self.log = WatchLogStore(str(log_path), wake_callback=self._wake_service)
        self.state._native.attach_events(self.log._native)
        state_parent = Path(state_path).parent
        self.metadata_dir = os.path.abspath(str(state_parent)) if state_parent.name == ".sunpack_watch" else ""
        self.metadata_files = {
            os.path.abspath(str(Path(state_path))),
            os.path.abspath(str(self.state.journal_path)),
            os.path.abspath(str(log_path)),
            *(os.path.abspath(str(Path(state_path).with_name(name))) for name in
              ("catalog.snapshot.bin", "catalog.snapshot.bin.tmp", "catalog.wal.bin", "catalog.lock")),
        }
        self._lock = threading.Lock()
        # Publish claims and observation generations under one short gate.
        # Probes and WAL waits run outside; claims cancel probes before publish.
        self._claim_gate = threading.RLock()
        self._active_claims: dict[str, _SourceClaim] = {}
        self._claims_by_owner: dict[str, set[str]] = {}
        self._dirty_during_claim: dict[str, dict[str, str]] = {}
        self._source_probes: dict[str, _SourceProbe] = {}
        self._password_source_lock = threading.RLock()
        self._directory_pending: set[str] = set()
        self._watch_rearm: set[str] = set()
        self._observed_watches = {}
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
        self._quiet_trackers: dict[str, AdaptiveQuietTracker] = {}
        self._closed = False
        self._password_reload_at: float | None = None
        self._password_retry_at: float | None = None
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
        self._configured_user_passwords = dedupe_passwords(list(config.get("user_passwords") or []))
        self._password_file_source = password_file_source()
        self.builtin_password_file = os.path.abspath(str(builtin_passwords_module.builtin_password_path()))
        self._password_source_signature = self._refresh_password_sources()
        if self.state.record_password_source_signature(self._password_source_signature):
            self._mark_all_password_failures_dirty()
        self._clipboard_monitor = ClipboardPasswordMonitor(
            volume_changed=self._notify_watch_volumes,
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
        self.log.begin_recovery()
        self.state.retain_scopes(self.scopes.values())
        self._prepare_usn_startup_baseline()
        removed_entries = self.state.prune_missing_records()
        if removed_entries:
            self.log.write(
                "state_pruned_on_start",
                entries=removed_entries,
            )
        self._watch_handler = _WatchEventHandler(self)
        self._refresh_directory_watches()
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
        self._publish_password_update()
        self._clipboard_monitor.start()
        self._started = True
        self._recover_persisted_work()
        self._reconcile_persisted_blockers()
        self._recover_usn_startup_gap()
        self.log.recover(self.state._native)
        self.log.write(
            "scheduler_started",
            roots=self.watch_roots,
            out_dir=self.out_dir,
            output_roots=self.output_roots,
            recursive=any(entry.recursive for entry in self.root_entries.values()),
            pending=self.pending_count,
            cold_start_seconds=self.cold_start_seconds,
            quiet_min_seconds=self._quiet_policy.minimum_seconds,
            quiet_max_seconds=self._quiet_policy.maximum_seconds,
        )

    def _refresh_directory_watches(self, changed=()):
        desired = {}
        for root in self.watch_roots:
            if os.path.isdir(root):
                desired[(root, self.root_entries[path_key(root)].recursive)] = None
            # One nearest existing parent guards deletion/recreation. If it
            # disappears, its own event re-arms the guard one level higher.
            parent = os.path.dirname(root)
            while parent:
                if os.path.isdir(parent):
                    desired[(parent, False)] = None
                    break
                ancestor = os.path.dirname(parent)
                if ancestor == parent:
                    break
                parent = ancestor
        password_dir = os.path.dirname(self.builtin_password_file)
        from sunpack.runtime.cli.runtime_state import server_runtime_active
        if not server_runtime_active() and os.path.isdir(password_dir):
            desired[(password_dir, False)] = None
        for key, watch in list(self._observed_watches.items()):
            if key not in desired or any(_paths_match(key[0], path, recursive=True) for path in changed):
                self._observer.unschedule(watch)
                del self._observed_watches[key]
        for key in desired:
            if key not in self._observed_watches:
                try:
                    if path_key(key[0]) in self.root_entries:
                        validate_ntfs_watch_roots([key[0]])
                    self._observed_watches[key] = self._observer.schedule(self._watch_handler, key[0], recursive=key[1])
                except FileNotFoundError:
                    continue  # Its ancestor guard re-arms when it reappears.
                except (OSError, RuntimeError) as exc:
                    self.log.write("watch_root_unavailable", root=key[0], error=str(exc))

    def _notify_watch_volumes(self, unitmask, arrived):
        # The Windows callback only queues existing work; no filesystem IO here.
        with self._lock:
            if self._closed:
                return
            roots = []
            for root in self.watch_roots:
                drive = os.path.splitdrive(root)[0]
                if unitmask:
                    letter = drive[-2:-1].upper()
                    if not drive.endswith(":") or not ("A" <= letter <= "Z"):
                        continue
                    if not (unitmask & (1 << (ord(letter) - ord("A")))):
                        continue
                elif (root, self.root_entries[path_key(root)].recursive) in self._observed_watches:
                    continue
                roots.append(root)
            self._watch_rearm.update(roots)
            if arrived:
                self._directory_pending.update(roots)
        if roots:
            self._wake_service()

    def _queue_watch_rearm(self, path):
        if any(_paths_match(root, path, recursive=True) for root in self.watch_roots):
            with self._lock:
                self._watch_rearm.add(os.path.abspath(path))
            self._wake_service()

    async def scan_initial_roots(self, roots: list[str]) -> list[str]:
        return await self.pipeline_engine.work_broker.run(
            "watch_initial_scan", "watch", lambda: self._scan_initial_roots(roots), request_id="watch",
        )

    def _scan_initial_roots(self, roots: list[str]) -> list[str]:
        completed = []
        for root in roots:
            matched = _longest_matching_root(root,self.watch_roots)
            if matched is None or not os.path.exists(root):
                continue
            candidates, errors = self._scan_candidates([root], recursive=self.root_entries[path_key(matched)].recursive)
            for candidate in candidates:
                self.enqueue(candidate.path, event_type="initial_scan")
            if not errors:
                completed.append(root)
        # Initial-scan admissions use the existing asynchronous WAL writer;
        # flush once for the batch before the service marks roots scanned.
        self.state.flush()
        self.log.write("initial_scan_completed", roots=completed)
        return completed

    def _watch_root_directory(self, root: str) -> str | None:
        return _nearest_existing_directory(root)

    def _scan_options_for(self, scope):
        entry = self.root_entries.get(path_key(scope.root))
        return self._deep_scan_options if entry and entry.deep_detect else self._scan_options

    def _scan_candidates(self, roots: list[str], *, recursive: bool) -> tuple[list[WatchCandidate], list[tuple[str, str, str]]]:
        from sunpack.runtime.watch.scanner import _candidate_from_native
        candidates, errors = [], []
        for root in roots:
            matched = _longest_matching_root(root, self.watch_roots)
            scope = self.scopes[path_key(matched)] if matched else DiscoveryScope(root, recursive=recursive)
            options = self._scan_options_for(scope)
            failures = options.catalog_update(self._catalog, scope.native, root, True)
            errors.extend(failures)
            candidates.extend(_candidate_from_native(row) for row in options.catalog_candidates(self._catalog, scope.native, root))
        if errors:
            self.log.write("filesystem_scan_failed", roots=roots, errors=[
                filesystem_scan_failure(error, self.i18n.language).message for error in errors
            ])
        return candidates, errors

    def _prepare_usn_startup_baseline(self) -> None:
        """Durably establish first-run cursors before the observer can miss a gap."""
        missing: dict[str, dict[str, int]] = {}
        for root in self.watch_roots:
            try:
                directory = self._watch_root_directory(root)
                if directory is None:
                    continue
                volume, journal_id, next_usn = watch_volume_cursor(directory)
            except Exception as exc:
                self.log.write("usn_cursor_unavailable", root=root, error=str(exc))
                continue
            if self.state.watch_cursor(volume) is None:
                missing[volume] = {"journal_id": journal_id, "next_usn": next_usn}
        if missing:
            self.state.merge_watch_cursors(missing, durable=True)

    def _recover_usn_startup_gap(self) -> None:
        """Restore the disposable index; task admission still uses the Watch WAL."""
        cursor_updates = {}
        changed_paths = {}
        rebuilt = []
        plans = []
        volumes = {}
        failed_volumes = set()
        for root in self.watch_roots:
            if not os.path.isdir(root):
                continue
            scope = self.scopes[path_key(root)]
            cached = self._catalog.cursor(scope.native)
            plan = {"root": root, "scope": scope, "cached": cached, "cursor": None, "error": None}
            plans.append(plan)
            try:
                volume, journal, end = watch_volume_cursor(self._watch_root_directory(root))
                plan["cursor"] = (volume, journal, end)
                saved = self.state.watch_cursor(volume)
                if not (cached is not None and cached[0] == volume and cached[1] == journal
                        and 0 < cached[2] <= end):
                    raise ValueError("catalog requires enumeration")
                watch_start = int((saved or {}).get("next_usn", 0))
                if not saved or int(saved.get("journal_id", 0)) != journal or not 0 < watch_start <= end:
                    watch_start = cached[2]
                start = min(cached[2], watch_start)
                group = volumes.setdefault((volume, journal), {
                    "start": start, "end": end, "scopes": [], "paths": (), "error": None,
                })
                group["start"] = min(group["start"], start)
                group["end"] = max(group["end"], end)
                group["scopes"].append(scope.native)
                plan["group"] = group
            except Exception as exc:
                plan["error"] = str(exc)
        for (volume, journal), group in volumes.items():
            try:
                group["paths"] = sorted(watch_catalog_changes(
                    self._catalog, group["scopes"], volume, journal, group["start"], group["end"],
                ), key=len)
            except Exception as exc:
                group["error"] = str(exc)
            group["scopes"].clear()
        for plan in plans:
            root, scope, cached = plan["root"], plan["scope"], plan["cached"]
            options = self._scan_options_for(scope)
            cursor = plan["cursor"]
            try:
                if plan["error"] is not None:
                    raise OSError(plan["error"])
                group = plan["group"]
                if group["error"] is not None:
                    raise OSError(group["error"])
                cursor = (cursor[0], cursor[1], group["end"])
                covered = set()
                for path in group["paths"]:
                    key = path_key(path)
                    ancestor = key
                    while ancestor and ancestor not in covered:
                        ancestor = ancestor.rpartition("\\")[0]
                    if ancestor:
                        continue
                    if not scope.contains(path) or self.should_ignore_event_path(path):
                        continue
                    errors, arrivals = options.catalog_refresh(self._catalog, scope.native, path)
                    if errors:
                        raise OSError(str(errors))
                    covered.add(key)
                    if os.path.isfile(path):
                        changed_paths[path_key(path)] = path
                    for arrival in arrivals:
                        changed_paths[path_key(arrival)] = arrival
            except Exception as exc:
                if cached is None:
                    errors = options.catalog_update(self._catalog, scope.native)
                    arrivals = ()
                else:
                    errors, arrivals = options.catalog_refresh(self._catalog, scope.native)
                rebuilt.append(root)
                if cached is not None:
                    changed_paths.update((path_key(path), path) for path in arrivals)
                self.log.write("catalog_rebuilt", root=root, reason=str(exc), errors=errors)
                if errors:
                    if cursor is not None:
                        failed_volumes.add(cursor[0])
                    cursor = None
            if cursor is not None:
                volume, journal, end = cursor
                self._catalog.set_cursor(scope.native, volume, journal, end)
                previous = cursor_updates.get(volume)
                if previous is None or end < previous["next_usn"]:
                    cursor_updates[volume] = {"journal_id": journal, "next_usn": end}
        for volume in failed_volumes:
            cursor_updates.pop(volume, None)
        for path in changed_paths.values():
            if not _persisted_blocker_owns_retry(self.state, path):
                self.enqueue(path, force=True, event_type="startup_usn_recovery")
        with self._lock:
            recovered_candidates = list(self._pending.values())
        if cursor_updates:
            self.state.queue_recovery_batch(recovered_candidates, cursor_updates)
        if self._catalog.error:
            self.log.write("catalog_persistence_failed", error=self._catalog.error)
        self.log.write("usn_startup_recovered", changed=len(changed_paths),
            queued=len(recovered_candidates), fallback_roots=rebuilt)

    def _recovery_output_matches(self, pending, path):
        # A recorded output root may have been replaced during our own flatten.
        key = "owned|" + path_key(path)
        record = self.state._native.runtime_record(key)
        expected = record.get("identities", []) if record else []
        if not expected:
            expected = [pending.output_identities.get(os.path.abspath(path))]
        try:
            volume, identity, _ = watch_path_identity(path)
            return f"{volume}|{identity}" in expected
        except OSError:
            return False

    def _recover_persisted_work(self) -> None:
        """Recover only durable in-flight work; never scan unrelated Watch roots."""

        for pending in self.state.pending_work_items():
            if not watch_path_available(pending.source_input_root or pending.path, self.scopes.values()):
                continue
            active_outputs = dict(getattr(pending, "active_outputs", {}) or {})
            committed_roots = list(getattr(pending, "committed_roots", []) or [])
            completed_sources = {
                path_key(path)
                for path in list(getattr(pending, "completed_sources", []) or [])
                if path
            }
            scope_dir = str(getattr(pending, "password_scope_dir", "") or "")
            internal = bool(getattr(pending, "internal_recovery", False))
            promoted_destinations = pending.promoted_destinations
            if not active_outputs and not committed_roots and not promoted_destinations:
                if os.path.exists(pending.path):
                    self.enqueue(
                        pending.path,
                        force=pending.force,
                        event_type="recovery",
                        _crash_recovery=internal,
                        _recovery_scope_dir=scope_dir,
                        _state_prequeued=True,
                    )
                elif self.state.file_presence(pending.path) is False:
                    self.state.forget_path(pending.path)
                continue

            recovered: dict[str, WatchCandidate] = {}
            unavailable = False
            promoted_input_present = False
            for target in promoted_destinations:
                if not watch_path_available(target, self.scopes.values()):
                    unavailable = True
                    break
                candidate = _candidate_for_event_path(target)
                if candidate is None:
                    if self.state.file_presence(target) is not False:
                        unavailable = True
                        break
                    continue
                promoted_input_present = True
                if not _persisted_blocker_owns_retry(self.state, candidate.path):
                    recovered.setdefault(path_key(candidate.path), candidate)
            if unavailable:
                # An offline destination is not evidence that the move failed.
                continue
            if not active_outputs and not committed_roots:
                candidate = _candidate_for_event_path(pending.path)
                if candidate is not None and not _persisted_blocker_owns_retry(self.state, candidate.path):
                    recovered.setdefault(path_key(candidate.path), candidate)

            cleanup_failed = False
            for output_dir in dict.fromkeys(active_outputs.values()):
                if not self._recovery_output_matches(pending, output_dir):
                    self.log.write("crash_output_identity_changed", owner_path=pending.path, output_dir=output_dir)
                    continue
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
                root for root in committed_roots if not self._recovery_output_matches(pending, root)
            ]
            # Promotion removes empty source directories. A surviving promoted
            # input resumes that work even when its former output root is gone;
            # re-extracting the retained outer archive would duplicate it.
            if missing_committed_roots and not promoted_input_present:
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
                if not self._recovery_output_matches(pending, root):
                    continue
                try:
                    candidates, _errors = scan_watch_candidates([root], recursive=True)
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
                discovery_scopes={path_key(candidate.path): self._recovered_scope(pending, candidate.path).to_record()
                                  for candidate in candidates},
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

    def _recovered_scope(self, pending, path):
        for root in sorted(pending.committed_roots, key=len, reverse=True):
            scope = DiscoveryScope(root, recursive=True)
            if scope.contains(path) and self._recovery_output_matches(pending, root):
                return scope
        if pending.discovery_scope:
            scope = DiscoveryScope.from_record(pending.discovery_scope)
            if scope.contains(path):
                return scope
        return DiscoveryScope(os.path.dirname(path))

    def _reconcile_persisted_blockers(self) -> None:
        """Re-evaluate only persisted blockers once at startup; no polling."""

        for entry in self.state.entry_items():
            if not os.path.exists(entry.path):
                continue
            if entry.status == "failed_password":
                if entry.password_generation < self.state.password_generation:
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
            if self._reservations is not None and self._reservations.watch_outputs is self._outputs:
                self._reservations.watch_outputs = None
            self._outputs.close()
            self._catalog.close()
            if self._catalog.error:
                self.log.write("catalog_persistence_failed", error=self._catalog.error)
            self.state.close()
            self._catalog = None
        finally:
            self.log.close()
            with self._claim_gate, self._lock:
                self._pending.clear()
                self._pending_by_key.clear()
                self._active_states.clear()
                self._ready_heap.clear()
                self._quiet_trackers.clear()
                self._active_claims.clear()
                self._claims_by_owner.clear()
                self._dirty_during_claim.clear()
                self._source_probes.clear()
                self._password_reload_at = None
                self._password_retry_at = None

    def _stop_blocking(self):
        self.log.invalidate()
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
        with self._lock:
            rearm = tuple(self._watch_rearm)
            self._watch_rearm.clear()
            directories = sorted(self._directory_pending, key=len)
            self._directory_pending.clear()
        if rearm and self._started:
            await self.pipeline_engine.work_broker.run("watch_rearm", "watch", self._refresh_directory_watches, rearm, request_id="watch")
        covered = []
        for directory in directories:
            if not any(_is_relative_to(directory,parent) for parent in covered):
                await self.pipeline_engine.work_broker.run("watch_directory", directory,
                    self._scan_initial_roots, [directory], request_id="watch", origin="watch")
                covered.append(directory)
        now = time.monotonic()
        with self._lock:
            reload_due = self._password_reload_at is not None and self._password_reload_at <= now
            if reload_due:
                self._password_reload_at = None
        if reload_due:
            await self.pipeline_engine.work_broker.run(
                "password_reload", "watch", self._publish_password_update, request_id="watch", origin="watch",
            )
        self._process_password_retries(time.monotonic())
        result = await self._harvest_completed_requests()
        ready = self._pop_ready(time.monotonic())
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
        self._catalog.commit()
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
                self.log.write("failed_terminal", path=request.candidate.path, error=str(exc))
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
            request.source_paths = ()
            request.source_groups.clear()
            self._release_pipeline_source_claims(request.notification_id, request_path=request.candidate.path)
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
        return case_key(os.path.abspath(path))

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
        now = monotonic_now = time.monotonic()
        with self._lock:
            if self._directory_pending or self._watch_rearm:
                return 0.0
            next_ready = self._next_ready_entry_locked()
            delay = (
                None
                if next_ready is None
                else max(0.0, next_ready[0] - now)
            )
            for deadline in (self._password_reload_at, self._password_retry_at):
                if deadline is not None:
                    password_delay = max(0.0, deadline - monotonic_now)
                    delay = password_delay if delay is None else min(delay, password_delay)
            if self._cache_cleanup_deadline is not None and not self._cache_cleanup_blocked_locked():
                cleanup_delay = max(0.0, self._cache_cleanup_deadline - monotonic_now)
                delay = cleanup_delay if delay is None else min(delay, cleanup_delay)
        history_expiry = self.log.next_history_expiry
        if history_expiry is not None:
            history_delay = max(0.0, history_expiry - monotonic_now)
            delay = history_delay if delay is None else min(delay, history_delay)
        return delay

    def _reset_idle_cache_cleanup(self) -> None:
        with self._lock:
            self._cache_cleanup_deadline = None

    def _cache_cleanup_blocked_locked(self) -> bool:
        return bool(
            self._closed or self._pending or self._inflight_requests
            or self._inflight_path_counts or self._external_activity_requested
        )

    def _schedule_journal_retirement(self) -> None:
        with self._lock:
            if self._cache_cleanup_blocked_locked():
                return  # Completion will arm maintenance after existing work.
            if self._cache_cleanup_deadline is None:
                self._cache_cleanup_deadline = time.monotonic() + self.runtime_cache_cleanup_idle_seconds
        self._wake_service()

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

    def _maintain_persistent_state(self) -> None:
        self._catalog.commit(True)
        # Recovery preserved during a root change may have completed since
        # startup. Retire only resident state, not the file index.
        self.state.retain_scopes(self.scopes.values())

    async def _maybe_clear_idle_caches(self) -> None:
        # Log expiry is independent of pipeline/foreground activity. Its exact
        # deadline also wakes Watch when all events were ignored.
        self.log.clear_expired_history()
        now = time.monotonic()
        with self._lock:
            if self._cache_cleanup_deadline is None or now < self._cache_cleanup_deadline:
                return
            if self._cache_cleanup_blocked_locked():
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
                if self._cache_cleanup_blocked_locked():
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
            await self.pipeline_engine.work_broker.run(
                "catalog_maintenance", "watch", self._maintain_persistent_state, request_id="watch", origin="watch",
            )
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

    def _start_source_probe(self, path: str, *, allow_owned=False, replace_active=True):
        probe = _SourceProbe(os.path.abspath(path), allow_owned, not replace_active)
        with self._claim_gate:
            if self._closed or (self.should_ignore_event_path(path) and not allow_owned):
                return None
            if self._defer_claimed_path_locked(probe.path):
                return None
            key = path_key(probe.path)
            previous = self._source_probes.get(key)
            if previous is not None:
                if not replace_active:
                    previous.recheck = True
                    return None
                probe.recheck = probe.recheck or previous.recheck
            self._source_probes[key] = probe
        return probe

    def _source_probe_valid(self, probe) -> bool:
        with self._claim_gate:
            return (not self._closed
                    and self._source_probes.get(path_key(probe.path)) is probe
                    and (probe.allow_owned or not self.should_ignore_event_path(probe.path)))

    def _end_source_probe(self, probe) -> None:
        recheck = False
        with self._claim_gate:
            key = path_key(probe.path)
            if self._source_probes.get(key) is probe:
                del self._source_probes[key]
                if not self._source_probes:
                    self._source_probes.clear()
                if probe.recheck:
                    with self._lock:
                        state = self._active_states.get(probe.path)
                        if state is not None:
                            self._schedule_active_locked(probe.path, state)
                            recheck = True
        if recheck:
            self._wake_service()

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
        pending_recovery = self.state.pending_work_for_path(path)
        retry_scope = (_password_retry_snapshot.failure_payload.get("discovery_scope")
                       if _password_retry_snapshot is not None else None)
        retry_internal = bool(retry_scope and _password_retry_snapshot.source_input_root)
        authorized_recovery = bool((pending_recovery and pending_recovery.internal_recovery) or retry_internal)
        if retry_scope and not DiscoveryScope.from_record(retry_scope).contains(path):
            raise ValueError("Retry input is outside its persisted discovery scope")
        probe = self._start_source_probe(path, allow_owned=authorized_recovery)
        if probe is None:
            return
        admit = lambda: self._source_probe_valid(probe)
        became_active = False
        try:
            with self._lock:
                previous_hint = self._candidate_baseline_locked(probe.path)
            if previous_hint is None:
                previous_hint = _candidate_from_state_entry(self.state.latest_entry_for_path(probe.path))
            if event_type == "pipeline_claim_released":
                entry = self.state.latest_entry_for_path(probe.path)
                force = force or (entry is not None and entry.status == "suspended_missing_volume")
            candidate = _candidate_for_event_path(
                path, since_usn=previous_hint.change_usn if previous_hint is not None else 0,
            )
            # Timestamp the observation before catalog/state work. Processing
            # time is not evidence of a downloader's write interval.
            now = time.monotonic()
            if candidate is None:
                self._log_candidate_ignored(path, "not_a_file_or_unreadable")
                return
            matched_root = _longest_matching_root(candidate.path, self.watch_roots)
            if matched_root:
                scope = self.scopes[path_key(matched_root)]
                self._scan_options_for(scope).catalog_update(self._catalog, scope.native, candidate.path)
            password_retry = (_password_retry_snapshot is not None
                              and _candidate_matches_password_failure(candidate, _password_retry_snapshot))
            internal_recovery = bool(_crash_recovery or retry_internal)
            if not self._is_under_watched_root(candidate.path) and not password_retry and not internal_recovery:
                self._log_candidate_ignored(candidate.path, "outside_watched_roots")
                return
            if self._is_under_metadata_dir(candidate.path):
                self._log_candidate_ignored(candidate.path, "under_metadata_dir")
                return
            with self._claim_gate, self._lock:
                if not admit():
                    return
                previous = self._candidate_baseline_locked(candidate.path) or previous_hint
                change_kind = _candidate_change_kind(previous, candidate)
                active = self._active_states.get(candidate.path)
                promote = event_type == "initial_scan" and active is not None
                needs_queue = active is None or promote
            unchanged = not force and change_kind == _CandidateChangeKind.UNCHANGED
            metadata_only = not force and change_kind == _CandidateChangeKind.METADATA_ONLY
            if not _state_prequeued and (promote or (needs_queue and not unchanged and not metadata_only)):
                durable_owner = bool(password_retry or internal_recovery or event_type == "initial_scan")
                self.state.queue_active(
                    candidate, force=force, password_scope_dir=_recovery_scope_dir,
                    source_input_root=(_password_retry_snapshot.source_input_root if password_retry or retry_internal
                                       else self._source_input_root_for(candidate.path)),
                    internal_recovery=internal_recovery,
                    discovery_scope=retry_scope or (pending_recovery.discovery_scope if pending_recovery else {}),
                    durable_owner=durable_owner, persist=durable_owner,
                    durable=bool(password_retry or internal_recovery), admit=admit,
                )
            if unchanged:
                return
            if metadata_only:
                self.state.advance_entry_observation(candidate, admit=admit)
            with self._claim_gate, self._lock:
                if not admit():
                    return
                if metadata_only:
                    self._accept_metadata_observation_locked(candidate, now)
                    return
                state = self._active_states.get(candidate.path)
                self._store_pending_locked(candidate.path, candidate)
                if state is None:
                    retry_is_unchanged = password_retry or (
                        _crash_recovery and change_kind != _CandidateChangeKind.CONTENT_CHANGED)
                    active_quiet_seconds = 0.0 if retry_is_unchanged else self._observe_candidate_activity(candidate, now)
                    state = self._new_active_state_locked(last_event_at=now, quiet_seconds=active_quiet_seconds)
                    self._active_states[candidate.path] = state
                    became_active = True
                else:
                    active_quiet_seconds = self._observe_candidate_activity(candidate, now, content_changed=True)
                    state.last_event_at = now
                    state.quiet_seconds = active_quiet_seconds
                    state.generation += 1
                self._remember_observation_locked(candidate)
                self._schedule_active_locked(candidate.path, state)
        finally:
            self._end_source_probe(probe)
        if became_active:
            self.log.write(
                "candidate_active", path=candidate.path, force=force, event_type=event_type,
                src_path=src_path, size=candidate.size, mtime=candidate.mtime,
                quiet_seconds=active_quiet_seconds, pending=self.pending_count,
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
        claim = self._active_claims.get(key)
        if claim is None:
            return False
        self._dirty_during_claim.setdefault(claim.owner, {})[key] = normalized
        return True

    def _claim_pipeline_sources(
        self, owner: str, paths: Iterable[str], *, path: str = "", groups: list[dict] | None = None,
        promoted_paths: Iterable[str] = (),
    ) -> bool:
        normalized = dedupe_normalized_paths(
            os.path.abspath(str(path))
            for path in paths
            if str(path or "")
        )
        if not owner or not normalized:
            return False
        promoted_keys = {path_key(source) for source in promoted_paths}
        ordinary_claim = _SourceClaim(owner)
        promoted_claim = None
        promoted = False
        retired_pending: list[tuple[str, str]] = []
        with self._claim_gate:
            claimed_keys = [path_key(path) for path in normalized]
            owned_keys = self._claims_by_owner.setdefault(owner, set())
            for key in claimed_keys:
                probe = self._source_probes.pop(key, None)
                if probe is not None:
                    self._dirty_during_claim.setdefault(owner, {})[key] = probe.path
                previous_claim = self._active_claims.get(key)
                previous_owner = previous_claim.owner if previous_claim else ""
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
                source_promoted = key in promoted_keys or bool(
                    previous_claim and previous_claim.promoted_nested_input
                )
                if source_promoted and promoted_claim is None:
                    promoted_claim = _SourceClaim(owner, True)
                self._active_claims[key] = promoted_claim if source_promoted else ordinary_claim
                promoted |= source_promoted
                owned_keys.add(key)
            if not self._source_probes:
                self._source_probes.clear()
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
            path=path,
            groups=groups or (),
            processing=True,
            owner=owner,
            path_count=len(normalized),
            retired_pending=len(retired_pending),
        )
        return promoted

    def _release_pipeline_source_claims(self, owner: str, *, request_path: str = "") -> None:
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
        if released or reconcile or request_path:
            self.log.write(
                "pipeline_sources_released",
                owner=owner,
                path=request_path,
                paths=list(owned_keys),
                released=released,
                dirty=len(reconcile),
            )
        for dirty_path in reconcile:
            self.enqueue(dirty_path, event_type="pipeline_claim_released")

    def should_ignore_event_path(self, path: str) -> bool:
        if not path:
            return True
        return (self._is_under_metadata_dir(path)
                or bool(self._reservations and self._reservations.contains(path))
                or self._outputs.protected(path))

    def _log_candidate_ignored(self, path: str, reason: str, **payload) -> None:
        normalized = case_key(os.path.abspath(str(path))) if path else ""
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
        return case_key(os.path.abspath(path)) == case_key(self.builtin_password_file)

    def enqueue_many(self, paths: Iterable[str]):
        for path in paths:
            self.enqueue(path)

    def notify_password_source_changed(self, reason: str, path: str = "") -> None:
        with self._lock:
            if self._closed:
                return
            self._password_reload_at = time.monotonic() + self.password_retry_debounce_seconds
        self._wake_service()

    def _publish_password_update(self) -> None:
        with self._password_source_lock:
            signature = self._refresh_password_sources()
            if signature == self._password_source_signature:
                return
            self._password_source_signature = signature
            generation = self.state.mark_password_source_changed(signature)
            self.log.write("password_source_changed", password_generation=generation)
            self._mark_all_password_failures_dirty()

    def notify_directory_arrived(self, path: str):
        if not path:
            return
        self._queue_watch_rearm(path)
        self._outputs.reconcile(path)
        if self.should_ignore_event_path(path):
            return
        root = _longest_matching_root(os.path.abspath(path), self.watch_roots)
        with self._lock:
            if root is not None and (self.root_entries[path_key(root)].recursive or path_key(path) == path_key(root)):
                self._directory_pending.add(os.path.abspath(path))
            else:
                self._directory_pending.update(root for root in self.watch_roots if _paths_match(root, path, recursive=True))
        self._wake_service()

    def retry_missing_volume_peers(self, path):
        if self._closed:
            return
        root = _longest_matching_root(os.path.abspath(path), self.watch_roots)
        if root is None:
            return
        scope = self.scopes[path_key(root)]
        for peer in self._catalog.bucket_paths(scope.native, path):
            if path_key(peer) == path_key(path):
                continue
            entry = self.state.latest_entry_for_path(peer)
            if entry is not None and entry.status == "suspended_missing_volume":
                self.enqueue(peer, force=True, event_type="volume_changed")

    def notify_path_departed(self, path: str, *, recursive: bool = False) -> None:
        normalized = os.path.abspath(path)
        if recursive:
            self._queue_watch_rearm(normalized)
        if not watch_path_available(normalized, self.scopes.values()):
            return
        self._outputs.reconcile(normalized, recursive=recursive)
        matched = _longest_matching_root(normalized,self.watch_roots)
        if matched is not None:
            scope = self.scopes[path_key(matched)]
            self._scan_options_for(scope).catalog_update(self._catalog, scope.native, normalized, recursive)
        # Observe presence outside the publication gate. The snapshot objects
        # are rechecked before retirement so late deletes cannot erase arrivals.
        if _recorded_file_presence(normalized) is not False and not recursive:
            return
        with self._claim_gate, self._lock:
            claimed = any(_paths_match(claim_path, normalized, recursive=recursive)
                          for claim_path in self._active_claims)
            inflight_owned = claimed or any(
                _paths_match(request.candidate.path, normalized, recursive=recursive)
                for request in self._inflight_requests)
            snapshots = [(mapping, [(key, value) for key, value in mapping.items()
                                    if _paths_match(key, normalized, recursive=recursive)])
                         for mapping in (self._pending, self._quiet_trackers)]
        missing = {key for _, rows in snapshots for key, _ in rows
                   if _recorded_file_presence(key) is False}
        pending_paths = []
        with self._claim_gate, self._lock:
            for mapping, rows in snapshots:
                for key, value in rows:
                    if (key not in missing or mapping.get(key) is not value
                            or path_key(os.path.abspath(key)) in self._source_probes):
                        continue
                    if mapping is self._pending:
                        self._remove_pending_locked(key)
                        self._active_states.pop(key, None)
                        pending_paths.append(key)
                    else:
                        mapping.pop(key, None)
                if not mapping:
                    mapping.clear()
        with self._claim_gate, self._lock:
            self._catalog.forget_observation(normalized, recursive=recursive, missing_only=True)
        pending_record = self.state.pending_work_for_path(normalized)
        recovery_armed = bool(pending_record and (pending_record.active_outputs or pending_record.committed_roots))
        if inflight_owned or recovery_armed:
            self.state.prune_missing_records(normalized, recursive=recursive)
            forgotten = False
        else:
            forgotten = self.state.forget_path(normalized, recursive=recursive, missing_only=True)
        self.log.write(
            "candidate_departed",
            path=normalized,
            recursive=recursive,
            forgotten=forgotten,
            pending_removed=len(pending_paths),
        )
        if not recursive:
            self.retry_missing_volume_peers(normalized)
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
            recovery = self.state.pending_work_for_path(path)
            probe = self._start_source_probe(path, allow_owned=bool(recovery and recovery.internal_recovery),
                                             replace_active=False)
            if probe is None:
                if self.should_ignore_event_path(path) and not (recovery and recovery.internal_recovery):
                    self._drop_active(path, epoch, generation)
                    self.state.complete_work_if_matches(candidate)
                    self.log.write("task_retired", path=path)
                continue

            def admit():
                with self._claim_gate:
                    if not self._source_probe_valid(probe):
                        return False
                    with self._lock:
                        state = self._active_states.get(path)
                        return state is not None and state.epoch == epoch and state.generation == generation

            try:
                refreshed = _candidate_for_event_path(path, since_usn=candidate.change_usn)
                if refreshed is None:
                    with self._claim_gate:
                        if admit():
                            self._drop_active(path, epoch, generation)
                    self.state.forget_path(path, missing_only=True)
                    self.log.write("candidate_departed", path=path)
                    continue
                if _candidate_observation_changed(candidate, refreshed):
                    with self._claim_gate:
                        if not admit():
                            continue
                        if _candidate_content_changed(candidate, refreshed):
                            self._record_boundary_activity(path, epoch, generation, refreshed, now)
                            continue
                        if not self._update_boundary_metadata(path, epoch, generation, refreshed):
                            continue
                    candidate = refreshed
                try:
                    file_ready = watch_file_is_ready(path)
                except FileNotFoundError:
                    with self._claim_gate:
                        if admit():
                            self._drop_active(path, epoch, generation)
                    self.state.forget_path(path, missing_only=True)
                    self.log.write("candidate_departed", path=path)
                    continue
                if not file_ready:
                    with self._claim_gate:
                        if admit():
                            self._record_boundary_activity(path, epoch, generation, refreshed, now, content_changed=False)
                    self.log.write_throttled("candidate_busy", throttle_key=case_key(os.path.abspath(path)),
                                             interval_seconds=30.0, path=path)
                    continue
                self.state.record_attempt(refreshed.path, refreshed.size, refreshed.mtime,
                                          refreshed.file_id, refreshed.change_usn, admit=admit)
                with self._claim_gate:
                    if not admit():
                        continue
                    with self._lock:
                        ready.append(refreshed)
                        self._remove_pending_locked(path)
                        self._active_states.pop(path, None)
                self.log.write("candidate_quiet", path=path, generation=generation, quiet_seconds=quiet_seconds)
            except Exception as exc:
                with self._claim_gate:
                    if admit():
                        self._record_boundary_activity(path, epoch, generation, candidate, now, content_changed=False)
                try:
                    self.log.write_throttled(
                        "candidate_error", throttle_key=self._scheduler_path_key(path), interval_seconds=30.0,
                        path=path, error=str(exc), error_type=type(exc).__name__,
                    )
                except Exception:
                    pass
            finally:
                self._end_source_probe(probe)
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
            self._catalog.forget_observation(path)
            if not self._quiet_trackers:
                self._quiet_trackers.clear()

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
            self._observe_candidate_activity(candidate, time.monotonic(), content_changed=False)
            return True

    def _remember_observation_locked(self, candidate: WatchCandidate) -> None:
        self._catalog.remember_observation(
            candidate.path, candidate.size, candidate.mtime, candidate.file_id, candidate.change_usn,
        )

    def _retire_quiet_tracker(self, path: str) -> None:
        with self._claim_gate, self._lock:
            key = path_key(os.path.abspath(path))
            if (key in self._pending_by_key or key in self._inflight_path_counts
                    or key in self._active_claims):
                return
            tracker = self._quiet_trackers.pop(path, None)
            self._catalog.retire_observation(
                path,
                quiet_seconds=tracker.quiet_seconds if tracker is not None else None,
                last_content_event_at=tracker.last_content_event_at if tracker is not None else None,
                quiet_calibrated=tracker.calibrated if tracker is not None else False,
            )
            if not self._quiet_trackers:
                self._quiet_trackers.clear()

    def _candidate_baseline_locked(self, path: str) -> WatchCandidate | NativeWatchObservation | None:
        normalized = os.path.abspath(path)
        return (
            self._pending.get(normalized)
            or self._pending.get(path)
            or self._catalog.observation(normalized)
        )

    def _accept_metadata_observation_locked(self, candidate: WatchCandidate, now: float) -> None:
        self._remember_observation_locked(candidate)
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
            observation = self._catalog.observation(candidate.path)
            if observation is not None:
                if observation.quiet_seconds > 0.0:
                    tracker.quiet_seconds = min(
                        self._quiet_policy.maximum_seconds,
                        max(self._quiet_policy.minimum_seconds, observation.quiet_seconds),
                    )
                tracker.calibrated = observation.quiet_calibrated
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

    def _process_password_retries(self, now: float) -> None:
        with self._lock:
            if self._password_retry_at is None or now < self._password_retry_at:
                return
            self._password_retry_at = None
        for entry in self.state.failed_password_entries():
            if (entry.password_generation < self.state.password_generation
                    and os.path.exists(entry.path)):
                self.log.write("retry_password_failure", path=entry.path)
                self.enqueue(entry.path, force=True, event_type="password_retry", _password_retry_snapshot=entry)

    async def _submit_candidate(
        self,
        candidate: WatchCandidate,
    ) -> _ActivePipelineRequest | None:
        pending_recovery = self.state.pending_work_for_path(candidate.path)
        internal_scope = (DiscoveryScope.from_record(pending_recovery.discovery_scope)
            if pending_recovery and pending_recovery.internal_recovery and pending_recovery.discovery_scope else None)
        if pending_recovery and pending_recovery.internal_recovery and internal_scope is None:
            # Legacy records had no scope: a shallow boundary is the only
            # evidence they authorize. New records always carry their scope.
            internal_scope = DiscoveryScope(os.path.dirname(candidate.path))
        if internal_scope is not None and not internal_scope.contains(candidate.path):
            raise ValueError("Recovery input is outside its persisted discovery scope")
        if self.should_ignore_event_path(candidate.path) and internal_scope is None:
            self.state.complete_work([candidate.path])
            self.log.write("task_retired", path=candidate.path)
            return None
        source_input_root = self._source_input_root_for(candidate.path)
        root_entry = self.root_entries.get(path_key(source_input_root))
        if root_entry is None:
            self.log.write("processing_deferred_missing_input_root", path=candidate.path, source_input_root=source_input_root)
            return None
        options = EmbeddedOptions(force_scan=root_entry.deep_detect)
        self.state.bind_input_root(candidate.path, source_input_root)
        scope = internal_scope or self.scopes[path_key(source_input_root)]
        self.state.queue_active(candidate, discovery_scope=scope.to_record(), durable=True)
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
            run_config["password_scope_dir"] = scope_dir or os.path.dirname(candidate.path)
        output_root = self._output_root_for(candidate.path)
        run_config["watch_owner_path"] = candidate.path
        run_config["watch_deep_detect"] = options.force_scan
        run_config["watch_internal_recovery"] = internal_scope is not None
        nested_recovery = internal_scope is not None and path_key(internal_scope.root) != path_key(source_input_root)
        run_config["output"] = {
            **(run_config.get("output", {}) if isinstance(run_config.get("output"), dict) else {}),
            "root": "" if nested_recovery else output_root,
            "common_root": "" if nested_recovery else self._common_root_for(candidate.path),
            "fixed_root": not nested_recovery,
        }
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
        self.log.write("processing_started", path=candidate.path, owner=notification_id, size=candidate.size, mtime=candidate.mtime)
        try:
            task = asyncio.create_task(self.pipeline_engine.run(
                [PipelineTarget(candidate.path, output=run_config["output"])],
                progress_callback=lambda archive_task, event: self._handle_pipeline_progress(
                    candidate.path,
                    notification_id,
                    archive_task,
                    event,
                    request=request,
                ),
                request_config=run_config,
                origin="watch",
                discovery_scope=internal_scope or self.scopes[path_key(source_input_root)],
                catalog=None if internal_scope else (self._catalog, self._scan_options_for(scope), candidate.path),
                detection_options=options,
            ))
        except BaseException:
            if host is not None:
                host.archive_registry.release(notification_id)
            raise
        self._reset_idle_cache_cleanup()
        task.add_done_callback(lambda _task: self._wake_service())
        # No await separates task creation and this assignment; the callback
        # receives the request before the pipeline gets its first loop turn.
        request = _ActivePipelineRequest(
            notification_id=notification_id,
            candidate=candidate,
            task=task,
            password_generation=password_generation,
            registry_owner=notification_id if host is not None else "",
            source_input_root=source_input_root,
            deep_detect=options.force_scan,
            password_scope_dir=run_config["password_scope_dir"],
        )
        return request

    def _handle_pipeline_progress(
        self,
        owner_path: str,
        notification_id: str,
        archive_task,
        event: dict,
        *,
        request: _ActivePipelineRequest | None = None,
    ) -> None:
        name = str(event.get("event") or "")
        if name == "task_sources_claimed":
            source_paths = event.get("source_paths") or getattr(archive_task, "cleanup_parts", ()) or ()
            if request is not None and event.get("depth") == 1:
                # Reuse the published tuple. Keep this request's input evidence
                # even if live source claims transfer to a newer family owner.
                request.source_paths = tuple(source_paths)
            groups = event.get("groups") or ()
            if request is not None:
                for group in groups:
                    request.source_groups[path_key(group["path"])] = group
                    for member in group["members"]:
                        request.source_groups[path_key(member)] = group
            promoted_paths = []
            if event.get("promoted_nested_input") is True:
                promoted_paths = source_paths
            elif "depth" not in event:
                # Per-task claims follow lease acquisition, including a family
                # adopted during missing-volume recovery. Read only its parts.
                promoted_paths = self.state.promoted_nested_input_paths(source_paths)
            promoted = self._claim_pipeline_sources(
                notification_id, source_paths, path=owner_path, groups=groups,
                promoted_paths=promoted_paths,
            )
            if promoted and "depth" not in event:
                # Live publication claims cover the gap before failure state
                # is persisted; ownership transfer preserves their provenance.
                archive_task.runtime["promoted_nested_input"] = True
            destinations = event.get("promoted_destinations")
            if destinations and not self.state.prepare_input_promotion(owner_path, destinations):
                raise RuntimeError("watch input promotion state transition rejected")
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
        except FileNotFoundError as exc:
            missing_path = os.path.abspath(os.fsdecode(exc.filename)) if exc.filename else ""
            if (
                not missing_path
                or not any(
                    path_key(path) == path_key(missing_path)
                    for path in (candidate.path, *request.source_paths)
                )
                or os.path.exists(missing_path)
            ):
                raise
            # A submitted sibling can survive while the actual input is renamed.
            # Retire only that stale input, preserving newly queued generations.
            self._retire_claimed_paths([missing_path], candidate)
            self.log.write("task_retired", path=missing_path)
            self._notify("suppressed", request.notification_id)
            return WatchRunResult(processed=1)
        summary = response.summary
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

        scan_errors = {
            failure.message for failure in summary.scan_failures
            if failure.kind == FailureKind.FILESYSTEM_ERROR
        }
        if scan_errors:
            self.log.write("filesystem_scan_failed", path=candidate.path, errors=sorted(scan_errors))
            # The Watch completion projection omits log-only scan diagnostics.
            # The pipeline response and CLI error reporting retain them.
            summary = replace(
                summary,
                scan_failures=tuple(failure for failure in summary.scan_failures
                                    if failure.kind != FailureKind.FILESYSTEM_ERROR),
            )

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
                self.state.prune_missing_records(retry_path)
                self.log.write("task_retired", path=retry_path)
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
            scope_dir = request.password_scope_dir or os.path.dirname(os.path.abspath(candidate.path))
            blockers = ([BLOCKER_MISSING_VOLUME] if missing else []) + ([BLOCKER_PASSWORD] if password else [])
            payload = _failure_payload(
                failure, path=retry_candidate.path, blockers=blockers,
                password_scope_dir=scope_dir if password else "",
                source_input_root=self._source_input_root_for(retry_path),
            )
            payload["discovery_scope"] = failure.details.get("discovery_scope") or (
                self.scopes[path_key(request.source_input_root)].to_record()
                if path_key(request.source_input_root) in self.scopes else DiscoveryScope(os.path.dirname(retry_path)).to_record())
            error = _failure_message(failure, self.i18n.t("watch.failure.extraction_failed"))
            status = "suspended_missing_volume" if missing else "failed_password"
            with self._password_source_lock:
                # Publish before comparing under the same lock used by password
                # updates: either this completion or the update queues a retry.
                published = self.state.mark(
                    retry_candidate.path, retry_candidate.size, retry_candidate.mtime,
                    file_id=retry_candidate.file_id, change_usn=retry_candidate.change_usn,
                    status=status, error=error, failure_payload=payload,
                    source_group=request.source_groups.get(path_key(retry_path)),
                    password_generation=request.password_generation,
                )
                retry_password = (
                    password and not missing
                    and request.password_generation < self.state.password_generation
                )
            if not published:
                retired_failures.append(failure)
                continue
            if retry_password:
                self._mark_all_password_failures_dirty()
            # Nuitka 4.1.3 loses list mutation tracking through a conditional receiver.
            if missing:
                waiting_failures.append(failure)
            else:
                recorded_password_failures.append(failure)

        # A successful outer input may own unpublished nested promotion intents.
        # Hand them off to durable blockers before retiring any source record.
        if direct_outcome == OutcomeKind.COMPLETE_SUCCESS:
            self._retire_claimed_paths(claimed_paths, request.candidate)

        terminal_failures = [
            failure
            for failure in failures
            if failure not in waiting_failures
            and failure not in recorded_password_failures
            and failure not in retired_failures
        ]
        failed = summary.failed_tasks

        # Every backend-confirmed group needs its own outcome, including nested
        # archives. The request's main input alone cannot retire child cards.
        for item in results:
            task_path = result_path(item)
            if not task_path:
                continue
            if (path_key(task_path) == path_key(candidate.path)
                    and not (waiting_failures or recorded_password_failures or retired_failures)):
                continue
            failure = result_failure(item)
            if failure in waiting_failures or failure in recorded_password_failures or failure in retired_failures:
                continue
            outcome = result_outcome(item)
            if outcome == OutcomeKind.COMPLETE_SUCCESS:
                self.log.write("done", path=task_path, output_dirs=[item.output_dir] if item.output_dir else [])
            elif outcome in {OutcomeKind.FAILURE, OutcomeKind.PARTIAL_SUCCESS}:
                self.log.write("failed_terminal", path=task_path, error=result_error(item))

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

        if retired_failures and not summary.scan_failures:
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
            with self._claim_gate:
                claim = self._active_claims.get(path_key(candidate.path))
                retire_group = claim is None or claim.owner == request.notification_id
            self.log.write("no_tasks_found", path=candidate.path, retire_group=retire_group)
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
        return any(scope.contains(path) for scope in self.scopes.values())

    def _is_under_metadata_dir(self, path: str) -> bool:
        normalized = os.path.abspath(path)
        if normalized in self.metadata_files:
            return True
        return bool(self.metadata_dir and _is_relative_to(normalized, self.metadata_dir))

    def _refresh_password_sources(self) -> str:
        snapshot = self._password_file_source.reload()
        self.config["user_passwords"] = self._configured_user_passwords
        self.config.pop("builtin_passwords", None)
        self.config["password_snapshot"] = snapshot
        return _password_source_signature(self._configured_user_passwords, snapshot.signature)

    def _mark_all_password_failures_dirty(self) -> None:
        if not self.state.has_entry_status("failed_password"):
            return
        with self._lock:
            self._password_retry_at = time.monotonic()
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
        if is_directory and not any(scope.native.intersects_output(path)
                for path in (src_path, getattr(event, "dest_path", "")) if path
                for scope in self.scheduler.scopes.values()):
            return
        if src_path:
            self._handle_departure_path(
                src_path,
                is_directory=is_directory,
            )
        dest_path = getattr(event, "dest_path", "")
        if is_directory:
            if dest_path:
                self.scheduler.notify_directory_arrived(dest_path)
            return
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
        if self.scheduler.should_ignore_event_path(path):
            return
        if is_directory:
            self.scheduler._queue_watch_rearm(path)
        if not self.scheduler._is_under_watched_root(path) and not (
                is_directory and any(scope.native.intersects_output(path) for scope in self.scheduler.scopes.values())):
            return
        self.scheduler.notify_path_departed(path, recursive=is_directory)

    def _handle(self, event: FileSystemEvent, event_type: str):
        if getattr(event, "is_directory", False):
            if event_type == "created":
                self.scheduler.notify_directory_arrived(getattr(event, "src_path", ""))
            return
        src_path = getattr(event, "src_path", "")
        if src_path:
            self._handle_path(src_path, event_type=event_type)

    def _handle_path(self, path: str, *, event_type: str = "unknown", src_path: str = ""):
        if self.scheduler.is_builtin_password_file(path):
            self.scheduler.notify_password_source_changed("builtin_password_file", path="")
            return
        if not self.scheduler._is_under_watched_root(path):
            return
        if self.scheduler.should_ignore_event_path(path):
            return
        try:
            self.scheduler.enqueue(path, event_type=event_type, src_path=src_path)
            self.scheduler.retry_missing_volume_peers(path)
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


def _candidate_observation_changed(previous: WatchCandidate | NativeWatchObservation, current: WatchCandidate) -> bool:
    return (
        previous.size != current.size
        or previous.mtime != current.mtime
        or previous.file_id != current.file_id
        or previous.change_usn != current.change_usn
    )


def _candidate_matches_password_failure(candidate: WatchCandidate, entry: WatchStateEntry) -> bool:
    return (
        case_key(os.path.abspath(candidate.path)) == case_key(os.path.abspath(entry.path))
        and _candidate_change_kind(_candidate_from_state_entry(entry), candidate)
        != _CandidateChangeKind.CONTENT_CHANGED
    )


def _candidate_change_kind(
    previous: WatchCandidate | NativeWatchObservation | None,
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


def _nearest_existing_directory(path: str) -> str | None:
    current = os.path.abspath(path)
    while not os.path.isdir(current):
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent
    return current


def _longest_matching_root(path: str, roots: list[str]) -> str | None:
    matches = [root for root in roots if _is_relative_to(path, root)]
    if not matches:
        return None
    return max(matches, key=len)


def _is_relative_to(path: str, root: str) -> bool:
    return path_key_is_under(absolute_path_key(path), absolute_path_key(root))


def _paths_match(path: str, expected: str, *, recursive: bool) -> bool:
    normalized = os.path.abspath(path)
    expected = os.path.abspath(expected)
    return case_key(normalized) == case_key(expected) or (
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
    snapshot_signature: str,
) -> str:
    payload = json.dumps(
        [user_passwords, snapshot_signature],
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
    source_input_root: str = "",
) -> dict:
    payload = _failure_to_dict(failure)
    if source_input_root:
        payload["source_input_root"] = source_input_root
    if blockers is not None:
        payload["blockers"] = list(blockers)
    if password_scope_dir:
        payload["password_scope_dir"] = os.path.abspath(password_scope_dir)
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


def _summary_processed_no_tasks(summary: RunSummary) -> bool:
    return (
        summary.success_count <= 0
        and not summary.failed_tasks
        and not summary.processed_keys
        and not summary.recovered_outputs
    )
