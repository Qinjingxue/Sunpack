from __future__ import annotations

import copy
import asyncio
import os
import stat
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable, TextIO

from sunpack.pipeline.discovery.detection.input_planning import ArchiveInputPlanningStage
from sunpack.core.config.detection_view import discovery_run_config
from sunpack.core.contracts.pipeline import PipelineArtifacts, PipelineDiscovery, PipelineResponse, PipelineTarget
from sunpack.core.contracts.results import ArchiveCleanupResult, DirectoryFlattenResult, OutcomeKind, TargetRunResult
from sunpack.core.contracts.run_state import RunState
from sunpack.pipeline.coordinator.archive_job import ArchiveJobExecutor
from sunpack.pipeline.coordinator.output_scan_policy import NestedOutputScanPolicy
from sunpack.pipeline.coordinator.recursive_authorization import RecursiveAuthorization
from sunpack.pipeline.coordinator.recursion import RecursionController
from sunpack.pipeline.coordinator.reporting import RunReporter
from sunpack.pipeline.coordinator.task_scan import ArchiveTaskScanner
from sunpack.pipeline.coordinator.target_groups import relation_group_to_candidate
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.pipeline.postprocess.internal.blocked_input import promote_blocked_input
from sunpack.pipeline.extraction.scheduler import ExtractionScheduler
from sunpack.pipeline.extraction.output_inventory import OutputInventory
from sunpack.core.i18n import I18nContext
from sunpack.pipeline.postprocess.actions import PostProcessActions
from sunpack.pipeline.postprocess.internal.cleanup import ArchiveCleanup
from sunpack.core.passwords.internal.store import MAX_RECENT_PASSWORDS
from sunpack.core.platform.windows.shell_notify import notify_shell_directories_updated
from sunpack.core.support.output_reservation import OutputReservationRegistry, build_output_dir_resolver
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner
from sunpack.core.support.output_paths import default_output_dir_for_task
from sunpack.core.support.path_keys import path_key
from sunpack.core.support.archive_sessions import release_archive_sessions_under_roots
from sunpack.core.support.resource_lifecycle import TaskResourceScope, promotion_barrier
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker, CancellationToken, CURRENT_ORIGIN


@dataclass
class _Submission:
    request_id: str
    targets: tuple[PipelineTarget, ...]
    direct: bool
    user_passwords: tuple[str, ...]
    builtin_passwords: tuple[str, ...]
    config: dict
    origin: str = "foreground"
    detection_options: EmbeddedOptions = EmbeddedOptions()
    stdout: TextIO | None = None
    stderr: TextIO | None = None
    input_reader: Callable[[str], Awaitable[str]] | None = None
    progress_callback: Callable[[Any, dict[str, Any]], None] | None = None


class PipelineEngine:
    """Single-event-loop owner for independently completing requests."""

    def __init__(self, config: dict):
        self.config = config
        worker_config = _worker_config(config)
        self._broker = AsyncWorkBroker(
            thread_capacity=int(worker_config.get("stage_thread_capacity", 0) or 0),
            max_pending_jobs=int(
                worker_config.get("max_pending_stage_jobs", worker_config.get("max_queue_jobs", 4096)) or 4096
            ),
        )
        self._services = _PipelineServices(config, self._broker)
        self._runtime = self._services
        self._active_requests: dict[str, asyncio.Task] = {}
        self._request_runtime_factory = _RequestRuntime
        self._path_leases = _PathLeaseRegistry()
        self._recent_passwords: list[str] = []
        self._user_passwords = tuple(config.get("user_passwords", []) or [])
        self._builtin_passwords = tuple(config.get("builtin_passwords", []) or [])
        self._started = False
        self._closed = False
        self._owner_loop: asyncio.AbstractEventLoop | None = None
        self._state_changed_callback: Callable[[], None] | None = None
        self._broker.set_state_changed_callback(self._notify_state_changed)

    @property
    def recent_passwords(self) -> list[str]:
        return list(self._recent_passwords)

    @property
    def work_broker(self) -> AsyncWorkBroker:
        return self._broker

    def is_idle(self) -> bool:
        return not self._active_requests and self._broker.pending_jobs == 0 and self._broker.active_jobs == 0

    def set_state_changed_callback(self, callback: Callable[[], None] | None) -> None:
        self._state_changed_callback = callback

    def _notify_state_changed(self) -> None:
        callback = self._state_changed_callback
        if callback is not None:
            callback()

    async def __aenter__(self) -> "PipelineEngine":
        if self._closed:
            raise RuntimeError("PipelineEngine is closed")
        loop = asyncio.get_running_loop()
        if self._owner_loop is not None and self._owner_loop is not loop:
            raise RuntimeError("PipelineEngine belongs to a different event loop")
        self._owner_loop = loop
        self._broker.bind()
        await self._services.start()
        self._started = True
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self.aclose(graceful=True)

    async def run(
        self,
        targets: Iterable[str | PipelineTarget],
        *,
        direct: bool = False,
        request_config: dict | None = None,
        stdout: TextIO | None = None,
        stderr: TextIO | None = None,
        input_reader: Callable[[str], Awaitable[str]] | None = None,
        progress_callback: Callable[[Any, dict[str, Any]], None] | None = None,
        origin: str = "foreground",
        detection_options: EmbeddedOptions | None = None,
    ) -> PipelineResponse:
        if not self._started or self._closed:
            raise RuntimeError("PipelineEngine must be entered before run")
        if asyncio.get_running_loop() is not self._owner_loop:
            raise RuntimeError("PipelineEngine.run must execute on its owner event loop")
        normalized = tuple(self._normalize_target(target) for target in targets)
        if not normalized:
            raise ValueError("PipelineEngine.run requires at least one target")
        request_config = copy.deepcopy(request_config if request_config is not None else self.config)
        detection_options = detection_options or EmbeddedOptions()
        request_config = discovery_run_config(request_config, deep_detect=detection_options.force_scan)
        user_passwords = tuple(request_config.get("user_passwords", self._user_passwords) or [])
        builtin_passwords = tuple(request_config.get("builtin_passwords", self._builtin_passwords) or [])
        request_config["user_passwords"] = list(user_passwords)
        request_config["builtin_passwords"] = list(builtin_passwords)
        submission = _Submission(
            request_id=uuid.uuid4().hex,
            targets=normalized,
            direct=bool(direct),
            user_passwords=user_passwords,
            builtin_passwords=builtin_passwords,
            config=request_config,
            origin="watch" if str(origin).lower() == "watch" else "foreground",
            detection_options=detection_options,
            stdout=stdout,
            stderr=stderr,
            input_reader=input_reader,
            progress_callback=progress_callback,
        )
        cancellation = CancellationToken()
        resource_scope = TaskResourceScope(
            submission.request_id,
            files=(target.path for target in submission.targets),
        )
        task = asyncio.current_task()
        if task is not None:
            self._active_requests[submission.request_id] = task
            self._notify_state_changed()
        origin_marker = CURRENT_ORIGIN.set(submission.origin)
        try:
            with resource_scope.activate():
                cancellation.raise_if_cancelled()
                runtime = self._request_runtime_factory(
                    self._services,
                    submission,
                    submission.detection_options,
                    self._path_leases,
                )
                start_time = time.time()
                try:
                    response = await runtime.execute_async(self._broker, cancellation)
                except _CoalescedWatchRequest as coalesced:
                    owner_task = self._active_requests.get(coalesced.owner_request_id)
                    if owner_task is None or owner_task is task:
                        raise
                    owner_response = await asyncio.shield(owner_task)
                    return replace(
                        owner_response,
                        request_id=submission.request_id,
                        discovery=replace(
                            owner_response.discovery,
                            coalesced_from_request_id=coalesced.owner_request_id,
                        ),
                    )
                self._remember_recent_passwords(response.recent_passwords)
                if response.summary.postprocess_completed:
                    await self._broker.run(
                        "report",
                        submission.request_id,
                        runtime.reporter.log_final_summary,
                        start_time,
                        response.summary.success_count,
                        response.summary.failed_tasks,
                        recovered_outputs=response.summary.recovered_outputs,
                        failures=response.summary.failures,
                        cleanup_results=response.summary.cleanup_results,
                        request_id=submission.request_id,
                        cancellation=cancellation,
                    )
                return response
        except asyncio.CancelledError:
            cancellation.cancel()
            raise
        finally:
            try:
                await resource_scope.aclose()
            finally:
                self._services.output_reservations.release(submission.request_id)
                await self._path_leases.release(submission.request_id)
                self._active_requests.pop(submission.request_id, None)
                CURRENT_ORIGIN.reset(origin_marker)
                self._notify_state_changed()

    async def clear_runtime_caches(self) -> dict:
        """Clear process-wide runtime caches only while this engine is idle."""

        if not self.is_idle():
            return {"skipped": "engine_busy"}

        def clear() -> dict:
            from sunpack.core.support.runtime_cache_cleanup import (
                clear_all_runtime_caches,
                runtime_cache_stats,
            )

            before = runtime_cache_stats()
            cleared = clear_all_runtime_caches()
            if self._services is not None:
                cleared["output_reservations"] = self._services.output_reservations.clear_idle_cache()
            after = runtime_cache_stats()
            return {"before": before, "cleared": cleared, "after": after}

        return await self._broker.run("cache_cleanup", "engine", clear, request_id="engine")

    def update_password_sources(self, *, user_passwords: Iterable[str], builtin_passwords: Iterable[str]) -> None:
        self._user_passwords = tuple(user_passwords)
        self._builtin_passwords = tuple(builtin_passwords)

    def reconfigure_request(self, config: dict) -> None:
        """Refresh the snapshot source for future requests only."""
        _replace_mapping_in_place(self.config, config)

    async def set_process_mode(self, *, mode: str) -> dict[str, Any]:
        return await self._services.sevenzip_runner.set_process_mode_asyncio(mode=mode)

    async def aclose(self, *, graceful: bool = True) -> None:
        if self._closed:
            return
        if not graceful:
            current = asyncio.current_task()
            for task in tuple(self._active_requests.values()):
                if task is not current:
                    task.cancel()
        elif self._active_requests:
            current = asyncio.current_task()
            await asyncio.gather(
                *(task for task in set(self._active_requests.values()) if task is not current),
                return_exceptions=True,
            )
        await self._services.close(self._broker)
        await self._broker.close(graceful=graceful)
        self._closed = True
        self._started = False

    def _remember_recent_passwords(self, passwords: Iterable[str]) -> None:
        for password in reversed(list(passwords)):
            if password in self._recent_passwords:
                self._recent_passwords.remove(password)
            self._recent_passwords.insert(0, password)
        del self._recent_passwords[MAX_RECENT_PASSWORDS:]

    @staticmethod
    def _normalize_target(target: str | PipelineTarget) -> PipelineTarget:
        if isinstance(target, PipelineTarget):
            return PipelineTarget(os.path.abspath(os.path.normpath(target.path)), dict(target.output))
        return PipelineTarget(os.path.abspath(os.path.normpath(str(target))))


class _CoalescedWatchRequest(RuntimeError):
    def __init__(self, owner_request_id: str):
        super().__init__(owner_request_id)
        self.owner_request_id = owner_request_id


@dataclass(frozen=True, slots=True)
class _LeasePath:
    path: str
    key: str
    resolved_key: str
    ancestor_keys: tuple[str, ...]
    is_dir: bool
    version_row: tuple[str, int, int, int, int] | None


def _snapshot_lease_path(path: str) -> _LeasePath:
    normalized = os.path.abspath(os.path.normpath(path))
    key = path_key(normalized)
    try:
        stat_result = os.stat(normalized)
    except OSError:
        stat_result = None

    is_dir = bool(stat_result is not None and stat.S_ISDIR(stat_result.st_mode))
    version_row = (
        (
            key,
            int(stat_result.st_dev),
            int(stat_result.st_ino),
            int(stat_result.st_size),
            int(stat_result.st_mtime_ns),
        )
        if stat_result is not None
        else None
    )

    try:
        resolved = Path(normalized).resolve()
    except (OSError, ValueError):
        resolved_key = ""
        ancestor_keys = ()
    else:
        resolved_key = path_key(str(resolved))
        ancestor_keys = tuple(path_key(str(parent)) for parent in resolved.parents)

    return _LeasePath(
        path=normalized,
        key=key,
        resolved_key=resolved_key,
        ancestor_keys=ancestor_keys,
        is_dir=is_dir,
        version_row=version_row,
    )


def _lease_ownership_version(
    paths: Iterable[_LeasePath],
) -> tuple[tuple[str, int, int, int, int], ...]:
    rows = []
    for path in paths:
        if path.version_row is None:
            return ()
        rows.append(path.version_row)
    rows.sort(key=lambda row: row[0])
    return tuple(rows)


class _PathLeaseRegistry:
    _COMPLETED_WATCH_LIMIT = 4096

    def __init__(self):
        self._owned: dict[str, set[str]] = {}
        self._lease_paths: dict[str, dict[str, _LeasePath]] = {}
        self._exact_owners: dict[str, str] = {}
        self._entries_by_key: dict[str, _LeasePath] = {}
        self._directory_owners: dict[str, dict[str, int]] = {}
        self._prefix_owners: dict[str, dict[str, int]] = {}
        self._pins: dict[str, dict[object, frozenset[str]]] = {}
        self._pin_counts: dict[str, dict[str, int]] = {}
        self._ownership_versions: dict[str, tuple[tuple[str, int, int, int, int], ...]] = {}
        self._owner_modes: dict[str, bool] = {}
        self._generation_owners: dict[
            tuple[tuple[tuple[str, int, int, int, int], ...], bool],
            str,
        ] = {}
        self._completed_watch_generations: dict[
            tuple[tuple[str, ...], bool],
            tuple[tuple[tuple[str, int, int, int, int], ...], str],
        ] = {}
        self._waiters_by_blocker: dict[str, set[asyncio.Future[None]]] = {}
        self._waiter_blockers: dict[
            asyncio.Future[None],
            frozenset[str],
        ] = {}
        self._lock = asyncio.Lock()

    def _snapshot_paths(
        self,
        paths: Iterable[str],
        *,
        refresh: bool,
    ) -> tuple[_LeasePath, ...]:
        prepared: dict[str, _LeasePath] = {}
        for raw_path in paths:
            if not raw_path:
                continue
            normalized = os.path.abspath(os.path.normpath(raw_path))
            key = path_key(normalized)
            if key in prepared:
                continue
            existing = self._entries_by_key.get(key)
            if existing is not None and not refresh:
                if existing.path == normalized:
                    prepared[key] = existing
                else:
                    prepared[key] = _LeasePath(
                        path=normalized,
                        key=key,
                        resolved_key=existing.resolved_key,
                        ancestor_keys=existing.ancestor_keys,
                        is_dir=existing.is_dir,
                        version_row=existing.version_row,
                    )
                continue
            prepared[key] = _snapshot_lease_path(normalized)
        return tuple(prepared.values())

    async def acquire(self, owner: str, paths: Iterable[str], *, lease_id: object = None) -> None:
        prepared = self._snapshot_paths(paths, refresh=False)
        # The caller has finished its previous extraction/verification attempt.
        # Other jobs in this request keep their pins throughout an upgrade.
        first = True
        while True:
            async with self._lock:
                if first:
                    self._unpin(owner, lease_id)
                    first = False
                blockers = self._blocking_owners(owner, prepared)
                if not blockers:
                    self._claim(owner, prepared)
                    keys = frozenset(path.key for path in prepared)
                    self._pins.setdefault(owner, {})[lease_id] = keys
                    counts = self._pin_counts.setdefault(owner, {})
                    for key in keys:
                        counts[key] = counts.get(key, 0) + 1
                    return
                # Never wait while retaining an idle partial family. Only paths
                # still used by sibling jobs or their cleanup remain protected.
                counts = self._pin_counts.get(owner, {})
                idle = [key for key in self._lease_paths.get(owner, {}) if key not in counts]
                if self._remove_paths(owner, idle):
                    self._wake_waiters_for(owner)
                waiter = self._register_waiter(blockers)
            try:
                await waiter
            except BaseException:
                async with self._lock:
                    self._unregister_waiter(waiter)
                raise

    def _unpin(self, owner: str, lease_id: object) -> list[str]:
        pins = self._pins.get(owner, {})
        keys = pins.pop(lease_id, ())
        if not pins:
            self._pins.pop(owner, None)
        counts = self._pin_counts.get(owner, {})
        idle = []
        for key in keys:
            counts[key] -= 1
            if not counts[key]:
                counts.pop(key)
                idle.append(key)
        if not counts:
            self._pin_counts.pop(owner, None)
        return idle

    async def release_lease(self, owner: str, lease_id: object) -> None:
        async with self._lock:
            if self._remove_paths(owner, self._unpin(owner, lease_id)):
                self._wake_waiters_for(owner)

    async def replace(
        self,
        owner: str,
        paths: Iterable[str],
        *,
        coalesce_exact: bool = False,
        deep_detect: bool = False,
    ) -> str | None:
        """Atomically claim a fully resolved physical input set.

        Discovery is intentionally allowed to run without a lease. If a later
        recursive round needs a different set, release the previous set before
        waiting so two requests can never deadlock while upgrading partial
        ownership.

        Watch may submit two members of the same split family concurrently.
        Once discovery proves that both requests resolve to the exact same
        physical ownership, the later request can coalesce with the active one
        instead of waiting and extracting the same logical archive twice.
        """
        prepared = self._snapshot_paths(paths, refresh=coalesce_exact)
        ownership_version = _lease_ownership_version(prepared) if coalesce_exact else ()
        release_previous = True

        while True:
            async with self._lock:
                if release_previous:
                    release_previous = False
                    if self._remove_owner(owner):
                        self._wake_waiters_for(owner)

                if coalesce_exact:
                    exact_owner = self._generation_owners.get((ownership_version, deep_detect), "")
                    if exact_owner and exact_owner != owner:
                        return exact_owner

                blockers = self._blocking_owners(owner, prepared)
                if not blockers:
                    self._claim(
                        owner,
                        prepared,
                        ownership_version=ownership_version,
                        deep_detect=deep_detect,
                    )
                    return None
                waiter = self._register_waiter(blockers)
            try:
                await waiter
            except BaseException:
                async with self._lock:
                    self._unregister_waiter(waiter)
                raise

    async def release(self, owner: str) -> None:
        async with self._lock:
            if self._remove_owner(owner):
                self._wake_waiters_for(owner)

    def ownership_version_for(
        self,
        owner: str,
        paths: Iterable[str],
    ) -> tuple[tuple[str, int, int, int, int], ...]:
        """Project one task's byte generation from the already-computed Watch lease."""
        owned_version = self._ownership_versions.get(owner, ())
        if not owned_version:
            return ()
        keys = {
            path_key(os.path.abspath(os.path.normpath(path)))
            for path in paths
            if path
        }
        if not keys:
            return ()
        selected = tuple(row for row in owned_version if row[0] in keys)
        return selected if len(selected) == len(keys) else ()

    def input_version_for(self, paths: Iterable[str], *, departed_version=()):
        snapshots = self._snapshot_paths(paths, refresh=True)
        version = _lease_ownership_version(snapshots)
        if version or not departed_version:
            return version
        expected = {row[0]: row for row in departed_version}
        # Reuse a consumed generation only if every surviving member is still
        # unchanged. A changed survivor plus a missing member is a new input.
        if len(expected) == len(snapshots) and all(
            item.version_row is None or item.version_row == expected.get(item.key)
            for item in snapshots
        ):
            return departed_version
        return ()

    def completed_watch_output(
        self,
        ownership_version: tuple[tuple[str, int, int, int, int], ...],
        *,
        deep_detect: bool = False,
    ) -> str:
        """Return the prior output only for the exact unchanged physical generation."""
        if not ownership_version:
            return ""
        key = (tuple(row[0] for row in ownership_version), deep_detect)
        record = self._completed_watch_generations.get(key)
        if record is None:
            return ""
        recorded_version, output_dir = record
        if recorded_version != ownership_version:
            return ""
        if not output_dir or not os.path.isdir(output_dir):
            self._completed_watch_generations.pop(key, None)
            return ""
        # Refresh insertion order so the bounded map behaves as a tiny LRU.
        self._completed_watch_generations.pop(key, None)
        self._completed_watch_generations[key] = record
        return output_dir

    def remember_completed_watch(
        self,
        ownership_version: tuple[tuple[str, int, int, int, int], ...],
        output_dir: str,
        *,
        deep_detect: bool = False,
    ) -> None:
        if not ownership_version or not output_dir:
            return
        key = (tuple(row[0] for row in ownership_version), deep_detect)
        record = (ownership_version, os.path.abspath(os.path.normpath(output_dir)))
        self._completed_watch_generations.pop(key, None)
        self._completed_watch_generations[key] = record
        while len(self._completed_watch_generations) > self._COMPLETED_WATCH_LIMIT:
            oldest = next(iter(self._completed_watch_generations))
            self._completed_watch_generations.pop(oldest, None)

    def _blocking_owners(
        self,
        owner: str,
        candidates: Iterable[_LeasePath],
    ) -> set[str]:
        blockers: set[str] = set()
        for candidate in candidates:
            exact_owner = self._exact_owners.get(candidate.key)
            if exact_owner:
                blockers.add(exact_owner)

            if not candidate.resolved_key:
                continue

            for prefix in (candidate.resolved_key, *candidate.ancestor_keys):
                blockers.update(self._directory_owners.get(prefix, ()))

            if candidate.is_dir:
                blockers.update(self._prefix_owners.get(candidate.resolved_key, ()))

        blockers.discard(owner)
        return blockers

    def _claim(
        self,
        owner: str,
        paths: Iterable[_LeasePath],
        *,
        ownership_version: tuple[tuple[str, int, int, int, int], ...] = (),
        deep_detect: bool = False,
    ) -> None:
        owner_paths = self._lease_paths.setdefault(owner, {})
        owned = self._owned.setdefault(owner, set())
        for path in paths:
            if path.key in owner_paths:
                continue
            owner_paths[path.key] = path
            owned.add(path.path)
            self._exact_owners[path.key] = owner
            self._entries_by_key[path.key] = path

            if path.resolved_key:
                if path.is_dir:
                    owners = self._directory_owners.setdefault(path.resolved_key, {})
                    owners[owner] = owners.get(owner, 0) + 1
                for prefix in (path.resolved_key, *path.ancestor_keys):
                    owners = self._prefix_owners.setdefault(prefix, {})
                    owners[owner] = owners.get(owner, 0) + 1

        if ownership_version:
            self._ownership_versions[owner] = ownership_version
            self._owner_modes[owner] = deep_detect
            self._generation_owners[(ownership_version, deep_detect)] = owner

    def _remove_owner(self, owner: str) -> bool:
        removed = self._remove_paths(owner, tuple(self._lease_paths.get(owner, {})))
        self._lease_paths.pop(owner, None)
        owned = self._owned.pop(owner, None)
        self._pins.pop(owner, None)
        self._pin_counts.pop(owner, None)
        ownership_version = self._ownership_versions.pop(owner, ())
        mode = self._owner_modes.pop(owner, False)
        if (
            ownership_version
            and self._generation_owners.get((ownership_version, mode)) == owner
        ):
            self._generation_owners.pop((ownership_version, mode), None)

        return owned is not None or removed or bool(ownership_version)

    def _remove_paths(self, owner: str, keys: Iterable[str]) -> bool:
        paths = self._lease_paths.get(owner, {})
        removed = False
        for key in keys:
            path = paths.pop(key, None)
            if path is None:
                continue
            removed = True
            self._owned[owner].discard(path.path)
            if self._exact_owners.get(path.key) == owner:
                self._exact_owners.pop(path.key, None)
                self._entries_by_key.pop(path.key, None)

            if path.resolved_key:
                if path.is_dir:
                    directory_owners = self._directory_owners.get(path.resolved_key)
                    if directory_owners is not None:
                        directory_owners[owner] -= 1
                        if not directory_owners[owner]:
                            directory_owners.pop(owner)
                        if not directory_owners:
                            self._directory_owners.pop(path.resolved_key, None)

                for prefix in (path.resolved_key, *path.ancestor_keys):
                    prefix_owners = self._prefix_owners.get(prefix)
                    if prefix_owners is None:
                        continue
                    prefix_owners[owner] -= 1
                    if not prefix_owners[owner]:
                        prefix_owners.pop(owner)
                    if not prefix_owners:
                        self._prefix_owners.pop(prefix, None)

        return removed

    def _register_waiter(self, blockers: set[str]) -> asyncio.Future[None]:
        waiter = asyncio.get_running_loop().create_future()
        frozen = frozenset(blockers)
        self._waiter_blockers[waiter] = frozen
        for blocker in frozen:
            self._waiters_by_blocker.setdefault(blocker, set()).add(waiter)
        return waiter

    def _unregister_waiter(self, waiter: asyncio.Future[None]) -> None:
        blockers = self._waiter_blockers.pop(waiter, ())
        for blocker in blockers:
            waiters = self._waiters_by_blocker.get(blocker)
            if waiters is None:
                continue
            waiters.discard(waiter)
            if not waiters:
                self._waiters_by_blocker.pop(blocker, None)

    def _wake_waiters_for(self, blocker: str) -> None:
        waiters = tuple(self._waiters_by_blocker.get(blocker, ()))
        for waiter in waiters:
            self._unregister_waiter(waiter)
            if not waiter.done():
                waiter.set_result(None)


def _replace_mapping_in_place(target: dict, source: dict) -> None:
    for key in tuple(target):
        if key not in source:
            target.pop(key, None)
    for key, value in source.items():
        current = target.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            _replace_mapping_in_place(current, value)
        else:
            target[key] = copy.deepcopy(value)


def _postprocess_actions_factory(config: dict, **kwargs):
    """Indirection point for callers that replace PostProcessActions."""

    return PostProcessActions(config, **kwargs)


def _worker_config(config: dict) -> dict:
    performance = config.get("performance") if isinstance(config.get("performance"), dict) else {}
    worker = performance.get("worker") if isinstance(performance.get("worker"), dict) else {}
    return dict(worker)


class _PipelineServices:
    """Thread-safe process services shared by all request runtimes."""

    def __init__(
        self,
        config: dict,
        broker: AsyncWorkBroker,
    ):
        self.config = config
        self.broker = broker
        self.output_reservations = OutputReservationRegistry()
        worker_config = _worker_config(config)
        self.sevenzip_runner = SevenZipRunner(worker_config)
        self._automatic_stage_capacity = int(worker_config.get("stage_thread_capacity", 0) or 0) == 0

    async def start(self) -> None:
        self.sevenzip_runner.bind_event_loop(asyncio.get_running_loop())
        handshake = await self.sevenzip_runner.start_asyncio()
        if self._automatic_stage_capacity:
            initial_limit = int(handshake.get("initial_active_limit", 0) or handshake.get("thread_capacity", 1) or 1)
            self.broker.configure_thread_capacity(initial_limit)

    async def close(self, broker: AsyncWorkBroker) -> None:
        await self.sevenzip_runner.aclose()

        def close_services() -> None:
            from sunpack.core.support.runtime_cache_cleanup import clear_all_runtime_caches

            clear_all_runtime_caches()

        await broker.run(
            "service_close",
            "engine",
            close_services,
            request_id="engine",
        )


class _SourceCleanup:
    """Shared-source refcount plus asynchronous source deletion."""

    def __init__(
        self,
        context: RunState,
        config: dict,
        factory: Callable[..., Any],
        request_id: str,
        *,
        notify: Callable = notify_shell_directories_updated,
    ):
        from sunpack.pipeline.coordinator.cleanup_refs import CleanupRefTable

        self._context = context
        self._config = config
        self._factory = factory
        self._notify = notify
        self.request_id = str(request_id or "")
        self._table = CleanupRefTable()

    def register(self, tasks) -> None:
        self._table.register_all(tasks)

    def release_task(self, task, *, outcome_kind):
        from sunpack.core.contracts.results import OutcomeKind

        self._table.refresh(task)
        if outcome_kind == OutcomeKind.COMPLETE_SUCCESS:
            self._table.mark_cleanup_eligible(task)
        return self._table.release(task)

    def sweep_requests(self):
        return self._table.sweep()

    async def apply(self, request, *, broker, cancellation=None):
        from sunpack.pipeline.coordinator.cleanup_refs import ReleaseOutcome, ReleaseRequest

        if not (request.paths and request.should_clean):
            return ReleaseOutcome(task_key=request.task_key, released=request.paths)

        # The promotion barrier inside the cleanup waits on lifecycle events
        # until every handle this process holds on the sources is released.
        # A sharing violation left after it belongs to another process, so it
        # is reported with the result instead of being retried on a timer.
        pending = tuple(request.cleanup_paths)
        outcome = await self._run_cleanup(
            ReleaseRequest(
                task_key=request.task_key,
                paths=pending,
                cleanup_paths=pending,
            ),
            broker=broker,
            cancellation=cancellation,
        )
        if outcome.failed:
            with self._context.lock:
                by_path = {path_key(item.path): item for item in self._context.cleanup_results}
                by_path.update({path_key(item.path): item for item in outcome.failed})
                self._context.cleanup_results[:] = list(by_path.values())

        return ReleaseOutcome(
            task_key=request.task_key,
            released=request.paths,
            deleted=outcome.deleted,
            failed=outcome.failed,
            error=outcome.error,
        )

    async def _run_cleanup(
        self,
        request,
        *,
        broker,
        cancellation=None,
    ):
        from sunpack.pipeline.coordinator.cleanup_refs import ReleaseOutcome
        from sunpack.core.support.archive_sessions import release_archive_sessions_under_roots
        from sunpack.core.support.resource_lifecycle import (
            ResourceBusyError,
            ResourceLifecycleError,
            promotion_barrier,
        )

        def run_cleanup():
            existing = [path for path in request.paths if os.path.exists(path)]
            results: list[ArchiveCleanupResult] = []
            error = ""
            if existing:
                try:
                    if self._mode() == "keep":
                        cleanup = ArchiveCleanup("keep", self._config.get("cli", {}).get("language", "en"))
                        results.extend(cleanup.cleanup_success_archives(
                            [[path] for path in existing],
                        ))
                    else:
                        actions = self._factory(self._config, stdout=None)
                        with promotion_barrier(
                            existing,
                            cache_releasers=(release_archive_sessions_under_roots,),
                            quiesce=False,
                        ):
                            results.extend(actions.apply(
                                archives_to_clean=[[path] for path in existing],
                                flatten_targets=[],
                            ))
                except (ResourceBusyError, ResourceLifecycleError) as exc:
                    error = str(exc)
                    code = int(getattr(exc, "winerror", 0) or 0)
                    results.extend(
                        ArchiveCleanupResult(
                            path,
                            self._mode(),
                            "failed",
                            code or 32,
                            f"cleanup barrier unavailable: {exc}",
                        )
                        for path in existing
                    )
            seen = {path_key(item.path) for item in results}
            results.extend(
                ArchiveCleanupResult(
                    path,
                    self._mode(),
                    "missing",
                )
                for path in request.paths
                if path_key(path) not in seen
            )
            by_path = {path_key(item.path): item for item in results}
            final = [by_path[path_key(path)] for path in request.paths if path_key(path) in by_path]
            deleted = tuple(item.path for item in final if item.status in {"recycled", "deleted"})
            return ReleaseOutcome(
                task_key=request.task_key,
                released=request.paths,
                deleted=deleted,
                failed=tuple(item for item in final if item.status == "failed"),
                error=error,
            )

        try:
            outcome = await broker.run(
                "background_source_cleanup",
                request.task_key or self.request_id,
                run_cleanup,
                request_id=self.request_id,
                cancellation=cancellation,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return ReleaseOutcome(
                task_key=request.task_key, released=request.paths, error=str(exc),
                failed=tuple(ArchiveCleanupResult(
                    path, self._mode(), "failed",
                    int(getattr(exc, "winerror", 0) or 0), str(exc),
                ) for path in request.paths),
            )
        if outcome.deleted:
            self._notify(
                tuple(dict.fromkeys(
                    os.path.dirname(path)
                    for path in outcome.deleted
                    if os.path.dirname(path)
                ))
            )
        return outcome

    def _mode(self) -> str:
        return str(self._config.get("post_extract", {}).get("archive_cleanup_mode", "recycle"))


class _ShellUpdateBatch:
    """Coalesce the current loop turn's notifications and release them on flush."""

    def __init__(self):
        self._paths: dict[str, str] = {}
        self._handle: asyncio.Handle | None = None

    def add(self, paths: Iterable[str]) -> None:
        for path in paths:
            if path:
                absolute = os.path.abspath(path)
                self._paths.setdefault(os.path.normcase(absolute), absolute)
        if self._paths and self._handle is None:
            self._handle = asyncio.get_running_loop().call_soon(self.flush)

    def flush(self) -> None:
        if self._handle is not None:
            self._handle.cancel()
            self._handle = None
        paths = tuple(self._paths.values())
        self._paths.clear()
        if paths:
            notify_shell_directories_updated(paths)


class _RequestRuntime:
    """All mutable state belonging to exactly one PipelineEngine submission."""

    def __init__(
        self,
        services: _PipelineServices,
        submission: _Submission,
        detection_options: EmbeddedOptions,
        path_leases: _PathLeaseRegistry,
    ):
        self.services = services
        self.submission = submission
        self.config = submission.config
        self.path_leases = path_leases
        cli_config = self.config["cli"]
        self.i18n = I18nContext(cli_config.get("language"))
        self.language = self.i18n.language
        self.quiet = bool(cli_config.get("quiet", False))
        self.verbose = bool(cli_config.get("verbose", False))
        self.context = RunState()
        self.reporter = RunReporter(
            language=self.language,
            quiet=self.quiet,
            verbose=self.verbose,
            stdout=submission.stdout,
            stderr=submission.stderr,
        )
        self._shell_updates = _ShellUpdateBatch()
        self.source_cleanup = _SourceCleanup(
            self.context,
            self.config,
            _postprocess_actions_factory,
            submission.request_id,
            notify=self._shell_updates.add,
        )
        self.task_scanner = ArchiveTaskScanner(
            self.config,
            self.context,
            detection_options=detection_options,
        )
        self.input_planning_stage = ArchiveInputPlanningStage(
            self.config,
        )
        self.output_scan_policy = NestedOutputScanPolicy(self.config)
        self.recursive_authorization = RecursiveAuthorization(self.config)
        performance = self.config.get("performance", {}) if isinstance(self.config.get("performance"), dict) else {}
        worker_config = dict(
            performance.get("worker", {})
            if isinstance(performance.get("worker"), dict)
            else {}
        )
        request_runner = services.sevenzip_runner.fork()
        request_runner.request_id = submission.request_id
        request_runner.origin = submission.origin
        self.extractor = ExtractionScheduler(
            cli_passwords=submission.user_passwords,
            builtin_passwords=submission.builtin_passwords,
            max_retries=self.config.get("max_retries", 3),
            process_config=worker_config,
            output_config=self.config.get("output", {}),
            extraction_config={
                **(self.config.get("extraction", {}) if isinstance(self.config.get("extraction"), dict) else {}),
                "language": self.language,
            },
            sevenzip_runner=request_runner,
            output_stream=submission.stdout,
        )
        self.extractor.set_progress_callback(self._report_progress)
        self.job_executor = ArchiveJobExecutor(
            self.context,
            self.extractor,
            self.config,
            progress_reporter=self.reporter,
            request_id=submission.request_id,
            origin=submission.origin,
        )
        self.recursion = self._new_recursion()
        self._active_task_keys: set[str] = set()
        self._cleanup_tasks: dict[asyncio.Task, tuple[str, ...]] = {}
        self._prompt_gates: dict[int, asyncio.Task] = {}

    def _report_progress(self, task: Any, event: dict[str, Any]) -> None:
        self.reporter.task_progress(task, event)
        callback = self.submission.progress_callback
        if callback is not None:
            try:
                callback(task, dict(event))
            except Exception:
                lifecycle_event = str(event.get("event") or "") in {
                    "task_sources_claimed",
                    "task_output_started",
                    "task_output_finished",
                }
                if getattr(self.submission, "origin", "") == "watch" and lifecycle_event:
                    # A durable start protects direct output writes. The finish
                    # event clears that record after verification.
                    raise
                # Ordinary progress observers remain best-effort UI/reporting.
                pass

    def _resolve_missing_volume_once(self, task, _outcome):
        current_paths = list(task.all_parts or [task.main_path])
        format_hint = task.archive_input().format_hint
        group = self.task_scanner.provider.resolve_volume_once_in_directory(
            current_paths,
            format_hint=format_hint,
        )
        if group is None:
            return None
        candidate = relation_group_to_candidate(group)
        replacement = ArchiveTask.from_archive_input(
            candidate.archive_input,
            discovery_source="relations",
            carrier_path=candidate.carrier_path,
            cleanup_paths=candidate.cleanup_paths,
            discovery_evidence=dict(candidate.relation_anchor),
        )
        if replacement is not None:
            replacement.runtime["volume_retry_attempted"] = True
            replacement.runtime["volume_retry_basis"] = [
                "confirmed_structure",
                "anchor_constrained_filename",
            ]
        if replacement is None:
            return None
        planned = self.input_planning_stage.plan_task_to_tasks(replacement)
        if len(planned) != 1:
            return None
        replacement = planned[0]
        return replacement

    async def execute_async(
        self,
        broker: AsyncWorkBroker,
        cancellation: CancellationToken,
    ) -> PipelineResponse:
        submission = self.submission
        request_id = submission.request_id
        roots = list(dict.fromkeys(target.path for target in submission.targets))
        ownership = _RequestResults(submission, self.config)

        try:
            if submission.direct:
                tasks = await broker.run(
                    "discover",
                    request_id,
                    self.task_scanner.direct_file_tasks,
                    roots,
                    request_id=request_id,
                    cancellation=cancellation,
                )
                await self._run_discovery_batch(
                    tasks,
                    roots=roots,
                    scan_session=None,
                    depth=1,
                    direct=True,
                    ownership=ownership,
                    broker=broker,
                    cancellation=cancellation,
                )
            else:
                await self._discover_and_run(
                    roots,
                    scan_session=None,
                    depth=1,
                    ownership=ownership,
                    broker=broker,
                    cancellation=cancellation,
                )

            await self._drain_cleanup_tasks()
            response = ownership.response(
                self.context,
                recent_passwords=self.extractor.recent_passwords,
            )
            return replace(
                response,
                summary=replace(response.summary, postprocess_completed=True),
            )
        finally:
            for request in self.source_cleanup.sweep_requests():
                self._schedule_cleanup(request, broker=broker, cancellation=cancellation)
            await self._drain_cleanup_tasks()
            self._shell_updates.flush()
            self.extractor.set_progress_callback(None)
            await broker.run(
                "extractor_close",
                request_id,
                self.extractor.close,
                request_id=request_id,
            )
            self.input_planning_stage.clear_report_cache()

    async def _discover_and_run(
        self,
        roots: list[str],
        *,
        scan_session,
        depth: int,
        ownership,
        broker,
        cancellation,
    ) -> bool:
        if not roots:
            return True
        self.reporter.scan_started(depth)
        discovered = await broker.run(
            "discover_detect",
            self.submission.request_id,
            self.task_scanner.discover_targets,
            roots,
            scan_session=scan_session,
            is_recursive_scan=depth > 1,
            request_id=self.submission.request_id,
            cancellation=cancellation,
        )
        return await self._run_discovery_batch(
            discovered,
            roots=roots,
            scan_session=scan_session or self.task_scanner.last_scan_session,
            depth=depth,
            direct=False,
            ownership=ownership,
            broker=broker,
            cancellation=cancellation,
        )

    async def _run_discovery_batch(
        self,
        tasks,
        *,
        roots: list[str],
        scan_session,
        depth: int,
        direct: bool,
        ownership,
        broker,
        cancellation,
    ) -> bool:
        authorization = await broker.run(
            "nested_policy",
            self.submission.request_id,
            self.recursive_authorization.authorize_batch,
            tasks,
            roots,
            scan_session or self.task_scanner.last_scan_session,
            depth=depth,
            request_id=self.submission.request_id,
            cancellation=cancellation,
        )
        candidates = (
            authorization.allowed_tasks
            if direct
            else self.task_scanner.filter_processed_tasks(authorization.allowed_tasks)
        )
        with self.context.lock:
            self.context.policy_skips.extend(authorization.skipped)
        tasks = self._claim_tasks(candidates)

        if self.submission.origin == "watch" and depth == 1 and tasks:
            member_paths = [
                path
                for task in tasks
                for path in (task.all_parts or [task.main_path])
            ]
            coalesced_owner = await self.path_leases.replace(
                self.submission.request_id,
                member_paths,
                coalesce_exact=True,
                deep_detect=self.submission.detection_options.force_scan,
            )
            if coalesced_owner:
                raise _CoalescedWatchRequest(coalesced_owner)

        # This registration is deliberately only a source-cleanup lifetime
        # guard. It never gates planning, extraction, verification or recursion.
        self.source_cleanup.register(tasks)
        self.reporter.tasks_discovered(depth, tasks, direct=direct)

        if self.submission.origin == "watch" and tasks:
            claimed_sources = tuple(dict.fromkeys(
                path
                for task in tasks
                for path in (task.cleanup_parts or task.all_parts or [task.main_path])
                if path
            ))
            self._report_progress(
                tasks[0],
                {
                    "type": "semantic",
                    "event": "task_sources_claimed",
                    "source_paths": claimed_sources,
                },
            )

        if tasks:
            await broker.run(
                "directory_passwords",
                self.submission.request_id,
                self.job_executor.directory_password_contexts.annotate,
                tasks,
                request_id=self.submission.request_id,
                cancellation=cancellation,
            )

        results = await asyncio.gather(
            *(
                self._execute_job(
                    task,
                    depth=depth,
                    ownership=ownership,
                    broker=broker,
                    cancellation=cancellation,
                )
                for task in tasks
            ),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, BaseException):
                raise result
        return all(results)

    def _claim_tasks(self, tasks):
        claimed = []
        with self.context.lock:
            processed = set(self.context.processed_keys)
            for task in tasks:
                key = str(task.key or task.main_path)
                if key in processed or key in self._active_task_keys:
                    continue
                self._active_task_keys.add(key)
                claimed.append(task)
        return claimed

    async def _execute_job(
        self,
        task,
        *,
        depth: int,
        ownership,
        broker,
        cancellation,
    ) -> bool:
        released_source_ref = False
        retain_watch_lease = False
        task_key = str(task.key or task.main_path)
        try:
            if self.input_planning_stage.requires_analysis(task):
                planned = await broker.run(
                    "plan", task_key, self._plan_task_isolated, task,
                    request_id=self.submission.request_id,
                    cancellation=cancellation,
                )
            else:
                cancellation.raise_if_cancelled()
                planned = [task]
            if len(planned) != 1 or planned[0] is not task:
                raise RuntimeError(
                    "Archive input planning must preserve one logical ArchiveTask identity"
                )

            ownership.remember_tasks([task])
            watch_version = self._watch_generation_for_task(task, depth=depth)
            if watch_version:
                task.runtime["source_generation"] = watch_version
            output_dir_resolver = build_output_dir_resolver(
                [task],
                ownership.output_dir_for_task,
                reservation_registry=self.services.output_reservations,
                owner=self.submission.request_id,
            )
            task, outcome, result = await self.job_executor.execute_async(
                task,
                depth=depth,
                output_dir_resolver=output_dir_resolver,
                broker=broker,
                cancellation=cancellation,
                missing_volume_retry=self._resolve_missing_volume_once,
                ensure_input_lease=lambda current: self._ensure_task_lease(current, depth=depth),
            )
            watch_version = task.runtime.get("source_generation", watch_version)
            retain_watch_lease = bool(watch_version and outcome.outcome_kind == OutcomeKind.COMPLETE_SUCCESS)
            ownership.remember_tasks([task])  # Missing-volume retry may adopt a complete family.
            promoted = False
            if _should_promote_blocked_input(depth, outcome.outcome_kind, result.failure):
                result, promoted = await self._promote_blocked_input(
                    task, result, ownership=ownership, broker=broker, cancellation=cancellation,
                )
            ownership.remember_results([result])
            output_dir = (
                result.output_dir
                if result.outcome_kind != OutcomeKind.FAILURE
                else ""
            )

            cleanup_request = self.source_cleanup.release_task(
                task,
                outcome_kind=outcome.outcome_kind,
            )
            released_source_ref = True
            self._schedule_cleanup(
                cleanup_request,
                broker=broker,
                cancellation=cancellation,
                lease_id=None if retain_watch_lease else id(task),
            )

            # Retryable nested inputs leave recursive ownership, but remain failed.
            subtree_complete = outcome.outcome_kind == OutcomeKind.COMPLETE_SUCCESS or promoted
            ran_recursive_children = False
            if output_dir and self.recursion.allows_children(depth):
                scan_work = await broker.run(
                    "nested_scan",
                    task_key,
                    self._nested_scan_work,
                    output_dir,
                    outcome.result,
                    request_id=self.submission.request_id,
                    cancellation=cancellation,
                )
                if scan_work.roots and await self._allow_recursive_depth(depth + 1):
                    ran_recursive_children = True
                    children_complete = await self._discover_and_run(
                        list(scan_work.roots),
                        scan_session=scan_work.session,
                        depth=depth + 1,
                        ownership=ownership,
                        broker=broker,
                        cancellation=cancellation,
                    )
                    subtree_complete = subtree_complete and children_complete

            if output_dir and subtree_complete:
                if ran_recursive_children:
                    # Recursion may consume the output tree; a zero-member
                    # archive's original empty output remains a valid result.
                    try:
                        os.rmdir(output_dir)
                    except OSError:
                        pass
                if not os.path.exists(output_dir):
                    ownership.forget_output(output_dir)
                    cleared = replace(result, output_dir="")
                    self._replace_target_result(result, cleared)
                    result = cleared
                    output_dir = ""

            if (
                output_dir
                and subtree_complete
                and self.config.get("post_extract", {}).get("flatten_single_directory", True)
            ):
                # Flatten mutates the output subtree namespace. Let cleanup remain
                # fully asynchronous during extraction/recursion, but finish only
                # cleanup operations whose source paths would be moved by this
                # particular flatten.
                await self._drain_cleanup_tasks_under(output_dir)
                flattened = await self._flatten_output(
                    task,
                    output_dir,
                    broker=broker,
                    cancellation=cancellation,
                )
                output_dir = flattened.output_dir
                subtree_complete = subtree_complete and not flattened.errors
                ownership.relocate_outputs(flattened)

            if watch_version and outcome.outcome_kind == OutcomeKind.COMPLETE_SUCCESS and output_dir:
                self.path_leases.remember_completed_watch(
                    watch_version, output_dir,
                    deep_detect=self.submission.detection_options.force_scan,
                )

            if output_dir:
                self._shell_updates.add([output_dir])
            return subtree_complete
        except _CompletedWatchOutput as reused:
            result = TargetRunResult(
                input_path=task.main_path, outcome_kind=OutcomeKind.COMPLETE_SUCCESS,
                task_key=task.key, output_dir=reused.output_dir,
                verification={"reused_completed_generation": True},
            )
            with self.context.lock:
                self.context.target_results.append(result)
                self.context.processed_keys.add(task.key)
            ownership.remember_tasks([task])
            ownership.remember_results([result])
            active_output = task.runtime.pop("watch_active_output", None)
            if active_output is not None:
                self.extractor.emit_semantic_event(
                    task, "task_output_finished", critical=True,
                    task_path=active_output[0], output_dir=active_output[1], keep_output=False,
                )
            return True
        finally:
            if retain_watch_lease:
                # Same-family retries can consume the completed generation only
                # after recursion/flatten has settled its final output location.
                await self.path_leases.release_lease(self.submission.request_id, id(task))
            if not released_source_ref:
                cleanup_request = self.source_cleanup.release_task(
                    task,
                    outcome_kind=OutcomeKind.FAILURE,
                )
                self._schedule_cleanup(
                    cleanup_request,
                    broker=broker,
                    cancellation=cancellation,
                    lease_id=id(task),
                )
            with self.context.lock:
                self._active_task_keys.discard(task_key)

    def _nested_scan_work(self, output_dir: str, extraction_result):
        logical_roots = []
        inventories = {}
        for logical_root, projected_inventory in self.output_scan_policy.project_logical_scan_roots(
            output_dir,
            extraction_result,
        ):
            logical_roots.append(logical_root)
            inventory = OutputInventory.from_value(
                projected_inventory,
                expected_root=logical_root,
            )
            if inventory is not None:
                inventories[os.path.normcase(os.path.abspath(logical_root))] = inventory
        return self.output_scan_policy.prepare_scan(
            [output_dir],
            inventories=inventories,
            logical_roots=logical_roots,
        )

    async def _allow_recursive_depth(self, depth: int) -> bool:
        if self.recursion.mode != "prompt":
            return True
        gate = self._prompt_gates.get(depth)
        if gate is None:
            gate = asyncio.create_task(
                self.recursion.prompt_continue(
                    depth - 1,
                    readline=self.submission.input_reader,
                    stdout=self.submission.stdout,
                )
            )
            self._prompt_gates[depth] = gate
        return bool(await gate)

    def _watch_generation_for_task(self, task, *, depth: int):
        if self.submission.origin != "watch" or depth != 1:
            return ()
        part_paths = tuple(task.archive_input().part_paths())
        if len(part_paths) < 2:
            return ()
        return self.path_leases.ownership_version_for(
            self.submission.request_id,
            part_paths,
        )

    def _schedule_cleanup(self, request, *, broker, cancellation, lease_id=None) -> None:
        if not request.should_clean and lease_id is None:
            return

        async def run_cleanup():
            try:
                if request.should_clean:
                    await self.source_cleanup.apply(
                        request,
                        broker=broker,
                        cancellation=cancellation,
                    )
            finally:
                if lease_id is not None:
                    await self.path_leases.release_lease(self.submission.request_id, lease_id)

        task = asyncio.create_task(run_cleanup())
        self._cleanup_tasks[task] = tuple(
            str(path) for path in request.cleanup_paths if path
        )

        def completed(done):
            self._cleanup_tasks.pop(done, None)
            try:
                done.result()
            except asyncio.CancelledError:
                pass
            except Exception:
                # Source cleanup is best-effort and never invalidates a verified
                # extraction. _SourceCleanup records actionable failures.
                pass

        task.add_done_callback(completed)

    async def _drain_cleanup_tasks(self) -> None:
        while self._cleanup_tasks:
            pending = tuple(self._cleanup_tasks)
            await asyncio.gather(*pending, return_exceptions=True)

    async def _drain_cleanup_tasks_under(self, root: str) -> None:
        while True:
            pending = tuple(
                task
                for task, cleanup_paths in self._cleanup_tasks.items()
                if not task.done()
                and any(self._cleanup_path_is_under(path, root) for path in cleanup_paths)
            )
            if not pending:
                return
            await asyncio.gather(*pending, return_exceptions=True)

    @staticmethod
    def _cleanup_path_is_under(path: str, root: str) -> bool:
        candidate = os.path.normcase(os.path.abspath(path))
        normalized_root = os.path.normcase(os.path.abspath(root))
        try:
            return os.path.commonpath((candidate, normalized_root)) == normalized_root
        except ValueError:
            return False

    def _replace_target_result(self, old, new) -> None:
        with self.context.lock:
            self.context.target_results[:] = [new if item is old else item for item in self.context.target_results]

    async def _promote_blocked_input(self, task, result, *, ownership, broker, cancellation):
        destination = ownership.input_dir_for_task(task)
        sources = tuple(task.cleanup_parts or task.all_parts or [task.main_path])
        # Watch admission must claim publication paths before any file appears;
        # leases additionally protect requests already admitted by Watch.
        destinations = [os.path.join(destination, os.path.basename(path)) for path in sources]
        await self.path_leases.acquire(
            self.submission.request_id, [*sources, *destinations], lease_id=id(task),
        )
        if self.submission.origin == "watch":
            self._report_progress(task, {
                "type": "semantic", "event": "task_sources_claimed",
                "source_paths": (*sources, *destinations),
            })

        def promote():
            with promotion_barrier(
                sources, cache_releasers=(release_archive_sessions_under_roots,), quiesce=False,
            ):
                return promote_blocked_input(sources, destination)

        promoted = False
        try:
            moved = await broker.run(
                "postprocess", task.key or task.main_path, promote,
                request_id=self.submission.request_id, cancellation=cancellation,
            )
            task.apply_path_mapping(moved.path_map)
            ownership.remap_task(task, result.input_path)
            updated = replace(result, input_path=task.main_path, failure_message="")
            self._shell_updates.add(moved.touched_dirs)
            promoted = True
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            residual_map = getattr(exc, "path_map", {})
            if residual_map:
                task.apply_path_mapping(residual_map)
                ownership.remap_task(task, result.input_path)
            failure = FailureInfo(
                FailureKind.FILESYSTEM_ERROR, "postprocess", f"Unable to promote blocked nested input: {exc}",
                details={"blocked_input_failure": result.failure.to_dict(), "destination": destination},
            )
            updated = replace(result, input_path=task.main_path, failure=failure, error=failure.message, failure_message="")
        self._replace_target_result(result, updated)
        return updated, promoted

    async def _flatten_output(self, task, output_dir: str, *, broker, cancellation) -> DirectoryFlattenResult:
        def flatten():
            with promotion_barrier(
                [output_dir],
                cache_releasers=(release_archive_sessions_under_roots,),
                quiesce=False,
            ):
                return _postprocess_actions_factory(
                    self.config,
                    stdout=self.submission.stdout,
                ).flattener.flatten_dirs(output_dir)

        try:
            result = await broker.run(
                "postprocess", task.key or task.main_path, flatten,
                request_id=self.submission.request_id, cancellation=cancellation,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            result = DirectoryFlattenResult(output_dir, output_dir, errors=(str(exc),))
        with self.context.lock:
            if result.source_dir:
                # Keep unrelated result identities stable: their coordinators
                # may still need to replace a record after recursive promotion.
                relocated_results = []
                for item in self.context.target_results:
                    relocated = result.relocate(item.output_dir)
                    relocated_results.append(
                        replace(item, output_dir=relocated) if relocated != item.output_dir else item
                    )
                self.context.target_results[:] = relocated_results
                self.context.cleanup_results[:] = [
                    replace(item, path=result.relocate(item.path))
                    for item in self.context.cleanup_results
                ]
            if result.errors:
                self.context.cleanup_results.append(ArchiveCleanupResult(
                    result.output_dir, "flatten", "failed", message="; ".join(result.errors),
                ))
        if result.source_dir:
            self.reporter.relocate_outputs(result)
        return result

    async def _ensure_task_lease(self, task, *, depth: int = 1) -> None:
        self.source_cleanup.register([task])
        paths = task.all_parts or [task.main_path]
        requested_version = (
            self.path_leases.input_version_for(paths)
            if self.submission.origin == "watch" and depth == 1 and len(paths) > 1 else ()
        )
        await self.path_leases.acquire(self.submission.request_id, paths, lease_id=id(task))
        if self.submission.origin == "watch" and depth == 1 and len(paths) > 1:
            # A missing-volume retry can replace its input set while awaiting
            # this lease. Check the final physical generation after acquisition.
            version = self.path_leases.input_version_for(paths, departed_version=requested_version)
            task.runtime["source_generation"] = version
            completed = self.path_leases.completed_watch_output(
                version, deep_detect=self.submission.detection_options.force_scan,
            )
            if completed:
                raise _CompletedWatchOutput(completed)
            self._report_progress(task, {
                "type": "semantic", "event": "task_sources_claimed",
                "source_paths": tuple(task.cleanup_parts or paths),
            })

    def _plan_task_isolated(self, task):
        stage = ArchiveInputPlanningStage(self.config)
        try:
            return stage.plan_task_to_tasks(task)
        finally:
            stage.clear_report_cache()

    def _new_recursion(self) -> RecursionController:
        config = self.config.get("recursive_extract", {"mode": "fixed", "max_rounds": 1})
        if not isinstance(config, dict):
            raise ValueError("recursive_extract must be normalized before PipelineEngine starts")
        return RecursionController(
            mode=str(config.get("mode", "fixed")),
            max_depth=int(config.get("max_rounds", 1)),
            language=self.language,
        )


class _CompletedWatchOutput(Exception):
    def __init__(self, output_dir: str):
        self.output_dir = output_dir


def _should_promote_blocked_input(depth: int, outcome: OutcomeKind, failure: FailureInfo | None) -> bool:
    return bool(
        depth > 1 and outcome == OutcomeKind.FAILURE and failure is not None
        and (failure.is_password_failure or failure.contains(FailureKind.MISSING_VOLUME))
    )


class _RequestResults:
    """Collect one request's outputs and preserve per-target output settings."""

    def __init__(self, submission: _Submission, config: dict):
        self.submission = submission
        self.config = config
        self._task_targets: dict[str, PipelineTarget] = {}
        self._output_targets: dict[str, PipelineTarget] = {}
        self._claimed_paths: list[str] = []
        self._task_paths: dict[str, tuple[str, ...]] = {}
        self._target_input_dirs = {
            path_key(target.path): os.path.abspath(target.path if os.path.isdir(target.path) else os.path.dirname(target.path))
            for target in submission.targets
        }

    def input_dir_for_task(self, task) -> str:
        return self._target_input_dirs[path_key(self._target_for_path(task.main_path).path)]

    def forget_output(self, output_dir: str) -> None:
        self._output_targets.pop(path_key(output_dir), None)

    def remap_task(self, task, old_path: str) -> None:
        target = self._target_for_path(old_path)
        self._task_targets[path_key(task.main_path)] = target
        self._task_paths.pop(path_key(old_path), None)
        self._task_paths[path_key(task.main_path)] = tuple(task.cleanup_parts or task.all_parts or [task.main_path])

    def remember_tasks(self, tasks) -> None:
        for task in tasks:
            target = self._target_for_path(task.main_path)
            paths = tuple(dict.fromkeys(task.all_parts or [task.main_path]))
            self._task_targets[path_key(task.main_path)] = target
            self._claimed_paths.extend(paths)
            self._task_paths[path_key(task.main_path)] = paths

    def remember_results(self, results) -> None:
        for result in results:
            if not result.output_dir:
                continue
            target = self._target_for_path(result.input_path)
            self._output_targets[path_key(result.output_dir)] = target

    def relocate_outputs(self, result: DirectoryFlattenResult) -> None:
        if not result.source_dir:
            return
        self._output_targets = {
            path_key(result.relocate(path)): target
            for path, target in self._output_targets.items()
        }

    def output_dir_for_task(self, task) -> str:
        target = self._target_for_path(task.main_path)
        output_config = {
            **(self.config.get("output", {}) if isinstance(self.config.get("output"), dict) else {}),
            **dict(target.output),
        }
        return default_output_dir_for_task(task, output_config)

    def response(self, context: RunState, *, recent_passwords: Iterable[str]) -> PipelineResponse:
        request_results = list(context.target_results)
        summary = context.snapshot(
            target_results=request_results,
            scan_failed_tasks=list(context.scan_failed_tasks),
            scan_failures=list(context.scan_failures),
            policy_skips=list(context.policy_skips),
        )
        blocked_paths = []
        for result in request_results:
            if result.outcome_kind == OutcomeKind.COMPLETE_SUCCESS:
                continue
            blocked_paths.extend(
                self._task_paths.get(
                    path_key(result.input_path),
                    (result.input_path,),
                )
            )
        return PipelineResponse(
            request_id=self.submission.request_id,
            summary=summary,
            artifacts=PipelineArtifacts(
                shell_refresh_paths=tuple(dict.fromkeys([
                    *(
                        result.output_dir
                        for result in request_results
                        if result.outcome_kind in {
                            OutcomeKind.COMPLETE_SUCCESS,
                            OutcomeKind.PARTIAL_SUCCESS,
                        }
                        and result.output_dir
                    ),
                    *(
                        str(item.get("out_dir") or "")
                        for item in summary.recovered_outputs
                        if str(item.get("out_dir") or "")
                    ),
                ])),
            ),
            discovery=PipelineDiscovery(
                entry_paths=tuple(target.path for target in self.submission.targets),
                claimed_paths=tuple(dict.fromkeys(self._claimed_paths)),
                blocked_paths=tuple(dict.fromkeys(blocked_paths)),
            ),
            recent_passwords=tuple(recent_passwords),
        )

    def _target_for_path(self, path: str) -> PipelineTarget:
        normalized = os.path.abspath(path)
        key = path_key(normalized)
        known = self._task_targets.get(key)
        if known is not None:
            return known

        exact = [
            target
            for target in self.submission.targets
            if path_key(target.path) == key
        ]
        if exact:
            return exact[0]

        output_matches = [
            (len(output_root), target)
            for output_root, target in self._output_targets.items()
            if output_root == key or _is_relative_to(normalized, output_root)
        ]
        if output_matches:
            return max(output_matches, key=lambda item: item[0])[1]

        containing = [
            target
            for target in self.submission.targets
            if os.path.isdir(target.path) and _is_relative_to(normalized, target.path)
        ]
        if containing:
            return max(containing, key=lambda target: len(target.path))
        return self.submission.targets[0]


def _is_relative_to(path: str, root: str) -> bool:
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (OSError, ValueError):
        return False
