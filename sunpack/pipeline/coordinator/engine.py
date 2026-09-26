from __future__ import annotations

import copy
import asyncio
import os
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterable, TextIO

from sunpack.pipeline.discovery.detection.input_planning import ArchiveInputPlanningStage
from sunpack.core.contracts.pipeline import PipelineArtifacts, PipelineDiscovery, PipelineResponse, PipelineTarget
from sunpack.core.contracts.results import ArchiveCleanupResult, OutcomeKind, TargetRunResult
from sunpack.core.contracts.run_state import RunState
from sunpack.pipeline.coordinator.archive_job import ArchiveJobExecutor
from sunpack.pipeline.coordinator.output_scan_policy import NestedOutputScanPolicy
from sunpack.pipeline.coordinator.recursive_authorization import RecursiveAuthorization
from sunpack.pipeline.coordinator.recursion import RecursionController
from sunpack.pipeline.coordinator.reporting import RunReporter
from sunpack.pipeline.coordinator.task_scan import ArchiveTaskScanner
from sunpack.pipeline.coordinator.target_groups import relation_group_to_candidate
from sunpack.pipeline.extraction.scheduler import ExtractionScheduler
from sunpack.pipeline.extraction.output_inventory import OutputInventory
from sunpack.core.i18n import I18nContext
from sunpack.pipeline.postprocess.actions import PostProcessActions
from sunpack.core.passwords.internal.store import MAX_RECENT_PASSWORDS
from sunpack.core.platform.windows.shell_notify import notify_shell_directories_updated
from sunpack.core.support.output_reservation import OutputReservationRegistry, build_output_dir_resolver
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner
from sunpack.core.support.output_paths import default_output_dir_for_task
from sunpack.core.support.path_keys import path_key
from sunpack.core.support.archive_sessions import release_archive_sessions_under
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
    detection_options: EmbeddedOptions | None = None
    stdout: TextIO | None = None
    stderr: TextIO | None = None
    progress_callback: Callable[[Any, dict[str, Any]], None] | None = None


async def _commit_response(broker, config, response, *, stdout=None):
    response = await broker.run(
        "postprocess",
        response.request_id,
        _finalize_response,
        config,
        response,
        stdout=stdout,
        request_id=response.request_id,
    )
    for delay in (0.1, 0.3):
        pending = [item for item in response.summary.cleanup_results if item.retryable and item.attempts < 3]
        if not pending:
            break
        await asyncio.sleep(delay)
        response = await broker.run(
            "postprocess",
            response.request_id,
            _finalize_response,
            config,
            response,
            stdout=stdout,
            retry_results=pending,
            request_id=response.request_id,
        )
    return response


class PipelineEngine:
    """Single-event-loop owner for independently completing requests."""

    def __init__(self, config: dict, detection_options: EmbeddedOptions | None = None):
        self.config = config
        self.detection_options = detection_options or EmbeddedOptions()
        worker_config = _worker_config(config)
        self._broker = AsyncWorkBroker(
            thread_capacity=int(worker_config.get("stage_thread_capacity", 0) or 0),
            max_pending_jobs=int(
                worker_config.get("max_pending_stage_jobs", worker_config.get("max_queue_jobs", 4096)) or 4096
            ),
        )
        self._services = _PipelineServices(config, self._broker, self.detection_options)
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
            detection_options=detection_options or self.detection_options,
            stdout=stdout,
            stderr=stderr,
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
                    submission.detection_options or self.detection_options,
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
                response = await _commit_response(
                    self._broker,
                    submission.config,
                    response,
                    stdout=stdout,
                )
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


class _PathLeaseRegistry:
    _COMPLETED_WATCH_LIMIT = 4096

    def __init__(self):
        self._owned: dict[str, set[str]] = {}
        self._ownership_versions: dict[str, tuple[tuple[str, int, int, int, int], ...]] = {}
        self._completed_watch_generations: dict[
            tuple[str, ...],
            tuple[tuple[tuple[str, int, int, int, int], ...], str],
        ] = {}
        self._changed = asyncio.Condition()

    async def acquire(self, owner: str, paths: Iterable[str]) -> None:
        normalized = {os.path.abspath(os.path.normpath(path)) for path in paths if path}
        async with self._changed:
            await self._changed.wait_for(lambda: not self._conflicts(owner, normalized))
            self._owned.setdefault(owner, set()).update(normalized)

    async def replace(
        self,
        owner: str,
        paths: Iterable[str],
        *,
        coalesce_exact: bool = False,
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
        normalized = {os.path.abspath(os.path.normpath(path)) for path in paths if path}
        ownership_version = _physical_ownership_version(normalized) if coalesce_exact else ()
        async with self._changed:
            previous = self._owned.pop(owner, None)
            self._ownership_versions.pop(owner, None)
            if previous is not None:
                self._changed.notify_all()
            if coalesce_exact:
                exact_owner = self._exact_owner(owner, normalized, ownership_version)
                if exact_owner:
                    return exact_owner
            await self._changed.wait_for(lambda: not self._conflicts(owner, normalized))
            self._owned[owner] = normalized
            if coalesce_exact:
                self._ownership_versions[owner] = ownership_version
            self._changed.notify_all()
            return None

    async def release(self, owner: str) -> None:
        async with self._changed:
            released = self._owned.pop(owner, None)
            self._ownership_versions.pop(owner, None)
            if released is not None:
                self._changed.notify_all()

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

    def completed_watch_output(
        self,
        ownership_version: tuple[tuple[str, int, int, int, int], ...],
    ) -> str:
        """Return the prior output only for the exact unchanged physical generation."""
        if not ownership_version:
            return ""
        key = tuple(row[0] for row in ownership_version)
        record = self._completed_watch_generations.get(key)
        if record is None:
            return ""
        recorded_version, output_dir = record
        if recorded_version != ownership_version or not output_dir or not os.path.isdir(output_dir):
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
    ) -> None:
        if not ownership_version or not output_dir:
            return
        key = tuple(row[0] for row in ownership_version)
        record = (ownership_version, os.path.abspath(os.path.normpath(output_dir)))
        self._completed_watch_generations.pop(key, None)
        self._completed_watch_generations[key] = record
        while len(self._completed_watch_generations) > self._COMPLETED_WATCH_LIMIT:
            oldest = next(iter(self._completed_watch_generations))
            self._completed_watch_generations.pop(oldest, None)

    def _exact_owner(
        self,
        owner: str,
        candidates: set[str],
        ownership_version: tuple[tuple[str, int, int, int, int], ...],
    ) -> str:
        if not candidates or not ownership_version:
            return ""
        candidate_keys = {path_key(path) for path in candidates}
        for current_owner, current_paths in self._owned.items():
            if current_owner == owner:
                continue
            if (
                {path_key(path) for path in current_paths} == candidate_keys
                and self._ownership_versions.get(current_owner) == ownership_version
            ):
                return current_owner
        return ""

    def _conflicts(self, owner: str, candidates: set[str]) -> bool:
        for current_owner, current_paths in self._owned.items():
            if current_owner == owner:
                continue
            for candidate in candidates:
                for current in current_paths:
                    if path_key(candidate) == path_key(current):
                        return True
                    if os.path.isdir(candidate) and _is_relative_to(current, candidate):
                        return True
                    if os.path.isdir(current) and _is_relative_to(candidate, current):
                        return True
        return False



def _physical_ownership_version(
    paths: Iterable[str],
) -> tuple[tuple[str, int, int, int, int], ...]:
    """Cheap byte-version identity for Watch request coalescing.

    Paths alone are insufficient: a volume may receive new bytes while an
    earlier request is still active. Size/mtime plus filesystem identity keeps
    same-version duplicate events cheap without swallowing a newer arrival.
    """

    rows = []
    for raw_path in paths:
        normalized = os.path.abspath(os.path.normpath(raw_path))
        try:
            stat = os.stat(normalized)
        except OSError:
            return ()
        rows.append((
            path_key(normalized),
            int(stat.st_dev),
            int(stat.st_ino),
            int(stat.st_size),
            int(stat.st_mtime_ns),
        ))
    rows.sort(key=lambda row: row[0])
    return tuple(rows)

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
        detection_options: EmbeddedOptions | None = None,
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


class _CleanupRefScope:
    def __init__(self, context: RunState, config: dict, factory: Callable[..., Any]):
        from sunpack.pipeline.coordinator.cleanup_refs import CleanupRefTable

        self._context = context
        self._config = config
        self._factory = factory
        self.request_id = ""
        self._table = CleanupRefTable()

    def bind(self, request_id: str) -> "_CleanupRefScope":
        self.request_id = str(request_id or "")
        self._context.cleanup_refs[self.request_id] = self._table
        return self

    def register(self, tasks) -> None:
        self._table.register_all(tasks)

    def release_task(self, task, *, outcome_kind):
        from sunpack.core.contracts.results import OutcomeKind

        if outcome_kind == OutcomeKind.COMPLETE_SUCCESS:
            self._table.mark_cleanup_eligible(task)
        return self._table.release(task)

    def sweep_requests(self):
        return self._table.sweep()

    async def apply(self, request, *, broker, cancellation=None):
        from sunpack.pipeline.coordinator.cleanup_refs import ReleaseOutcome

        if not (request.paths and request.should_clean):
            return ReleaseOutcome(task_key=request.task_key, released=request.paths)
        return await self._apply(request, broker=broker, cancellation=cancellation)

    async def _apply(self, request, *, broker, cancellation=None) -> "ReleaseOutcome":
        from sunpack.pipeline.coordinator.cleanup_refs import ReleaseOutcome
        from sunpack.core.support.archive_sessions import release_archive_sessions_under
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
                    actions = self._factory(self._config, stdout=None)
                    if self._mode() == "keep":
                        # Keeping sources is not a filesystem mutation.  Do not
                        # establish a source promotion barrier merely to produce
                        # the corresponding "kept" cleanup results.
                        results.extend(
                            actions.apply(
                                archives_to_clean=[[path] for path in existing],
                                flatten_targets=[],
                            )
                        )
                    else:
                        with promotion_barrier(
                            existing,
                            cache_releasers=(release_archive_sessions_under,),
                            quiesce=False,
                        ):
                            results.extend(
                                actions.apply(
                                    archives_to_clean=[[path] for path in existing],
                                    flatten_targets=[],
                                )
                            )
                except (ResourceBusyError, ResourceLifecycleError) as exc:
                    error = str(exc)
                    code = int(getattr(exc, "winerror", 0) or 0)
                    results.extend(
                        ArchiveCleanupResult(
                            path,
                            self._mode(),
                            "failed",
                            1,
                            code or 32,
                            f"cleanup barrier unavailable: {exc}",
                        )
                        for path in existing
                    )
            # A path that was already gone is reported as missing, so the summary still accounts for every source.
            seen = {item.path for item in results}
            results.extend(
                ArchiveCleanupResult(path, self._mode(), "missing")
                for path in request.paths
                if path not in seen
            )
            ordered = {item.path: item for item in results}
            final = [ordered[path] for path in request.paths if path in ordered]
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
                "postprocess",
                request.task_key or self.request_id,
                run_cleanup,
                request_id=self.request_id,
                cancellation=cancellation,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # A closed or unavailable broker must not fail the extraction; the sources stay in place.
            return ReleaseOutcome(task_key=request.task_key, released=request.paths, error=str(exc))
        if outcome.deleted:
            # The deleted sources are gone, so refresh their folders.
            notify_shell_directories_updated(
                tuple(dict.fromkeys(os.path.dirname(path) for path in outcome.deleted if os.path.dirname(path)))
            )
        if outcome.failed:
            with self._context.lock:
                known = {path_key(item.path) for item in self._context.cleanup_results}
                self._context.cleanup_results.extend(
                    item for item in outcome.failed if path_key(item.path) not in known
                )
        return outcome

    def _mode(self) -> str:
        return str(self._config.get("post_extract", {}).get("archive_cleanup_mode", "recycle"))


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
        cli_config = self.config.get("cli") if isinstance(self.config.get("cli"), dict) else {}
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
        self.cleanup_scope = _CleanupRefScope(
            self.context,
            self.config,
            _postprocess_actions_factory,
        ).bind(submission.request_id)
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
        self._cleanup_tasks: set[asyncio.Task] = set()
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
        replacement = self.task_scanner.provider.task_from_candidate(candidate)
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
        ownership = _RequestOwnership([submission], self.config)

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
            return ownership.responses(
                self.context,
                recent_passwords=self.extractor.recent_passwords,
            )[request_id]
        finally:
            for request in self.cleanup_scope.sweep_requests():
                self._schedule_cleanup(request, broker=broker, cancellation=cancellation)
            await self._drain_cleanup_tasks()
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
    ) -> None:
        if not roots:
            return
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
        await self._run_discovery_batch(
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
    ) -> None:
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
            )
            if coalesced_owner:
                raise _CoalescedWatchRequest(coalesced_owner)

        # This registration is deliberately only a source-cleanup lifetime
        # guard. It never gates planning, extraction, verification or recursion.
        self.cleanup_scope.register(tasks)
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
    ) -> None:
        released_source_ref = False
        task_key = str(task.key or task.main_path)
        try:
            planned = await broker.run(
                "plan",
                task_key,
                self._plan_task_isolated,
                task,
                request_id=self.submission.request_id,
                cancellation=cancellation,
            )
            if len(planned) != 1 or planned[0] is not task:
                raise RuntimeError(
                    "Archive input planning must preserve one logical ArchiveTask identity"
                )

            ownership.remember_tasks([task])
            watch_version = self._watch_generation_for_task(task)
            if watch_version:
                completed_output = self.path_leases.completed_watch_output(watch_version)
                if completed_output:
                    with self.context.lock:
                        self.context.target_results.append(TargetRunResult(
                            input_path=task.main_path,
                            outcome_kind=OutcomeKind.COMPLETE_SUCCESS,
                            task_key=task.key,
                            output_dir=completed_output,
                            verification={"reused_completed_generation": True},
                        ))
                        self.context.processed_keys.add(task.key)
                    cleanup_request = self.cleanup_scope.release_task(
                        task,
                        outcome_kind=OutcomeKind.FAILURE,
                    )
                    released_source_ref = True
                    self._schedule_cleanup(
                        cleanup_request,
                        broker=broker,
                        cancellation=cancellation,
                    )
                    return

            output_dir_resolver = build_output_dir_resolver(
                [task],
                ownership.output_dir_for_task,
                reservation_registry=self.services.output_reservations,
                owner=self.submission.request_id,
            )
            task, outcome, output_dir = await self.job_executor.execute_async(
                task,
                depth=depth,
                output_dir_resolver=output_dir_resolver,
                broker=broker,
                cancellation=cancellation,
                missing_volume_retry=self._resolve_missing_volume_once,
                ensure_input_lease=self._ensure_task_lease,
            )

            cleanup_request = self.cleanup_scope.release_task(
                task,
                outcome_kind=outcome.outcome_kind,
            )
            released_source_ref = True
            self._schedule_cleanup(
                cleanup_request,
                broker=broker,
                cancellation=cancellation,
            )

            if (
                watch_version
                and outcome.outcome_kind == OutcomeKind.COMPLETE_SUCCESS
                and output_dir
            ):
                self.path_leases.remember_completed_watch(
                    watch_version,
                    output_dir,
                )

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
                if scan_work.roots and await self._allow_recursive_depth(
                    depth + 1,
                    broker=broker,
                    cancellation=cancellation,
                ):
                    await self._discover_and_run(
                        list(scan_work.roots),
                        scan_session=scan_work.session,
                        depth=depth + 1,
                        ownership=ownership,
                        broker=broker,
                        cancellation=cancellation,
                    )

            if (
                output_dir
                and outcome.outcome_kind == OutcomeKind.COMPLETE_SUCCESS
                and self.config.get("post_extract", {}).get("flatten_single_directory", True)
            ):
                await self._flatten_output(
                    task,
                    output_dir,
                    broker=broker,
                    cancellation=cancellation,
                )
        finally:
            if not released_source_ref:
                cleanup_request = self.cleanup_scope.release_task(
                    task,
                    outcome_kind=OutcomeKind.FAILURE,
                )
                self._schedule_cleanup(
                    cleanup_request,
                    broker=broker,
                    cancellation=cancellation,
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

    async def _allow_recursive_depth(self, depth: int, *, broker, cancellation) -> bool:
        if self.recursion.mode != "prompt":
            return True
        gate = self._prompt_gates.get(depth)
        if gate is None:
            gate = asyncio.create_task(
                broker.run(
                    "prompt",
                    self.submission.request_id,
                    self.recursion.prompt_continue,
                    depth - 1,
                    request_id=self.submission.request_id,
                    cancellation=cancellation,
                )
            )
            self._prompt_gates[depth] = gate
        return bool(await gate)

    def _watch_generation_for_task(self, task):
        if self.submission.origin != "watch":
            return ()
        part_paths = tuple(task.archive_input().part_paths())
        if len(part_paths) < 2:
            return ()
        carrier = str(task.carrier_path or "")
        part_keys = {path_key(path) for path in part_paths}
        if not carrier or path_key(carrier) in part_keys:
            return ()
        return _physical_ownership_version(part_paths)

    def _schedule_cleanup(self, request, *, broker, cancellation) -> None:
        if not (request.paths and request.should_clean):
            return

        async def run_cleanup():
            await self.cleanup_scope.apply(
                request,
                broker=broker,
                cancellation=cancellation,
            )

        task = asyncio.create_task(run_cleanup())
        self._cleanup_tasks.add(task)

        def completed(done):
            self._cleanup_tasks.discard(done)
            try:
                done.result()
            except asyncio.CancelledError:
                pass
            except Exception:
                # Source cleanup is best-effort and never invalidates a verified
                # extraction. _CleanupRefScope records actionable failures.
                pass

        task.add_done_callback(completed)

    async def _drain_cleanup_tasks(self) -> None:
        while self._cleanup_tasks:
            pending = tuple(self._cleanup_tasks)
            await asyncio.gather(*pending, return_exceptions=True)

    async def _flatten_output(self, task, output_dir: str, *, broker, cancellation) -> None:
        def flatten():
            with promotion_barrier(
                [output_dir],
                cache_releasers=(release_archive_sessions_under,),
                quiesce=False,
            ):
                _postprocess_actions_factory(
                    self.config,
                    stdout=self.submission.stdout,
                ).apply(
                    cleanup_archives=False,
                    flatten_targets=[output_dir],
                )

        await broker.run(
            "postprocess",
            task.key or task.main_path,
            flatten,
            request_id=self.submission.request_id,
            cancellation=cancellation,
        )

    async def _ensure_task_lease(self, task) -> None:
        paths = task.all_parts or [task.main_path]
        await self.path_leases.acquire(self.submission.request_id, paths)

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


def _finalize_response(
    config: dict,
    response: PipelineResponse,
    *,
    stdout=None,
    retry_results=None,
) -> PipelineResponse:
    if response.summary.postprocess_completed and retry_results is None:
        return response
    shell_refresh_paths = list(response.artifacts.shell_refresh_paths)
    previous = None
    cleanup_requests = ()
    if retry_results is not None:
        # Only failed cleanups are retried here; successful sources are already removed task by task.
        shell_refresh_paths = []
        cleanup_requests = tuple((item.path,) for item in retry_results)
        previous = {path_key(item.path): item for item in retry_results}
    mutation_roots = [path for family in cleanup_requests for path in family]
    if mutation_roots:
        with promotion_barrier(
            mutation_roots,
            cache_releasers=(release_archive_sessions_under,),
        ):
            cleanup_results = PostProcessActions(config, stdout=stdout).apply(
                archives_to_clean=list(cleanup_requests),
                flatten_targets=[],
                previous_cleanup=previous,
            )
    else:
        cleanup_results = PostProcessActions(config, stdout=stdout).apply(
            archives_to_clean=list(cleanup_requests),
            flatten_targets=[],
            previous_cleanup=previous,
        )
    notify_shell_directories_updated(shell_refresh_paths)
    merged = {path_key(item.path): item for item in response.summary.cleanup_results}
    merged.update({path_key(item.path): item for item in cleanup_results})
    return replace(response, summary=replace(
        response.summary,
        cleanup_results=tuple(merged.values()),
        postprocess_completed=True,
    ))


class _RequestOwnership:
    def __init__(self, submissions: list[_Submission], config: dict):
        self.submissions = submissions
        self.config = config
        self._task_owner: dict[str, str] = {}
        self._claimed_paths: dict[str, list[str]] = {item.request_id: [] for item in submissions}
        self._task_paths: dict[str, dict[str, tuple[str, ...]]] = {item.request_id: {} for item in submissions}
        self._output_owner: dict[str, str] = {}

    def remember_tasks(self, tasks) -> None:
        for task in tasks:
            owner = self.owner_for_path(task.main_path)
            owner_id = owner.request_id
            paths = tuple(dict.fromkeys(task.all_parts or [task.main_path]))
            self._task_owner[path_key(task.main_path)] = owner_id
            self._claimed_paths[owner_id].extend(paths)
            self._task_paths[owner_id][path_key(task.main_path)] = paths

    def remember_results(self, results) -> None:
        for result in results:
            owner = self.owner_for_path(result.input_path)
            if result.output_dir:
                self._output_owner[path_key(result.output_dir)] = owner.request_id

    def output_dir_for_task(self, task) -> str:
        owner = self.owner_for_path(task.main_path)
        target = self._target_for_path(owner, task.main_path)
        output_config = {
            **(self.config.get("output", {}) if isinstance(self.config.get("output"), dict) else {}),
            **dict(target.output),
        }
        return default_output_dir_for_task(task, output_config)

    def owner_for_path(self, path: str) -> _Submission:
        normalized = os.path.abspath(path)
        known = self._task_owner.get(path_key(normalized)) or self._owner_for_output(normalized)
        if known:
            return self._submission(known)
        exact = []
        containing = []
        for submission in self.submissions:
            for target in submission.targets:
                if path_key(target.path) == path_key(normalized):
                    exact.append(submission)
                elif os.path.isdir(target.path) and _is_relative_to(normalized, target.path):
                    containing.append((len(target.path), submission))
        if exact:
            return exact[0]
        if containing:
            return max(containing, key=lambda item: item[0])[1]
        return self.submissions[0]

    def responses(self, context: RunState, *, recent_passwords: Iterable[str]) -> dict[str, PipelineResponse]:
        results = {item.request_id: [] for item in self.submissions}
        for result in context.target_results:
            results[self.owner_for_path(result.input_path).request_id].append(result)
        responses = {}
        for submission in self.submissions:
            request_results = results[submission.request_id]
            if len(self.submissions) == 1:
                scan_failed_tasks = list(context.scan_failed_tasks)
                scan_failures = list(context.scan_failures)
            else:
                scan_failed_tasks = []
                scan_failures = [
                    failure
                    for failure in context.scan_failures
                    if self._failure_owner(failure) == submission.request_id
                ]
            summary = context.snapshot(
                target_results=request_results,
                scan_failed_tasks=scan_failed_tasks,
                scan_failures=scan_failures,
                policy_skips=[
                    item
                    for item in context.policy_skips
                    if self.owner_for_path(str(item.get("path") or "")).request_id
                    == submission.request_id
                ],
            )
            blocked_paths = []
            for result in request_results:
                if result.outcome_kind == OutcomeKind.COMPLETE_SUCCESS:
                    continue
                blocked_paths.extend(
                    self._task_paths[submission.request_id].get(
                        path_key(result.input_path),
                        (result.input_path,),
                    )
                )
            responses[submission.request_id] = PipelineResponse(
                request_id=submission.request_id,
                summary=summary,
                artifacts=PipelineArtifacts(
                    flatten_targets=(),
                    shell_refresh_paths=tuple(dict.fromkeys([
                        *(
                            result.output_dir
                            for result in request_results
                            if result.outcome_kind in {OutcomeKind.COMPLETE_SUCCESS, OutcomeKind.PARTIAL_SUCCESS}
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
                    entry_paths=tuple(target.path for target in submission.targets),
                    claimed_paths=tuple(dict.fromkeys(self._claimed_paths[submission.request_id])),
                    blocked_paths=tuple(dict.fromkeys(blocked_paths)),
                ),
                recent_passwords=tuple(recent_passwords),
            )
        return responses

    def _target_for_path(self, submission: _Submission, path: str) -> PipelineTarget:
        exact = [target for target in submission.targets if path_key(target.path) == path_key(path)]
        if exact:
            return exact[0]
        containing = [target for target in submission.targets if os.path.isdir(target.path) and _is_relative_to(path, target.path)]
        return max(containing, key=lambda target: len(target.path)) if containing else submission.targets[0]

    def _owner_for_output(self, path: str) -> str:
        normalized = os.path.abspath(path)
        matches = [
            (len(output), owner)
            for output_key, owner in self._output_owner.items()
            for output in [output_key]
            if output_key == path_key(normalized) or _is_relative_to(normalized, output_key)
        ]
        return max(matches, default=(0, ""), key=lambda item: item[0])[1]

    def _failure_owner(self, failure) -> str:
        details = getattr(failure, "details", {})
        path = str(details.get("path") or details.get("archive") or "") if isinstance(details, dict) else ""
        return self.owner_for_path(path).request_id if path else ""

    def _submission(self, request_id: str) -> _Submission:
        return next(item for item in self.submissions if item.request_id == request_id)


def _is_relative_to(path: str, root: str) -> bool:
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (OSError, ValueError):
        return False
