from __future__ import annotations

import copy
import asyncio
import os
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol, TextIO

from sunpack.detection.input_planning import ArchiveInputPlanningStage
from sunpack.repair_inspection import RepairInspectionService
from sunpack.contracts.pipeline import PipelineArtifacts, PipelineResponse, PipelineTarget
from sunpack.contracts.results import ArchiveCleanupResult, OutcomeKind, RunSummary
from sunpack.contracts.run_context import RunContext
from sunpack.coordinator.extraction_batch import ExtractionBatchRunner
from sunpack.coordinator.output_scan_policy import NestedOutputScanPolicy
from sunpack.coordinator.nested_extraction_policy import NestedExtractionPolicy
from sunpack.coordinator.nested_extraction_policy import EMBEDDED_SCAN_ALLOWED_FACT
from sunpack.coordinator.recursion import RecursionController
from sunpack.coordinator.reporting import RunReporter
from sunpack.coordinator.task_scan import ArchiveTaskScanner
from sunpack.coordinator.target_groups import relation_group_to_fact_bag
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.i18n import I18nContext
from sunpack.postprocess.actions import PostProcessActions
from sunpack.passwords.internal.store import MAX_RECENT_PASSWORDS
from sunpack.platform.windows.shell_notify import notify_shell_directories_updated
from sunpack.rename.scheduler import OutputReservationRegistry, RenameScheduler
from sunpack.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner
from sunpack.support.output_paths import default_output_dir_for_task
from sunpack.support.path_keys import path_key
from sunpack.support.archive_sessions import release_archive_sessions_under
from sunpack.support.resource_lifecycle import TaskResourceScope, promotion_barrier
from sunpack.detection.options import DetectionOptions
from sunpack.coordinator.async_work import AsyncWorkBroker, CancellationToken, CURRENT_ORIGIN, map_bounded


@dataclass
class _Submission:
    request_id: str
    targets: tuple[PipelineTarget, ...]
    direct: bool
    user_passwords: tuple[str, ...]
    builtin_passwords: tuple[str, ...]
    config: dict
    origin: str = "foreground"
    detection_options: DetectionOptions | None = None
    stdout: TextIO | None = None
    stderr: TextIO | None = None
    progress_callback: Callable[[Any, dict[str, Any]], None] | None = None


class AsyncOutputCommitter(Protocol):
    async def commit(self, config: dict, response: PipelineResponse) -> PipelineResponse: ...


class DirectOutputCommitter:
    def __init__(self, broker: AsyncWorkBroker, *, stdout=None):
        self._broker = broker
        self._stdout = stdout

    async def commit(self, config: dict, response: PipelineResponse) -> PipelineResponse:
        return await _commit_response(self._broker, config, response, stdout=self._stdout)


class IdentityOutputCommitter:
    """Let an embedding perform an atomic output commit after inspection."""

    async def commit(self, config: dict, response: PipelineResponse) -> PipelineResponse:
        return response


class MappedOutputCommitter:
    def __init__(self, broker: AsyncWorkBroker, output_path_map: Mapping[str, str]):
        self._broker = broker
        self._output_path_map = dict(output_path_map)

    async def commit(self, config: dict, response: PipelineResponse) -> PipelineResponse:
        return await _commit_response(self._broker, config, response, output_path_map=self._output_path_map)


async def _commit_response(broker, config, response, *, output_path_map=None, stdout=None):
    response = await broker.run("postprocess", response.request_id, _finalize_response,
                                config, response, output_path_map=output_path_map,
                                stdout=stdout, request_id=response.request_id)
    for delay in (0.1, 0.3):
        pending = [item for item in response.summary.cleanup_results if item.retryable and item.attempts < 3]
        if not pending:
            break
        await asyncio.sleep(delay)
        response = await broker.run("postprocess", response.request_id, _finalize_response,
                                    config, response, stdout=stdout, retry_results=pending,
                                    request_id=response.request_id)
    return response


class PipelineEngine:
    """Single-event-loop owner for independently completing requests."""

    def __init__(self, config: dict, detection_options: DetectionOptions | None = None):
        self.config = config
        self.detection_options = detection_options or DetectionOptions()
        worker_config = _worker_config(config)
        self._broker = AsyncWorkBroker(
            thread_capacity=int(worker_config.get("stage_thread_capacity", 0) or 0),
            max_pending_jobs=int(
                worker_config.get("max_pending_stage_jobs", worker_config.get("max_queue_jobs", 4096)) or 4096
            ),
        )
        self._services = _PipelineServices(config, self._broker, self.detection_options)
        self._services.max_inflight_files = _max_inflight_files(config, self._broker)
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
        output_committer: AsyncOutputCommitter | None = None,
        request_config: dict | None = None,
        stdout: TextIO | None = None,
        stderr: TextIO | None = None,
        progress_callback: Callable[[Any, dict[str, Any]], None] | None = None,
        origin: str = "foreground",
        detection_options: DetectionOptions | None = None,
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
                target_paths = [target.path for target in submission.targets]
                cancellation.raise_if_cancelled()
                await self._path_leases.acquire(submission.request_id, target_paths)
                runtime = self._request_runtime_factory(
                    self._services,
                    submission,
                    submission.detection_options or self.detection_options,
                    self._path_leases,
                )
                start_time = time.time()
                response = await runtime.execute_async(self._broker, cancellation)
                self._remember_recent_passwords(response.recent_passwords)
                committer = output_committer or DirectOutputCommitter(self._broker, stdout=stdout)
                response = await committer.commit(submission.config, response)
                if getattr(response.summary, "_postprocess_completed", False):
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
            from sunpack.support.runtime_cache_cleanup import (
                clear_all_runtime_caches,
                runtime_cache_stats,
            )

            services = (self._services.repair_inspection_service,)
            before = runtime_cache_stats(inspection_services=services)
            cleared = clear_all_runtime_caches(
                inspection_services=(self._services.repair_inspection_service,),
            )
            after = runtime_cache_stats(inspection_services=services)
            return {"before": before, "cleared": cleared, "after": after}

        return await self._broker.run("cache_cleanup", "engine", clear, request_id="engine")

    def update_password_sources(self, *, user_passwords: Iterable[str], builtin_passwords: Iterable[str]) -> None:
        self._user_passwords = tuple(user_passwords)
        self._builtin_passwords = tuple(builtin_passwords)

    def reconfigure_request(self, config: dict) -> None:
        """Refresh the snapshot source for future requests only."""
        _replace_mapping_in_place(self.config, config)

    async def set_process_mode(self, *, background: bool) -> dict[str, Any]:
        return await self._services.sevenzip_runner.set_process_mode_asyncio(background=background)

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


class _PathLeaseRegistry:
    def __init__(self):
        self._owned: dict[str, set[str]] = {}
        self._changed = asyncio.Condition()

    async def acquire(self, owner: str, paths: Iterable[str]) -> None:
        normalized = {os.path.abspath(os.path.normpath(path)) for path in paths if path}
        async with self._changed:
            await self._changed.wait_for(lambda: not self._conflicts(owner, normalized))
            self._owned.setdefault(owner, set()).update(normalized)

    async def replace(self, owner: str, paths: Iterable[str]) -> None:
        normalized = {os.path.abspath(os.path.normpath(path)) for path in paths if path}
        async with self._changed:
            await self._changed.wait_for(lambda: not self._conflicts(owner, normalized))
            self._owned[owner] = normalized
            self._changed.notify_all()

    async def release(self, owner: str) -> None:
        async with self._changed:
            if self._owned.pop(owner, None) is not None:
                self._changed.notify_all()

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


def _max_inflight_files(config: dict, broker: AsyncWorkBroker) -> int:
    worker = _worker_config(config)
    configured = int(worker.get("max_inflight_files", 0) or 0)
    if configured > 0:
        return configured
    native_capacity = int(worker.get("thread_capacity", 0) or broker.thread_capacity)
    return min(512, max(64, 4 * (broker.thread_capacity + max(1, native_capacity))))


class _PipelineServices:
    """Thread-safe process services shared by all request runtimes."""

    def __init__(
        self,
        config: dict,
        broker: AsyncWorkBroker,
        detection_options: DetectionOptions | None = None,
    ):
        self.config = config
        self.broker = broker
        self.max_inflight_files = 64
        self.output_reservations = OutputReservationRegistry()
        self.repair_inspection_service = RepairInspectionService(
            config,
        )
        worker_config = _worker_config(config)
        self.sevenzip_runner = SevenZipRunner(worker_config)
        self._automatic_stage_capacity = int(worker_config.get("stage_thread_capacity", 0) or 0) == 0

    async def start(self) -> None:
        self.sevenzip_runner.bind_event_loop(asyncio.get_running_loop())
        handshake = await self.sevenzip_runner.start_asyncio()
        if self._automatic_stage_capacity:
            initial_limit = int(handshake.get("initial_active_limit", 0) or handshake.get("thread_capacity", 1) or 1)
            self.broker.configure_thread_capacity(initial_limit)
            self.max_inflight_files = min(512, max(64, 4 * initial_limit))

    async def close(self, broker: AsyncWorkBroker) -> None:
        await self.sevenzip_runner.aclose()

        def close_services() -> None:
            from sunpack.support.runtime_cache_cleanup import clear_all_runtime_caches

            clear_all_runtime_caches(
                inspection_services=(self.repair_inspection_service,),
            )

        await broker.run(
            "service_close",
            "engine",
            close_services,
            request_id="engine",
        )


class _CleanupRefScope:
    def __init__(self, context: RunContext, config: dict, factory: Callable[..., Any]):
        from sunpack.coordinator.cleanup_refs import CleanupRefTable

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

    async def release_task(self, task, *, outcome_kind, broker, cancellation=None) -> "ReleaseOutcome":
        from sunpack.coordinator.cleanup_refs import ReleaseOutcome
        from sunpack.contracts.results import OutcomeKind

        if outcome_kind == OutcomeKind.COMPLETE_SUCCESS:
            self._table.mark_cleanup_eligible(task)
        request = self._table.release(task)
        if not (request.paths and request.should_clean):
            # Nothing to remove: the path is still referenced elsewhere, or every owner that released it failed.
            return ReleaseOutcome(task_key=request.task_key, released=request.paths)
        return await self._apply(request, broker=broker, cancellation=cancellation)

    async def sweep(self, *, broker, cancellation=None) -> list["ReleaseOutcome"]:
        outcomes = []
        for request in self._table.sweep():
            if not (request.paths and request.should_clean):
                continue
            outcomes.append(await self._apply(request, broker=broker, cancellation=cancellation))
        return outcomes

    async def _apply(self, request, *, broker, cancellation=None) -> "ReleaseOutcome":
        from sunpack.coordinator.cleanup_refs import ReleaseOutcome
        from sunpack.support.archive_sessions import release_archive_sessions_under
        from sunpack.support.resource_lifecycle import (
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
        return outcome

    def _mode(self) -> str:
        return str(self._config.get("post_extract", {}).get("archive_cleanup_mode", "recycle"))


class _RequestRuntime:
    """All mutable state belonging to exactly one PipelineEngine submission."""

    def __init__(
        self,
        services: _PipelineServices,
        submission: _Submission,
        detection_options: DetectionOptions,
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
        self.context = RunContext()
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
        self.nested_extraction_policy = NestedExtractionPolicy(self.config)
        self.rename_scheduler = RenameScheduler(
            services.output_reservations,
            submission.request_id,
        )
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
        self.batch_runner = ExtractionBatchRunner(
            self.context,
            self.extractor,
            self.output_scan_policy,
            self.rename_scheduler,
            self.config,
            repair_inspection_service=services.repair_inspection_service,
            progress_reporter=self.reporter,
            request_id=submission.request_id,
        )

    def _report_progress(self, task: Any, event: dict[str, Any]) -> None:
        self.reporter.task_progress(task, event)
        callback = self.submission.progress_callback
        if callback is not None:
            try:
                callback(task, dict(event))
            except Exception:
                # Progress observers are best-effort; a broken UI/notification sink must never fail an extraction.
                pass

    def _resolve_missing_volume_once(self, task, _outcome):
        current_paths = list(task.all_parts or [task.main_path])
        try:
            format_hint = task.archive_input().format_hint
        except (TypeError, ValueError, AttributeError):
            format_hint = str(task.detected_ext or "").lstrip(".")
        group = self.task_scanner.provider.resolve_volume_once_in_directory(
            current_paths,
            format_hint=format_hint,
        )
        if group is None:
            return None
        bag = relation_group_to_fact_bag(group)
        bag.set("relation.volume_retry_attempted", True)
        bag.set(
            "relation.volume_retry_basis",
            ["confirmed_structure", "anchor_constrained_filename"],
        )
        bag.set(
            EMBEDDED_SCAN_ALLOWED_FACT,
            bool(task.fact_bag.get(EMBEDDED_SCAN_ALLOWED_FACT)),
        )
        replacement = self.task_scanner.provider.task_from_candidate_bag(bag)
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
        all_targets = [target.path for target in submission.targets]
        ownership = _RequestOwnership([submission], self.config)
        recursion = self._new_recursion()
        round_index = 1
        current_roots = list(dict.fromkeys(all_targets))
        current_tasks = None
        current_scan_session = None
        if submission.direct:
            current_tasks = await broker.run(
                "discover",
                request_id,
                self.task_scanner.direct_file_tasks,
                current_roots,
                request_id=request_id,
                cancellation=cancellation,
            )

        try:
            while current_tasks if submission.direct else current_roots:
                cancellation.raise_if_cancelled()
                if submission.direct:
                    tasks = current_tasks or []
                else:
                    self.reporter.scan_started(round_index)
                    tasks = await broker.run(
                        "discover_detect",
                        request_id,
                        self.task_scanner.scan_targets,
                        current_roots,
                        scan_session=current_scan_session,
                        is_recursive_scan=(round_index > 1),
                        request_id=request_id,
                        cancellation=cancellation,
                    )
                authorization = await broker.run(
                    "nested_policy",
                    request_id,
                    self.nested_extraction_policy.authorize_batch,
                    tasks,
                    current_roots,
                    current_scan_session or self.task_scanner.last_scan_session,
                    round_index=round_index,
                    request_id=request_id,
                    cancellation=cancellation,
                )
                async def plan_one(task):
                    return await broker.run(
                        "plan",
                        task.key or task.main_path,
                        self._plan_task_isolated,
                        task,
                        request_id=request_id,
                        cancellation=cancellation,
                    )

                planned_groups = await map_bounded(
                    authorization.allowed_tasks,
                    self.services.max_inflight_files,
                    plan_one,
                )
                tasks = [task for group in planned_groups for task in group]
                self.context.policy_skips.extend(authorization.skipped)
                ownership.remember_tasks(tasks)
                member_paths = [
                    path
                    for task in tasks
                    for path in (task.all_parts or [task.main_path])
                ]
                lease_paths = [*all_targets, *member_paths]
                cancellation.raise_if_cancelled()
                await self.path_leases.replace(request_id, lease_paths)
                self.batch_runner.set_progress_round(
                    round_index,
                    direct=submission.direct and round_index == 1,
                )
                before_results = len(self.context.target_results)
                new_roots = await self.batch_runner.execute_async(
                    tasks,
                    broker=broker,
                    cancellation=cancellation,
                    default_output_dir_for_task=ownership.output_dir_for_task,
                    missing_volume_retry=self._resolve_missing_volume_once,
                    ensure_input_lease=self._ensure_task_lease,
                    cleanup_scope=self.cleanup_scope,
                )
                next_scan_session = self.output_scan_policy.take_scan_session(new_roots)
                ownership.remember_results(self.context.target_results[before_results:])
                if not recursion.should_continue(round_index, bool(new_roots)):
                    break
                if recursion.mode == "prompt" and not await broker.run(
                    "prompt",
                    request_id,
                    recursion.prompt_continue,
                    round_index,
                    request_id=request_id,
                    cancellation=cancellation,
                ):
                    break
                current_roots = new_roots
                current_scan_session = next_scan_session
                current_tasks = None
                if submission.direct:
                    current_tasks = await broker.run(
                        "discover_detect",
                        request_id,
                        self.task_scanner.scan_targets,
                        new_roots,
                        scan_session=current_scan_session,
                        is_recursive_scan=True,
                        request_id=request_id,
                        cancellation=cancellation,
                    )
                round_index += 1

            response = ownership.responses(
                self.context,
                recent_passwords=self.extractor.recent_passwords,
            )[request_id]
            return response
        finally:
            self.extractor.set_progress_callback(None)
            await broker.run(
                "extractor_close",
                request_id,
                self.extractor.close,
                request_id=request_id,
            )
            self.input_planning_stage.clear_report_cache()

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
            max_rounds=int(config.get("max_rounds", 1)),
            language=self.language,
        )


def _finalize_response(
    config: dict,
    response: PipelineResponse,
    *,
    output_path_map: Mapping[str, str] | None = None,
    stdout=None,
    retry_results=None,
) -> PipelineResponse:
    if getattr(response.summary, "_postprocess_completed", False) and retry_results is None:
        return response
    mapping = {path_key(old): os.path.abspath(new) for old, new in (output_path_map or {}).items()}

    def remap(path: str) -> str:
        normalized = os.path.abspath(path)
        exact = mapping.get(path_key(normalized))
        if exact:
            return exact
        ancestors = [
            (old, new)
            for old, new in (output_path_map or {}).items()
            if _is_relative_to(normalized, old)
        ]
        if not ancestors:
            return path
        old, new = max(ancestors, key=lambda item: len(os.path.abspath(item[0])))
        return os.path.join(os.path.abspath(new), os.path.relpath(normalized, os.path.abspath(old)))

    flatten_targets_all = [remap(path) for path in response.artifacts.flatten_targets]
    shell_refresh_paths = [remap(path) for path in response.artifacts.shell_refresh_paths]
    previous = None
    cleanup_requests = ()
    if retry_results is not None:
        # Only failed cleanups are retried here; successful sources are already removed task by task.
        flatten_targets_all = []
        shell_refresh_paths = []
        cleanup_requests = tuple((item.path,) for item in retry_results)
        previous = {path_key(item.path): item for item in retry_results}
    post_extract = config.get("post_extract", {})
    flatten_enabled = post_extract.get("flatten_single_directory", True)
    flatten_targets = flatten_targets_all if flatten_enabled else []
    mutation_roots = list(flatten_targets)
    mutation_roots.extend(path for family in cleanup_requests for path in family)
    if mutation_roots:
        with promotion_barrier(
            mutation_roots,
            cache_releasers=(release_archive_sessions_under,),
        ):
            cleanup_results = PostProcessActions(config, stdout=stdout).apply(
                archives_to_clean=list(cleanup_requests),
                flatten_targets=flatten_targets,
                previous_cleanup=previous,
            )
    else:
        cleanup_results = PostProcessActions(config, stdout=stdout).apply(
            archives_to_clean=list(cleanup_requests),
            flatten_targets=flatten_targets,
            previous_cleanup=previous,
        )
    notify_shell_directories_updated(shell_refresh_paths)
    merged = {path_key(item.path): item for item in response.summary.cleanup_results}
    merged.update({path_key(item.path): item for item in cleanup_results})
    response.summary.cleanup_results = list(merged.values())
    response.summary._postprocess_completed = True
    return response


class _RequestOwnership:
    def __init__(self, submissions: list[_Submission], config: dict):
        self.submissions = submissions
        self.config = config
        self._task_owner: dict[str, str] = {}
        self._task_keys: dict[str, list[str]] = {item.request_id: [] for item in submissions}
        self._output_owner: dict[str, str] = {}

    def remember_tasks(self, tasks) -> None:
        for task in tasks:
            owner = self.owner_for_path(task.main_path)
            self._task_owner[path_key(task.main_path)] = owner.request_id
            self._task_keys[owner.request_id].append(task.key)

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

    def responses(self, context: RunContext, *, recent_passwords: Iterable[str]) -> dict[str, PipelineResponse]:
        results = {item.request_id: [] for item in self.submissions}
        for result in context.target_results:
            results[self.owner_for_path(result.input_path).request_id].append(result)
        flatten = {item.request_id: [] for item in self.submissions}
        for path in context.flatten_candidates:
            owner_id = self._owner_for_output(path) or self.owner_for_path(path).request_id
            flatten[owner_id].append(path)

        responses = {}
        for submission in self.submissions:
            request_results = results[submission.request_id]
            failed = [
                f"{os.path.basename(result.input_path)} [{result.error or getattr(result.failure, 'message', '')}]"
                for result in request_results
                if result.outcome_kind == OutcomeKind.FAILURE
            ]
            if len(self.submissions) == 1:
                failed = list(context.failed_tasks)
                failures = list(context.failures)
            else:
                failures = [
                    result.failure
                    for result in request_results
                    if result.failure is not None
                ]
                failures.extend(
                    failure
                    for failure in context.failures
                    if failure not in failures and self._failure_owner(failure) == submission.request_id
                )
            recovered = [
                item for item in context.recovered_outputs
                if self.owner_for_path(str(item.get("out_dir") or item.get("archive") or "")).request_id == submission.request_id
            ]
            summary = RunSummary(
                success_count=sum(result.outcome_kind == OutcomeKind.COMPLETE_SUCCESS for result in request_results),
                failed_tasks=failed,
                processed_keys=list(dict.fromkeys(self._task_keys[submission.request_id])),
                partial_success_count=sum(result.outcome_kind == OutcomeKind.PARTIAL_SUCCESS for result in request_results),
                recovered_outputs=recovered,
                failures=failures,
                target_results=request_results,
                policy_skips=[
                    item
                    for item in context.policy_skips
                    if self.owner_for_path(str(item.get("path") or "")).request_id
                    == submission.request_id
                ],
            )
            responses[submission.request_id] = PipelineResponse(
                request_id=submission.request_id,
                summary=summary,
                artifacts=PipelineArtifacts(
                    flatten_targets=tuple(sorted(flatten[submission.request_id], key=lambda value: value.count(os.sep))),
                    shell_refresh_paths=tuple(dict.fromkeys([
                        *(
                            result.output_dir
                            for result in request_results
                            if result.outcome_kind in {OutcomeKind.COMPLETE_SUCCESS, OutcomeKind.PARTIAL_SUCCESS}
                            and result.output_dir
                        ),
                        *(
                            str(item.get("out_dir") or "")
                            for item in recovered
                            if str(item.get("out_dir") or "")
                        ),
                    ])),
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
