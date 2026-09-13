import os
from dataclasses import dataclass
from typing import Any, List

from sunpack.contracts.run_context import RunContext
from sunpack.contracts.results import OutcomeKind, TargetRunResult
from sunpack.contracts.content_recovery import (
    CONTENT_REQUIREMENT_COMPLETE,
    ContentRecoveryPolicy,
)
from sunpack.contracts.tasks import ArchiveTask
from sunpack.postprocess.failed_output_cleanup import cleanup_failed_output_if_eligible
from sunpack.coordinator.resource_preflight import ResourcePreflightInspector
from sunpack.relations.stage import ArchiveRelationStage
from sunpack.coordinator.verification_stage import verify_and_project
from sunpack.coordinator.output_scan_policy import NestedOutputScanPolicy
from sunpack.support.output_inventory import OutputInventory
from sunpack.contracts.extraction import ExtractionResult
from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.extraction.knowledge import write_extraction_result
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.support.output_cleanup import OutputCleanupEvent, cleanup_output_for_retry
from sunpack.coordinator.async_work import map_unbounded
from sunpack.contracts.verification import DECISION_ACCEPT, DECISION_ACCEPT_PARTIAL, DECISION_RETRY_EXTRACT


def _advance_batch_state(state, sent, *, first: bool):
    try:
        return False, next(state) if first else state.send(sent)
    except StopIteration as completed:
        return True, completed.value
from sunpack.passwords.directory_context import DirectoryPasswordContextStore
from sunpack.rename.scheduler import RenameScheduler
from sunpack.verification import VerificationResult, VerificationScheduler
from sunpack.verification.error_classification import classify_verification_error
from sunpack.contracts.verification import (
    CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
    CONTENT_INTEGRITY_UNKNOWN,
    CONTENT_INTEGRITY_VERIFIED_PARTIAL,
    VERIFICATION_STRENGTH_CRC,
    VERIFICATION_STRENGTH_MANIFEST,
    VERIFICATION_STRENGTH_ORACLE,
)
from sunpack.support.path_keys import absolute_path_key
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.i18n import I18nContext
from sunpack.config.advanced_defaults import advanced_config_value


@dataclass
class BatchExtractionOutcome:
    result: ExtractionResult
    verification: VerificationResult | None = None
    attempts: int = 1
    planned_out_dir: str = ""
    content_requirement: str = CONTENT_REQUIREMENT_COMPLETE

    @property
    def outcome_kind(self) -> OutcomeKind:
        if self.result.success and _verification_accepts_complete_strict(self.verification):
            return OutcomeKind.COMPLETE_SUCCESS
        if (
            self.content_requirement != CONTENT_REQUIREMENT_COMPLETE
            and _verification_accepts_partial(self.verification)
            and _partial_result_is_acceptable(self.result)
        ):
            return OutcomeKind.PARTIAL_SUCCESS
        return OutcomeKind.FAILURE

    @property
    def policy_rejected_partial_output(self) -> bool:
        # Embedded payloads are independent logical archives.  A failed
        # encrypted sibling does not make already verified/plain child outputs
        # disposable partial files.
        if (
            self.result.failure is not None
            and self.result.failure.contains(FailureKind.EMBEDDED_SEGMENTS_FAILED)
            and any(
                bool(child.success)
                for _segment, child in (self.result.embedded_results or [])
            )
        ):
            return False
        if self.content_requirement != CONTENT_REQUIREMENT_COMPLETE:
            return False
        verification = self.verification
        return bool(
            self.result.partial_outputs
            or _verification_accepts_partial(verification)
            or getattr(verification, "content_integrity", "")
            in {CONTENT_INTEGRITY_VERIFIED_PARTIAL, CONTENT_INTEGRITY_PAYLOAD_DAMAGED}
        )


class ExtractionBatchRunner:
    def __init__(
        self,
        context: RunContext,
        extractor: ExtractionScheduler,
        output_scan_policy: NestedOutputScanPolicy,
        rename_scheduler: RenameScheduler | None = None,
        config: dict | None = None,
        progress_reporter: Any | None = None,
        request_id: str = "",
    ):
        self.context = context
        self.extractor = extractor
        self.output_scan_policy = output_scan_policy
        self.rename_scheduler = rename_scheduler or RenameScheduler()
        self.config = config or {}
        self.content_policy = ContentRecoveryPolicy.from_config(self.config)
        cli_config = self.config.get("cli") if isinstance(self.config.get("cli"), dict) else {}
        self.i18n = I18nContext(cli_config.get("language"))
        self.progress_reporter = progress_reporter
        self.request_id = str(request_id or "")
        self.progress_round_index = 1
        self.progress_direct_mode = False
        self.relation_stage = ArchiveRelationStage()
        self.verifier = VerificationScheduler(self.config, password_session=self.extractor.password_session)
        self.directory_password_contexts = DirectoryPasswordContextStore(self.config)
        performance = advanced_config_value(("performance",))
        if isinstance(self.config.get("performance"), dict):
            performance.update(self.config["performance"])
        self.resource_inspector = ResourcePreflightInspector(
            password_session=self.extractor.password_session,
            rename_scheduler=self.rename_scheduler,
            precise_resource_min_size_mb=performance["precise_resource_min_size_mb"],
        )

    def set_progress_round(self, round_index: int, *, direct: bool = False) -> None:
        self.progress_round_index = max(1, int(round_index or 1))
        self.progress_direct_mode = bool(direct)

    def prepare_tasks(self, tasks: List[ArchiveTask]):
        self.relation_stage.resolve_tasks(tasks)
        # Physical source paths are immutable. Detected formats and logical
        # volume identities travel through ArchiveInputDescriptor/ArchiveState.

    async def execute_async(
        self,
        tasks: List[ArchiveTask],
        *,
        broker,
        cancellation,
        default_output_dir_for_task=None,
        missing_volume_retry=None,
        ensure_input_lease=None,
        cleanup_scope=None,
    ) -> List[str]:
        """Execute independent logical archives as interleaved coroutines."""

        if not tasks:
            if self.progress_reporter is not None:
                self.progress_reporter.begin_round(self.progress_round_index, [], direct=self.progress_direct_mode)
            return []

        def prepare_batch():
            self.prepare_tasks(tasks)
            self.directory_password_contexts.annotate(tasks)
            resolver = self.rename_scheduler.build_output_dir_resolver(
                tasks,
                default_output_dir_for_task or self.extractor.default_output_dir_for_task,
            )
            resolver = self._cached_output_dir_resolver(resolver)
            prepared = self._skip_tasks_inside_batch_outputs(tasks, resolver)
            if cleanup_scope is not None:
                # Reference counts must exist before any task can finish, so a shared source path is
                # never deleted while another task in this round still has to read it.
                cleanup_scope.register(prepared)
            return resolver, prepared

        output_dir_resolver, prepared_tasks = await broker.run(
            "admission",
            self.request_id,
            prepare_batch,
            request_id=self.request_id,
            cancellation=cancellation,
        )
        if self.progress_reporter is not None:
            self.progress_reporter.begin_round(
                self.progress_round_index,
                prepared_tasks,
                direct=self.progress_direct_mode,
            )

        async def execute_one(task):
            task, outcome = await self._execute_one_async(
                task,
                output_dir_resolver,
                broker=broker,
                cancellation=cancellation,
                missing_volume_retry=missing_volume_retry,
                ensure_input_lease=ensure_input_lease,
            )
            output_dir = self.collect_result(task, outcome)
            if cleanup_scope is not None and output_dir:
                # Clean up as soon as extract and verification are both finished, because
                # verification reads the source archive back to build its manifest.
                await cleanup_scope.release_task(
                    task,
                    outcome_kind=outcome.outcome_kind,
                    broker=broker,
                    cancellation=cancellation,
                )
            return task, outcome

        # Python only bounds blocking preparation through the broker. Every
        # extraction-ready task is submitted to the native worker, where
        # fairness and resource admission are centralized.
        try:
            outcomes = await map_unbounded(prepared_tasks, execute_one)
        finally:
            if cleanup_scope is not None:
                # Cancelled or otherwise unreported tasks still hold references; drop them so a
                # round can never strand the table.
                await cleanup_scope.sweep(broker=broker)

        output_dirs = []
        logical_scan_roots = []
        output_inventories: dict[str, OutputInventory] = {}
        for task, outcome in outcomes:
            output_dir = outcome.result.out_dir if outcome.result is not None else ""
            if not output_dir:
                continue
            output_dirs.append(output_dir)
            self.directory_password_contexts.remember(output_dir, task)
            if isinstance(self.output_scan_policy, NestedOutputScanPolicy):
                projected_roots = self.output_scan_policy.project_logical_scan_roots(output_dir, outcome.result)
            else:
                projected_roots = [(output_dir, None)]
            for logical_root, projected_inventory in projected_roots:
                logical_scan_roots.append(logical_root)
                inventory = OutputInventory.from_value(projected_inventory, expected_root=logical_root)
                if inventory is not None:
                    output_inventories[os.path.normcase(os.path.abspath(logical_root))] = inventory
        if isinstance(self.output_scan_policy, NestedOutputScanPolicy):
            return self.output_scan_policy.scan_roots_from_outputs(
                output_dirs,
                inventories=output_inventories,
                logical_roots=logical_scan_roots,
            )
        return self.output_scan_policy.scan_roots_from_outputs(output_dirs)

    async def _execute_one_async(
        self,
        task: ArchiveTask,
        output_dir_resolver,
        *,
        broker,
        cancellation,
        missing_volume_retry=None,
        ensure_input_lease=None,
    ) -> tuple[ArchiveTask, BatchExtractionOutcome]:
        file_id = task.key or task.main_path

        def preflight():
            inspected = self._inspect_tasks_before_extract([task], output_dir_resolver)[0]
            _index, _task, out_dir, result = inspected
            if result.skip_result is not None:
                return out_dir, BatchExtractionOutcome(result.skip_result)
            guard_enabled = bool(self._resource_guard_config().get("enabled", False))
            if guard_enabled or knowledge_view.resource_analysis(task):
                self.resource_inspector.inspect(task)
            else:
                self.resource_inspector.record_estimated_single_task_profile(task)
            guarded = self._resource_guard_results([task], output_dir_resolver)
            return out_dir, guarded[0][1] if guarded else None

        retried_missing_volume = False
        while True:
            planned_out_dir, terminal = await broker.run(
                "preflight",
                file_id,
                preflight,
                request_id=self.request_id,
                cancellation=cancellation,
            )
            if not (
                terminal is not None
                and callable(missing_volume_retry)
                and not retried_missing_volume
                and terminal.result.failure is not None
                and terminal.result.failure.contains(FailureKind.MISSING_VOLUME)
            ):
                break
            replacement = await broker.run(
                "missing_volume",
                file_id,
                missing_volume_retry,
                task,
                terminal,
                request_id=self.request_id,
                cancellation=cancellation,
            )
            retried_missing_volume = True
            if not isinstance(replacement, ArchiveTask):
                break
            task.adopt_detection_plan(replacement)
            task.fact_bag.set("relation.volume_retry_attempted", True)
            await broker.run(
                "relation",
                file_id,
                self.prepare_tasks,
                [task],
                request_id=self.request_id,
                cancellation=cancellation,
            )
        if terminal is not None:
            terminal.planned_out_dir = planned_out_dir
            self._report_task_finished(task, terminal)
            return task, terminal

        state = self._extract_verify_state_machine(
            task,
            planned_out_dir,
            missing_volume_retry=missing_volume_retry,
        )
        sent = None
        first = True
        while True:
            done, value = await broker.run(
                "extract_prepare" if first else "verify_extract",
                file_id,
                _advance_batch_state,
                state,
                sent,
                first=first,
                request_id=self.request_id,
                cancellation=cancellation,
            )
            if done:
                outcome = value
                outcome.planned_out_dir = planned_out_dir
                self._report_task_finished(task, outcome)
                return task, outcome
            request = value
            first = False
            if callable(ensure_input_lease):
                await ensure_input_lease(request["task"])
            sent = await self.extractor.extract_asyncio(
                broker,
                request["task"],
                request["out_dir"],
                request_id=self.request_id,
                file_id=file_id,
                cancellation=cancellation,
            )

    def _report_task_started(self, task: ArchiveTask) -> None:
        if self.progress_reporter is not None:
            self.progress_reporter.task_started(task, self.progress_round_index)

    def _report_task_finished(self, task: ArchiveTask, outcome: BatchExtractionOutcome) -> None:
        if self.progress_reporter is not None:
            self.progress_reporter.task_finished(task, outcome, self.progress_round_index)

    def _report_task_status(self, task: ArchiveTask, state: str, detail: str = "") -> None:
        if self.progress_reporter is not None:
            self.progress_reporter.task_status(task, state, detail)

    @staticmethod
    def _cached_output_dir_resolver(output_dir_resolver):
        cache: dict[int, str] = {}

        def resolve(task: ArchiveTask) -> str:
            key = id(task)
            if key not in cache:
                cache[key] = output_dir_resolver(task)
            return cache[key]

        return resolve

    def _resource_guard_results(self, tasks: list[ArchiveTask], output_dir_resolver) -> list[tuple[ArchiveTask, BatchExtractionOutcome]]:
        guard = self._resource_guard_config()
        if not guard or not bool(guard.get("enabled", False)):
            return []
        results: list[tuple[ArchiveTask, BatchExtractionOutcome]] = []
        for task in tasks:
            analysis = knowledge_view.resource_analysis(task)
            if not isinstance(analysis, dict):
                continue
            violations = _resource_guard_violations(analysis, guard)
            if not violations:
                continue
            guard_payload = {
                "status": "guarded",
                "violations": violations,
                "policy": {
                    "max_file_count": guard.get("max_file_count"),
                    "max_total_unpacked_size": guard.get("max_total_unpacked_size"),
                    "max_largest_item_size": guard.get("max_largest_item_size"),
                    "max_compression_ratio": guard.get("max_compression_ratio"),
                },
            }
            task.fact_bag.set("resource.guard", guard_payload)
            out_dir = output_dir_resolver(task)
            result = ExtractionResult(
                success=False,
                archive=task.main_path,
                out_dir=out_dir,
                all_parts=task.all_parts,
                error="resource_guard",
                diagnostics={
                    "result": {
                        "status": "failed",
                        "native_status": "guarded",
                        "failure_stage": "preflight",
                        "failure_kind": "resource_guard",
                        "guard_status": "guarded",
                        "resource_guard": guard_payload,
                    }
                },
            )
            results.append((task, BatchExtractionOutcome(result=result)))
        return results

    def _resource_guard_config(self) -> dict:
        performance = self.config.get("performance") if isinstance(self.config.get("performance"), dict) else {}
        guard = performance.get("resource_guard") if isinstance(performance.get("resource_guard"), dict) else {}
        return dict(guard)

    def _inspect_tasks_before_extract(self, tasks: list[ArchiveTask], output_dir_resolver) -> list[tuple[int, ArchiveTask, str, Any]]:
        results = []
        for index, task in enumerate(tasks):
            self._report_task_started(task)
            out_dir = output_dir_resolver(task)
            results.append((index, task, out_dir, self.extractor.inspect(task, out_dir)))
        return results

    def _inspect_resource_profiles(self, tasks: list[ArchiveTask]) -> None:
        for task in tasks:
            self.resource_inspector.inspect(task)

    def _extract_verify_state_machine(
        self,
        task: ArchiveTask,
        out_dir: str,
        *,
        missing_volume_retry=None,
    ):
        verification_config = self.verifier.config
        max_verification_retries = max(0, int(verification_config.get("max_retries", 0) or 0))
        cleanup_failed_output = bool(verification_config.get("cleanup_failed_output", True))
        attempts = max_verification_retries + 1
        volume_retry_attempted = bool(task.fact_bag.get("relation.volume_retry_attempted"))

        attempt_index = 0
        while attempt_index < attempts:
            self._report_task_status(task, "extracting")
            result = yield {
                "task": task,
                "out_dir": out_dir,
            }
            write_extraction_result(task, result)
            if not result.success:
                self._report_task_status(task, "error", str(result.error or ""))
                verification = verify_and_project(self.verifier, task, result)
                current_outcome = BatchExtractionOutcome(
                    result=result,
                    verification=verification,
                    attempts=attempt_index + 1,
                )
                if (
                    not volume_retry_attempted
                    and callable(missing_volume_retry)
                    and _should_retry_missing_volume_resolution(task, result)
                ):
                    volume_retry_attempted = True
                    self._report_task_status(task, "resolving_volumes")
                    replacement = missing_volume_retry(task, current_outcome)
                    if isinstance(replacement, ArchiveTask):
                        cleanup_output_for_retry(
                            result.out_dir,
                            event=OutputCleanupEvent.VERIFICATION_RETRY,
                            planned_output_dir=out_dir,
                        )
                        task.adopt_detection_plan(replacement)
                        task.fact_bag.set("relation.volume_retry_attempted", True)
                        task.fact_bag.set(
                            "relation.volume_retry_basis",
                            ["confirmed_structure", "anchor_constrained_filename"],
                        )
                        self.prepare_tasks([task])
                        self.directory_password_contexts.annotate([task])
                        continue
                if self._must_stop_for_proven_content_loss(task, result, verification):
                    return current_outcome
                if _verification_accepts_complete(verification):
                    return current_outcome
                return current_outcome

            verification = verify_and_project(self.verifier, task, result)
            outcome = BatchExtractionOutcome(result=result, verification=verification, attempts=attempt_index + 1)
            if self._must_stop_for_proven_content_loss(task, result, verification):
                return outcome
            if _verification_accepts_complete(verification):
                return outcome
            if attempt_index >= max_verification_retries:
                return outcome
            if verification.decision_hint != DECISION_RETRY_EXTRACT and not self._retry_on_verification_failure():
                break
            if cleanup_failed_output:
                cleanup_output_for_retry(
                    result.out_dir,
                    event=OutputCleanupEvent.VERIFICATION_RETRY,
                    planned_output_dir=out_dir,
                )
            attempt_index += 1
        return BatchExtractionOutcome(
            result=ExtractionResult(
                success=False, archive=task.main_path, out_dir=out_dir,
                all_parts=task.all_parts, error=self.i18n.t("failure.verification_failed"),
            ), attempts=attempts,
        )

    def _must_stop_for_proven_content_loss(
        self,
        task: ArchiveTask,
        result: ExtractionResult,
        verification: VerificationResult,
    ) -> bool:
        if self.content_policy.allows_partial:
            return False
        return _proves_content_loss(result, verification)

    def _retry_on_verification_failure(self) -> bool:
        return bool(self.verifier.config.get("retry_on_verification_failure", True))

    def _skip_tasks_inside_batch_outputs(self, tasks: List[ArchiveTask], output_dir_resolver=None) -> List[ArchiveTask]:
        output_dir_resolver = output_dir_resolver or self.extractor.default_output_dir_for_task
        output_roots = []
        for task in tasks:
            output_dir = output_dir_resolver(task)
            if output_dir:
                output_roots.append((task, absolute_path_key(output_dir)))

        filtered = []
        for task in tasks:
            task_path = absolute_path_key(task.main_path)
            inside_another_output = False
            for owner, output_root in output_roots:
                if owner is task:
                    continue
                try:
                    if os.path.commonpath([task_path, output_root]) == output_root:
                        inside_another_output = True
                        break
                except ValueError:
                    continue
            if not inside_another_output:
                filtered.append(task)
        return filtered

    def collect_result(self, task: ArchiveTask, outcome: BatchExtractionOutcome | ExtractionResult) -> str | None:
        content_policy = getattr(self, "content_policy", None) or ContentRecoveryPolicy.from_config(
            getattr(self, "config", {})
        )
        if isinstance(outcome, ExtractionResult):
            outcome = BatchExtractionOutcome(outcome, content_requirement=content_policy.requirement)
        else:
            outcome.content_requirement = content_policy.requirement
        res = outcome.result
        out_dir = res.out_dir
        cleanup = cleanup_failed_output_if_eligible(
            out_dir,
            planned_output_dir=outcome.planned_out_dir,
            failed=outcome.outcome_kind == OutcomeKind.FAILURE,
            force_owned_output_cleanup=outcome.policy_rejected_partial_output,
        )
        diagnostics = res.diagnostics if isinstance(res.diagnostics, dict) else {}
        res.diagnostics = {**diagnostics, "failed_output_cleanup": cleanup.to_dict()}

        possible_missing_volume = _possible_missing_volume_failure(
            task,
            outcome.outcome_kind,
            res.failure,
            getattr(self, "i18n", I18nContext("en")),
        )
        if outcome.outcome_kind == OutcomeKind.FAILURE and possible_missing_volume is not None:
            res.failure = possible_missing_volume
            res.error = possible_missing_volume.message

        with self.context.lock:
            if outcome.outcome_kind == OutcomeKind.COMPLETE_SUCCESS:
                self.context.success_count += 1
                self.context.processed_keys.add(task.key)
                self.context.flatten_candidates.add(out_dir)
                self.context.target_results.append(TargetRunResult(
                    input_path=task.main_path,
                    outcome_kind=OutcomeKind.COMPLETE_SUCCESS,
                    output_dir=out_dir,
                    verification=_verification_payload(outcome.verification) if outcome.verification is not None else {},
                ))
                return out_dir
            if outcome.outcome_kind == OutcomeKind.PARTIAL_SUCCESS:
                if outcome.verification is not None:
                    self.context.partial_success_count += 1
                    self.context.recovered_outputs.append({
                        "archive": task.main_path,
                        "out_dir": out_dir,
                        "completeness": outcome.verification.completeness,
                        "assessment_status": outcome.verification.assessment_status,
                        "content_integrity": outcome.verification.content_integrity,
                        "container_integrity": outcome.verification.container_integrity,
                        "verification_strength": outcome.verification.verification_strength,
                        "archive_coverage": _coverage_payload(outcome.verification),
                        "progress_manifest": res.progress_manifest,
                        **(
                            {"warning": possible_missing_volume.to_dict()}
                            if possible_missing_volume is not None
                            else {}
                        ),
                    })
                if possible_missing_volume is not None:
                    self.context.failures.append(possible_missing_volume)
                self.context.processed_keys.add(task.key)
                self.context.target_results.append(TargetRunResult(
                    input_path=task.main_path,
                    outcome_kind=OutcomeKind.PARTIAL_SUCCESS,
                    output_dir=out_dir,
                    verification=_verification_payload(outcome.verification) if outcome.verification is not None else {},
                    error=(
                        possible_missing_volume.message
                        if possible_missing_volume is not None
                        else str(res.error or "")
                    ),
                    failure=possible_missing_volume,
                ))
                return out_dir
            self.context.failed_tasks.append(self._failure_message(task, outcome))
            if outcome.result.failure is not None:
                self.context.failures.append(outcome.result.failure)
            self.context.target_results.append(TargetRunResult(
                input_path=task.main_path,
                outcome_kind=OutcomeKind.FAILURE,
                output_dir=out_dir,
                verification=_verification_payload(outcome.verification) if outcome.verification is not None else {},
                error=str(res.error or ""),
                failure=outcome.result.failure,
            ))
            return None

    def _failure_message(self, task: ArchiveTask, outcome: BatchExtractionOutcome) -> str:
        name = os.path.basename(task.main_path)
        if outcome.result.success and outcome.verification is not None and not _verification_accepts(outcome.verification):
            return f"{name} [{self._verification_failure_summary(outcome)}]"
        return f"{name} [{outcome.result.error}]"

    def _verification_failure_summary(self, outcome: BatchExtractionOutcome) -> str:
        verification = outcome.verification
        if verification is None:
            return self.i18n.t("failure.verification_failed")
        steps = "; ".join(f"{step.method}:{step.status}" for step in verification.steps) or "none"
        return self.i18n.t(
            "failure.verification_failed_detail",
            completeness=getattr(verification, "completeness", ""),
            integrity=getattr(verification, "assessment_status", ""),
            decision=getattr(verification, "decision_hint", ""),
            coverage=getattr(getattr(verification, "archive_coverage", None), "completeness", ""),
            attempts=outcome.attempts,
            steps=steps,
        )


def _verification_accepts(verification: VerificationResult | Any) -> bool:
    decision = getattr(verification, "decision_hint", "")
    return decision in {DECISION_ACCEPT, DECISION_ACCEPT_PARTIAL}


def _verification_accepts_complete(verification: VerificationResult | Any) -> bool:
    return _verification_accepts_complete_strict(verification)


def _verification_accepts_complete_strict(verification: VerificationResult | Any) -> bool:
    if verification is None:
        return False
    # The verifier's decision is the contract boundary. Some extraction backends
    # cannot provide per-file coverage, so an accepted result may legitimately
    # carry an "unknown" assessment while still being a full success.
    return getattr(verification, "decision_hint", "") == DECISION_ACCEPT


def _verification_accepts_partial(verification: VerificationResult | Any) -> bool:
    return getattr(verification, "decision_hint", "") == DECISION_ACCEPT_PARTIAL


def _partial_result_is_acceptable(result: ExtractionResult) -> bool:
    """Reject execution/authentication failures, while allowing damaged sources to yield verified content."""
    reason = result.failure.kind.value if result.failure is not None else ""
    return not reason or reason in {"damaged", "missing_volume"}


def _proves_content_loss(result: ExtractionResult, verification: VerificationResult) -> bool:
    """Return true only for content evidence, never for container-structure evidence alone."""
    failure = result.failure
    if failure is not None and failure.contains(FailureKind.MISSING_VOLUME):
        return True

    for payload in _nested_diagnostic_payloads(result):
        failure_kind = str(payload.get("failure_kind") or "")
        failure_stage = str(payload.get("failure_stage") or "")
        if not failure_kind:
            continue
        classified = classify_verification_error(failure_kind, failure_stage)
        if classified.content_integrity != CONTENT_INTEGRITY_UNKNOWN:
            return True

    content_integrity = str(getattr(verification, "content_integrity", "") or "")
    strength = str(getattr(verification, "verification_strength", "") or "")
    return (
        content_integrity
        in {CONTENT_INTEGRITY_VERIFIED_PARTIAL, CONTENT_INTEGRITY_PAYLOAD_DAMAGED}
        and strength
        in {VERIFICATION_STRENGTH_MANIFEST, VERIFICATION_STRENGTH_CRC, VERIFICATION_STRENGTH_ORACLE}
    )


def _nested_diagnostic_payloads(result: ExtractionResult):
    roots: list[Any] = [result.diagnostics]
    if result.failure is not None:
        roots.append(result.failure.details)
    pending = [value for value in roots if isinstance(value, dict)]
    seen: set[int] = set()
    while pending:
        payload = pending.pop()
        marker = id(payload)
        if marker in seen:
            continue
        seen.add(marker)
        yield payload
        pending.extend(value for value in payload.values() if isinstance(value, dict))


def _resource_guard_violations(analysis: dict[str, Any], guard: dict[str, Any]) -> list[dict[str, Any]]:
    checks = [
        ("file_count", "max_file_count"),
        ("item_count", "max_item_count"),
        ("total_unpacked_size", "max_total_unpacked_size"),
        ("largest_item_size", "max_largest_item_size"),
    ]
    violations: list[dict[str, Any]] = []
    for field, limit_key in checks:
        limit = _optional_positive_int(guard.get(limit_key))
        if limit is None:
            continue
        actual = _safe_int(analysis.get(field))
        if actual > limit:
            violations.append({"field": field, "limit": limit, "actual": actual})
    ratio_limit = _optional_positive_float(guard.get("max_compression_ratio"))
    if ratio_limit is not None:
        unpacked = _safe_int(analysis.get("total_unpacked_size"))
        packed = _safe_int(analysis.get("total_packed_size") or analysis.get("archive_size"))
        if packed > 0:
            ratio = unpacked / packed
            if ratio > ratio_limit:
                violations.append({"field": "compression_ratio", "limit": ratio_limit, "actual": ratio})
    return violations


def _optional_positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _optional_positive_float(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _coverage_payload(verification: VerificationResult) -> dict[str, Any]:
    coverage = verification.archive_coverage
    return {
        "completeness": coverage.completeness,
        "file_coverage": coverage.file_coverage,
        "byte_coverage": coverage.byte_coverage,
        "expected_files": coverage.expected_files,
        "matched_files": coverage.matched_files,
        "complete_files": coverage.complete_files,
        "partial_files": coverage.partial_files,
        "failed_files": coverage.failed_files,
        "missing_files": coverage.missing_files,
        "unverified_files": coverage.unverified_files,
        "expected_bytes": coverage.expected_bytes,
        "matched_bytes": coverage.matched_bytes,
        "complete_bytes": coverage.complete_bytes,
        "confidence": coverage.confidence,
        "sources": list(coverage.sources),
    }


def _coverage_complete_files(payload: dict[str, Any]) -> int:
    coverage = payload.get("archive_coverage") if isinstance(payload, dict) else {}
    if not isinstance(coverage, dict):
        return 0
    try:
        return max(0, int(coverage.get("complete_files") or 0))
    except (TypeError, ValueError):
        return 0


def _verification_payload(verification: VerificationResult) -> dict[str, Any]:
    output_quality = _output_quality_payload(verification)
    return {
        "completeness": verification.completeness,
        "recoverable_upper_bound": verification.recoverable_upper_bound,
        "assessment_status": verification.assessment_status,
        "content_integrity": verification.content_integrity,
        "container_integrity": verification.container_integrity,
        "verification_strength": verification.verification_strength,
        "total_item_count": verification.total_item_count,
        "verified_item_count": verification.verified_item_count,
        "archive_walk_complete": verification.archive_walk_complete,
        "decision_hint": verification.decision_hint,
        "output_quality_score": output_quality["score"],
        "output_file_count": output_quality["file_count"],
        "output_total_bytes": output_quality["total_bytes"],
        "output_complete_ratio": output_quality["complete_ratio"],
        "output_failed_ratio": output_quality["failed_ratio"],
        "output_empty": output_quality["empty"],
        "output_confidence": output_quality["confidence"],
        "output_quality": output_quality,
        "archive_coverage": _coverage_payload(verification),
    }


def _output_quality_payload(verification: VerificationResult | Any) -> dict[str, Any]:
    return {
        "score": float(getattr(verification, "output_quality_score", 0.0) or 0.0),
        "file_count": int(getattr(verification, "output_file_count", 0) or 0),
        "total_bytes": int(getattr(verification, "output_total_bytes", 0) or 0),
        "complete_ratio": float(getattr(verification, "output_complete_ratio", 0.0) or 0.0),
        "failed_ratio": float(getattr(verification, "output_failed_ratio", 0.0) or 0.0),
        "empty": bool(getattr(verification, "output_empty", True)),
        "confidence": float(getattr(verification, "output_confidence", 0.0) or 0.0),
    }


def _should_retry_missing_volume_resolution(
    task: ArchiveTask,
    result: ExtractionResult,
) -> bool:
    failure = result.failure
    if failure is not None and failure.contains(FailureKind.MISSING_VOLUME):
        return True
    anchor = task.fact_bag.get("relation.volume_anchor") or {}
    structurally_incomplete = bool(
        isinstance(anchor, dict)
        and anchor.get("confidence") == "strong"
        and anchor.get("multivolume")
        and task.fact_bag.get("relation.split_group_complete") is False
    )
    return bool(
        structurally_incomplete
        and failure is not None
        and failure.kind in {
            FailureKind.UNSUPPORTED,
            FailureKind.DAMAGED,
            FailureKind.UNKNOWN,
        }
    )


def _possible_missing_volume_failure(
    task: ArchiveTask,
    outcome_kind: OutcomeKind,
    failure: FailureInfo | None,
    i18n: I18nContext,
) -> FailureInfo | None:
    if outcome_kind == OutcomeKind.COMPLETE_SUCCESS or not _task_is_split_input(task):
        return None
    if failure is not None and failure.contains(FailureKind.MISSING_VOLUME):
        return None

    missing_indices = [int(value) for value in (task.fact_bag.get("relation.split_missing_indices") or [])]
    missing_ranges = [
        [int(value) for value in item]
        for item in (task.fact_bag.get("relation.split_observed_missing_ranges") or [])
        if isinstance(item, (list, tuple))
    ]
    observed_gap = bool(missing_indices or missing_ranges)
    probe_suspected = _failure_has_possible_missing_volume_evidence(failure)

    evidence = ""
    if outcome_kind == OutcomeKind.PARTIAL_SUCCESS:
        evidence = "partial_recovery_on_split_input"
    elif probe_suspected:
        evidence = "backend_possible_missing_volume"
    elif observed_gap and failure is not None and failure.kind in {
        FailureKind.UNKNOWN,
        FailureKind.DAMAGED,
    }:
        evidence = "observed_volume_gap_after_archive_failure"
    if not evidence:
        return None

    details: dict[str, Any] = {
        "missing_volume_confirmed": False,
        "evidence": evidence,
        "partial_recovery": outcome_kind == OutcomeKind.PARTIAL_SUCCESS,
    }
    if missing_indices:
        details["observed_missing_indices"] = missing_indices
    if missing_ranges:
        details["observed_missing_ranges"] = missing_ranges
    if failure is not None:
        details["original_failure_kind"] = failure.kind.value

    return FailureInfo(
        kind=FailureKind.MISSING_VOLUME,
        stage="extraction_report",
        message=i18n.t("failure.possible_missing_volume"),
        message_key="failure.possible_missing_volume",
        user_action="wait_for_volume",
        causes=(failure,) if failure is not None else (),
        details=details,
    )


def _task_is_split_input(task: ArchiveTask) -> bool:
    return bool(
        task.split_info.is_split
        or task.fact_bag.get("relation.is_split_related")
        or len(task.all_parts or []) > 1
    )


def _failure_has_possible_missing_volume_evidence(failure: FailureInfo | None) -> bool:
    if failure is None:
        return False
    details = failure.details if isinstance(failure.details, dict) else {}
    read_error = details.get("read_error") if isinstance(details.get("read_error"), dict) else {}
    if read_error.get("possible_missing_volume"):
        return True
    if details.get("missing_volume_confirmed") is False and details.get("evidence"):
        return True
    return any(_failure_has_possible_missing_volume_evidence(cause) for cause in failure.causes)
