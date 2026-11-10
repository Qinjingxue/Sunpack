import os
from dataclasses import dataclass, replace
from typing import Any

from sunpack.core.contracts.run_state import RunState
from sunpack.core.contracts.results import OutcomeKind, TargetRunResult
from sunpack.core.contracts.content_recovery import (
    ContentRecoveryDecision,
    ContentRecoveryPolicy,
)
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.postprocess.failed_output_cleanup import cleanup_failed_output_if_eligible
from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.pipeline.extraction.knowledge import write_extraction_result
from sunpack.pipeline.extraction.scheduler import ExtractionScheduler
from sunpack.pipeline.extraction.output_inventory import OutputInventory
from sunpack.pipeline.postprocess.output_cleanup import DEFAULT_OUTPUT_CLEANUP_MANAGER, OutputCleanupEvent

from sunpack.core.passwords.directory_context import PasswordScopeContext
from sunpack.pipeline.verification import VerificationResult, VerificationScheduler
from sunpack.core.i18n import I18nContext


def _advance_job_state(state, sent, *, first: bool):
    try:
        return False, next(state) if first else state.send(sent)
    except StopIteration as completed:
        return True, completed.value


@dataclass
class ArchiveJobOutcome:
    result: ExtractionResult
    verification: VerificationResult | None = None
    attempts: int = 1
    planned_out_dir: str = ""
    content_decision: ContentRecoveryDecision = ContentRecoveryDecision()

    @property
    def outcome_kind(self) -> OutcomeKind:
        return self.content_decision.outcome_kind

    @property
    def policy_rejected_partial_output(self) -> bool:
        return self.content_decision.rejected_partial_output


class ArchiveJobExecutor:
    def __init__(
        self,
        context: RunState,
        extractor: ExtractionScheduler,
        config: dict,
        *,
        progress_reporter: Any | None = None,
        request_id: str = "",
        origin: str = "",
        output_reservations=None,
    ):
        self.context = context
        self.extractor = extractor
        self.config = config
        self.scanning = config.get("extraction", {}).get("operation") == "scan"
        self.content_policy = ContentRecoveryPolicy.from_config(self.config)
        cli_config = self.config["cli"]
        self.i18n = I18nContext(cli_config["language"])
        self.progress_reporter = progress_reporter
        self.request_id = str(request_id or "")
        self.origin = str(origin or "")
        self.output_reservations = output_reservations
        self._uncommitted_outputs: dict[str, ArchiveTask] = {}
        self.verifier = VerificationScheduler(self.config, password_session=self.extractor.password_session)
        self.password_scope_context = self.config.get("password_scope_context") or PasswordScopeContext(self.config.get("password_scope_dir", ""))

    def _finish_output(self, task, output_dir: str, *, keep: bool) -> None:
        active = task.runtime.pop("watch_active_output", None)
        if self.origin == "watch":
            self.extractor.emit_semantic_event(
                task, "task_output_finished", critical=True,
                task_path=active[0] if active is not None else task.main_path,
                output_dir=output_dir, keep_output=keep,
            )

    @property
    def has_uncommitted_outputs(self) -> bool:
        return bool(self._uncommitted_outputs)

    def rollback_interrupted_outputs(self) -> tuple[str, ...]:
        errors = []
        for output_dir, task in self._uncommitted_outputs.items():
            continued = bool(task.runtime.get("retry_output_dir"))
            paths = task.runtime.get("retry_created_outputs", ()) if continued else (output_dir,)
            before_errors = len(errors)
            for path in paths:
                result = DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_canonical(
                    path, event=OutputCleanupEvent.USER_CANCELLED,
                    planned_output_dir=path, allow_nonempty=True,
                )
                if not (result.cleaned or result.already_absent):
                    errors.append(f"{path}: {result.error or result.reason}")
            if not continued and len(errors) != before_errors:
                continue
            self._finish_output(task, output_dir, keep=continued)
        self._uncommitted_outputs.clear()
        return tuple(errors)

    def relocate_output(self, result) -> bool:
        if not result.source_dir:
            return False
        task = self._uncommitted_outputs.pop(result.path, None)
        if task is None:
            return False
        self._uncommitted_outputs[result.output_dir] = task
        if self.origin == "watch":
            active = task.runtime.get("watch_active_output")
            task_path = active[0] if active is not None else task.main_path
            task.runtime["watch_active_output"] = (task_path, result.output_dir)
            self.extractor.emit_semantic_event(
                task, "task_output_started", critical=True, task_path=task_path, output_dir=result.output_dir,
            )
        return True

    def commit_output(self, task, output_dir, cancellation) -> None:
        cancellation.raise_if_cancelled()
        if output_dir not in self._uncommitted_outputs:
            return
        self._finish_output(task, output_dir, keep=True)
        self._uncommitted_outputs.pop(output_dir, None)

    def finish_outputs(self) -> None:
        for output_dir, task in self._uncommitted_outputs.items():
            self._finish_output(task, output_dir, keep=bool(task.runtime.pop("watch_keep_output", False)))
        self._uncommitted_outputs.clear()

    async def execute_async(
        self,
        task: ArchiveTask,
        *,
        depth: int,
        output_dir_resolver,
        broker,
        cancellation,
        missing_volume_retry=None,
        ensure_input_lease=None,
    ) -> tuple[ArchiveTask, ArchiveJobOutcome, TargetRunResult]:
        """Run one logical archive through preflight, extraction and verification."""

        try:
            task, outcome = await self._execute_one_async(
                task,
                output_dir_resolver,
                depth=depth,
                broker=broker,
                cancellation=cancellation,
                missing_volume_retry=missing_volume_retry,
                ensure_input_lease=ensure_input_lease,
            )
        finally:
            # A later output or progress consumer may still own the task.
            # The native inventory and catalog are only needed for volume retry.
            task.runtime.pop("discovery_snapshot", None)
            task.runtime.pop("discovery_catalog", None)
        result = await broker.run(
            "collect_result_cleanup",
            task.key or task.main_path,
            self.collect_result,
            task,
            outcome,
            request_id=self.request_id,
            cancellation=cancellation,
        )
        await broker.run(
            "report", task.key or task.main_path, self._report_task_finished, task, outcome, depth,
            request_id=self.request_id, cancellation=cancellation,
        )
        preserve_output = bool(result.output_dir and (
            task.runtime.get("retry_output_dir")
            or result.outcome_kind != OutcomeKind.FAILURE or outcome.result.has_complete_inputs
        ))
        path = outcome.planned_out_dir
        if path in self._uncommitted_outputs and not os.path.lexists(path):
            self._uncommitted_outputs.pop(path)
            await broker.run("output_state", task.key or task.main_path, self._finish_output,
                             task, path, keep=False, request_id=self.request_id)
        if self.origin == "watch" and depth == 1:
            task.runtime["watch_keep_output"] = preserve_output
        elif self.origin == "watch":
            active_output = task.runtime.pop("watch_active_output", None)
            if active_output is not None:
                await self.extractor.emit_semantic_event_async(
                    broker, task, "task_output_finished", request_id=self.request_id, critical=True,
                    task_path=active_output[0], output_dir=active_output[1], keep_output=preserve_output,
                )
        if preserve_output:
            self.password_scope_context.remember(result.output_dir, task)
        return task, outcome, result

    async def _execute_one_async(
        self,
        task: ArchiveTask,
        output_dir_resolver,
        *,
        depth: int,
        broker,
        cancellation,
        missing_volume_retry=None,
        ensure_input_lease=None,
    ) -> tuple[ArchiveTask, ArchiveJobOutcome]:
        file_id = task.key or task.main_path

        def preflight():
            if not retried_missing_volume:
                self._report_task_started(task, depth)
            if task.discovery_failure is not None:
                failure = task.discovery_failure
                if failure.message_key:
                    failure = replace(failure, message=self.i18n.t(failure.message_key, **failure.message_params))
                return "", ArchiveJobOutcome(ExtractionResult(
                    success=False, out_dir="", error=failure.message, failure=failure,
                ))
            out_dir = "" if self.scanning else output_dir_resolver(task)
            result = self.extractor.inspect(task, out_dir)
            if result is not None:
                return out_dir, ArchiveJobOutcome(result)
            return out_dir, None

        retried_missing_volume = False
        while True:
            if callable(ensure_input_lease):
                await ensure_input_lease(task)
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
        if terminal is not None:
            terminal.planned_out_dir = planned_out_dir
            return task, terminal

        if self.scanning:
            result = await self.extractor.extract_asyncio(
                broker, task, "", request_id=self.request_id, file_id=file_id, cancellation=cancellation,
            )
            return task, ArchiveJobOutcome(result)

        register_output = self.output_reservations is not None and self.output_reservations.watch_outputs is not None
        register_with_start = register_output and self.origin == "watch" and bool(self.config.get("watch_owner_path"))
        if register_output and not register_with_start:
            await broker.run("watch_output_root", file_id, self.output_reservations.register_watch_output,
                             planned_out_dir, request_id=self.request_id, cancellation=cancellation)
        if self.origin == "watch":
            await broker.run("output_state", file_id, self._start_watch_output, task,
                             planned_out_dir, depth, register_with_start,
                             request_id=self.request_id, cancellation=cancellation)
        else:
            self._track_output(task, planned_out_dir, depth)
        state = self._extract_verify_state_machine(
            task,
            planned_out_dir,
            missing_volume_retry=missing_volume_retry,
            volume_retry_attempted=retried_missing_volume,
        )
        sent = None
        first = True
        while True:
            done, value = await broker.run(
                "extract_prepare" if first else "verify_extract",
                file_id,
                _advance_job_state,
                state,
                sent,
                first=first,
                request_id=self.request_id,
                cancellation=cancellation,
            )
            if done:
                outcome = value
                outcome.planned_out_dir = planned_out_dir
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

    def _start_watch_output(self, task, path, depth, register_output):
        self.extractor.emit_semantic_event(
            task, "task_output_started", critical=True, output_dir=path,
            register_output=register_output,
        )
        # Track only after exclusive creation succeeds. The broker joins this
        # operation before cancellation can roll back a successfully started job.
        task.runtime["watch_active_output"] = (task.main_path, path)
        self._track_output(task, path, depth)

    def _track_output(self, task, path, depth):
        if depth == 1:
            self._uncommitted_outputs[path] = task
        if task.runtime.get("retry_output_dir"):
            task.runtime["retry_created_outputs"] = []

    def _report_task_started(self, task: ArchiveTask, depth: int) -> None:
        if self.progress_reporter is not None:
            self.progress_reporter.task_started(task, depth)

    def _report_task_finished(self, task: ArchiveTask, outcome: ArchiveJobOutcome, depth: int) -> None:
        if self.progress_reporter is not None:
            self.progress_reporter.task_finished(task, outcome, depth)

    def _report_task_status(self, task: ArchiveTask, state: str, detail: str = "") -> None:
        if self.progress_reporter is not None:
            self.progress_reporter.task_status(task, state, detail)

    def _extract_verify_state_machine(
        self,
        task: ArchiveTask,
        out_dir: str,
        *,
        missing_volume_retry=None,
        volume_retry_attempted: bool = False,
    ):
        while True:
            self._report_task_status(task, "extracting")
            result = yield {
                "task": task,
                "out_dir": out_dir,
            }
            write_extraction_result(task, result)
            if not result.success:
                self._report_task_status(task, "error", str(result.error or ""))
                verification = self.verifier.verify(task, result)
                current_outcome = ArchiveJobOutcome(
                    result=result,
                    verification=verification,
                    attempts=1,
                )
                if (
                    not volume_retry_attempted
                    and callable(missing_volume_retry)
                    and _should_retry_missing_volume_resolution(result)
                ):
                    volume_retry_attempted = True
                    self._report_task_status(task, "resolving_volumes")
                    replacement = missing_volume_retry(task, current_outcome)
                    if isinstance(replacement, ArchiveTask):
                        DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_canonical(
                            result.out_dir,
                            event=OutputCleanupEvent.VERIFICATION_RETRY,
                            planned_output_dir=out_dir,
                        )
                        task.adopt_detection_plan(replacement)
                        self.password_scope_context.annotate([task])
                        continue
                return current_outcome

            # Verification observes this extraction once. Failed verification
            # is a result, not a reason to run the same extraction again.
            verification = self.verifier.verify(task, result)
            return ArchiveJobOutcome(result=result, verification=verification, attempts=1)

    def collect_result(self, task: ArchiveTask, outcome: ArchiveJobOutcome | ExtractionResult) -> TargetRunResult:
        if isinstance(outcome, ExtractionResult):
            outcome = ArchiveJobOutcome(outcome)
        res = outcome.result
        if self.scanning:
            from sunpack.pipeline.coordinator.scan_projection import scan_items

            result = TargetRunResult(
                input_path=task.main_path, task_key=task.key,
                outcome_kind=OutcomeKind.SCANNED if res.success else OutcomeKind.FAILURE,
                failure=res.failure, error=res.error,
                scan_items=tuple(scan_items(task, res, self.i18n)),
            )
            with self.context.lock:
                self.context.add_target_result(result)
            return result
        outcome.content_decision = self.content_policy.decide(res, outcome.verification)
        out_dir = res.out_dir
        inventory = OutputInventory.from_value(res.output_inventory, expected_root=out_dir) if out_dir else None
        payload_inventory = (inventory.stats.file_count, inventory.stats.total_size) if inventory is not None else None
        if res.input_results:
            payload_inventory = (res.files_written, res.bytes_written)
        cleanup = cleanup_failed_output_if_eligible(
            out_dir,
            planned_output_dir=outcome.planned_out_dir,
            failed=outcome.outcome_kind == OutcomeKind.FAILURE and not task.runtime.get("retry_output_dir"),
            force_owned_output_cleanup=outcome.policy_rejected_partial_output,
            payload_inventory=payload_inventory,
        )
        diagnostics = res.diagnostics
        res.diagnostics = {**diagnostics, "failed_output_cleanup": cleanup.to_dict()}

        if res.failure is not None and (
            task.runtime.get("retry_output_dir") or res.has_complete_inputs
        ):
            # The path itself is the continuation signal; no output scan or
            # retained success inventories are needed across requests/restarts.
            res.failure = replace(res.failure, details={
                **res.failure.details, "retry_output_dir": out_dir,
            })

        possible_missing_volume = _possible_missing_volume_failure(
            task,
            outcome.outcome_kind,
            res.failure,
            self.i18n,
        )
        if outcome.outcome_kind == OutcomeKind.FAILURE and possible_missing_volume is not None:
            res.failure = possible_missing_volume
            res.error = possible_missing_volume.message

        recovery = None
        if outcome.outcome_kind == OutcomeKind.PARTIAL_SUCCESS and outcome.verification is not None:
            recovery = {
                "archive": task.main_path,
                "out_dir": out_dir,
                "completeness": outcome.verification.completeness,
                "assessment_status": outcome.verification.assessment_status,
                "content_integrity": outcome.verification.content_integrity,
                "container_integrity": outcome.verification.container_integrity,
                "verification_strength": outcome.verification.verification_strength,
                "archive_coverage": _coverage_payload(outcome.verification),
                **(
                    {"warning": possible_missing_volume.to_dict()}
                    if possible_missing_volume is not None
                    else {}
                ),
            }

        result = TargetRunResult(
            input_path=task.main_path,
            outcome_kind=outcome.outcome_kind,
            task_key=task.key,
            output_dir=out_dir,
            verification=_verification_payload(outcome.verification) if outcome.verification is not None else {},
            error=(
                possible_missing_volume.message
                if possible_missing_volume is not None
                else str(res.error or "")
            ),
            failure=(possible_missing_volume if possible_missing_volume is not None else outcome.result.failure),
            failure_message=(
                self._failure_message(task, outcome)
                if outcome.outcome_kind == OutcomeKind.FAILURE
                else ""
            ),
            recovery=recovery,
        )
        with self.context.lock:
            if outcome.outcome_kind in {OutcomeKind.COMPLETE_SUCCESS, OutcomeKind.PARTIAL_SUCCESS}:
                self.context.processed_keys.add(task.key)
            self.context.add_target_result(result)
        return result

    def _failure_message(self, task: ArchiveTask, outcome: ArchiveJobOutcome) -> str:
        name = os.path.basename(task.main_path)
        if outcome.result.success and outcome.verification is not None and outcome.outcome_kind == OutcomeKind.FAILURE:
            return f"{name} [{self._verification_failure_summary(outcome)}]"
        return f"{name} [{outcome.result.error}]"

    def _verification_failure_summary(self, outcome: ArchiveJobOutcome) -> str:
        verification = outcome.verification
        if verification is None:
            return self.i18n.t("failure.verification_failed")
        steps = "; ".join(f"{step.method}:{step.status}" for step in verification.steps) or "none"
        return self.i18n.t(
            "failure.verification_failed_detail",
            completeness=verification.completeness,
            integrity=verification.assessment_status,
            decision=verification.decision_hint,
            coverage=verification.archive_coverage.completeness,
            attempts=outcome.attempts,
            steps=steps,
        )


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


def _output_quality_payload(verification: VerificationResult) -> dict[str, Any]:
    return {
        "score": verification.output_quality_score,
        "file_count": verification.output_file_count,
        "total_bytes": verification.output_total_bytes,
        "complete_ratio": verification.output_complete_ratio,
        "failed_ratio": verification.output_failed_ratio,
        "empty": verification.output_empty,
        "confidence": verification.output_confidence,
    }


def _should_retry_missing_volume_resolution(
    result: ExtractionResult,
) -> bool:
    failure = result.failure
    # The physical-family fallback replaces the entire task and clears its
    # output. Multi-input carriers resume through the segment continuation.
    return bool(failure is not None and not result.input_results
                and failure.contains(FailureKind.MISSING_VOLUME))


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
    probe_suspected = _failure_has_possible_missing_volume_evidence(failure)

    evidence = ""
    if outcome_kind == OutcomeKind.PARTIAL_SUCCESS:
        evidence = "partial_recovery_on_split_input"
    elif probe_suspected:
        evidence = "backend_possible_missing_volume"
    if not evidence:
        return None

    details: dict[str, Any] = {
        "missing_volume_confirmed": False,
        "evidence": evidence,
        "partial_recovery": outcome_kind == OutcomeKind.PARTIAL_SUCCESS,
    }
    if failure is not None:
        details["original_failure_kind"] = failure.kind.value

    return FailureInfo(
        kind=FailureKind.DAMAGED,
        stage="extraction_report",
        message=i18n.t("failure.possible_missing_volume"),
        message_key="failure.possible_missing_volume",
        causes=(failure,) if failure is not None else (),
        details=details,
    )


def _task_is_split_input(task: ArchiveTask) -> bool:
    descriptor = task.archive_input()
    return bool(
        descriptor.open_mode in {"native_volumes", "sfx_with_volumes"}
        or len(descriptor.part_paths()) > 1
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
