import asyncio
import os
import subprocess
from contextlib import nullcontext
from typing import Any, Callable

from sunpack_native import analyze_zip_filename_encoding

from sunpack.core.support.output_paths import OutputPathAllocator
from sunpack.core.support.path_keys import resolved_path_key
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor

from sunpack.core.contracts.failures import PASSWORD_NOT_IN_LIST_KEY, FailureInfo, FailureKind, aggregate_input_failures
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.contracts.input_plan import LogicalArchiveInput
from sunpack.pipeline.extraction.internal.workflow.errors import classify_extract_failure
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner
from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import discard_worker_file_tables, worker_result_payload
from sunpack.pipeline.extraction.progress import build_extraction_progress_manifest, recoverable_partial_inventory
from sunpack.core.contracts.extraction import ExtractionResult, InputExecutionResult
from sunpack.core.passwords.result import PasswordResolution, PasswordResolutionStatus
from sunpack.core.passwords.resolver import archive_structure_password_state
from sunpack.core.support import archive_knowledge_projection as knowledge_view
from sunpack.core.support.archive_input_projection import write_source_password_probe_input
from sunpack.pipeline.extraction.output_inventory import OutputInventory, collect_output_inventory
from sunpack.core.i18n import I18nContext
from sunpack.pipeline.postprocess.output_cleanup import DEFAULT_OUTPUT_CLEANUP_MANAGER, OutputCleanupEvent


def _zip_filename_codepage(task: ArchiveTask, descriptor: ArchiveInputDescriptor) -> str | None:
    if descriptor.format_hint != "zip" or descriptor.volume_attempts is not None:
        # A speculative volume family cannot supply an archive-wide override.
        return None

    generation = task.runtime.get("input_generation")
    cached = task.runtime.get("zip_filename_codepage")
    if cached is not None and cached[0] == generation and cached[1] is descriptor:
        return cached[2]

    try:
        codepage = analyze_zip_filename_encoding(descriptor.to_dict())
    except Exception:
        # Filename encoding is optional. The backend can still use ZIP flags
        # and Unicode extra fields when inspection fails.
        codepage = None
    task.runtime["zip_filename_codepage"] = (generation, descriptor, codepage)
    return codepage


def _advance_state(state, sent, *, first: bool, runner: SevenZipRunner, cancellation_token):
    # Run planning, filesystem preparation and failure continuations in the
    # same admitted broker job. Only native transport returns to the loop.
    while True:
        if cancellation_token is not None:
            cancellation_token.raise_if_cancelled()
        try:
            request = next(state) if first else state.send(sent)
        except StopIteration as completed:
            return True, completed.value
        first = False
        try:
            job = runner._build_job(**request)
        except Exception as exc:
            sent = runner.failed_process_for_exception(exc, request)
        else:
            return False, {"job": job, "task": request["task"]}


class SingleArchiveExtractor:
    def __init__(
        self,
        password_store,
        password_resolver,
        sevenzip_runner: SevenZipRunner | None = None,
        best_effort: bool = True,
        quiet: bool = False,
        language: str = "en",
        operation: str = "extract",
    ):
        self.password_store = password_store
        self.password_resolver = password_resolver
        self.sevenzip_runner = sevenzip_runner
        self.best_effort = bool(best_effort)
        self.quiet = bool(quiet)
        self.i18n = I18nContext(language)
        self.scanning = operation == "scan"

    async def extract_asyncio(
        self,
        broker,
        task: ArchiveTask,
        out_dir: str,
        *,
        request_id: str,
        file_id: str,
        cancellation,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "extract",
    ) -> ExtractionResult:
        """Advance one extraction generator without holding a worker slot
        while the native worker owns the archive operation.
        """

        state = self._extract_state_machine(
            task,
            out_dir,
            phase_timer=phase_timer,
            phase_prefix=phase_prefix,
        )
        sent = None
        first = True
        while True:
            done, value = await broker.run(
                "extract_prepare" if first else "extract_continue",
                file_id,
                _advance_state,
                state,
                sent,
                first=first,
                runner=self.sevenzip_runner,
                cancellation_token=cancellation,
                request_id=request_id,
                cancellation=cancellation,
            )
            if done:
                return value
            request = value
            first = False
            try:
                sent = await cancellation.wait(
                    self.sevenzip_runner.submit_attempt_asyncio(**request)
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                sent = self.sevenzip_runner.failed_process_for_exception(exc, request)

    def _extract_state_machine(
        self,
        task: ArchiveTask,
        out_dir: str,
        *,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "extract",
    ):
        inputs = task.inputs
        if (len(inputs) == 1 and inputs[0].descriptor is task.archive_input()
                and inputs[0].failure is None and not task.recovery.checkpoints):
            result = yield from self._extract_one_state_machine(
                task, out_dir, phase_timer=phase_timer, phase_prefix=phase_prefix,
            )
            result.logical_input = task.inputs[0]
            return result
        return (yield from self._extract_inputs_state_machine(
            task, out_dir, inputs, phase_timer=phase_timer, phase_prefix=phase_prefix,
        ))

    def _extract_one_state_machine(
        self, task: ArchiveTask, out_dir: str, *,
        phase_timer: Callable[..., Any] | None = None, phase_prefix: str = "extract",
    ):
        node = task.inputs[0]
        if node.password is not None:
            task.knowledge().set("archive.password", node.password,
                                 source_layer="analysis", source_module="input_plan")
        descriptor = task.archive_input()
        archive = descriptor.entry_path
        run_parts = descriptor.part_paths()
        is_split = (
            descriptor.open_mode in {"native_volumes", "sfx_with_volumes"}
            or len(run_parts) > 1
        )

        self._log(task, self.i18n.t("extract.log.start", archive=archive))

        try:
            if not self.scanning:
                os.makedirs(out_dir, exist_ok=True)
        except Exception as exc:
            failure = self._failure_info(FailureKind.FILESYSTEM_ERROR, "preflight", "extract.dir_create_failed", error=str(exc))
            return self._failed(
                out_dir,
                self._localized_failure(failure),
                failure=failure,
                diagnostics={"failure_stage": "preflight", "failure_kind": "output_filesystem", "message": str(exc)},
            )

        run_result = None
        err = ""
        correct_pwd = None

        with _phase(phase_timer, f"{phase_prefix}_resolve_password"):
            resolution = self._resolve_password(task, archive, run_parts)
        resolution_failure = self._password_resolution_failure(resolution)
        if resolution_failure is not None:
            self._cleanup_output(out_dir, OutputCleanupEvent.EXTRACTION_ABORT)
            self._log(task, self.i18n.t("extract.log.failed", archive=archive, error=self._localized_failure(resolution_failure)))
            return self._failed(
                out_dir,
                self._localized_failure(resolution_failure),
                failure=resolution_failure,
                diagnostics={
                    "failure_stage": resolution_failure.stage,
                    "failure_kind": resolution_failure.kind.value,
                    "message": resolution.error_text,
                    "result": {"encrypted": resolution.encrypted} if resolution.encrypted is not None else {},
                },
            )
        correct_pwd = resolution.password
        test_err = resolution.error_text
        if correct_pwd is None:
            err = test_err
        else:
            with _phase(phase_timer, f"{phase_prefix}_scan_filename_encoding"):
                selected_codepage = None if self.scanning else _zip_filename_codepage(task, descriptor)
            self.sevenzip_runner.emit_semantic_event(
                task,
                "extract_ready",
                archive_path=archive,
                completed_bytes=0,
                total_bytes=0,
            )
            with _phase(phase_timer, f"{phase_prefix}_sevenzip_attempt"):
                run_result = yield {
                    "archive_path": archive,
                    "out_dir": out_dir,
                    "password": correct_pwd,
                    "password_candidates": list(resolution.candidate_passwords),
                    "password_verified": bool(correct_pwd) and not resolution.requires_extraction_confirmation,
                    "encrypted": resolution.encrypted,
                    "operation": "scan" if self.scanning else "extract",
                    "selected_codepage": selected_codepage,
                    "task": task,
                    "phase_timer": phase_timer,
                    "phase_prefix": f"{phase_prefix}_sevenzip",
                }

            if self.scanning:
                return self._scan_result(resolution, run_result, archive, is_split)

            if run_result.returncode == 0:
                if descriptor.volume_attempts is not None:
                    selection = worker_result_payload(run_result).get("volume_selection")
                    if not isinstance(selection, dict):
                        raise ValueError("worker omitted the successful volume composition")
                    task.select_volumes(node, descriptor.select_volumes(selection))
                selected_password = self._worker_selected_password(resolution, run_result)
                if selected_password is not None:
                    correct_pwd = selected_password
                if resolution.requires_extraction_confirmation:
                    self.password_resolver.confirm_extraction(resolution, password=correct_pwd)
                with _phase(phase_timer, f"{phase_prefix}_diagnostics_success"):
                    diagnostics = self._diagnostics_from(run_result)
                    if resolution.requires_extraction_confirmation:
                        worker_result = worker_result_payload(run_result)
                        diagnostics["password_verification"] = self._password_verification_label(
                            resolution, worker_result
                        )
                        diagnostics["password_candidates_rejected"] = int(
                            worker_result.get("password_attempts") or 0
                        ) if worker_result.get("password_candidates_all_rejected") else 0
                        diagnostics["password_candidates_inconclusive"] = 0
                with _phase(phase_timer, f"{phase_prefix}_output_stats_success"):
                    worker_result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
                    output_inventory = collect_output_inventory(out_dir, worker_result)
                    output_stats = {
                        "file_count": output_inventory.stats.file_count,
                        "total_bytes": output_inventory.stats.total_size,
                    }
                    self._fill_success_output_counts(diagnostics, output_stats)
                self._log(task, self.i18n.t("extract.log.success", archive=archive))
                manifest_payload = None
                if worker_result:
                    with _phase(phase_timer, f"{phase_prefix}_build_success_manifest"):
                        manifest_payload = build_extraction_progress_manifest(
                            archive=archive,
                            output_inventory=output_inventory,
                            diagnostics=diagnostics,
                        )
                    discard_worker_file_tables(worker_result)
                return ExtractionResult(
                    success=True,
                    out_dir=out_dir,
                    password_used=correct_pwd,
                    selected_codepage=selected_codepage,
                    diagnostics=diagnostics,
                    progress_manifest_payload=manifest_payload,
                    output_inventory=output_inventory,
                    files_written=output_stats["file_count"],
                    bytes_written=output_stats["total_bytes"],
                )

            err = f"{run_result.stdout}\n{run_result.stderr}".lower()
        with _phase(phase_timer, f"{phase_prefix}_classify_error"):
            failure = classify_extract_failure(
                run_result,
                err,
                archive=archive,
                is_split_archive=is_split,
                password_evidence=resolution.candidate_evidence,
            )
        if resolution.requires_extraction_confirmation and run_result is not None:
            worker_result = worker_result_payload(run_result)
            selected_password = self._worker_selected_password(resolution, run_result)
            if selected_password is not None:
                correct_pwd = selected_password
            if failure.details.get("evidence") == "entry_crc_proven_before_failure":
                self.password_resolver.confirm_extraction(resolution, password=correct_pwd)
            elif failure.kind == FailureKind.WRONG_PASSWORD and worker_result.get("password_candidates_all_rejected"):
                self.password_resolver.reject_extraction_candidates(resolution)

        error_msg = self._localized_failure(failure)
        self._log(task, self.i18n.t("extract.log.failed", archive=archive, error=error_msg))
        with _phase(phase_timer, f"{phase_prefix}_diagnostics_failure"):
            diagnostics = self._diagnostics_from(run_result)
            if resolution.requires_extraction_confirmation:
                worker_result = worker_result_payload(run_result)
                diagnostics["password_verification"] = self._password_verification_label(
                    resolution, worker_result
                )
                diagnostics["password_candidates_rejected"] = int(
                    worker_result.get("password_attempts") or 0
                ) if failure.kind == FailureKind.WRONG_PASSWORD and worker_result.get("password_candidates_all_rejected") else 0
                diagnostics["password_candidates_inconclusive"] = (
                    len(resolution.candidate_passwords)
                    if failure.kind == FailureKind.PASSWORD_INCONCLUSIVE
                    else 0
                )
        output_inventory = None
        if self.best_effort and failure.kind != FailureKind.PASSWORD_INCONCLUSIVE:
            with _phase(phase_timer, f"{phase_prefix}_recoverable_partial_check"):
                output_inventory = recoverable_partial_inventory(diagnostics, out_dir)
        manifest_payload = None
        if output_inventory is not None:
            with _phase(phase_timer, f"{phase_prefix}_build_partial_manifest"):
                manifest_payload = build_extraction_progress_manifest(
                    archive=archive,
                    output_inventory=output_inventory,
                    diagnostics=diagnostics,
                )
            diagnostics["partial_outputs"] = True
        discard_worker_file_tables(worker_result_payload(run_result))
        if output_inventory is None:
            self._cleanup_output(out_dir, OutputCleanupEvent.UNRECOVERABLE_FAILURE)
        return self._failed(
            out_dir,
            error_msg,
            failure=failure,
            password_used=(None if failure.kind in {FailureKind.WRONG_PASSWORD, FailureKind.PASSWORD_INCONCLUSIVE} else correct_pwd),
            selected_codepage=selected_codepage,
            diagnostics=diagnostics,
            partial_outputs=output_inventory is not None,
            progress_manifest_payload=manifest_payload,
            output_inventory=output_inventory,
        )


    def _resolve_password(self, task: ArchiveTask, archive_path: str, part_paths: list[str]):
        archive_key = self._password_archive_key(task)
        scope_path = task.runtime.get("password_scope_dir") or os.path.dirname(os.path.abspath(task.main_path))
        known_password = knowledge_view.archive_password(task)
        if known_password is not None:
            return PasswordResolution(
                password=str(known_password),
                status=PasswordResolutionStatus.RESOLVED,
                archive_key=archive_key,
            )
        if (
            not self.password_store.has_candidates(scope_path=scope_path)
            and (password_state := archive_structure_password_state(task)) != "required"
        ):
            unknown = password_state == "unknown"
            return PasswordResolution(
                password="",
                status=PasswordResolutionStatus.RESOLVED if unknown else PasswordResolutionStatus.UNENCRYPTED,
                archive_key=archive_key,
                encrypted=None if unknown else False,
                requires_extraction_confirmation=unknown,
                candidate_passwords=("",) if unknown else (),
                candidate_evidence="empty_password_direct" if unknown else "",
            )
        return self.password_resolver.resolve(
            archive_path,
            task,
            part_paths=part_paths,
            archive_key=archive_key,
            scope_path=scope_path,
        )

    def _cleanup_output(self, out_dir: str, event: OutputCleanupEvent) -> None:
        if self.scanning:
            return
        DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_canonical(
            out_dir,
            event=event,
            planned_output_dir=out_dir,
        )

    def _scan_result(self, resolution, run_result, archive, is_split):
        payload = worker_result_payload(run_result)
        confirmed = (resolution.password is not None and not resolution.requires_extraction_confirmation)
        confirmed = confirmed or payload.get("password_verified") is True
        password = self._worker_selected_password(resolution, run_result) if confirmed else None
        if payload.get("password_verified") is True:
            self.password_resolver.confirm_extraction(resolution, password=password)
        elif payload.get("password_candidates_all_rejected"):
            self.password_resolver.reject_extraction_candidates(resolution)
        failure = None
        if run_result.returncode != 0:
            failure = classify_extract_failure(run_result, f"{run_result.stdout}\n{run_result.stderr}".lower(),
                                               archive=archive, is_split_archive=is_split,
                                               password_evidence=resolution.candidate_evidence)
        # Keep only receipts, never transport histories or request candidate arrays.
        facts = {key: payload[key] for key in (
            "encrypted", "archive_type", "missing_volume", "missing_volume_evidence",
            "missing_volume_name", "password_verified", "failure_kind", "message",
        ) if key in payload}
        if resolution.encrypted is not None:
            facts.setdefault("encrypted", resolution.encrypted)
        return ExtractionResult(success=failure is None, out_dir="", password_used=password,
                                failure=failure, error=self._localized_failure(failure) if failure else "",
                                diagnostics={"result": facts})

    @staticmethod
    def _password_archive_key(task: ArchiveTask) -> str:
        return task.inputs[0].input_id

    def _failed(
        self,
        out_dir: str,
        error: str,
        *,
        failure: FailureInfo | None = None,
        password_used: str | None = None,
        selected_codepage: str | None = None,
        diagnostics: dict | None = None,
        partial_outputs: bool = False,
        progress_manifest_payload: Any = None,
        output_inventory: OutputInventory | None = None,
    ) -> ExtractionResult:
        diagnostic_payload = dict(diagnostics or {})
        if failure is not None:
            diagnostic_payload.setdefault("failure_stage", failure.stage)
            diagnostic_payload.setdefault("failure_kind", failure.kind.value)
            diagnostic_payload["failure"] = failure.to_dict()
        return ExtractionResult(
            success=False,
            out_dir=out_dir,
            error=error,
            failure=failure,
            password_used=password_used,
            selected_codepage=selected_codepage,
            diagnostics=diagnostic_payload,
            partial_outputs=partial_outputs,
            progress_manifest_payload=progress_manifest_payload,
            output_inventory=output_inventory,
        )

    def _localized_failure(self, failure: FailureInfo) -> str:
        if failure.message_key:
            return self.i18n.t(failure.message_key, **failure.message_params)
        return failure.message

    def _failure_info(
        self,
        kind: FailureKind,
        stage: str,
        message_key: str,
        *,
        user_action: str = "",
        **params,
    ) -> FailureInfo:
        return FailureInfo(
            kind=kind,
            stage=stage,
            message=self.i18n.t(message_key, **params),
            message_key=message_key,
            message_params=dict(params),
            user_action=user_action,
        )

    @staticmethod
    def _diagnostics_from(result: subprocess.CompletedProcess | None) -> dict:
        return result.worker_diagnostics if result is not None else {}

    @staticmethod
    def _worker_selected_password(resolution: PasswordResolution, run_result: subprocess.CompletedProcess | None) -> str | None:
        candidates = tuple(resolution.candidate_passwords or ())
        if not candidates:
            return resolution.password
        result = worker_result_payload(run_result)
        try:
            index = int(result.get("matched_index", -1))
        except (TypeError, ValueError):
            index = -1
        if 0 <= index < len(candidates):
            return candidates[index]
        return resolution.password

    @staticmethod
    def _password_verification_label(resolution: PasswordResolution, worker_result: dict) -> str:
        if worker_result.get("password_candidate_direct"):
            return "sevenzip_worker_candidate_direct"
        if worker_result.get("password_candidate_batch") or resolution.candidate_passwords:
            return "sevenzip_worker_candidate_batch"
        return "extraction_transaction"

    def _password_resolution_failure(self, resolution: PasswordResolution) -> FailureInfo | None:
        if resolution.password is not None:
            return None
        mapping = {
            PasswordResolutionStatus.PASSWORD_REQUIRED: (
                FailureKind.PASSWORD_REQUIRED,
                PASSWORD_NOT_IN_LIST_KEY,
                "request_password",
            ),
            PasswordResolutionStatus.CANDIDATES_EXHAUSTED: (
                FailureKind.WRONG_PASSWORD,
                PASSWORD_NOT_IN_LIST_KEY,
                "request_password",
            ),
            PasswordResolutionStatus.INCONCLUSIVE: (
                FailureKind.PASSWORD_INCONCLUSIVE,
                "failure.password_state_unknown",
                "",
            ),
            PasswordResolutionStatus.DAMAGED: (
                FailureKind.DAMAGED,
                "failure.damaged",
                "",
            ),
            PasswordResolutionStatus.UNSUPPORTED: (
                FailureKind.UNSUPPORTED,
                "failure.unsupported",
                "",
            ),
            PasswordResolutionStatus.BACKEND_ERROR: (
                FailureKind.BACKEND_UNAVAILABLE,
                "failure.password_verifier_unavailable",
                "",
            ),
            PasswordResolutionStatus.NEEDS_VOLUME_OR_TAIL_DAMAGED: (
                FailureKind.DAMAGED,
                "failure.missing_volume_or_tail_damaged",
                "",
            ),
            PasswordResolutionStatus.MISSING_VOLUME: (
                FailureKind.MISSING_VOLUME,
                "failure.missing_volume",
                "wait_for_volume",
            ),
        }
        spec = mapping.get(resolution.status)
        if spec is None:
            return None
        kind, message_key, user_action = spec
        native_result = resolution.test_result if isinstance(resolution.test_result, dict) else {}
        read_error = native_result.get("read_error")
        message_params = {}
        if isinstance(read_error, dict) and read_error.get("field"):
            field_code = str(read_error["field"])
            field_name = self.i18n.t(f"archive.field.{field_code}")
            message_key = (
                "failure.archive_field_read_failed_possible_missing_volume"
                if read_error.get("possible_missing_volume")
                else "failure.archive_field_read_failed"
            )
            message_params = {
                "field": field_name,
                "offset": int(read_error.get("offset") or 0),
                "requested": int(read_error.get("requested") or 0),
                "actual": int(read_error.get("actual") or 0),
            }
        return FailureInfo(
            kind=kind,
            stage="password_resolution",
            message=self.i18n.t(message_key, **message_params),
            message_key=message_key,
            message_params=dict(message_params),
            user_action=user_action,
            details={"diagnostic": resolution.error_text, "read_error": read_error},
        )


    def _extract_inputs_state_machine(
        self,
        task: ArchiveTask,
        out_dir: str,
        inputs: tuple[LogicalArchiveInput, ...],
        *,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "extract_inputs",
    ) -> ExtractionResult:
        archive = task.main_path
        self._log(task, self.i18n.t("extract.log.embedded_start", archive=archive, count=len(inputs)))
        try:
            with _phase(phase_timer, f"{phase_prefix}_mkdir_initial"):
                if not self.scanning:
                    os.makedirs(out_dir, exist_ok=True)
        except Exception as exc:
            failure = self._failure_info(FailureKind.FILESYSTEM_ERROR, "preflight", "extract.dir_create_failed", error=str(exc))
            return self._failed(
                out_dir,
                self._localized_failure(failure),
                failure=failure,
                diagnostics={"failure_stage": "preflight", "failure_kind": "output_filesystem", "message": str(exc)},
            )

        input_results: list[InputExecutionResult] = []
        password_used = None
        selected_codepage = None
        selected_ids = {node.input_id for node in inputs}
        retained = [item for item in task.recovery.checkpoints if item.input.input_id not in selected_ids]
        segment_failures = [item.failure for item in retained if not item.complete and item.failure is not None]
        segment_paths: set[str] = set()
        segment_allocator = None if self.scanning else OutputPathAllocator()
        segment_count = task.recovery.input_count or len(inputs)
        previous = {item.input.input_id: item for item in task.recovery.checkpoints}

        for node in inputs:
            position = node.position
            descriptor = node.descriptor
            # A single embedded payload is the logical archive represented by
            # this task (the common SFX case).  Extract it at the task output
            # root so manifest paths continue to match.  Multiple independent
            # payloads still need isolated subdirectories to avoid collisions.
            checkpoint = previous.get(node.input_id)
            segment_dir = "" if self.scanning else checkpoint.output_dir if checkpoint and checkpoint.output_dir else (
                out_dir
                if segment_count == 1
                else segment_allocator.next_available(
                    os.path.join(out_dir, self._safe_segment_dir_name(descriptor.logical_name, position)),
                    segment_paths,
                )
            )
            if not self.scanning:
                segment_paths.add(resolved_path_key(segment_dir))
            if checkpoint and checkpoint.output_dir:
                # This attempt owns one logical output. Replacing a changed or
                # failed input must never merge old files into its new result.
                self._cleanup_output(segment_dir, OutputCleanupEvent.EXTRACTION_ABORT)
            if "retry_created_outputs" in task.runtime:
                # Only these new segment roots belong to this retry's rollback.
                task.runtime["retry_created_outputs"].append(segment_dir)
            with _phase(phase_timer, f"{phase_prefix}_segment_set_archive_input"):
                # Each logical payload owns its knowledge. The carrier stays
                # unchanged, including when a payload fails or is cancelled.
                child_task = ArchiveTask.from_archive_input(
                    descriptor, discovery_source=task.discovery_source,
                    carrier_path=task.carrier_path,
                )
                child_task.key = node.input_id
                child_task.set_inputs((node,))
                child_task.runtime = dict(task.runtime)
                # Password verification must bind to the currently active
                # logical segment.
                write_source_password_probe_input(child_task, descriptor)
            discovery_failure = node.failure
            self.sevenzip_runner.emit_semantic_event(child_task, "input_started")
            if discovery_failure is not None:
                result = self._failed(segment_dir, self._localized_failure(discovery_failure),
                                      failure=discovery_failure)
            else:
                result = yield from self._extract_one_state_machine(
                    child_task, segment_dir,
                    phase_timer=phase_timer, phase_prefix=f"{phase_prefix}_segment_extract",
                )
            if not self.scanning and result.success and node.descriptor.volume_attempts is not None:
                task.select_volumes(node, child_task.archive_input())
                node = child_task.inputs[0]
            result.logical_input = node
            if not self.scanning:
                self.sevenzip_runner.emit_semantic_event(
                    child_task, "input_finished", success=result.success,
                    error=result.error, out_dir=result.out_dir,
                )

            if self.scanning:
                input_results.append(InputExecutionResult(node, result))
                if result.failure is not None:
                    segment_failures.append(result.failure)
                continue

            if result.password_used is not None and password_used is None:
                password_used = result.password_used
            if result.selected_codepage is not None and selected_codepage is None:
                selected_codepage = result.selected_codepage
            with _phase(phase_timer, f"{phase_prefix}_segment_directory_stats"):
                segment_inventory = OutputInventory.from_value(
                    result.output_inventory,
                    expected_root=segment_dir,
                )
                if segment_inventory is None:
                    segment_inventory = collect_output_inventory(segment_dir)
                    result.output_inventory = segment_inventory
                result.files_written = segment_inventory.stats.file_count
                result.bytes_written = segment_inventory.stats.total_size
            input_results.append(InputExecutionResult(node, result))
            if result.failure is not None:
                segment_failures.append(result.failure)

        # Retained inputs use the same result model without keeping native file
        # tables alive across retries. Failed checkpoints remain failed even
        # when their independently proved complete members can be recovered.
        input_results.extend(InputExecutionResult(
            item.input,
            ExtractionResult(
                item.complete, item.output_dir, failure=item.failure,
                files_written=item.files_written, bytes_written=item.bytes_written,
                recovered_complete_files=item.recovered_complete_files,
            ),
            retained=True,
        ) for item in retained)

        if self.scanning:
            failure = (aggregate_input_failures(segment_failures, segment_count=segment_count, i18n=self.i18n)
                       if segment_failures else None)
            return ExtractionResult(success=failure is None, out_dir="", input_results=input_results,
                                    failure=failure, error=self._localized_failure(failure) if failure else "")

        with _phase(phase_timer, f"{phase_prefix}_directory_stats_total"):
            # Recursive discovery consumes each child's native inventory.
            # The carrier only needs counters; a second per-file table is unused.
            totals = {
                "file_count": sum(item.result.files_written for item in input_results),
                "total_bytes": sum(item.result.bytes_written for item in input_results),
            }
        success_count = sum(item.complete for item in input_results)
        any_success = success_count > 0
        any_partial = any(item.result.recovered_complete_files > 0 if item.retained else
                          item.result.partial_outputs or item.result.files_written > 0
                          for item in input_results)
        all_success = bool(input_results) and success_count == len(input_results)
        diagnostics = {
            "result": {
                "status": "ok" if all_success else ("partial" if any_success or any_partial else "failed"),
                "input_count": len(input_results),
                "input_success_count": success_count,
                "files_written": totals["file_count"],
                "bytes_written": totals["total_bytes"],
                "item_count": totals["file_count"],
            },
        }
        aggregate_failure = None
        if segment_failures:
            aggregate_failure = aggregate_input_failures(
                segment_failures,
                segment_count=segment_count,
                i18n=self.i18n,
            )
        if any_success:
            self._log(task, self.i18n.t(
                "extract.log.embedded_success" if all_success else "extract.log.embedded_failed",
                archive=archive,
            ))
            return ExtractionResult(
                success=all_success,
                out_dir=out_dir,
                error=aggregate_failure.message if aggregate_failure is not None else "",
                failure=aggregate_failure,
                password_used=password_used,
                selected_codepage=selected_codepage,
                diagnostics=diagnostics,
                # Each successful child is a complete independent archive;
                # failed sibling segments are represented by `failure`, not as
                # corrupt partial files.  This keeps terminal-failure cleanup
                # from deleting the complete child outputs.
                partial_outputs=False,
                files_written=totals["file_count"],
                bytes_written=totals["total_bytes"],
                input_results=input_results,
            )
        self._log(task, self.i18n.t("extract.log.embedded_failed", archive=archive))
        if aggregate_failure is None:
            aggregate_failure = FailureInfo(
                kind=FailureKind.INPUTS_FAILED,
                stage="inputs",
                message=self.i18n.t("failure.embedded_extract_failed"),
                message_key="failure.embedded_extract_failed",
                details={"segment_count": len(inputs)},
            )
        failed_result = self._failed(
            out_dir,
            aggregate_failure.message,
            failure=aggregate_failure,
            password_used=password_used,
            selected_codepage=selected_codepage,
            diagnostics={
                **diagnostics,
                "failure_stage": "inputs",
                "failure_kind": "embedded_extraction_failed",
            },
            partial_outputs=any_partial,
        )
        failed_result.input_results = input_results
        failed_result.files_written = totals["file_count"]
        failed_result.bytes_written = totals["total_bytes"]
        return failed_result


    @staticmethod
    def _safe_segment_dir_name(logical_name: str, position: int) -> str:
        raw = os.path.basename(logical_name) or f"embedded_{position:02d}"
        safe = "".join("_" if ch in '<>:"/\\|?*' or ord(ch) < 32 else ch for ch in raw)
        return safe if safe.strip(".") else f"embedded_{position:02d}"


    @staticmethod
    def _fill_success_output_counts(diagnostics: dict[str, Any], stats: dict[str, int]) -> None:
        result = diagnostics.get("result")
        if not isinstance(result, dict):
            result = {}
            diagnostics["result"] = result
        result.setdefault("status", "ok")
        result["files_written"] = int(stats.get("file_count", 0) or 0)
        result["bytes_written"] = int(stats.get("total_bytes", 0) or 0)
        result["item_count"] = max(int(result.get("item_count", 0) or 0), int(stats.get("file_count", 0) or 0))

    def _log(self, task, message: str) -> None:
        if not self.quiet:
            self.sevenzip_runner.emit_semantic_event(task, "task_detail", detail=message)


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
