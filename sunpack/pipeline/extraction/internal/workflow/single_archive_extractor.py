import asyncio
import os
import sys
import subprocess
from contextlib import nullcontext
from dataclasses import replace
from typing import Any, Callable

from sunpack.core.support.resource_lifecycle import task_walk
from sunpack.core.support.output_paths import OutputPathAllocator
from sunpack.core.support.path_keys import resolved_path_key

from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.extraction.internal.workflow.errors import classify_extract_failure
from sunpack.pipeline.extraction.internal.sevenzip.metadata import ArchiveMetadataScanner
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner
from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import compact_success_worker_diagnostics, worker_result_payload
from sunpack.pipeline.extraction.progress import build_extraction_progress_manifest, has_recoverable_partial_outputs
from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.passwords.result import PasswordResolution, PasswordResolutionStatus
from sunpack.core.passwords.resolver import archive_structure_requires_password, archive_structure_password_state
from sunpack.core.support import archive_knowledge_projection as knowledge_view
from sunpack.core.support.archive_input_projection import write_source_password_probe_input
from sunpack.pipeline.extraction.output_inventory import OutputInventory, collect_output_inventory
from sunpack.core.i18n import I18nContext
from sunpack.pipeline.postprocess.output_cleanup import DEFAULT_OUTPUT_CLEANUP_MANAGER, OutputCleanupEvent


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
        startupinfo = request.pop("startupinfo", None)
        try:
            job = runner._build_job(**request)
        except Exception as exc:
            sent = runner.failed_process_for_exception(exc, request)
        else:
            return False, {"job": job, "startupinfo": startupinfo, "task": request["task"]}


class SingleArchiveExtractor:
    def __init__(
        self,
        password_store,
        password_resolver,
        metadata_scanner: ArchiveMetadataScanner,
        sevenzip_runner: SevenZipRunner | None = None,
        best_effort: bool = True,
        quiet: bool = False,
        language: str = "en",
        output_stream=None,
    ):
        self.password_store = password_store
        self.password_resolver = password_resolver
        self.metadata_scanner = metadata_scanner
        self.sevenzip_runner = sevenzip_runner
        self.best_effort = bool(best_effort)
        self.quiet = bool(quiet)
        self.i18n = I18nContext(language)
        self.output_stream = output_stream if output_stream is not None else sys.stdout

    def extract(
        self,
        task: ArchiveTask,
        out_dir: str,
        *,
        allow_embedded_segments: bool = True,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "extract",
    ) -> ExtractionResult:
        state = self._extract_state_machine(
            task,
            out_dir,
            allow_embedded_segments=allow_embedded_segments,
            phase_timer=phase_timer,
            phase_prefix=phase_prefix,
        )
        try:
            request = next(state)
        except StopIteration as completed:
            return completed.value
        while True:
            result = self.sevenzip_runner.extract_attempt(**request)
            try:
                request = state.send(result)
            except StopIteration as completed:
                return completed.value

    async def extract_asyncio(
        self,
        broker,
        task: ArchiveTask,
        out_dir: str,
        *,
        request_id: str,
        file_id: str,
        cancellation,
        allow_embedded_segments: bool = True,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "extract",
    ) -> ExtractionResult:
        """Advance one extraction generator without holding a worker slot
        while the native worker owns the archive operation.
        """

        state = self._extract_state_machine(
            task,
            out_dir,
            allow_embedded_segments=allow_embedded_segments,
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
        allow_embedded_segments: bool = True,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "extract",
    ):
        if allow_embedded_segments:
            with _phase(phase_timer, f"{phase_prefix}_read_extractable_segments"):
                segments = [
                    dict(item)
                    for item in knowledge_view.source_extractable_segments(task)
                    if isinstance(item, dict) and isinstance(item.get("archive_input"), dict)
                ]
            if segments:
                return (yield from self._extract_embedded_segments_state_machine(
                    task,
                    out_dir,
                    segments,
                            phase_timer=phase_timer,
                    phase_prefix=f"{phase_prefix}_embedded",
                ))

        descriptor = task.archive_input()
        archive = descriptor.entry_path
        all_parts = descriptor.part_paths() or [archive]
        is_split = (
            descriptor.open_mode in {"native_volumes", "sfx_with_volumes"}
            or len(all_parts) > 1
        )

        self._log(self.i18n.t("extract.log.start", archive=archive))

        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as exc:
            failure = self._failure_info(FailureKind.FILESYSTEM_ERROR, "preflight", "extract.dir_create_failed", error=str(exc))
            return self._failed(
                out_dir,
                self._localized_failure(failure),
                failure=failure,
                diagnostics={"failure_stage": "preflight", "failure_kind": "output_filesystem", "message": str(exc)},
            )

        with _phase(phase_timer, f"{phase_prefix}_startupinfo"):
            startupinfo = self._startupinfo()
        descriptor = task.archive_input()
        run_archive = descriptor.entry_path
        run_parts = descriptor.part_paths()
        run_result = None
        test_result = None
        err = ""
        correct_pwd = None
        selected_codepage = None

        with _phase(phase_timer, f"{phase_prefix}_resolve_password"):
            resolution = self._resolve_password(task, run_archive, run_parts)
        resolution_failure = self._password_resolution_failure(resolution)
        if resolution_failure is not None:
            self._cleanup_output(out_dir, OutputCleanupEvent.EXTRACTION_ABORT)
            self._log(self.i18n.t("extract.log.failed", archive=archive, error=self._localized_failure(resolution_failure)))
            return self._failed(
                out_dir,
                self._localized_failure(resolution_failure),
                failure=resolution_failure,
                diagnostics={
                    "failure_stage": resolution_failure.stage,
                    "failure_kind": resolution_failure.kind.value,
                    "message": resolution.error_text,
                },
            )
        correct_pwd = resolution.password
        test_result = resolution.test_result
        test_err = resolution.error_text
        with _phase(phase_timer, f"{phase_prefix}_scan_filename_encoding"):
            format_hint = task.archive_input().format_hint
            filename_encoding = self.metadata_scanner.scan_for_task(
                task, run_archive, password=correct_pwd,
                part_paths=run_parts, format_hint=format_hint,
            )
            selected_codepage = filename_encoding.selected_codepage
            if filename_encoding.error:
                # Filename detection is an optional override.  Failure or
                # ambiguity must not prevent the archive backend from
                # using UTF-8 flags / Unicode extra fields itself.
                self._log(
                    self.i18n.t("extract.log.metadata_override_not_used", error=filename_encoding.error)
                )
                selected_codepage = None

        if correct_pwd is None:
            err = test_err
        else:
            self.sevenzip_runner.emit_semantic_event(
                task,
                "extract_ready",
                archive_path=run_archive,
                completed_bytes=0,
                total_bytes=0,
            )
            with _phase(phase_timer, f"{phase_prefix}_sevenzip_attempt"):
                run_result = yield {
                    "archive_path": run_archive,
                    "part_paths": run_parts,
                    "out_dir": out_dir,
                    "password": correct_pwd,
                    "password_candidates": list(resolution.candidate_passwords),
                    "selected_codepage": selected_codepage,
                    "startupinfo": startupinfo,
                    "task": task,
                    "phase_timer": phase_timer,
                    "phase_prefix": f"{phase_prefix}_sevenzip",
                }

            if run_result.returncode == 0:
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
                    compact_success_worker_diagnostics(diagnostics)
                    output_stats = {
                        "file_count": output_inventory.stats.file_count,
                        "total_bytes": output_inventory.stats.total_size,
                    }
                    self._fill_success_output_counts(diagnostics, output_stats)
                self._log(self.i18n.t("extract.log.success", archive=archive))
                manifest_payload = None
                if diagnostics.get("result"):
                    with _phase(phase_timer, f"{phase_prefix}_build_success_manifest"):
                        manifest_payload = build_extraction_progress_manifest(
                            archive=archive,
                            out_dir=out_dir,
                            diagnostics=diagnostics,
                            round_index=1,
                        )
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
        self._log(self.i18n.t("extract.log.failed", archive=archive, error=error_msg))
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
        with _phase(phase_timer, f"{phase_prefix}_recoverable_partial_check"):
            recoverable_partial = (
                failure.kind != FailureKind.PASSWORD_INCONCLUSIVE
                and self.best_effort
                and has_recoverable_partial_outputs(diagnostics, out_dir)
            )
        if recoverable_partial:
            with _phase(phase_timer, f"{phase_prefix}_build_partial_manifest"):
                manifest_payload = build_extraction_progress_manifest(
                    archive=archive,
                    out_dir=out_dir,
                    diagnostics=diagnostics,
                    round_index=1,
                )
            diagnostics["partial_outputs"] = True
            return self._failed(
                out_dir,
                error_msg,
                failure=failure,
                password_used=(None if failure.kind in {FailureKind.WRONG_PASSWORD, FailureKind.PASSWORD_INCONCLUSIVE} else correct_pwd),
                selected_codepage=selected_codepage,
                diagnostics=diagnostics,
                partial_outputs=True,
                progress_manifest_payload=manifest_payload,
            )
        self._cleanup_output(out_dir, OutputCleanupEvent.UNRECOVERABLE_FAILURE)
        return self._failed(
            out_dir,
            error_msg,
            failure=failure,
            password_used=(None if failure.kind in {FailureKind.WRONG_PASSWORD, FailureKind.PASSWORD_INCONCLUSIVE} else correct_pwd),
            selected_codepage=selected_codepage,
            diagnostics=diagnostics,
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
        if not self.password_store.has_candidates(scope_path=scope_path) and not self._task_requires_password(task):
            unknown = archive_structure_password_state(task) == "unknown"
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

    @staticmethod
    def _task_requires_password(task: ArchiveTask) -> bool:
        return archive_structure_requires_password(task)

    def _startupinfo(self):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return startupinfo

    @staticmethod
    def _cleanup_output(out_dir: str, event: OutputCleanupEvent) -> None:
        DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_canonical(
            out_dir,
            event=event,
            planned_output_dir=out_dir,
        )

    @staticmethod
    def _password_archive_key(task: ArchiveTask) -> str:
        """Keep password resolution state local to the active logical input.

        Ordinary tasks retain their key. Carved/concatenated inputs use
        their format and physical ranges; the filename is display data.
        """
        try:
            descriptor = task.archive_input()
        except Exception:
            return task.key
        if descriptor.open_mode not in {"file_range", "concat_ranges"}:
            return task.key
        extents = descriptor.extents if descriptor.open_mode == "concat_ranges" else (
            part.extent for part in descriptor.parts
        )
        ranges = tuple((extent.path, extent.start, extent.end) for extent in extents)
        return f"{task.key}#{descriptor.format_hint}:{ranges!r}"

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
                "failure.password_required",
                "request_password",
            ),
            PasswordResolutionStatus.CANDIDATES_EXHAUSTED: (
                FailureKind.WRONG_PASSWORD,
                "failure.password_wrong_or_unknown",
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


    def _extract_embedded_segments_state_machine(
        self,
        task: ArchiveTask,
        out_dir: str,
        segments: list[dict[str, Any]],
        *,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "extract_embedded",
    ) -> ExtractionResult:
        archive = task.main_path
        all_parts = list(task.all_parts or [archive])
        self._log(self.i18n.t("extract.log.embedded_start", archive=archive, count=len(segments)))
        try:
            with _phase(phase_timer, f"{phase_prefix}_mkdir_initial"):
                os.makedirs(out_dir, exist_ok=True)
        except Exception as exc:
            failure = self._failure_info(FailureKind.FILESYSTEM_ERROR, "preflight", "extract.dir_create_failed", error=str(exc))
            return self._failed(
                out_dir,
                self._localized_failure(failure),
                failure=failure,
                diagnostics={"failure_stage": "preflight", "failure_kind": "output_filesystem", "message": str(exc)},
            )

        segment_results: list[dict[str, Any]] = []
        embedded_results: list[tuple[dict[str, Any], ExtractionResult]] = []
        segment_inventories: list[OutputInventory] = []
        password_used = None
        selected_codepage = None
        any_success = False
        any_partial = False
        segment_failures: list[FailureInfo] = list(task.runtime.get("password_retry_other_failures", ()))
        segment_paths: set[str] = set()
        segment_allocator = OutputPathAllocator()
        segment_count = int(task.runtime.get("password_retry_segment_count", len(segments)))

        for position, segment in enumerate(segments, start=1):
            segment_id = str(segment.get("segment_id") or f"embedded_{position:02d}")
            with _phase(phase_timer, f"{phase_prefix}_segment_descriptor"):
                descriptor = ArchiveInputDescriptor.from_any(
                    segment.get("archive_input") if isinstance(segment.get("archive_input"), dict) else None,
                    archive_path=archive,
                    part_paths=all_parts,
                    format_hint=str(segment.get("format") or ""),
                    logical_name=str(segment.get("logical_name") or task.logical_name),
                )
            # A single embedded payload is the logical archive represented by
            # this task (the common SFX case).  Extract it at the task output
            # root so manifest paths continue to match.  Multiple independent
            # payloads still need isolated subdirectories to avoid collisions.
            segment_dir = (
                out_dir
                if segment_count == 1
                else segment_allocator.next_available(
                    os.path.join(out_dir, self._safe_segment_dir_name(descriptor.logical_name, position)),
                    segment_paths,
                    is_directory=True,
                )
            )
            segment_paths.add(resolved_path_key(segment_dir))
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
                child_task.key = task.key
                child_task.runtime = dict(task.runtime)
                # Embedded boundary resolution may already have proven the
                # password for this exact logical range. Keep that proof in
                # runtime-only state so it is not serialized into manifests.
                segment_passwords = child_task.runtime.pop("embedded_segment_passwords", None)
                if isinstance(segment_passwords, dict):
                    known_password = segment_passwords.get(str(segment.get("start_offset")))
                    if isinstance(known_password, str):
                        child_task.knowledge().set(
                            "archive.password",
                            known_password,
                            source_layer="embedded",
                            source_module="boundary_resolver",
                        )
                # Password verification must bind to the currently active
                # logical segment.
                write_source_password_probe_input(child_task, descriptor.to_dict())
            result = yield from self._extract_state_machine(
                child_task, segment_dir, allow_embedded_segments=False,
                phase_timer=phase_timer, phase_prefix=f"{phase_prefix}_segment_extract",
            )
            result.diagnostics = {
                **dict(result.diagnostics or {}),
                "verification_archive_input": dict(segment.get("archive_input") or {}),
            }

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
                segment_inventories.append(segment_inventory)
                stats = {
                    "file_count": segment_inventory.stats.file_count,
                    "total_bytes": segment_inventory.stats.total_size,
                }
            segment_success = bool(result.success)
            segment_partial = bool(result.partial_outputs or stats["file_count"] > 0)
            embedded_results.append(({
                **dict(segment),
                "success": segment_success,
                "partial_outputs": segment_partial,
            }, result))
            any_success = any_success or segment_success
            any_partial = any_partial or segment_partial
            if result.failure is not None:
                segment_failures.append(replace(result.failure, details={
                    **result.failure.details, "retry_input": descriptor.to_dict(),
                }))
            segment_results.append({
                "segment_id": segment_id,
                "index": int(segment.get("index") or position),
                "format": segment.get("format") or "",
                "logical_name": segment.get("logical_name") or "",
                "start_offset": segment.get("start_offset"),
                "end_offset": segment.get("end_offset"),
                "confidence": segment.get("confidence"),
                "archive_input": segment.get("archive_input"),
                "out_dir": segment_dir,
                "success": segment_success,
                "partial_outputs": segment_partial,
                "error": result.error,
                "failure": result.failure.to_dict() if result.failure is not None else None,
                "password_used": result.password_used,
                "selected_codepage": result.selected_codepage,
                "diagnostics": dict(result.diagnostics or {}),
                "files_written": stats["file_count"],
                "bytes_written": stats["total_bytes"],
            })

        with _phase(phase_timer, f"{phase_prefix}_directory_stats_total"):
            output_inventory = OutputInventory.merge(out_dir, segment_inventories)
            totals = {
                "file_count": output_inventory.stats.file_count,
                "total_bytes": output_inventory.stats.total_size,
            }
        all_success = bool(segment_results) and not segment_failures and all(item.get("success") for item in segment_results)
        diagnostics = {
            "result": {
                "status": "ok" if all_success else ("partial" if any_success or any_partial else "failed"),
                "embedded_segment_count": len(segment_results),
                "embedded_success_count": sum(1 for item in segment_results if item.get("success")),
                "files_written": totals["file_count"],
                "bytes_written": totals["total_bytes"],
                "item_count": totals["file_count"],
            },
            "embedded_segments": segment_results,
        }
        aggregate_failure = None
        if segment_failures:
            aggregate_failure = self._aggregate_embedded_failure(
                segment_failures,
                segment_count=segment_count,
            )
            generation = task.runtime.get("input_generation")
            if generation:
                aggregate_failure = replace(aggregate_failure, details={
                    **aggregate_failure.details, "retry_generation": generation,
                })
        if any_success:
            self._log(self.i18n.t(
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
                output_inventory=output_inventory,
                files_written=totals["file_count"],
                bytes_written=totals["total_bytes"],
                embedded_results=embedded_results,
            )
        self._log(self.i18n.t("extract.log.embedded_failed", archive=archive))
        if aggregate_failure is None:
            aggregate_failure = FailureInfo(
                kind=FailureKind.EMBEDDED_SEGMENTS_FAILED,
                stage="embedded_segments",
                message=self.i18n.t("failure.embedded_extract_failed"),
                message_key="failure.embedded_extract_failed",
                details={"segment_count": len(segment_results)},
            )
        failed_result = self._failed(
            out_dir,
            aggregate_failure.message,
            failure=aggregate_failure,
            password_used=password_used,
            selected_codepage=selected_codepage,
            diagnostics={
                **diagnostics,
                "failure_stage": "embedded_segments",
                "failure_kind": "embedded_extraction_failed",
            },
            partial_outputs=any_partial,
        )
        failed_result.embedded_results = embedded_results
        return failed_result

    def _aggregate_embedded_failure(
        self,
        segment_failures: list[FailureInfo],
        *,
        segment_count: int,
    ) -> FailureInfo:
        details = {
            "segment_count": int(segment_count),
            "failed_segment_count": len(segment_failures),
        }
        if len(segment_failures) == 1 and segment_count == 1:
            child = segment_failures[0]
            return FailureInfo(
                kind=FailureKind.EMBEDDED_SEGMENTS_FAILED,
                stage="embedded_segments",
                message=self._localized_failure(child),
                message_key=child.message_key,
                message_params=dict(child.message_params),
                user_action=child.user_action,
                causes=(child,),
                details=details,
            )

        password_failure = any(failure.is_password_failure for failure in segment_failures)
        message_key = "failure.embedded_wrong_password" if password_failure else "failure.embedded_extract_failed"
        return FailureInfo(
            kind=FailureKind.EMBEDDED_SEGMENTS_FAILED,
            stage="embedded_segments",
            message=self.i18n.t(message_key),
            message_key=message_key,
            user_action="request_password" if password_failure else "",
            causes=tuple(segment_failures),
            details=details,
        )

    @staticmethod
    def _safe_segment_dir_name(logical_name: str, position: int) -> str:
        raw = os.path.basename(logical_name) or f"embedded_{position:02d}"
        safe = "".join("_" if ch in '<>:"/\\|?*' or ord(ch) < 32 else ch for ch in raw)
        return safe if safe.strip(".") else f"embedded_{position:02d}"


    @staticmethod
    def _directory_stats(path: str) -> dict[str, int]:
        file_count = 0
        total_bytes = 0
        if not os.path.isdir(path):
            return {"file_count": 0, "total_bytes": 0}
        for root, _dirs, files in task_walk(path):
            for name in files:
                file_count += 1
                try:
                    total_bytes += int(os.path.getsize(os.path.join(root, name)))
                except OSError:
                    pass
        return {"file_count": file_count, "total_bytes": total_bytes}

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

    def _log(self, message: str) -> None:
        if not self.quiet:
            print(message, file=self.output_stream, flush=True)


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
