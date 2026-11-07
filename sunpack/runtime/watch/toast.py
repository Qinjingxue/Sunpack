from __future__ import annotations

import asyncio
import os
import threading
import time
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from sunpack.core.support.path_keys import case_key
from sunpack.core.support.work_context import CURRENT_CANCELLATION, CancellationToken
from sunpack.core.i18n import I18nContext

# native 侧的空间事件名（与 sevenzip_runner / coordinator.reporting 一致），表达等待状态而非 job 生命周期状态。
_SPACE_EVENTS = frozenset({"space_blocked", "space_status", "space_resumed"})
from sunpack.core.support.resource_lifecycle import task_scandir
from sunpack_native import append_failure_report, publish_failure_report
from sunpack.core.platform.windows.toast_protocol import (
    ToastAction,
    ToastActionKind,
    ToastProgressMode,
    ToastSnapshot,
    ToastSnapshotKind,
)
from sunpack.pipeline.postprocess.output_cleanup import OutputCleanupExecutor


class WatchNotificationSink(Protocol):
    def submitted(self, request_id: str, source_path: str) -> None: ...

    def progress(self, request_id: str, task: Any, event: dict[str, Any]) -> None: ...

    def succeeded(self, request_id: str, output_dirs: list[str], warnings: list[str] | None = None) -> None: ...

    def failed(
        self,
        request_id: str,
        errors: list[str],
        failure_payloads: Sequence[Mapping[str, Any]],
    ) -> None: ...

    def suppressed(self, request_id: str) -> None: ...

    def aborted(self, request_id: str) -> None: ...

    def interrupted(self, request_id: str, errors: list[str]) -> None: ...


class NullWatchNotificationSink:
    def interrupted(self, request_id: str, errors: list[str]) -> None:
        pass

    def submitted(self, request_id: str, source_path: str) -> None:
        pass

    def progress(self, request_id: str, task: Any, event: dict[str, Any]) -> None:
        pass

    def succeeded(self, request_id: str, output_dirs: list[str], warnings: list[str] | None = None) -> None:
        pass

    def failed(
        self,
        request_id: str,
        errors: list[str],
        failure_payloads: Sequence[Mapping[str, Any]],
    ) -> None:
        pass

    def suppressed(self, request_id: str) -> None:
        pass

    def aborted(self, request_id: str) -> None:
        pass


@dataclass(slots=True)
class _TaskProgress:
    completed_bytes: int = 0
    total_bytes: int = 0
    # 该 task 因输出卷空间不足被 native 合法暂停：进度条不得推进，但提示文案必须能表达"已暂停"。
    disk_blocked: bool = False
    memory_blocked: bool = False
    space_detail: str = ""


@dataclass
class _RequestProgress:
    source_path: str
    tasks: dict[int, _TaskProgress] = field(default_factory=dict)
    visible: bool = False
    stopping: bool = False


@dataclass
class _BatchProgress:
    source_path: str = ""
    succeeded: int = 0
    failed: int = 0
    total_bytes: int = 0
    output_target: str = ""
    warnings: str = ""
    failure_details: Path | None = None
    report_failed: bool = False
    interrupted: int = 0
    cleanup_failed: bool = False
    cancellation: CancellationToken = field(default_factory=CancellationToken, repr=False)
    pending_appends: int = 0
    finalizing: bool = False
    io_lock: Any = field(default_factory=threading.Lock, repr=False)

    @property
    def completed(self) -> int:
        return self.succeeded + self.failed + self.interrupted


class WatchFailureReportStore:
    def __init__(
        self,
        state_dir: str,
        i18n: I18nContext,
        *,
        retention_days: int = 30,
    ):
        self.directory = Path(state_dir) / "failures"
        self.i18n = i18n
        self.retention_days = max(1, int(retention_days))

    def append_failure(
        self, path: Path, index: int, source_path: str,
        errors: list[str], payloads: Sequence[Mapping[str, Any]],
    ) -> None:
        append_failure_report(
            str(path),
            self.i18n.t("toast.report.failure", index=index, path=source_path),
            self.i18n.t("toast.report.error", error=""),
            (value for value in errors if value),
            self.i18n.t("toast.report.unknown_error"),
            self.i18n.t("toast.report.details", details=""),
            payloads,
        )

    def write(self, details: Path | None, failed: int) -> str:
        now = datetime.now().astimezone()
        filename = f"failed-{now:%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:8]}.txt"
        path = self.directory / filename
        temporary = path.with_suffix(".tmp")
        lines = [
            self.i18n.t("toast.report.title"),
            self.i18n.t("toast.report.generated", timestamp=now.isoformat(timespec="seconds")),
            self.i18n.t("toast.report.summary", failed=failed),
            "",
        ]
        publish_failure_report(
            str(details) if details is not None else None,
            str(temporary), str(path), (line + "\n" for line in lines),
        )
        self._trim(details)
        return str(path)

    def _trim(self, active_details: Path | None) -> None:
        cutoff = time.time() - self.retention_days * 86400
        try:
            with task_scandir(self.directory) as entries:
                for entry in entries:
                    path = self.directory / entry.name
                    report = entry.name.startswith("failed-") and path.suffix in {".txt", ".tmp"}
                    spool = entry.name.startswith("batch-") and path.suffix == ".tmp"
                    if path == active_details or not (report or spool):
                        continue
                    try:
                        if entry.is_file() and entry.stat().st_mtime < cutoff:
                            OutputCleanupExecutor.remove_file(str(path))
                    except OSError:
                        continue
        except OSError:
            return


class WatchToastCoordinator:
    """Build one debounced Toast snapshot from all extraction-ready requests."""

    def __init__(self, host, config: dict, state_dir: str):
        watch = config["watch"]
        self.host = host
        self.i18n = I18nContext(config.get("cli", {}).get("language") if isinstance(config.get("cli"), dict) else None)
        self._debounce_seconds = 0.8
        self._lock = threading.RLock()
        self._requests: dict[str, _RequestProgress] = {}
        self._batch = _BatchProgress()
        self._batch_id = ""
        self._batch_started_at = 0.0
        self._finalize_generation = 0
        self._finalize_timer: threading.Timer | None = None
        self._closed = False
        self.report_store = WatchFailureReportStore(
            state_dir,
            self.i18n,
            retention_days=int(watch.get("toast_report_retention_days", 30)),
        )

    def submitted(self, request_id: str, source_path: str) -> None:
        with self._lock:
            if not self._closed:
                self._requests[str(request_id)] = _RequestProgress(source_path=os.path.abspath(source_path))

    def cancel_batch(self, batch_id: str) -> tuple[str, ...] | None:
        with self._lock:
            if self._closed:
                return None
            # Only the current batch owns cancellable work. A late activation
            # needs no history and must never stop requests from a newer batch.
            if not batch_id or batch_id != self._batch_id or not self._requests:
                return ()
            if any(not request.stopping for request in self._requests.values()):
                for request in self._requests.values():
                    request.stopping = True
                self._publish_progress_locked()
            return tuple(self._requests)

    def interrupted(self, request_id: str, errors: list[str]) -> None:
        self._terminal(request_id, "interrupted", errors=errors)

    def progress(self, request_id: str, task: Any, event: dict[str, Any]) -> None:
        space_event = str(event.get("event") or "")
        with self._lock:
            request = self._requests.get(str(request_id))
            if self._closed or request is None:
                return
            if space_event in {"memory_blocked", "memory_resumed"}:
                task_id = id(task)
                if space_event == "memory_blocked":
                    request.visible = True
                    self._ensure_batch_locked(request.source_path)
                    self._cancel_finalize_locked()
                    request.tasks.setdefault(task_id, _TaskProgress())
                if task_id in request.tasks:
                    request.tasks[task_id].memory_blocked = space_event == "memory_blocked"
                self._publish_progress_locked()
                return
            if space_event in _SPACE_EVENTS:
                self._space_progress_locked(request, task, space_event, event)
                return
            extract_started = event.get("type") == "progress" and event.get("event") == "extract_started"
            task_id = id(task)
            if extract_started:
                request.visible = True
                request.tasks.setdefault(task_id, _TaskProgress())
                self._ensure_batch_locked(request.source_path)
                self._cancel_finalize_locked()
            task_progress = request.tasks.get(task_id)
            if task_progress is None:
                return
            try:
                completed = max(0, int(event.get("completed_bytes", task_progress.completed_bytes) or 0))
                total = max(0, int(event.get("total_bytes", task_progress.total_bytes) or 0))
            except (TypeError, ValueError):
                return
            # 磁盘满暂停期间不得推进进度条（那是"等待"，不是进展）。
            task_progress.completed_bytes = min(completed, total) if total > 0 else completed
            task_progress.total_bytes = total
            if not (task_progress.disk_blocked or task_progress.memory_blocked):
                self._publish_progress_locked()

    # Transport filters stale episodes; retain only each task's visible state.
    def _space_progress_locked(
        self, request: _RequestProgress, task: Any, event: str, payload: dict[str, Any]
    ) -> None:
        task_id = id(task)

        task_progress = request.tasks.get(task_id)
        if task_progress is None and event == "space_blocked":
            # Disk full may happen before the first extract_started progress event.
            request.visible = True
            self._ensure_batch_locked(request.source_path)
            self._cancel_finalize_locked()
            task_progress = _TaskProgress()
            request.tasks[task_id] = task_progress

        if event == "space_resumed":
            if task_progress is not None:
                task_progress.disk_blocked = False
                task_progress.space_detail = ""
            self._publish_progress_locked()
            return

        if task_progress is None:
            return
        task_progress.disk_blocked = True
        if event == "space_status":
            if not bool(payload.get("volume_query_ok", True)):
                # 卷不可访问与"空间不足"必须可区分。
                task_progress.space_detail = self.i18n.t(
                    "report.status.disk_unavailable",
                    error=str(payload.get("volume_query_error") or 0),
                )
            else:
                task_progress.space_detail = ""
        else:
            task_progress.space_detail = ""
        self._publish_progress_locked()

    def succeeded(self, request_id: str, output_dirs: list[str], warnings: list[str] | None = None) -> None:
        self._terminal(request_id, "success", output_dirs=output_dirs, errors=warnings)

    def failed(
        self,
        request_id: str,
        errors: list[str],
        failure_payloads: Sequence[Mapping[str, Any]],
    ) -> None:
        self._terminal(
            request_id,
            "failure",
            errors=errors,
            failure_payloads=failure_payloads,
        )

    def suppressed(self, request_id: str) -> None:
        with self._lock:
            request = self._requests.pop(str(request_id), None)
            if request is None or self._closed:
                return
            if request.visible:
                if self._batch.completed or self._has_pending_batch_requests_locked():
                    self._publish_progress_locked()
                    self._schedule_finalize_if_drained_locked()
                else:
                    self._cancel_finalize_locked()
                    self._reset_batch_locked(clear=True)
            else:
                self._schedule_finalize_if_drained_locked()

    def aborted(self, request_id: str) -> None:
        self.suppressed(request_id)

    def stop(self) -> None:
        with self._lock:
            self._closed = True
            self._cancel_finalize_locked()
            self._requests.clear()
            batch = self._batch
            self._reset_batch_locked(clear=True)
            cleanup = not batch.pending_appends and not batch.finalizing
        batch.cancellation.cancel()
        # The service calls stop on its existing worker. Never wait for an
        # active writer: that writer owns cleanup after noticing detachment.
        if cleanup:
            self._discard_details(batch)

    def _terminal(
        self,
        request_id: str,
        outcome: str,
        *,
        output_dirs: list[str] | None = None,
        errors: list[str] | None = None,
        failure_payloads: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        with self._lock:
            request = self._requests.pop(str(request_id), None)
            if request is None or self._closed:
                return
            if not request.visible and outcome != "interrupted":
                self._schedule_finalize_if_drained_locked()
                return
            self._ensure_batch_locked(request.source_path)
            batch = self._batch
            if not batch.completed:
                batch.source_path = request.source_path
            batch.total_bytes += sum(max(0, task.total_bytes) for task in request.tasks.values())
            if outcome == "interrupted":
                batch.interrupted += 1
                batch.cleanup_failed = batch.cleanup_failed or bool(errors)
            elif outcome == "success":
                batch.succeeded += 1
                batch.output_target = _common_output_target([batch.output_target, *(output_dirs or [])])
                batch.warnings = _bounded_text(
                    (value + "\n" for value in (batch.warnings, *(errors or [])) if value), 2048,
                ).rstrip()
            else:
                batch.failed += 1
                if batch.failure_details is None:
                    batch.failure_details = self.report_store.directory / f"batch-{self._batch_id}.tmp"
                batch.pending_appends += 1
                failure_index = batch.failed
            self._cancel_finalize_locked()
            self._publish_progress_locked()
            self._schedule_finalize_if_drained_locked()
        if outcome == "failure":
            cancellation = CURRENT_CANCELLATION.get()
            unsubscribe = cancellation.subscribe(batch.cancellation.cancel) if cancellation else None
            try:
                with batch.io_lock:
                    with self._lock:
                        append = not self._closed and self._batch is batch and not batch.report_failed
                    if append:
                        with batch.cancellation.native_scope():
                            self.report_store.append_failure(
                                batch.failure_details, failure_index, request.source_path,
                                errors or [], failure_payloads or [],
                            )
            except BaseException as exc:
                # Serialization errors are as unsafe to link as disk errors.
                with self._lock:
                    batch.report_failed = True
                if not isinstance(exc, Exception):
                    raise
            finally:
                if unsubscribe is not None:
                    unsubscribe()
                with self._lock:
                    batch.pending_appends -= 1
                    detached = self._batch is not batch or self._closed
                    cleanup = detached and not batch.pending_appends and not batch.finalizing
                    if not detached:
                        self._schedule_finalize_if_drained_locked()
                if cleanup:
                    self._discard_details(batch)

    def _ensure_batch_locked(self, source_path: str) -> None:
        if not self._batch_id:
            self._batch_id = uuid.uuid4().hex
            self._batch_started_at = time.monotonic()
            self._batch.source_path = source_path

    def _visible_requests_locked(self) -> list[_RequestProgress]:
        return [request for request in self._requests.values() if request.visible]

    def _has_pending_batch_requests_locked(self) -> bool:
        # A stop also owns requests still scanning at the time of the click.
        # Later invisible arrivals neither inherit that stop nor delay its end.
        return any(request.visible or request.stopping for request in self._requests.values())

    def _publish_progress_locked(self) -> None:
        requests = self._visible_requests_locked()
        batch = self._batch
        stopping = any(request.stopping for request in self._requests.values()) and all(
            request.stopping for request in requests
        )
        if not self._batch_id:
            return
        completed_requests = batch.completed
        tasks = [task for request in requests for task in request.tasks.values()]
        known_total = batch.total_bytes + sum(task.total_bytes for task in tasks if task.total_bytes > 0)
        completed_bytes = batch.total_bytes + sum(
            min(task.completed_bytes, task.total_bytes)
            for task in tasks
            if task.total_bytes > 0
        )
        has_unknown_active = any(
            task.total_bytes <= 0
            for request in requests
            for task in request.tasks.values()
        )
        count = completed_requests + len(requests)
        if completed_requests == count and known_total <= 0:
            mode = ToastProgressMode.DETERMINATE
            value = 1.0
        elif has_unknown_active or known_total <= 0:
            mode = ToastProgressMode.INDETERMINATE
            value = 0.0
        else:
            mode = ToastProgressMode.DETERMINATE
            value = min(1.0, completed_bytes / known_total)
        progress_title = (
            self.i18n.t("toast.progress.single", name=os.path.basename(
                requests[0].source_path if requests else batch.source_path,
            ))
            if count == 1
            else self.i18n.t("toast.progress.multiple", count=count)
        )
        if mode == ToastProgressMode.DETERMINATE:
            value_text = self.i18n.t(
                "toast.progress.value",
                percent=int(value * 100),
                completed_bytes=_format_bytes(completed_bytes),
                total_bytes=_format_bytes(known_total),
            )
        else:
            value_text = self.i18n.t("toast.progress.indeterminate")
        # 空间不足并入既有进度快照，不另发 publish，否则 toast 会在"进度"与"暂停"之间来回抖动。
        disk_paused = any(task.disk_blocked for task in tasks)
        memory_paused = any(task.memory_blocked for task in tasks)
        title_key = "toast.progress.paused_title" if disk_paused or memory_paused else "toast.progress.title"
        if stopping:
            title_key = "interrupt.stopping_title"
            mode = ToastProgressMode.INDETERMINATE
            value = 0.0
            value_text = ""
            progress_status = self.i18n.t("interrupt.stopping")
        elif memory_paused:
            mode = ToastProgressMode.INDETERMINATE
            value = 0.0
            value_text = self.i18n.t("report.status.memory_paused")
            progress_status = self.i18n.t("toast.progress.memory_paused")
        elif disk_paused:
            mode = ToastProgressMode.INDETERMINATE
            value = 0.0
            value_text = self.i18n.t("report.status.disk_paused")
            detail = next(
                (task.space_detail for task in tasks if task.disk_blocked and task.space_detail),
                "",
            )
            progress_status = detail or self.i18n.t("toast.progress.disk_paused")
        else:
            progress_status = self.i18n.t("toast.progress.status", completed=completed_requests, total=count)
        if not stopping and memory_paused and disk_paused:
            value_text = self.i18n.t("report.status.resources_paused")
            detail = next((task.space_detail for task in tasks if task.disk_blocked and task.space_detail), "")
            progress_status = detail or self.i18n.t("report.status.resources_resume_hint")
        self.host.publish(ToastSnapshot(
            kind=ToastSnapshotKind.PROGRESS,
            batch_id=self._batch_id,
            title=self.i18n.t(title_key),
            body=self.i18n.t("interrupt.stopping") if stopping else self.i18n.t("toast.progress.body", completed=completed_requests, total=count),
            progress_mode=mode,
            progress_value=value,
            progress_title=progress_title,
            progress_status=progress_status,
            progress_value_text=value_text,
            # Keep Stop stable until the final toast replaces this progress
            # notification; removing it requires Windows to show another popup.
            actions=(
                ToastAction(ToastActionKind.CANCEL_BATCH, self.i18n.t("interrupt.stop"), self._batch_id),
            ),
        ))

    def _schedule_finalize_if_drained_locked(self) -> None:
        if (not self._batch.completed or self._has_pending_batch_requests_locked()
                or self._batch.pending_appends or self._batch.finalizing):
            return
        self._cancel_finalize_locked()
        self._finalize_generation += 1
        generation = self._finalize_generation
        timer = threading.Timer(self._debounce_seconds, self._finalize, args=(generation,))
        timer.daemon = True
        self._finalize_timer = timer
        timer.start()

    def _cancel_finalize_locked(self) -> None:
        self._finalize_generation += 1
        timer, self._finalize_timer = self._finalize_timer, None
        if timer is not None:
            timer.cancel()

    def _finalize(self, generation: int) -> None:
        with self._lock:
            if self._closed or generation != self._finalize_generation:
                return
            owner = self._batch
            if (not owner.completed or self._has_pending_batch_requests_locked()
                    or owner.pending_appends or owner.finalizing):
                return
            owner.finalizing = True
            batch = replace(owner)
            batch_id, started_at = self._batch_id, self._batch_started_at
        report_path = ""
        try:
            with owner.io_lock:
                if (batch.failed or (batch.cleanup_failed and batch.succeeded)) and not batch.report_failed:
                    try:
                        with owner.cancellation.native_scope():
                            report_path = self.report_store.write(
                                batch.failure_details, batch.failed + int(batch.cleanup_failed),
                            )
                    except (Exception, asyncio.CancelledError):
                        with self._lock:
                            owner.report_failed = True
                with self._lock:
                    valid = (not self._closed and self._batch is owner
                             and generation == self._finalize_generation
                             and not owner.pending_appends
                             and not self._has_pending_batch_requests_locked())
                    if valid:
                        self._publish_final_locked(batch, batch_id, started_at, report_path)
                        self._reset_batch_locked(clear=False)
                if report_path and not valid:
                    self._discard_path(Path(report_path))
        finally:
            with self._lock:
                owner.finalizing = False
                detached = self._batch is not owner or self._closed
                cleanup = detached and not owner.pending_appends
                if not detached:
                    self._schedule_finalize_if_drained_locked()
            if cleanup:
                self._discard_details(owner)

    def _publish_final_locked(
        self, batch: _BatchProgress, batch_id: str, started_at: float, report_path: str,
    ) -> None:
        if batch.interrupted and not (batch.succeeded or batch.failed):
            self.host.publish(ToastSnapshot(
                kind=ToastSnapshotKind.FAILURE if batch.cleanup_failed else ToastSnapshotKind.SUCCESS,
                batch_id=batch_id, title=self.i18n.t("interrupt.finished"),
                body=self.i18n.t("interrupt.cleanup_failed" if batch.cleanup_failed else "interrupt.cleaned"),
            ))
            return
        succeeded, failed = batch.succeeded, batch.failed + int(batch.cleanup_failed)
        duration = self.i18n.format_duration(time.monotonic() - started_at)
        actions: list[ToastAction] = []
        output_target = batch.output_target
        if output_target:
            actions.append(ToastAction(
                ToastActionKind.OPEN_DIRECTORY,
                self.i18n.t("toast.action.open_output"),
                output_target,
            ))
        if report_path:
            actions.append(ToastAction(
                ToastActionKind.OPEN_LOG,
                self.i18n.t("toast.action.open_failure_log"), report_path,
            ))
        if failed and succeeded:
            kind = ToastSnapshotKind.MIXED
            title = self.i18n.t("toast.final.mixed.title")
            body = self.i18n.t(
                "toast.final.mixed.body",
                succeeded=succeeded,
                failed=failed,
                duration=duration,
            )
        elif failed:
            kind = ToastSnapshotKind.FAILURE
            title = self.i18n.t("toast.final.failure.title")
            body = self.i18n.t("toast.final.failure.body", failed=failed, duration=duration)
        else:
            kind = ToastSnapshotKind.SUCCESS
            title = self.i18n.t("toast.final.success.title")
            body = self.i18n.t("toast.final.success.body", succeeded=succeeded, duration=duration)
        if batch.warnings:
            body += "\n" + batch.warnings
        if batch.interrupted:
            body += "\n" + self.i18n.t("interrupt.cleanup_failed" if batch.cleanup_failed else "interrupt.cleaned")
        self.host.publish(ToastSnapshot(
            kind=kind,
            batch_id=batch_id,
            title=title,
            body=body,
            actions=tuple(actions[:2]),
        ))

    def _reset_batch_locked(self, *, clear: bool) -> None:
        self._batch_id = ""
        self._batch_started_at = 0.0
        self._batch = _BatchProgress()
        if clear:
            self.host.clear()

    @staticmethod
    def _discard_path(path: Path) -> None:
        try:
            OutputCleanupExecutor.remove_file(str(path))
        except OSError:
            pass

    def _discard_details(self, batch: _BatchProgress) -> None:
        if batch.failure_details is not None:
            self._discard_path(batch.failure_details)


def _bounded_text(parts: Iterable[str], limit: int) -> str:
    if limit <= 0:
        return ""
    chunks = []
    remaining = limit
    for part in parts:
        if len(part) > remaining:
            chunks.append(part[:max(0, remaining - 1)] + "…")
            break
        chunks.append(part)
        remaining -= len(part)
        if not remaining:
            break
    return "".join(chunks)


def _format_bytes(value: int) -> str:
    amount = float(max(0, value))
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    for unit in units:
        if amount < 1024.0 or unit == units[-1]:
            return f"{int(amount)} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024.0
    return f"{int(value)} B"


def _existing_directories(paths: list[str]) -> list[str]:
    result = []
    seen = set()
    for raw in paths:
        path = os.path.abspath(str(raw or ""))
        key = case_key(path)
        if raw and key not in seen and os.path.isdir(path):
            seen.add(key)
            result.append(path)
    return result


def _common_output_target(paths: list[str]) -> str:
    existing = _existing_directories(paths)
    if not existing:
        return ""
    if len(existing) == 1:
        return existing[0]
    try:
        common = os.path.commonpath(existing)
    except ValueError:
        return existing[0]
    return common if os.path.isdir(common) else existing[0]
