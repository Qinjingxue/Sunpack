from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from sunpack.core.support.path_keys import case_key
from sunpack.core.i18n import I18nContext

# native 侧的空间事件名（与 sevenzip_runner / coordinator.reporting 一致），表达等待状态而非 job 生命周期状态。
_SPACE_EVENTS = frozenset({"space_blocked", "space_status", "space_resumed"})
from sunpack.core.support.resource_lifecycle import task_glob, write_task_text
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
        failure_payloads: list[dict[str, Any]],
    ) -> None: ...

    def suppressed(self, request_id: str) -> None: ...

    def aborted(self, request_id: str) -> None: ...


class NullWatchNotificationSink:
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
        failure_payloads: list[dict[str, Any]],
    ) -> None:
        pass

    def suppressed(self, request_id: str) -> None:
        pass

    def aborted(self, request_id: str) -> None:
        pass


@dataclass
class _TaskProgress:
    name: str
    completed_bytes: int = 0
    total_bytes: int = 0
    # 该 task 因输出卷空间不足被 native 合法暂停：进度条不得推进，但提示文案必须能表达"已暂停"。
    disk_blocked: bool = False
    space_detail: str = ""
    # 该 task 在空间事件里出现过的真实 job_id，job 终态时从 (volume_key, episode) → job_id 集合里删除。
    space_job_ids: set[str] = field(default_factory=set)


@dataclass
class _RequestProgress:
    source_path: str
    tasks: dict[int, _TaskProgress] = field(default_factory=dict)
    visible: bool = False


@dataclass
class _BatchProgress:
    source_path: str = ""
    succeeded: int = 0
    failed: int = 0
    total_bytes: int = 0
    output_target: str = ""
    warnings: str = ""
    failure_details: list[str] = field(default_factory=list)
    failure_chars: int = 0

    @property
    def completed(self) -> int:
        return self.succeeded + self.failed


class WatchFailureReportStore:
    def __init__(
        self,
        state_dir: str,
        i18n: I18nContext,
        *,
        retention_days: int = 30,
        max_files: int = 16,
        max_bytes: int = 2 * 1024 * 1024,
    ):
        self.directory = Path(state_dir) / "failures"
        self.i18n = i18n
        self.retention_days = max(1, int(retention_days))
        self.max_files = max(1, int(max_files))
        self.max_bytes = max(1024, int(max_bytes))

    def format_failure(
        self, index: int, source_path: str, errors: list[str], payloads: list[dict[str, Any]], limit: int,
    ) -> str:
        def parts():
            yield self.i18n.t("toast.report.failure", index=index, path=source_path) + "\n"
            error = _bounded_text((str(value) + "; " for value in errors if value), limit)
            yield self.i18n.t("toast.report.error", error=error or self.i18n.t("toast.report.unknown_error")) + "\n"
            if payloads:
                yield self.i18n.t("toast.report.details", details="")
                yield from json.JSONEncoder(ensure_ascii=False, indent=2, sort_keys=True, default=str).iterencode(payloads)
            yield "\n"
        return _bounded_text(parts(), limit)

    def write(self, details: list[str], failed: int) -> str:
        self.directory.mkdir(parents=True, exist_ok=True)
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
        lines.extend(details)
        if failed > len(details):
            lines.append(self.i18n.t("toast.report.omitted", count=failed - len(details)))
        write_task_text(temporary, "\n".join(lines), encoding="utf-8")
        os.replace(temporary, path)
        self._trim()
        return str(path)

    def _trim(self) -> None:
        try:
            files = sorted(
                (item for item in task_glob(self.directory, "failed-*.txt") if item.is_file()),
                key=lambda item: item.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            return
        cutoff = time.time() - self.retention_days * 86400
        retained_bytes = 0
        for index, path in enumerate(files):
            try:
                stat = path.stat()
                remove = (
                    (index > 0 and stat.st_mtime < cutoff)
                    or index >= self.max_files
                    or (index > 0 and retained_bytes + stat.st_size > self.max_bytes)
                )
                if remove:
                    OutputCleanupExecutor.remove_file(str(path))
                else:
                    retained_bytes += stat.st_size
            except OSError:
                continue


class WatchToastCoordinator:
    """Build one debounced Toast snapshot from all extraction-ready requests."""

    def __init__(self, host, config: dict, state_dir: str):
        watch = config["watch"]
        self.host = host
        self.i18n = I18nContext(config.get("cli", {}).get("language") if isinstance(config.get("cli"), dict) else None)
        self._debounce_seconds = max(0.0, int(watch.get("toast_completion_debounce_ms", 800)) / 1000.0)
        self._lock = threading.RLock()
        self._requests: dict[str, _RequestProgress] = {}
        self._batch = _BatchProgress()
        self._batch_id = ""
        self._batch_started_at = 0.0
        self._finalize_generation = 0
        self._finalize_timer: threading.Timer | None = None
        self._closed = False
        # (volume_key, episode_id) -> 仍在等待该 episode 的 job_id 集合；全部等待 job 终态后集合变空。
        self._space_blocked_jobs: dict[tuple[str, int], set[str]] = {}
        self.report_store = WatchFailureReportStore(
            state_dir,
            self.i18n,
            retention_days=int(watch.get("toast_report_retention_days", 30)),
            max_files=int(watch.get("toast_report_max_files", 16)),
            max_bytes=int(watch.get("toast_report_max_bytes", 2 * 1024 * 1024)),
        )

    def submitted(self, request_id: str, source_path: str) -> None:
        with self._lock:
            if not self._closed:
                previous = self._requests.get(str(request_id))
                if previous is not None:
                    self._release_space_jobs_for_request_locked(previous)
                self._requests[str(request_id)] = _RequestProgress(source_path=os.path.abspath(source_path))

    def progress(self, request_id: str, task: Any, event: dict[str, Any]) -> None:
        space_event = str(event.get("event") or "")
        with self._lock:
            request = self._requests.get(str(request_id))
            if self._closed or request is None:
                return
            if space_event in _SPACE_EVENTS:
                self._space_progress_locked(request, task, space_event, event)
                return
            extract_started = event.get("type") == "progress" and event.get("event") == "extract_started"
            task_id = id(task)
            if extract_started:
                request.visible = True
                request.tasks.setdefault(task_id, _TaskProgress(name=_task_name(task, request.source_path)))
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
            if task_progress.disk_blocked:
                task_progress.completed_bytes = min(completed, total) if total > 0 else completed
                task_progress.total_bytes = total
                return
            task_progress.completed_bytes = min(completed, total) if total > 0 else completed
            task_progress.total_bytes = total
            self._publish_progress_locked()

    # 空间不足暂停/恢复：按 (volume_key, episode_id) 维护仍在等待的 job 集合，集合空后提示必须消失。
    def _space_progress_locked(
        self, request: _RequestProgress, task: Any, event: str, payload: dict[str, Any]
    ) -> None:
        try:
            episode = int(payload.get("episode_id") or 0)
        except (TypeError, ValueError):
            episode = 0
        key = (str(payload.get("volume_key") or ""), episode)
        task_id = id(task)
        job_id = str(payload.get("job_id") or "")

        task_progress = request.tasks.get(task_id)
        if task_progress is None and event == "space_blocked":
            # Disk full may happen before the first extract_started progress event.
            request.visible = True
            self._ensure_batch_locked(request.source_path)
            self._cancel_finalize_locked()
            task_progress = _TaskProgress(name=_task_name(task, request.source_path))
            request.tasks[task_id] = task_progress

        if event == "space_resumed":
            self._space_blocked_jobs.pop(key, None)
            if task_progress is not None:
                task_progress.disk_blocked = False
                task_progress.space_detail = ""
            self._publish_progress_locked()
            return

        if task_progress is None:
            return
        task_progress.disk_blocked = True
        if job_id:
            self._space_blocked_jobs.setdefault(key, set()).add(job_id)
            task_progress.space_job_ids.add(job_id)
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

    def _space_blocked_jobs_empty(self) -> bool:
        with self._lock:
            return not any(self._space_blocked_jobs.values())

    def _release_space_jobs_for_request_locked(self, request: _RequestProgress) -> None:
        """job 终态时把它的 job_id 从所有 episode 集合里移除，集合空则提示消失。"""

        for task_progress in request.tasks.values():
            task_progress.disk_blocked = False
            task_progress.space_detail = ""
            if not task_progress.space_job_ids:
                continue
            for key in list(self._space_blocked_jobs):
                self._space_blocked_jobs[key].difference_update(task_progress.space_job_ids)
                if not self._space_blocked_jobs[key]:
                    self._space_blocked_jobs.pop(key, None)
            task_progress.space_job_ids.clear()

    def succeeded(self, request_id: str, output_dirs: list[str], warnings: list[str] | None = None) -> None:
        self._terminal(request_id, "success", output_dirs=output_dirs, errors=warnings)

    def failed(
        self,
        request_id: str,
        errors: list[str],
        failure_payloads: list[dict[str, Any]],
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
            self._release_space_jobs_for_request_locked(request)
            if request.visible:
                if self._batch.completed or self._visible_requests_locked():
                    self._publish_progress_locked()
                    self._schedule_finalize_if_drained_locked()
                else:
                    self._cancel_finalize_locked()
                    self._reset_batch_locked(clear=True)

    def aborted(self, request_id: str) -> None:
        self.suppressed(request_id)

    def stop(self) -> None:
        with self._lock:
            self._closed = True
            self._cancel_finalize_locked()
            self._requests.clear()
            self._space_blocked_jobs.clear()
            self._reset_batch_locked(clear=True)

    def _terminal(
        self,
        request_id: str,
        outcome: str,
        *,
        output_dirs: list[str] | None = None,
        errors: list[str] | None = None,
        failure_payloads: list[dict[str, Any]] | None = None,
    ) -> None:
        with self._lock:
            request = self._requests.pop(str(request_id), None)
            if request is None or self._closed:
                return
            self._release_space_jobs_for_request_locked(request)
            if not request.visible:
                return
            batch = self._batch
            if not batch.completed:
                batch.source_path = request.source_path
            batch.total_bytes += sum(max(0, task.total_bytes) for task in request.tasks.values())
            if outcome == "success":
                batch.succeeded += 1
                batch.output_target = _common_output_target([batch.output_target, *(output_dirs or [])])
                batch.warnings = _bounded_text(
                    (value + "\n" for value in (batch.warnings, *(errors or [])) if value), 2048,
                ).rstrip()
            else:
                batch.failed += 1
                # A Unicode character occupies at most four UTF-8 bytes. Retain
                # bounded report text, never completed tasks or payload graphs.
                remaining = self.report_store.max_bytes // 4 - batch.failure_chars
                if remaining > 0:
                    detail = self.report_store.format_failure(
                        batch.failed, request.source_path, errors or [], failure_payloads or [], remaining,
                    )
                    batch.failure_details.append(detail)
                    batch.failure_chars += len(detail)
            self._publish_progress_locked()
            self._schedule_finalize_if_drained_locked()

    def _ensure_batch_locked(self, source_path: str) -> None:
        if not self._batch_id:
            self._batch_id = uuid.uuid4().hex
            self._batch_started_at = time.monotonic()
            self._batch.source_path = source_path

    def _visible_requests_locked(self) -> list[_RequestProgress]:
        return [request for request in self._requests.values() if request.visible]

    def _publish_progress_locked(self) -> None:
        requests = self._visible_requests_locked()
        batch = self._batch
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
        if disk_paused:
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
        self.host.publish(ToastSnapshot(
            kind=ToastSnapshotKind.PROGRESS,
            batch_id=self._batch_id,
            title=self.i18n.t("toast.progress.paused_title" if disk_paused else "toast.progress.title"),
            body=self.i18n.t("toast.progress.body", completed=completed_requests, total=count),
            progress_mode=mode,
            progress_value=value,
            progress_title=progress_title,
            progress_status=progress_status,
            progress_value_text=value_text,
        ))

    def _schedule_finalize_if_drained_locked(self) -> None:
        if not self._batch.completed or self._visible_requests_locked():
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
            if not self._batch.completed or self._visible_requests_locked():
                return
            batch = self._batch
            succeeded, failed = batch.succeeded, batch.failed
            duration = self.i18n.format_duration(time.monotonic() - self._batch_started_at)
            actions: list[ToastAction] = []
            output_target = batch.output_target
            if output_target:
                actions.append(ToastAction(
                    ToastActionKind.OPEN_DIRECTORY,
                    self.i18n.t("toast.action.open_output"),
                    output_target,
                ))
            if failed:
                try:
                    report_path = self.report_store.write(batch.failure_details, failed)
                except OSError:
                    report_path = ""
                if report_path:
                    actions.append(ToastAction(
                        ToastActionKind.OPEN_LOG,
                        self.i18n.t("toast.action.open_failure_log"),
                        report_path,
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
            self.host.publish(ToastSnapshot(
                kind=kind,
                batch_id=self._batch_id,
                title=title,
                body=body,
                actions=tuple(actions[:2]),
            ))
            self._reset_batch_locked(clear=False)

    def _reset_batch_locked(self, *, clear: bool) -> None:
        self._batch_id = ""
        self._batch_started_at = 0.0
        self._batch = _BatchProgress()
        if clear:
            self.host.clear()


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


def _task_name(task: Any, fallback: str) -> str:
    path = str(getattr(task, "main_path", "") or fallback)
    return os.path.basename(path) or path


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
