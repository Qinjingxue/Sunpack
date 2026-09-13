import os
import shutil
import sys
import threading
import time
from typing import Any, List

from sunpack.contracts.failures import FailureInfo
from sunpack.contracts.results import ArchiveCleanupResult
from sunpack.i18n import I18nContext

# native 侧的空间事件名（与 sevenzip_runner 的 _SPACE_EVENTS 一致），表达等待状态而非 job 生命周期状态。
_SPACE_EVENTS = frozenset({"space_blocked", "space_status", "space_resumed"})


def _format_bytes(value: int) -> str:
    size = float(max(0, int(value)))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024.0 or unit == "TiB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TiB"


class RunReporter:
    """Thread-safe, user-facing progress for one pipeline run."""

    def __init__(
        self,
        language: str = "en",
        quiet: bool = False,
        verbose: bool = False,
        *,
        stdout=None,
        stderr=None,
    ):
        self.i18n = I18nContext(language)
        self.language = self.i18n.language
        self.quiet = bool(quiet)
        self.verbose = bool(verbose)
        self.stdout = stdout if stdout is not None else sys.stdout
        self.stderr = stderr if stderr is not None else sys.stderr
        self._lock = threading.Lock()
        self._total_tasks = 0
        self._completed_tasks = 0
        self._nested_tasks = 0
        self._max_depth = 0
        self._task_lineages: dict[int, tuple[str, ...]] = {}
        self._output_lineages: dict[str, tuple[str, ...]] = {}
        self._top_level_outputs: list[str] = []
        self._interactive = not self.quiet and _terminal_supports_updates(self.stdout)
        self._use_color = self._interactive and os.environ.get("NO_COLOR") is None
        self._panel_tasks: list[int] = []
        self._task_rows: dict[int, dict[str, Any]] = {}
        self._last_streamed_progress: dict[int, int] = {}
        # (volume_key, episode_id) -> 仍在等待该 episode 的 job_id 集合；收到 space_resumed 时移除。
        self._space_blocked_jobs: dict[tuple[str, int], set[str]] = {}
        self._last_render_at = 0.0

    def scan_started(self, round_index: int) -> None:
        if self.quiet:
            return
        depth = max(1, int(round_index or 1))
        with self._lock:
            key = "report.scan_started" if depth == 1 else "report.recursive_scan_checking"
            self._print(self.i18n.t(key, depth=depth))

    def begin_round(self, round_index: int, tasks: list[Any], direct: bool = False) -> None:
        depth = max(1, int(round_index or 1))
        with self._lock:
            for task in tasks:
                parent_lineage = self._lineage_for_path(str(getattr(task, "main_path", "") or ""))
                self._task_lineages[id(task)] = parent_lineage
                self._task_rows[id(task)] = {
                    "task": task,
                    "depth": depth,
                    "lineage": parent_lineage,
                    "state": "waiting",
                    "progress": 0.0,
                    "completed_bytes": 0,
                    "total_bytes": 0,
                    "detail": "",
                }
            self._total_tasks += len(tasks)
            if depth > 1:
                self._nested_tasks += len(tasks)
            if tasks:
                self._max_depth = max(self._max_depth, depth)
            if self.quiet:
                return
            if direct and depth == 1:
                message = self.i18n.t("report.ready_archives", count=len(tasks))
            elif depth == 1:
                message = self.i18n.t("report.scan_found", count=len(tasks))
            else:
                message = self.i18n.t("report.recursive_found", depth=depth, count=len(tasks))
            self._print(message)
            if self._interactive:
                self._panel_tasks = [id(task) for task in tasks]
                for task_id in self._panel_tasks:
                    self._print(self._format_task_row(self._task_rows[task_id]))

    def task_started(self, task: Any, round_index: int) -> None:
        if self.quiet:
            return
        with self._lock:
            if self._interactive:
                self._update_task_locked(task, state="preparing", force=True)
                return
            depth = max(1, int(round_index or 1))
            name = _task_name(task)
            prefix = self._tree_prefix(depth)
            progress = f"{self._completed_tasks}/{self._total_tasks}"
            self._print(self.i18n.t("report.processing", prefix=prefix, progress=progress, name=name))

    def task_status(self, task: Any, state: str, detail: str = "") -> None:
        if self.quiet:
            return
        with self._lock:
            if self._interactive:
                self._update_task_locked(task, state=state, detail=detail, force=True)
                return

    def task_progress(self, task: Any, event: dict[str, Any]) -> None:
        if self.quiet:
            return
        name = str(event.get("event") or "")
        if name in _SPACE_EVENTS:
            self._space_progress(task, name, event)
            return
        try:
            completed = max(0, int(event.get("completed_bytes", 0) or 0))
            total = max(0, int(event.get("total_bytes", 0) or 0))
        except (TypeError, ValueError):
            return
        progress = min(1.0, completed / total) if total > 0 else 0.0
        with self._lock:
            row = self._task_rows.get(id(task))
            if row is None:
                return
            old_percent = int(float(row.get("progress", 0.0)) * 100)
            new_percent = int(progress * 100)
            # 磁盘满暂停期间不得把状态改回 extracting：暂停是"等待"，不是进度。
            if row.get("space_blocked"):
                self._remember_progress_locked(row, progress, completed, total)
                return
            row.update({
                "state": "extracting",
                "progress": progress,
                "completed_bytes": completed,
                "total_bytes": total,
            })
            if self._interactive and new_percent != old_percent:
                self._render_panel_locked(force=False)
            elif not self._interactive:
                # Terminals without cursor control get a throttled, line-based bar that also
                # works through wrappers and redirected output without flooding logs.
                task_id = id(task)
                last_percent = self._last_streamed_progress.get(task_id, -10)
                displayed_percent = (new_percent // 10) * 10
                if new_percent >= 100 or displayed_percent >= last_percent + 10:
                    self._last_streamed_progress[task_id] = displayed_percent
                    self._print(self._format_task_row(row))

    # 空间不足暂停/恢复：按 (volume_key, episode_id) 去重；space_status 是低频诊断（默认 15s），不是看门狗保活。
    def _space_progress(self, task: Any, event: str, payload: dict[str, Any]) -> None:
        key = (str(payload.get("volume_key") or ""), int(payload.get("episode_id") or 0))
        job_id = str(payload.get("job_id") or "")
        with self._lock:
            row = self._task_rows.get(id(task))
            if row is None:
                return
            if event == "space_resumed":
                row["space_blocked"] = False
                row.pop("space_episode", None)
                self._space_blocked_jobs.pop(key, None)
                self._restore_progress_locked(row)
                if self._interactive:
                    self._render_panel_locked(force=True)
                return

            row["space_blocked"] = True
            row["space_episode"] = key[1]
            row["state"] = "disk_paused"
            if job_id:
                self._space_blocked_jobs.setdefault(key, set()).add(job_id)
            if event == "space_status":
                detail = self._space_status_detail(payload)
                if detail:
                    row["detail"] = detail
            else:
                row["detail"] = ""
            if self._interactive:
                self._render_panel_locked(force=True)
            elif not self._interactive and event == "space_blocked":
                self._print(self.i18n.t(
                    "report.disk_paused",
                    name=_task_name(task),
                    free=_format_bytes(int(payload.get("free_bytes") or 0)),
                ))

    def _space_status_detail(self, payload: dict[str, Any]) -> str:
        # 卷查询失败（拔盘 / UNC 断开 / 权限变化）必须与"空间不足"可区分。
        if not bool(payload.get("volume_query_ok", True)):
            return self.i18n.t(
                "report.status.disk_unavailable",
                error=str(payload.get("volume_query_error") or 0),
            )
        return ""

    def _remember_progress_locked(
        self, row: dict[str, Any], progress: float, completed: int, total: int
    ) -> None:
        row["progress"] = progress
        row["completed_bytes"] = completed
        row["total_bytes"] = total

    def _restore_progress_locked(self, row: dict[str, Any]) -> None:
        row["state"] = "extracting"

    def task_finished(self, task: Any, outcome: Any, round_index: int) -> None:
        with self._lock:
            depth = max(1, int(round_index or 1))
            self._completed_tasks += 1
            name = _task_name(task)
            parent_lineage = self._task_lineages.get(id(task), ())
            result = getattr(outcome, "result", outcome)
            out_dir = str(getattr(result, "out_dir", "") or "")
            success = bool(getattr(outcome, "success", getattr(result, "success", False)))
            partial = success and getattr(getattr(outcome, "verification", None), "decision_hint", "") == "accept_partial"
            if success and out_dir:
                lineage = (*parent_lineage, name)
                self._output_lineages[_absolute_key(out_dir)] = lineage
                if depth == 1 and out_dir not in self._top_level_outputs:
                    self._top_level_outputs.append(out_dir)

            if self.quiet:
                return
            if self._interactive:
                state = "partial" if partial else "complete" if success else "error"
                error = str(getattr(result, "error", "") or "") if not success else ""
                self._update_task_locked(
                    task,
                    state=state,
                    progress=1.0 if success else None,
                    detail=error,
                    force=True,
                )
                return
            prefix = self._tree_prefix(depth)
            progress = f"{self._completed_tasks}/{self._total_tasks}"
            if partial:
                status = self.i18n.t("report.status.partial")
            elif success:
                status = self.i18n.t("report.status.success")
            else:
                status = self.i18n.t("report.status.failed")
            parent = " > ".join(parent_lineage)
            relation = self.i18n.t("report.relation.from", parent=parent) if parent else ""
            detail = ""
            if self.verbose and success and out_dir:
                detail = self.i18n.t("report.detail.output", output=out_dir)
            elif self.verbose and not success:
                error = str(getattr(result, "error", "") or "")
                detail = self.i18n.t("report.detail.error", error=error) if error else ""
            self._print(f"{prefix}[{status} {progress}] {name}{relation}{detail}")

    def log_final_summary(
        self,
        start_time: float,
        success_count: int,
        failed_tasks: List[str],
        recovered_outputs: List[dict] | None = None,
        failures: List[FailureInfo] | None = None,
        cleanup_results: List[ArchiveCleanupResult] | None = None,
    ):
        recovered = list(recovered_outputs or [])
        partial_count = len(recovered)
        complete_count = max(0, int(success_count))
        failed_count = len(failed_tasks)
        elapsed = max(0.0, time.time() - start_time)

        if not self.quiet:
            self._print("\n" + self.i18n.t("report.complete_title"))
            self._print("-" * 54)
            self._print(self.i18n.t("report.time", duration=self.i18n.format_duration(elapsed)))
            self._print(self.i18n.t("report.counts", complete=complete_count, partial=partial_count, failed=failed_count))
            if self._max_depth > 1:
                self._print(self.i18n.t("report.recursion", levels=self._max_depth, count=self._nested_tasks))
            output_location = self._output_location()
            if output_location:
                self._print(self.i18n.t("report.output", output=output_location))

            for item in recovered:
                archive = os.path.basename(str(item.get("archive") or ""))
                coverage = item.get("archive_coverage") if isinstance(item.get("archive_coverage"), dict) else {}
                completeness = _percent(coverage.get("completeness", item.get("completeness", 0.0)))
                self._print(self.i18n.t("report.partial", archive=archive, completeness=completeness, coverage=_file_coverage(coverage)))
                warning = FailureInfo.from_dict(item.get("warning"))
                if warning is not None:
                    self._print(self.i18n.t("report.partial_warning", warning=warning.message))

        structured_failures = list(failures or [])
        if failed_tasks:
            if not self.quiet:
                for failed_task in failed_tasks:
                    self._print(self.i18n.t("report.failed", task=failed_task))
                if structured_failures and all(failure.is_password_failure for failure in structured_failures):
                    self._print(self.i18n.t("report.password_failure"))
        else:
            if not self.quiet:
                self._print(self.i18n.t("report.partial_complete" if recovered else "report.all_success"))

        cleanup_failures = [
            item for item in cleanup_results or [] if item.status == "failed"
        ]
        if cleanup_failures and not self.quiet:
            self._print(self.i18n.t("cleanup.incomplete", count=len(cleanup_failures)))
            for item in cleanup_failures:
                self._print(f"  {item.path}: {item.message}")

        if not self.quiet:
            self._print("-" * 54)

    def _print(self, value: str) -> None:
        print(value, file=self.stdout, flush=True)

    def _lineage_for_path(self, path: str) -> tuple[str, ...]:
        if not path:
            return ()
        candidate = _absolute_key(path)
        best_root = ""
        best_lineage: tuple[str, ...] = ()
        for output_root, lineage in self._output_lineages.items():
            try:
                inside = os.path.commonpath([candidate, output_root]) == output_root
            except ValueError:
                inside = False
            if inside and len(output_root) > len(best_root):
                best_root = output_root
                best_lineage = lineage
        return best_lineage

    def _update_task_locked(
        self,
        task: Any,
        *,
        state: str | None = None,
        progress: float | None = None,
        detail: str | None = None,
        force: bool = False,
    ) -> None:
        row = self._task_rows.get(id(task))
        if row is None:
            return
        if state is not None:
            row["state"] = state
        if progress is not None:
            row["progress"] = min(1.0, max(0.0, float(progress)))
        if detail is not None:
            row["detail"] = detail
        self._render_panel_locked(force=force)

    def _render_panel_locked(self, *, force: bool) -> None:
        if not self._interactive or not self._panel_tasks:
            return
        now = time.monotonic()
        if not force and now - self._last_render_at < 0.08:
            return
        self._last_render_at = now
        self.stdout.write(f"\033[{len(self._panel_tasks)}A")
        for task_id in self._panel_tasks:
            row = self._task_rows.get(task_id)
            text = self._format_task_row(row) if row is not None else ""
            self.stdout.write(f"\r\033[2K{text}\n")
        self.stdout.flush()

    def _format_task_row(self, row: dict[str, Any]) -> str:
        depth = int(row.get("depth", 1) or 1)
        task = row.get("task")
        state = str(row.get("state") or "waiting")
        progress = float(row.get("progress", 0.0) or 0.0)
        percent = max(0, min(100, int(progress * 100)))
        filled = max(0, min(20, int(progress * 20)))
        bar = "#" * filled + "-" * (20 - filled)
        labels = {
            "waiting": "report.status.waiting",
            "preparing": "report.status.preparing",
            "extracting": "report.status.extracting",
            "disk_paused": "report.status.disk_paused",
            "error": "report.status.error",
            "partial": "report.status.partial",
            "complete": "report.status.complete",
        }
        label = self.i18n.t(labels.get(state, labels["waiting"]))
        colors = {
            "waiting": "\033[90m",
            "preparing": "\033[36m",
            "extracting": "\033[36m",
            "disk_paused": "\033[33m",
            "error": "\033[31m",
            "partial": "\033[33m",
            "complete": "\033[32m",
        }
        label = f"{label:^8}"
        plain_label = label
        if self._use_color:
            label = f"{colors.get(state, '')}{label}\033[0m"
        prefix = self._tree_prefix(depth)
        lineage = tuple(row.get("lineage") or ())
        parent = " > ".join(lineage)
        relation = self.i18n.t("report.relation.from", parent=parent) if parent else ""
        detail = str(row.get("detail") or "")
        if detail and (self.verbose or state == "error"):
            detail = self.i18n.t("report.detail.error", error=detail)
        else:
            detail = ""
        fixed = f"{prefix}[{plain_label}] [{bar}] {percent:3d}%  "
        fixed_width = _display_width(fixed)
        terminal_columns = getattr(self.stdout, "terminal_columns", None)
        if not isinstance(terminal_columns, int) or terminal_columns <= 0:
            terminal_columns = shutil.get_terminal_size(fallback=(120, 30)).columns
        available = max(1, terminal_columns - fixed_width)
        suffix = _truncate_display(f"{_task_name(task)}{relation}{detail}", available)
        return f"{prefix}[{label}] [{bar}] {percent:3d}%  {suffix}"

    @staticmethod
    def _tree_prefix(depth: int) -> str:
        return "" if depth <= 1 else "  " * (depth - 1) + "└─ "

    def _output_location(self) -> str:
        outputs = [os.path.abspath(os.path.normpath(path)) for path in self._top_level_outputs if path]
        if not outputs:
            return ""
        if len(outputs) == 1:
            return outputs[0]
        try:
            return os.path.commonpath(outputs)
        except ValueError:
            return self.i18n.t("report.multiple_locations")


def _task_name(task: Any) -> str:
    path = str(getattr(task, "main_path", "") or "")
    return os.path.basename(path) or str(getattr(task, "logical_name", "") or path or "archive")


def _absolute_key(path: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.normpath(path)))


def _terminal_supports_updates(stream: Any) -> bool:
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty) or not isatty():
        return False
    forwarded_capability = getattr(stream, "supports_terminal_updates", None)
    if forwarded_capability is not None:
        return bool(forwarded_capability)
    try:
        import ctypes

        handle = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _truncate_display(text: str, max_width: int) -> str:
    ellipsis = "…"
    ellipsis_width = _display_width(ellipsis)
    if max_width < ellipsis_width:
        return ""
    width = 0
    chars = []
    for char in text:
        char_width = 2 if ord(char) > 0xFF else 1
        if width + char_width > max_width:
            while chars and width + ellipsis_width > max_width:
                removed = chars.pop()
                width -= 2 if ord(removed) > 0xFF else 1
            return "".join(chars) + ellipsis
        chars.append(char)
        width += char_width
    return text


def _display_width(text: str) -> int:
    return sum(2 if ord(char) > 0xFF else 1 for char in text)


def _percent(value) -> str:
    try:
        return f"{float(value or 0.0) * 100:.1f}%"
    except (TypeError, ValueError):
        return "0.0%"


def _file_coverage(coverage: dict) -> str:
    expected = int(coverage.get("expected_files", 0) or 0)
    matched = int(coverage.get("matched_files", 0) or 0)
    complete = int(coverage.get("complete_files", 0) or 0)
    if expected <= 0:
        return ""
    return f" ({complete}/{matched}/{expected})"
