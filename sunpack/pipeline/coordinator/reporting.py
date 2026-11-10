import asyncio
import os
import shutil
import sys
import threading
import time
from typing import Any

from sunpack.core.support.path_map import PathMap
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.results import DirectoryFlattenResult, RunSummary, OutcomeKind
from sunpack.core.i18n import I18nContext
from sunpack.core.support.filesystem_scan_errors import is_filesystem_scan_failure

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
        emit_errors: bool = True,
        stdout=None,
        stderr=None,
        work_broker=None,
        request_id: str = "",
    ):
        self.i18n = I18nContext(language)
        self.quiet = bool(quiet)
        self.verbose = bool(verbose)
        self.emit_errors = bool(emit_errors)
        self.stdout = stdout if stdout is not None else sys.stdout
        self.stderr = stderr if stderr is not None else sys.stderr
        self._lock = threading.RLock()
        self._nested_tasks = 0
        self._max_depth = 0
        self._output_rows = PathMap()
        self._top_level_outputs = PathMap()
        self._interactive = not self.quiet and _terminal_supports_updates(self.stdout)
        self._scope_roots = {}
        self._input_rows = {}
        self._rendered_lines = 0
        self._panel_pauses = 0
        self._finished_scopes = set()
        self._task_rows: dict[str, dict[str, Any]] = {}
        self._last_render_at = 0.0
        self._work_broker = work_broker
        self._request_id = request_id
        self._pending_resource_progress: dict[tuple[int, str], tuple[Any, dict[str, Any]]] = {}
        self._resource_progress_task: asyncio.Task | None = None

    def tasks_discovered(self, depth: int, tasks: list[Any]) -> None:
        with self._lock:
            if depth > 1:
                self._nested_tasks += len(tasks)
            if tasks:
                self._max_depth = max(self._max_depth, depth)
            if self.quiet:
                return
            for task in tasks:
                key = str(task.key or task.main_path)
                parent = self._parent_row_for_path(task.main_path)
                self._task_rows[key] = self._new_row(_task_name(task))
                if parent in self._task_rows:
                    self._task_rows[parent]["children"].append(key)
                else:
                    self._scope_roots[key] = None
            self._render_panel_locked(force=True)

    @staticmethod
    def _new_row(name):
        return dict(name=name, children=[], state="waiting",
                    progress=0.0, progress_known=False,
                    detail="", output="", container=False, input_ids=[])

    def _row_key(self, task):
        key = str(task.key or task.main_path)
        inputs = getattr(task, "inputs", ())
        if len(inputs) == 1 and inputs[0].input_id in self._input_rows:
            return self._input_rows[inputs[0].input_id]
        return key if key in self._task_rows else None

    def task_started(self, task: Any) -> None:
        if self.quiet:
            return
        with self._lock:
            key = str(task.key or task.main_path)
            row = self._task_rows.get(key)
            if row is None:
                return
            inputs = getattr(task, "inputs", ())
            row["container"] = len(inputs) > 1
            for node in inputs:
                if len(inputs) == 1:
                    self._input_rows[node.input_id] = key
                    row["input_ids"].append(node.input_id)
                    continue
                child = node.input_id
                if child not in self._task_rows:
                    extent = node.descriptor.primary_extent
                    name = self.i18n.t("cli.scan.segment", index=node.position)
                    name += f" ({node.descriptor.format_hint})"
                    if extent:
                        name += f" [{extent.start}, {extent.end if extent.end is not None else '?'})"
                    self._task_rows[child] = self._new_row(name)
                    if node.failure is not None:
                        self._task_rows[child]["state"] = "error"
                        self._task_rows[child]["detail"] = self._format_failure(node.failure)
                    row["children"].append(child)
                self._input_rows[child] = child
                self._task_rows[child]["input_ids"].append(child)
            row["state"] = "preparing"
            self._render_panel_locked(force=True)

    def task_status(self, task: Any, state: str, detail: str = "") -> None:
        if self.quiet:
            return
        with self._lock:
            row = self._task_rows.get(self._row_key(task))
            if row is None:
                return
            row["state"] = state
            if state in {"waiting", "preparing", "extracting"} and (row.get("space_blocked") or row.get("memory_blocked")):
                self._restore_progress_locked(row)
            row["detail"] = detail
            self._render_panel_locked(force=True)

    def task_progress(self, task: Any, event: dict[str, Any]) -> None:
        if self.quiet:
            return
        name = str(event.get("event") or "")
        if name in {"input_started", "input_finished", "task_detail"}:
            # Pipeline semantic events arrive in admitted broker jobs. Their
            # scope/output relationship must survive concurrent console updates.
            with self._lock:
                self._task_progress_locked(task, event)
            return
        if name in _SPACE_EVENTS or name in {"memory_blocked", "memory_resumed"}:
            if self._work_broker is None:
                self._resource_progress(task, event)
            else:
                # Called on the request loop. Keep at most one latest event per
                # task/resource while the existing broker waits for output.
                resource = "space" if name in _SPACE_EVENTS else "memory"
                self._pending_resource_progress[id(task), resource] = (task, dict(event))
                if self._resource_progress_task is None or self._resource_progress_task.done():
                    if self._resource_progress_task is not None:
                        self._resource_progress_task.result()
                    self._resource_progress_task = asyncio.create_task(self._drain_resource_progress())
            return
        # Native progress is best-effort. Never park the runtime loop behind a
        # report thread holding this lock while waiting for client capacity.
        if not self._lock.acquire(blocking=False):
            return
        try:
            self._task_progress_locked(task, event)
        except BlockingIOError:
            # The final report is lossless and uses the blocking broker path.
            pass
        finally:
            self._lock.release()

    def _resource_progress(self, task: Any, event: dict[str, Any]) -> None:
        # Broker workers may wait for the reporter and output; the loop must not.
        with self._lock:
            self._task_progress_locked(task, event)

    async def _drain_resource_progress(self) -> None:
        while self._pending_resource_progress:
            key = next(iter(self._pending_resource_progress))
            task, event = self._pending_resource_progress.pop(key)
            await self._work_broker.run(
                "report", "", self._resource_progress, task, event,
                request_id=self._request_id,
            )

    async def drain_progress(self) -> None:
        pending = self._resource_progress_task
        if pending is not None:
            try:
                await asyncio.shield(pending)
            except asyncio.CancelledError:
                # Match the broker's join-before-release cancellation contract.
                while not pending.done():
                    try:
                        await asyncio.shield(pending)
                    except asyncio.CancelledError:
                        continue
                pending.result()
                raise
            finally:
                self._resource_progress_task = None
                self._pending_resource_progress.clear()

    def _task_progress_locked(self, task: Any, event: dict[str, Any]) -> None:
        if self.quiet:
            return
        task_id = self._row_key(task)
        row = self._task_rows.get(task_id)
        if row is None or row["state"] in {"complete", "partial", "error"}:
            return
        name = str(event.get("event") or "")
        if name in {"input_started", "input_finished", "task_detail"}:
            if name == "input_started":
                row["state"] = "preparing"
            elif name == "input_finished":
                row["state"] = "complete" if event.get("success") else "error"
                row["detail"] = str(event.get("error") or "")
                row["output"] = str(event.get("out_dir") or "")
                if row["output"] and event.get("success"):
                    self._output_rows[row["output"]] = task_id
            elif self.verbose:
                row["detail"] = str(event.get("detail") or "")
            self._render_panel_locked(force=True)
            return
        if name in {"memory_blocked", "memory_resumed"}:
            row["memory_blocked"] = name == "memory_blocked"
            self._restore_progress_locked(row)
            self._render_panel_locked(force=True)
            return
        if name in _SPACE_EVENTS:
            self._space_progress_locked(row, name, event)
            return
        if event.get("type") != "progress":
            return
        try:
            completed = max(0, int(event.get("completed_bytes", 0) or 0))
            total = max(0, int(event.get("total_bytes", 0) or 0))
        except (TypeError, ValueError):
            return
        known = total > 0
        progress = min(1.0, completed / total) if known else 0.0
        old_percent = int(row["progress"] * 100) if self._interactive and row["progress_known"] else None
        old_state = row["state"]
        row["progress"] = progress
        row["progress_known"] = known
        if row.get("space_blocked") or row.get("memory_blocked"):
            return
        row["state"] = "extracting"
        if self._interactive:
            new_percent = int(progress * 100) if known else None
            if new_percent != old_percent or old_state != "extracting":
                self._render_panel_locked(force=False)

    # Transport filters stale episodes; only retain the visible state here.
    def _space_progress_locked(
        self, row: dict[str, Any], event: str, payload: dict[str, Any],
    ) -> None:
        row["space_blocked"] = event != "space_resumed"
        self._restore_progress_locked(row)
        row["detail"] = self._space_status_detail(payload) if event == "space_status" else ""
        self._render_panel_locked(force=True)

    def _space_status_detail(self, payload: dict[str, Any]) -> str:
        # 卷查询失败（拔盘 / UNC 断开 / 权限变化）必须与"空间不足"可区分。
        if not bool(payload.get("volume_query_ok", True)):
            return self.i18n.t(
                "report.status.disk_unavailable",
                error=str(payload.get("volume_query_error") or 0),
            )
        return ""

    def _restore_progress_locked(self, row: dict[str, Any]) -> None:
        row["state"] = "memory_paused" if row.get("memory_blocked") else ("disk_paused" if row.get("space_blocked") else "extracting")

    def task_finished(self, task: Any, outcome: Any, depth: int) -> None:
        with self._lock:
            if self.quiet:
                return
            key = self._row_key(task)
            row = self._task_rows.get(key)
            if row is None:
                return
            result = getattr(outcome, "result", outcome)
            kind = outcome.outcome_kind
            success = kind in {OutcomeKind.COMPLETE_SUCCESS, OutcomeKind.PARTIAL_SUCCESS}
            row["state"] = "partial" if kind == OutcomeKind.PARTIAL_SUCCESS else "complete" if success else "error"
            row["detail"] = str(getattr(result, "error", "") or "")
            row["output"] = str(getattr(result, "out_dir", "") or "")
            if success:
                row["progress"] = 1.0
                row["progress_known"] = True
            if row["output"] and (success or getattr(result, "has_complete_inputs", False)):
                self._output_rows[row["output"]] = key
                if depth == 1:
                    self._top_level_outputs.setdefault(row["output"], row["output"])
            # Verification can reject a child after its worker completed.
            # Refresh existing segment rows from the authoritative result.
            for item in getattr(result, "input_results", ()):
                child = self._task_rows.get(self._input_rows.get(item.input.input_id))
                if child is not None and child is not row:
                    child["state"] = "complete" if item.complete else "error"
                    child["detail"] = item.result.error or (self.i18n.t("failure.verification_failed")
                        if item.verified_complete is False else "")
            self._render_panel_locked(force=True)

    def scope_finished(self, task, depth):
        """Flush one complete recursive tree, then release all display state."""
        if self.quiet or depth != 1:
            return
        with self._lock:
            root = str(task.key or task.main_path)
            if root not in self._task_rows:
                return
            if self._panel_pauses:
                self._finished_scopes.add(root)
                return
            self._flush_scope_locked(root)

    def _flush_scope_locked(self, root):
        self._clear_panel_locked()
        for line in self._scope_lines((root,)):
            print(line, file=self.stdout)
        pending = [root]
        while pending:
            key = pending.pop()
            row = self._task_rows.pop(key)
            pending.extend(row["children"])
            for input_id in row["input_ids"]:
                self._input_rows.pop(input_id, None)
            if row["output"]:
                self._output_rows.pop(row["output"], None)
        self._scope_roots.pop(root, None)
        self._render_panel_locked(force=True)
        self.stdout.flush()


    def pause_panel(self):
        with self._lock:
            self._panel_pauses += 1
            self._clear_panel_locked()
            self.stdout.flush()

    def resume_panel(self):
        with self._lock:
            self._panel_pauses -= 1
            if self._panel_pauses == 0:
                for root in self._finished_scopes:
                    self._flush_scope_locked(root)
                self._finished_scopes.clear()
                self._render_panel_locked(force=True)

    def _scope_lines(self, roots):
        pending = [iter((key, "", True, True) for key in roots)]
        while pending:
            try:
                key, prefix, last, root = next(pending[-1])
            except StopIteration:
                pending.pop()
                continue
            row = self._task_rows[key]
            branch = "" if root else "└─ " if last else "├─ "
            yield prefix + branch + str(row["name"]).replace("\n", " ").replace("\r", " ")
            child_prefix = prefix + ("" if root else "   " if last else "│  ")
            if not row["container"]:
                yield child_prefix + "  " + self._format_task_row(row)
                if row["detail"] and (self.verbose or row["state"] == "error"):
                    yield child_prefix + "  " + row["detail"].replace("\n", " ").replace("\r", " ")
                if self.verbose and row["output"]:
                    yield child_prefix + "  " + self.i18n.t("report.detail.output", output=row["output"])
            children = row["children"]
            pending.append(self._child_entries(children, child_prefix))


    @staticmethod
    def _child_entries(children, prefix):
        for i, child in enumerate(children):
            yield child, prefix, i == len(children) - 1, False

    def relocate_outputs(self, result: DirectoryFlattenResult) -> None:
        with self._lock:
            for _path, original in self._top_level_outputs.pop_under(result.path):
                relocated = result.relocate(original)
                self._top_level_outputs[relocated] = relocated
            self._output_rows.relocate(result)
            for row in self._task_rows.values():
                if row["output"]:
                    row["output"] = result.relocate(row["output"])

    def log_final_summary(
        self,
        start_time: float,
        summary: RunSummary,
    ):
        recovered = summary.recovered_outputs
        partial_count = len(recovered)
        complete_count = summary.success_count
        elapsed = max(0.0, time.time() - start_time)

        if not self.quiet:
            self._print("\n" + self.i18n.t("report.complete_title"))
            self._print("-" * 54)
            self._print(self.i18n.t("report.time", duration=self.i18n.format_duration(elapsed)))
            self._print(self.i18n.t("report.counts", complete=complete_count, partial=partial_count,
                                    failed=summary.failed_count, scan_errors=summary.scan_error_count,
                                    input_errors=summary.input_error_count))
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

        if self.emit_errors:
            for failure in summary.scan_failures:
                key = "report.scan_error" if is_filesystem_scan_failure(failure) else "report.failed"
                self._print(self.i18n.t(key, task=self._format_failure(failure)), error=True)
            for result in summary.target_results:
                if result.outcome_kind != OutcomeKind.FAILURE:
                    continue
                key = "report.input_error" if result.failure is not None and result.failure.kind == FailureKind.INVALID_INPUT else "report.failed"
                message = result.failure_message or f"{result.input_path} [{result.error}]"
                self._print(self.i18n.t(key, task=message), error=True)
            if summary.scan_error_count:
                self._print(self.i18n.t("report.scan_incomplete"), error=True)
            if summary.failed_count and summary.failures and all(failure.is_password_failure for failure in summary.failures):
                self._print(self.i18n.t("report.password_failure"), error=True)
        if not summary.failed_tasks and not self.quiet:
            self._print(self.i18n.t("report.partial_complete" if recovered else "report.all_success"))

        cleanup_failures = [
            item for item in summary.cleanup_results if item.status == "failed"
        ]
        if cleanup_failures and self.emit_errors:
            self._print(self.i18n.t("report.postprocess_warning", message=self.i18n.t(
                "cleanup.incomplete", count=len(cleanup_failures),
            )), error=True)
            for item in cleanup_failures:
                self._print(f"  {item.path}: {item.message}", error=True)

        if not self.quiet:
            self._print("-" * 54)

    def _format_failure(self, failure: FailureInfo) -> str:
        reason = self.i18n.t(failure.message_key, **failure.message_params) if failure.message_key else failure.message
        path = failure.details.get("path")
        return f"{path}: {reason}" if path and failure.stage == "embedded_boundary" else reason

    def _print(self, value: str, *, error: bool = False) -> None:
        with self._lock:
            self._clear_panel_locked()
            print(value, file=self.stderr if error else self.stdout, flush=True)
            self._render_panel_locked(force=True)

    def _parent_row_for_path(self, path: str) -> str | None:
        parent = None
        if path and self._output_rows:
            for _, row_key in self._output_rows.ancestors(path):
                parent = row_key
        return parent

    def _clear_panel_locked(self):
        if self._rendered_lines:
            self.stdout.write(f"\033[{self._rendered_lines}A\r\033[J")
            self._rendered_lines = 0

    def _render_panel_locked(self, *, force: bool) -> None:
        if not self._interactive or self._panel_pauses:
            return
        now = time.monotonic()
        if not force and now - self._last_render_at < 0.08:
            return
        self._last_render_at = now
        # Bound terminal rendering by its viewport, without truncating the final
        # tree or retaining event histories. No idle refresh thread is needed.
        size = shutil.get_terminal_size(fallback=(120, 30))
        columns = getattr(self.stdout, "terminal_columns", size.columns)
        height = max(3, size.lines - 2)
        self._clear_panel_locked()
        lines = []
        for line in self._scope_lines(self._scope_roots):
            if len(lines) == height - 1:
                lines.append("…")
                break
            lines.append(_truncate_display(line, max(1, columns - 1)))
        if lines:
            self.stdout.write("\n".join(lines) + "\n")
        self._rendered_lines = len(lines)
        self.stdout.flush()

    def _format_task_row(self, row: dict[str, Any]) -> str:
        state = row["state"]
        if state in {"disk_paused", "memory_paused"} and row.get("space_blocked") and row.get("memory_blocked"):
            state = "resources_paused"
        label = self.i18n.t("report.status." + state)
        percent = f"{row['progress']:.0%}" if row["progress_known"] else "--%"
        detail = ""
        if state in {"disk_paused", "memory_paused", "resources_paused"}:
            hint = {"disk_paused": "disk", "memory_paused": "memory", "resources_paused": "resources"}[state]
            detail = " " + (row["detail"] or self.i18n.t(f"report.status.{hint}_resume_hint"))
        return f"[{label}] {percent}{detail}"

    def _output_location(self) -> str:
        outputs = [os.path.abspath(os.path.normpath(path)) for path in self._top_level_outputs.values() if path]
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


def _terminal_supports_updates(stream: Any) -> bool:
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty) or not isatty():
        return False
    forwarded_capability = getattr(stream, "supports_terminal_updates", None)
    if forwarded_capability is not None:
        return bool(forwarded_capability)
    if os.name != "nt":
        return False
    try:
        import ctypes
        import msvcrt

        # Query the actual destination stream, not GetStdHandle(STD_OUTPUT_HANDLE):
        # a wrapper/redirection can point at a different console or a pipe.
        handle = msvcrt.get_osfhandle(stream.fileno())
        kernel32 = ctypes.windll.kernel32
        # ctypes defaults to 32-bit arguments; console HANDLEs are pointer-sized.
        kernel32.GetConsoleMode.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
        kernel32.GetConsoleMode.restype = ctypes.c_int
        kernel32.SetConsoleMode.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        kernel32.SetConsoleMode.restype = ctypes.c_int
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        if not mode.value & 0x0004 and not kernel32.SetConsoleMode(handle, mode.value | 0x0004):
            return False
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(mode.value & 0x0004)
    except (AttributeError, OSError, ValueError, TypeError):
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
