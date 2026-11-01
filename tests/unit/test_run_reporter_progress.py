import io
import re
from types import SimpleNamespace

import pytest

import sunpack.pipeline.coordinator.reporting as reporting
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.results import RunSummary, TargetRunResult, OutcomeKind
from sunpack.pipeline.coordinator.reporting import RunReporter
from sunpack.core.support.filesystem_scan_errors import filesystem_scan_failure


def _task(path):
    return SimpleNamespace(main_path=str(path), logical_name=path.stem)


def _outcome(out_dir, *, success=True, partial=False, error=""):
    return SimpleNamespace(
        success=success,
        result=SimpleNamespace(success=success, out_dir=str(out_dir), error=error),
        verification=SimpleNamespace(decision_hint="accept_partial" if partial else "accept"),
    )


@pytest.mark.parametrize("quiet", [False, True])
def test_reporter_keeps_display_and_lineage_without_retaining_finished_inputs(tmp_path, quiet):
    """Display tests cannot detect a reporter pinning native discovery snapshots.

    Without this, completed recursive subtrees can accumulate for the entire
    request. Two tiny snapshots verify ownership and later rendering together.
    """
    import gc
    import weakref
    from sunpack.core.contracts.filesystem import DirectorySnapshot, FileEntry
    from tests.helpers.archive_tasks import make_archive_task

    output = io.StringIO()
    reporter = RunReporter("en", stdout=output, quiet=quiet)
    for depth, root in ((1, tmp_path), (2, tmp_path / "outer")):
        task = make_archive_task(root / ("outer.zip" if depth == 1 else "inner.zip"))
        snapshot = DirectorySnapshot.from_entries(root, [FileEntry(root / "member", False, 7)])
        task.runtime["discovery_snapshot"] = snapshot
        task_ref, snapshot_ref = weakref.ref(task), weakref.ref(snapshot)
        reporter.tasks_discovered(depth, [task])
        reporter.task_finished(task, _outcome(root / ("outer" if depth == 1 else "inner")), depth)
        row = reporter._task_rows[id(task)]
        assert row["name"] == ("outer.zip" if depth == 1 else "inner.zip")
        if depth == 2:
            assert row["lineage"] == ("outer.zip",)
        del task, snapshot
        gc.collect()
        assert task_ref() is None and snapshot_ref() is None
        assert row["name"] in reporter._format_task_row(row)


def test_progress_displays_nested_archive_parent_chain_and_final_page(tmp_path, capsys):
    reporter = RunReporter("zh")
    outer = _task(tmp_path / "outer.zip")
    outer_output = tmp_path / "outer"

    reporter.scan_started(1)
    reporter.tasks_discovered(1, [outer])
    reporter.task_started(outer, 1)
    reporter.task_finished(outer, _outcome(outer_output), 1)

    inner = _task(outer_output / "folder" / "inner.7z")
    inner_output = outer_output / "folder" / "inner"
    reporter.tasks_discovered(2, [inner])
    reporter.task_started(inner, 2)
    reporter.task_finished(inner, _outcome(inner_output), 2)
    reporter.log_final_summary(0, RunSummary(target_results=(
        TargetRunResult(str(outer.main_path), OutcomeKind.COMPLETE_SUCCESS),
        TargetRunResult(str(inner.main_path), OutcomeKind.COMPLETE_SUCCESS),
    )))

    output = capsys.readouterr().out
    assert "[扫描中] 正在查找压缩包…" in output
    assert "[扫描完成] 发现 1 个待处理压缩包" in output
    assert "[递归扫描] 第 2 层发现 1 个嵌套压缩包" in output
    assert "+- [成功 2/2] inner.7z（来自 outer.zip）" in output
    assert "完整成功：2  部分恢复：0  解压失败：0  扫描错误：0" in output
    assert "递归层级：2 层，处理嵌套包：1 个" in output
    assert f"输出位置：{outer_output}" in output


def test_progress_displays_full_lineage_for_deep_recursion(tmp_path, capsys):
    reporter = RunReporter("zh")
    paths = [
        (tmp_path / "outer.zip", tmp_path / "outer"),
        (tmp_path / "outer" / "inner.rar", tmp_path / "outer" / "inner"),
        (tmp_path / "outer" / "inner" / "data.7z", tmp_path / "outer" / "inner" / "data"),
    ]

    for depth, (archive, output_dir) in enumerate(paths, start=1):
        task = _task(archive)
        reporter.tasks_discovered(depth, [task])
        reporter.task_finished(task, _outcome(output_dir), depth)

    output = capsys.readouterr().out
    assert "data.7z（来自 outer.zip > inner.rar）" in output


def test_partial_recovery_prints_possible_missing_volume_warning(tmp_path, capsys):
    warning = FailureInfo(
        FailureKind.MISSING_VOLUME,
        "extraction_report",
        "压缩包内容不完整；可能缺少一个或多个分卷",
        details={"missing_volume_confirmed": False, "partial_recovery": True},
    )

    RunReporter("zh").log_final_summary(
        0,
        RunSummary(target_results=(TargetRunResult(str(tmp_path / "sample.zip.001"), OutcomeKind.PARTIAL_SUCCESS, recovery={
            "archive": str(tmp_path / "sample.zip.001"),
            "completeness": 0.75,
            "warning": warning.to_dict(),
        }),)),
    )

    output = capsys.readouterr().out
    assert "[部分恢复] sample.zip.001" in output
    assert "[警告] 压缩包内容不完整；可能缺少一个或多个分卷" in output


@pytest.mark.parametrize("language", ["zh", "en"])
@pytest.mark.parametrize("quiet, emit_errors", [(False, True), (True, True), (True, False)])
def test_final_summary_distinguishes_scan_and_archive_errors(tmp_path, language, quiet, emit_errors):
    # Separately covers mixed error presentation and overflow counts. Native
    # scan tests alone cannot expose quiet swallowing archive failure messages.
    output, errors = io.StringIO(), io.StringIO()
    path = tmp_path / "broken.7z"
    failure = FailureInfo(
        FailureKind.DAMAGED,
        "embedded_boundary",
        "Embedded archive is truncated before its terminal boundary",
        message_key="failure.damaged",
        details={"path": str(path)},
    )
    scan_failures = [filesystem_scan_failure(error, language) for error in (
        ("read_dir", str(tmp_path / "blocked"), "access denied"),
        ("omitted", str(tmp_path), "4"),
    )]
    # Classification must survive a processing error sharing the scan text.
    from dataclasses import replace
    failure = replace(failure, message=scan_failures[0].message)

    RunReporter(language, quiet=quiet, emit_errors=emit_errors, stdout=output, stderr=errors).log_final_summary(
        0,
        RunSummary(scan_failures=(failure, *scan_failures)),
    )

    labels = ("[解压失败]", "[扫描错误]", "[扫描不完整]", "压缩包损坏", "解压失败：1  扫描错误：5") if language == "zh" else (
        "[Extraction failed]", "[Scan error]", "[Scan incomplete]", "Archive is damaged", "Extraction failed: 1  Scan errors: 5",
    )
    if emit_errors:
        assert f"{path}: {labels[3]}" in errors.getvalue()
        assert errors.getvalue().count(labels[0]) == 1
        assert errors.getvalue().count(labels[1]) == 2
        assert labels[2] in errors.getvalue()
    else:
        assert errors.getvalue() == ""
    if quiet:
        assert output.getvalue() == ""
    else:
        assert labels[4] in output.getvalue()
        assert all(label not in output.getvalue() for label in labels[:3])


def test_interactive_panel_updates_fixed_row_with_progress_and_colors(tmp_path, monkeypatch):
    stream = io.StringIO()
    stream.terminal_columns = 72
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: True)
    monkeypatch.setattr(reporting.sys, "stdout", stream)
    reporter = RunReporter("zh")
    task = _task(tmp_path / "large.7z")

    reporter.tasks_discovered(1, [task])
    reporter.task_started(task, 1)
    reporter._last_render_at = 0.0
    reporter.task_progress(task, {"type": "progress", "completed_bytes": 50, "total_bytes": 100})
    reporter.task_status(task, "extracting")
    reporter.task_finished(task, _outcome(tmp_path / "large"), 1)

    output = stream.getvalue()
    assert "等待队列" in output
    assert "50%" in output
    assert "正在解压" in output
    assert "\033[32m" in output and "完成" in output
    assert "\033[1A" in output
    row = reporter._format_task_row(reporter._task_rows[id(task)])
    plain_row = re.sub(r"\033\[[0-9;]*m", "", row)
    assert reporting._display_width(plain_row) <= stream.terminal_columns


def test_interactive_row_accounts_for_wide_status_and_archive_characters(tmp_path, monkeypatch):
    stream = io.StringIO()
    stream.terminal_columns = 80
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: True)
    reporter = RunReporter("zh", stdout=stream)
    task = _task(tmp_path / ("很长的嵌套压缩包名称" * 8 + ".zip"))

    reporter.tasks_discovered(2, [task])
    reporter.task_progress(task, {"type": "progress", "completed_bytes": 50, "total_bytes": 100})

    row = reporter._format_task_row(reporter._task_rows[id(task)])
    plain_row = re.sub(r"\033\[[0-9;]*m", "", row)
    assert reporting._display_width(plain_row) <= stream.terminal_columns
    assert plain_row.endswith("…")


@pytest.mark.parametrize("language,hint", [
    ("zh", "释放空间后自动继续"),
    ("en", "Free space to resume automatically"),
])
def test_disk_full_guidance_in_interactive_and_streamed_cli(tmp_path, monkeypatch, language, hint):
    task = _task(tmp_path / "sample.zip")
    blocked = {
        "type": "progress", "event": "space_blocked",
        "volume_key": "C:", "episode_id": 1, "job_id": "job-1",
        "free_bytes": 0,
    }

    terminal = io.StringIO()
    terminal.terminal_columns = 120
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: True)
    interactive = RunReporter(language, stdout=terminal)
    interactive.tasks_discovered(1, [task])
    interactive.task_progress(task, blocked)
    assert hint in terminal.getvalue()
    assert reporting._display_width(
        re.sub(r"\033\[[0-9;]*m", "", interactive._format_task_row(interactive._task_rows[id(task)]))
    ) < terminal.terminal_columns

    streamed = io.StringIO()
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: False)
    noninteractive = RunReporter(language, stdout=streamed)
    noninteractive.tasks_discovered(1, [task])
    noninteractive.task_progress(task, blocked)
    noninteractive.task_progress(task, {**blocked, "event": "space_status"})
    assert streamed.getvalue().count(hint.lower() if language == "en" else hint) == 1


def test_forwarded_terminal_capability_does_not_require_server_console():
    stream = io.StringIO()
    stream.isatty = lambda: True
    stream.supports_terminal_updates = True

    assert reporting._terminal_supports_updates(stream)


def test_noninteractive_terminal_streams_throttled_progress_bar(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: False)
    reporter = RunReporter("zh")
    task = _task(tmp_path / "large.7z")

    reporter.tasks_discovered(1, [task])
    reporter.task_progress(task, {"type": "progress", "completed_bytes": 5, "total_bytes": 100})
    reporter.task_progress(task, {"type": "progress", "completed_bytes": 9, "total_bytes": 100})
    reporter.task_progress(task, {"type": "progress", "completed_bytes": 50, "total_bytes": 100})

    output = capsys.readouterr().out
    assert output.count("正在解压") == 2
    assert "  5%" in output
    assert " 50%" in output


@pytest.mark.parametrize("language", ["zh", "en"])
@pytest.mark.parametrize("interactive", [True, False])
@pytest.mark.parametrize("blocked_first", ["memory", "space"])
@pytest.mark.parametrize("resumed_first", ["memory", "space"])
def test_resource_waits_overlap_and_clear(tmp_path, monkeypatch, language, interactive, blocked_first, resumed_first):
    # Single-resource tests miss ordering-dependent labels, premature recovery,
    # and diagnostics left behind after recovery. Exercise both output modes.
    stream = io.StringIO()
    stream.terminal_columns = 200
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: interactive)
    reporter = RunReporter(language, stdout=stream, verbose=True)
    task = _task(tmp_path / "sample.7z")
    reporter.tasks_discovered(1, [task])
    reporter.task_progress(task, {"type": "progress", "completed_bytes": 25, "total_bytes": 100})

    def send(resource, action, **extra):
        reporter.task_progress(task, {"event": resource + "_" + action,
            "volume_key": "C:", "episode_id": 1, "job_id": "job", **extra})

    def latest():
        return reporter._format_task_row(reporter._task_rows[id(task)])

    send(blocked_first, "blocked")
    send("space" if blocked_first == "memory" else "memory", "blocked")
    combined = reporter.i18n.t("report.status.resources_paused")
    assert combined in latest() and combined in stream.getvalue()
    reporter.task_status(task, "extracting")
    assert combined in latest()
    send("space", "status", volume_query_ok=False, volume_query_error=21)
    unavailable = reporter.i18n.t("report.status.disk_unavailable", error="21")
    assert unavailable in latest()
    send("space", "status", volume_query_ok=True)
    assert unavailable not in latest()
    assert unavailable not in stream.getvalue().splitlines()[-1]

    send(resumed_first, "resumed")
    remaining = "disk" if resumed_first == "memory" else "memory"
    label = reporter.i18n.t("report.status." + remaining + "_paused")
    assert label in latest() and combined not in latest()
    assert label in stream.getvalue().splitlines()[-1]
    send("space" if resumed_first == "memory" else "memory", "resumed")
    restored = latest()
    assert reporter.i18n.t("report.status.extracting") in restored
    assert label not in restored and unavailable not in restored
    assert "25%" in restored
    assert reporter.i18n.t("report.status.extracting") in stream.getvalue().splitlines()[-1]


@pytest.mark.parametrize("interactive", [True, False])
@pytest.mark.parametrize("finish_while_pending", [False, True])
@pytest.mark.parametrize("cancel_drain", [False, True])
def test_resource_recovery_survives_report_lock_and_output_backpressure(tmp_path, monkeypatch, interactive, finish_while_pending, cancel_drain):
    # Unlike ordinary progress tests, park a real output writer holding the
    # report lock, send both recovery events, then send no further progress.
    # This detects lost transitions, loop deadlock and late terminal revival.
    import asyncio
    import threading
    from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker

    async def scenario():
        loop = asyncio.get_running_loop()
        held = asyncio.Event()
        release = threading.Event()

        class Output(io.StringIO):
            terminal_columns = 200
            parked = False

            def write(self, text):
                if self.parked:
                    self.parked = False
                    loop.call_soon_threadsafe(held.set)
                    assert release.wait(3), "resource progress blocked the event loop"
                return super().write(text)

        output = Output()
        broker = AsyncWorkBroker(thread_capacity=2)
        reporter = RunReporter("zh", stdout=output, work_broker=broker, request_id="test")
        task = _task(tmp_path / "sample.7z")
        reporter.tasks_discovered(1, [task])

        def send(resource, action):
            reporter.task_progress(task, {"event": resource + "_" + action,
                "volume_key": "C:", "episode_id": 1, "job_id": "job"})

        send("memory", "blocked")
        send("space", "blocked")
        await reporter.drain_progress()
        assert "等待内存/磁盘" in output.getvalue()
        output.parked = True

        def parked_report():
            with reporter._lock:
                reporter._print("other report")
                if finish_while_pending:
                    reporter.task_finished(task, _outcome(tmp_path / "sample"), 1)

        writer = asyncio.create_task(broker.run("report", "", parked_report))
        draining = None
        try:
            await held.wait()
            # Repeated transitions must coalesce rather than retain an event
            # history or create one waiting asyncio task per native event.
            for _ in range(100):
                send("memory", "blocked")
                send("space", "blocked")
                send("memory", "resumed")
                send("space", "resumed")
            assert len(reporter._pending_resource_progress) <= 2
            reporter.task_progress(task, {"type": "progress", "completed_bytes": 1, "total_bytes": 2})
            if cancel_drain:
                draining = asyncio.create_task(reporter.drain_progress())
                await asyncio.sleep(0)  # Enter the drain before cancelling its waiter.
                draining.cancel()
        finally:
            release.set()
            await writer
            try:
                if draining is not None:
                    with pytest.raises(asyncio.CancelledError):
                        await draining
                else:
                    await reporter.drain_progress()
            finally:
                await broker.close()
        row = reporter._task_rows[id(task)]
        if interactive and finish_while_pending:
            assert row["state"] == "complete"
        elif not finish_while_pending:
            assert row["state"] == "extracting"
            assert not row["space_blocked"] and not row["memory_blocked"]
            assert "正在解压" in output.getvalue().splitlines()[-1]
        assert reporter._pending_resource_progress == {}
        assert reporter._resource_progress_task is None

    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: interactive)
    asyncio.run(scenario())
