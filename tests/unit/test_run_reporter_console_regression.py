"""Console progress regressions from a real Windows user report.

These exercise the production RunReporter and output streams rather than
mocking the renderer. The pipeline integration test exercises the native worker.
"""
import io
import os
import re
import sys
from types import SimpleNamespace

import pytest

import sunpack.pipeline.coordinator.reporting as reporting
from sunpack.pipeline.coordinator.reporting import RunReporter
from sunpack.core.contracts.results import OutcomeKind


def _success(out_dir):
    return SimpleNamespace(
        outcome_kind=OutcomeKind.COMPLETE_SUCCESS,
        result=SimpleNamespace(success=True, out_dir=str(out_dir), error=""),
        verification=SimpleNamespace(decision_hint="accept"),
    )


def test_scope_tree_keeps_segments_and_recursive_output_with_bounded_terminal(tmp_path, monkeypatch):
    # One tree checks routing, stable grouping, no task retention, and viewport
    # bounds; former flat-row tests could not detect cross-segment updates.
    import weakref
    import gc
    from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
    from sunpack.core.contracts.input_plan import LogicalArchiveInput
    from sunpack.core.contracts.tasks import ArchiveTask
    from tests.helpers.archive_tasks import make_archive_task

    for interactive in (False, True):
        monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: interactive)
        stream = io.StringIO()
        stream.terminal_columns = 68
        reporter = RunReporter("zh", stdout=stream)
        nodes = tuple(LogicalArchiveInput(ArchiveInputDescriptor(
            str(tmp_path / "carrier.bin"), open_mode="file_range", format_hint="zip",
            parts=[ArchiveInputPart(InputExtent(str(tmp_path / "carrier.bin"), start, start + 40))],
        ), position=i) for i, start in enumerate((32, 128), 1))
        outer = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="embedded", logical_inputs=nodes)
        other = make_archive_task(tmp_path / "other.zip")
        reporter.tasks_discovered(1, [outer, other])
        reporter.task_started(outer)
        reporter.task_started(other)
        for node in nodes:
            child = ArchiveTask.from_archive_input(node.descriptor, discovery_source="embedded", logical_inputs=(node,))
            reporter.task_progress(child, {"type": "progress", "completed_bytes": node.position, "total_bytes": 10})
            assert reporter._task_rows[node.input_id]["progress"] == node.position / 10
            reporter.task_progress(child, {"type": "semantic", "event": "input_finished", "success": True,
                                           "out_dir": str(tmp_path / "out" / str(node.position))})
        reporter.task_finished(outer, _success(tmp_path / "out"), 1)
        nested = make_archive_task(tmp_path / "out" / "2" / "nested.zip")
        reporter.tasks_discovered(2, [nested])
        reporter.task_started(nested)
        reporter.task_finished(nested, _success(tmp_path / "out" / "2" / "nested"), 2)
        ref = weakref.ref(nested)
        del nested, child
        gc.collect()
        assert ref() is None
        if interactive:
            assert reporter._rendered_lines <= 28
            for line in stream.getvalue().splitlines():
                plain = re.sub(r"\033\[[0-9;]*[A-Za-z]", "", line).replace("\r", "")
                assert reporting._display_width(plain) < stream.terminal_columns
        else:
            assert stream.getvalue() == ""
        stream.seek(0); stream.truncate(0)
        reporter.pause_panel()
        paused = stream.getvalue()
        reporter.scope_finished(outer, 1)
        assert stream.getvalue() == paused and outer.key in reporter._task_rows
        reporter.resume_panel()
        text = stream.getvalue()
        assert text.index("段 1") < text.index("段 2") < text.index("nested.zip")
        assert "   └─ nested.zip" in text.splitlines()
        assert "│" in text and "└─" in text
        assert nodes[0].input_id not in reporter._input_rows
        assert outer.key not in reporter._task_rows
        if not interactive:
            assert "other.zip" not in text and "\033[" not in text
        reporter.task_finished(other, _success(tmp_path / "other"), 1)
        reporter.task_progress(other, {"event": "memory_blocked"})
        assert reporter._task_rows[other.key]["state"] == "complete"
        reporter.scope_finished(other, 1)
        assert not reporter._task_rows and not reporter._input_rows and not reporter._output_rows

        from dataclasses import replace
        from sunpack.core.contracts.failures import FailureInfo, FailureKind
        blocked_nodes = tuple(replace(node,
            descriptor=node.descriptor.with_path_mapping(lambda path: path.replace("carrier.bin", "blocked.bin")),
            input_id="", failure=FailureInfo(FailureKind.DAMAGED, "embedded", f"segment {node.position} damaged"),
        ) for node in nodes)
        blocked = ArchiveTask.from_archive_input(blocked_nodes[0].descriptor,
                    discovery_source="embedded", logical_inputs=blocked_nodes)
        reporter.tasks_discovered(1, [blocked])
        reporter.task_started(blocked)
        reporter.task_finished(blocked, SimpleNamespace(outcome_kind=OutcomeKind.FAILURE,
                               result=SimpleNamespace(error="blocked", out_dir="")), 1)
        stream.seek(0); stream.truncate(0)
        reporter.scope_finished(blocked, 1)
        assert "segment 1 damaged" in stream.getvalue() and "segment 2 damaged" in stream.getvalue()
        assert not reporter._task_rows


@pytest.mark.skipif(sys.platform != "win32", reason="requires real Windows console handles")
def test_windows_pipe_handle_is_not_mistaken_for_vt_console():
    reader, writer = os.pipe()
    try:
        class RedirectedOutput:
            def isatty(self):
                return True

            def fileno(self):
                return writer

        assert reporting._terminal_supports_updates(RedirectedOutput()) is False
    finally:
        os.close(reader)
        os.close(writer)
