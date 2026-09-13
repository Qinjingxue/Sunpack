from __future__ import annotations

from types import SimpleNamespace

from sunpack.coordinator.engine import _RequestRuntime
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner


class _Reporter:
    def __init__(self):
        self.events = []

    def task_progress(self, task, event):
        self.events.append((task, event))


def test_pipeline_progress_observer_receives_a_copy_and_cannot_fail_pipeline(tmp_path):
    task = object()
    event = {"type": "progress", "completed_bytes": 1, "total_bytes": 2}
    observed = []
    runtime = object.__new__(_RequestRuntime)
    runtime.reporter = _Reporter()

    def observer(current_task, payload):
        observed.append((current_task, payload))
        payload["completed_bytes"] = 99
        raise RuntimeError("observer failure")

    runtime.submission = SimpleNamespace(progress_callback=observer)
    runtime._report_progress(task, event)

    assert runtime.reporter.events == [(task, event)]
    assert observed[0][0] is task
    assert observed[0][1] is not event
    assert event["completed_bytes"] == 1


def test_extract_ready_semantic_event_uses_ordered_progress_sink(tmp_path):
    archive = tmp_path / "ready.zip"
    task = ArchiveTask(fact_bag=FactBag(), main_path=str(archive), all_parts=[str(archive)])
    events = []
    runner = SevenZipRunner({})
    runner.progress_callback = lambda current_task, event: events.append((current_task, event))

    runner.emit_semantic_event(
        task,
        "extract_ready",
        archive_path=str(archive),
        completed_bytes=0,
        total_bytes=0,
    )

    assert events == [(task, {
        "type": "semantic",
        "event": "extract_ready",
        "archive_path": str(archive),
        "completed_bytes": 0,
        "total_bytes": 0,
    })]
