import asyncio
import zipfile

from tests.helpers.archive_tasks import make_archive_task
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner
from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import worker_result_payload
from sunpack.core.support.resources import get_sevenzip_bridge_worker_path


def test_native_worker_progress_event_is_forwarded_to_task_callback(tmp_path):
    archive = tmp_path / "progress.zip"
    payload = b"sunpack-progress\n" * (1024 * 1024 // 17)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as handle:
        handle.writestr("payload.bin", payload)

    task = make_archive_task(archive, format_hint="zip")
    events = []
    runner = SevenZipRunner({})
    runner.worker_path = get_sevenzip_bridge_worker_path()
    runner.progress_callback = lambda current_task, event: events.append((current_task, event))

    job = runner._build_job(
        archive_path=str(archive),
        out_dir=str(tmp_path / "out"),
        password=None,
        password_candidates=None,
        selected_codepage=None,
        task=task,
    )

    async def run():
        try:
            return await asyncio.wait_for(runner.submit_attempt_asyncio(job, task=task), 15)
        finally:
            await runner.aclose()

    completed = asyncio.run(run())

    assert completed.returncode == 0, completed.stderr
    assert worker_result_payload(completed)["status"] == "ok"
    progress_events = completed.worker_diagnostics["progress_events"]
    assert progress_events
    started = [event for event in progress_events if event.get("event") == "extract_started"]
    assert len(started) == 1
    assert int(started[0].get("completed_bytes") or 0) > 0
    assert events == [(task, event) for event in progress_events]


def test_progress_tail_preserves_all_callbacks_and_total_count():
    # The short real-worker case cannot detect dropped callbacks or a count
    # incorrectly derived from a truncated tail. Exercise actual async delivery.
    count = 512
    class Worker:
        worker_epoch = "history-test"
        worker_path = "test.exe"
        def take_stderr(self): return []
        def is_alive(self): return True
        async def submit(self, _payload, job_id, *, on_event, **_kwargs):
            for index in range(count):
                on_event({"type": "progress", "job_id": job_id,
                             "event": "item_done", "item_index": index})
            on_event({"type": "result", "job_id": job_id, "status": "ok"})
            on_event({"type": "native_event", "job_id": job_id, "event": "job_finished"})
    class Holder:
        async def get_or_start(self): return Worker()
    runner = SevenZipRunner({}, shared_async_worker_holder=Holder())
    indices = []
    runner.progress_callback = lambda _task, event: indices.append(event["item_index"])
    completed = asyncio.run(runner.submit_attempt_asyncio({"job_id": "history"}))
    diagnostics = completed.worker_diagnostics
    assert completed.returncode == 0
    assert indices == list(range(count))
    assert diagnostics["progress_event_count"] == count
    assert len(diagnostics["progress_events"]) < count
    assert diagnostics["last_progress_event"]["item_index"] == count - 1
