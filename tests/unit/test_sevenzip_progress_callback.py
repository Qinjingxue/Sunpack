import zipfile

from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner
from sunpack.extraction.internal.sevenzip.worker_diagnostics import worker_result_payload
from sunpack.support.resources import get_7z_dll_path, get_sevenzip_bridge_worker_path


def test_native_worker_progress_event_is_forwarded_to_task_callback(tmp_path):
    archive = tmp_path / "progress.zip"
    payload = b"sunpack-progress\n" * (1024 * 1024 // 17)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as handle:
        handle.writestr("payload.bin", payload)

    task = ArchiveTask(fact_bag=FactBag(), main_path=str(archive), all_parts=[str(archive)])
    events = []
    runner = SevenZipRunner({})
    runner.worker_path = get_sevenzip_bridge_worker_path()
    runner.seven_zip_dll_path = get_7z_dll_path()
    runner.progress_callback = lambda current_task, event: events.append((current_task, event))

    try:
        completed = runner.submit_attempt(
            archive_path=str(archive),
            part_paths=[str(archive)],
            out_dir=str(tmp_path / "out"),
            password=None,
            selected_codepage=None,
            decoded_names=[],
            startupinfo=None,
            task=task,
        ).result(timeout=15)
    finally:
        runner.close()

    assert completed.returncode == 0, completed.stderr
    assert worker_result_payload(completed)["status"] == "ok"
    progress_events = completed.worker_diagnostics["progress_events"]
    assert progress_events
    assert events == [(task, event) for event in progress_events]
