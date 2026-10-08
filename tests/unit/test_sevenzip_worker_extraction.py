import asyncio
import binascii
import json
import os
import subprocess
import struct
import tarfile
import zipfile

import pytest

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.failures import FailureKind
from tests.helpers.archive_tasks import make_archive_task, make_task_from_descriptor
from tests.helpers.worker_events import worker_trace_item
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import (
    SevenZipRunner,
    _NativeWorkerProcess,
    _apply_native_environment,
)
from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import worker_result_payload
from sunpack.pipeline.extraction.scheduler import ExtractionScheduler
from sunpack.core.support.resources import get_sevenzip_bridge_worker_path
from tests.helpers.tool_config import get_test_tools


def _invoke_worker(worker, request, *, env=None, timeout=10):
    return subprocess.run([worker], input=json.dumps(request, ensure_ascii=False),
                          capture_output=True, text=True, encoding="utf-8", env=env, timeout=timeout)


def _require_worker_or_skip():
    try:
        return get_sevenzip_bridge_worker_path()
    except Exception as exc:
        pytest.skip(f"sunpack_sevenzip_worker.exe is required: {exc}")


def _require_7z_or_skip():
    seven_zip = get_test_tools()["seven_zip"]
    if not seven_zip or not seven_zip.is_file():
        pytest.skip("7z.exe is required to build worker extraction fixtures")
    _require_worker_or_skip()
    return seven_zip


def test_worker_duplicate_invalid_names_report_failure_without_spinning(tmp_path):
    worker = _require_worker_or_skip()
    archive = tmp_path / "duplicate-invalid.zip"
    literal = str(archive).replace("'", "''")
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.IO.Compression; "
         f"$f=[IO.File]::Open('{literal}',[IO.FileMode]::Create); "
         "$z=[IO.Compression.ZipArchive]::new($f,[IO.Compression.ZipArchiveMode]::Create); "
         "1..1000 | ForEach-Object { [void]$z.CreateEntry(('entry'+$_+'.txt')) }; "
         "$n=('a'*260)+'.txt'; 1..12 | ForEach-Object { [void]$z.CreateEntry($n) }; "
         "$z.Dispose(); $f.Dispose()"],
        check=True, capture_output=True,
    )
    for attempt in range(3):
        result = subprocess.run(
            [worker], input=json.dumps({"job_id": "invalid-name-regression", "archive_path": str(archive),
                                       "output_dir": str(tmp_path / f"out-{attempt}"), "format_hint": "zip"}),
            capture_output=True, text=True, encoding="utf-8", timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        final = _worker_result(result.stdout)
        assert result.returncode != 0
        assert final["status"] == "failed"
        assert final["failure_kind"] == "output_filesystem"


def _create_7z(tmp_path, name: str, text: str):
    seven_zip = _require_7z_or_skip()
    source = tmp_path / f"{name}.txt"
    source.write_text(text, encoding="utf-8")
    archive = tmp_path / f"{name}.7z"
    result = subprocess.run(
        [str(seven_zip), "a", str(archive), str(source), "-mx=0", "-y"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"7z failed:\n{result.stdout}\n{result.stderr}")
    return archive, source.name


def _create_7z_with_nested_file(tmp_path):
    seven_zip = _require_7z_or_skip()
    nested_dir = tmp_path / "conflict"
    nested_dir.mkdir()
    child = nested_dir / "child.txt"
    child.write_text("nested payload", encoding="utf-8")
    archive = tmp_path / "nested.7z"
    result = subprocess.run(
        [str(seven_zip), "a", str(archive), "conflict\\child.txt", "-mx=0", "-y"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"7z failed:\n{result.stdout}\n{result.stderr}")
    return archive


def _create_encrypted_zip(tmp_path, password: str = "secret"):
    seven_zip = _require_7z_or_skip()
    source = tmp_path / "encrypted-source.txt"
    source.write_text("encrypted worker payload", encoding="utf-8")
    archive = tmp_path / "encrypted.zip"
    result = subprocess.run(
        [
            str(seven_zip),
            "a",
            str(archive),
            str(source),
            "-tzip",
            "-mx=0",
            "-y",
            f"-p{password}",
        ],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"7z failed:\n{result.stdout}\n{result.stderr}")
    return archive, source.name


def _create_shift_jis_zip(tmp_path):
    archive = tmp_path / "shift-jis.zip"
    expected_name = "日本語/説明.txt"
    raw_name = expected_name.encode("cp932")
    payload = b"shift-jis payload"
    crc = binascii.crc32(payload) & 0xFFFFFFFF
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50, 20, 0, 0, 0, 0, crc,
        len(payload), len(payload), len(raw_name), 0,
    ) + raw_name + payload
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50, 20, 20, 0, 0, 0, 0, crc,
        len(payload), len(payload), len(raw_name),
        0, 0, 0, 0, 0, 0,
    ) + raw_name
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50, 0, 0, 1, 1, len(central), len(local), 0,
    )
    archive.write_bytes(local + central + eocd)
    return archive, expected_name, payload


def test_worker_does_not_classify_unencrypted_open_failure_as_wrong_password(tmp_path):
    worker = _require_worker_or_skip()
    archive = tmp_path / "malformed.7z"
    archive.write_bytes(b"7z\xbc\xaf'\x1c" + b"\x00" * 26)
    payload = {
        "job_id": "unencrypted-open-failure",
        "archive_path": str(archive),
        "output_dir": str(tmp_path / "out"),
        "password": "irrelevant",
    }

    result = _invoke_worker(worker, payload)
    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip().startswith("{")]
    worker_result = next(item for item in lines if item.get("type") == "result")

    assert result.returncode != 0
    assert worker_result["wrong_password"] is False
    assert worker_result["encrypted"] is False
    assert worker_result["failure_kind"] != "encrypted_or_wrong_password"


def test_native_worker_result_escapes_control_characters(tmp_path):
    worker_path = _require_worker_or_skip()
    archive = tmp_path / "control-name.zip"
    # Control characters are mapped to '_' on disk, so an over-long component
    # forces the item to fail while its raw name still reaches the result.
    failed_name = "control-\x01-name" + "x" * 300 + ".txt"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(failed_name, "unsafe filename payload")
    payload = {
        "job_id": "control-name",
        "archive_path": str(archive),
        "output_dir": str(tmp_path / "out"),
    }
    runner = SevenZipRunner({"watchdog_no_progress_timeout_seconds": 2})
    runner.worker_path = worker_path
    try:
        completed = runner.submit_attempt(
            payload,
            startupinfo=None,
            task=_task(archive),
        ).result(timeout=10)
    finally:
        runner.close()

    worker_result = worker_result_payload(completed)
    assert completed.returncode != 0
    assert "timed out" not in completed.stderr.lower()
    assert worker_result["job_id"] == "control-name"
    assert worker_result["failed_item"] == failed_name
    assert worker_result["diagnostics"]["failed_item"]["path"] == failed_name


def test_native_worker_asyncio_event_controller_completes_job(tmp_path):
    worker_path = _require_worker_or_skip()
    archive = tmp_path / "async.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("async.txt", "async payload")
    out_dir = tmp_path / "async-out"
    payload = {
        "job_id": "async-event-controller",
        "archive_path": str(archive),
        "output_dir": str(out_dir),
    }

    async def run_attempt():
        runner = SevenZipRunner(
            {
                "watchdog_no_progress_timeout_seconds": 2,
                "cancel_grace_seconds": 0.5,
            }
        )
        runner.worker_path = worker_path
        try:
            return await asyncio.wait_for(
                runner.submit_attempt_asyncio(payload, task=_task(archive)),
                timeout=10,
            )
        finally:
            await runner.aclose()

    completed = asyncio.run(run_attempt())

    assert completed.returncode == 0
    assert (out_dir / "async.txt").read_text(encoding="utf-8") == "async payload"


def test_native_worker_asyncio_process_exit_completes_pending_job(tmp_path):
    worker = tmp_path / "exit_worker.cmd"
    worker.write_text(
        '@echo {"type":"worker_ready"}\r\n@set /p request=\r\n@exit /b 7\r\n',
        encoding="utf-8",
    )
    runner = SevenZipRunner({})
    runner.worker_path = str(worker)

    async def run_attempt():
        try:
            return await asyncio.wait_for(
                runner.submit_attempt_asyncio(
                    {"job_id": "async-process-exit"},
                    task=_task(worker),
                ),
                timeout=3,
            )
        finally:
            await runner.aclose()

    completed = asyncio.run(run_attempt())

    assert completed.returncode == -101
    assert completed.worker_diagnostics["process_failure"]["failure_kind"] == "worker_lost"


def test_native_worker_asyncio_no_progress_cancels_without_polling(tmp_path):
    worker = tmp_path / "stalled_worker.cmd"
    worker.write_text(
        '@echo {"type":"worker_ready"}\r\n'
        "@set /p request=\r\n"
        "@set /p cancellation=\r\n"
        "@set /p shutdown=\r\n",
        encoding="utf-8",
    )
    runner = SevenZipRunner(
        {
            "watchdog_no_progress_timeout_seconds": 0.05,
            "cancel_grace_seconds": 0.5,
        }
    )
    runner.worker_path = str(worker)

    async def run_attempt():
        try:
            return await asyncio.wait_for(
                runner.submit_attempt_asyncio(
                    {"job_id": "async-deadline"},
                    task=_task(worker),
                ),
                timeout=2,
            )
        finally:
            await runner.aclose()

    completed = asyncio.run(run_attempt())

    assert completed.returncode == -101
    assert completed.worker_diagnostics["process_failure"]["failure_kind"] == "timeout"
    assert "no observable progress" in completed.stderr


@pytest.mark.parametrize("completion", ["job_finished", "worker_exit", "grace_expired"])
def test_cancelled_request_retains_input_lease_until_native_work_stops(tmp_path, completion):
    from sunpack.pipeline.coordinator.engine import PipelineEngine

    worker = tmp_path / "cancel_worker.cmd"
    ending = (
        '@echo {"type":"result","job_id":"cancel-job","status":"failed"}\r\n'
        '@echo {"type":"native_event","event":"job_finished","job_id":"cancel-job"}\r\n'
        '@set /p shutdown=\r\n'
        if completion == "job_finished"
        else '@set /p ignored=\r\n' if completion == "grace_expired"
        else '@exit /b 7\r\n'
    )
    worker.write_text(
        '@echo {"type":"worker_ready"}\r\n'
        '@set /p request=\r\n'
        '@echo {"type":"native_event","event":"job_started","job_id":"cancel-job"}\r\n'
        '@set /p cancellation=\r\n'
        '@echo {"type":"cancel_ack","job_id":"cancel-job"}\r\n'
        '@echo {"type":"native_event","event":"job_cancelling","job_id":"cancel-job"}\r\n'
        '@set /p finish=\r\n' + ending,
        encoding="utf-8",
    )

    async def scenario():
        runner = SevenZipRunner({"cancel_grace_seconds": 0.5 if completion == "grace_expired" else 5})
        runner.worker_path = str(worker)
        started, cancelling = asyncio.Event(), asyncio.Event()

        def event(_task, value):
            if value.get("event") == "job_started":
                started.set()
            elif value.get("event") == "job_cancelling":
                cancelling.set()

        runner.native_event_callback = event

        class Runtime:
            def __init__(self, services, submission, options, leases):
                self.submission, self.leases = submission, leases

            async def execute_async(self, broker, cancellation):
                await self.leases.acquire(self.submission.request_id, [str(worker)])
                await runner.submit_attempt_asyncio({"job_id": "cancel-job"}, task=_task(worker))
                raise AssertionError("the request must remain cancelled")

        async with PipelineEngine({}) as engine:
            engine._request_runtime_factory = Runtime
            request = asyncio.create_task(engine.run([str(worker)]))
            waiting = None
            try:
                await asyncio.wait_for(started.wait(), 2)
                request.cancel()
                await asyncio.wait_for(cancelling.wait(), 2)
                request.cancel()
                waiting = asyncio.create_task(engine._path_leases.acquire("second", [str(worker)]))
                await asyncio.sleep(0)
                assert not request.done()
                assert not waiting.done()
                assert not engine.is_idle()
                if completion != "grace_expired":
                    native = await runner._async_worker_holder_or_create().get_or_start(None)
                    await native.send('{"worker_command":"finish"}')
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(request, 2)
                await asyncio.wait_for(waiting, 2)
                assert engine.is_idle()
            finally:
                await runner.aclose()
                await asyncio.gather(request, return_exceptions=True)
                if waiting is not None:
                    waiting.cancel()
                    await asyncio.gather(waiting, return_exceptions=True)
                await engine._path_leases.release("second")

    asyncio.run(scenario())


@pytest.mark.parametrize("layout", ["plain", "carrier", "split"])
def test_worker_header_encrypted_7z_tries_candidates_with_disguised_names(tmp_path, layout):
    seven_zip = _require_7z_or_skip()
    worker = _require_worker_or_skip()
    source = tmp_path / "payload.txt"
    source.write_text("encrypted payload", encoding="utf-8")
    archive = tmp_path / "encrypted.7z"
    subprocess.run(
        [str(seven_zip), "a", str(archive), str(source), "-psecret", "-mhe=on", "-mx=0", "-y"],
        check=True, capture_output=True,
    )
    data = archive.read_bytes()
    disguised = tmp_path / "input.blob"
    descriptor = {"entry_path": str(disguised), "format_hint": "7z", "open_mode": "file"}
    if layout == "plain":
        disguised.write_bytes(data)
    elif layout == "carrier":
        prefix = b"carrier prefix"
        disguised.write_bytes(prefix + data + b"carrier suffix")
        descriptor.update(open_mode="file_range", parts=[{
            "path": str(disguised), "start": len(prefix), "end": len(prefix) + len(data),
        }])
    else:
        second = tmp_path / "part.disguised"
        midpoint = len(data) // 2
        disguised.write_bytes(data[:midpoint])
        second.write_bytes(data[midpoint:])
        descriptor.update(open_mode="concat_ranges", ranges=[
            {"path": str(disguised), "start": 0}, {"path": str(second), "start": 0},
        ])
    out = tmp_path / "out"
    result = _invoke_worker(worker, {
            "job_id": "header-passwords", "archive_path": str(disguised),
            "output_dir": str(out), "format_hint": "7z", "archive_input": descriptor,
            "password_candidates": ["wrong", "secret"],
        }, timeout=10)
    final = _worker_result(result.stdout)
    assert result.returncode == 0, result.stdout + result.stderr
    assert final["status"] == "ok"
    assert final["matched_index"] == 1
    assert final["password_attempts"] == 2
    assert (out / source.name).read_text(encoding="utf-8") == "encrypted payload"


def test_native_worker_starts_in_neutral_working_directory(tmp_path, monkeypatch):
    captured = {}

    class StartObserved(RuntimeError):
        pass

    def fake_popen(*args, **kwargs):
        captured.update(kwargs)
        raise StartObserved

    monkeypatch.setattr(
        "sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner.runtime_working_directory",
        lambda: str(tmp_path),
    )
    monkeypatch.setattr("sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner.subprocess.Popen", fake_popen)

    with pytest.raises(StartObserved):
        _NativeWorkerProcess("worker.exe", None)

    assert captured["cwd"] == str(tmp_path)


def test_native_environment_zero_thread_capacity_uses_native_auto_capacity():
    environment = {"SUNPACK_NATIVE_WORKER_THREAD_CAPACITY": "8"}

    _apply_native_environment(
        environment,
        {
            "thread_capacity": 0,
        },
    )

    assert "SUNPACK_NATIVE_WORKER_THREAD_CAPACITY" not in environment


def test_native_environment_configures_memory_guard():
    environment = {}
    _apply_native_environment(
        environment,
        {
            "minimum_available_memory_ratio": 0.10,
        },
    )

    assert environment["SUNPACK_NATIVE_MIN_AVAILABLE_MEMORY_RATIO"] == "0.1"


def test_native_environment_does_not_freeze_worker_process_mode_at_startup():
    environment = {"SUNPACK_NATIVE_PROCESS_MODE": "background"}

    _apply_native_environment(environment, {"windows_process_mode": "background"})

    assert "SUNPACK_NATIVE_PROCESS_MODE" not in environment

    _apply_native_environment(environment, {})

    assert "SUNPACK_NATIVE_PROCESS_MODE" not in environment


def test_native_worker_reports_cpu_credit_sizing_plan():
    worker_path = _require_worker_or_skip()
    environment = os.environ.copy()
    for key in (
        "SUNPACK_NATIVE_WORKER_THREAD_CAPACITY",
        "SUNPACK_NATIVE_PROCESS_MODE",
        "SUNPACK_NATIVE_WORKER_PROFILE",
    ):
        environment.pop(key, None)
    completed = subprocess.run(
        [worker_path],
        input='{"worker_command":"shutdown","job_id":"shutdown"}\n',
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        timeout=10,
        check=True,
    )
    handshake = json.loads(completed.stdout.splitlines()[0])

    logical_processors = max(1, int(handshake["logical_processors"]))
    assert handshake["type"] == "worker_ready"
    assert handshake["sizing_mode"] == "dynamic"
    assert int(handshake["thread_capacity"]) == logical_processors
    assert int(handshake["nominal_cpu_budget"]) == logical_processors
    assert int(handshake["memory_poll_interval_ms"]) == 1000
    assert float(handshake["minimum_available_memory_ratio"]) == 0.1


def test_worker_event_rejects_non_objects_and_malformed_rows():
    from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import parse_worker_json_line

    assert parse_worker_json_line(json.dumps({
        "type": "result", "verified_manifest": {"rows": [[0, "a.txt", "", 3, 3, 1, 7, 1, 7, 1, 1, 1, 123, "616263"]]},
    })) == {}
    assert parse_worker_json_line(json.dumps({
        "type": "result", "diagnostics": {"output_trace": {"items": [{"path": "a.txt"}]}},
    })) == {}
    assert parse_worker_json_line("not json") == {}
    assert parse_worker_json_line("[1, 2]") == {}
    assert parse_worker_json_line('{"type":"progress"} trailing') == {}
    assert parse_worker_json_line(
        '{"type":"result","verified_manifest":{"inventory":[1,1,0,3,1],"rows":[[0,"a.txt"]]}}'
    ) == {}
    assert parse_worker_json_line('{"type":"progress","completed_bytes":5}') == {
        "type": "progress", "completed_bytes": 5,
    }


def test_preparsed_worker_result_avoids_stdout_reparse_and_bounds_tail():
    from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import (
        build_worker_diagnostics,
        native_worker_manifest,
        parse_worker_json_line,
    )

    result_payload = parse_worker_json_line(json.dumps({
        "type": "result",
        "status": "ok",
        "verified_manifest": {
            "validated": True,
            "rows": [[0, "source.txt", "output.txt", 3, 3, 1, 7, 1, 7, 1, 1, 1, 123, "616263"]],
            "inventory": [1, 1, 0, 3, 0],
        },
    }))
    diagnostics = build_worker_diagnostics(
        stdout="x" * 100_000,
        stderr="",
        returncode=0,
        result_payload=result_payload,
    )

    assert diagnostics["result"] is result_payload
    assert "rows" not in result_payload["verified_manifest"]
    assert "files" not in result_payload["verified_manifest"]
    files = native_worker_manifest(result_payload).file_page(0, 10)
    assert files[0]["path"] == "source.txt"
    assert files[0]["output_path"] == "output.txt"
    assert sum(len(line) for line in diagnostics["process"]["stdout_tail"]) <= 4000


def test_complete_worker_inventory_drops_transient_native_rows_and_output_trace():
    from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import (
        build_worker_diagnostics,
        compact_success_worker_diagnostics,
        parse_worker_json_line,
    )

    result = parse_worker_json_line(json.dumps({
        "status": "ok",
        "verified_manifest": {
            "validated": True,
            "inventory": [1, 1, 0, 3, 1],
            "rows": [[0, "a.txt", "", 3, 3, 1, 7, 1, 7, 1, 1, 1, 123, "616263"]],
        },
        "diagnostics": {
            "output_trace": {
                "items": [worker_trace_item(path="a.txt")],
                "files_written": 1,
            }
        },
    }))
    diagnostics = build_worker_diagnostics(stdout="", stderr="", returncode=0, result_payload=result)
    assert "native_items" in result["diagnostics"]["output_trace"]

    compact_success_worker_diagnostics(diagnostics)

    assert "native_items" not in result["diagnostics"]["output_trace"]
    assert "native_rows" not in result["verified_manifest"]


def test_worker_output_trace_includes_per_item_failure(tmp_path):
    worker = _require_worker_or_skip()
    archive = _create_7z_with_nested_file(tmp_path)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "conflict").write_text("blocks directory creation", encoding="utf-8")
    payload = {
        "job_id": "output-trace",
        "archive_path": str(archive),
        "output_dir": str(out_dir),
    }

    result = _invoke_worker(worker, payload)
    worker_result = _worker_result(result.stdout)
    native = worker_result["diagnostics"]["output_trace"]["native_items"]
    output_items = native.item_page(0, len(native))
    failed_items = [item for item in output_items if item["failed"]]

    assert result.returncode != 0
    assert worker_result["failure_stage"] == "output_write"
    assert failed_items
    assert failed_items[-1]["bytes_written"] == 0
    assert "conflict" in failed_items[-1]["path"].replace("\\", "/")


def test_worker_propagates_delayed_async_file_open_failure(tmp_path):
    worker = _require_worker_or_skip()
    archive = tmp_path / "async-open-failure.zip"
    # A component longer than NTFS allows passes archive path validation (even
    # through the extended-length prefix), but CreateFileW rejects it. The async writer must
    # report that delayed failure after draining instead of publishing a
    # successful extraction.
    invalid_name = "x" * 300 + ".txt"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(invalid_name, "payload")
    out_dir = tmp_path / "out"
    payload = {
        "job_id": "async-open-failure",
        "archive_path": str(archive),
        "output_dir": str(out_dir),
        "format_hint": "zip",
    }

    result = _invoke_worker(worker, payload)
    worker_result = _worker_result(result.stdout)
    native = worker_result["diagnostics"]["output_trace"]["native_items"]
    output_items = native.item_page(0, len(native))

    assert result.returncode != 0
    assert worker_result["status"] == "failed"
    assert worker_result["failure_stage"] == "output_write"
    assert worker_result["failure_kind"] == "output_filesystem"
    assert worker_result["files_written"] == 0
    assert worker_result["failed_item"] == invalid_name
    assert worker_result["diagnostics"]["failed_item"]["path"] == invalid_name
    assert output_items[-1]["failed"] is True
    assert output_items[-1]["bytes_written"] == 0
    assert not any(out_dir.glob("*.txt"))


def test_worker_dry_run_reports_success_diagnostics_without_writing(tmp_path):
    worker = _require_worker_or_skip()
    archive, filename = _create_7z(tmp_path, "dryrun", "dry-run payload")
    dry_output = tmp_path / "dry_output"
    payload = {
        "job_id": "dry-run",
        "archive_path": str(archive),
        "output_dir": str(dry_output),
        "format_hint": "7z",
        "dry_run": True,
    }

    result = _invoke_worker(worker, payload)
    worker_result = _worker_result(result.stdout)
    output_trace = worker_result["diagnostics"]["output_trace"]

    assert result.returncode == 0
    assert worker_result["status"] == "ok"
    assert worker_result["dry_run"] is True
    assert worker_result["files_written"] == 1
    assert worker_result["bytes_written"] == len("dry-run payload")
    assert len(output_trace["native_items"]) == 1
    item = output_trace["native_items"].item_page(0, 1)[0]
    assert item["path"].endswith(filename)
    assert item["has_source_crc32"] is True
    assert item["has_output_crc32"] is True
    assert item["output_crc32"] == item["source_crc32"]
    assert item["crc_verified"] is True
    assert not dry_output.exists()


@pytest.mark.parametrize("dry_run", [False, True])
def test_worker_skips_output_crc_when_source_crc_is_missing(tmp_path, dry_run):
    worker = _require_worker_or_skip()
    payload = b"tar payload without an archive CRC"
    source = tmp_path / "payload.bin"
    source.write_bytes(payload)
    archive = tmp_path / "payload.tar"
    with tarfile.open(archive, "w") as handle:
        handle.add(source, arcname=source.name)
    output_dir = tmp_path / ("dry-output" if dry_run else "out")
    result = _invoke_worker(worker, {
            "job_id": f"{'dry-run' if dry_run else 'extract'}-no-source-crc",
            "archive_path": str(archive),
            "output_dir": str(output_dir),
            "format_hint": "tar",
            "dry_run": dry_run,
        })
    worker_result = _worker_result(result.stdout)

    assert result.returncode == 0, result.stdout + result.stderr
    assert worker_result["status"] == "ok"
    assert worker_result["dry_run"] is dry_run
    if dry_run:
        item = next(
            row for row in worker_result["diagnostics"]["output_trace"]["native_items"].item_page(0, 128)
            if not row["is_dir"]
        )
        assert item["has_source_crc32"] is False
        assert item["has_output_crc32"] is False
        assert item["crc_verified"] is True
        assert not output_dir.exists()
    else:
        # Successful real extraction intentionally omits verbose diagnostics.
        # The dry-run branch above verifies the no-output-CRC trace contract;
        # this branch verifies that the same path still writes correct bytes.
        assert "diagnostics" not in worker_result
        assert (output_dir / source.name).read_bytes() == payload
        row = worker_result["verified_manifest"]["native_rows"].file_page(0, 1)[0]
        assert row["mtime_ns"] > 0 and row["magic"] == payload


def test_runner_serializes_only_codepage_for_filename_override(tmp_path):
    archive = tmp_path / "legacy.zip"
    archive.write_bytes(b"PK")
    task = make_archive_task(archive, format_hint="zip")
    runner = SevenZipRunner({})

    job = runner._build_job(
        archive_path=str(archive),
        part_paths=[str(archive)],
        out_dir=str(tmp_path / "out"),
        password=None,
        password_candidates=None,
        selected_codepage="932",
        task=task,
    )

    assert job["codepage"] == "932"
    assert "decoded_names" not in job


def test_worker_applies_explicit_shift_jis_item_paths(tmp_path):
    worker = _require_worker_or_skip()
    archive, expected_name, payload_bytes = _create_shift_jis_zip(tmp_path)
    out_dir = tmp_path / "out"
    payload = {
        "job_id": "shift-jis",
        "archive_path": str(archive),
        "output_dir": str(out_dir),
        "format_hint": "zip",
        "codepage": "932",
    }

    result = _invoke_worker(worker, payload)
    worker_result = _worker_result(result.stdout)

    assert result.returncode == 0, result.stdout + result.stderr
    assert worker_result["requested_codepage"] == "932"
    assert worker_result["applied_codepage"] == "932"
    assert worker_result["filename_decoder"] == "sevenzip_zip_codepage"
    assert (out_dir / "日本語" / "説明.txt").read_bytes() == payload_bytes


def test_native_worker_queue_isolates_failed_job_and_continues(tmp_path):
    worker = _require_worker_or_skip()
    archive = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("ok.txt", "batch payload")
    runner = SevenZipRunner({"thread_capacity": 2})
    runner.worker_path = worker
    try:
        bad = runner.submit_attempt(
            {
                "job_id": "bad",
                "archive_path": str(tmp_path / "missing.zip"),
                "part_paths": [str(tmp_path / "missing.zip")],
                "output_dir": str(tmp_path / "bad"),
            },
            task=_task(tmp_path / "missing.zip"),
        ).result(timeout=10)
        good = runner.submit_attempt(
            {
                "job_id": "ok",
                "archive_path": str(archive),
                "part_paths": [str(archive)],
                "output_dir": str(tmp_path / "ok"),
            },
            task=_task(archive),
        ).result(timeout=10)
    finally:
        runner.close()

    assert worker_result_payload(bad)["status"] == "failed"
    assert worker_result_payload(good)["status"] == "ok"
    assert (tmp_path / "ok" / "ok.txt").read_text(encoding="utf-8") == "batch payload"


def test_extraction_scheduler_saves_process_failure_diagnostics(tmp_path):
    archive = tmp_path / "sample.bin"
    archive.write_bytes(b"not an archive")
    scheduler = ExtractionScheduler(max_retries=1)
    scheduler.sevenzip_runner.worker_path = str(tmp_path / "missing_worker.exe")

    try:
        result = scheduler.extract(_task(archive), str(tmp_path / "out"))
    finally:
        scheduler.close()

    assert result.success is False
    assert result.diagnostics["process_failure"]["failure_stage"] == "worker_start"
    assert result.diagnostics["process_failure"]["failure_kind"] == "process_start"
    assert result.diagnostics["repro"]["request"]["archive_path"] == str(archive)


def test_extraction_scheduler_classifies_malformed_worker_output_as_process_exit(tmp_path):
    worker = tmp_path / "malformed_worker.cmd"
    worker.write_text("@echo not-json\r\n@exit /b 2\r\n", encoding="utf-8")
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"not used")
    scheduler = ExtractionScheduler(max_retries=1)
    scheduler.sevenzip_runner.worker_path = str(worker)

    try:
        result = scheduler.extract(_task(archive), str(tmp_path / "out"))
    finally:
        scheduler.close()

    assert result.success is False
    assert result.diagnostics["failure_stage"] == "worker_communication"
    assert result.diagnostics["failure_kind"] == "worker_lost"
    assert result.diagnostics["process_failure"]["message"]


def test_sevenzip_runner_observed_no_progress_reports_process_timeout(tmp_path):
    worker = tmp_path / "sleep_worker.cmd"
    worker.write_text("@ping 127.0.0.1 -n 3 >nul\r\n", encoding="utf-8")
    scheduler = ExtractionScheduler(
        max_retries=1,
        process_config={
            "watchdog_no_progress_timeout_seconds": 0.1,
            "cancel_grace_seconds": 0.5,
        },
    )
    scheduler.sevenzip_runner.worker_path = str(worker)
    try:
        result = scheduler.extract(_task(worker), str(tmp_path / "out"))
    finally:
        scheduler.close()

    assert result.success is False
    assert result.diagnostics["process_failure"]["failure_kind"] == "timeout"


def _task(path, archive_input=None):
    if archive_input:
        descriptor = ArchiveInputDescriptor.from_any(
            archive_input,
            archive_path=str(path),
        )
        return make_task_from_descriptor(descriptor, key=str(path))
    return make_archive_task(path, key=str(path))


def _worker_result(stdout: str) -> dict:
    from sunpack_native import NativeWorkerResultAccumulator, parse_worker_transport_event

    accumulators = {}
    for line in stdout.splitlines():
        if not line.strip():
            continue
        payload = parse_worker_transport_event(line)
        job_id = payload.get("job_id")
        if payload["type"] not in {"manifest_chunk", "trace_chunk", "result"}:
            continue
        accumulator = accumulators.setdefault(job_id, NativeWorkerResultAccumulator(job_id))
        accumulator.accept(payload)
        if payload["type"] == "result":
            return payload
    raise AssertionError("worker did not emit a result")


def test_extraction_scheduler_uses_worker_for_file_range(tmp_path, monkeypatch):
    monkeypatch.setenv("SUNPACK_SEVENZIP_PROFILE_READS", "1")
    archive, filename = _create_7z(tmp_path, "payload", "range payload")
    data = archive.read_bytes()
    prefix = b"SHELLDATA"
    mixed = tmp_path / "mixed.bin"
    mixed.write_bytes(prefix + data + b"TAIL")

    task = _task(mixed, {
        "kind": "archive_input",
        "entry_path": str(mixed),
        "open_mode": "file_range",
        "format_hint": "7z",
        "parts": [{
            "path": str(mixed),
            "role": "main",
            "start": len(prefix),
            "end": len(prefix) + len(data),
        }],
    })
    result = ExtractionScheduler(max_retries=1).extract(task, str(tmp_path / "out"))

    assert result.success is True
    assert (tmp_path / "out" / filename).read_text(encoding="utf-8") == "range payload"
    assert result.diagnostics["result"]["input_trace"]["prefetch_enabled"] is True


def test_confirmed_truncated_file_range_open_failure_is_damaged(tmp_path):
    _require_worker_or_skip()
    archive, _ = _create_7z(tmp_path, "truncated-range", "payload")
    data = archive.read_bytes()
    prefix = b"SFX-STUB"
    truncated = tmp_path / "truncated.exe"
    truncated.write_bytes(prefix + data[:-1])

    task = _task(truncated, {
        "kind": "archive_input",
        "entry_path": str(truncated),
        "open_mode": "file_range",
        "format_hint": "7z",
        "parts": [{
            "path": str(truncated),
            "role": "main",
            "start": len(prefix),
            "end": len(prefix) + len(data),
        }],
    })
    result = ExtractionScheduler(max_retries=1).extract(task, str(tmp_path / "out"))

    assert result.success is False
    assert result.failure.kind is FailureKind.DAMAGED
    worker = result.diagnostics["result"]
    assert worker["native_status"] == "damaged"
    assert worker["damaged"] is True
    assert worker["failure_stage"] == "archive_open"
    assert worker["failure_kind"] == "structure_recognition"


def test_extraction_scheduler_saves_worker_diagnostics_on_failure(tmp_path):
    _require_worker_or_skip()
    missing = tmp_path / "missing.7z"
    result = ExtractionScheduler(max_retries=1).extract(_task(missing), str(tmp_path / "out"))

    assert result.success is False
    assert result.diagnostics["result"]["failure_stage"] == "input_open"
    assert result.diagnostics["result"]["failure_kind"] == "input_stream"
    assert result.diagnostics["result"]["diagnostics"]["input_trace"]["read_error"] is True
    assert result.diagnostics["repro"]["request"]["archive_path"] == str(missing)


def test_extraction_scheduler_uses_worker_for_concat_ranges(tmp_path, monkeypatch):
    monkeypatch.setenv("SUNPACK_SEVENZIP_PROFILE_READS", "1")
    archive, filename = _create_7z(tmp_path, "payload", "concat payload")
    data = archive.read_bytes()
    midpoint = len(data) // 2
    part_a = tmp_path / "part_a.bin"
    part_b = tmp_path / "part_b.bin"
    part_a.write_bytes(data[:midpoint])
    part_b.write_bytes(data[midpoint:])

    virtual = tmp_path / "payload.virtual"
    virtual.write_bytes(b"not used directly")
    task = _task(virtual, {
        "kind": "archive_input",
        "entry_path": str(virtual),
        "open_mode": "concat_ranges",
        "format_hint": "7z",
        "ranges": [
            {"path": str(part_a), "start": 0},
            {"path": str(part_b), "start": 0},
        ],
    })
    result = ExtractionScheduler(max_retries=1).extract(task, str(tmp_path / "out"))

    assert result.success is True
    assert (tmp_path / "out" / filename).read_text(encoding="utf-8") == "concat payload"
    assert result.diagnostics["result"]["input_trace"]["prefetch_enabled"] is True


def test_worker_maps_windows_invalid_entry_names_like_the_verifier(tmp_path):
    from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
    from sunpack.pipeline.verification.methods._archive_output_match import (
        archive_files_from_names,
        coverage_from_native_inventory,
    )

    worker = _require_worker_or_skip()
    archive = tmp_path / "windows-names.zip"
    entries = {
        "logs/12:30.log": "stream",
        "a?b*c.txt": "wildcards",
        "trailing.": "dot",
        "con.txt": "device",
        "sub/NUL": "device-dir",
    }
    with zipfile.ZipFile(archive, "w") as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    out_dir = tmp_path / "out"
    payload = {
        "job_id": "windows-names",
        "archive_path": str(archive),
        "output_dir": str(out_dir),
        "format_hint": "zip",
    }

    result = _invoke_worker(worker, payload)
    worker_result = _worker_result(result.stdout)

    assert result.returncode == 0, result.stdout + result.stderr
    assert worker_result["status"] == "ok"
    expected_on_disk = {
        "logs/12_30.log": "stream",
        "a_b_c.txt": "wildcards",
        "trailing_": "dot",
        "_con.txt": "device",
        "sub/_NUL": "device-dir",
    }
    written = {
        entry.name
        for entry in os.scandir(out_dir)
    } | {f"logs/{entry.name}" for entry in os.scandir(out_dir / "logs")} | {
        f"sub/{entry.name}" for entry in os.scandir(out_dir / "sub")
    }
    assert set(expected_on_disk) <= written
    # Mapped names are ordinary Win32 names: plain paths can open them.
    for relative, content in expected_on_disk.items():
        assert (out_dir / relative).read_text(encoding="utf-8") == content
    # No alternate data stream was created on a file named "12".
    assert not (out_dir / "logs" / "12").exists()

    coverage, _ = coverage_from_native_inventory(
        archive_files_from_names(list(entries)),
        collect_output_inventory(str(out_dir)),
        method="test",
    )
    assert coverage.missing_files == 0
    assert coverage.failed_files == 0
    assert coverage.matched_files == len(entries)


def test_worker_manifest_protocol(subtests):
    from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import (
        native_worker_manifest, parse_worker_json_line,
    )
    path = '目录/"quoted"\\name.txt'
    fields = [("rows", [[0, path, "", 3, 3, 1, 1, 1, 1, 1, 1, 1, 123, "616263"]]),
              ("inventory", [1, 1, 0, 3, 1])]
    for order in (fields, fields[::-1]):
        with subtests.test(rows_first=order[0][0] == "rows"):
            result = parse_worker_json_line(json.dumps({"type": "result", "verified_manifest": dict(order)}))
            manifest = result["verified_manifest"]
            assert "rows" not in manifest and "files" not in manifest
            assert manifest["inventory"]["complete"] and manifest["inventory"]["identity_paths"]
            native = native_worker_manifest(result)
            assert len(native) == 1 and native.all_complete()
            row = native.file_page(0, 1)[0]
            assert row["path"] == path and row["magic"] == b"abc" and row["mtime_ns"] == 123
            assert row["status"] == "complete" and "output_path" not in row


def test_worker_password_candidates(tmp_path, subtests):
    from sunpack.core.passwords.verifier.zip_fast import ZipFastVerifier
    worker = _require_worker_or_skip()
    archive, filename = _create_encrypted_zip(tmp_path)
    weak = [f"weak-collision-{index}" for index in range(4096)]
    matches = ZipFastVerifier().verify_batch(str(archive), weak).matched_indices
    cases = [(["secret"], True), (["wrong-password-1", "wrong-password-2"], False)]
    if matches:
        collision = weak[matches[0]]
        cases.extend([([collision], False), ([collision, "secret"], True)])
    else:
        with subtests.test(scenario="weak_header_collision"):
            pytest.skip("fixture has no weak ZipCrypto header collision in candidate batch")
    for index, (candidates, accepted) in enumerate(cases):
        with subtests.test(candidates=candidates):
            out = tmp_path / f"out-{index}"
            result = _invoke_worker(worker, {
                "job_id": str(index), "archive_path": str(archive), "output_dir": str(out),
                "format_hint": "zip", "password": "placeholder", "password_candidates": candidates,
            })
            final = _worker_result(result.stdout)
            assert (result.returncode == 0) is accepted, result.stdout + result.stderr
            assert (final["status"] == "ok") is accepted
            if accepted:
                assert final["matched_index"] == candidates.index("secret")
                assert (out / filename).read_text(encoding="utf-8") == "encrypted worker payload"
            else:
                assert final["native_status"] == "wrong_password"
                assert final["password_candidates_all_rejected"] and final["matched_index"] == -1
                if len(candidates) > 1:
                    assert not (out / filename).exists()
