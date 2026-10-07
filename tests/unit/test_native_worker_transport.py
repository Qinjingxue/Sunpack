import asyncio
import io
import json
import subprocess
import threading
from types import SimpleNamespace

import pytest
from sunpack_native import NativeWorkerResultAccumulator, parse_worker_transport_event

from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import (
    _AsyncNativeWorkerProcess,
    _NativeQueueCapacity,
    _NativeWorkerProcess,
)
from sunpack.core.support.resources import get_sevenzip_bridge_worker_path
from tests.helpers.worker_events import worker_trace_item


def _event(kind, job_id="job", **fields):
    return parse_worker_transport_event(json.dumps({"type": kind, "job_id": job_id, **fields}))


def _row(path="目录/a.txt"):
    return [0, path, "renamed.txt", 3, 3, 1, 7, 1, 7, 1, 1, 1, 123, "616263"]


def _result(job_id="job", *, chunks=1, files=1, trace_chunks=1, items=1):
    return _event(
        "result", job_id, status="failed",
        verified_manifest={
            "validated": False, "item_count": files,
            "file_count": files, "inventory": [0, files, 0, files * 3, 0],
            "chunk_count": chunks,
        },
        diagnostics={"output_trace": {"chunk_count": trace_chunks, "item_count": items}},
    )


def test_interleaved_chunks_preserve_native_tables_and_metadata():
    first = NativeWorkerResultAccumulator("first")
    second = NativeWorkerResultAccumulator("second")
    for job_id, accumulator in [("second", second), ("first", first)]:
        assert accumulator.accept(_event("manifest_chunk", job_id, seq=0, rows=[_row(job_id)]))
        assert accumulator.accept(_event(
            "trace_chunk",
            job_id,
            seq=0,
            items=[worker_trace_item(path=job_id, failed=True, hresult=-2147467259)],
        ))
    for job_id, accumulator in [("first", first), ("second", second)]:
        result = _result(job_id)
        assert accumulator.accept(result) is False
        manifest = result["verified_manifest"]
        native = manifest["native_rows"]
        assert len(native) == native.file_count == 1
        row = native.file_page(0, 1)[0]
        assert row["path"] == job_id and row["output_path"] == "renamed.txt"
        assert row["magic"] == b"abc" and row["mtime_ns"] == 123
        assert row["output_crc32"] == 7 and row["status"] == "complete"
        trace = result["diagnostics"]["output_trace"]
        assert trace["native_items"].item_page(0, 1)[0]["hresult"] == -2147467259
        assert "rows" not in manifest and "items" not in trace
        assert "chunk_count" not in manifest and "chunk_count" not in trace


@pytest.mark.parametrize("seq", [1, 2])
def test_chunk_sequence_gap_is_rejected(seq):
    accumulator = NativeWorkerResultAccumulator("job")
    with pytest.raises(ValueError, match="sequence"):
        accumulator.accept(_event("manifest_chunk", seq=seq, rows=[_row()]))


def test_duplicate_chunks_and_inconsistent_result_counts_are_rejected():
    accumulator = NativeWorkerResultAccumulator("job")
    accumulator.accept(_event("manifest_chunk", seq=0, rows=[_row()]))
    with pytest.raises(ValueError, match="sequence"):
        accumulator.accept(_event("manifest_chunk", seq=0, rows=[_row()]))
    for result in [_result(chunks=2, trace_chunks=0, items=0), _result(files=2, trace_chunks=0, items=0)]:
        with pytest.raises(ValueError, match="count mismatch"):
            accumulator.accept(result)


def test_empty_result_publishes_empty_native_tables():
    accumulator = NativeWorkerResultAccumulator("job")
    result = _result(chunks=0, files=0, trace_chunks=0, items=0)
    accumulator.accept(result)
    assert len(result["verified_manifest"]["native_rows"]) == 0
    assert len(result["diagnostics"]["output_trace"]["native_items"]) == 0


def test_large_total_manifest_is_not_limited_by_one_stdout_line():
    accumulator = NativeWorkerResultAccumulator("job")
    rows = [_row("x" * 1000) for _ in range(400)]
    total_bytes = 0
    for seq in range(170):
        line = json.dumps({"type": "manifest_chunk", "job_id": "job", "seq": seq, "rows": rows}).encode()
        assert len(line) < 512 * 1024
        total_bytes += len(line)
        assert accumulator.accept(parse_worker_transport_event(line))
    assert total_bytes > 64 * 1024 * 1024
    result = _result(chunks=170, files=170 * 400, trace_chunks=0, items=0)
    accumulator.accept(result)
    native = result["verified_manifest"]["native_rows"]
    assert len(native) == 68000
    assert native.file_page(67999, 1)[0]["magic"] == b"abc"


def test_malformed_routed_chunk_and_unattributable_line_are_distinguished():
    event = parse_worker_transport_event(b'{"type":"manifest_chunk","job_id":"a\\\"b","seq":0,"rows":[[broken]}')
    assert event["type"] == "protocol_error" and event["job_id"] == 'a"b'
    with pytest.raises(ValueError, match="unattributable"):
        parse_worker_transport_event(b"broken stream")


def test_sync_bad_job_waits_for_native_finish_and_does_not_affect_other_jobs():
    worker = object.__new__(_NativeWorkerProcess)
    worker.process_config = {}
    worker.worker_epoch = "test"
    worker._async_jobs = {}
    worker._job_states = {}
    worker._dispatch_lock = threading.Lock()
    worker._deadline_changed = threading.Event()
    sent, callbacks, failures = [], [], []
    worker.send = sent.append
    for job_id in ["bad", "good"]:
        worker.submit_async("request", job_id, parsed_events=True,
                            on_line=lambda line, event: callbacks.append(event) or event.get("event") == "job_finished",
                            on_timeout=lambda message: failures.append(message))
    payload = _event("manifest_chunk", "bad", seq=1, rows=[_row()])
    worker._dispatch_line("", payload, "bad")
    assert "bad" in worker._async_jobs and not failures and not callbacks
    assert worker._async_jobs["bad"]["cancel_requested"] is True
    assert json.loads(sent[-1]) == {"worker_command": "cancel", "job_id": "bad"}
    good_result = _event("result", "good", status="ok")
    worker._dispatch_line("", good_result, "good")
    worker._dispatch_line("", _event("native_event", "good", event="job_finished"), "good")
    assert "good" not in worker._async_jobs and not failures
    worker._dispatch_line("", _event("native_event", "bad", event="job_finished"), "bad")
    assert not worker._async_jobs and len(failures) == 1
    assert [event["job_id"] for event in callbacks] == ["good", "good"]


def test_sync_fatal_protocol_error_stops_process_before_failure_callback():
    worker = object.__new__(_NativeWorkerProcess)
    worker._dispatch_lock = threading.Lock()
    worker._deadline_changed = threading.Event()
    worker.queue_capacity = _NativeQueueCapacity()
    worker._job_states = {"job": {}}
    order = []
    worker._async_jobs = {"job": {"completion_lock": threading.Lock(), "on_timeout": lambda message: order.append("failed")}}
    worker.close = lambda: order.append("stopped")
    worker._dispatch_stdout(io.StringIO("broken\n"))
    assert order == ["stopped", "failed"]


def test_async_bad_chunk_cancels_only_its_job_and_retains_ownership_until_finish():
    async def run():
        worker = _AsyncNativeWorkerProcess("unused", None)
        reader = asyncio.StreamReader()
        exited = asyncio.Event()
        sent, callbacks, failures = [], [], []

        async def send(payload):
            sent.append(payload)

        async def wait():
            await exited.wait()

        def terminate():
            worker.process.returncode = 0
            exited.set()

        worker.process = SimpleNamespace(stdout=reader, returncode=None, terminate=terminate, wait=wait)
        worker.send = send
        barrier = asyncio.Event()

        def callback(line, event):
            callbacks.append(event)
            if event.get("type") == "progress":
                barrier.set()
            return event.get("event") == "job_finished"

        for job_id in ["bad", "good"]:
            await worker.submit("request", job_id, parsed_events=True, on_line=callback, on_timeout=failures.append)
        dispatch = asyncio.create_task(worker._dispatch_stdout())

        def feed(kind, job_id, **fields):
            reader.feed_data((json.dumps({"type": kind, "job_id": job_id, **fields}) + "\n").encode())

        reader.feed_data(b'{"type":"manifest_chunk","job_id":"bad","seq":0,"rows":[[broken]}\n')
        feed("progress", "good")
        await asyncio.wait_for(barrier.wait(), 2)
        assert "bad" in worker._jobs and not failures
        assert json.loads(sent[-1]) == {"worker_command": "cancel", "job_id": "bad"}
        assert worker.process.returncode is None
        feed("manifest_chunk", "good", seq=0, rows=[_row("good.txt")])
        feed("result", "good", verified_manifest={"file_count": 1, "chunk_count": 1, "inventory": [1, 1, 0, 3, 0]})
        feed("native_event", "good", event="job_finished")
        feed("native_event", "bad", event="job_finished")
        reader.feed_eof()
        await asyncio.wait_for(dispatch, 2)
        assert len(failures) == 1 and "malformed worker event" in failures[0]
        assert not worker._jobs
        result = next(event for event in callbacks if event["type"] == "result")
        assert result["verified_manifest"]["native_rows"].file_page(0, 1)[0]["path"] == "good.txt"
        assert not any(event["type"] == "manifest_chunk" for event in callbacks)

    asyncio.run(run())


@pytest.mark.parametrize("oversized", [False, True])
def test_async_fatal_stream_error_stops_process_before_failing_jobs(oversized):
    async def run():
        worker = _AsyncNativeWorkerProcess("unused", None)
        reader = asyncio.StreamReader(limit=4 * 1024 * 1024)
        order = []

        async def send(payload):
            pass

        async def wait():
            order.append("stopped")

        def terminate():
            worker.process.returncode = -1

        worker.process = SimpleNamespace(stdout=reader, returncode=None, terminate=terminate, wait=wait)
        worker.send = send
        for job_id in ["first", "second"]:
            await worker.submit("request", job_id, on_line=lambda line: False,
                                on_timeout=lambda message: order.append("failed"))
        reader.feed_data(b"x" * (4 * 1024 * 1024 + 1) if oversized else b"broken\n")
        await asyncio.wait_for(worker._dispatch_stdout(), 2)
        assert order == ["stopped", "failed", "failed"]
        assert not worker._jobs

    asyncio.run(run())


@pytest.fixture(scope="module")
def many_item_archive(tmp_path_factory):
    root = tmp_path_factory.mktemp("worker-chunks")
    archive = root / "disguised.bin"
    literal = str(archive).replace("'", "''")
    script = (
        "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.IO.Compression; "
        f"$f=[IO.File]::Open('{literal}',[IO.FileMode]::Create); "
        "$z=[IO.Compression.ZipArchive]::new($f,[IO.Compression.ZipArchiveMode]::Create); "
        "0..5999 | ForEach-Object { [void]$z.CreateEntry(('目录/'+('x'*160)+('{0:D5}.txt' -f $_))) }; "
        "$z.Dispose(); $f.Dispose()"
    )
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                   check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    return archive


def _request(archive, job_id="many-items", origin="foreground"):
    return json.dumps({"job_id": job_id, "origin": origin, "archive_path": str(archive), "dry_run": True, "format_hint": "zip"})


def _assert_many_item_result(result):
    assert result["status"] == "ok"
    files = result["verified_manifest"]["native_rows"]
    trace = result["diagnostics"]["output_trace"]["native_items"]
    assert len(files) == files.file_count == len(trace) == 6000
    assert files.file_page(5999, 1)[0]["path"].endswith("05999.txt")
    assert trace.item_page(5999, 1)[0]["path"].endswith("05999.txt")


def test_real_worker_chunks_are_bounded_by_serialized_bytes(many_item_archive):
    completed = subprocess.run([get_sevenzip_bridge_worker_path()], input=_request(many_item_archive),
                               capture_output=True, text=True, encoding="utf-8", timeout=15,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    assert completed.returncode == 0, completed.stderr
    accumulator = NativeWorkerResultAccumulator("many-items")
    counts = {"manifest_chunk": 0, "trace_chunk": 0}
    result = None
    for line in completed.stdout.splitlines():
        event = parse_worker_transport_event(line)
        kind = event["type"]
        if kind in counts:
            assert len(line.encode("utf-8")) <= 512 * 1024
            assert event["seq"] == counts[kind]
            counts[kind] += 1
            assert accumulator.accept(event)
        elif kind == "result":
            assert len(line.encode("utf-8")) < 16 * 1024
            assert "rows" not in event["verified_manifest"]
            assert "items" not in event["diagnostics"]["output_trace"]
            accumulator.accept(event)
            result = event
    assert all(count > 1 for count in counts.values())
    assert len(completed.stdout.encode("utf-8")) > 4 * 1024 * 1024
    _assert_many_item_result(result)


def test_standalone_dry_run_assembles_chunks_with_the_same_native_contract(many_item_archive):
    from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_bridge_worker import dry_run_archive

    completed = dry_run_archive(str(many_item_archive), format_hint="zip")
    assert completed.ok, completed.message
    _assert_many_item_result(completed.result)
    assert all(event["type"] == "progress" for event in completed.progress)


@pytest.mark.parametrize("transport", ["sync", "async"])
def test_real_worker_large_results_are_assembled_in_both_transports(many_item_archive, transport):
    events = []

    def callback(line, event):
        events.append(event)
        return event.get("event") == "job_finished"

    if transport == "sync":
        worker = _NativeWorkerProcess(get_sevenzip_bridge_worker_path(), None)
        finished = threading.Event()

        def sync_callback(line, event):
            done = callback(line, event)
            if done and sum(event.get("event") == "job_finished" for event in events) == 2:
                finished.set()
            return done

        try:
            for job_id, origin in [("watch", "watch"), ("cli", "foreground")]:
                worker.submit_async(_request(many_item_archive, job_id, origin), job_id, parsed_events=True,
                                    on_line=sync_callback, on_timeout=lambda message: (events.append({"error": message}), finished.set()))
            assert finished.wait(15)
        finally:
            worker.close()
        assert not any("error" in event for event in events)
    else:
        async def run():
            worker = _AsyncNativeWorkerProcess(get_sevenzip_bridge_worker_path(), None)
            await worker.start()
            try:
                finished = []
                for job_id, origin in [("watch", "watch"), ("cli", "foreground")]:
                    await worker.submit(_request(many_item_archive, job_id, origin), job_id, parsed_events=True,
                                        on_line=callback, on_timeout=lambda message: events.append({"error": message}))
                    finished.append(worker._jobs[job_id]["finished"])
                await asyncio.wait_for(asyncio.gather(*finished), 15)
            finally:
                await worker.close()

        asyncio.run(run())
        assert not any("error" in event for event in events)
    assert not any(event.get("type") in {"manifest_chunk", "trace_chunk"} for event in events)
    results = [event for event in events if event.get("type") == "result"]
    assert {result["job_id"] for result in results} == {"watch", "cli"}
    for result in results:
        _assert_many_item_result(result)
