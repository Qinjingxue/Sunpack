import asyncio
import gc
import io
import json
import subprocess
import threading
import weakref
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


def test_shared_worker_process_mode_retries_failed_ack_and_serializes_transitions():
    # The transport needs successful acknowledgements, not requested labels.
    # Concurrent callers must also retain independent acknowledgement ownership.
    async def scenario():
        worker = _AsyncNativeWorkerProcess("unused", None)
        stdout = asyncio.StreamReader()
        worker.process = SimpleNamespace(pid=123, returncode=None, stdout=stdout)
        worker.handshake = {"process_mode": "high", "process_mode_applied": False}
        sent = []
        dispatcher = asyncio.create_task(worker._dispatch_stdout())

        async def send(payload):
            mode = json.loads(payload)["mode"]
            sent.append(mode)
            await asyncio.sleep(0)
            if len(sent) == 1:
                raise OSError("interrupted send")
            stdout.feed_data(json.dumps({
                "type": "process_mode_ack", "mode": mode, "applied": len(sent) != 2,
            }).encode() + b"\n")

        worker.send = send
        try:
            with pytest.raises(OSError):
                await worker.set_process_mode(mode="high")
            assert not (await worker.set_process_mode(mode="high"))["applied"]
            results = await asyncio.gather(*(worker.set_process_mode(mode=mode)
                                            for mode in ["high", "high", "normal", "background"]))
            assert all(result["applied"] for result in results)
            assert [result["mode"] for result in results] == ["high", "high", "normal", "background"]
            assert sent == ["high", "high", "high", "normal", "background"]
            assert (await worker.set_process_mode(mode="background"))["applied"]
            assert len(sent) == 5
        finally:
            worker._shutdown_sent = True
            stdout.feed_eof()
            await dispatcher

    asyncio.run(scenario())


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
    worker._idle = threading.Condition(worker._dispatch_lock)
    worker._closing = False
    worker._shutdown_sent = False
    sent, callbacks, failures = [], [], []
    worker.send = sent.append
    for job_id in ["bad", "good"]:
        worker.submit_async("request", job_id, parsed_events=True,
                            on_line=lambda line, event: callbacks.append(event) or event.get("event") == "job_finished",
                            on_error=lambda message: failures.append(message))
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
    worker._idle = threading.Condition(worker._dispatch_lock)
    worker._closing = False
    worker._shutdown_sent = False
    worker.queue_capacity = _NativeQueueCapacity()
    worker._job_states = {"job": {}}
    order = []
    worker._async_jobs = {"job": {"completion_lock": threading.Lock(), "on_error": lambda message: order.append("failed")}}
    worker.abort = lambda: order.append("stopped")
    worker._dispatch_stdout(io.StringIO("broken\n"))
    assert order == ["stopped", "failed"]


def test_sync_terminal_callback_can_resubmit_before_returning():
    # Queue mocks finish on one thread. Force the loop/thread handoff while the
    # stdout callback is still on the stack; without retirement it rejects the
    # replacement job, and an unconditional old cleanup would delete it.
    worker = object.__new__(_NativeWorkerProcess)
    worker.process_config = {}
    worker.worker_epoch = "test"
    worker._async_jobs = {}
    worker._job_states = {}
    worker._dispatch_lock = threading.Lock()
    worker._idle = threading.Condition(worker._dispatch_lock)
    worker._closing = False
    worker._shutdown_sent = False
    worker.send = lambda _: None
    failures = []
    replacement = []

    def terminal(line, event):
        def resubmit():
            try:
                worker.submit_async("retry", "job", parsed_events=True,
                    on_line=lambda line, event: True, on_error=failures.append)
                replacement.append(worker._async_jobs["job"])
            except Exception as exc:
                failures.append(str(exc))
        thread = threading.Thread(target=resubmit)
        thread.start()
        thread.join(2)
        assert not thread.is_alive()
        return True

    worker.submit_async("request", "job", parsed_events=True,
                        on_line=terminal, on_error=failures.append)
    worker._dispatch_line("", _event("native_event", event="job_finished"), "job")
    assert not failures and len(replacement) == 1
    assert worker._async_jobs["job"] is replacement[0]
    worker._dispatch_line("", _event("native_event", event="job_finished"), "job")
    assert not worker._async_jobs and not worker._job_states


@pytest.mark.parametrize("transport", ["sync", "async"])
def test_queued_and_running_jobs_ignore_legacy_timeout_and_complete_on_native_events(tmp_path, transport):
    # Existing transport tests finish promptly and cannot catch a watchdog
    # cancelling a queued job. The short legacy setting keeps this inexpensive.
    script = tmp_path / "queued_worker.cmd"
    script.write_text(
        '@echo {"type":"worker_ready"}\r\n'
        '@set /p first=\r\n'
        '@echo {"type":"native_event","event":"job_started","job_id":"active"}\r\n'
        '@set /p second=\r\n'
        '@echo {"type":"native_event","event":"job_queued","job_id":"queued"}\r\n'
        '@set /p finish=\r\n'
        '@echo {"type":"result","job_id":"active","status":"ok"}\r\n'
        '@echo {"type":"native_event","event":"job_finished","job_id":"active"}\r\n'
        '@echo {"type":"result","job_id":"queued","status":"ok"}\r\n'
        '@echo {"type":"native_event","event":"job_finished","job_id":"queued"}\r\n'
        '@set /p shutdown=\r\n', encoding="utf-8",
    )

    async def run():
        loop = asyncio.get_running_loop()
        started, queued, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
        events, failures, sent = [], [], []
        config = {"watchdog_no_progress_timeout_seconds": 0.01, "cancel_grace_seconds": 0.01}

        def callback(line, event):
            events.append(event)
            if event.get("event") == "job_started":
                loop.call_soon_threadsafe(started.set)
            if event.get("event") == "job_queued":
                loop.call_soon_threadsafe(queued.set)
            if event.get("event") == "job_finished" and event["job_id"] == "queued":
                loop.call_soon_threadsafe(finished.set)
            return event.get("event") == "job_finished"

        if transport == "async":
            worker = _AsyncNativeWorkerProcess(str(script), None, config)
            await worker.start()
            send = worker.send

            async def send_recorded(payload):
                sent.append(payload)
                await send(payload)
        else:
            worker = _NativeWorkerProcess(str(script), None, config)
            send = worker.send

            def send_recorded(payload):
                sent.append(payload)
                send(payload)

        worker.send = send_recorded
        try:
            for job_id in ("active", "queued"):
                if transport == "async":
                    await worker.submit("request", job_id, parsed_events=True, on_line=callback, on_error=failures.append)
                else:
                    worker.submit_async("request", job_id, parsed_events=True, on_line=callback, on_error=failures.append)
                if job_id == "active":
                    await asyncio.wait_for(started.wait(), 2)
            await asyncio.wait_for(queued.wait(), 2)
            await asyncio.sleep(0.08)
            assert worker.is_alive() and not failures and not finished.is_set()
            assert sent == ["request", "request"]
            if transport == "async":
                await worker.send("finish")
            else:
                worker.send("finish")
            await asyncio.wait_for(finished.wait(), 2)
            assert not failures
            assert {e["job_id"] for e in events if e["type"] == "result"} == {"active", "queued"}
        finally:
            if transport == "async":
                await worker.close()
            else:
                worker.close()

    asyncio.run(run())


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
            await worker.submit("request", job_id, parsed_events=True, on_line=callback, on_error=failures.append)
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


@pytest.mark.parametrize("outcome", ["success", "callback_error", "malformed_chunk"])
def test_idle_async_reader_releases_finished_callbacks_but_keeps_active_jobs(outcome):
    # Outcome tests stop at EOF and cannot detect idle tail-held callbacks.
    # Without this, collection while another job stays live is unverified.
    # Three tiny in-memory streams cover normal/error ownership without workers.
    async def run():
        waiting = asyncio.Event()

        class Reader(asyncio.StreamReader):
            async def readline(self):
                if not self._buffer:
                    waiting.set()
                return await super().readline()

        class Job:
            def on_line(self, line, event):
                if outcome == "callback_error":
                    raise ValueError("callback failed")
                return event.get("event") == "job_finished"

            def on_error(self, message):
                failures.append(message)

        reader = Reader()
        worker = _AsyncNativeWorkerProcess("unused", None)
        worker.process = SimpleNamespace(stdout=reader, returncode=0, wait=lambda: asyncio.sleep(0))
        failures, sent = [], []

        async def send(payload):
            sent.append(payload)

        async def register(job_id):
            owner = Job()
            reference = weakref.ref(owner)
            await worker.submit("request", job_id, parsed_events=True,
                                on_line=owner.on_line, on_error=owner.on_error)
            return reference

        async def feed_and_wait(line):
            waiting.clear()
            reader.feed_data(line)
            await asyncio.wait_for(waiting.wait(), 2)

        worker.send = send
        finished = await register("finished")
        active = await register("active")
        dispatch = asyncio.create_task(worker._dispatch_stdout())
        try:
            await asyncio.wait_for(waiting.wait(), 2)
            if outcome == "malformed_chunk":
                await feed_and_wait(b'{"type":"manifest_chunk","job_id":"finished","seq":0,"rows":[[broken]}\n')
                gc.collect()
                assert finished() is not None and not failures
                assert json.loads(sent[-1])["worker_command"] == "cancel"
            await feed_and_wait(b'{"type":"native_event","job_id":"finished","event":"job_finished"}\n')
            gc.collect()
            assert finished() is None
            assert active() is not None and set(worker._jobs) == {"active"}
            assert len(failures) == (outcome != "success")
            assert not dispatch.done()
        finally:
            worker._shutdown_sent = True
            reader.feed_eof()
            await asyncio.wait_for(dispatch, 2)
            worker._fail_all_jobs("closed")

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
                                on_error=lambda message: order.append("failed"))
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
    # Explicit shutdown must drain admitted work, just like the EOF path used
    # by standalone dry-run. Sending it immediately exposes native cancellation.
    completed = subprocess.run([get_sevenzip_bridge_worker_path()],
                               input=_request(many_item_archive) + '\n{"worker_command":"shutdown"}\n',
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
                                    on_line=sync_callback, on_error=lambda message: (events.append({"error": message}), finished.set()))
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
                                        on_line=callback, on_error=lambda message: events.append({"error": message}))
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


@pytest.mark.parametrize("returncode", [-101, -102])
def test_legacy_negative_worker_codes_do_not_infer_timeout_or_stall(returncode):
    from sunpack.core.contracts.failures import FailureKind
    from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import attach_worker_diagnostics
    from sunpack.pipeline.extraction.internal.workflow.errors import classify_extract_failure

    completed = attach_worker_diagnostics(
        subprocess.CompletedProcess(["worker"], returncode, "", "broken worker connection")
    )
    assert completed.worker_diagnostics["process_failure"]["failure_kind"] == "process_io"
    failure = classify_extract_failure(completed, completed.stderr)
    assert failure.kind == FailureKind.PROCESS_ERROR
    assert failure.details["failure_kind"] == "process_io"
    assert "broken worker connection" in failure.message
    assert "timed out" not in failure.message.lower()
    assert "no progress" not in failure.message.lower()


def test_worker_transport_failure_detail_outweighs_legacy_code_and_archive_text():
    from sunpack.core.contracts.failures import FailureKind
    from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import attach_worker_diagnostics
    from sunpack.pipeline.extraction.internal.workflow.errors import classify_extract_failure

    completed = attach_worker_diagnostics(
        subprocess.CompletedProcess(["worker"], -101, "", "data error"),
        process_failure={
            "failure_stage": "worker_communication",
            "failure_kind": "worker_lost",
            "message": "named pipe disconnected unexpectedly",
        },
    )
    failure = classify_extract_failure(completed, completed.stderr)
    assert failure.kind == FailureKind.PROCESS_ERROR
    assert failure.details["failure_stage"] == "worker_communication"
    assert failure.details["failure_kind"] == "worker_lost"
    assert "named pipe disconnected unexpectedly" in failure.message


@pytest.mark.parametrize("broken", [False, True])
def test_async_close_drains_before_shutdown_and_joins_all_readers(broken):
    # Existing completion tests close only after jobs finish. This exercises
    # close with an active job, concurrent callers, EOF failure and pipe teardown.
    # Event gates make the ordering deterministic without timer sleeps.
    async def scenario():
        worker = _AsyncNativeWorkerProcess("unused", None)
        reader = asyncio.StreamReader()
        exit_gate, reader_gate = asyncio.Event(), asyncio.Event()
        stopping = asyncio.Event()
        sent, errors = [], []

        class Input:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        async def wait():
            await exit_gate.wait()
            worker.process.returncode = 0

        def terminate():
            worker.process.returncode = -1
            exit_gate.set()

        async def send(payload):
            sent.append(payload)
            if json.loads(payload).get("worker_command") == "shutdown":
                stopping.set()

        async def tail_reader():
            await reader_gate.wait()

        worker.process = SimpleNamespace(stdout=reader, stdin=Input(), returncode=None,
                                         terminate=terminate, wait=wait)
        worker.send = send
        await worker.submit('{"job_id":"active"}', "active", parsed_events=True,
                            on_line=lambda line, event: event.get("event") == "job_finished",
                            on_error=errors.append)
        worker._stdout_task = asyncio.create_task(worker._dispatch_stdout())
        worker._tasks = [worker._stdout_task, asyncio.create_task(tail_reader())]
        closing = asyncio.create_task(worker.close())
        await asyncio.sleep(0)
        second = asyncio.create_task(worker.close())
        with pytest.raises(RuntimeError, match="closing"):
            await worker.submit('{}', "late", on_line=lambda _: False, on_error=errors.append)
        assert len(sent) == 1 and not closing.done()
        if broken:
            reader.feed_eof()
        else:
            reader.feed_data(b'{"type":"native_event","job_id":"active","event":"job_finished"}\n')
            await asyncio.wait_for(stopping.wait(), 2)
            assert not closing.done() and not second.done() and not errors
            exit_gate.set()
            reader.feed_eof()
        await worker._stdout_task
        await asyncio.sleep(0)
        assert not closing.done() and not second.done()
        reader_gate.set()
        await asyncio.wait_for(asyncio.gather(closing, second), 2)
        assert bool(errors) == broken
        assert not worker._jobs and not worker._tasks
        assert sum('shutdown' in payload for payload in sent) == (not broken)

    asyncio.run(scenario())


@pytest.mark.parametrize("broken", [False, True])
def test_sync_close_drains_before_shutdown_and_joins_all_readers(monkeypatch, broken):
    # Sync transports have separate admission and reader threads; the async
    # regression cannot catch their locking or an early return before EOF.
    # A fake pipe and event gates cover this without launching a child process.
    import queue
    from sunpack.pipeline.extraction.internal.sevenzip import sevenzip_runner as module

    lines = queue.Queue()
    exited, shutdown, close_waiting = threading.Event(), threading.Event(), threading.Event()
    reader_gate = threading.Event()
    sent, errors = [], []

    class Output:
        def __iter__(self):
            while True:
                line = lines.get()
                if line is None:
                    return
                yield line

        def close(self):
            pass

    class Input:
        def write(self, payload):
            sent.append(payload)
            if 'shutdown' in payload:
                shutdown.set()

        def flush(self):
            pass

        def close(self):
            pass

    class Process:
        pid = 0
        stdin, stdout = Input(), Output()

        class Stderr:
            def __iter__(self):
                assert reader_gate.wait(3)
                return iter(())

            def close(self):
                pass

        stderr = Stderr()

        def poll(self):
            return 0 if exited.is_set() else None

        def terminate(self):
            exited.set()

        def wait(self):
            assert exited.wait(3)
            return 0

    monkeypatch.setattr(module.subprocess, 'Popen', lambda *args, **kwargs: Process())
    worker = _NativeWorkerProcess("unused", None)
    original_wait = worker._idle.wait_for

    def wait_for(predicate):
        close_waiting.set()
        return original_wait(predicate)

    monkeypatch.setattr(worker._idle, 'wait_for', wait_for)
    worker.submit_async('{}', "active", parsed_events=True,
                        on_line=lambda line, event: event.get('event') == 'job_finished',
                        on_error=errors.append)
    closing = threading.Thread(target=worker.close)
    closing.start()
    try:
        assert close_waiting.wait(3)
        with pytest.raises(RuntimeError, match="closing"):
            worker.submit_async('{}', "late", on_line=lambda _: False, on_error=errors.append)
        assert not shutdown.is_set() and closing.is_alive()
        if broken:
            lines.put('broken stream\n')
        else:
            lines.put('{"type":"native_event","job_id":"active","event":"job_finished"}\n')
            assert shutdown.wait(3)
            assert closing.is_alive() and not errors
        exited.set()
        lines.put(None)
        worker._reader_threads[0].join(3)
        assert not worker._reader_threads[0].is_alive() and closing.is_alive()
    finally:
        exited.set()
        lines.put(None)
        reader_gate.set()
        closing.join(3)
    assert not closing.is_alive() and bool(errors) == broken
    assert not worker._async_jobs
    assert shutdown.is_set() != broken


def test_async_broken_pipe_above_reader_limit_reaches_process_exit():
    # In-memory fatal-stream tests cannot reproduce asyncio transport wait()
    # waiting on a paused OS pipe. One small child covers that independent hang.
    import sys

    async def scenario():
        worker = _AsyncNativeWorkerProcess("unused", None)
        worker.process = await asyncio.create_subprocess_exec(
            sys.executable, '-c', 'import os; os.write(1, b"x" * (512 * 1024))',
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, limit=4096,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        worker._stdout_task = asyncio.create_task(worker._dispatch_stdout())
        worker._tasks = [worker._stdout_task, asyncio.create_task(worker._pump_stderr())]
        try:
            await asyncio.wait_for(asyncio.shield(worker._stdout_task), 3)
            assert worker.process.returncode is not None
            await worker.close()
        finally:
            if worker.is_alive():
                worker.process.kill()
            if worker._stdout_task is not None and not worker._stdout_task.done():
                # Release a paused pipe even when testing a broken implementation.
                while await worker.process.stdout.read(64 * 1024):
                    pass
            await worker.process.wait()

    asyncio.run(scenario())
