from __future__ import annotations

import asyncio
import io
import threading
from pathlib import Path

import pytest

from sunpack.pipeline.coordinator import archive_job
from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker, CancellationToken
from sunpack.pipeline.coordinator.engine import PipelineEngine, _RequestRuntime
from tests.helpers.config_factory import make_config
from tests.helpers.fs_builder import make_zip


@pytest.mark.parametrize("origin", ["foreground", "watch"])
def test_interruption_joins_verification_rolls_back_tree_and_keeps_completed_root(tmp_path, monkeypatch, origin):
    """Other extraction tests never interrupt a live verifier in a nested tree.

    One real carrier batch catches rollback racing IO, retaining unfinished
    recursive output, or deleting a completed independent root in either mode.
    """
    outer = tmp_path / "outer.blob"
    child = make_zip({"data.txt": b"unfinished child"})
    outer.write_bytes(b"prefix!" * 20 + make_zip({"inner.blob": child, "keep.txt": b"verified parent"}) + b"tail!" * 20)
    completed = tmp_path / "completed.zip"
    completed.write_bytes(make_zip({"complete.txt": b"completed root"}))
    config = make_config({
        "recursive_extract": 3,
        "post_extract": {"archive_cleanup_mode": "d", "flatten_single_directory": False},
    })
    release = threading.Event()
    original = archive_job.verify_and_project
    events = []
    completed_done = threading.Event()
    completed_output = []
    execute_original = _RequestRuntime._execute_job

    async def execute(self, task, **kwargs):
        result = await execute_original(self, task, **kwargs)
        if Path(task.main_path) == completed:
            completed_output.append(next(item.output_dir for item in self.context.target_results if item.input_path == str(completed)))
            completed_done.set()
        return result
    monkeypatch.setattr(_RequestRuntime, "_execute_job", execute)

    async def scenario():
        loop = asyncio.get_running_loop()
        verifying = asyncio.Event()
        output = []

        def verify(verifier, task, result, **kwargs):
            if Path(task.main_path).name == "inner.blob":
                assert completed_done.wait(10)
                output.append(Path(result.out_dir))
                loop.call_soon_threadsafe(verifying.set)
                assert release.wait(10), "test did not release verifier"
            return original(verifier, task, result, **kwargs)

        monkeypatch.setattr(archive_job, "verify_and_project", verify)
        token = CancellationToken()
        async with PipelineEngine(config) as engine:
            request = asyncio.create_task(engine.run(
                [str(outer), str(completed)], origin=origin, cancellation=token,
                stdout=io.StringIO(), stderr=io.StringIO(),
                progress_callback=lambda task, event: events.append(dict(event)),
            ))
            try:
                await asyncio.wait_for(verifying.wait(), 10)
                parent = output[0].parent
                assert (parent / "keep.txt").read_bytes() == b"verified parent"
                assert (output[0] / "data.txt").is_file()
                token.cancel()
                token.cancel()
                await asyncio.sleep(0)
                assert not request.done()
                assert output[0].is_dir(), "rollback ran before verifier released its handles"
            finally:
                release.set()
            response = await asyncio.wait_for(request, 10)
            assert response.interrupted and not response.interruption_cleanup_errors
            assert not output[0].exists()
            assert not parent.exists()
            assert (Path(completed_output[0]) / "complete.txt").read_bytes() == b"completed root"
            assert outer.is_file()
            assert engine.is_idle()
            # The same shared engine must still accept subsequent work.
            another = tmp_path / "next.zip"
            another.write_bytes(make_zip({"next.txt": b"next request"}))
            next_response = await engine.run([str(another)], stdout=io.StringIO(), stderr=io.StringIO())
            assert not next_response.interrupted and next_response.summary.success_count == 1
        if origin == "watch":
            kept = [event for event in events if event.get("event") == "task_output_finished" and event.get("keep_output")]
            discarded = [event for event in events if event.get("event") == "task_output_finished" and not event.get("keep_output")]
            assert kept and discarded

    asyncio.run(scenario())


def test_broker_task_cancellation_waits_for_real_operation_exit():
    """Queued-token tests cannot detect a cancelled waiter abandoning live IO.

    One event-gated operation checks joining and repeated cancellation without
    filesystem or scheduler timing assumptions.
    """
    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=1)
        entered, release = asyncio.Event(), threading.Event()
        loop = asyncio.get_running_loop()

        def work():
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(10)

        task = asyncio.create_task(broker.run("verify", "archive", work))
        try:
            await entered.wait()
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done() and broker.active_jobs == 1
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert broker.active_jobs == 0
        await broker.close()

    asyncio.run(scenario())


def test_native_stop_drains_worker_and_reports_rollback_failure(tmp_path, monkeypatch):
    """Verifier cancellation never exercises the native job cancel path.

    Stop at real extraction start and deny rollback once, covering both native
    lifetime and truthful terminal cleanup errors in one small archive run.
    """
    from sunpack.pipeline.postprocess.output_cleanup import OutputCleanupExecutor

    archive = tmp_path / "active.zip"
    archive.write_bytes(make_zip({f"item-{index}.txt": b"payload" * 100 for index in range(256)}))
    config = make_config({"post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False}})

    async def scenario():
        token = CancellationToken()
        started = []
        def progress(task, event):
            if event.get("event") == "extract_started":
                started.append(task.main_path)
                token.cancel()
        def deny(path):
            raise PermissionError("test output held open")
        monkeypatch.setattr(OutputCleanupExecutor, "remove_tree", staticmethod(deny))
        async with PipelineEngine(config) as engine:
            response = await engine.run([str(archive)], cancellation=token,
                stdout=io.StringIO(), stderr=io.StringIO(), progress_callback=progress)
            assert started and response.interrupted
            assert len(response.interruption_cleanup_errors) == 1
            assert "test output held open" in response.interruption_cleanup_errors[0]
            assert engine.is_idle()
            worker = engine._services.sevenzip_runner._async_worker_holder._worker
            assert not worker._jobs
            assert worker.is_alive(), "stopping a job must not kill the shared worker"
            assert archive.exists()
    asyncio.run(scenario())


def test_watch_toast_stop_reaches_pipeline_and_finishes_after_durable_cleanup(tmp_path, monkeypatch):
    """Isolated toast and scheduler tests cannot prove their real signal wiring.

    One event-driven Watch batch covers activation through persisted terminal
    state and ensures its final notification follows output cleanup.
    """
    from sunpack.core.platform.windows.toast_protocol import ToastSnapshotKind
    from sunpack.runtime.cli import persistent_process, runtime_state
    from sunpack.runtime.cli.runtime_host import RuntimeHost
    from sunpack.runtime.watch.scheduler import WatchScheduler
    from sunpack.runtime.watch.toast import WatchToastCoordinator
    from types import SimpleNamespace

    # This test admits a filesystem candidate directly; SCM/USN subscription
    # installation is independently covered by broker integration tests.
    monkeypatch.setattr("sunpack.runtime.watch.scheduler.validate_ntfs_watch_roots", lambda roots: None)

    source = tmp_path / "source"
    source.mkdir()
    archive = source / "watch.blob"
    archive.write_bytes(make_zip({f"file-{index}.txt": b"watch" for index in range(128)}))
    config = make_config({"watch": {"clipboard_monitor_enabled": False},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False}})

    async def scenario():
        loop = asyncio.get_running_loop()
        wake, finalized = asyncio.Event(), asyncio.Event()
        runtime = RuntimeHost()
        monkeypatch.setattr(runtime_state, "runtime_host", lambda: runtime)
        controls = []

        async def stop(batch_id):
            assert await persistent_process._execute_streaming_request_async(
                {"argv": ["--cancel-watch-batch", batch_id]}, None,
            ) == 0

        class Host:
            stopped = False
            snapshots = []
            def clear(self):
                pass
            def publish(self, snapshot):
                self.snapshots.append(snapshot)
                if snapshot.kind != ToastSnapshotKind.PROGRESS:
                    loop.call_soon_threadsafe(finalized.set)
                elif not self.stopped:
                    self.stopped = True
                    loop.call_soon_threadsafe(lambda: controls.append(asyncio.create_task(stop(snapshot.batch_id))))

        host = Host()
        toast = WatchToastCoordinator(host, config, str(tmp_path / "state"))
        async with PipelineEngine(config) as engine:
            watcher = WatchScheduler(config, [str(source)], output_roots={str(source): str(tmp_path / "out")},
                state_path=str(tmp_path / "state.snapshot"), cold_start_seconds=0,
                pipeline_engine=engine, notification_sink=toast, wake_callback=wake.set)
            runtime._watch_service = SimpleNamespace(scheduler=watcher, toast_coordinator=toast)
            try:
                watcher.enqueue(str(archive))
                await watcher.run_once()
                async def drain():
                    while watcher._inflight_requests:
                        await wake.wait()
                        wake.clear()
                        await watcher.run_once()
                await asyncio.wait_for(drain(), 10)
                await asyncio.wait_for(finalized.wait(), 5)
                await asyncio.gather(*controls)
                assert host.stopped
                assert host.snapshots[-1].body == toast.i18n.t("interrupt.cleaned")
                assert not watcher.state.pending_work_items()
                assert watcher.state.latest_entry_for_path(str(archive)).status == "interrupted"
                assert not [path for path in (tmp_path / "out").rglob("*") if path.is_file()]
                watcher.enqueue(str(archive))
                assert watcher.pending_count == 0
            finally:
                await asyncio.gather(*controls, return_exceptions=True)
                await watcher.aclose()
                toast.stop()
    asyncio.run(scenario())


def test_cli_control_returns_130_and_json_after_output_cleanup(tmp_path, monkeypatch):
    """Console and Watch tests cannot detect the CLI losing its request token,
    returning the ordinary failure code, or emitting success JSON on stop.
    One real CLI command exercises those boundaries without a server install.
    """
    import json
    import struct
    from sunpack.runtime.cli import cli, persistent_process
    from sunpack.runtime.cli.commands import extract

    archive = tmp_path / "active.zip"
    archive.write_bytes(make_zip({"data.txt": b"unfinished"}))
    config = make_config({"post_extract": {"archive_cleanup_mode": "d"}})
    monkeypatch.setattr(cli, "runtime_id_available", lambda: False)
    monkeypatch.setattr(extract, "load_request_config", lambda *a, **k: config)
    monkeypatch.setattr(extract, "pipeline_engine", PipelineEngine)
    release = threading.Event()
    verify_original = archive_job.verify_and_project

    async def scenario():
        loop = asyncio.get_running_loop()
        entered = asyncio.Event()
        output = []
        def verify(verifier, task, result, **kwargs):
            output.append(Path(result.out_dir))
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(10)
            return verify_original(verifier, task, result, **kwargs)
        monkeypatch.setattr(archive_job, "verify_and_project", verify)
        protocol = persistent_process._PipeRequestProtocol(b"t" * 32,
            on_connected=lambda: None, on_closed=lambda: None,
            on_completed=lambda: None, on_shutdown=lambda: None)
        class Transport:
            wire = bytearray()
            def write(self, data): self.wire.extend(data)
            def get_write_buffer_size(self): return 0
            def close(self): pass
        transport = Transport()
        protocol.connection_made(transport)
        payload = {"cwd": str(tmp_path), "argv": ["extract", str(archive), "--json", "--no-pause"]}
        protocol._payload = payload
        request = protocol._request_task = asyncio.create_task(protocol._run_request(payload))
        try:
            await asyncio.wait_for(entered.wait(), 10)
            protocol.data_received(b"\xff" * 4)
            await asyncio.sleep(0)
            assert not request.done() and output[0].exists()
        finally:
            release.set()
        await asyncio.wait_for(request, 10)
        assert not output[0].exists() and archive.exists()
        wire = io.BytesIO(transport.wire[20:])
        stdout, exit_code = [], None
        while header := wire.read(5):
            kind, size = struct.unpack("!BI", header)
            data = wire.read(size)
            if kind == 0: exit_code = struct.unpack("!i", data)[0]
            elif kind == 1: stdout.append(data)
        assert exit_code == 130
        result = json.loads(b"".join(stdout))
        assert result["summary"]["interrupted"] and result["summary"]["cleanup_complete"]
        await protocol._output_task
    asyncio.run(scenario())

