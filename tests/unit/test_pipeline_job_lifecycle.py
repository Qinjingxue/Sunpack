from __future__ import annotations

import asyncio

import pytest

from sunpack.pipeline.coordinator.engine import _RequestRuntime


@pytest.mark.parametrize("failure_stage", ["cleanup", "shell", "progress"])
def test_request_finalization_releases_owners_after_cleanup_failure(monkeypatch, tmp_path, failure_stage):
    # Successful-close coverage misses failures in the finalizer itself. Keep
    # the failed runtime alive, like a retained traceback, and verify that
    # progress callbacks and request ownership have already been released.
    import sunpack.pipeline.coordinator.engine as engine_module
    from tests.helpers.config_factory import make_config

    async def no_worker(*args):
        pass

    monkeypatch.setattr(engine_module._PipelineServices, "start", no_worker)
    monkeypatch.setattr(engine_module._PipelineServices, "close", no_worker)

    async def scenario():
        async with engine_module.PipelineEngine(make_config()) as engine:
            factory = engine._request_runtime_factory
            captured = []

            def configured(*args):
                runtime = factory(*args)
                captured.append(runtime)

                def fail():
                    raise RuntimeError("finalization failure")

                async def async_fail():
                    fail()

                async def discover(*args, **kwargs):
                    # Fail in finalization, after the normal execution body.
                    runtime.source_cleanup.sweep_requests = fail if failure_stage == "cleanup" else lambda: ()
                    runtime._shell_updates.flush = fail if failure_stage == "shell" else lambda: None
                    if failure_stage == "progress":
                        runtime.reporter.drain_progress = async_fail

                runtime._discover_and_run = discover
                return runtime

            engine._request_runtime_factory = configured
            with pytest.raises(RuntimeError, match="finalization failure"):
                await engine.run([str(tmp_path)])
            runtime = captured.pop()
            assert runtime.extractor.sevenzip_runner.progress_callback is None
            assert engine.is_idle()

    asyncio.run(scenario())


def test_closed_engine_releases_callback_owners_without_cyclic_gc(monkeypatch):
    # Resource-cache tests inspect handles, not Python owner retention after
    # close. Disabling cyclic GC exposes that separate lifecycle failure using
    # one worker-free engine, without RSS measurements or timing assertions.
    import gc
    import weakref
    import sunpack.pipeline.coordinator.engine as engine_module
    from tests.helpers.config_factory import make_config

    async def no_worker(*args):
        pass

    monkeypatch.setattr(engine_module._PipelineServices, "start", no_worker)
    monkeypatch.setattr(engine_module._PipelineServices, "close", no_worker)

    class Observer:
        def changed(self):
            pass

    async def scenario():
        observer = Observer()
        async with engine_module.PipelineEngine(make_config()) as engine:
            engine.set_state_changed_callback(observer.changed)
        observer_ref = weakref.ref(observer)
        del observer
        assert observer_ref() is None
        return weakref.ref(engine)

    enabled = gc.isenabled()
    gc.disable()
    try:
        assert asyncio.run(scenario())() is None
    finally:
        if enabled:
            gc.enable()


def test_batched_jobs_finish_independent_work_and_nested_batches_before_raising():
    """Cover admission beyond the queue budget with nested and failed jobs.

    Existing small batches never exhaust admission; losing pending work or
    blocking children would escape them. This uses no files or timed waits.
    """
    import threading
    from types import SimpleNamespace as NS
    import pytest
    from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker, CancellationToken

    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=2, max_pending_jobs=4)
        runtime = object.__new__(_RequestRuntime)
        runtime.submission = NS(origin="foreground", request_id="batch")
        runtime.recursive_authorization = NS(authorize_batch=lambda tasks, *a, **k: NS(allowed_tasks=tasks, skipped=()))
        runtime.context = NS(lock=threading.Lock(), policy_skips=[])
        runtime._claim_tasks = lambda tasks: tasks
        runtime.source_cleanup = NS(register=lambda tasks: None)
        runtime.reporter = NS(tasks_discovered=lambda *a, **k: None)
        runtime.job_executor = NS(password_scope_context=NS(annotate=lambda tasks: None))
        runtime._consumer_budget = broker.max_pending_jobs
        seen = set()
        children_done = asyncio.Event()

        async def batch(tasks, depth):
            return await runtime._run_discovery_batch(
                tasks, roots=[], scan_session=None, depth=depth, direct=True,
                ownership=None, broker=broker, cancellation=CancellationToken(),
            )

        async def job(task, **kwargs):
            seen.add(task)
            if task == 0:
                assert await batch([100, 101], 2)
                children_done.set()
            elif task == 2:
                await children_done.wait()
                raise ValueError("first input failure")
            elif task == 3:
                raise ValueError("later input failure")
            await asyncio.sleep(0)
            return task != 5

        runtime._execute_job = job
        try:
            with pytest.raises(ValueError, match="first input failure"):
                await asyncio.wait_for(batch(list(range(12)), 1), timeout=2)
            assert seen == {*range(12), 100, 101}
        finally:
            await broker.close()

    asyncio.run(scenario())


def test_flatten_cleanup_drain_does_not_wait_for_unrelated_paths(tmp_path):
    async def scenario():
        runtime = object.__new__(_RequestRuntime)
        inside_gate = asyncio.Event()
        outside_gate = asyncio.Event()
        inside = asyncio.create_task(inside_gate.wait())
        outside = asyncio.create_task(outside_gate.wait())
        runtime._cleanup_tasks = {
            inside: (str(tmp_path / "out" / "wrapper" / "inner.zip"),),
            outside: (str(tmp_path / "other" / "unrelated.zip"),),
        }

        waiter = asyncio.create_task(
            runtime._drain_cleanup_tasks_under(str(tmp_path / "out"))
        )
        await asyncio.sleep(0)
        assert waiter.done() is False

        inside_gate.set()
        await asyncio.wait_for(waiter, timeout=1)

        assert inside.done() is True
        assert outside.done() is False
        outside.cancel()
        await asyncio.gather(outside, return_exceptions=True)

    asyncio.run(scenario())


def test_watch_claim_publishes_each_confirmed_task_and_updated_volume_members(tmp_path):
    """Catch aggregate-claim grouping and retry membership loss.

    Other lifecycle tests use foreground integer jobs and cannot detect either
    GUI contract failure. One file-free batch also covers the retry claim path.
    """
    import threading
    from types import SimpleNamespace as NS
    from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, InputExtent
    from sunpack.core.contracts.tasks import ArchiveTask
    from sunpack.pipeline.coordinator.engine import _PathLeaseRegistry
    from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker, CancellationToken
    from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions

    async def scenario():
        paths = [str(tmp_path / name) for name in ("disguised.a", "unrelated.blob", "late.bin")]
        first = ArchiveTask.from_archive_input(ArchiveInputDescriptor(
            paths[0], open_mode="concat_ranges", logical_name="movie.7z",
            extents=[InputExtent(path) for path in paths[:2]],
        ), discovery_source="test", cleanup_paths=[str(tmp_path / "carrier")])
        second = ArchiveTask.from_archive_input(ArchiveInputDescriptor(
            str(tmp_path / "inner.zip"), logical_name="inner.zip",
        ), discovery_source="test")
        broker = AsyncWorkBroker(thread_capacity=2, max_pending_jobs=4)
        runtime = object.__new__(_RequestRuntime)
        runtime.submission = NS(origin="watch", request_id="claim", detection_options=EmbeddedOptions())
        runtime.recursive_authorization = NS(authorize_batch=lambda tasks, *a, **k: NS(allowed_tasks=tasks, skipped=()))
        runtime.context = NS(lock=threading.Lock(), policy_skips=[])
        runtime._claim_tasks = lambda tasks: tasks
        runtime.source_cleanup = NS(register=lambda tasks: None)
        runtime.reporter = NS(tasks_discovered=lambda *a, **k: None)
        runtime.job_executor = NS(password_scope_context=NS(annotate=lambda tasks: None))
        runtime._consumer_budget = broker.max_pending_jobs
        runtime.path_leases = _PathLeaseRegistry({})
        claims = []
        runtime._report_progress = lambda task, event: claims.append(event)

        async def job(task, **kwargs):
            return True

        runtime._execute_job = job
        try:
            assert await runtime._run_discovery_batch(
                [first, second], roots=[], scan_session=None, depth=1, direct=True,
                ownership=None, broker=broker, cancellation=CancellationToken(),
            )
            assert claims[0]["groups"] == [
                {"path": paths[0], "name": "movie.7z", "members": paths[:2], "multipart": True},
                {"path": second.main_path, "name": "inner.zip", "members": [second.main_path]},
            ]
            assert str(tmp_path / "carrier") in claims[0]["source_paths"]
            first.set_archive_input(ArchiveInputDescriptor(
                paths[0], open_mode="concat_ranges", logical_name="movie.7z",
                extents=[InputExtent(path) for path in paths],
            ))
            await runtime._ensure_task_lease(first, cancellation=CancellationToken())
            assert claims[-1]["groups"] == [{"path": paths[0], "name": "movie.7z", "members": paths, "multipart": True}]
        finally:
            await broker.close()

    asyncio.run(scenario())
