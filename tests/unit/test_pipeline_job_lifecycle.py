from __future__ import annotations

import asyncio
import inspect

from sunpack.pipeline.coordinator.engine import _RequestRuntime


def test_archive_job_releases_source_before_starting_recursive_discovery():
    source = inspect.getsource(_RequestRuntime._execute_job)

    release = source.index("self.source_cleanup.release_task")
    recurse = source.index("await self._discover_and_run")
    flatten = source.index("await self._flatten_output")

    assert release < recurse < flatten


def test_source_cleanup_is_scheduled_not_awaited_on_job_path():
    source = inspect.getsource(_RequestRuntime._execute_job)

    release = source.index("self.source_cleanup.release_task")
    schedule = source.index("self._schedule_cleanup", release)
    recurse = source.index("await self._discover_and_run")

    assert release < schedule < recurse
    assert "await self.source_cleanup.apply" not in source


def test_recursive_job_waits_for_descendants_and_subtree_cleanup_before_flatten():
    source = inspect.getsource(_RequestRuntime._execute_job)

    recurse = source.index("await self._discover_and_run")
    drain = source.index("await self._drain_cleanup_tasks_under")
    flatten = source.index("await self._flatten_output")

    assert recurse < drain < flatten


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


def test_discovery_batch_registers_shared_source_refs_before_dispatch():
    source = inspect.getsource(_RequestRuntime._run_discovery_batch)

    register = source.index("self.source_cleanup.register(tasks)")
    dispatch = source.index("results = await asyncio.gather")

    assert register < dispatch
