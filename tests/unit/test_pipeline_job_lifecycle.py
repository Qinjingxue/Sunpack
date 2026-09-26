from __future__ import annotations

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


def test_recursive_job_waits_for_descendants_only_before_flatten():
    source = inspect.getsource(_RequestRuntime._execute_job)

    recurse = source.index("await self._discover_and_run")
    flatten = source.index("await self._flatten_output")

    assert recurse < flatten


def test_discovery_batch_registers_shared_source_refs_before_dispatch():
    source = inspect.getsource(_RequestRuntime._run_discovery_batch)

    register = source.index("self.source_cleanup.register(tasks)")
    dispatch = source.index("results = await asyncio.gather")

    assert register < dispatch
