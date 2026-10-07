from __future__ import annotations

from types import SimpleNamespace
import asyncio
import pytest

from sunpack.core.contracts.pipeline import PipelineDiscovery
from sunpack.pipeline.coordinator.engine import _CompletedWatchOutput, _PathLeaseRegistry, _RequestRuntime
from sunpack.runtime.watch.scheduler import _response_claimed_paths


def test_watch_consumes_pipeline_claimed_paths_without_reconstructing_membership(tmp_path):
    first = tmp_path / "archive.7z.001"
    second = tmp_path / "archive.7z.002"
    response = SimpleNamespace(
        discovery=PipelineDiscovery(
            entry_paths=(str(second),),
            claimed_paths=(str(first), str(second)),
        )
    )

    assert _response_claimed_paths(response, str(second)) == [
        str(first),
        str(second),
    ]


def test_watch_completed_generation_records_complete_physical_family(tmp_path):
    first = str(tmp_path / "archive.7z.001")
    second = str(tmp_path / "archive.7z.002")
    version = (("first", 1, 2, 3, 4), ("second", 1, 2, 3, 4))
    calls = []

    runtime = object.__new__(_RequestRuntime)
    runtime.submission = SimpleNamespace(origin="watch", request_id="request")
    runtime.path_leases = SimpleNamespace(
        ownership_version_for=lambda owner, paths: calls.append((owner, paths)) or version,
    )

    descriptor = SimpleNamespace(part_paths=lambda: (first, second))
    data_task = SimpleNamespace(
        archive_input=lambda: descriptor,
        carrier_path=first,
    )
    launcher_task = SimpleNamespace(
        archive_input=lambda: descriptor,
        carrier_path=str(tmp_path / "archive.exe"),
    )

    assert runtime._watch_generation_for_task(data_task, depth=1) == version
    assert calls == [("request", (first, second))]
    assert runtime._watch_generation_for_task(launcher_task, depth=1) == version
    assert runtime._watch_generation_for_task(data_task, depth=2) == ()


def test_retry_checks_completed_final_family_after_acquiring_lease(tmp_path):
    async def scenario():
        parts = [tmp_path / "a.001", tmp_path / "a.002"]
        for path in parts:
            path.write_text("part")
        output = tmp_path / "output"
        output.mkdir()
        registry = _PathLeaseRegistry()
        registry.remember_completed_watch(registry.input_version_for(map(str, parts)), str(output))
        runtime = object.__new__(_RequestRuntime)
        runtime.path_leases = registry
        runtime.submission = SimpleNamespace(origin="watch", request_id="retry",
            detection_options=SimpleNamespace(force_scan=False))
        runtime.source_cleanup = SimpleNamespace(register=lambda tasks: None)
        runtime._report_progress = lambda task, event: None
        task = SimpleNamespace(all_parts=list(map(str, parts)), cleanup_parts=[], runtime={})
        with pytest.raises(_CompletedWatchOutput) as stopped:
            await runtime._ensure_task_lease(task)
        assert stopped.value.output_dir == str(output)
        await registry.release("retry")
        # A changed physical member invalidates the entire completed generation.
        parts[1].write_text("changed part")
        await runtime._ensure_task_lease(task)
        await registry.release("retry")

    asyncio.run(scenario())


def test_consumed_family_generation_rejects_changed_surviving_member(tmp_path):
    registry = _PathLeaseRegistry()
    first, second = tmp_path / "a.001", tmp_path / "a.002"
    first.write_text("first")
    second.write_text("second")
    paths = [str(first), str(second)]
    original = registry.input_version_for(paths)
    first.unlink()
    assert registry.input_version_for(paths, departed_version=original) == original
    second.write_text("changed second")
    assert registry.input_version_for(paths, departed_version=original) == ()


def test_late_completed_generation_lookup_preserves_newer_record(tmp_path):
    registry = _PathLeaseRegistry()
    path = tmp_path / "a.001"
    path.write_text("generation A")
    first = registry.input_version_for([str(path)])
    output_a, output_b = tmp_path / "out-a", tmp_path / "out-b"
    output_a.mkdir()
    output_b.mkdir()
    registry.remember_completed_watch(first, str(output_a))
    path.write_text("generation B with different bytes")
    second = registry.input_version_for([str(path)])
    assert first != second
    registry.remember_completed_watch(second, str(output_b))
    assert registry.completed_watch_output(first) == ""
    assert registry.completed_watch_output(second) == str(output_b)
    output_b.rmdir()
    assert registry.completed_watch_output(second) == ""
    assert not registry._completed_watch_generations

