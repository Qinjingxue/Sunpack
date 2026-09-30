from __future__ import annotations

from types import SimpleNamespace

from sunpack.core.contracts.pipeline import PipelineDiscovery
from sunpack.pipeline.coordinator.engine import _RequestRuntime
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


def test_watch_completed_generation_records_data_parts_and_reuses_only_external_carrier(tmp_path):
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
    assert not runtime._watch_task_can_reuse_completed(data_task)
    assert runtime._watch_task_can_reuse_completed(launcher_task)
    assert runtime._watch_generation_for_task(data_task, depth=2) == ()

