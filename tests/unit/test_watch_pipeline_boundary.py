from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

from sunpack.contracts.pipeline import PipelineDiscovery
from sunpack.watch.scheduler import WatchScheduler, _response_claimed_paths


def test_watch_scheduler_public_boundary_has_no_group_resolver_parameter():
    assert "group_coordinator" not in inspect.signature(WatchScheduler).parameters


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


def test_watch_layer_does_not_import_archive_discovery_internals():
    source = Path(inspect.getsourcefile(WatchScheduler)).read_text(encoding="utf-8")
    forbidden = (
        "WatchGroupCoordinator",
        "plan_watch_dispatches",
        "DiscoveryScanSession",
        "sunpack.relations",
        "sunpack.detection",
        "split_size_family_keys",
        "apply_ordered_filters_to_entries",
    )
    assert all(token not in source for token in forbidden)
