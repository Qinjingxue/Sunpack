import asyncio
from types import SimpleNamespace

import pytest

import sunpack.runtime.watch.scheduler as scheduler_module
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.runtime.watch.scheduler import WatchScheduler
from sunpack.runtime.watch.state import WatchStateStore
from tests.helpers.config_factory import make_config
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.real.plan1_real_archives.plan1_support import assert_expected_files_extracted


@pytest.mark.parametrize("provenance", ["live_claim", "persisted_blocker"])
def test_watch_promoted_sibling_controls_verified_group_cleanup(tmp_path, monkeypatch, provenance):
    # Timing-dependent download tests cannot guarantee either provenance handoff.
    # Two small real extractions cover publication before failure persistence and
    # reopening the durable blocker, including regrouping from an unmarked tail.
    monkeypatch.setattr(scheduler_module, "validate_ntfs_watch_roots", lambda _roots: None)
    case = ArchiveFixtureFactory().create(
        tmp_path / "fixtures", "promoted", "7z", password="known",
        split=True, payload_size=128 * 1024, split_volume_size=64 * 1024,
    )
    parts = sorted(case.archive_dir.iterdir())
    assert len(parts) > 1
    head, tail = parts[0], parts[-1]
    state_path = str(tmp_path / "state.snapshot")
    if provenance == "persisted_blocker":
        state = WatchStateStore(state_path)
        try:
            candidate = scheduler_module._candidate_for_event_path(str(head))
            state.mark(
                candidate.path, candidate.size, candidate.mtime,
                file_id=candidate.file_id, change_usn=candidate.change_usn,
                status="suspended_missing_volume",
                failure_payload={
                    "kind": "missing_volume", "blockers": ["missing_volume"],
                    "details": {"promoted_nested_input": True},
                },
            )
        finally:
            state.close()
    output = tmp_path / "out"
    config = make_config({
        "detection": {"enabled": True},
        "user_passwords": ["known"],
        "watch": {"clipboard_monitor_enabled": False},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    })

    async def scenario():
        async with PipelineEngine(config) as engine:
            watcher = WatchScheduler(
                config, [str(case.archive_dir)], out_dir=str(output),
                state_path=state_path, cold_start_seconds=0, pipeline_engine=engine,
            )
            try:
                watcher._scan_initial_roots([str(case.archive_dir)])
                if provenance == "live_claim":
                    watcher._handle_pipeline_progress(str(head), "publisher", SimpleNamespace(runtime={}), {
                        "event": "task_sources_claimed", "source_paths": (str(head),),
                        "promoted_nested_input": True,
                    })
                    assert not watcher.state.entries
                assert watcher.state.latest_entry_for_path(str(tail)) is None
                request = await watcher._submit_candidate(
                    scheduler_module._candidate_for_event_path(str(tail)),
                )
                assert request is not None
                result = await watcher._finish_active_request(request)
                watcher._release_pipeline_source_claims("publisher")
                assert result.succeeded == 1 and not result.errors
                assert_expected_files_extracted(case, output)
                assert not any(part.exists() for part in parts)
                assert not watcher.state.entries and not watcher._active_claims
            finally:
                await watcher.aclose()

    asyncio.run(asyncio.wait_for(scenario(), timeout=20))
