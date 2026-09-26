from __future__ import annotations

import contextlib

import sunpack.pipeline.coordinator.engine as engine_module
from sunpack.core.contracts.pipeline import PipelineArtifacts, PipelineResponse
from sunpack.core.contracts.results import ArchiveCleanupResult, RunSummary


def _recording(monkeypatch, barrier_calls, apply_calls, shell_calls):
    @contextlib.contextmanager
    def recording_barrier(roots, **_kwargs):
        barrier_calls.append(tuple(roots))
        yield

    class RecordingActions:
        def __init__(self, *_args, **_kwargs):
            pass

        def apply(self, **kwargs):
            apply_calls.append(kwargs)
            return []

    monkeypatch.setattr(engine_module, "promotion_barrier", recording_barrier)
    monkeypatch.setattr(engine_module, "PostProcessActions", RecordingActions)
    monkeypatch.setattr(
        engine_module,
        "notify_shell_directories_updated",
        lambda paths: shell_calls.append(tuple(paths)),
    )


def test_finalize_response_is_aggregation_only(monkeypatch):
    response = PipelineResponse(
        request_id="finalize",
        summary=RunSummary(),
        artifacts=PipelineArtifacts(shell_refresh_paths=("output",)),
    )
    barrier_calls = []
    apply_calls = []
    shell_calls = []
    _recording(monkeypatch, barrier_calls, apply_calls, shell_calls)

    finalized = engine_module._finalize_response({}, response)

    assert finalized.summary.postprocess_completed is True
    assert barrier_calls == []
    assert apply_calls == []
    assert shell_calls == [("output",)]


def test_finalize_response_retries_only_failed_cleanups(tmp_path, monkeypatch):
    archive = tmp_path / "archive.zip"
    failed = ArchiveCleanupResult(str(archive), "recycle", "failed", 1, 32, "sharing violation")
    response = PipelineResponse(
        request_id="finalize-retry",
        summary=RunSummary(cleanup_results=(failed,)),
        artifacts=PipelineArtifacts(),
    )
    barrier_calls = []
    apply_calls = []
    shell_calls = []
    _recording(monkeypatch, barrier_calls, apply_calls, shell_calls)

    finalized = engine_module._finalize_response(
        {"post_extract": {"archive_cleanup_mode": "recycle"}},
        response,
        retry_results=[failed],
    )

    assert finalized.summary.postprocess_completed is True
    assert barrier_calls == [(str(archive),)]
    assert apply_calls == [
        {
            "archives_to_clean": [(str(archive),)],
            "flatten_targets": [],
            "previous_cleanup": {engine_module.path_key(str(archive)): failed},
        }
    ]
    assert shell_calls == [()]
