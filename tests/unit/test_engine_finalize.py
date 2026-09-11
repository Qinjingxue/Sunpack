from __future__ import annotations

import contextlib

import pytest

import sunpack.coordinator.engine as engine_module
from sunpack.contracts.pipeline import PipelineArtifacts, PipelineResponse
from sunpack.contracts.results import ArchiveCleanupResult, RunSummary


def _recording(monkeypatch, barrier_calls, apply_calls):
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
    monkeypatch.setattr(engine_module, "notify_shell_directories_updated", lambda _paths: None)


@pytest.mark.parametrize(
    ("flatten_enabled", "expected_roots"),
    [
        (False, ()),
        (True, ("output",)),
    ],
)
def test_finalize_response_gates_only_flatten_targets(
    tmp_path,
    monkeypatch,
    flatten_enabled,
    expected_roots,
):
    """Source archives are removed per task, so finalize only gates flattening."""

    output = tmp_path / "output"
    response = PipelineResponse(
        request_id="finalize-roots",
        summary=RunSummary(success_count=1, failed_tasks=[], processed_keys=[]),
        artifacts=PipelineArtifacts(flatten_targets=(str(output),)),
    )
    barrier_calls: list[tuple[str, ...]] = []
    apply_calls: list[dict] = []
    _recording(monkeypatch, barrier_calls, apply_calls)

    engine_module._finalize_response(
        {"post_extract": {"archive_cleanup_mode": "recycle", "flatten_single_directory": flatten_enabled}},
        response,
    )

    expected = tuple(str(tmp_path / name) for name in expected_roots)
    assert barrier_calls == ([expected] if expected else [])
    assert apply_calls == [
        {
            "archives_to_clean": [],
            "flatten_targets": [str(output)] if flatten_enabled else [],
            "previous_cleanup": None,
        }
    ]


def test_finalize_response_retries_only_failed_cleanups(tmp_path, monkeypatch):
    """The retry pass deletes the failed leftovers and never flattens."""

    archive = tmp_path / "archive.zip"
    output = tmp_path / "output"
    failed = ArchiveCleanupResult(str(archive), "recycle", "failed", 1, 32, "sharing violation")
    response = PipelineResponse(
        request_id="finalize-retry",
        summary=RunSummary(success_count=1, failed_tasks=[], processed_keys=[]),
        artifacts=PipelineArtifacts(flatten_targets=(str(output),)),
    )
    barrier_calls: list[tuple[str, ...]] = []
    apply_calls: list[dict] = []
    _recording(monkeypatch, barrier_calls, apply_calls)

    engine_module._finalize_response(
        {"post_extract": {"archive_cleanup_mode": "recycle", "flatten_single_directory": True}},
        response,
        retry_results=[failed],
    )

    assert barrier_calls == [(str(archive),)]
    assert apply_calls == [
        {
            "archives_to_clean": [(str(archive),)],
            "flatten_targets": [],
            "previous_cleanup": {engine_module.path_key(str(archive)): failed},
        }
    ]
