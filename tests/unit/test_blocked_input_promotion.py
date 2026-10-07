from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.pipeline import PipelineTarget
from sunpack.core.contracts.results import OutcomeKind, TargetRunResult
from sunpack.core.contracts.run_state import RunState
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.coordinator.engine import _RequestResults, _RequestRuntime, _should_promote_blocked_input
from sunpack.pipeline.postprocess.internal.blocked_input import promote_blocked_input


@pytest.mark.parametrize("depth,outcome,kind,expected", [
    (1, OutcomeKind.FAILURE, FailureKind.WRONG_PASSWORD, False),
    (2, OutcomeKind.FAILURE, FailureKind.WRONG_PASSWORD, True),
    (4, OutcomeKind.FAILURE, FailureKind.MISSING_VOLUME, True),
    (2, OutcomeKind.PARTIAL_SUCCESS, FailureKind.MISSING_VOLUME, False),
    (2, OutcomeKind.FAILURE, FailureKind.PASSWORD_INCONCLUSIVE, False),
    (2, OutcomeKind.FAILURE, FailureKind.DAMAGED, False),
    (2, OutcomeKind.FAILURE, FailureKind.UNSUPPORTED, False),
])
def test_only_blocked_nested_failures_are_promoted(depth, outcome, kind, expected):
    assert _should_promote_blocked_input(depth, outcome, FailureInfo(kind, "extraction", "failure")) == expected


@pytest.mark.parametrize("keep_sibling", [False, True])
def test_moves_complete_physical_group_preserving_names(tmp_path, keep_sibling):
    source = tmp_path / "out" / "nested"
    destination = tmp_path / "input"
    source.mkdir(parents=True)
    destination.mkdir()
    parts = [source / name for name in ("game.part1.rar", "game.part2.rar", "carrier.exe")]
    for path in parts:
        path.write_text(path.name)
    if keep_sibling:
        (source / "readme.txt").write_text("keep")
    result = promote_blocked_input(map(str, parts), str(destination))
    assert set(result.path_map) == set(map(str, parts))
    assert all((destination / path.name).read_text() == path.name for path in parts)
    assert source.exists() == keep_sibling
    assert source.parent.exists()


def test_collision_preflights_entire_group(tmp_path):
    source = tmp_path / "out"
    destination = tmp_path / "input"
    source.mkdir()
    destination.mkdir()
    first, second = source / "a.001", source / "a.002"
    first.write_text("first")
    second.write_text("second")
    (destination / second.name).write_text("existing")
    with pytest.raises(OSError):
        promote_blocked_input([str(first), str(second)], str(destination))
    assert first.exists() and second.exists()
    assert not (destination / first.name).exists()
    assert (destination / second.name).read_text() == "existing"


@pytest.mark.parametrize("collision", [False, True])
@pytest.mark.parametrize("origin", ["foreground", "watch"])
def test_coordinator_rewrites_recorded_result_and_cleanup_input(tmp_path, collision, origin):
    async def scenario():
        source = tmp_path / "out" / "deep" / "nested"
        source.mkdir(parents=True)
        top = tmp_path / "input"
        top.mkdir()
        outer = top / "outer.zip"
        outer.write_text("outer")
        inner = source / "inner.rar"
        inner.write_text("inner")
        if collision:
            (top / inner.name).write_text("existing")
        task = ArchiveTask.from_archive_input(
            ArchiveInputDescriptor(str(inner)), discovery_source="test",
        )
        submission = SimpleNamespace(targets=(PipelineTarget(str(outer)),), request_id="request", origin=origin)
        ownership = _RequestResults(submission, {})
        ownership.remember_results([TargetRunResult(str(outer), OutcomeKind.COMPLETE_SUCCESS, output_dir=str(tmp_path / "out"))])
        ownership.remember_tasks([task])
        # Snapshot survives removal of the original top-level archive.
        outer.unlink()
        original = TargetRunResult(str(inner), OutcomeKind.FAILURE,
            failure=FailureInfo(FailureKind.WRONG_PASSWORD, "extraction", "wrong password"))
        runtime = object.__new__(_RequestRuntime)
        runtime.context = RunState()
        runtime.context.target_results.append(original)
        runtime.submission = submission
        runtime._shell_updates = SimpleNamespace(add=lambda paths: None)
        from sunpack.pipeline.coordinator.engine import _PathLeaseRegistry
        runtime.path_leases = _PathLeaseRegistry()
        claims = []
        runtime._report_progress = lambda task, event: claims.append(event)

        class Broker:
            async def run(self, stage, key, function, **kwargs):
                if origin == "watch":
                    assert claims == [{
                        "type": "semantic", "event": "task_sources_claimed",
                        "source_paths": (str(inner), str(top / inner.name)),
                    }]
                    assert not (top / inner.name).exists() or collision
                else:
                    assert not claims
                return function()

        result, promoted = await runtime._promote_blocked_input(
            task, original, ownership=ownership, broker=Broker(), cancellation=None,
        )
        assert runtime.context.target_results == [result]
        assert result.outcome_kind == OutcomeKind.FAILURE
        if collision:
            assert not promoted and inner.exists()
            assert result.failure.kind == FailureKind.FILESYSTEM_ERROR
            assert not result.failure.is_password_failure
            assert result.failure.details["blocked_input_failure"]["kind"] == "wrong_password"
        else:
            assert promoted and result.input_path == str(top / inner.name)
            assert result.failure is original.failure
            assert task.cleanup_parts == [str(top / inner.name)]
            assert ownership.response(runtime.context, recent_passwords=()).discovery.blocked_paths == (str(top / inner.name),)

    asyncio.run(scenario())
