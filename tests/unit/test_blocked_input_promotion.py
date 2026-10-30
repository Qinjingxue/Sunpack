from __future__ import annotations

import asyncio
from pathlib import Path
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


def test_collision_renames_extension_and_preserves_entire_group(tmp_path):
    source = tmp_path / "out"
    destination = tmp_path / "input"
    source.mkdir()
    destination.mkdir()
    first, second = source / "a.001", source / "a.002"
    first.write_text("first")
    second.write_text("second")
    (destination / second.name).write_text("existing")
    result = promote_blocked_input([str(first), str(second)], str(destination))
    assert not first.exists() and not second.exists()
    assert Path(result.path_map[str(first)]).read_text() == "first"
    renamed = Path(result.path_map[str(second)])
    assert renamed.name.startswith(second.name + ".")
    assert not any(char.isdigit() for char in renamed.name[len(second.name):])
    assert renamed.read_text() == "second"
    assert (destination / second.name).read_text() == "existing"


def test_failed_promotion_precommit_leaves_all_sources_untouched(tmp_path):
    # Collision and rollback tests do not catch movement after a rejected WAL
    # barrier; that would recreate the original crash window on disk errors.
    source, destination = tmp_path / "out", tmp_path / "input"
    source.mkdir()
    destination.mkdir()
    parts = [source / name for name in ("inner.data.001", "inner.data.002")]
    for path in parts:
        path.write_text(path.name)

    def reject():
        raise OSError("injected WAL failure")

    with pytest.raises(OSError, match="injected WAL failure"):
        promote_blocked_input(map(str, parts), str(destination), before_move=reject)
    assert all(path.read_text() == path.name for path in parts)
    assert not list(destination.iterdir())


@pytest.mark.parametrize("collision", [False, True, "lease", "move", "denied"])
@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("kind", [FailureKind.WRONG_PASSWORD, FailureKind.MISSING_VOLUME])
def test_coordinator_rewrites_recorded_result_and_cleanup_input(tmp_path, collision, origin, kind):
    async def scenario():
        source = tmp_path / "out" / "deep" / "nested"
        source.mkdir(parents=True)
        top = tmp_path / "input"
        top.mkdir()
        outer = top / "outer.zip"
        outer.write_text("outer")
        inner = source / "inner.rar"
        inner.write_text("inner")
        if collision is True:
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
            failure=FailureInfo(kind, "extraction", "blocked input"))
        runtime = object.__new__(_RequestRuntime)
        runtime.context = RunState()
        runtime.context.add_target_result(original)
        runtime.submission = submission
        runtime._shell_updates = SimpleNamespace(add=lambda paths: None)
        from sunpack.pipeline.coordinator.engine import _PathLeaseRegistry
        runtime.path_leases = _PathLeaseRegistry()
        # An active sibling request owns the colliding destination. Waiting
        # for it would deadlock if its own nested input needs our parent.
        parent = str(top / "pinned-parent.zip")
        await runtime.path_leases.acquire("request", [parent], lease_id="parent")
        if collision is True:
            await runtime.path_leases.acquire("sibling", [str(top / inner.name)], lease_id="parent")
        raced = False
        acquire = runtime.path_leases.acquire

        async def race_acquire(*args, **kwargs):
            nonlocal raced
            if collision == "lease" and not raced:
                raced = True
                (top / inner.name).write_text("existing")
            return await acquire(*args, **kwargs)

        runtime.path_leases.acquire = race_acquire
        claims = []
        runtime._report_progress = lambda task, event: claims.append(event)

        class Broker:
            async def run(self, stage, key, function, **kwargs):
                nonlocal raced
                if function.__name__ == "promote":
                    if collision == "denied":
                        raise PermissionError("injected access denial")
                    if origin == "watch":
                        source_path, target_path = claims[-1]["source_paths"]
                        assert source_path == str(inner) and not Path(target_path).exists()
                    if collision == "move" and not raced:
                        raced = True
                        (top / inner.name).write_text("existing")
                return function()

        result, promoted = await asyncio.wait_for(runtime._promote_blocked_input(
            task, original, ownership=ownership, broker=Broker(), cancellation=None,
        ), timeout=3)
        assert runtime.path_leases.holds_lease("request", [parent], lease_id="parent")
        assert not runtime.path_leases._waiter_blockers
        assert runtime.context.target_results == [result]
        assert result.outcome_kind == OutcomeKind.FAILURE
        if collision == "denied":
            assert not promoted and inner.read_text() == "inner"
            assert result.failure.kind == FailureKind.FILESYSTEM_ERROR
            assert result.failure.causes == (original.failure,)
            assert result.failure.contains(kind)
            return
        target = Path(result.input_path)
        assert promoted and not inner.exists() and target.read_text() == "inner"
        assert target.parent == top and target.name.startswith(inner.name)
        assert (target.name != inner.name) == bool(collision)
        if collision:
            assert (top / inner.name).read_text() == "existing"
        assert result.failure is not original.failure
        assert result.failure.kind == original.failure.kind
        assert result.failure.message == original.failure.message
        assert result.failure.details["promoted_nested_input"] is True
        assert result.failure.details["discovery_scope"]["root"] == str(top)
        assert original.failure.details == {}
        assert task.cleanup_parts == [str(target)]
        if origin == "watch":
            intent = [event for event in claims if "promoted_destinations" in event]
            assert len(intent) == 1 and intent[0]["promoted_destinations"] == [str(target)]
            assert claims[-1]["promoted_nested_input"] is True
            assert claims[-1]["groups"] == [{
                "path": str(target), "name": target.name, "members": [str(target)],
            }]
        assert ownership.response(runtime.context, recent_passwords=()).discovery.blocked_paths == (str(target),)

    asyncio.run(scenario())


def test_stop_while_waiting_to_publish_group_keeps_sources_and_parent_pin(tmp_path):
    # Collision tests terminate before waiting. They cannot catch a publication
    # blocked by another request's reservation ignoring the user's stop token.
    from sunpack.pipeline.coordinator.async_work import CancellationToken
    from sunpack.pipeline.coordinator.engine import _PathLeaseRegistry

    async def scenario():
        source, destination = tmp_path / "nested", tmp_path / "input"
        source.mkdir()
        destination.mkdir()
        parts = [source / name for name in ("inner.blob.001", "inner.blob.002")]
        for path in parts:
            path.write_text(path.name)
        task = SimpleNamespace(cleanup_parts=list(map(str, parts)), key="inner", main_path=str(parts[0]))
        registry = _PathLeaseRegistry()
        parent = str(destination / "outer.zip")
        await registry.acquire("request", [parent], lease_id="parent")
        await registry.acquire("other", [str(destination / parts[-1].name)])
        token = CancellationToken()
        waiting = asyncio.Event()
        register = registry._register_waiter

        def observe(blockers):
            future = register(blockers)
            waiting.set()
            return future

        registry._register_waiter = observe
        runtime = object.__new__(_RequestRuntime)
        runtime.submission = SimpleNamespace(request_id="request", origin="watch")
        runtime.path_leases = registry
        class Broker:
            async def run(self, stage, key, function, **kwargs):
                return function()

        operation = asyncio.create_task(runtime._promote_blocked_input(
            task, None, ownership=SimpleNamespace(input_dir_for_task=lambda _task: str(destination)),
            broker=Broker(), cancellation=token,
        ))
        await asyncio.wait_for(waiting.wait(), 3)
        token.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(operation, 3)
        assert all(path.read_text() == path.name for path in parts)
        assert not list(destination.iterdir())
        assert registry.holds_lease("request", [parent], lease_id="parent")
        assert not registry._waiter_blockers and not registry._waiters_by_blocker
        assert not token._callbacks

    asyncio.run(scenario())
