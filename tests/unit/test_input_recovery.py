from dataclasses import replace

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.input_plan import (
    InputCheckpoint, InputRecovery, LogicalArchiveInput, recovery_blockers,
)
from sunpack.core.support.path_keys import path_key


def test_one_input_can_wait_for_password_and_volumes_without_replaying_completed_inputs(tmp_path):
    # The mixed-carrier integration test has blockers on separate inputs. This
    # case uniquely catches suppressing a password probe on the same incomplete
    # input, and proves its persisted state drops that blocker after resolution.
    first, sibling, arrived = (str(tmp_path / name) for name in ("first", "sibling", "arrived"))
    pending = LogicalArchiveInput(ArchiveInputDescriptor(first, format_hint="rar",
        analysis={"volume_completeness": "missing"}))
    complete = LogicalArchiveInput(ArchiveInputDescriptor(sibling, format_hint="zip"), position=2)
    generation = ((path_key(first), "first-generation"), (path_key(sibling), "sibling-generation"))
    password = FailureInfo(FailureKind.PASSWORD_REQUIRED, "analysis", "password required")
    recovery = InputRecovery((
        InputCheckpoint(pending, (generation[0],), str(tmp_path / "out/a"), failure=password),
        InputCheckpoint(complete, (generation[1],), str(tmp_path / "out/b"), complete=True),
    ), str(tmp_path / "out"), 2)
    failure = replace(password, details={"input_recovery": recovery.to_dict()})
    assert recovery_blockers(failure) == {"password", "missing_volume"}
    selected, carried = InputRecovery.from_failure(failure).select((pending, complete), generation, password_changed=True)
    assert [node.input_id for node in selected] == [pending.input_id]
    missing = FailureInfo(FailureKind.MISSING_VOLUME, "analysis", "volume required")
    recovery = replace(carried, checkpoints=tuple(
        replace(item, failure=missing) if item.input.input_id == pending.input_id else item
        for item in carried.checkpoints))
    assert not recovery.select((pending, complete), generation, password_changed=True)[0]
    refined = replace(pending, descriptor=replace(pending.descriptor, open_mode="native_volumes", volume_style="rar_part",
        parts=[ArchiveInputPart(InputExtent(first), volume_number=1, canonical_name="archive.part1.rar"),
               ArchiveInputPart(InputExtent(arrived), volume_number=2, canonical_name="archive.part2.rar")],
        analysis={"volume_completeness": "complete"}))
    selected, carried = recovery.select((refined, complete), (*generation, (path_key(arrived), "arrived-generation")),
                                       password_changed=False)
    assert [node.input_id for node in selected] == [pending.input_id]
    assert carried.output_dir == recovery.output_dir
    assert next(item for item in carried.checkpoints if item.input.input_id == complete.input_id).complete


def test_selected_volume_checkpoint_reuses_winner_and_preserves_shared_cleanup(tmp_path):
    # Completed winners and pending plans differ by design. This covers both
    # reuse after password retry and a completed sibling's physical dependency.
    from sunpack.core.contracts.archive_input import VolumeAttemptPlan, VolumeAttemptSlot
    from sunpack.core.contracts.tasks import ArchiveTask
    paths = [str(tmp_path / name) for name in ("head", "winner", "shared", "pending")]
    extents = tuple(InputExtent(path, 0, 100) for path in paths)
    plan = VolumeAttemptPlan(extents[:3], ((VolumeAttemptSlot(1, "x.001", (0,)),
                                           VolumeAttemptSlot(2, "x.002", (1, 2))),),
                             head_size_from_total=180)
    descriptor = ArchiveInputDescriptor(paths[0], "native_volumes", "7z", volume_style="numeric_suffix",
        parts=[ArchiveInputPart(extents[0], "first", 1, "x.001")], volume_attempts=plan)
    discovered = LogicalArchiveInput(descriptor)
    winner = replace(discovered, descriptor=descriptor.select_volumes({"layout": 0, "sources": [0, 1]}))
    generation = tuple((path_key(path), "generation") for path in paths)
    recovery = InputRecovery((InputCheckpoint(winner, generation[:2], "out/winner", complete=True),), "out", 2)
    # Alternative replacement does not replay the selected unchanged bytes.
    changed_loser = (*generation[:2], (path_key(paths[2]), "new generation"), generation[3])
    active, retained = recovery.select((discovered,), changed_loser, password_changed=True)
    assert not active and retained.output_dir == "out"
    assert retained.checkpoints[0].input.descriptor == winner.descriptor
    changed_winner = (generation[0], (path_key(paths[1]), "new generation"), *generation[2:])
    assert recovery.select((discovered,), changed_winner, password_changed=False)[0] == (discovered,)
    removed_winner = replace(discovered, descriptor=replace(descriptor, volume_attempts=replace(plan,
        layouts=((plan.layouts[0][0], VolumeAttemptSlot(2, "x.002", (2,))),))))
    assert recovery.select((removed_winner,), generation, password_changed=False)[0]

    sibling = LogicalArchiveInput(ArchiveInputDescriptor(paths[2], format_hint="zip"))
    task = ArchiveTask.from_archive_input(descriptor, discovery_source="test")
    task.recovery = InputRecovery((InputCheckpoint(sibling, (generation[2],), "out/sibling", complete=True),))
    task.select_volumes(discovered, winner.descriptor)
    assert set(task.cleanup_parts) == set(paths[:3])

    # Reusing a winner bypasses extraction/select_volumes. Reconcile the same
    # cleanup lease on retry, including shared active and completed inputs.
    from sunpack.core.contracts.retry_targets import apply_input_retry
    from sunpack.pipeline.coordinator.cleanup_refs import CleanupRefTable
    pending = LogicalArchiveInput(ArchiveInputDescriptor(paths[3], format_hint="zip"), position=2)
    password = FailureInfo(FailureKind.PASSWORD_REQUIRED, "extraction", "password required")
    for shared in ("none", "active", "checkpoint"):
        checkpoints = [*recovery.checkpoints,
            InputCheckpoint(pending, (generation[3],), "out/pending", failure=password)]
        inputs = (discovered, pending)
        if shared != "none":
            inputs += (sibling,)
            if shared == "checkpoint":
                checkpoints.append(InputCheckpoint(sibling, (changed_loser[2],), "out/sibling", complete=True))
        failure = replace(password, details={"input_recovery": replace(recovery, checkpoints=tuple(checkpoints)).to_dict()})
        task = ArchiveTask.from_archive_input(descriptor, discovery_source="test", logical_inputs=inputs)
        refs = CleanupRefTable()
        refs.register(task)
        apply_input_retry(task, failure, changed_loser)
        assert discovered.input_id not in {node.input_id for node in task.inputs}
        if shared == "checkpoint":
            assert sibling.input_id not in {node.input_id for node in task.inputs}
        refs.refresh(task)
        refs.mark_cleanup_eligible(task)
        released = set(refs.release(task).cleanup_paths)
        assert released == set(paths if shared != "none" else (paths[0], paths[1], paths[3]))


def test_discarded_partial_retry_marker_is_not_output_evidence(tmp_path):
    # Aggregate extraction covers the policy transition. This cheap contract
    # test uniquely covers persisted/remapped markers, a second requirement
    # change before execution, and unknown failures without discarded proof.
    from sunpack.core.contracts.retry_targets import apply_input_retry, remap_retry_failure
    from sunpack.core.contracts.tasks import ArchiveTask
    from sunpack.pipeline.coordinator.input_completion import checkpoint_inputs
    from sunpack.core.contracts.extraction import ExtractionResult

    source = str(tmp_path / "source")
    moved = str(tmp_path / "moved")
    node = LogicalArchiveInput(ArchiveInputDescriptor(source, format_hint="zip"))
    generation = ((path_key(source), "generation"),)
    damaged = FailureInfo(FailureKind.DAMAGED, "extract", "damaged")
    checkpoint = InputCheckpoint(node, generation, failure=damaged, discarded_recoverable_output=True)
    failure = replace(damaged, details={"input_recovery": InputRecovery((checkpoint,), input_count=1).to_dict()})
    moved_generation = ((path_key(moved), "generation"),)
    remapped = remap_retry_failure(failure, {source: moved}, moved_generation)
    recovery = InputRecovery.from_failure(remapped).relocate_outputs(lambda path: path)
    moved_node = replace(node, descriptor=node.descriptor.with_path_mapping(lambda _path: moved))
    assert recovery.checkpoints[0].discarded_recoverable_output
    assert not recovery.output_dir and not recovery.checkpoints[0].output_dir
    assert not recovery.checkpoints[0].recovered_complete_files
    assert recovery.select((moved_node,), moved_generation, password_changed=False, recover_partial=True)[0] == (moved_node,)
    assert not recovery.select((moved_node,), moved_generation, password_changed=True)[0]
    # Old checkpoints are still readable; no lost-proof marker is invented.
    old = checkpoint.to_dict()
    old.pop("discarded_recoverable_output")
    assert not InputCheckpoint.from_dict(old).discarded_recoverable_output

    task = ArchiveTask.from_archive_input(moved_node.descriptor, discovery_source="test")
    task.runtime["input_generation"] = moved_generation
    apply_input_retry(task, remapped, moved_generation, recover_partial=True)
    # A fresh attempt without recoverable members consumes the marker, even
    # when it fails again. Merely keeping allow_partial must not replay it.
    fresh = ExtractionResult(False, "", failure=FailureInfo(FailureKind.UNKNOWN, "extract", "unknown"),
                             logical_input=moved_node)
    checkpoint_inputs(task, fresh)
    assert not task.recovery.checkpoints[0].discarded_recoverable_output
    assert not InputRecovery.from_failure(fresh.failure).select(
        (moved_node,), moved_generation, password_changed=True, recover_partial=True,
    )[0]
