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
