from pathlib import Path
from dataclasses import replace

import pytest

from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.results import OutcomeKind, RunSummary, TargetRunResult
from sunpack.core.contracts.retry_targets import merge_latest_results, password_retry_paths, result_outcome


@pytest.mark.parametrize("mode", ["file", "file_range", "concat_ranges", "native_volumes", "sfx_with_volumes"])
def test_input_retry_distinguishes_provenance_from_changed_execution_facts(tmp_path, mode):
    # Mixed-input integration tests change passwords and arriving files, but do
    # not change analysis with an unchanged generation. Cover that wakeup rule
    # and advisory-only reuse for every input mapping without any archive I/O.
    from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
    from sunpack.core.contracts.input_plan import InputCheckpoint, InputRecovery, LogicalArchiveInput
    from sunpack.core.support.path_keys import path_key

    path = str(tmp_path / "disguised.bin")
    extent = InputExtent(path, 19, 512)
    descriptor = ArchiveInputDescriptor(
        path, open_mode=mode, format_hint="rar", logical_name="payload",
        volume_style="rar_part" if "volumes" in mode else "",
        parts=[ArchiveInputPart(extent, volume_number=1, canonical_name="payload.part1.rar")],
        extents=[extent] if mode == "concat_ranges" else [],
        analysis={"needs_password": True, "segment_confidence": 0.9},
    )
    generation = ((path_key(path), 512, 100),)
    failure = FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "password required")
    original = LogicalArchiveInput(descriptor)
    recovery = InputRecovery((InputCheckpoint(original, generation, failure=failure),))
    # Exercise the actual persisted shape, which intentionally drops provenance.
    recovery = InputRecovery.from_failure(FailureInfo(
        FailureKind.WRONG_PASSWORD, "password_resolution", "password required",
        details={"input_recovery": recovery.to_dict()},
    ))
    advisory = replace(original, descriptor=replace(descriptor, analysis={
        **descriptor.analysis, "segment_confidence": 0.8, "segment_source": "new scan",
    }))
    selected, carried = recovery.select((advisory,), generation, password_changed=False)
    assert not selected and len(carried.checkpoints) == 1
    assert recovery.select((advisory,), generation, password_changed=True)[0] == (advisory,)

    changed_extent = replace(extent, end=513)
    changes = [
        replace(descriptor, analysis={**descriptor.analysis, "needs_password": False}),
        replace(descriptor, parts=[replace(descriptor.parts[0], extent=changed_extent)]),
        replace(descriptor, logical_name="different output"),
    ]
    if mode == "concat_ranges":
        changes.append(replace(descriptor, extents=[changed_extent]))
    for changed in changes:
        node = replace(original, descriptor=changed)
        assert recovery.select((node,), generation, password_changed=False)[0] == (node,)


def _summary(*results):
    return RunSummary(target_results=list(results))


def test_password_retry_paths_are_task_scoped(tmp_path):
    outer = tmp_path / "outer.zip"
    inner = tmp_path / "inner.zip"
    failure = FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")
    summary = _summary(
        TargetRunResult(str(outer), OutcomeKind.COMPLETE_SUCCESS),
        TargetRunResult(str(inner), OutcomeKind.FAILURE, error="wrong password", failure=failure),
    )
    assert password_retry_paths(summary) == [str(inner)]


def test_missing_volume_is_never_a_password_retry_target(tmp_path):
    archive = tmp_path / "inner.7z.001"
    failure = FailureInfo(
        FailureKind.MISSING_VOLUME,
        "extraction",
        "missing volume and password",
        causes=(FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password"),),
    )
    summary = _summary(
        TargetRunResult(str(archive), OutcomeKind.FAILURE, error="missing volume", failure=failure)
    )
    assert password_retry_paths(summary) == []


def test_latest_result_ledger_keeps_unrelated_terminal_failure(tmp_path):
    outer = tmp_path / "outer.zip"
    password_archive = tmp_path / "password.zip"
    missing_archive = tmp_path / "missing.7z.001"
    password = FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")
    missing = FailureInfo(FailureKind.MISSING_VOLUME, "extraction", "missing volume")
    first = _summary(
        TargetRunResult(str(outer), OutcomeKind.COMPLETE_SUCCESS),
        TargetRunResult(str(password_archive), OutcomeKind.FAILURE, error="wrong password", failure=password),
        TargetRunResult(str(missing_archive), OutcomeKind.FAILURE, error="missing volume", failure=missing),
    )
    second = _summary(TargetRunResult(str(password_archive), OutcomeKind.COMPLETE_SUCCESS))
    latest = {}
    merge_latest_results(latest, first)
    merge_latest_results(latest, second)
    outcomes = {Path(item.input_path).name: result_outcome(item) for item in latest.values()}
    assert outcomes == {
        "outer.zip": OutcomeKind.COMPLETE_SUCCESS,
        "password.zip": OutcomeKind.COMPLETE_SUCCESS,
        "missing.7z.001": OutcomeKind.FAILURE,
    }
