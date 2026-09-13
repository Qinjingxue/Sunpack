from __future__ import annotations

import pytest

from sunpack.contracts.detection import FactBag
from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.contracts.results import OutcomeKind
from sunpack.contracts.tasks import ArchiveTask, SplitArchiveInfo
from sunpack.coordinator.extraction_batch import _possible_missing_volume_failure
from sunpack.i18n import I18nContext


def _task(*, split: bool = True, missing_indices=()) -> ArchiveTask:
    bag = FactBag()
    bag.set("relation.is_split_related", split)
    if missing_indices:
        bag.set("relation.split_missing_indices", list(missing_indices))
    return ArchiveTask(
        fact_bag=bag,
        main_path="sample.7z.001" if split else "sample.7z",
        all_parts=["sample.7z.001"] if split else ["sample.7z"],
        split_info=SplitArchiveInfo(is_split=split),
    )


def _failure(kind: FailureKind, *, details=None) -> FailureInfo:
    return FailureInfo(kind, "extraction", kind.value, details=dict(details or {}))


def test_partial_split_recovery_reports_possible_missing_without_changing_outcome():
    warning = _possible_missing_volume_failure(
        _task(),
        OutcomeKind.PARTIAL_SUCCESS,
        None,
        I18nContext("zh"),
    )

    assert warning is not None
    assert warning.kind is FailureKind.MISSING_VOLUME
    assert warning.details["missing_volume_confirmed"] is False
    assert warning.details["partial_recovery"] is True
    assert "可能缺少" in warning.message


def test_actual_archive_failure_plus_observed_gap_reports_possible_missing_and_keeps_cause():
    original = _failure(FailureKind.UNKNOWN)

    warning = _possible_missing_volume_failure(
        _task(missing_indices=(2,)),
        OutcomeKind.FAILURE,
        original,
        I18nContext("en"),
    )

    assert warning is not None
    assert warning.causes == (original,)
    assert warning.details["observed_missing_indices"] == [2]
    assert warning.details["evidence"] == "observed_volume_gap_after_archive_failure"


def test_backend_possible_missing_probe_is_promoted_after_real_failure():
    original = _failure(
        FailureKind.DAMAGED,
        details={"missing_volume_confirmed": False, "evidence": "tail_size_heuristic"},
    )

    warning = _possible_missing_volume_failure(
        _task(),
        OutcomeKind.FAILURE,
        original,
        I18nContext("en"),
    )

    assert warning is not None
    assert warning.details["evidence"] == "backend_possible_missing_volume"
    assert warning.causes == (original,)


@pytest.mark.parametrize(
    "kind",
    [
        FailureKind.WRONG_PASSWORD,
        FailureKind.PASSWORD_INCONCLUSIVE,
        FailureKind.UNSUPPORTED,
        FailureKind.BACKEND_UNAVAILABLE,
        FailureKind.FILESYSTEM_ERROR,
        FailureKind.PROCESS_ERROR,
    ],
)
def test_unrelated_runtime_failures_are_not_promoted_by_filename_gap(kind):
    assert _possible_missing_volume_failure(
        _task(missing_indices=(2,)),
        OutcomeKind.FAILURE,
        _failure(kind),
        I18nContext("en"),
    ) is None


def test_complete_or_non_split_result_never_reports_possible_missing():
    assert _possible_missing_volume_failure(
        _task(missing_indices=(2,)),
        OutcomeKind.COMPLETE_SUCCESS,
        None,
        I18nContext("en"),
    ) is None
    assert _possible_missing_volume_failure(
        _task(split=False),
        OutcomeKind.PARTIAL_SUCCESS,
        None,
        I18nContext("en"),
    ) is None
