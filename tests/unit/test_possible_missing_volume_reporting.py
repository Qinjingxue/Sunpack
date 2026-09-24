from __future__ import annotations

import pytest

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.results import OutcomeKind
from sunpack.pipeline.coordinator.extraction_batch import _possible_missing_volume_failure
from sunpack.core.i18n import I18nContext
from tests.helpers.archive_tasks import make_archive_task, make_task_from_descriptor


def _task(*, split: bool = True, missing_indices=()):
    del missing_indices
    if not split:
        return make_archive_task("sample.7z", format_hint="7z")
    descriptor = ArchiveInputDescriptor.from_split_volumes(
        archive_path="sample.7z.001",
        volumes=[{
            "path": "sample.7z.001",
            "number": 1,
            "style": "numeric_suffix",
            "prefix": "sample.7z.",
            "width": 3,
            "role": "first",
        }],
        format_hint="7z",
        logical_name="sample",
    )
    return make_task_from_descriptor(descriptor)


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

    # Relation no longer manufactures a scan-time gap. A missing-volume
    # failure is emitted only when the extraction/backend path proves it.
    assert warning is None


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
