import json
import subprocess

import pytest

from sunpack.extraction.internal.workflow.errors import classify_extract_failure
from sunpack.contracts.failures import FailureKind
from sunpack.passwords.result import PasswordResolution, PasswordResolutionStatus
from sunpack.extraction.internal.workflow.single_archive_extractor import SingleArchiveExtractor
from sunpack.i18n import I18nContext


def test_split_worker_damage_takes_precedence_over_wrong_password_signal():
    completed = _worker_completed({
        "wrong_password": True,
        "damaged": True,
        "checksum_error": True,
        "missing_volume": False,
        "native_status": "wrong_password",
        "failure_kind": "checksum_error",
    })

    failure = classify_extract_failure(
        completed,
        "",
        archive="payload.7z.001",
        is_split_archive=True,
    )

    assert failure.message_key == "failure.damaged"


def test_unknown_empty_password_on_split_input_is_not_conclusive_password_evidence():
    resolution = PasswordResolution(
        password="",
        status=PasswordResolutionStatus.RESOLVED,
        encrypted=None,
        requires_extraction_confirmation=True,
    )
    original = classify_extract_failure(
        _worker_completed({"wrong_password": True, "native_status": "wrong_password"}),
        "",
        archive="payload.7z.001",
        is_split_archive=True,
    )

    failure = SingleArchiveExtractor._downgrade_ambiguous_split_empty_password(
        resolution,
        original,
        is_split=True,
    )

    assert failure.kind is FailureKind.PASSWORD_INCONCLUSIVE
    assert failure.is_password_failure is False


def test_password_probe_tail_failure_maps_to_missing_volume_with_ambiguous_cli_message():
    extractor = object.__new__(SingleArchiveExtractor)
    extractor.i18n = I18nContext("zh")
    resolution = PasswordResolution(
        password=None,
        status=PasswordResolutionStatus.NEEDS_VOLUME_OR_TAIL_DAMAGED,
        error_text="evidence=seven_zip_start_header_length",
        test_result={
            "read_error": {
                "field": "7z.next_header",
                "offset": 4096,
                "requested": 128,
                "actual": 0,
                "possible_missing_volume": True,
            }
        },
    )

    failure = extractor._password_resolution_failure(resolution)

    assert failure is not None
    assert failure.kind is FailureKind.MISSING_VOLUME
    assert "7z 尾部 Next Header" in failure.message
    assert "可能缺少分卷" in failure.message
    assert failure.message_key == "failure.archive_field_read_failed_possible_missing_volume"
    assert failure.message_params == {
        "field": "7z 尾部 Next Header",
        "offset": 4096,
        "requested": 128,
        "actual": 0,
    }
    assert extractor._localized_failure(failure) == failure.message
    assert failure.to_dict()["message_params"] == failure.message_params
    assert failure.details["read_error"]["field"] == "7z.next_header"
    assert failure.details["diagnostic"] == "evidence=seven_zip_start_header_length"


def test_known_encrypted_split_input_keeps_wrong_password_failure():
    resolution = PasswordResolution(
        password="",
        status=PasswordResolutionStatus.RESOLVED,
        encrypted=True,
        requires_extraction_confirmation=True,
    )
    original = classify_extract_failure(
        _worker_completed({"wrong_password": True, "native_status": "wrong_password"}),
        "",
        archive="payload.7z.001",
        is_split_archive=True,
    )

    assert SingleArchiveExtractor._downgrade_ambiguous_split_empty_password(
        resolution,
        original,
        is_split=True,
    ) is original


@pytest.mark.parametrize(
    "payload",
    [
        {
            "wrong_password": False,
            "native_status": "error",
            "failure_kind": "encrypted_or_wrong_password",
            "operation_result_name": "data_error",
            "message": "archive could not be extracted",
        },
        {
            "wrong_password": False,
            "native_status": "error",
            "diagnostics": {
                "failure_kind": "unknown",
                "operation_result_name": "wrong_password",
            },
        },
    ],
    ids=["failure-kind", "nested-operation-result"],
)
def test_worker_wrong_password_evidence_maps_to_wrong_password(payload):
    completed = _worker_completed(payload)

    assert classify_extract_failure(completed, "").message_key == "failure.wrong_password"


@pytest.mark.parametrize(
    ("operation_result_name", "failure_kind"),
    [
        ("data_error", "corrupted_data"),
        ("crc_error", "checksum_error"),
    ],
)
def test_zipcrypto_data_or_crc_without_password_proof_is_inconclusive(
    operation_result_name,
    failure_kind,
):
    completed = _worker_completed({
        "wrong_password": True,
        "damaged": operation_result_name == "crc_error",
        "password_rejected": False,
        "password_crc_proven": False,
        "operation_result_name": operation_result_name,
        "failure_kind": failure_kind,
    })

    failure = classify_extract_failure(
        completed,
        "",
        archive="payload.zip",
        password_evidence="zipcrypto_header_byte",
    )

    assert failure.kind is FailureKind.PASSWORD_INCONCLUSIVE
    assert failure.is_password_failure is False


def test_zipcrypto_backend_password_rejection_after_weak_header_match_is_inconclusive():
    completed = _worker_completed({
        "wrong_password": True,
        "password_rejected": True,
        "password_crc_proven": False,
        "operation_result_name": "wrong_password",
        "failure_kind": "encrypted_or_wrong_password",
    })

    failure = classify_extract_failure(
        completed,
        "",
        archive="payload.zip",
        password_evidence="zipcrypto_header_byte",
    )

    assert failure.kind is FailureKind.PASSWORD_INCONCLUSIVE
    assert failure.is_password_failure is False


def test_worker_candidate_batch_rejection_overrides_weak_zipcrypto_evidence():
    completed = _worker_completed({
        "wrong_password": True,
        "password_rejected": True,
        "password_candidates_all_rejected": True,
        "native_status": "wrong_password",
        "operation_result_name": "wrong_password",
        "failure_kind": "wrong_password",
    })

    failure = classify_extract_failure(
        completed,
        "",
        archive="payload.zip",
        password_evidence="zipcrypto_header_byte",
    )

    assert failure.kind is FailureKind.WRONG_PASSWORD
    assert failure.is_password_failure is True


def test_zipcrypto_damage_after_encrypted_entry_crc_proof_is_damaged():
    completed = _worker_completed({
        "wrong_password": False,
        "damaged": True,
        "checksum_error": True,
        "password_rejected": False,
        "password_crc_proven": True,
        "password_crc_proven_items": 1,
        "operation_result_name": "crc_error",
        "failure_kind": "checksum_error",
    })

    failure = classify_extract_failure(
        completed,
        "",
        archive="payload.zip",
        password_evidence="zipcrypto_header_byte",
    )

    assert failure.kind is FailureKind.DAMAGED
    assert failure.is_password_failure is False
    assert failure.details == {
        "evidence": "zipcrypto_entry_crc_proven_before_failure",
        "password_crc_proven_items": 1,
    }


def test_structured_missing_volume_keeps_callback_evidence():
    completed = _worker_completed({
        "missing_volume": True,
        "missing_volume_evidence": "open_volume_callback_not_found",
        "missing_volume_name": "payload.7z.003",
    })

    failure = classify_extract_failure(completed, "")

    assert failure.kind is FailureKind.MISSING_VOLUME
    assert failure.details == {
        "missing_volume_confirmed": True,
        "evidence": "open_volume_callback_not_found",
        "missing_volume_name": "payload.7z.003",
    }


def test_tail_size_suspicion_does_not_become_missing_volume():
    completed = _worker_completed({
        "damaged": True,
        "missing_volume": False,
        "missing_volume_suspected": True,
        "missing_volume_evidence": "tail_size_heuristic",
    })

    failure = classify_extract_failure(completed, "", archive="payload.7z.001")

    assert failure.kind is FailureKind.DAMAGED
    assert failure.details["missing_volume_confirmed"] is False
    assert failure.details["evidence"] == "tail_size_heuristic"


def test_tail_size_suspicion_does_not_override_explicit_wrong_password():
    completed = _worker_completed({
        "wrong_password": True,
        "missing_volume": False,
        "missing_volume_suspected": True,
        "missing_volume_evidence": "tail_size_heuristic",
    })

    failure = classify_extract_failure(completed, "", archive="payload.7z.001")

    assert failure.kind is FailureKind.WRONG_PASSWORD


@pytest.mark.parametrize(
    "message",
    ["Unexpected end of archive", "Can not open the file as archive"],
    ids=["unexpected-end", "cannot-open"],
)
def test_split_archive_generic_backend_errors_are_damage_without_hard_evidence(message):
    failure = classify_extract_failure(None, message, archive="payload.7z.001")

    assert failure.kind is FailureKind.DAMAGED


def test_archive_name_containing_missing_volume_is_not_explicit_backend_evidence():
    failure = classify_extract_failure(
        None,
        "Can not open the file as archive: missing volume sample.7z.001",
        archive="missing volume sample.7z.001",
    )

    assert failure.kind is FailureKind.DAMAGED


def test_explicit_backend_missing_volume_line_remains_missing_volume():
    failure = classify_extract_failure(None, "ERROR: Missing volume : payload.7z.003")

    assert failure.kind is FailureKind.MISSING_VOLUME


def _worker_completed(payload: dict) -> subprocess.CompletedProcess:
    event = {"type": "result", **payload}
    return subprocess.CompletedProcess(
        args=["sevenzip_worker"],
        returncode=1,
        stdout=json.dumps(event),
        stderr="",
    )
