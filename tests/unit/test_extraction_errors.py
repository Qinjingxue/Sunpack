import json
import subprocess


from sunpack.core.contracts.failures import FailureKind
from sunpack.core.i18n import I18nContext
from sunpack.core.passwords.result import PasswordResolution, PasswordResolutionStatus
from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import (
    attach_worker_diagnostics,
)
from sunpack.pipeline.extraction.internal.workflow.errors import (
    classify_extract_failure,
)
from sunpack.pipeline.extraction.internal.workflow.single_archive_extractor import (
    SingleArchiveExtractor,
)


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


def _worker_completed(payload: dict) -> subprocess.CompletedProcess:
    event = {"type": "result", **payload}
    return attach_worker_diagnostics(subprocess.CompletedProcess(
        args=["sevenzip_worker"],
        returncode=1,
        stdout=json.dumps(event),
        stderr="",
    ))


def test_zipcrypto_proof_contract(subtests):
    cases = [
        ("zip_empty_password_direct", "data_error", False, False, FailureKind.WRONG_PASSWORD),
        ("zip_empty_password_direct", "crc_error", False, False, FailureKind.WRONG_PASSWORD),
        ("zip_empty_password_direct", "crc_error", True, False, FailureKind.DAMAGED),
        ("zipcrypto_header_byte", "data_error", False, False, FailureKind.PASSWORD_INCONCLUSIVE),
        ("zipcrypto_header_byte", "crc_error", False, False, FailureKind.PASSWORD_INCONCLUSIVE),
        ("zipcrypto_header_byte", "wrong_password", False, False, FailureKind.PASSWORD_INCONCLUSIVE),
        ("zipcrypto_header_byte", "wrong_password", False, True, FailureKind.WRONG_PASSWORD),
        ("zipcrypto_header_byte", "crc_error", True, False, FailureKind.DAMAGED),
    ]
    for evidence, operation, proven, rejected, expected in cases:
        with subtests.test(evidence=evidence, operation=operation, proven=proven, rejected=rejected):
            failure = classify_extract_failure(_worker_completed({
                "encrypted": True, "wrong_password": evidence == "zipcrypto_header_byte" and not proven,
                "damaged": operation == "crc_error", "checksum_error": operation == "crc_error",
                "password_rejected": operation == "wrong_password", "password_crc_proven": proven,
                "password_crc_proven_items": int(proven), "password_candidates_all_rejected": rejected,
                "operation_result_name": operation,
                "failure_kind": {"crc_error": "checksum_error", "data_error": "data_error",
                                 "wrong_password": "encrypted_or_wrong_password"}[operation],
            }), "", archive="payload.zip", password_evidence=evidence)
            assert failure.kind is expected
            assert failure.is_password_failure is (expected is FailureKind.WRONG_PASSWORD)
            if proven:
                assert failure.details["evidence"] == "zipcrypto_entry_crc_proven_before_failure"


def test_failure_evidence_contract(subtests):
    cases = [
        ({"wrong_password": True, "damaged": True, "checksum_error": True,
          "native_status": "wrong_password", "failure_kind": "checksum_error"}, "", FailureKind.DAMAGED),
        ({"wrong_password": False, "native_status": "error", "failure_kind": "encrypted_or_wrong_password",
          "operation_result_name": "data_error"}, "", FailureKind.WRONG_PASSWORD),
        ({"wrong_password": False, "native_status": "error",
          "diagnostics": {"failure_kind": "unknown", "operation_result_name": "wrong_password"}}, "", FailureKind.WRONG_PASSWORD),
        ({"missing_volume": True, "missing_volume_evidence": "open_volume_callback_not_found",
          "missing_volume_name": "payload.7z.003"}, "", FailureKind.MISSING_VOLUME),
        ({"damaged": True, "missing_volume": False, "missing_volume_suspected": True,
          "missing_volume_evidence": "tail_size_heuristic"}, "", FailureKind.DAMAGED),
        ({"wrong_password": True, "missing_volume": False, "missing_volume_suspected": True,
          "missing_volume_evidence": "tail_size_heuristic"}, "", FailureKind.WRONG_PASSWORD),
        (None, "Unexpected end of archive", FailureKind.DAMAGED),
        (None, "Can not open the file as archive", FailureKind.DAMAGED),
        (None, "Can not open the file as archive: missing volume sample.7z.001", FailureKind.DAMAGED),
        (None, "ERROR: Missing volume : payload.7z.003", FailureKind.MISSING_VOLUME),
    ]
    for payload, message, expected in cases:
        with subtests.test(payload=payload, message=message):
            failure = classify_extract_failure(_worker_completed(payload) if payload is not None else None,
                message, archive="missing volume sample.7z.001", is_split_archive=True)
            assert failure.kind is expected
            if payload and payload.get("missing_volume"):
                assert failure.details["missing_volume_confirmed"]
                assert failure.details["missing_volume_name"] == "payload.7z.003"
            if payload and payload.get("missing_volume_suspected") and payload.get("damaged"):
                assert failure.details["missing_volume_confirmed"] is False
