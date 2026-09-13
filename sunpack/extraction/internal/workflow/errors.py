import os
import re
import subprocess
from typing import Optional

from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.extraction.internal.sevenzip.worker_diagnostics import worker_result_payload
from sunpack.i18n import I18nContext
from sunpack.support.archive_error_signals import (
    has_archive_damage_signals,
    has_transient_system_signals,
    looks_like_split_archive_name,
    normalize_error_text,
)

_norm = normalize_error_text
_EN = I18nContext("en")


def should_retry_extract_failure(
    run_result: Optional[subprocess.CompletedProcess],
    err_text: str,
    archive: str = None,
    is_split_archive: bool = False,
) -> bool:
    err_lower = _norm(err_text)
    worker_result = worker_result_payload(run_result) or worker_result_payload(err_text)
    if worker_result:
        if worker_result.get("wrong_password") or worker_result.get("damaged") or worker_result.get("missing_volume"):
            return False
        if worker_result.get("native_status") in {"wrong_password", "damaged", "unsupported"}:
            return False

    if has_archive_damage_signals(err_lower):
        return False

    if has_transient_system_signals(err_lower):
        return True

    if not run_result:
        return False

    code = run_result.returncode
    if code in (-100, -101, -102, 8):
        return True
    if code is not None and code < 0:
        return True

    return False


def classify_extract_failure(
    run_result: Optional[subprocess.CompletedProcess],
    err_text: str,
    archive: str = None,
    is_split_archive: bool = False,
    *,
    password_evidence: str = "",
) -> FailureInfo:
    archive_name = os.path.basename(archive or "").lower()
    is_split_archive = is_split_archive or looks_like_split_archive_name(archive_name)
    err_lower = _norm(err_text)
    worker_result = worker_result_payload(run_result) or worker_result_payload(err_text)
    if worker_result:
        if worker_result.get("missing_volume"):
            return _failure(
                FailureKind.MISSING_VOLUME,
                "failure.missing_volume",
                details=_missing_volume_details(worker_result, confirmed=True),
            )
        if worker_result.get("password_candidates_all_rejected"):
            return _failure(FailureKind.WRONG_PASSWORD, "failure.wrong_password", user_action="request_password")
        if password_evidence == "zipcrypto_header_byte":
            operation_result_name = str(worker_result.get("operation_result_name") or "").lower()
            failure_kind = str(worker_result.get("failure_kind") or "").lower()
            zipcrypto_password_or_payload_failure = operation_result_name in {
                "wrong_password",
                "data_error",
                "crc_error",
            } or failure_kind in {
                "encrypted_or_wrong_password",
                "data_error",
                "checksum_error",
                "crc_error",
            }
            if zipcrypto_password_or_payload_failure:
                if worker_result.get("password_crc_proven"):
                    return _failure(
                        FailureKind.DAMAGED,
                        "failure.damaged",
                        details={
                            "evidence": "zipcrypto_entry_crc_proven_before_failure",
                            "password_crc_proven_items": int(worker_result.get("password_crc_proven_items") or 0),
                        },
                    )
                return _failure(
                    FailureKind.PASSWORD_INCONCLUSIVE,
                    "failure.password_state_unknown",
                    details={
                        "evidence": "zipcrypto_failure_without_password_proof",
                        "backend_operation_result": operation_result_name,
                    },
                )
        if is_split_archive and _worker_reports_payload_damage(worker_result):
            return _failure(
                FailureKind.DAMAGED,
                "failure.damaged",
                details=(
                    _missing_volume_details(worker_result, confirmed=False)
                    if worker_result.get("missing_volume_suspected")
                    else None
                ),
            )
        if _worker_reports_wrong_password(worker_result):
            return _failure(FailureKind.WRONG_PASSWORD, "failure.wrong_password", user_action="request_password")
        if worker_result.get("missing_volume_suspected"):
            return _failure(
                FailureKind.DAMAGED,
                "failure.damaged",
                details=_missing_volume_details(worker_result, confirmed=False),
            )
        if worker_result.get("checksum_error"):
            return _failure(FailureKind.DAMAGED, "failure.damaged")
        if worker_result.get("damaged") or worker_result.get("native_status") == "damaged":
            return _failure(FailureKind.DAMAGED, "failure.damaged")
        if worker_result.get("unsupported_method"):
            return _failure(FailureKind.UNSUPPORTED, "failure.unsupported")
        if worker_result.get("native_status") == "backend_unavailable":
            return _failure(FailureKind.BACKEND_UNAVAILABLE, "failure.backend_unavailable")
        if worker_result.get("native_status") == "unsupported":
            return _failure(FailureKind.UNSUPPORTED, "failure.unsupported")

    if _has_explicit_missing_volume_line(err_text):
        return _failure(
            FailureKind.MISSING_VOLUME,
            "failure.missing_volume",
            details={"missing_volume_confirmed": True, "evidence": "explicit_backend_message"},
        )
    if "unexpected end of archive" in err_lower or "unexpected end of data" in err_lower:
        return _failure(FailureKind.DAMAGED, "failure.damaged")
    if "crc failed" in err_lower or "data error in encrypted file" in err_lower:
        if is_split_archive:
            return _failure(FailureKind.DAMAGED, "failure.damaged")
        return _failure(FailureKind.DAMAGED, "failure.damaged")
    if "headers error" in err_lower or "data error" in err_lower:
        return _failure(FailureKind.DAMAGED, "failure.damaged")
    if "cannot open the file as" in err_lower or "can not open the file as archive" in err_lower:
        return _failure(FailureKind.DAMAGED, "failure.damaged")
    if "is not archive" in err_lower or "archive is corrupted" in err_lower or "checksum error" in err_lower:
        return _failure(FailureKind.DAMAGED, "failure.damaged")
    if "unsupported compression method" in err_lower or "unsupported method" in err_lower:
        return _failure(FailureKind.UNSUPPORTED, "failure.unsupported")

    if run_result:
        code = run_result.returncode
        if code == -100:
            return _failure(FailureKind.PROCESS_ERROR, "failure.process_start_failed")
        if code == -101:
            return _failure(FailureKind.PROCESS_ERROR, "failure.process_timeout")
        if code == -102:
            return _failure(FailureKind.PROCESS_ERROR, "failure.process_no_progress")
        if code is not None and code < 0:
            return _failure(FailureKind.PROCESS_ERROR, "failure.process_exited")
        if code == 1:
            return _failure(FailureKind.UNKNOWN, "failure.warning_busy_or_partial")
        elif code == 2:
            return _failure(FailureKind.UNKNOWN, "failure.unsupported")
        elif code == 7:
            return _failure(FailureKind.PROCESS_ERROR, "failure.invalid_arguments")
        elif code == 8:
            return _failure(FailureKind.PROCESS_ERROR, "failure.process_exit_code", code=code)
        elif code == 255:
            return _failure(FailureKind.PROCESS_ERROR, "failure.user_interrupted")
        elif code not in (None, 0):
            return _failure(FailureKind.PROCESS_ERROR, "failure.process_exit_code", code=code)

    return _failure(FailureKind.UNKNOWN, "failure.unknown")


def _failure(
    kind: FailureKind,
    message_key: str,
    *,
    user_action: str = "",
    details: dict | None = None,
    **params,
) -> FailureInfo:
    return FailureInfo(
        kind=kind,
        stage="extraction",
        message=_EN.t(message_key, **params),
        message_key=message_key,
        message_params=dict(params),
        user_action=user_action,
        details=dict(details or {}),
    )


def _missing_volume_details(worker_result: dict, *, confirmed: bool) -> dict:
    details = {
        "missing_volume_confirmed": confirmed,
        "evidence": str(worker_result.get("missing_volume_evidence") or "structured_worker_result"),
    }
    missing_name = str(worker_result.get("missing_volume_name") or "")
    if missing_name:
        details["missing_volume_name"] = missing_name
    return details


def _has_explicit_missing_volume_line(err_text: str) -> bool:
    return re.search(
        r"^\s*(?:error\s*:\s*)?missing volume(?:\s*:.*)?\s*$",
        err_text or "",
        re.IGNORECASE | re.MULTILINE,
    ) is not None


def _worker_reports_payload_damage(worker_result: dict) -> bool:
    if worker_result.get("checksum_error") or worker_result.get("damaged"):
        return True
    if worker_result.get("native_status") == "damaged":
        return True
    failure_kind = str(worker_result.get("failure_kind") or "").lower()
    if failure_kind in {"corrupted_data", "data_error", "checksum_error", "crc_error"}:
        return True
    diagnostics = worker_result.get("diagnostics")
    if isinstance(diagnostics, dict):
        nested_kind = str(diagnostics.get("failure_kind") or "").lower()
        if nested_kind in {"corrupted_data", "data_error", "checksum_error", "crc_error"}:
            return True
    return False


def _worker_reports_wrong_password(worker_result: dict) -> bool:
    if worker_result.get("wrong_password") or worker_result.get("native_status") == "wrong_password":
        return True
    if str(worker_result.get("failure_kind") or "").lower() in {
        "wrong_password",
        "encrypted_or_wrong_password",
    }:
        return True
    if str(worker_result.get("operation_result_name") or "").lower() == "wrong_password":
        return True
    diagnostics = worker_result.get("diagnostics")
    if not isinstance(diagnostics, dict):
        return False
    return (
        str(diagnostics.get("failure_kind") or "").lower()
        in {"wrong_password", "encrypted_or_wrong_password"}
        or str(diagnostics.get("operation_result_name") or "").lower() == "wrong_password"
    )
