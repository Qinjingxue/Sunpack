import os
import re
import subprocess
from typing import Optional

from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import worker_result_payload
from sunpack.core.i18n import I18nContext
from sunpack.core.support.archive_error_signals import (
    has_archive_damage_signals,
    looks_like_split_archive_name,
    normalize_error_text,
)

_norm = normalize_error_text
_EN = I18nContext("en")


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
    worker_result = worker_result_payload(run_result)
    if worker_result:
        if worker_result.get("missing_volume"):
            return _failure(
                FailureKind.MISSING_VOLUME,
                "failure.missing_volume",
                details=_missing_volume_details(worker_result, confirmed=True),
            )
        if worker_result.get("password_candidates_all_rejected"):
            return _failure(FailureKind.WRONG_PASSWORD, "failure.wrong_password", user_action="request_password")
        if password_evidence == "zipcrypto_header_byte" or (
            password_evidence == "empty_password_direct" and worker_result.get("encrypted")
        ):
            operation = str(worker_result.get("operation_result_name") or "").lower()
            kind = str(worker_result.get("failure_kind") or "").lower()
            if operation in {"wrong_password", "data_error", "crc_error"} or kind in {
                "encrypted_or_wrong_password", "data_error", "checksum_error", "crc_error",
            }:
                # Runtime encryption without an authenticated item cannot prove
                # damage. The same rule applies to every archive handler.
                if worker_result.get("password_crc_proven"):
                    return _failure(FailureKind.DAMAGED, "failure.damaged", details={
                        "evidence": "entry_crc_proven_before_failure",
                        "password_crc_proven_items": int(worker_result.get("password_crc_proven_items") or 0),
                    })
                if password_evidence == "empty_password_direct":
                    return _failure(FailureKind.WRONG_PASSWORD, "failure.wrong_password", user_action="request_password",
                        details={"evidence": "empty_password_failed_without_crc_proof", "backend_operation_result": operation})
                return _failure(FailureKind.PASSWORD_INCONCLUSIVE, "failure.password_state_unknown",
                    details={"evidence": "zipcrypto_failure_without_password_proof", "backend_operation_result": operation})
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

    diagnostics = getattr(run_result, "worker_diagnostics", None)
    process_failure = diagnostics.get("process_failure") if isinstance(diagnostics, dict) else None
    if isinstance(process_failure, dict) and process_failure:
        # A confirmed transport/startup fault takes precedence over stderr.
        # A generic worker_exit/process_exit, however, is only a consequence
        # of a nonzero exit and must not conceal archive-specific evidence.
        is_generic_exit = (
            process_failure.get("failure_kind") == "process_exit"
            and process_failure.get("failure_stage") == "worker_exit"
        )
        if not is_generic_exit:
            return _worker_process_failure_info(process_failure)

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

    # Keep the generic worker exit as the fallback when there is no stronger
    # archive-specific evidence, preserving the original exit diagnostics.
    if isinstance(process_failure, dict) and process_failure:
        return _worker_process_failure_info(process_failure)

    if run_result:
        code = run_result.returncode
        if code == -100:
            return _failure(FailureKind.PROCESS_ERROR, "failure.process_start_failed")
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


def _worker_process_failure_info(process_failure: dict) -> FailureInfo:
    failure_kind = str(process_failure.get("failure_kind") or "process_error")
    failure_stage = str(process_failure.get("failure_stage") or "worker_process")
    message = str(process_failure.get("message") or "").strip() or "worker failed without a result"
    return _failure(
        FailureKind.PROCESS_ERROR,
        "failure.worker_process_failed",
        details={
            "failure_kind": failure_kind,
            "failure_stage": failure_stage,
            "message": message,
        },
        kind=failure_kind,
        message=message,
    )


def _failure(
    failure_kind: FailureKind,
    message_key: str,
    *,
    user_action: str = "",
    details: dict | None = None,
    **params,
) -> FailureInfo:
    return FailureInfo(
        kind=failure_kind,
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
