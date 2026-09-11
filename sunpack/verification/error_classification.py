from __future__ import annotations

from dataclasses import dataclass

from sunpack.contracts.verification import (
    CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
    CONTENT_INTEGRITY_UNKNOWN,
    CONTENT_INTEGRITY_VERIFIED_PARTIAL,
    CONTAINER_INTEGRITY_STRUCTURALLY_DAMAGED,
    CONTAINER_INTEGRITY_UNKNOWN,
)


@dataclass(frozen=True)
class VerificationErrorClass:
    content_integrity: str = CONTENT_INTEGRITY_UNKNOWN
    container_integrity: str = CONTAINER_INTEGRITY_UNKNOWN
    category: str = "unknown"


_PAYLOAD_DAMAGE = {
    "checksum_error",
    "corrupted_data",
    "crc_error",
    "data_error",
    "decompression_error",
    "hash_mismatch",
    "payload_hash_mismatch",
}

_INCOMPLETE_CONTENT = {
    "input_truncated",
    "missing_volume",
    "stream_truncated",
    "unexpected_end",
}

_STRUCTURAL_ONLY = {
    "central_directory_bad",
    "central_directory_missing",
    "headers_error",
    "not_archive",
    "structure_recognition",
}

_PASSWORD = {
    "encrypted_or_wrong_password",
    "password_required",
    "wrong_password",
}

_EXECUTION = {
    "backend_unavailable",
    "decoded_name_count_mismatch",
    "input_stream",
    "output_filesystem",
    "process_exit",
    "process_io",
    "process_signal",
    "process_stall",
    "process_start",
    "process_timeout",
    "resource_guard",
    "unsupported",
    "unsupported_method",
}


def classify_verification_error(failure_kind: str, failure_stage: str = "") -> VerificationErrorClass:
    kind = str(failure_kind or "").strip().lower()
    stage = str(failure_stage or "").strip().lower()
    if kind in _PAYLOAD_DAMAGE or (stage == "item_extract" and kind not in _PASSWORD | _INCOMPLETE_CONTENT):
        return VerificationErrorClass(
            content_integrity=CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
            category="payload_damage",
        )
    if kind in _INCOMPLETE_CONTENT:
        return VerificationErrorClass(
            content_integrity=CONTENT_INTEGRITY_VERIFIED_PARTIAL,
            container_integrity=CONTAINER_INTEGRITY_STRUCTURALLY_DAMAGED,
            category="incomplete_archive",
        )
    if kind in _STRUCTURAL_ONLY:
        return VerificationErrorClass(
            container_integrity=CONTAINER_INTEGRITY_STRUCTURALLY_DAMAGED,
            category="container_structure",
        )
    if kind in _PASSWORD:
        return VerificationErrorClass(category="password")
    if kind in _EXECUTION:
        return VerificationErrorClass(category="execution")
    return VerificationErrorClass()
