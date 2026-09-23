from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, cast


VerifierStatus = Literal[
    "match",
    "not_required",
    "no_match",
    "unknown_needs_final_verifier",
    "damaged",
    "unsupported_method",
    "backend_unavailable",
    "needs_volume_or_tail_damaged",
]


VERIFIER_STATUSES = {
    "match",
    "not_required",
    "no_match",
    "unknown_needs_final_verifier",
    "damaged",
    "unsupported_method",
    "backend_unavailable",
    "needs_volume_or_tail_damaged",
}


def normalize_verifier_status(value: object) -> VerifierStatus:
    normalized = str(value or "").strip().lower()
    if normalized not in VERIFIER_STATUSES:
        raise ValueError(f"invalid verifier status: {value!r}")
    return cast(VerifierStatus, normalized)


@dataclass(frozen=True)
class PasswordBatchVerification:
    ok: bool
    status: VerifierStatus = "unknown_needs_final_verifier"
    matched_index: int = -1
    matched_indices: tuple[int, ...] = ()
    attempts: int = 0
    test_result: object = None
    error_text: str = ""
    terminal: bool = False
    final_confirmation_required: bool = True
    match_evidence: str = ""


class PasswordVerifier(Protocol):
    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        ...
