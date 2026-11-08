from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, cast

from sunpack.core.passwords.verifier.input import PasswordProbeInput


VerifierStatus = Literal[
    "match",
    "not_required",
    "no_match",
    "unknown_needs_final_verifier",
    "damaged",
    "unsupported_method",
    "backend_unavailable",
    "needs_volume_or_tail_damaged",
    "missing_volume",
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
    "missing_volume",
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

    @classmethod
    def from_native(cls, outcome: dict, *, always_confirm: bool = False) -> PasswordBatchVerification:
        status = normalize_verifier_status(outcome.get("status"))
        matched_index = int(outcome.get("matched_index", -1))
        return cls(
            ok=(status == "match" and matched_index >= 0) or status == "not_required",
            status=status,
            matched_index=matched_index,
            matched_indices=tuple(int(index) for index in outcome.get("matched_indices") or ()),
            attempts=int(outcome.get("attempts", 0)),
            test_result=outcome,
            error_text=str(outcome.get("message") or "").lower(),
            terminal=status in {"damaged", "needs_volume_or_tail_damaged", "missing_volume"},
            final_confirmation_required=status != "not_required" and (
                always_confirm or bool(outcome.get("final_confirmation_required", status == "match"))
            ),
            match_evidence=str(outcome.get("match_evidence") or ""),
        )


class PasswordVerifier(Protocol):
    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | PasswordProbeInput | None = None,
    ) -> PasswordBatchVerification:
        ...
