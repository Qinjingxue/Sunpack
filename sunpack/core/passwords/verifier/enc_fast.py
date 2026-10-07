from __future__ import annotations

from sunpack.core.passwords.verifier.base import PasswordBatchVerification, normalize_verifier_status
from sunpack.core.passwords.verifier.input import requires_volume_aware_verifier, verifier_input
from sunpack.core.support.archive_sessions import borrow_archive_sessions
from sunpack_native import enc_fast_verify_passwords_from_ranges


class EncFastVerifier:
    format_hint = "enc"

    def verify_batch(self, archive_path: str, passwords: list[str], *,
                     part_paths: list[str] | None = None,
                     archive_input: dict | None = None) -> PasswordBatchVerification:
        if requires_volume_aware_verifier(archive_path, part_paths=part_paths, archive_input=archive_input):
            return PasswordBatchVerification(
                ok=False, status="needs_volume_or_tail_damaged", attempts=0,
                error_text="ENC requires a complete logical byte stream", terminal=True,
            )
        path, ranges = verifier_input(archive_path, part_paths=part_paths, archive_input=archive_input)
        with borrow_archive_sessions([item.get("path") for item in ranges] if ranges else [path]) as sessions:
            outcome = (enc_fast_verify_passwords_from_ranges(ranges, passwords) if ranges
                       else sessions[0].enc_fast_verify_passwords(passwords))
        status = normalize_verifier_status(outcome.get("status"))
        index = int(outcome.get("matched_index", -1))
        return PasswordBatchVerification(
            ok=status == "match" and index >= 0, status=status, matched_index=index,
            attempts=int(outcome.get("attempts", 0)), test_result=outcome,
            error_text=str(outcome.get("message") or ""), terminal=status == "damaged",
            final_confirmation_required=False, match_evidence=str(outcome.get("match_evidence") or ""),
        )
