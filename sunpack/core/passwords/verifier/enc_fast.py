from __future__ import annotations

from sunpack.core.passwords.verifier.base import PasswordBatchVerification, normalize_verifier_status
from sunpack.core.passwords.verifier.input import PasswordProbeInput, prepare_password_input
from sunpack_native import enc_fast_verify_passwords_from_ranges


class EncFastVerifier:
    format_hint = "enc"
    prepare_input = staticmethod(prepare_password_input)

    def verify_batch(self, archive_path: str, passwords: list[str], *,
                     part_paths: list[str] | None = None,
                     archive_input: dict | PasswordProbeInput | None = None) -> PasswordBatchVerification:
        prepared = prepare_password_input(archive_path, part_paths=part_paths, archive_input=archive_input)
        if prepared.volume_aware:
            return PasswordBatchVerification(
                ok=False, status="unsupported_method", attempts=0,
            )
        ranges = prepared.ranges
        with prepared.borrow_sessions() as sessions:
            outcome = (enc_fast_verify_passwords_from_ranges(ranges, passwords, sessions=sessions) if ranges
                       else sessions[0].enc_fast_verify_passwords(passwords))
        status = normalize_verifier_status(outcome.get("status"))
        index = int(outcome.get("matched_index", -1))
        return PasswordBatchVerification(
            ok=status == "match" and index >= 0, status=status, matched_index=index,
            attempts=int(outcome.get("attempts", 0)), test_result=outcome,
            error_text=str(outcome.get("message") or ""), terminal=status == "damaged",
            final_confirmation_required=False, match_evidence=str(outcome.get("match_evidence") or ""),
        )
