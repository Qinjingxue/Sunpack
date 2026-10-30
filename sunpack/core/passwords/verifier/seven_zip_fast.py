from __future__ import annotations

from sunpack.core.passwords.verifier.base import PasswordBatchVerification, normalize_verifier_status
from sunpack.core.passwords.verifier.input import PasswordProbeInput, prepare_password_input
from sunpack_native import seven_zip_fast_verify_passwords_from_ranges


class SevenZipFastVerifier:
    format_hint = "7z"
    prepare_input = staticmethod(prepare_password_input)

    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | PasswordProbeInput | None = None,
    ) -> PasswordBatchVerification:
        prepared = prepare_password_input(archive_path, part_paths=part_paths, archive_input=archive_input)
        if prepared.volume_aware:
            return PasswordBatchVerification(
                ok=False,
                status="unknown_needs_final_verifier",
                attempts=0,
                error_text="7z volume set requires the volume-aware bounded verifier",
            )
        ranges = prepared.ranges
        normalized_passwords = list(passwords or [""])
        with prepared.borrow_sessions() as sessions:
            outcome = (
                seven_zip_fast_verify_passwords_from_ranges(ranges, normalized_passwords, sessions=sessions)
                if ranges
                else sessions[0].seven_zip_fast_verify_passwords(normalized_passwords)
            )
        status = normalize_verifier_status(outcome.get("status"))
        matched_index = int(outcome.get("matched_index", -1))
        attempts = int(outcome.get("attempts", 0))
        message = str(outcome.get("message") or "")
        return PasswordBatchVerification(
            ok=(status == "match" and matched_index >= 0) or status == "not_required",
            status=status,
            matched_index=matched_index,
            attempts=attempts,
            test_result=outcome,
            error_text=message.lower(),
            terminal=status in {"damaged", "needs_volume_or_tail_damaged", "missing_volume"},
            final_confirmation_required=bool(
                outcome.get("final_confirmation_required", status == "match")
            ) if status != "not_required" else False,
            match_evidence=str(outcome.get("match_evidence") or ""),
        )
