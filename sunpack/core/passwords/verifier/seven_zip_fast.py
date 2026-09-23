from __future__ import annotations

from sunpack.core.passwords.verifier.base import PasswordBatchVerification, normalize_verifier_status
from sunpack.core.passwords.verifier.input import requires_volume_aware_verifier, verifier_input
from sunpack.core.support.archive_sessions import get_archive_session, retain_archive_sessions
from sunpack_native import seven_zip_fast_verify_passwords_from_ranges


class SevenZipFastVerifier:
    format_hint = "7z"

    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        if requires_volume_aware_verifier(
            archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
        ):
            return PasswordBatchVerification(
                ok=False,
                status="unknown_needs_final_verifier",
                attempts=0,
                error_text="7z volume set requires the volume-aware bounded verifier",
            )
        verifier_path, ranges = verifier_input(
            archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
        )
        normalized_passwords = list(passwords or [""])
        retain_archive_sessions(
            [item.get("path") for item in ranges] if ranges else [verifier_path]
        )
        outcome = (
            seven_zip_fast_verify_passwords_from_ranges(ranges, normalized_passwords)
            if ranges
            else get_archive_session(verifier_path).seven_zip_fast_verify_passwords(normalized_passwords)
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
            terminal=status in {"damaged", "needs_volume_or_tail_damaged"},
            final_confirmation_required=bool(
                outcome.get("final_confirmation_required", status == "match")
            ) if status != "not_required" else False,
            match_evidence=str(outcome.get("match_evidence") or ""),
        )
