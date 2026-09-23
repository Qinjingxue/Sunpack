from __future__ import annotations

from sunpack.core.passwords.verifier.base import PasswordBatchVerification, normalize_verifier_status
from sunpack.core.passwords.verifier.input import (
    requires_volume_aware_verifier,
    structured_volume_input,
    verifier_input,
)
from sunpack.core.support.archive_sessions import get_archive_session, retain_archive_sessions
from sunpack_native import rar_fast_verify_passwords_from_ranges, rar_fast_verify_passwords_from_volumes


class RarFastVerifier:
    format_hint = "rar"

    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        normalized_passwords = list(passwords or [""])
        volume_input = structured_volume_input(
            archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
        )
        if volume_input is not None and volume_input[0] in {
            "rar_part",
            "rar_oldstyle",
            "rar_sfx_part",
            "sfx_numeric_suffix",
        }:
            volume_numbers = sorted(
                int(item.get("volume_number") or 0) for item in volume_input[1]
            )
            if volume_numbers != list(range(1, len(volume_numbers) + 1)):
                return self._from_outcome(
                    {
                        "status": "needs_volume_or_tail_damaged",
                        "matched_index": -1,
                        "attempts": 0,
                        "message": (
                            "structured RAR volume numbers are not contiguous from one"
                        ),
                    }
                )
            retain_archive_sessions([item.get("path") for item in volume_input[1]])
            return self._from_outcome(
                rar_fast_verify_passwords_from_volumes(volume_input[1], normalized_passwords)
            )
        if requires_volume_aware_verifier(
            archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
        ):
            return PasswordBatchVerification(
                ok=False,
                status="unknown_needs_final_verifier",
                attempts=0,
                error_text="rar volume set requires the volume-aware bounded verifier",
            )
        verifier_path, ranges = verifier_input(
            archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
        )
        retain_archive_sessions(
            [item.get("path") for item in ranges] if ranges else [verifier_path]
        )
        outcome = (
            rar_fast_verify_passwords_from_ranges(ranges, normalized_passwords)
            if ranges
            else get_archive_session(verifier_path).rar_fast_verify_passwords(normalized_passwords)
        )
        return self._from_outcome(outcome)

    @staticmethod
    def _from_outcome(outcome: dict) -> PasswordBatchVerification:
        status = normalize_verifier_status(outcome.get("status"))
        matched_index = int(outcome.get("matched_index", -1))
        attempts = int(outcome.get("attempts", 0))
        message = str(outcome.get("message") or "")
        final_confirmation_required = bool(
            outcome.get("final_confirmation_required", status == "match")
        )
        return PasswordBatchVerification(
            ok=(status == "match" and matched_index >= 0) or status == "not_required",
            status=status,
            matched_index=matched_index,
            attempts=attempts,
            test_result=outcome,
            error_text=message.lower(),
            terminal=status in {"damaged", "needs_volume_or_tail_damaged"},
            final_confirmation_required=False if status == "not_required" else final_confirmation_required,
            match_evidence=str(outcome.get("match_evidence") or ""),
        )
