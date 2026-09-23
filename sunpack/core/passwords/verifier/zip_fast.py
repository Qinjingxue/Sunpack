from __future__ import annotations

from sunpack.core.passwords.verifier.base import PasswordBatchVerification, normalize_verifier_status
from sunpack.core.passwords.verifier.input import (
    requires_volume_aware_verifier,
    structured_volume_input,
    verifier_input,
)
from sunpack.core.support.archive_sessions import get_archive_session, retain_archive_sessions
from sunpack_native import zip_fast_verify_passwords_from_ranges, zip_fast_verify_passwords_from_volumes


class ZipFastVerifier:
    format_hint = "zip"

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
        if volume_input is not None and volume_input[0] == "zip_spanned":
            retain_archive_sessions([item.get("path") for item in volume_input[1]])
            return self._from_outcome(
                zip_fast_verify_passwords_from_volumes(volume_input[1], normalized_passwords)
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
                error_text="zip volume set requires the volume-aware bounded verifier",
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
            zip_fast_verify_passwords_from_ranges(ranges, normalized_passwords)
            if ranges
            else get_archive_session(verifier_path).zip_fast_verify_passwords(normalized_passwords)
        )

        return self._from_outcome(outcome)

    @staticmethod
    def _from_outcome(outcome: dict) -> PasswordBatchVerification:
        status = normalize_verifier_status(outcome.get("status"))
        matched_index = int(outcome.get("matched_index", -1))
        matched_indices = tuple(int(index) for index in outcome.get("matched_indices") or ())
        attempts = int(outcome.get("attempts", 0))
        message = str(outcome.get("message") or "")
        match_evidence = str(outcome.get("match_evidence") or "")
        return PasswordBatchVerification(
            ok=(status == "match" and matched_index >= 0) or status == "not_required",
            status=status,
            matched_index=matched_index,
            matched_indices=matched_indices,
            attempts=attempts,
            test_result=outcome,
            error_text=message.lower(),
            terminal=status in {"damaged", "needs_volume_or_tail_damaged"},
            final_confirmation_required=False if status == "not_required" else True,
            match_evidence=match_evidence,
        )
