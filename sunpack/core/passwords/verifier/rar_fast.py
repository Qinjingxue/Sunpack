from __future__ import annotations

from sunpack.core.passwords.verifier.base import PasswordBatchVerification, normalize_verifier_status
from sunpack.core.passwords.verifier.input import PasswordProbeInput, prepare_password_input
from sunpack_native import rar_fast_verify_passwords_from_ranges, rar_fast_verify_passwords_from_volumes


class RarFastVerifier:
    format_hint = "rar"
    prepare_input = staticmethod(prepare_password_input)

    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | PasswordProbeInput | None = None,
    ) -> PasswordBatchVerification:
        normalized_passwords = list(passwords or [""])
        prepared = prepare_password_input(archive_path, part_paths=part_paths, archive_input=archive_input)
        if prepared.volumes is not None and prepared.volume_style in {
            "rar_part",
            "rar_oldstyle",
            "rar_sfx_part",
            "sfx_numeric_suffix",
        }:
            with prepared.borrow_sessions() as sessions:
                outcome = rar_fast_verify_passwords_from_volumes(prepared.volumes, normalized_passwords, sessions=sessions)
            return self._from_outcome(outcome)
        if prepared.volume_aware:
            return PasswordBatchVerification(
                ok=False,
                status="unknown_needs_final_verifier",
                attempts=0,
                error_text="rar volume set requires the volume-aware bounded verifier",
            )
        ranges = prepared.ranges
        with prepared.borrow_sessions() as sessions:
            outcome = (
                rar_fast_verify_passwords_from_ranges(ranges, normalized_passwords, sessions=sessions)
                if ranges
                else sessions[0].rar_fast_verify_passwords(normalized_passwords)
            )
        return self._from_outcome(outcome)

    @staticmethod
    def _from_outcome(outcome: dict) -> PasswordBatchVerification:
        status = normalize_verifier_status(outcome.get("status"))
        matched_index = int(outcome.get("matched_index", -1))
        matched_indices = tuple(int(index) for index in outcome.get("matched_indices") or ())
        attempts = int(outcome.get("attempts", 0))
        message = str(outcome.get("message") or "")
        final_confirmation_required = bool(
            outcome.get("final_confirmation_required", status == "match")
        )
        return PasswordBatchVerification(
            ok=(status == "match" and matched_index >= 0) or status == "not_required",
            status=status,
            matched_index=matched_index,
            matched_indices=matched_indices,
            attempts=attempts,
            test_result=outcome,
            error_text=message.lower(),
            terminal=status in {"damaged", "needs_volume_or_tail_damaged", "missing_volume"},
            final_confirmation_required=False if status == "not_required" else final_confirmation_required,
            match_evidence=str(outcome.get("match_evidence") or ""),
        )
