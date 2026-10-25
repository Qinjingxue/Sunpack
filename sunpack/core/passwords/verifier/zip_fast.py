from __future__ import annotations

from sunpack.core.passwords.verifier.base import PasswordBatchVerification, normalize_verifier_status
from sunpack.core.passwords.verifier.input import PasswordProbeInput, prepare_password_input
from sunpack_native import zip_fast_verify_passwords_from_ranges, zip_fast_verify_passwords_from_volumes


class ZipFastVerifier:
    format_hint = "zip"
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
        analysis = (archive_input or {}).get("analysis") or {}
        eocd_offset = analysis.get("zip_eocd_offset")
        prepared = prepare_password_input(archive_path, part_paths=part_paths, archive_input=archive_input)
        if prepared.volumes is not None and prepared.volume_style == "zip_spanned":
            with prepared.borrow_sessions() as sessions:
                outcome = zip_fast_verify_passwords_from_volumes(prepared.volumes, normalized_passwords, eocd_offset, sessions=sessions)
            return self._from_outcome(outcome)
        if prepared.volume_aware:
            return PasswordBatchVerification(
                ok=False,
                status="unknown_needs_final_verifier",
                attempts=0,
                error_text="zip volume set requires the volume-aware bounded verifier",
            )
        ranges = prepared.ranges
        with prepared.borrow_sessions() as sessions:
            outcome = (
                zip_fast_verify_passwords_from_ranges(ranges, normalized_passwords, eocd_offset, sessions=sessions)
                if ranges
                else sessions[0].zip_fast_verify_passwords(normalized_passwords, eocd_offset)
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
