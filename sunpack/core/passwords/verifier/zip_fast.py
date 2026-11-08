from __future__ import annotations

from sunpack.core.passwords.verifier.base import PasswordBatchVerification
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
            return PasswordBatchVerification.from_native(outcome, always_confirm=True)
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

        return PasswordBatchVerification.from_native(outcome, always_confirm=True)
