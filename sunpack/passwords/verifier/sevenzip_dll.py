from __future__ import annotations

import subprocess
from typing import Any

from sunpack.passwords.verifier.base import PasswordBatchVerification
from sunpack.support.sevenzip_bridge import (
    STATUS_BACKEND_UNAVAILABLE,
    STATUS_DAMAGED,
    STATUS_NEEDS_VOLUME_OR_TAIL_DAMAGED,
    STATUS_UNSUPPORTED,
    STATUS_WRONG_PASSWORD,
    get_native_password_tester,
)


class SevenZipDllVerifier:
    def __init__(self, native_password_tester: object | None = None, password_tester: Any = None):
        self.native_password_tester = native_password_tester or get_native_password_tester()
        self.password_tester = password_tester

    @classmethod
    def from_archive_password_tester(cls, password_tester: Any) -> "SevenZipDllVerifier":
        return cls(
            native_password_tester=getattr(password_tester, "native_password_tester", None),
            password_tester=password_tester,
        )

    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        normalized_passwords = list(passwords or [""])
        native_attempt = self.native_password_tester.try_passwords(
            archive_path,
            normalized_passwords,
            part_paths=part_paths,
            archive_input=archive_input,
        )
        native_result = subprocess.CompletedProcess(
            args=["embedded-7zip", "test-passwords", archive_path],
            returncode=0 if native_attempt.ok else 2,
            stdout="" if native_attempt.ok else native_attempt.message,
            stderr="" if native_attempt.ok else native_attempt.message,
        )
        native_result.operation_result = native_attempt.operation_result
        error_text = (native_attempt.message or "").lower()
        if native_attempt.ok:
            password = normalized_passwords[native_attempt.matched_index]
            if self.password_tester is not None:
                self.password_tester.add_recent_password(password)
            return PasswordBatchVerification(
                ok=True,
                status="match",
                matched_index=native_attempt.matched_index,
                attempts=native_attempt.attempts,
                test_result=native_result,
                error_text="",
                terminal=True,
                final_confirmation_required=False,
            )
        status_by_native = {
            STATUS_WRONG_PASSWORD: "no_match",
            STATUS_DAMAGED: "damaged",
            STATUS_UNSUPPORTED: "unsupported_method",
            STATUS_BACKEND_UNAVAILABLE: "backend_unavailable",
            STATUS_NEEDS_VOLUME_OR_TAIL_DAMAGED: "needs_volume_or_tail_damaged",
        }
        status = status_by_native.get(native_attempt.status, "unknown_needs_final_verifier")
        return PasswordBatchVerification(
            ok=False,
            status=status,
            matched_index=-1,
            attempts=native_attempt.attempts,
            test_result=native_result,
            error_text=error_text,
            terminal=status in {
                "damaged",
                "unsupported_method",
                "backend_unavailable",
                "needs_volume_or_tail_damaged",
            },
        )
