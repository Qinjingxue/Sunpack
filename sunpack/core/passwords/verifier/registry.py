from __future__ import annotations

from collections.abc import Iterable

from sunpack.core.passwords.verifier.base import PasswordBatchVerification, PasswordVerifier
from sunpack.core.passwords.verifier.input import PasswordProbeInput, prepare_password_input
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor


class PasswordVerifierChain:
    """Dispatch bounded password verifiers in format-preferred order.

    This layer never performs full-payload confirmation. Verifiers return either
    a conclusive result or weak candidate evidence; the extraction worker owns
    confirmation of weak candidates.
    """

    def __init__(self, fast_verifiers: Iterable[PasswordVerifier]):
        self._fast_verifiers = tuple(fast_verifiers)
        by_format: dict[str, list[PasswordVerifier]] = {}
        for verifier in self._fast_verifiers:
            format_hint = _normalize_archive_format(str(getattr(verifier, "format_hint", "")))
            by_format.setdefault(format_hint, []).append(verifier)
        self._generic_verifiers = tuple(by_format.pop("", ()))
        self._preferred_verifiers = {
            format_hint: (*verifiers, *self._generic_verifiers)
            for format_hint, verifiers in by_format.items()
        }

    prepare_input = staticmethod(prepare_password_input)

    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | PasswordProbeInput | None = None,
    ) -> PasswordBatchVerification:
        preferred = _preferred_archive_format(archive_input)
        verifiers = (
            self._preferred_verifiers.get(preferred, self._generic_verifiers)
            if preferred else self._fast_verifiers
        )
        for verifier in verifiers:
            outcome = verifier.verify_batch(
                archive_path,
                passwords,
                part_paths=part_paths,
                archive_input=archive_input,
            )
            if outcome.status in {"unsupported_method", "unknown_needs_final_verifier"}:
                continue
            return outcome
        return PasswordBatchVerification(
            ok=False,
            status="unknown_needs_final_verifier",
            attempts=0,
            error_text="no bounded password verifier accepted archive",
        )


def _preferred_archive_format(archive_input: ArchiveInputDescriptor | dict | PasswordProbeInput | None) -> str:
    if isinstance(archive_input, (ArchiveInputDescriptor, PasswordProbeInput)):
        return _normalize_archive_format(archive_input.format_hint)
    if archive_input is not None:
        return _normalize_archive_format(
            str(archive_input.get("format_hint") or archive_input.get("format") or "")
        )
    return ""


def _normalize_archive_format(value: str) -> str:
    normalized = (value or "").strip().lower().lstrip(".")
    if normalized in {"7zip", "sevenzip", "seven_zip"}:
        return "7z"
    if normalized in {"zip", "rar", "7z", "enc"}:
        return normalized
    return ""
