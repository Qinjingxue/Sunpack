from __future__ import annotations

from dataclasses import dataclass, field

from sunpack.core.passwords.verifier.base import PasswordBatchVerification, PasswordVerifier


@dataclass
class PasswordVerifierRegistry:
    fast_verifiers: list[PasswordVerifier] = field(default_factory=list)

    def add_fast(self, verifier: PasswordVerifier) -> None:
        self.fast_verifiers.append(verifier)

    def build(self) -> PasswordVerifier:
        if len(self.fast_verifiers) == 1:
            return self.fast_verifiers[0]
        return PasswordVerifierChain(list(self.fast_verifiers))


class PasswordVerifierChain:
    """Dispatch bounded password verifiers in format-preferred order.

    This layer never performs full-payload confirmation. Verifiers return either
    a conclusive result or weak candidate evidence; the extraction worker owns
    confirmation of weak candidates.
    """

    def __init__(self, fast_verifiers: list[PasswordVerifier]):
        self.fast_verifiers = list(fast_verifiers)

    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        return self._run_fast_verifiers(
            archive_path,
            passwords,
            part_paths=part_paths,
            archive_input=archive_input,
        )

    def verify_fast_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        return self.verify_batch(
            archive_path,
            passwords,
            part_paths=part_paths,
            archive_input=archive_input,
        )

    def _run_fast_verifiers(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        for verifier in self._ordered_fast_verifiers(archive_path, archive_input):
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

    def _ordered_fast_verifiers(
        self,
        archive_path: str,
        archive_input: dict | None = None,
    ) -> list[PasswordVerifier]:
        preferred = _preferred_archive_format(archive_input)
        if not preferred:
            return list(self.fast_verifiers)
        matching = [
            verifier
            for verifier in self.fast_verifiers
            if _normalize_archive_format(str(getattr(verifier, "format_hint", ""))) == preferred
        ]
        generic = [
            verifier
            for verifier in self.fast_verifiers
            if not _normalize_archive_format(str(getattr(verifier, "format_hint", "")))
        ]
        if not matching:
            return list(self.fast_verifiers)
        return matching + [verifier for verifier in generic if verifier not in matching]


def _preferred_archive_format(archive_input: dict | None = None) -> str:
    if isinstance(archive_input, dict):
        hinted = _normalize_archive_format(
            str(archive_input.get("format_hint") or archive_input.get("format") or "")
        )
        if hinted:
            return hinted
    return ""


def _normalize_archive_format(value: str) -> str:
    normalized = (value or "").strip().lower().lstrip(".")
    if normalized in {"7zip", "sevenzip", "seven_zip"}:
        return "7z"
    if normalized in {"zip", "rar", "7z"}:
        return normalized
    return ""
