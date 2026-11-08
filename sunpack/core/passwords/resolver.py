from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor

from sunpack.core.support.archive_formats import canonical_format
from sunpack.core.support.archive_sessions import archive_session_scope

from sunpack.core.passwords.candidates import PasswordCandidatePipeline
from sunpack.core.passwords.fingerprint import build_archive_fingerprint
from sunpack.core.passwords.job import PasswordJob
from sunpack.core.passwords.result import PasswordResolution, PasswordResolutionStatus
from sunpack.core.passwords.scheduler import PasswordScheduler, PasswordSearchResult, PasswordSearchStatus
from sunpack.core.passwords.session import PasswordSession

if TYPE_CHECKING:
    from sunpack.core.contracts.tasks import ArchiveTask


def _selected_structure_format(
    descriptor: ArchiveInputDescriptor, probe_input: ArchiveInputDescriptor | None,
) -> str:
    hint = canonical_format(
        (probe_input.format_hint if probe_input is not None else "") or descriptor.format_hint,
        unknown="",
    )
    if hint in {"jar", "docx", "xlsx", "apk"}:
        return "zip"
    if hint in {"rar4", "rar5"}:
        return "rar"
    return hint


def archive_structure_password_state(task: ArchiveTask | None) -> str:
    """Return the bounded password state for one structured archive input."""
    if task is None:
        return "unknown"

    descriptor = task.archive_input()
    if descriptor.format_hint == "enc" or descriptor.analysis.get("password_required"):
        return "required"

    evidence = task.knowledge().get("discovery.evidence", {})
    if isinstance(evidence, dict) and evidence.get("needs_password"):
        return "required"

    active_format = _selected_structure_format(descriptor, task.password_probe_input)
    if active_format in {"tar", "gzip", "bzip2", "xz", "zstd", "lz4"}:
        return "not_required"
    return "unknown"


class PasswordResolver:
    """Plan bounded password checks from ArchiveTask/ArchiveInput state."""

    def __init__(
        self,
        password_tester,
        password_session: PasswordSession | None = None,
        password_scheduler: PasswordScheduler | None = None,
    ):
        self.password_tester = password_tester
        self.password_session = password_session or PasswordSession()
        self.password_scheduler = (
            password_scheduler or password_tester.password_scheduler
        )

    def resolve(
        self,
        archive_path: str,
        task: ArchiveTask | None = None,
        part_paths: list[str] | None = None,
        archive_key: str = "",
        scope_path: str = "",
    ) -> PasswordResolution:
        archive_key = archive_key or (task.key if task is not None else archive_path)
        password = self.password_session.get_resolved(archive_key)
        if password is not None:
            return PasswordResolution(
                password=password,
                status=PasswordResolutionStatus.RESOLVED,
                archive_key=archive_key,
            )

        password_state = archive_structure_password_state(task)
        if password_state == "not_required":
            return self._remember(
                archive_key,
                "",
                status=PasswordResolutionStatus.UNENCRYPTED,
                encrypted=False,
            )

        has_candidates = self.password_tester.password_store.has_candidates(scope_path=scope_path)
        if not has_candidates and password_state == "required":
            return PasswordResolution(
                password=None,
                status=PasswordResolutionStatus.PASSWORD_REQUIRED,
                error_text="archive requires a password but no candidates were provided",
                archive_key=archive_key,
                encrypted=True,
            )

        archive_input = self._archive_input_for_password_probe(task)
        # Fingerprinting validates each physical file. Reuse those readers for
        # the bounded password probes of this same logical input operation.
        with archive_session_scope():
            fingerprint = build_archive_fingerprint(
                archive_path,
                part_paths,
                archive_input=archive_input,
            )
            if not has_candidates:
                return self._confirmation_resolution(
                    archive_key,
                    "",
                    fingerprint.key,
                    candidate_passwords=("",),
                    candidate_evidence="empty_password_direct",
                )
            search = self._plan_password_search(
                archive_path,
                archive_input=archive_input,
                part_paths=part_paths,
                fingerprint=fingerprint,
                scope_path=scope_path,
                include_empty=password_state == "unknown",
            )
        if search.status in {
            PasswordSearchStatus.FOUND,
            PasswordSearchStatus.UNENCRYPTED,
        }:
            resolution = self._remember_search(
                archive_key,
                search,
                encrypted=search.status == PasswordSearchStatus.FOUND,
            )
            if resolution.password:
                self._promote_success(resolution.password)
            return resolution
        if search.extraction_candidates:
            candidate_passwords = tuple(search.extraction_candidates)
            return self._confirmation_resolution(
                archive_key,
                candidate_passwords[0],
                fingerprint.key,
                encrypted=True if password_state == "required" else None,
                candidate_evidence=search.extraction_candidate_evidence,
                candidate_passwords=candidate_passwords,
            )
        return self._remember_search(
            archive_key,
            search,
            encrypted=True if password_state == "required" else None,
        )

    def confirm_extraction(
        self,
        resolution: PasswordResolution,
        password: str | None = None,
    ) -> None:
        password = password if password is not None else resolution.password
        if not resolution.requires_extraction_confirmation or password is None:
            return
        self.password_session.set_resolved(resolution.archive_key, password)
        self.password_scheduler.remember_extraction_success(
            resolution.fingerprint_key,
            password,
        )
        if password:
            self._promote_success(password)

    def reject_extraction_candidates(self, resolution: PasswordResolution) -> None:
        if not resolution.requires_extraction_confirmation:
            return
        candidates = resolution.candidate_passwords or (
            (resolution.password,) if resolution.password is not None else ()
        )
        for password in candidates:
            self.password_scheduler.remember_extraction_rejection(
                resolution.fingerprint_key,
                password,
            )

    def _plan_password_search(
        self,
        archive_path: str,
        *,
        archive_input: ArchiveInputDescriptor | None,
        part_paths: list[str] | None,
        fingerprint,
        scope_path: str,
        include_empty: bool = False,
    ) -> PasswordSearchResult:
        candidates = PasswordCandidatePipeline.from_password_store(
            self.password_tester.password_store,
            scope_path=scope_path,
            include_empty=include_empty,
        )
        return self.password_scheduler.plan_for_extraction(PasswordJob(
            archive_path=archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
            fingerprint=fingerprint,
            candidates=candidates,
        ))

    def _promote_success(self, password: str) -> None:
        self.password_tester.add_recent_password(password)

    @staticmethod
    def _confirmation_resolution(
        archive_key: str,
        password: str,
        fingerprint_key: str,
        *,
        encrypted: bool | None = None,
        candidate_evidence: str = "",
        candidate_passwords: tuple[str, ...] = (),
    ) -> PasswordResolution:
        return PasswordResolution(
            password=password,
            status=PasswordResolutionStatus.RESOLVED,
            archive_key=archive_key,
            encrypted=encrypted,
            requires_extraction_confirmation=True,
            candidate_passwords=candidate_passwords,
            fingerprint_key=fingerprint_key,
            candidate_evidence=candidate_evidence,
        )

    @staticmethod
    def _archive_input_for_password_probe(task: ArchiveTask | None) -> ArchiveInputDescriptor | None:
        if task is None:
            return None
        probe_input = task.password_probe_input
        descriptor = task.archive_input()
        selected_input = probe_input or descriptor
        selected_format = _selected_structure_format(descriptor, probe_input)
        if selected_format in {"zip", "rar", "7z"} and selected_format != selected_input.format_hint:
            return replace(selected_input, format_hint=selected_format)
        return selected_input

    def _remember(
        self,
        archive_key: str,
        password: str | None,
        status: PasswordResolutionStatus,
        test_result: object = None,
        error_text: str = "",
        encrypted: bool | None = None,
    ) -> PasswordResolution:
        if password is not None:
            self.password_session.set_resolved(archive_key, password)
        return PasswordResolution(
            password=password,
            status=status,
            test_result=test_result,
            error_text=error_text,
            archive_key=archive_key,
            encrypted=encrypted,
        )

    def _remember_search(
        self,
        archive_key: str,
        search: PasswordSearchResult,
        *,
        encrypted: bool | None,
    ) -> PasswordResolution:
        status = {
            PasswordSearchStatus.FOUND: PasswordResolutionStatus.RESOLVED,
            PasswordSearchStatus.UNENCRYPTED: PasswordResolutionStatus.UNENCRYPTED,
            PasswordSearchStatus.EXHAUSTED: PasswordResolutionStatus.CANDIDATES_EXHAUSTED,
            PasswordSearchStatus.DAMAGED: PasswordResolutionStatus.DAMAGED,
            PasswordSearchStatus.UNSUPPORTED: PasswordResolutionStatus.UNSUPPORTED,
            PasswordSearchStatus.BACKEND_UNAVAILABLE: PasswordResolutionStatus.BACKEND_ERROR,
            PasswordSearchStatus.NEEDS_VOLUME_OR_TAIL_DAMAGED: PasswordResolutionStatus.NEEDS_VOLUME_OR_TAIL_DAMAGED,
            PasswordSearchStatus.MISSING_VOLUME: PasswordResolutionStatus.MISSING_VOLUME,
            PasswordSearchStatus.INCONCLUSIVE: PasswordResolutionStatus.INCONCLUSIVE,
        }[search.status]
        return self._remember(
            archive_key,
            search.password,
            status=status,
            test_result=search.test_result,
            error_text=search.error_text,
            encrypted=encrypted,
        )
