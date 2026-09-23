from __future__ import annotations

from typing import Any

from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.passwords.candidates import PasswordCandidatePipeline
from sunpack.passwords.fingerprint import build_archive_fingerprint
from sunpack.passwords.job import PasswordJob
from sunpack.passwords.result import PasswordResolution, PasswordResolutionStatus
from sunpack.passwords.scheduler import PasswordScheduler, PasswordSearchResult, PasswordSearchStatus
from sunpack.passwords.session import PasswordSession


def _selected_structure_format(task: Any | None) -> str:
    if task is None:
        return ""
    knowledge = _knowledge(task)
    descriptor = _archive_input_descriptor(task)
    values = (
        knowledge.get("source.password_probe_input.format_hint"),
        knowledge.get("inspection.summary.format"),
        descriptor.format_hint if descriptor is not None else "",
        knowledge.get("source.input.format_hint"),
    )
    hint = next(
        (
            str(value or "").strip().lower().lstrip(".")
            for value in values
            if str(value or "").strip()
        ),
        "",
    )
    if hint in {"zip", "jar", "docx", "xlsx", "apk"}:
        return "zip"
    if hint in {"7z", "sevenzip", "seven_zip"}:
        return "7z"
    if hint in {"rar", "rar4", "rar5"}:
        return "rar"
    if hint == "tar":
        return "tar"
    if hint in {
        "gz", "gzip", "tgz", "tar.gz",
        "bz2", "bzip2", "tbz", "tbz2", "tar.bz2",
        "xz", "txz", "tar.xz",
        "zst", "zstd", "tzst", "tar.zst",
    }:
        return "compression"
    return ""


def _structure_facts(task: Any | None) -> list[tuple[str, dict]]:
    if task is None:
        return []
    knowledge = _knowledge(task)
    selected_format = _selected_structure_format(task)
    candidates = (
        ("rar", ("format.rar.structure",)),
        ("zip", ("format.zip.structure",)),
        ("7z", ("format.7z.structure",)),
        ("tar", ("format.tar.structure",)),
        ("compression", ("format.compression.structure", "compression.stream_structure")),
    )
    output: list[tuple[str, dict]] = []
    for fmt, paths in candidates:
        if selected_format and fmt != selected_format:
            continue
        for path in paths:
            value = knowledge.get(path)
            if isinstance(value, dict):
                output.append((fmt, value))
                break
    return output


def _validated_format_password_state(fmt: str, structure: dict) -> str:
    explicit = str(structure.get("password_state") or "").strip().lower()
    if explicit in {"required", "not_required"}:
        return explicit

    password_required = bool(structure.get("password_required"))
    if fmt == "rar":
        if structure.get("strong_accept") and password_required:
            return "required"
        if (
            structure.get("strong_accept")
            and structure.get("header_crc_ok")
            and "password_required" in structure
            and not password_required
            and not structure.get("header_encrypted")
        ):
            return "not_required"
        return "unknown"

    if fmt == "zip":
        try:
            encrypted_entries = int(
                structure.get("central_directory_encrypted_entries") or 0
            )
        except (TypeError, ValueError):
            encrypted_entries = 0
        structurally_valid = bool(
            structure.get("plausible")
            and structure.get("central_directory_present")
            and structure.get("central_directory_walk_ok")
        )
        if password_required and structurally_valid and encrypted_entries > 0:
            return "required"
        if (
            not password_required
            and structure.get("encryption_scan_complete")
            and structurally_valid
        ):
            return "not_required"
        return "unknown"

    if fmt == "7z":
        structurally_valid = bool(
            structure.get("strong_accept")
            or (
                structure.get("next_header_crc_ok")
                and structure.get("next_header_nid_valid")
            )
        )
        if (
            password_required
            and structurally_valid
            and structure.get("encryption_scan_complete", True)
        ):
            return "required"
        if (
            not password_required
            and structure.get("encryption_scan_complete")
            and structurally_valid
        ):
            return "not_required"

    if fmt in {"tar", "compression"}:
        return "not_required"
    return "unknown"


def archive_structure_password_state(task: Any | None) -> str:
    """Return the bounded password state for one structured archive input."""
    if task is None:
        return "unknown"

    descriptor = _archive_input_descriptor(task)
    if descriptor is not None:
        analysis = descriptor.analysis if isinstance(descriptor.analysis, dict) else {}
        if analysis.get("password_required"):
            return "required"

    evidence = _knowledge(task).get("discovery.evidence", {})
    if isinstance(evidence, dict) and evidence.get("needs_password"):
        return "required"

    active_format = _selected_structure_format(task)
    if active_format in {"tar", "compression"}:
        return "not_required"

    states = [
        _validated_format_password_state(fmt, value)
        for fmt, value in _structure_facts(task)
    ]
    if "required" in states:
        return "required"
    if "not_required" in states:
        return "not_required"
    return "unknown"


def archive_structure_requires_password(task: Any | None) -> bool:
    return archive_structure_password_state(task) == "required"


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
        task: Any | None = None,
        part_paths: list[str] | None = None,
        archive_key: str = "",
        directory_passwords: list[str] | None = None,
    ) -> PasswordResolution:
        archive_key = archive_key or _archive_key(task) or archive_path
        if self.password_session.has_resolved(archive_key):
            return PasswordResolution(
                password=self.password_session.get_resolved(archive_key),
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

        archive_input = self._archive_input_for_password_probe(task) or {}
        fingerprint = build_archive_fingerprint(
            archive_path,
            part_paths,
            archive_input=archive_input,
        )

        directory_passwords = list(directory_passwords or [])
        candidates = self.password_tester.password_store.candidates(
            directory_passwords=directory_passwords
        )
        if not candidates:
            if password_state == "required":
                return PasswordResolution(
                    password=None,
                    status=PasswordResolutionStatus.PASSWORD_REQUIRED,
                    error_text="archive requires a password but no candidates were provided",
                    archive_key=archive_key,
                    encrypted=True,
                )
            return self._confirmation_resolution(
                archive_key,
                "",
                fingerprint.key,
                task,
            )

        search = self._plan_password_search(
            archive_path,
            task=task,
            part_paths=part_paths,
            fingerprint=fingerprint,
            directory_passwords=directory_passwords,
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
            candidate_passwords = tuple(
                dict.fromkeys(search.extraction_candidates)
            )
            return self._confirmation_resolution(
                archive_key,
                candidate_passwords[0],
                fingerprint.key,
                task,
                candidate_evidence=search.extraction_candidate_evidence,
                candidate_passwords=candidate_passwords,
            )
        return self._remember_search(
            archive_key,
            search,
            encrypted=True if archive_structure_requires_password(task) else None,
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
        task: Any | None,
        part_paths: list[str] | None,
        fingerprint,
        directory_passwords: list[str] | None,
        include_empty: bool = False,
    ) -> PasswordSearchResult:
        archive_input = self._archive_input_for_password_probe(task)
        candidates = PasswordCandidatePipeline.from_password_store(
            self.password_tester.password_store,
            directory_passwords=directory_passwords,
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
        task: Any | None,
        *,
        candidate_evidence: str = "",
        candidate_passwords: tuple[str, ...] = (),
    ) -> PasswordResolution:
        return PasswordResolution(
            password=password,
            status=PasswordResolutionStatus.RESOLVED,
            archive_key=archive_key,
            encrypted=True if archive_structure_requires_password(task) else None,
            requires_extraction_confirmation=True,
            candidate_passwords=candidate_passwords,
            fingerprint_key=fingerprint_key,
            candidate_evidence=candidate_evidence,
        )

    @staticmethod
    def _archive_input_for_password_probe(task: Any | None) -> dict | None:
        if task is None:
            return None
        knowledge = _knowledge(task)
        knowledge_input = knowledge.get("source.password_probe_input")
        if not isinstance(knowledge_input, dict) or not knowledge_input:
            descriptor = _archive_input_descriptor(task)
            knowledge_input = descriptor.to_dict() if descriptor is not None else None
        if not isinstance(knowledge_input, dict):
            return None
        selected_format = _selected_structure_format(task)
        if selected_format in {"zip", "rar", "7z"}:
            return {**knowledge_input, "format_hint": selected_format}
        return knowledge_input

    def _remember(
        self,
        archive_key: str,
        password: str | None,
        status: PasswordResolutionStatus,
        test_result: object = None,
        error_text: str = "",
        encrypted: bool | None = None,
        remember_only_on_success: bool = False,
    ) -> PasswordResolution:
        if not remember_only_on_success or password is not None:
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
            PasswordSearchStatus.INCONCLUSIVE: PasswordResolutionStatus.INCONCLUSIVE,
            PasswordSearchStatus.STOPPED: PasswordResolutionStatus.INCONCLUSIVE,
        }[search.status]
        return self._remember(
            archive_key,
            search.password,
            status=status,
            test_result=search.test_result,
            error_text=search.error_text,
            encrypted=encrypted,
            remember_only_on_success=True,
        )


def _knowledge(task: Any) -> ArchiveKnowledge:
    if hasattr(task, "knowledge") and callable(task.knowledge):
        return task.knowledge()
    return ArchiveKnowledge()


def _archive_input_descriptor(task: Any):
    if hasattr(task, "archive_input") and callable(task.archive_input):
        try:
            return task.archive_input()
        except (TypeError, ValueError, AttributeError):
            return None
    return None


def _archive_key(task: Any | None) -> str:
    if task is None:
        return ""
    value = str(getattr(task, "key", "") or "")
    if value:
        return value
    descriptor = _archive_input_descriptor(task)
    if descriptor is None:
        return ""
    return str(descriptor.logical_name or descriptor.entry_path or "")
