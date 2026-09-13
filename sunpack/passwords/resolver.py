from __future__ import annotations

from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.contracts.detection import FactBag
from sunpack.passwords.candidates import PasswordCandidatePipeline
from sunpack.passwords.fingerprint import build_archive_fingerprint
from sunpack.passwords.job import PasswordJob
from sunpack.passwords.result import PasswordResolution, PasswordResolutionStatus
from sunpack.passwords.scheduler import PasswordScheduler, PasswordSearchResult, PasswordSearchStatus
from sunpack.passwords.session import PasswordSession


def _selected_structure_format(fact_bag: FactBag | None) -> str:
    """Return the format namespace belonging to the active logical input.

    A carrier task can retain structural facts for several archives found in
    the same byte stream.  Once extraction switches to one embedded range,
    those carrier facts must not participate in that range's password
    decision.  The archive input descriptor is the authoritative scope for
    this lookup; an empty hint deliberately keeps the historical all-format
    behavior for ordinary carrier tasks.
    """
    if fact_bag is None:
        return ""
    knowledge = ArchiveKnowledge.from_any(fact_bag.get("archive.knowledge"))
    values = (
        knowledge.get("source.password_probe_input.format_hint"),
        knowledge.get("source.input.format_hint"),
        knowledge.get("inspection.summary.format"),
        fact_bag.get("archive.format_hint"),
    )
    hint = next((str(value or "").strip().lower().lstrip(".") for value in values if str(value or "").strip()), "")
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


def _structure_facts(fact_bag: FactBag | None) -> list[tuple[str, dict]]:
    if fact_bag is None:
        return []
    knowledge = ArchiveKnowledge.from_any(fact_bag.get("archive.knowledge"))
    selected_format = _selected_structure_format(fact_bag)
    candidates = (
        ("rar", ("rar.structure", "format.rar.structure")),
        ("zip", ("zip.eocd_structure", "zip.structure", "format.zip.structure")),
        ("7z", ("7z.structure", "seven_zip.structure", "format.7z.structure")),
        ("tar", ("tar.header_structure", "format.tar.structure")),
        ("compression", ("compression.stream_structure", "format.compression.structure")),
    )
    output: list[tuple[str, dict]] = []
    for fmt, paths in candidates:
        if selected_format and fmt != selected_format:
            continue
        seen: set[int] = set()
        for path in paths:
            value = fact_bag.get(path)
            if not isinstance(value, dict):
                if path == "rar.structure":
                    knowledge_path = "format.rar.structure"
                elif path in {"zip.eocd_structure", "zip.structure"}:
                    knowledge_path = "format.zip.structure"
                elif path in {"7z.structure", "seven_zip.structure"}:
                    knowledge_path = "format.7z.structure"
                else:
                    knowledge_path = path
                value = knowledge.get(knowledge_path)
            if isinstance(value, dict) and id(value) not in seen:
                output.append((fmt, value))
                seen.add(id(value))
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
        encrypted_entries = structure.get("central_directory_encrypted_entries")
        try:
            encrypted_entries = int(encrypted_entries or 0)
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
        if password_required and structurally_valid and structure.get("encryption_scan_complete", True):
            return "required"
        if (
            not password_required
            and structure.get("encryption_scan_complete")
            and structurally_valid
        ):
            return "not_required"
    if fmt == "tar":
        # TAR has no archive-level password mechanism.  A valid header is
        # sufficient to prevent a user password list from being sent to the
        # generic archive backend.
        if structure.get("plausible") and structure.get("entry_walk_ok"):
            return "not_required"
        return "unknown"
    if fmt == "compression":
        # gzip/bzip2/xz/zstd stream containers likewise do not carry archive
        # passwords; the stream validator is the relevant structural proof.
        if structure.get("plausible"):
            return "not_required"
    return "unknown"


def archive_structure_password_state(fact_bag: FactBag | None) -> str:
    """Return the bounded structural password fact without running extraction."""
    active_format = _selected_structure_format(fact_bag)
    if active_format in {"tar", "compression"}:
        # The active archive-input descriptor is content-derived and scopes this
        # decision to one logical input.  These formats have no archive-level
        # password mechanism, so user candidates must never reach ZIP/RAR/7z
        # verifiers merely because the segment has no copied structure facts.
        return "not_required"
    states = [_validated_format_password_state(fmt, value) for fmt, value in _structure_facts(fact_bag)]
    if "required" in states:
        return "required"
    if "not_required" in states:
        return "not_required"
    return "unknown"


def archive_structure_requires_password(fact_bag: FactBag | None) -> bool:
    return archive_structure_password_state(fact_bag) == "required"


class PasswordResolver:
    """Plan bounded password checks and hand ambiguous candidates to extraction.

    Candidate origin never changes verification semantics.  Every password goes
    through the same fast-verifier plan; candidates lacking a bounded proof are
    submitted together to the SevenZip extraction worker, which performs a
    bounded backend probe before the real extraction transaction.
    """

    def __init__(
        self,
        password_tester,
        password_session: PasswordSession | None = None,
        password_scheduler: PasswordScheduler | None = None,
    ):
        self.password_tester = password_tester
        self.password_session = password_session or PasswordSession()
        self.password_scheduler = password_scheduler or password_tester.password_scheduler

    def resolve(
        self,
        archive_path: str,
        fact_bag: FactBag | None = None,
        part_paths: list[str] | None = None,
        archive_key: str = "",
        directory_passwords: list[str] | None = None,
    ) -> PasswordResolution:
        archive_key = archive_key or self._archive_key_from_fact_bag(fact_bag) or archive_path
        if self.password_session.has_resolved(archive_key):
            return PasswordResolution(
                password=self.password_session.get_resolved(archive_key),
                status=PasswordResolutionStatus.RESOLVED,
                archive_key=archive_key,
            )

        password_state = archive_structure_password_state(fact_bag)
        if password_state == "not_required":
            return self._remember(
                archive_key,
                "",
                status=PasswordResolutionStatus.UNENCRYPTED,
                encrypted=False,
            )

        archive_input = self._archive_input_for_password_probe(fact_bag) or {}
        fingerprint = build_archive_fingerprint(
            archive_path,
            part_paths,
            archive_input=archive_input,
        )

        directory_passwords = list(directory_passwords or [])
        candidates = self.password_tester.password_store.candidates(directory_passwords=directory_passwords)
        if not candidates:
            if password_state == "required":
                return PasswordResolution(
                    password=None,
                    status=PasswordResolutionStatus.PASSWORD_REQUIRED,
                    error_text="archive requires a password but no candidates were provided",
                    archive_key=archive_key,
                    encrypted=True,
                )
            # Unknown encryption state: let the real extraction prove the empty
            # password instead of performing a complete preflight test pass.
            return self._confirmation_resolution(archive_key, "", fingerprint.key, fact_bag)

        search = self._plan_password_search(
            archive_path,
            fact_bag=fact_bag,
            part_paths=part_paths,
            fingerprint=fingerprint,
            directory_passwords=directory_passwords,
            include_empty=password_state == "unknown",
        )
        if search.status in {PasswordSearchStatus.FOUND, PasswordSearchStatus.UNENCRYPTED}:
            resolution = self._remember_search(
                archive_key,
                search,
                encrypted=search.status == PasswordSearchStatus.FOUND,
            )
            if resolution.password:
                self._promote_success(resolution.password)
            return resolution
        if search.extraction_candidates:
            candidates = tuple(dict.fromkeys(search.extraction_candidates))
            return self._confirmation_resolution(
                archive_key,
                candidates[0],
                fingerprint.key,
                fact_bag,
                candidate_evidence=search.extraction_candidate_evidence,
                candidate_passwords=candidates,
            )
        return self._remember_search(
            archive_key,
            search,
            encrypted=True if self._facts_require_password(fact_bag) else None,
        )

    def confirm_extraction(self, resolution: PasswordResolution, password: str | None = None) -> None:
        password = password if password is not None else resolution.password
        if not resolution.requires_extraction_confirmation or password is None:
            return
        self.password_session.set_resolved(resolution.archive_key, password)
        self.password_scheduler.remember_extraction_success(resolution.fingerprint_key, password)
        if password:
            self._promote_success(password)

    def reject_extraction_candidates(self, resolution: PasswordResolution) -> None:
        if not resolution.requires_extraction_confirmation:
            return
        candidates = resolution.candidate_passwords or ((resolution.password,) if resolution.password is not None else ())
        for password in candidates:
            self.password_scheduler.remember_extraction_rejection(resolution.fingerprint_key, password)

    def _plan_password_search(
        self,
        archive_path: str,
        *,
        fact_bag: FactBag | None,
        part_paths: list[str] | None,
        fingerprint,
        directory_passwords: list[str] | None,
        include_empty: bool = False,
    ) -> PasswordSearchResult:
        archive_input = self._archive_input_for_password_probe(fact_bag)
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
        fact_bag: FactBag | None,
        *,
        candidate_evidence: str = "",
        candidate_passwords: tuple[str, ...] = (),
    ) -> PasswordResolution:
        return PasswordResolution(
            password=password,
            status=PasswordResolutionStatus.RESOLVED,
            archive_key=archive_key,
            encrypted=True if PasswordResolver._facts_require_password(fact_bag) else None,
            requires_extraction_confirmation=True,
            candidate_passwords=candidate_passwords,
            fingerprint_key=fingerprint_key,
            candidate_evidence=candidate_evidence,
        )

    @staticmethod
    def _archive_input_for_password_probe(fact_bag: FactBag | None) -> dict | None:
        if fact_bag is None:
            return None
        knowledge = ArchiveKnowledge.from_any(fact_bag.get("archive.knowledge"))
        knowledge_input = knowledge.get("source.password_probe_input")
        if not isinstance(knowledge_input, dict) or not knowledge_input:
            knowledge_input = knowledge.get("source.input")
        if not isinstance(knowledge_input, dict):
            return None
        selected_format = str(
            knowledge.get("inspection.summary.format", "")
            or knowledge_input.get("format_hint", "")
            or knowledge.get("source.input.format_hint", "")
            or fact_bag.get("archive.format_hint")
            or ""
        ).strip().lower().lstrip(".")
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

    @staticmethod
    def _facts_require_password(fact_bag: FactBag | None) -> bool:
        return archive_structure_requires_password(fact_bag)

    @staticmethod
    def _archive_key_from_fact_bag(fact_bag: FactBag | None) -> str:
        if fact_bag is None:
            return ""
        knowledge = ArchiveKnowledge.from_any(fact_bag.get("archive.knowledge"))
        source_derivation = knowledge.get("source.derivation") or {}
        if isinstance(source_derivation, dict):
            return str(source_derivation.get("candidate_logical_name") or source_derivation.get("candidate_entry_path") or "")
        source_input = knowledge.get("source.input") or {}
        return str(source_input.get("logical_name") or source_input.get("entry_path") or "") if isinstance(source_input, dict) else ""
