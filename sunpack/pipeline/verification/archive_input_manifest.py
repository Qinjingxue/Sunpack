from __future__ import annotations

from dataclasses import dataclass, field
from dataclasses import replace
from typing import Any

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
STATUS_OK = 0
STATUS_WRONG_PASSWORD = 1
STATUS_DAMAGED = 2
STATUS_UNSUPPORTED = 3
STATUS_BACKEND_UNAVAILABLE = 4

from sunpack_native import (
    archive_state_tar_manifest_native as _native_archive_state_tar_manifest,
    archive_state_zip_manifest_native as _native_archive_state_zip_manifest,
)


@dataclass(frozen=True)
class ArchiveInputManifest:
    status: int
    is_archive: bool
    damaged: bool
    checksum_error: bool
    item_count: int
    file_count: int
    files: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""
    archive_type: str = ""
    source: str = "archive_input"
    input_aware: bool = True
    archive_walk_complete: bool = False
    verified_item_count: int = 0
    entries_truncated: bool = False
    total_unpacked_size_hint: int = 0
    summary_only: bool = False
    failure_kind: str = ""

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and self.is_archive and not self.damaged and not self.checksum_error

    @property
    def expected_names(self) -> list[str]:
        return [
            str(item.get("path") or "")
            for item in self.files
            if item.get("path") and not bool(item.get("shadowed"))
        ]

    @property
    def total_unpacked_size(self) -> int:
        if self.summary_only:
            return max(0, int(self.total_unpacked_size_hint or 0))
        return sum(
            max(0, int(item.get("size", 0) or 0))
            for item in self.files
            if not bool(item.get("shadowed"))
        )

    @property
    def retained_file_count(self) -> int:
        return sum(1 for item in self.files if not bool(item.get("shadowed")))


_EVIDENCE_CACHE_ATTRIBUTE = "_archive_input_manifest_full_cache"
_EVIDENCE_LIMIT_ATTRIBUTE = "_archive_input_manifest_full_max_items"


def configure_archive_input_manifest_cache(evidence, *, max_items: int) -> None:
    """Declare the largest manifest view needed during this verification run."""
    requested = max(0, int(max_items or 0))
    current = max(0, int(getattr(evidence, _EVIDENCE_LIMIT_ATTRIBUTE, 0) or 0))
    object.__setattr__(evidence, _EVIDENCE_LIMIT_ATTRIBUTE, max(current, requested))


def archive_input_manifest_for_evidence(evidence, *, max_items: int = 200000) -> ArchiveInputManifest:
    requested = max(0, int(max_items or 0))
    codepage = str(evidence.selected_codepage or "")
    identity = _evidence_manifest_identity(evidence, codepage)
    configured_limit = max(0, int(getattr(evidence, _EVIDENCE_LIMIT_ATTRIBUTE, 0) or 0))
    full_limit = max(requested, configured_limit)
    cached = getattr(evidence, _EVIDENCE_CACHE_ATTRIBUTE, None)
    if not (
        isinstance(cached, dict)
        and cached.get("identity") == identity
        and isinstance(cached.get("manifest"), ArchiveInputManifest)
        and int(cached.get("max_items", -1)) >= full_limit
    ):
        hint = _format_hint(evidence.archive_input)
        # TAR needs a source-side walk.  A worker manifest only proves that the
        # range it was handed extracted successfully; it cannot prove that an
        # incorrectly planned suffix range covered the source archive.
        full_manifest = None if hint == "tar" else _worker_verified_manifest(evidence)
        if full_manifest is None:
            full_manifest = archive_input_manifest(
                evidence.archive_input,
                max_items=full_limit,
                password=evidence.password,
                codepage=codepage or None,
            )
        cached = {
            "identity": identity,
            "max_items": full_limit,
            "manifest": full_manifest,
        }
        object.__setattr__(evidence, _EVIDENCE_CACHE_ATTRIBUTE, cached)
    return _manifest_view(cached["manifest"], requested)


def _worker_verified_manifest(evidence) -> ArchiveInputManifest | None:
    result = evidence.worker_result if isinstance(evidence.worker_result, dict) else {}
    payload = result.get("verified_manifest") if isinstance(result.get("verified_manifest"), dict) else {}
    from sunpack.pipeline.extraction.output_inventory import OutputInventory
    inventory = OutputInventory.from_value(
        getattr(evidence.extraction_result, "output_inventory", None),
        expected_root=evidence.output_dir,
    )
    if (
        result.get("status") != "ok"
        or not payload.get("validated")
        or inventory is None
        or not inventory.worker_inventory_complete
        or int(payload.get("file_count", -1) or 0) != inventory.stats.file_count
    ):
        return None
    file_count = int(inventory.stats.file_count or 0)
    item_count = int(payload.get("item_count", file_count) or 0)
    return ArchiveInputManifest(
        status=STATUS_OK,
        is_archive=True,
        damaged=False,
        checksum_error=False,
        item_count=item_count,
        file_count=file_count,
        files=[],
        message="Archive payload was verified during extraction",
        archive_type=str(result.get("archive_type") or ""),
        source=str(payload.get("source") or "sevenzip_worker_extract"),
        input_aware=True,
        archive_walk_complete=True,
        verified_item_count=item_count,
        entries_truncated=False,
        total_unpacked_size_hint=int(inventory.stats.total_size or 0),
        summary_only=True,
    )


def _evidence_manifest_identity(evidence, codepage: str) -> tuple:
    source = evidence.archive_input
    return (
        repr(source.to_dict()),
        str(evidence.password or ""),
        codepage,
    )


def _manifest_view(manifest: ArchiveInputManifest, max_items: int) -> ArchiveInputManifest:
    limit = max(0, int(max_items or 0))
    if len(manifest.files) <= limit:
        return manifest
    files = manifest.files[:limit]
    return replace(manifest, files=files, entries_truncated=True)


def archive_input_manifest(
    archive_input: ArchiveInputDescriptor,
    *,
    max_items: int = 200000,
    password: str | None = None,
    codepage: str | None = None,
) -> ArchiveInputManifest:
    hint = _format_hint(archive_input)
    if hint == "tar":
        return _tar_archive_input_manifest(archive_input, max_items=max_items)
    if hint and hint != "zip":
        return ArchiveInputManifest(
            status=STATUS_UNSUPPORTED,
            is_archive=False,
            damaged=False,
            checksum_error=False,
            item_count=0,
            file_count=0,
            message=f"Archive-input manifest is not implemented for format: {hint}",
            archive_type=hint,
        )

    try:
        payload = dict(_native_archive_state_zip_manifest(
            archive_input.to_dict(),
            max_items,
            password,
            codepage,
        ))
    except (OSError, ValueError) as exc:
        return ArchiveInputManifest(
            status=STATUS_UNSUPPORTED,
            is_archive=False,
            damaged=False,
            checksum_error=False,
            item_count=0,
            file_count=0,
            message=f"Archive input cannot be opened as a verification byte view: {exc}",
        )
    if not bool(payload.get("is_archive")) and not hint:
        return ArchiveInputManifest(
            status=STATUS_UNSUPPORTED,
            is_archive=False,
            damaged=False,
            checksum_error=False,
            item_count=0,
            file_count=0,
            message="Archive-input manifest could not identify a supported archive format",
        )
    files = [dict(item) for item in payload.get("files") or [] if isinstance(item, dict)]
    file_count = int(payload.get("file_count", 0) or 0)
    return ArchiveInputManifest(
        status=int(payload["status"]) if payload.get("status") is not None else STATUS_DAMAGED,
        is_archive=bool(payload.get("is_archive", False)),
        damaged=bool(payload.get("damaged", False)),
        checksum_error=bool(payload.get("checksum_error", False)),
        item_count=int(payload.get("item_count", 0) or 0),
        file_count=file_count,
        files=files,
        message=str(payload.get("message") or ""),
        archive_type=str(payload.get("archive_type") or "zip"),
        source=str(payload.get("source") or "archive_state_native"),
        input_aware=bool(payload.get("state_aware", True)),
        archive_walk_complete=(int(payload["status"]) if payload.get("status") is not None else STATUS_DAMAGED) == STATUS_OK,
        verified_item_count=(
            int(payload.get("item_count", 0) or 0)
            if (int(payload["status"]) if payload.get("status") is not None else STATUS_DAMAGED) == STATUS_OK
            else 0
        ),
        entries_truncated=len(files) < file_count,
        failure_kind=str(payload.get("failure_kind") or ""),
    )


def _format_hint(archive_input: ArchiveInputDescriptor) -> str:
    return str(archive_input.format_hint or "").strip().lower().lstrip(".")


def _tar_archive_input_manifest(
    archive_input: ArchiveInputDescriptor,
    *,
    max_items: int,
) -> ArchiveInputManifest:
    try:
        payload = dict(_native_archive_state_tar_manifest(
            archive_input.to_dict(),
            max_items,
        ))
    except (OSError, ValueError) as exc:
        return ArchiveInputManifest(
            status=STATUS_UNSUPPORTED, is_archive=False, damaged=False, checksum_error=False,
            item_count=0, file_count=0, message=f"TAR input could not be read: {exc}",
            archive_type="tar",
        )
    files = [dict(item) for item in payload.get("files") or [] if isinstance(item, dict)]
    status = int(
        payload["status"] if payload.get("status") is not None else STATUS_DAMAGED
    )
    damaged = bool(payload.get("damaged", False))
    file_count = int(payload.get("file_count", 0) or 0)
    return ArchiveInputManifest(
        status=status,
        is_archive=bool(payload.get("is_archive", False)),
        damaged=damaged,
        checksum_error=bool(payload.get("checksum_error", False)),
        item_count=int(payload.get("item_count", 0) or 0),
        file_count=file_count,
        files=files,
        message=str(payload.get("message") or ""),
        archive_type="tar",
        source=str(payload.get("source") or "archive_state_tar_native"),
        archive_walk_complete=bool(payload.get("archive_walk_complete", status == STATUS_OK)),
        verified_item_count=int(payload.get("verified_item_count", 0) or 0),
        entries_truncated=bool(payload.get("entries_truncated", len(files) < file_count)),
        failure_kind=str(payload.get("failure_kind") or ("corrupted_data" if damaged else "")),
    )
