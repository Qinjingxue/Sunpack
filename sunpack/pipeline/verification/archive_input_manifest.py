from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
STATUS_OK = 0
STATUS_WRONG_PASSWORD = 1
STATUS_DAMAGED = 2
STATUS_UNSUPPORTED = 3
STATUS_BACKEND_UNAVAILABLE = 4

from sunpack_native import (
    NativeArchiveManifest,
    archive_state_tar_manifest_native as _native_archive_state_tar_manifest,
    archive_state_zip_manifest_native as _native_archive_state_zip_manifest,
)


@dataclass(frozen=True)
class ArchiveInputManifest:
    """Archive-input manifest summary over a Rust-owned entry table.

    ``entries`` holds the retained regular-file entries in Rust; a view only
    narrows ``entry_limit`` and never copies entries into Python objects.
    """

    status: int
    is_archive: bool
    damaged: bool
    checksum_error: bool
    item_count: int
    file_count: int
    entries: NativeArchiveManifest | None = None
    entry_limit: int | None = None
    message: str = ""
    archive_type: str = ""
    source: str = "archive_input"
    archive_walk_complete: bool = False
    verified_item_count: int = 0
    entries_truncated: bool = False
    # Aggregate over every regular file the walk saw, independent of how many
    # entries are retained or exposed by a view.
    total_unpacked_size: int = 0
    failure_kind: str = ""

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and self.is_archive and not self.damaged and not self.checksum_error

    @property
    def retained_file_count(self) -> int:
        if self.entries is None:
            return 0
        retained = len(self.entries)
        return retained if self.entry_limit is None else min(retained, self.entry_limit)

    @property
    def expected_names(self) -> list[str]:
        if self.entries is None:
            return []
        return list(self.entries.expected_names(self.retained_file_count))


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
    return _manifest_view(cached, requested)


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
        message="Archive payload was verified during extraction",
        archive_type=str(result.get("archive_type") or ""),
        source=str(payload.get("source") or "sevenzip_worker_extract"),
        archive_walk_complete=True,
        verified_item_count=item_count,
        total_unpacked_size=int(inventory.stats.total_size or 0),
    )


def _evidence_manifest_identity(evidence, codepage: str) -> tuple:
    source = evidence.archive_input
    return (
        repr(source.to_dict()),
        str(evidence.password or ""),
        codepage,
    )


def _manifest_view(cached: dict, max_items: int) -> ArchiveInputManifest:
    manifest: ArchiveInputManifest = cached["manifest"]
    limit = max(0, int(max_items or 0))
    if manifest.retained_file_count <= limit:
        return manifest
    return replace(manifest, entry_limit=limit, entries_truncated=True)


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
        native = _native_archive_state_zip_manifest(
            archive_input.to_dict(),
            max_items,
            password,
            codepage,
        )
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
    if not native.is_archive and not hint:
        return ArchiveInputManifest(
            status=STATUS_UNSUPPORTED,
            is_archive=False,
            damaged=False,
            checksum_error=False,
            item_count=0,
            file_count=0,
            message="Archive-input manifest could not identify a supported archive format",
        )
    return _manifest_from_native(native)


def _format_hint(archive_input: ArchiveInputDescriptor) -> str:
    return str(archive_input.format_hint or "").strip().lower().lstrip(".")


def _tar_archive_input_manifest(
    archive_input: ArchiveInputDescriptor,
    *,
    max_items: int,
) -> ArchiveInputManifest:
    try:
        native = _native_archive_state_tar_manifest(
            archive_input.to_dict(),
            max_items,
        )
    except (OSError, ValueError) as exc:
        return ArchiveInputManifest(
            status=STATUS_UNSUPPORTED, is_archive=False, damaged=False, checksum_error=False,
            item_count=0, file_count=0, message=f"TAR input could not be read: {exc}",
            archive_type="tar",
        )
    return _manifest_from_native(native)


def _manifest_from_native(native: NativeArchiveManifest) -> ArchiveInputManifest:
    file_count = int(native.file_count)
    return ArchiveInputManifest(
        status=int(native.status),
        is_archive=bool(native.is_archive),
        damaged=bool(native.damaged),
        checksum_error=bool(native.checksum_error),
        item_count=int(native.item_count),
        file_count=file_count,
        entries=native,
        message=str(native.message),
        archive_type=str(native.archive_type),
        source=str(native.source),
        archive_walk_complete=bool(native.archive_walk_complete),
        verified_item_count=int(native.verified_item_count),
        entries_truncated=len(native) < file_count,
        total_unpacked_size=int(native.total_unpacked_size),
        failure_kind=str(native.failure_kind),
    )
