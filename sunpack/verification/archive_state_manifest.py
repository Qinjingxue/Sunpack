from __future__ import annotations

from dataclasses import dataclass, field
from dataclasses import replace
from pathlib import Path
from typing import Any

from sunpack.contracts.archive_state import ArchiveState
from sunpack.support.sevenzip_bridge import STATUS_DAMAGED, STATUS_OK, STATUS_UNSUPPORTED
from sunpack_native import (
    archive_state_tar_manifest_native as _native_archive_state_tar_manifest,
    archive_state_zip_manifest_native as _native_archive_state_zip_manifest,
)


@dataclass(frozen=True)
class ArchiveStateManifest:
    status: int
    is_archive: bool
    damaged: bool
    checksum_error: bool
    item_count: int
    file_count: int
    files: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""
    archive_type: str = ""
    source: str = "archive_state"
    state_aware: bool = True
    archive_walk_complete: bool = False
    verified_item_count: int = 0
    entries_truncated: bool = False
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
        return sum(
            max(0, int(item.get("size", 0) or 0))
            for item in self.files
            if not bool(item.get("shadowed"))
        )

    @property
    def retained_file_count(self) -> int:
        return sum(1 for item in self.files if not bool(item.get("shadowed")))


_EVIDENCE_CACHE_ATTRIBUTE = "_archive_state_manifest_full_cache"
_EVIDENCE_LIMIT_ATTRIBUTE = "_archive_state_manifest_full_max_items"


def configure_archive_state_manifest_cache(evidence, *, max_items: int) -> None:
    """Declare the largest manifest view needed during this verification run."""
    requested = max(0, int(max_items or 0))
    current = max(0, int(getattr(evidence, _EVIDENCE_LIMIT_ATTRIBUTE, 0) or 0))
    object.__setattr__(evidence, _EVIDENCE_LIMIT_ATTRIBUTE, max(current, requested))


def archive_state_manifest_for_evidence(evidence, *, max_items: int = 200000) -> ArchiveStateManifest:
    requested = max(0, int(max_items or 0))
    codepage = str(evidence.selected_codepage or "")
    identity = _evidence_manifest_identity(evidence, codepage)
    configured_limit = max(0, int(getattr(evidence, _EVIDENCE_LIMIT_ATTRIBUTE, 0) or 0))
    full_limit = max(requested, configured_limit)
    cached = getattr(evidence, _EVIDENCE_CACHE_ATTRIBUTE, None)
    if not (
        isinstance(cached, dict)
        and cached.get("identity") == identity
        and isinstance(cached.get("manifest"), ArchiveStateManifest)
        and int(cached.get("max_items", -1)) >= full_limit
    ):
        hint = _format_hint(evidence.archive_state)
        # TAR needs a source-side walk.  A worker manifest only proves that the
        # range it was handed extracted successfully; it cannot prove that an
        # incorrectly planned suffix range covered the source archive.
        full_manifest = None if hint == "tar" else _worker_verified_manifest(evidence)
        if full_manifest is None:
            full_manifest = archive_state_manifest(
                evidence.archive_state,
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


def _worker_verified_manifest(evidence) -> ArchiveStateManifest | None:
    result = evidence.worker_result if isinstance(evidence.worker_result, dict) else {}
    payload = result.get("verified_manifest") if isinstance(result.get("verified_manifest"), dict) else {}
    from sunpack.support.output_inventory import OutputInventory
    inventory = OutputInventory.from_value(
        getattr(evidence.extraction_result, "output_inventory", None),
        expected_root=evidence.output_dir,
    )
    files = list(inventory.materialize_files()) if inventory is not None and inventory.worker_inventory_complete else []
    if (
        result.get("status") != "ok"
        or not payload.get("validated")
        or int(payload.get("file_count", -1) or 0) != len(files)
        or any(str(item.get("status") or "") != "complete" for item in files)
    ):
        return None
    return ArchiveStateManifest(
        status=STATUS_OK,
        is_archive=True,
        damaged=False,
        checksum_error=False,
        item_count=int(payload.get("item_count", len(files)) or 0),
        file_count=len(files),
        files=files,
        message="Archive payload was verified during extraction",
        archive_type=str(result.get("archive_type") or ""),
        source=str(payload.get("source") or "sevenzip_worker_extract"),
        state_aware=True,
        archive_walk_complete=True,
        verified_item_count=int(payload.get("item_count", len(files)) or 0),
        entries_truncated=False,
    )


def _evidence_manifest_identity(evidence, codepage: str) -> tuple:
    state = evidence.archive_state
    source = state.source
    return (
        repr(source.to_dict()),
        str(evidence.password or ""),
        codepage,
    )


def _manifest_view(manifest: ArchiveStateManifest, max_items: int) -> ArchiveStateManifest:
    limit = max(0, int(max_items or 0))
    if len(manifest.files) <= limit:
        return manifest
    files = manifest.files[:limit]
    return replace(manifest, files=files, entries_truncated=True)


def archive_state_manifest(
    state: ArchiveState,
    *,
    max_items: int = 200000,
    password: str | None = None,
    codepage: str | None = None,
) -> ArchiveStateManifest:
    hint = _format_hint(state)
    if hint == "tar" or (not hint and Path(state.source.entry_path).suffix.lower() == ".tar"):
        return _tar_archive_state_manifest(state, max_items=max_items)
    if hint and hint != "zip" and not Path(state.source.entry_path).suffix.lower() == ".zip":
        return ArchiveStateManifest(
            status=STATUS_UNSUPPORTED,
            is_archive=False,
            damaged=False,
            checksum_error=False,
            item_count=0,
            file_count=0,
            message=f"Archive-state manifest is not implemented for format: {hint}",
            archive_type=hint,
        )

    try:
        payload = dict(_native_archive_state_zip_manifest(
            state.source.to_dict(),
            max_items,
            password,
            codepage,
        ))
    except (OSError, ValueError) as exc:
        return ArchiveStateManifest(
            status=STATUS_UNSUPPORTED,
            is_archive=False,
            damaged=False,
            checksum_error=False,
            item_count=0,
            file_count=0,
            message=f"Archive state cannot be opened as a verification byte view: {exc}",
        )
    if not bool(payload.get("is_archive")) and not hint:
        return ArchiveStateManifest(
            status=STATUS_UNSUPPORTED,
            is_archive=False,
            damaged=False,
            checksum_error=False,
            item_count=0,
            file_count=0,
            message="Archive-state manifest could not identify a supported archive format",
        )
    files = [dict(item) for item in payload.get("files") or [] if isinstance(item, dict)]
    file_count = int(payload.get("file_count", 0) or 0)
    return ArchiveStateManifest(
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
        state_aware=bool(payload.get("state_aware", True)),
        archive_walk_complete=(int(payload["status"]) if payload.get("status") is not None else STATUS_DAMAGED) == STATUS_OK,
        verified_item_count=(
            int(payload.get("item_count", 0) or 0)
            if (int(payload["status"]) if payload.get("status") is not None else STATUS_DAMAGED) == STATUS_OK
            else 0
        ),
        entries_truncated=len(files) < file_count,
        failure_kind=str(payload.get("failure_kind") or ""),
    )


def _format_hint(state: ArchiveState) -> str:
    return str(state.format_hint or state.source.format_hint or "").strip().lower().lstrip(".")


def _tar_archive_state_manifest(
    state: ArchiveState,
    *,
    max_items: int,
) -> ArchiveStateManifest:
    try:
        payload = dict(_native_archive_state_tar_manifest(
            state.source.to_dict(),
            max_items,
        ))
    except (OSError, ValueError) as exc:
        return ArchiveStateManifest(
            status=STATUS_UNSUPPORTED, is_archive=False, damaged=False, checksum_error=False,
            item_count=0, file_count=0, message=f"TAR state could not be read: {exc}",
            archive_type="tar",
        )
    files = [dict(item) for item in payload.get("files") or [] if isinstance(item, dict)]
    status = int(
        payload["status"] if payload.get("status") is not None else STATUS_DAMAGED
    )
    damaged = bool(payload.get("damaged", False))
    file_count = int(payload.get("file_count", 0) or 0)
    return ArchiveStateManifest(
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
