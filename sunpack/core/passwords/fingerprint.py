from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sunpack.core.support.archive_sessions import borrow_archive_sessions
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor


def _descriptor(value: Any) -> ArchiveInputDescriptor | None:
    if isinstance(value, ArchiveInputDescriptor):
        return value
    return ArchiveInputDescriptor.from_dict(value) if value else None


def _archive_input_scope(descriptor: ArchiveInputDescriptor | None) -> str:
    if descriptor is None:
        return ""
    return json.dumps((
        descriptor.format_hint, descriptor.open_mode, descriptor.volume_style,
        tuple((part.path, part.extent.start, part.extent.end, part.volume_number, part.canonical_name)
              for part in descriptor.parts),
        tuple((extent.path, extent.start, extent.end) for extent in descriptor.extents),
        descriptor.volume_attempts.to_dict() if descriptor.volume_attempts else None,
    ), ensure_ascii=False, separators=(",", ":"))


def build_archive_fingerprint(
    archive_path: str,
    part_paths: list[str] | None = None,
    archive_input: Any = None,
) -> str:
    descriptor = _descriptor(archive_input)
    source_paths = [archive_path, *(part_paths or [])]
    if descriptor is not None:
        source_paths.extend(descriptor.part_paths())
    normalized_paths = dict.fromkeys(str(Path(path).resolve()) for path in dict.fromkeys(source_paths))
    # Reuse validated readers: their tokens include event invalidation even
    # when physical metadata collides. Opening a session reads no archive data,
    # and the password probe reuses it through the existing operation scope.
    # Paths and native tokens cannot contain NUL; JSON escapes logical scope.
    fields = []
    for path in normalized_paths:
        try:
            with borrow_archive_sessions((path,)) as (session,):
                generation = session.generation_token
        except OSError:
            generation = "unavailable"
        fields.extend((path, generation))
    fields.append(_archive_input_scope(descriptor))
    return "\0".join(fields)
