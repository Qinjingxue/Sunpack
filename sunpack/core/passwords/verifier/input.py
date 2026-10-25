"""One request-owned projection of the canonical Rust input for password batches."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field, replace

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, InputExtent


_VOLUME_CALLBACK_STYLES = frozenset({
    "rar_part", "rar_oldstyle", "rar_sfx_part", "sfx_numeric_suffix", "zip_spanned",
})


@dataclass(slots=True)
class PasswordProbeInput:
    source: dict | None
    path: str
    ranges: list[dict] | None = None
    volumes: list[dict] | None = None
    volume_style: str = ""
    volume_aware: bool = False
    session_paths: tuple[str, ...] = ()
    _stack: ExitStack | None = field(default=None, repr=False)
    _sessions: tuple | None = field(default=None, repr=False)

    def get(self, key, default=None):
        return self.source.get(key, default) if self.source is not None else default

    @contextmanager
    def scope(self):
        # The job borrows lazily and releases on every return/error. No cache
        # pins readers after password planning, extraction or cancellation.
        with ExitStack() as stack:
            bound = replace(self, _stack=stack, _sessions=None)
            try:
                yield bound
            finally:
                bound._sessions = None
                bound._stack = None

    @contextmanager
    def borrow_sessions(self):
        from sunpack.core.support.archive_sessions import borrow_archive_sessions
        if self._stack is None:
            with borrow_archive_sessions(self.session_paths) as sessions:
                yield sessions
        else:
            if self._sessions is None:
                self._sessions = self._stack.enter_context(borrow_archive_sessions(self.session_paths))
            yield self._sessions


def prepare_password_input(
    archive_path: str, *, part_paths: list[str] | None = None,
    archive_input: dict | PasswordProbeInput | None = None,
) -> PasswordProbeInput:
    if isinstance(archive_input, PasswordProbeInput):
        return archive_input
    if not archive_input:
        return PasswordProbeInput(archive_input, archive_path, volume_aware=bool(part_paths), session_paths=(archive_path,))
    descriptor = ArchiveInputDescriptor.from_dict(archive_input, archive_path=archive_path, part_paths=part_paths)
    path = descriptor.entry_path or archive_path
    volumes = None
    volume_aware = descriptor.open_mode == "sfx_with_volumes"
    ranges = None
    if descriptor.open_mode in {"native_volumes", "sfx_with_volumes"}:
        volume_aware = volume_aware or descriptor.volume_style in _VOLUME_CALLBACK_STYLES
        if volume_aware:
            volumes = [part.to_dict() for part in descriptor.parts]
        else:
            ranges = [InputExtent(part.path).to_dict() for part in descriptor.parts]
    elif descriptor.open_mode != "file":
        extents = descriptor.extents or [part.extent for part in descriptor.parts]
        # Preserve explicit boundaries; no stat/reinterpretation of Rust's plan.
        if len(extents) == 1 and extents[0].start == 0 and extents[0].end is None:
            path = extents[0].path
        elif extents:
            ranges = [extent.to_dict() for extent in extents]
    physical = volumes if volume_aware and volumes else ranges
    return PasswordProbeInput(
        archive_input, path, ranges, volumes, descriptor.volume_style, volume_aware,
        tuple(item["path"] for item in physical) if physical else (path,),
    )
