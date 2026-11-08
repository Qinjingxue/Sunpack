import weakref
from dataclasses import dataclass

from sunpack_native import AnalysisMultiVolumeView as _NativeAnalysisMultiVolumeView
from sunpack.core.support.archive_sessions import get_archive_session
from sunpack.core.support.resource_lifecycle import (
    ResourceKind,
    lifecycle_registration,
    register_current_task_resource,
)


@dataclass(frozen=True)
class ReadStats:
    read_bytes: int
    cache_hits: int


class _BinaryView:
    def _register_native(self, paths, kind: ResourceKind) -> None:
        self._resource_lease = register_current_task_resource(
            self,
            paths,
            self._native.close,
            kind=kind,
            registration_held=True,
        )
        self._resource_finalizer = weakref.finalize(self, self._resource_lease.close)
        self.size = int(self._native.size)

    @property
    def closed(self) -> bool:
        return self._resource_lease.closed

    def close(self) -> None:
        self._resource_lease.close()
        self._resource_finalizer.detach()

    def __enter__(self) -> "_BinaryView":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def read_at(self, offset: int, size: int) -> bytes:
        return bytes(self._native.read_at(int(offset), int(size)))

    def read_tail(self, size: int) -> bytes:
        return bytes(self._native.read_tail(int(size)))

    def stats(self) -> ReadStats:
        stats = self._native.stats()
        return ReadStats(
            read_bytes=int(stats.get("read_bytes", 0) or 0),
            cache_hits=int(stats.get("cache_hits", 0) or 0),
        )

    def analyze(
        self,
        config,
        *,
        initial_prepass: dict | None,
        format_structure: bool,
    ) -> dict:
        return self._native.analyze(config, initial_prepass, format_structure)


class SharedBinaryView(_BinaryView):
    """Thread-safe random-access binary view with a small shared LRU cache."""

    def __init__(
        self,
        path: str,
        *,
        cache_bytes: int = 64 * 1024 * 1024,
    ):
        self.path = path
        with lifecycle_registration((path,)) as identities:
            # The native view owns its reader independently of the cached session.
            session = get_archive_session(path, identity=identities[0])
            self._native = session.analysis_view(
                cache_bytes=max(0, int(cache_bytes or 0)),
            )
            self._register_native(identities, ResourceKind.NATIVE_ANALYSIS_VIEW)


class MultiVolumeBinaryView(_BinaryView):
    """Random-access logical view over ordered split-volume files.

    Archive analysis is native-only. Python owns lifecycle and structured
    input normalization; Rust owns byte layout, format parsing, and scoring.
    """

    def __init__(
        self,
        paths,
        *,
        cache_bytes: int = 64 * 1024 * 1024,
    ):
        volumes = _volume_paths(paths)
        if not volumes:
            raise ValueError("MultiVolumeBinaryView requires at least one volume")
        with lifecycle_registration(volumes) as identities:
            self._native = _NativeAnalysisMultiVolumeView(
                volumes,
                cache_bytes=max(0, int(cache_bytes or 0)),
            )
            self._register_native(identities, ResourceKind.NATIVE_MULTI_VOLUME_VIEW)
        self.path = str(self._native.path)


def _volume_paths(paths) -> list[str]:
    entries = list(paths or [])
    if entries and all(isinstance(item, dict) for item in entries):
        entries = sorted(entries, key=lambda item: int(item.get("number") or 0))
        return [str(item["path"]) for item in entries if item.get("path")]
    return [path for item in entries if (path := str(item))]
