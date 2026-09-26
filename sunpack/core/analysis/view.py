import os
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


class SharedBinaryView:
    """Thread-safe random-access binary view with a small shared LRU cache."""

    def __init__(
        self,
        path: str,
        *,
        cache_bytes: int = 64 * 1024 * 1024,
        max_read_bytes: int | None = None,
        max_concurrent_reads: int = 1,
    ):
        self.path = path
        self.size = os.path.getsize(path)
        self.cache_bytes = max(0, int(cache_bytes or 0))
        self.max_read_bytes = max_read_bytes if max_read_bytes is None else max(0, int(max_read_bytes))
        with lifecycle_registration((path,)):
            self._session = get_archive_session(path)
            self._native = self._session.analysis_view(
                cache_bytes=self.cache_bytes,
                max_read_bytes=self.max_read_bytes,
                max_concurrent_reads=max_concurrent_reads,
            )
            native = self._native
            self._resource_lease = register_current_task_resource(
                self,
                (path,),
                lambda native=native: getattr(native, "close", lambda: None)(),
                kind=ResourceKind.NATIVE_ANALYSIS_VIEW,
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
        self._session = None

    def __enter__(self) -> "SharedBinaryView":
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

    def signature_prepass(self, *, head_bytes: int, tail_bytes: int) -> dict | None:
        return dict(self._native.signature_prepass(int(head_bytes), int(tail_bytes)))

    def probe_zip(self, *, eocd_offset: int, max_cd_entries_to_walk: int = 64) -> dict | None:
        return dict(self._native.probe_zip(int(eocd_offset), int(max_cd_entries_to_walk)))

    def probe_rar(self, *, start_offset: int, max_blocks_to_walk: int = 4096) -> dict | None:
        return dict(self._native.probe_rar(int(start_offset), int(max_blocks_to_walk)))

    def probe_seven_zip(self, *, start_offset: int, max_next_header_check_bytes: int = 1024 * 1024) -> dict | None:
        return dict(self._native.probe_seven_zip(int(start_offset), int(max_next_header_check_bytes)))

    def probe_tar(self, *, start_offset: int = 0, max_entries_to_walk: int = 64) -> dict | None:
        return dict(self._native.probe_tar(int(start_offset), int(max_entries_to_walk)))

    def probe_compression_stream(self, *, format: str) -> dict | None:
        return dict(self._native.probe_compression_stream(str(format)))

    def probe_compressed_tar(self, *, format: str, max_probe_bytes: int = 4 * 1024 * 1024) -> dict | None:
        return dict(self._native.probe_compressed_tar(str(format), int(max_probe_bytes)))


class MultiVolumeBinaryView:
    """Random-access logical view over ordered split-volume files.

    Archive structure parsing is native-only. Python owns lifecycle and
    structured input normalization; Rust owns byte layout and format parsing.
    """

    def __init__(
        self,
        paths,
        *,
        cache_bytes: int = 64 * 1024 * 1024,
        max_read_bytes: int | None = None,
        max_concurrent_reads: int = 1,
    ):
        entries = _normalize_volume_entries(paths)
        self.volumes = [entry["path"] for entry in entries]
        if not self.volumes:
            raise ValueError("MultiVolumeBinaryView requires at least one volume")
        styles = {entry["style"] for entry in entries if entry["style"]}
        self.volume_style = next(iter(styles)) if len(styles) == 1 else ""
        self.path = self.volumes[0]
        self.cache_bytes = max(0, int(cache_bytes or 0))
        self.max_read_bytes = max_read_bytes if max_read_bytes is None else max(0, int(max_read_bytes))
        with lifecycle_registration(self.volumes):
            self._native = _NativeAnalysisMultiVolumeView(
                self.volumes,
                cache_bytes=self.cache_bytes,
                max_read_bytes=self.max_read_bytes,
                max_concurrent_reads=max_concurrent_reads,
            )
            native = self._native
            self._resource_lease = register_current_task_resource(
                self,
                self.volumes,
                lambda native=native: getattr(native, "close", lambda: None)(),
                kind=ResourceKind.NATIVE_MULTI_VOLUME_VIEW,
                registration_held=True,
            )
        self._resource_finalizer = weakref.finalize(self, self._resource_lease.close)
        self.path = str(self._native.path)
        self.size = int(self._native.size)

    @property
    def closed(self) -> bool:
        return self._resource_lease.closed

    def close(self) -> None:
        self._resource_lease.close()
        self._resource_finalizer.detach()

    def __enter__(self) -> "MultiVolumeBinaryView":
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

    def signature_prepass(self, *, head_bytes: int, tail_bytes: int) -> dict | None:
        return dict(self._native.signature_prepass(int(head_bytes), int(tail_bytes)))

    def probe_zip(self, *, eocd_offset: int, max_cd_entries_to_walk: int = 64) -> dict | None:
        return dict(self._native.probe_zip(int(eocd_offset), int(max_cd_entries_to_walk)))

    def probe_rar(self, *, start_offset: int, max_blocks_to_walk: int = 4096) -> dict | None:
        return dict(self._native.probe_rar(int(start_offset), int(max_blocks_to_walk)))

    def probe_seven_zip(self, *, start_offset: int, max_next_header_check_bytes: int = 1024 * 1024) -> dict | None:
        return dict(self._native.probe_seven_zip(int(start_offset), int(max_next_header_check_bytes)))

    def probe_tar(self, *, start_offset: int = 0, max_entries_to_walk: int = 64) -> dict | None:
        return dict(self._native.probe_tar(int(start_offset), int(max_entries_to_walk)))

    def probe_compression_stream(self, *, format: str) -> dict | None:
        return dict(self._native.probe_compression_stream(str(format)))

    def probe_compressed_tar(self, *, format: str, max_probe_bytes: int = 4 * 1024 * 1024) -> dict | None:
        return dict(self._native.probe_compressed_tar(str(format), int(max_probe_bytes)))


def _normalize_volume_entries(paths) -> list[dict]:
    entries = list(paths or [])
    if entries and all(isinstance(item, dict) for item in entries):
        entries = sorted(entries, key=lambda item: int(item.get("number") or 0))
        return [
            {
                "path": str(item.get("path") or ""),
                "number": int(item.get("number") or index + 1),
                "style": str(item.get("style") or ""),
            }
            for index, item in enumerate(entries)
            if item.get("path")
        ]
    return [
        {"path": str(item), "number": index + 1, "style": ""}
        for index, item in enumerate(entries)
        if str(item)
    ]
