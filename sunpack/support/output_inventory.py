from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from sunpack_native import (
    NativeOutputInventory,
    NativeWorkerManifest,
    output_inventory_from_serialized as _native_inventory_from_serialized,
    rebase_output_inventory_root as _native_rebase_output_inventory_root,
    scan_output_inventory as _native_scan_output_inventory,
)
from sunpack.extraction.internal.sevenzip.worker_diagnostics import native_worker_manifest


@dataclass(frozen=True)
class OutputStats:
    exists: bool
    is_dir: bool
    file_count: int = 0
    dir_count: int = 0
    total_size: int = 0
    transient_file_count: int = 0
    unreadable_count: int = 0


class OutputInventory:
    """Python facade over a Rust-owned file table."""

    __slots__ = ("root", "stats", "_native", "worker_crc_available", "worker_inventory_complete", "identity_paths")

    def __init__(self, native: NativeOutputInventory):
        self._native = native
        self.root = str(native.root)
        self.stats = OutputStats(
            exists=bool(native.exists), is_dir=bool(native.is_dir),
            file_count=int(native.file_count), dir_count=int(native.dir_count),
            total_size=int(native.total_size), transient_file_count=int(native.transient_file_count),
            unreadable_count=int(native.unreadable_count),
        )
        self.worker_crc_available = bool(native.worker_crc_available)
        self.worker_inventory_complete = bool(native.worker_inventory_complete)
        self.identity_paths = bool(native.identity_paths)

    @property
    def files(self) -> tuple[dict[str, Any], ...]:
        return self.materialize_files()

    def materialize_files(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(item) for item in self._native.materialize_files())

    def file_columns(self) -> tuple[list[str], list[int]]:
        paths, sizes = self._native.file_columns()
        return list(paths), [int(item) for item in sizes]

    def file_head_columns(self) -> tuple[list[str], list[int], list[int | None], list[bytes]]:
        paths, sizes, mtimes_ns, magics = self._native.file_head_columns()
        return (
            list(paths),
            [int(item) for item in sizes],
            [int(item) if item is not None else None for item in mtimes_ns],
            [bytes(item) for item in magics],
        )

    def build_directory_snapshots(self, options: dict[str, Any]):
        return self._native.build_directory_snapshots(
            options["patterns"],
            options["prune_dir_globs"],
            options["blocked_extensions"],
            options["blocked_file_names"],
            options["size_ranges"],
            options["mtime_ranges"],
            options["whitelist_rules"],
        )

    def relative_paths(self) -> tuple[str, ...]:
        return tuple(self._native.relative_paths())

    def all_crc_ok(self) -> bool:
        return bool(self._native.all_crc_ok())

    def rebased_root(self, new_root: str) -> "OutputInventory":
        return OutputInventory.from_native(
            _native_rebase_output_inventory_root(
                self._native,
                os.path.abspath(new_root),
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "root": self.root,
            "stats": {
                "exists": self.stats.exists,
                "is_dir": self.stats.is_dir,
                "file_count": self.stats.file_count,
                "dir_count": self.stats.dir_count,
                "total_size": self.stats.total_size,
                "transient_file_count": self.stats.transient_file_count,
                "unreadable_count": self.stats.unreadable_count,
                "relative_paths": list(self.relative_paths()),
            },
            "files": list(self.materialize_files()),
            "worker_crc_available": self.worker_crc_available,
            "worker_inventory_complete": self.worker_inventory_complete,
            "identity_paths": self.identity_paths,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None, *, expected_root: str = "") -> "OutputInventory | None":
        if not isinstance(payload, dict) or int(payload.get("version", 0) or 0) != 1:
            return None
        root = str(payload.get("root") or "")
        if expected_root and _path_key(root) != _path_key(expected_root):
            return None
        raw_stats = payload.get("stats") if isinstance(payload.get("stats"), dict) else {}
        files = [item for item in payload.get("files") or [] if isinstance(item, dict)]
        return cls.from_native(
            _native_inventory_from_serialized(
                root, files,
                bool(raw_stats.get("exists")), bool(raw_stats.get("is_dir")),
                int(raw_stats.get("file_count", 0) or 0), int(raw_stats.get("dir_count", 0) or 0),
                int(raw_stats.get("total_size", 0) or 0), int(raw_stats.get("transient_file_count", 0) or 0),
                int(raw_stats.get("unreadable_count", 0) or 0), bool(payload.get("worker_crc_available")),
                bool(payload.get("worker_inventory_complete")), bool(payload.get("identity_paths")),
            )
        )

    @classmethod
    def from_value(cls, value: Any, *, expected_root: str = "") -> "OutputInventory | None":
        if isinstance(value, cls):
            if expected_root and _path_key(value.root) != _path_key(expected_root):
                return None
            return value
        return cls.from_dict(value, expected_root=expected_root)

    @classmethod
    def from_native(cls, native: NativeOutputInventory) -> "OutputInventory":
        return cls(native)


def collect_output_inventory(
    output_dir: str,
    worker_result: dict[str, Any] | None = None,
) -> OutputInventory:
    root = os.path.abspath(output_dir) if output_dir else ""
    if not output_dir:
        return OutputInventory.from_native(_native_inventory_from_serialized(
            root, [], False, False, 0, 0, 0, 0, 0, False, False, False,
        ))
    worker_inventory = _complete_worker_inventory(worker_result)
    if worker_inventory is not None:
        return OutputInventory.from_native(worker_inventory.to_output_inventory(root))
    return OutputInventory.from_native(_native_scan_output_inventory(root))


def _complete_worker_inventory(worker_result: dict[str, Any] | None) -> NativeWorkerManifest | None:
    result = worker_result if isinstance(worker_result, dict) else {}
    manifest = result.get("verified_manifest") if isinstance(result.get("verified_manifest"), dict) else {}
    inventory = manifest.get("inventory") if isinstance(manifest.get("inventory"), dict) else {}
    native = native_worker_manifest(result)
    if (
        result.get("status") != "ok"
        or not manifest.get("validated")
        or native is None
        or not inventory.get("complete")
        or int(inventory.get("file_count", -1)) != len(native)
        or not native.all_complete()
    ):
        return None
    return native


def _path_key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path)) if path else ""
