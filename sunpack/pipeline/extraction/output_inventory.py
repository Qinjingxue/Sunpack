from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from sunpack.core.support.path_keys import case_key
from sunpack_native import (
    NativeOutputInventory,
    NativeWorkerManifest,
    output_inventory_from_serialized as _native_inventory_from_serialized,
    scan_output_inventory as _native_scan_output_inventory,
)
from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import native_worker_manifest


@dataclass(frozen=True)
class OutputStats:
    exists: bool
    is_dir: bool
    file_count: int = 0
    dir_count: int = 0
    total_size: int = 0
    unreadable_count: int = 0


class OutputInventory:
    """Python facade over a Rust-owned file table."""

    __slots__ = ("root", "stats", "_native", "worker_inventory_complete", "identity_paths")

    def __init__(self, native: NativeOutputInventory):
        self._native = native
        self.root = str(native.root)
        self.stats = OutputStats(
            exists=bool(native.exists), is_dir=bool(native.is_dir),
            file_count=int(native.file_count), dir_count=int(native.dir_count),
            total_size=int(native.total_size),
            unreadable_count=int(native.unreadable_count),
        )
        self.worker_inventory_complete = bool(native.worker_inventory_complete)
        self.identity_paths = bool(native.identity_paths)

    def file_page(self, *, offset: int = 0, limit: int = 128) -> tuple[dict[str, Any], ...]:
        return tuple(self._native.file_page(
            max(0, int(offset or 0)),
            max(0, int(limit or 0)),
        ))

    def build_directory_snapshots(self, options):
        return self._native.build_directory_snapshots(options)

    @classmethod
    def from_value(cls, value: OutputInventory | None, *, expected_root: str = "") -> OutputInventory | None:
        if value is not None and expected_root and _path_key(value.root) != _path_key(expected_root):
            return None
        return value

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
            root, [], False, False, 0, 0, 0, 0, False, False,
        ))
    worker_inventory = _complete_worker_inventory(worker_result)
    if worker_inventory is not None:
        return OutputInventory.from_native(worker_inventory.to_output_inventory(root))
    return OutputInventory.from_native(_native_scan_output_inventory(root))


def _complete_worker_inventory(worker_result: dict[str, Any] | None) -> NativeWorkerManifest | None:
    result = worker_result or {}
    manifest = result.get("verified_manifest", {})
    inventory = manifest.get("inventory", {})
    native = native_worker_manifest(result)
    if (
        result.get("status") != "ok"
        or not manifest.get("validated")
        or native is None
        or not inventory.get("complete")
        or int(inventory.get("file_count", -1)) != len(native)
        or not native.complete
    ):
        return None
    return native


def _path_key(path: str) -> str:
    return case_key(os.path.abspath(path)) if path else ""
