import os
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from sunpack.core.contracts.filesystem import DirectorySnapshot
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.pipeline.extraction.output_inventory import OutputInventory


@dataclass(frozen=True)
class NestedScanWork:
    roots: tuple[str, ...]
    session: DiscoveryScanSession | None


class NestedOutputScanPolicy:
    """Locate extracted output directories that require full archive detection."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self._output_scan_config = self._build_recursive_output_scan_config()

    def should_scan_output_dir(self, target_dir: str) -> bool:
        return bool(self._candidate_parent_roots(target_dir))

    def _candidate_parent_roots(
        self,
        target_dir: str,
        inventory: OutputInventory | None = None,
    ) -> list[str]:
        # Output discovery is inherently recursive and must not inherit the
        # user's initial directory-scan depth. Embedded segment extraction adds
        # a child directory (for example embedded_00_rar), while the next round
        # may intentionally remain current-directory-only.
        if inventory is not None and inventory.stats.exists and inventory.stats.is_dir:
            return list(inventory.parent_directories())

        snapshot = DirectoryScanner(target_dir, config=self._output_scan_config).scan()
        return [os.path.abspath(parent) for parent in snapshot.parent_directories()]

    def prepare_scan(
        self,
        output_dirs: Iterable[str],
        inventories: dict[str, OutputInventory | dict[str, Any]] | None = None,
        logical_roots: Iterable[str] | None = None,
    ) -> NestedScanWork:
        roots = []
        seen = set()
        inventories = inventories or {}
        # A carrier can contain several independently extracted archives.  In
        # that case the carrier output directory is only a physical container;
        # authorization for the next recursive discovery must be evaluated from
        # each confirmed segment directory independently.  Ordinary archives
        # continue to use their output directory as their single logical root.
        scan_dirs = logical_roots if logical_roots is not None else output_dirs
        scan_session = DiscoveryScanSession(
            config=self.config,
            include_raw_snapshots=True,
        )
        has_primed_snapshot = False
        for output_dir in scan_dirs:
            if not output_dir or not os.path.isdir(output_dir):
                continue
            inventory = OutputInventory.from_value(
                inventories.get(os.path.normcase(os.path.abspath(output_dir))),
                expected_root=output_dir,
            )
            snapshot = self._snapshot_from_inventory(inventory, scan_session)
            if snapshot is not None:
                if not snapshot.has_files:
                    continue
                root = os.path.abspath(output_dir)
                key = os.path.normcase(root)
                if key not in seen:
                    seen.add(key)
                    roots.append(root)
                scan_session.prime_snapshot(root, snapshot)
                has_primed_snapshot = True
                continue
            snapshot = DirectoryScanner(
                output_dir,
                config=self._output_scan_config,
                include_raw_snapshot=True,
            ).scan()
            if not snapshot.has_files:
                continue
            root = os.path.abspath(output_dir)
            key = os.path.normcase(root)
            if key not in seen:
                seen.add(key)
                roots.append(root)
            scan_session.prime_snapshot(root, snapshot)
            has_primed_snapshot = True
        session = scan_session if has_primed_snapshot else None
        if session is not None:
            session.set_scan_roots(roots)
        return NestedScanWork(tuple(roots), session)

    @staticmethod
    def project_logical_scan_roots(
        output_dir: str,
        extraction_result: Any,
    ) -> list[tuple[str, OutputInventory | dict[str, Any] | None]]:
        """Project one extraction result into independently authorized roots.

        The projection is deliberately based on the in-process child results
        produced by the extractor, rather than on directory names.  A normal
        archive has one logical root (its existing output directory).  An
        embedded carrier contributes the output directory of each confirmed
        segment, together with that segment's inventory when available.

        This only changes the recursive scan boundary.  It does not alter
        extraction, verification, output naming, or the authorization
        threshold itself.
        """
        embedded_results = list(getattr(extraction_result, "embedded_results", None) or [])
        projected: list[tuple[str, OutputInventory | dict[str, Any] | None]] = []
        for segment, child_result in embedded_results:
            segment = segment if isinstance(segment, dict) else {}
            segment_dir = str(
                getattr(child_result, "out_dir", "")
                or segment.get("out_dir")
                or ""
            ).strip()
            if not segment_dir:
                continue
            child_inventory = getattr(child_result, "output_inventory", None)
            projected.append((segment_dir, child_inventory))

        if projected:
            return projected

        return [(output_dir, getattr(extraction_result, "output_inventory", None))]

    def _snapshot_from_inventory(
        self,
        inventory: OutputInventory | None,
        scan_session: DiscoveryScanSession,
    ) -> DirectorySnapshot | None:
        if (
            inventory is None
            or not inventory.stats.exists
            or not inventory.stats.is_dir
            or not inventory.worker_inventory_complete
        ):
            return None
        scan_session.prime_output_inventory(inventory)
        return DirectoryScanner.snapshot_from_output_inventory(
            os.path.abspath(inventory.root),
            inventory,
            config=self._output_scan_config,
        )

    def _build_recursive_output_scan_config(self) -> dict[str, Any]:
        config = deepcopy(self.config)
        filesystem = config.get("filesystem")
        if not isinstance(filesystem, dict):
            filesystem = {}
            config["filesystem"] = filesystem
        filesystem["directory_scan_mode"] = "recursive"
        return config
