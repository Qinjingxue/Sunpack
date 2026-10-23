from sunpack.core.contracts.discovery_scope import DiscoveryScope
import os
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Iterable

from sunpack.core.support.path_keys import case_key
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
        self._output_scan_config = self.config
        self._scan_options = None
        self._scan_options_lock = Lock()

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

        snapshot = self._scan_output(target_dir)
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
        for output_dir in scan_dirs:
            if not output_dir:
                continue
            inventory = OutputInventory.from_value(
                inventories.get(case_key(os.path.abspath(output_dir))),
                expected_root=output_dir,
            )
            snapshot = self._snapshot_from_inventory(inventory, scan_session)
            if snapshot is None:
                snapshot = self._scan_output(output_dir)
            root = os.path.abspath(output_dir)
            scan_session.prime_snapshot(root, snapshot)
            if not snapshot.has_files:
                continue
            key = case_key(root)
            if key not in seen:
                seen.add(key)
                roots.append(root)
        session = scan_session if roots or scan_session.has_scan_errors else None
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
        ):
            return None
        scan_session.prime_output_inventory(inventory)
        return DirectoryScanner.snapshot_from_output_inventory(
            os.path.abspath(inventory.root),
            inventory,
            scan_options=self._compiled_scan_options(),
        )

    def _compiled_scan_options(self):
        with self._scan_options_lock:
            if self._scan_options is None:
                self._scan_options = DirectoryScanner.compile_scan_options(self._output_scan_config)
            return self._scan_options

    def _scan_output(self, root: str) -> DirectorySnapshot:
        filtered, raw = self._compiled_scan_options().scan_scope(DiscoveryScope(root, recursive=True).native)
        return DirectorySnapshot.from_native(Path(root), filtered, raw)

