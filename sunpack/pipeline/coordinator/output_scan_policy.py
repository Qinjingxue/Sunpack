import os
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from sunpack.core.contracts.filesystem import DirectorySnapshot, FileEntry
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.pipeline.extraction.output_inventory import OutputInventory
from sunpack.core.support.path_keys import normalized_path, path_key


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
        inventory_files = self._inventory_files(inventory)
        snapshot = None
        if inventory_files is None:
            snapshot = DirectoryScanner(target_dir, config=self._output_scan_config).scan()
        roots = []
        seen = set()
        candidates = (
            ((path, size) for path, size, _mtime_ns in snapshot.iter_file_columns())
            if snapshot is not None
            else inventory_files
        )
        for path, _size in candidates:
            parent = os.path.abspath(os.path.dirname(path))
            key = os.path.normcase(parent)
            if key not in seen:
                seen.add(key)
                roots.append(parent)
        return roots

    @staticmethod
    def _inventory_files(inventory: OutputInventory | None) -> Iterable[tuple[str, int]] | None:
        if inventory is None or not inventory.stats.exists or not inventory.stats.is_dir:
            return None
        root = os.path.abspath(inventory.root)
        paths, sizes = inventory.file_columns()
        return (
            (os.path.join(root, path), size)
            for path, size in zip(paths, sizes)
        )

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
        if inventory is None or not inventory.stats.exists or not inventory.stats.is_dir:
            return None
        root = Path(os.path.abspath(inventory.root))
        if inventory.worker_inventory_complete:
            scan_session.prime_file_head_columns(*inventory.file_head_columns())
            snapshot = DirectoryScanner.snapshot_from_output_inventory(
                str(root),
                inventory,
                config=self._output_scan_config,
            )
            if snapshot is not None:
                return snapshot
        inventory_files = self._inventory_files(inventory)
        if inventory_files is None:
            return None
        inventory_rows = [
            (path, size)
            for path, size in inventory_files
            if self._is_within_root(path, root)
        ]
        if not inventory_rows:
            return DirectorySnapshot.from_entries(root_path=root, entries=[])

        accepted_indices = set(DirectoryScanner.inventory_file_indices(
            str(root),
            [path for path, _size in inventory_rows],
            [size for _path, size in inventory_rows],
            config=self._output_scan_config,
        ))
        directory_paths: set[str] = set()
        raw_directory_paths: set[str] = set()
        root_text = str(root)
        root_case = os.path.normcase(root_text)
        for index, (path, _size) in enumerate(inventory_rows):
            parent = os.path.dirname(path)
            while os.path.normcase(parent) != root_case:
                raw_directory_paths.add(parent)
                if index in accepted_indices:
                    directory_paths.add(parent)
                next_parent = os.path.dirname(parent)
                if next_parent == parent:
                    break
                parent = next_parent

        raw_entries = [
            FileEntry(path=Path(path), is_dir=True)
            for path in sorted(raw_directory_paths, key=lambda item: (item.count(os.sep), item.lower()))
        ]
        raw_entries.extend(
            FileEntry(path=Path(os.path.abspath(path)), is_dir=False, size=size)
            for path, size in inventory_rows
        )

        entries = [
            FileEntry(path=Path(path), is_dir=True)
            for path in sorted(directory_paths, key=lambda item: (item.count(os.sep), item.lower()))
        ]
        entries.extend(
            FileEntry(path=Path(os.path.abspath(path)), is_dir=False, size=size)
            for index, (path, size) in enumerate(inventory_rows)
            if index in accepted_indices
        )
        prefiltered = DirectoryScanner.snapshot_from_entries(
            str(root),
            entries,
            config=self._output_scan_config,
            stop_before_filter="mtime_range",
        )
        candidate_paths = [normalized_path(path) for path, _size, _mtime_ns in prefiltered.iter_file_columns()]
        facts_by_key = scan_session.file_head_facts_for_paths(
            candidate_paths,
            magic_size=16,
            paths_normalized=True,
            copy_results=False,
        )
        hydrated_entries: list[FileEntry] = []
        for path, is_dir, size, mtime_ns in prefiltered.iter_columns():
            entry_path = Path(path)
            if is_dir:
                hydrated_entries.append(FileEntry(path=entry_path, is_dir=True))
                continue
            facts = facts_by_key.get(path_key(entry_path), {})
            if not facts.get("exists") or not facts.get("is_file"):
                continue
            hydrated_entries.append(FileEntry(
                path=entry_path,
                is_dir=False,
                size=facts.get("size"),
                mtime_ns=facts.get("mtime_ns"),
            ))
        return DirectoryScanner.snapshot_from_entries(
            str(root),
            hydrated_entries,
            config=self._output_scan_config,
            start_filter="mtime_range",
            raw_entries=raw_entries,
        )

    @staticmethod
    def _is_within_root(path: str, root: Path) -> bool:
        root_key = os.path.normcase(os.path.abspath(str(root))).rstrip("\\/")
        path_key_value = os.path.normcase(os.path.abspath(path)).rstrip("\\/")
        if path_key_value == root_key:
            return True
        return path_key_value.startswith(root_key + os.sep)

    def _build_recursive_output_scan_config(self) -> dict[str, Any]:
        config = deepcopy(self.config)
        filesystem = config.get("filesystem")
        if not isinstance(filesystem, dict):
            filesystem = {}
            config["filesystem"] = filesystem
        filesystem["directory_scan_mode"] = "recursive"
        return config
