from __future__ import annotations

import os

from sunpack_native import NativeCandidateTable
from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.discovery.relations.scheduler import RelationsScheduler
from sunpack.core.support.path_keys import normalized_path, safe_relative_path


RELATIONS = RelationsScheduler()


def build_candidates_for_target(
    target_path: str,
    session: DiscoveryScanSession | None = None,
) -> list[DiscoveryCandidate]:
    return build_candidates_for_targets([target_path], session=session)


def build_candidates_for_targets(
    target_paths: list[str],
    session: DiscoveryScanSession | None = None,
    config: dict | None = None,
) -> list[DiscoveryCandidate]:
    session = session or DiscoveryScanSession(RELATIONS, config=config)
    table = build_native_table_for_targets(target_paths, session=session, config=config)
    return [session.project_native_candidate(table, index) for index in range(len(table))]


def build_native_table_for_targets(
    target_paths: list[str],
    session: DiscoveryScanSession | None = None,
    config: dict | None = None,
) -> NativeCandidateTable:
    session = session or DiscoveryScanSession(RELATIONS, config=config)
    selected_dirs: list[str] = []
    selected_files: list[str] = []

    for raw_path in target_paths:
        path = normalized_path(raw_path)
        if os.path.isdir(path):
            selected_dirs.append(path)
        elif os.path.isfile(path):
            selected_files.append(path)

    scan_roots = list(selected_dirs)
    for file_path in selected_files:
        if not any(safe_relative_path(file_path, directory) is not None for directory in selected_dirs):
            scan_roots.append(_context_root_for_file(file_path))
    session.set_scan_roots(scan_roots)

    table = NativeCandidateTable()

    for directory in selected_dirs:
        partial = session.native_table_for_directory(directory)
        table.extend(partial)

    by_parent: dict[str, list[tuple[str, str]]] = {}
    for file_path in selected_files:
        if any(safe_relative_path(file_path, directory) is not None for directory in selected_dirs):
            continue
        parent = _context_root_for_file(file_path)
        by_parent.setdefault(parent, []).append((
            file_path,
            session.logical_name_for_archive(os.path.basename(file_path)),
        ))
    for parent, targets in by_parent.items():
        partial = session.native_table_for_directory(parent)
        partial.retain_file_targets(targets)
        table.extend(partial)

    table.dedupe()
    return table


def _context_root_for_file(file_path: str) -> str:
    return os.path.dirname(file_path) or os.getcwd()
