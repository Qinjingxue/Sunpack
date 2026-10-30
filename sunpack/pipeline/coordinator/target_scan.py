from __future__ import annotations

import os

from sunpack_native import NativeCandidateTable, classify_scan_targets
from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.discovery.relations.scheduler import RelationsScheduler
from sunpack.core.support.path_keys import normalized_path, safe_relative_path


RELATIONS = RelationsScheduler()


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

    paths = [normalized_path(path) for path in target_paths]
    kinds, errors = classify_scan_targets(paths)
    session.add_scan_errors(errors)
    for path, kind in zip(paths, kinds):
        if kind == 2:
            selected_dirs.append(path)
        elif kind == 1:
            selected_files.append(path)

    if session.scope is not None:
        selected_files = [path for path in selected_files if session.scope.contains(path)]
    session.set_scan_roots([*selected_dirs, *(_context_root_for_file(path) for path in selected_files)])
    selected_dirs = list(dict.fromkeys(session.scope_for(directory).root for directory in selected_dirs))
    selected_dirs = [directory for directory in selected_dirs if not any(
        other != directory and session.scope_for(other).max_depth is None
        and safe_relative_path(directory, other) is not None for other in selected_dirs)]

    table = NativeCandidateTable()

    for directory in selected_dirs:
        partial = session.native_table_for_directory(directory)
        table.extend(partial)

    by_parent: dict[str, list[tuple[str, str]]] = {}
    for file_path in selected_files:
        if any(session.scope_for(directory).contains(file_path) for directory in selected_dirs):
            continue
        parent = session.scope_for(_context_root_for_file(file_path)).root
        by_parent.setdefault(parent, []).append((
            file_path,
            session.logical_name_for_archive(os.path.basename(file_path)),
        ))
    for parent, targets in by_parent.items():
        partial = session.native_table_for_directory(parent, targets=targets)
        table.extend(partial)

    table.dedupe()
    return table


def _context_root_for_file(file_path: str) -> str:
    return os.path.dirname(file_path) or os.getcwd()
