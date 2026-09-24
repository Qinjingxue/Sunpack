from __future__ import annotations

import os

from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.discovery.relations.scheduler import RelationsScheduler
from sunpack.core.support.path_keys import normalized_path, path_key, safe_relative_path


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

    candidates: list[DiscoveryCandidate] = []
    seen_keys: set[str] = set()

    for directory in selected_dirs:
        _add_unique(candidates, seen_keys, session.candidates_for_directory(directory))

    for file_path in selected_files:
        if any(safe_relative_path(file_path, directory) is not None for directory in selected_dirs):
            continue
        parent = _context_root_for_file(file_path)
        parent_candidates = session.candidates_for_directory(parent)
        selected_key = path_key(file_path)
        matched = [
            candidate
            for candidate in parent_candidates
            if selected_key in candidate.path_keys
        ]
        if not matched:
            expected_name = session.logical_name_for_archive(os.path.basename(file_path)).lower()
            matched = [
                candidate
                for candidate in parent_candidates
                if candidate.is_split
                and os.path.basename(candidate.logical_name).lower() == expected_name
            ]
        _add_unique(candidates, seen_keys, matched)

    return candidates


def _candidate_key(candidate: DiscoveryCandidate) -> str:
    if not candidate.is_split:
        return path_key(candidate.entry_path)
    parent = os.path.dirname(normalized_path(candidate.entry_path))
    family = str(
        candidate.relation_metadata.get("split_family")
        or candidate.format_hint
        or "unknown"
    ).lower()
    return path_key(os.path.join(parent, f"{candidate.logical_name.lower()}\x1f{family}"))


def _candidate_rank(candidate: DiscoveryCandidate) -> tuple[int, int, int]:
    relation_strength = 2 if candidate.is_split else 1
    if candidate.relation_anchor.get("needs_password"):
        relation_strength = 1
    volumes = int(candidate.relation_metadata.get("split_member_count") or 0)
    members = len(candidate.archive_input.part_paths())
    return relation_strength, volumes, members


def _add_unique(
    target: list[DiscoveryCandidate],
    seen_keys: set[str],
    values: list[DiscoveryCandidate],
) -> None:
    for candidate in values:
        key = _candidate_key(candidate)
        if key in seen_keys:
            for index, current in enumerate(target):
                if _candidate_key(current) == key and _candidate_rank(candidate) > _candidate_rank(current):
                    target[index] = candidate
                    break
            continue
        seen_keys.add(key)
        target.append(candidate)


def _context_root_for_file(file_path: str) -> str:
    return os.path.dirname(file_path) or os.getcwd()
