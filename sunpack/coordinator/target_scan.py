import os
from typing import List

from sunpack.contracts.discovery import DiscoveryCandidate
from sunpack.coordinator.scan_session import DiscoveryScanSession
from sunpack.relations.scheduler import RelationsScheduler
from sunpack.support.path_keys import normalized_path, path_key, safe_relative_path


RELATIONS = RelationsScheduler()


def _candidate_key(candidate: DiscoveryCandidate) -> str:
    if not candidate.is_split:
        return path_key(candidate.entry_path)
    parent = os.path.dirname(normalized_path(candidate.entry_path)) if candidate.entry_path else ""
    logical_name = candidate.logical_name or os.path.basename(candidate.entry_path)
    family = str(candidate.relation_family or candidate.format_hint or "unknown").lower()
    return path_key(os.path.join(parent, f"{logical_name.lower()}\x1f{family}"))


def _add_unique(
    target: List[DiscoveryCandidate],
    seen_keys: set[str],
    candidates: List[DiscoveryCandidate],
) -> None:
    for candidate in candidates:
        key = _candidate_key(candidate)
        if key in seen_keys:
            for index, current in enumerate(target):
                if _candidate_key(current) == key and _candidate_rank(candidate) > _candidate_rank(current):
                    target[index] = candidate
                    break
            continue
        seen_keys.add(key)
        target.append(candidate)


def _candidate_rank(candidate: DiscoveryCandidate) -> tuple[int, int, int]:
    anchor = candidate.relation_anchor
    relation_strength = 2 if candidate.is_split else 1
    if anchor.get("needs_password"):
        relation_strength = 1
    volumes = len(candidate.archive_input.parts) if candidate.archive_input is not None else 0
    members = len(candidate.member_paths)
    return relation_strength, volumes, members


def build_discovery_candidates_for_target(
    target_path: str,
    session: DiscoveryScanSession | None = None,
) -> List[DiscoveryCandidate]:
    return build_discovery_candidates_for_targets([target_path], session=session)


def build_discovery_candidates_for_targets(
    target_paths: List[str],
    session: DiscoveryScanSession | None = None,
    config: dict | None = None,
) -> List[DiscoveryCandidate]:
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
            scan_roots.append(_context_root_for_file(file_path, config or {}))
    if hasattr(session, "set_scan_roots"):
        session.set_scan_roots(scan_roots)

    candidates: List[DiscoveryCandidate] = []
    seen_keys: set[str] = set()

    for directory in selected_dirs:
        _add_unique(candidates, seen_keys, session.candidates_for_directory(directory))

    for file_path in selected_files:
        if any(safe_relative_path(file_path, directory) is not None for directory in selected_dirs):
            continue

        parent = _context_root_for_file(file_path, config or {})
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


def _context_root_for_file(file_path: str, config: dict) -> str:
    current = os.path.dirname(file_path) or os.getcwd()
    depth = _scene_context_parent_depth(config)
    while depth > 0:
        parent = os.path.dirname(current)
        if not parent or parent == current:
            break
        current = parent
        depth -= 1
    return current


def _scene_context_parent_depth(config: dict) -> int:
    return 0
