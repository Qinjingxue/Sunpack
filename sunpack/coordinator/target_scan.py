import os
from typing import List

from sunpack.contracts.detection import FactBag
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.relations.scheduler import RelationsScheduler
from sunpack.support.path_keys import normalized_path, path_key, safe_relative_path


RELATIONS = RelationsScheduler()


def _bag_paths(bag: FactBag) -> list[str]:
    paths = []
    for key in (
        "file.path",
        "candidate.entry_path",
        "candidate.carrier_path",
        "file.split_members",
        "candidate.member_paths",
        "candidate.companion_paths",
        "candidate.cleanup_paths",
    ):
        value = bag.get(key)
        if isinstance(value, list):
            paths.extend(value)
        elif value:
            paths.append(value)
    return [path_key(path) for path in paths if path]

def _bag_key(bag: FactBag) -> str:
    path = bag.get("file.path", "")
    if not bag.get("relation.is_split_related"):
        return path_key(path)
    parent = os.path.dirname(normalized_path(path)) if path else ""
    logical_name = bag.get("file.logical_name") or os.path.basename(path)
    family = str(
        bag.get("relation.split_family")
        or bag.get("relation.format_hint")
        or "unknown"
    ).lower()
    return path_key(os.path.join(parent, f"{logical_name.lower()}\x1f{family}"))


def _add_unique(target: List[FactBag], seen_keys: set[str], bags: List[FactBag]):
    for bag in bags:
        key = _bag_key(bag)
        if key in seen_keys:
            for index, current in enumerate(target):
                if _bag_key(current) == key and _bag_rank(bag) > _bag_rank(current):
                    target[index] = bag
                    break
            continue
        seen_keys.add(key)
        target.append(bag)


def _bag_rank(bag: FactBag) -> tuple[int, int, int]:
    """Prefer the best-supported representation of one logical candidate."""
    relation_strength = 2 if bag.get("relation.is_split_related") else 1
    anchor = bag.get("relation.volume_anchor")
    if isinstance(anchor, dict) and anchor.get("needs_password"):
        relation_strength = 1
    volumes = len(bag.get("relation.split_volumes") or [])
    members = len(bag.get("candidate.member_paths") or [])
    return relation_strength, volumes, members


def build_fact_bags_for_target(target_path: str, session: DetectionScanSession | None = None) -> List[FactBag]:
    """Scan a selected file's parent so split-volume siblings remain visible."""
    return build_fact_bags_for_targets([target_path], session=session)


def build_fact_bags_for_targets(
    target_paths: List[str],
    session: DetectionScanSession | None = None,
    config: dict | None = None,
) -> List[FactBag]:
    session = session or DetectionScanSession(RELATIONS, config=config)
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

    fact_bags: List[FactBag] = []
    seen_keys: set[str] = set()

    for directory in selected_dirs:
        _add_unique(fact_bags, seen_keys, session.fact_bags_for_directory(directory))

    for file_path in selected_files:
        if any(safe_relative_path(file_path, directory) is not None for directory in selected_dirs):
            continue

        parent = _context_root_for_file(file_path, config or {})
        parent_bags = session.fact_bags_for_directory(parent)

        selected_key = path_key(file_path)
        matched = [
            bag for bag in parent_bags
            if selected_key in _bag_paths(bag)
        ]
        if _is_unverified_external_sfx_launcher(matched, file_path):
            expected_name = session.logical_name_for_archive(os.path.basename(file_path)).lower()
            split_matches = [
                bag for bag in parent_bags
                if bag.get("relation.is_split_related")
                and _sfx_logical_names_match(
                    os.path.basename(bag.get("file.logical_name", "")).lower(),
                    expected_name,
                )
            ]
            if split_matches:
                # This is a selection alias only. The launcher remains out of
                # the archive input and cleanup paths; the split group carries
                # the structurally proven data volumes.
                matched = [_selection_alias_for_external_sfx(bag) for bag in split_matches]
        if not matched:
            expected_name = session.logical_name_for_archive(os.path.basename(file_path)).lower()
            matched = [
                bag for bag in parent_bags
                if bag.get("relation.is_split_related")
                and os.path.basename(bag.get("file.logical_name", "")).lower() == expected_name
            ]
        _add_unique(fact_bags, seen_keys, matched)

    return fact_bags


def _is_unverified_external_sfx_launcher(bags: list[FactBag], file_path: str) -> bool:
    if os.path.splitext(file_path)[1].casefold() != ".exe" or len(bags) != 1:
        return False
    anchor = bags[0].get("relation.volume_anchor")
    if not isinstance(anchor, dict):
        return False
    evidence = anchor.get("evidence")
    return (
        not anchor.get("format")
        and bool(anchor.get("sfx"))
        and isinstance(evidence, list)
        and "sfx:pe_header" in evidence
    )


def _selection_alias_for_external_sfx(bag: FactBag) -> FactBag:
    alias = FactBag()
    alias.update(bag.to_dict())
    alias.set("file.container_type", "pe")
    return alias


def _sfx_logical_names_match(candidate_name: str, launcher_name: str) -> bool:
    if not candidate_name or not launcher_name:
        return False
    return (
        candidate_name == launcher_name
        or candidate_name.startswith(f"{launcher_name}.")
        or candidate_name.endswith(f".{launcher_name}")
        or f".{launcher_name}." in candidate_name
    )


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

