from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any

from sunpack.pipeline.extraction.output_inventory import (
    OutputInventory,
    OutputStats,
    collect_output_inventory,
)
from sunpack.core.support.path_names import clean_relative_archive_path, normalize_match_name, normalize_match_path


@dataclass(frozen=True)
class OutputFileIndex:
    files: tuple[dict[str, Any], ...]
    by_path: dict[str, dict[str, Any]]
    normalized_paths: frozenset[str]
    normalized_basenames: frozenset[str]


def output_stats_for_evidence(evidence: Any) -> OutputStats:
    return output_inventory_for_evidence(evidence).stats


def output_inventory_for_evidence(evidence: Any) -> OutputInventory:
    cached = getattr(evidence, "_output_inventory_cache", None)
    if isinstance(cached, OutputInventory):
        return cached
    output_dir = getattr(evidence, "output_dir", "")
    extraction_result = getattr(evidence, "extraction_result", None)
    inventory = OutputInventory.from_value(
        getattr(extraction_result, "output_inventory", None),
        expected_root=output_dir,
    )
    if inventory is None:
        inventory = collect_output_inventory(
            output_dir,
            getattr(evidence, "worker_result", None),
        )
    try:
        object.__setattr__(evidence, "_output_inventory_cache", inventory)
    except Exception:
        pass
    return inventory


def output_files_for_evidence(evidence: Any) -> list[dict[str, Any]]:
    return list(output_inventory_for_evidence(evidence).files)


def output_file_index_for_evidence(evidence: Any) -> OutputFileIndex:
    cached = getattr(evidence, "_output_file_index_cache", None)
    if isinstance(cached, OutputFileIndex):
        return cached
    files = output_inventory_for_evidence(evidence).files
    by_path: dict[str, dict[str, Any]] = {}
    normalized_paths: set[str] = set()
    normalized_basenames: set[str] = set()
    indexed_files: list[dict[str, Any]] = []
    for raw in files:
        path = clean_relative_archive_path(raw.get("output_path") or raw.get("path"))
        if not path or ".sunpack/" in path:
            continue
        key = normalize_match_path(path)
        by_path[key] = raw
        normalized_paths.add(key)
        normalized_basenames.add(normalize_match_name(os.path.basename(key)))
        indexed_files.append(raw)
    index = OutputFileIndex(
        files=tuple(indexed_files),
        by_path=by_path,
        normalized_paths=frozenset(normalized_paths),
        normalized_basenames=frozenset(normalized_basenames),
    )
    try:
        object.__setattr__(evidence, "_output_file_index_cache", index)
    except Exception:
        pass
    return index


def should_emit_file_observations(evidence: Any, method: str) -> bool:
    owner = str(getattr(evidence, "_file_observation_owner", "") or "")
    return not owner or owner == method
