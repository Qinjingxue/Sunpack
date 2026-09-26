from __future__ import annotations

from typing import Any

from sunpack.pipeline.extraction.output_inventory import (
    OutputInventory,
    OutputStats,
    collect_output_inventory,
)


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


def should_emit_file_observations(evidence: Any, method: str) -> bool:
    owner = str(getattr(evidence, "_file_observation_owner", "") or "")
    return not owner or owner == method
