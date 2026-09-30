from __future__ import annotations

from sunpack.pipeline.verification.evidence import VerificationEvidence
from sunpack.pipeline.extraction.output_inventory import (
    OutputInventory,
    OutputStats,
    collect_output_inventory,
)


def output_stats_for_evidence(evidence: VerificationEvidence) -> OutputStats:
    return output_inventory_for_evidence(evidence).stats


def output_inventory_for_evidence(evidence: VerificationEvidence) -> OutputInventory:
    cached = evidence._output_inventory_cache
    if cached is not None:
        return cached
    output_dir = evidence.output_dir
    extraction_result = evidence.extraction_result
    inventory = OutputInventory.from_value(
        extraction_result.output_inventory,
        expected_root=output_dir,
    )
    if inventory is None:
        inventory = collect_output_inventory(
            output_dir,
            evidence.worker_result,
        )
    object.__setattr__(evidence, "_output_inventory_cache", inventory)
    return inventory


def should_emit_file_observations(evidence: VerificationEvidence, method: str) -> bool:
    owner = evidence._file_observation_owner
    return not owner or owner == method
