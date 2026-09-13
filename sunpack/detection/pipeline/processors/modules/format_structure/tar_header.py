from typing import Any

import sunpack_native

from sunpack.analysis import ArchiveAnalyzer, TarProbeOptions
from sunpack.analysis.probes.tar import DEFAULT_DETECTION_ENTRIES_TO_WALK
from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor


DEFINITE_FIRST_HEADER_REJECTS = frozenset({
    "file_too_small",
    "leading_zero_block",
    "invalid_checksum_field",
    "invalid_size_field",
    "checksum_mismatch",
})


def _canonical_not_matched() -> dict[str, Any]:
    return {
        "magic_matched": False,
        "plausible": False,
        "strong_accept": False,
        "detected_ext": "",
        "confidence": "none",
        "error": "bad_signature",
        "evidence": [],
        "damage_flags": [],
    }


def _first_header_definitely_rejects(path: str, size: Any) -> bool:
    if not isinstance(size, int):
        return False
    if size < 512:
        return True
    try:
        observation = dict(sunpack_native.inspect_tar_header_structure(path, 1))
    except Exception:
        return False
    return observation.get("error") in DEFINITE_FIRST_HEADER_REJECTS


def prefill_tar_header_definite_negatives(fact_bags: list[FactBag]) -> None:
    pending: list[tuple[FactBag, str]] = []
    for bag in fact_bags:
        if bag.has("tar.header_structure") or bag.is_missing("tar.header_structure"):
            continue
        path = bag.get("file.path")
        size = bag.get("file.size")
        if not isinstance(path, str) or not path or not isinstance(size, int):
            continue
        if size < 512:
            bag.set("tar.header_structure", _canonical_not_matched())
            continue
        pending.append((bag, path))

    if not pending:
        return

    try:
        rejected_indices = sunpack_native.batch_tar_first_header_reject_indices(
            [path for _, path in pending]
        )
        for index in rejected_indices:
            if isinstance(index, int) and 0 <= index < len(pending):
                pending[index][0].set("tar.header_structure", _canonical_not_matched())
    except Exception:
        return


@register_processor(
    "tar_header_structure",
    input_facts={"file.path"},
    output_facts={"tar.header_structure"},
    schemas={
        "tar.header_structure": {
            "type": "dict",
            "description": "TAR header checksum and ustar marker structure check derived from the candidate file.",
        },
    },
)
def process_tar_header_structure(context: FactProcessorContext) -> dict[str, Any]:
    path = str(context.fact_bag.get("file.path") or "")
    if _first_header_definitely_rejects(path, context.fact_bag.get("file.size")):
        return _canonical_not_matched()

    observation = ArchiveAnalyzer(context.config).probe_tar(
        path,
        TarProbeOptions(max_entries_to_walk=int(context.fact_config.get(
            "max_entries_to_walk",
            DEFAULT_DETECTION_ENTRIES_TO_WALK,
        ))),
    )
    return observation.to_raw_dict()
