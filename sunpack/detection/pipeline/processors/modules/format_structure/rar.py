from typing import Any

from sunpack.analysis import ArchiveAnalyzer, MultiVolumeAnalysisSource, RarProbeOptions
from sunpack.analysis.probes.rar import DEFAULT_DETECTION_BLOCKS_TO_WALK
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.detection.pipeline.processors.modules.format_structure.multi_volume import detection_analysis_volumes
from sunpack.support.path_keys import path_key


RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"
RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"


def _single_input_magic(
    context: FactProcessorContext,
    inputs: list[Any],
    required_length: int,
) -> bytes | None:
    if len(inputs) != 1:
        return None
    input_item = inputs[0]
    input_path = input_item.get("path") if isinstance(input_item, dict) else input_item
    file_path = context.fact_bag.get("file.path") or ""
    if not input_path or not file_path or path_key(input_path) != path_key(file_path):
        return None
    magic = context.fact_bag.get("file.magic_bytes")
    if not isinstance(magic, (bytes, bytearray)) or len(magic) < required_length:
        return None
    return bytes(magic)


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


@register_processor(
    "rar_structure",
    input_facts={"file.path", "file.magic_bytes"},
    output_facts={"rar.structure"},
    schemas={
        "rar.structure": {
            "type": "dict",
            "description": "RAR4/RAR5 signature, main-header CRC, and optional second block/header walk checks.",
        },
    },
)
def process_rar_structure(context: FactProcessorContext) -> dict[str, Any]:
    inputs = detection_analysis_volumes(context)
    magic = _single_input_magic(context, inputs, len(RAR5_SIGNATURE))
    if magic is not None and not (
        magic.startswith(RAR4_SIGNATURE) or magic.startswith(RAR5_SIGNATURE)
    ):
        return _canonical_not_matched()

    observation = ArchiveAnalyzer(context.config).probe_rar(
        MultiVolumeAnalysisSource(tuple(inputs)),
        RarProbeOptions(
            max_blocks_to_walk=DEFAULT_DETECTION_BLOCKS_TO_WALK,
            accept_validated_prefix=True,
        ),
    )
    return observation.to_raw_dict()
