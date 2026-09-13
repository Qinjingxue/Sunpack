from typing import Any

from sunpack.analysis import ArchiveAnalyzer, MultiVolumeAnalysisSource, ZipEocdProbeOptions
from sunpack.analysis.probes.zip import DEFAULT_MAX_CD_ENTRIES_TO_WALK
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.detection.pipeline.processors.modules.format_structure.multi_volume import detection_analysis_volumes
from sunpack.support.path_keys import path_key


ZIP_START_SIGNATURES = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"PK\x06\x06",
)


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


def inspect_zip_eocd_structure(
    path: str,
    max_cd_entries_to_walk: int = DEFAULT_MAX_CD_ENTRIES_TO_WALK,
    identity: tuple[str, int, int] | None = None,
) -> dict[str, Any]:
    del identity
    return ArchiveAnalyzer().probe_zip_eocd(
        path,
        ZipEocdProbeOptions(max_cd_entries_to_walk=max_cd_entries_to_walk),
    ).to_raw_dict()


@register_processor(
    "zip_eocd_structure",
    input_facts={"file.path"},
    output_facts={"zip.eocd_structure"},
    schemas={
        "zip.eocd_structure": {
            "type": "dict",
            "description": "ZIP EOCD/central-directory structure and bounded encryption state derived from the candidate file.",
        },
    },
)
def process_zip_eocd_structure(context: FactProcessorContext) -> dict[str, Any]:
    inputs = detection_analysis_volumes(context)
    magic = _single_input_magic(context, inputs, required_length=4)
    if magic is not None and not any(magic.startswith(signature) for signature in ZIP_START_SIGNATURES):
        return _canonical_not_matched()

    max_entries = max(1, min(256, int(context.fact_config.get("max_cd_entries_to_walk", DEFAULT_MAX_CD_ENTRIES_TO_WALK))))
    return ArchiveAnalyzer(context.config).probe_zip_eocd(
        MultiVolumeAnalysisSource(tuple(inputs)),
        ZipEocdProbeOptions(max_cd_entries_to_walk=max_entries),
    ).to_raw_dict()
