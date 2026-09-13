from typing import Any

from sunpack.analysis import ArchiveAnalyzer, MultiVolumeAnalysisSource, SevenZipProbeOptions
from sunpack.analysis.probes.seven_zip import DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.detection.pipeline.processors.modules.format_structure.multi_volume import detection_analysis_volumes
from sunpack.support.path_keys import path_key


SEVEN_ZIP_SIGNATURE = b"7z\xbc\xaf\x27\x1c"


def _single_input_magic(
    context: FactProcessorContext,
    inputs: list[object],
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
    "seven_zip_structure",
    input_facts={"file.path", "file.magic_bytes"},
    output_facts={"7z.structure"},
    schemas={
        "7z.structure": {
            "type": "dict",
            "description": "7z signature, header CRC/range/NID checks, and bounded payload/header encryption state.",
        },
    },
)
def process_seven_zip_structure(context: FactProcessorContext) -> dict[str, Any]:
    inputs = detection_analysis_volumes(context)
    magic = _single_input_magic(context, inputs, len(SEVEN_ZIP_SIGNATURE))
    if magic is not None and not magic.startswith(SEVEN_ZIP_SIGNATURE):
        return _canonical_not_matched()

    observation = ArchiveAnalyzer(context.config).probe_seven_zip(
        MultiVolumeAnalysisSource(tuple(inputs)),
        SevenZipProbeOptions(
            max_next_header_check_bytes=int(context.fact_config.get(
                "max_next_header_check_bytes",
                DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES,
            )),
        ),
    )
    return observation.to_raw_dict()
