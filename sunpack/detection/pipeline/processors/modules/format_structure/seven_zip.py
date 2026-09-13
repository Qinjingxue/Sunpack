from typing import Any

from sunpack.analysis import ArchiveAnalyzer, MultiVolumeAnalysisSource, SevenZipProbeOptions
from sunpack.analysis.probes.seven_zip import DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.detection.pipeline.processors.modules.format_structure.multi_volume import detection_analysis_volumes


@register_processor(
    "seven_zip_structure",
    input_facts={"file.path"},
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
