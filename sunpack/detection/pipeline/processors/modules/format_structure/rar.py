from typing import Any

from sunpack.analysis import ArchiveAnalyzer, MultiVolumeAnalysisSource, RarProbeOptions
from sunpack.analysis.probes.rar import DEFAULT_DETECTION_BLOCKS_TO_WALK
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.detection.pipeline.processors.modules.format_structure.multi_volume import detection_analysis_volumes


@register_processor(
    "rar_structure",
    input_facts={"file.path"},
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
    observation = ArchiveAnalyzer(context.config).probe_rar(
        MultiVolumeAnalysisSource(tuple(inputs)),
        RarProbeOptions(
            max_blocks_to_walk=DEFAULT_DETECTION_BLOCKS_TO_WALK,
            accept_validated_prefix=True,
        ),
    )
    return observation.to_raw_dict()
