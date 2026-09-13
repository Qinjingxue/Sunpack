from typing import Any

from sunpack.analysis import ArchiveAnalyzer, TarProbeOptions
from sunpack.analysis.probes.tar import DEFAULT_DETECTION_ENTRIES_TO_WALK
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor


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
    observation = ArchiveAnalyzer(context.config).probe_tar(
        path,
        TarProbeOptions(max_entries_to_walk=int(context.fact_config.get(
            "max_entries_to_walk",
            DEFAULT_DETECTION_ENTRIES_TO_WALK,
        ))),
    )
    return observation.to_raw_dict()
