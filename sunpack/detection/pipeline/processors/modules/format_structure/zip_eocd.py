from typing import Any

from sunpack.analysis import ArchiveAnalyzer, MultiVolumeAnalysisSource, ZipEocdProbeOptions
from sunpack.analysis.probes.zip import DEFAULT_MAX_CD_ENTRIES_TO_WALK
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.detection.pipeline.processors.modules.format_structure.multi_volume import detection_analysis_volumes


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
    max_entries = max(1, min(256, int(context.fact_config.get("max_cd_entries_to_walk", DEFAULT_MAX_CD_ENTRIES_TO_WALK))))
    return ArchiveAnalyzer(context.config).probe_zip_eocd(
        MultiVolumeAnalysisSource(tuple(inputs)),
        ZipEocdProbeOptions(max_cd_entries_to_walk=max_entries),
    ).to_raw_dict()
