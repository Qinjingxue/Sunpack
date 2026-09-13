from typing import Any

from sunpack.analysis import ArchiveAnalyzer
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor


def inspect_compression_stream_structure(
    path: str,
    identity: tuple[str, int, int] | None = None,
) -> dict[str, Any]:
    """Return the compression structure observation owned by Analysis."""
    del identity
    return ArchiveAnalyzer().probe_compression_stream(path).to_raw_dict()


@register_processor(
    "compression_stream_structure",
    input_facts={"file.path"},
    output_facts={"compression.stream_structure"},
    schemas={
        "compression.stream_structure": {
            "type": "dict",
            "description": "Lightweight gzip, bzip2, xz, or zstd stream structure check derived from the candidate file.",
        },
    },
)
def process_compression_stream_structure(context: FactProcessorContext) -> dict[str, Any]:
    path = context.fact_bag.get("file.path") or ""
    return ArchiveAnalyzer(context.config).probe_compression_stream(path).to_raw_dict()
