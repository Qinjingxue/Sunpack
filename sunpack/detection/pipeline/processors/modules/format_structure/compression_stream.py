from typing import Any

from sunpack.analysis import ArchiveAnalyzer
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor


COMPRESSION_SIGNATURES = (
    b"\x1f\x8b\x08",  # gzip
    b"BZh",  # bzip2
    b"\xfd7zXZ\x00",  # xz
    b"\x28\xb5\x2f\xfd",  # zstd
)
COMPRESSION_SIGNATURE_LENGTH = max(map(len, COMPRESSION_SIGNATURES))


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
    magic = context.fact_bag.get("file.magic_bytes")
    if (
        isinstance(magic, (bytes, bytearray))
        and len(magic) >= COMPRESSION_SIGNATURE_LENGTH
        and not any(bytes(magic).startswith(signature) for signature in COMPRESSION_SIGNATURES)
    ):
        return _canonical_not_matched()

    return ArchiveAnalyzer(context.config).probe_compression_stream(path).to_raw_dict()
