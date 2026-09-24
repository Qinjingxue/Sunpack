"""Bounded format-identity confirmation for standalone compression streams."""

from sunpack.core.analysis.probes.compression_stream import CompressionStreamProbeOptions


def confirmed_stream(observation: dict, expected_format: str) -> bool:
    return bool(
        observation.get("plausible")
        and observation.get("identity_strong")
        and observation.get("validation_scope") == "format_identity"
        and observation.get("confidence") == "strong"
        and not observation.get("error")
        and observation.get("format") == expected_format
    )


def confirm_stream(path: str, analyzer, expected_format: str) -> bool:
    observation = analyzer.probe_compression_stream(
        path,
        CompressionStreamProbeOptions(format=expected_format, identity_only=True),
    ).to_raw_dict()
    return confirmed_stream(observation, expected_format)
