from sunpack.core.analysis.structure_pipeline.module import AnalysisModuleSpec
from sunpack.core.analysis.structure_pipeline.registry import register_analysis_module
from sunpack.core.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.core.analysis.probes.compression_stream import CompressionStreamProbeOptions, probe_compression_stream_view

GZIP_MAGIC = b"\x1f\x8b\x08"
BZIP2_MAGIC = b"BZh"
XZ_MAGIC = b"\xfd7zXZ\x00"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


class _CompressionModule:
    name = ""
    fmt = ""
    magic = b""

    @property
    def spec(self):
        return AnalysisModuleSpec(name=self.name, formats=(self.fmt,), signatures=(self.magic,), io_profile="head_tail")

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        embedded = [
            item for item in prepass.get("embedded_candidates", [])
            if item.get("format") == self.fmt
            and item["candidate_kind"] == "logical_archive"
        ]
        if embedded:
            complete = all(
                item.get("end_offset") is not None
                and item["boundary_kind"] == "exact"
                and item["extractable"]
                for item in embedded
            )
            confidence = min(float(max(item.get("confidence") or 0.0 for item in embedded)), 0.99)
            segments = []
            for item in embedded:
                start = int(item.get("offset") or 0)
                end = item.get("end_offset")
                segments.append(ArchiveSegment(
                    start_offset=start,
                    end_offset=int(end) if end is not None else None,
                    confidence=confidence if complete else min(confidence, 0.80),
                    damage_flags=[] if end is not None else ["stream_boundary_inferred"],
                    evidence=[f"{self.fmt}:{item.get('validation') or 'validated_header'}"],
                ))
            return ArchiveFormatEvidence(
                format=self.fmt,
                confidence=confidence if complete else min(confidence, 0.80),
                status="extractable" if complete else "damaged",
                segments=segments,
                details={"source": "embedded_scan", "candidates": embedded,
                         "boundary_confidence": "high" if complete else "low"},
            )
        observation = probe_compression_stream_view(
            view,
            CompressionStreamProbeOptions(format=self.fmt),
        )
        result = observation.to_raw_dict()
        if not result.get("magic_matched"):
            return ArchiveFormatEvidence(format=self.fmt, confidence=0.0, status="not_found", details=result)
        damage_flags = _stream_damage_flags(result)
        structure_complete = bool(result.get("structure_validation_complete"))
        boundary_exact = bool(result.get("boundary_exact"))
        trailing = int(result.get("archive.trailing_data") or 0)
        if result.get("plausible") and structure_complete and boundary_exact and not damage_flags and trailing == 0:
            confidence = 0.97
            return ArchiveFormatEvidence(
                format=self.fmt,
                confidence=confidence,
                status="extractable",
                segments=[ArchiveSegment(start_offset=0, end_offset=result.get("segment_end") or view.size, confidence=confidence, evidence=list(result.get("evidence") or []))],
                details=result,
            )
        if result.get("plausible"):
            if not structure_complete:
                damage_flags = sorted(set(damage_flags + ["structure_validation_incomplete"]))
            confidence = 0.78 if not damage_flags else 0.68
            return ArchiveFormatEvidence(
                format=self.fmt,
                confidence=confidence,
                status="damaged",
                segments=[ArchiveSegment(
                    start_offset=0,
                    end_offset=result.get("segment_end"),
                    confidence=confidence,
                    damage_flags=damage_flags,
                    evidence=list(result.get("evidence") or []),
                )],
                details={**result, "route_evidence_flags": damage_flags},
            )
        damage_flags = damage_flags or ["stream_unverified"]
        return ArchiveFormatEvidence(
            format=self.fmt,
            confidence=0.35,
            status="weak",
            segments=[ArchiveSegment(start_offset=0, end_offset=None, confidence=0.35, damage_flags=damage_flags, evidence=list(result.get("evidence") or []))],
            details={**result, "route_evidence_flags": damage_flags},
        )


def _stream_damage_flags(result: dict) -> list[str]:
    flags = list(result.get("damage_flags") or [])
    error = str(result.get("error") or "")
    if error:
        flags.append(error)
    return sorted(set(flags))


class GzipAnalysisModule(_CompressionModule):
    name = "gzip"
    fmt = "gzip"
    magic = GZIP_MAGIC


class Bzip2AnalysisModule(_CompressionModule):
    name = "bzip2"
    fmt = "bzip2"
    magic = BZIP2_MAGIC


class XzAnalysisModule(_CompressionModule):
    name = "xz"
    fmt = "xz"
    magic = XZ_MAGIC


class ZstdAnalysisModule(_CompressionModule):
    name = "zstd"
    fmt = "zstd"
    magic = ZSTD_MAGIC


class _CompressedTarModule:
    name = ""
    fmt = ""
    stream_fmt = ""

    @property
    def spec(self):
        return AnalysisModuleSpec(name=self.name, formats=(self.fmt,), signatures=(), io_profile="head_heavy")

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        result = view.probe_compressed_tar(
            format=self.stream_fmt,
            max_probe_bytes=int(config.get("max_probe_bytes", 4 * 1024 * 1024) or 4 * 1024 * 1024),
        )
        if not result.get("magic_matched"):
            return ArchiveFormatEvidence(format=self.fmt, confidence=0.0, status="not_found", details=result)
        if result.get("tar_plausible"):
            confidence = 0.93 if result.get("plausible") else 0.75
            return ArchiveFormatEvidence(
                format=self.fmt,
                confidence=confidence,
                status="extractable",
                segments=[ArchiveSegment(start_offset=0, end_offset=view.size, confidence=confidence, evidence=list(result.get("evidence") or []) + ["tar:inner_header"])],
                details={**result, "inner_format": "tar"},
            )
        return ArchiveFormatEvidence(format=self.fmt, confidence=0.0, status="not_found", details=result)


class TarGzAnalysisModule(_CompressedTarModule):
    name = "tar_gz"
    fmt = "tar.gz"
    stream_fmt = "gzip"


class TarBz2AnalysisModule(_CompressedTarModule):
    name = "tar_bz2"
    fmt = "tar.bz2"
    stream_fmt = "bzip2"


class TarXzAnalysisModule(_CompressedTarModule):
    name = "tar_xz"
    fmt = "tar.xz"
    stream_fmt = "xz"


class TarZstAnalysisModule(_CompressedTarModule):
    name = "tar_zst"
    fmt = "tar.zst"
    stream_fmt = "zstd"


for module in (
    GzipAnalysisModule(),
    Bzip2AnalysisModule(),
    XzAnalysisModule(),
    ZstdAnalysisModule(),
    TarGzAnalysisModule(),
    TarBz2AnalysisModule(),
    TarXzAnalysisModule(),
    TarZstAnalysisModule(),
):
    register_analysis_module(module)
