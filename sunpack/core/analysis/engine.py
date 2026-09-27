from typing import Any

from sunpack_native import NativeAnalysisConfig

from sunpack.core.analysis.config import analysis_config
from sunpack.core.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence, ArchiveSegment
from sunpack.core.analysis.request import AnalysisCapability, DEFAULT_ANALYSIS_CAPABILITIES
from sunpack.core.analysis.view import MultiVolumeBinaryView, SharedBinaryView


class AnalysisEngine:
    """Run the native analysis report and project it into Python contracts.

    Format probing, scoring, candidate merging, selection, and the extraction
    segment plan are decided once in Rust. This class only owns view lifecycle.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = analysis_config(config or {})
        self._native_config = NativeAnalysisConfig(self.config)

    def analyze_path(
        self,
        path: str,
        *,
        report_path: str | None = None,
        initial_prepass: dict | None = None,
        capabilities: frozenset[AnalysisCapability] | None = None,
    ) -> ArchiveAnalysisReport:
        with self._build_single_view(path) as view:
            return self.analyze_view(
                view,
                report_path=report_path or path,
                initial_prepass=initial_prepass,
                capabilities=capabilities,
            )

    def analyze_paths(
        self,
        paths,
        *,
        report_path: str | None = None,
        initial_prepass: dict | None = None,
        capabilities: frozenset[AnalysisCapability] | None = None,
    ) -> ArchiveAnalysisReport:
        volumes = list(paths or [])
        if len(volumes) == 1 and not isinstance(volumes[0], dict):
            return self.analyze_path(
                str(volumes[0]),
                report_path=report_path,
                initial_prepass=initial_prepass,
                capabilities=capabilities,
            )
        with self._build_multi_volume_view(volumes) as view:
            return self.analyze_view(
                view,
                report_path=report_path or str(view.path),
                initial_prepass=initial_prepass,
                capabilities=capabilities,
            )

    def analyze_view(
        self,
        view: SharedBinaryView | MultiVolumeBinaryView,
        *,
        report_path: str | None = None,
        initial_prepass: dict | None = None,
        capabilities: frozenset[AnalysisCapability] | None = None,
    ) -> ArchiveAnalysisReport:
        requested = DEFAULT_ANALYSIS_CAPABILITIES if capabilities is None else capabilities
        native = view.analyze(
            self._native_config,
            initial_prepass=initial_prepass,
            signature_prepass=AnalysisCapability.SIGNATURE_PREPASS in requested,
            format_structure=AnalysisCapability.FORMAT_STRUCTURE in requested,
        )
        return _report_from_native(report_path or view.path, native)

    def _build_single_view(self, path: str) -> SharedBinaryView:
        cache_bytes, max_read_bytes, max_concurrent_reads = self._view_limits()
        return SharedBinaryView(
            path,
            cache_bytes=cache_bytes,
            max_read_bytes=max_read_bytes,
            max_concurrent_reads=max_concurrent_reads,
        )

    def _build_multi_volume_view(self, paths) -> MultiVolumeBinaryView:
        cache_bytes, max_read_bytes, max_concurrent_reads = self._view_limits()
        return MultiVolumeBinaryView(
            paths,
            cache_bytes=cache_bytes,
            max_read_bytes=max_read_bytes,
            max_concurrent_reads=max_concurrent_reads,
        )

    def _view_limits(self) -> tuple[int, int | None, int]:
        cache_bytes = int(self.config.get("shared_cache_mb", 64) or 0) * 1024 * 1024
        max_read_mb = self.config.get("max_read_mb_per_archive", 256)
        max_read_bytes = None if max_read_mb is None else int(max_read_mb) * 1024 * 1024
        return cache_bytes, max_read_bytes, int(self.config.get("max_concurrent_reads", 1) or 1)


def _report_from_native(path: str, native: dict) -> ArchiveAnalysisReport:
    evidences = [
        ArchiveFormatEvidence(
            format=fmt,
            confidence=confidence,
            status=status,
            segments=[
                ArchiveSegment(
                    start_offset=start,
                    end_offset=end,
                    confidence=segment_confidence,
                    damage_flags=damage_flags,
                    evidence=segment_evidence,
                )
                for start, end, segment_confidence, damage_flags, segment_evidence in segments
            ],
            warnings=warnings,
            details=details,
        )
        for fmt, confidence, status, segments, warnings, details in native["evidences"]
    ]
    password = native["password_segment"]
    best = native["best_selected"]
    return ArchiveAnalysisReport(
        path=path,
        size=native["size"],
        evidences=evidences,
        selected=[evidences[index] for index in native["selected"]],
        prepass=native["prepass"],
        read_bytes=native["read_bytes"],
        cache_hits=native["cache_hits"],
        best_selected=evidences[best] if best is not None else None,
        extractable_segments=tuple(
            (evidences[evidence], evidences[evidence].segments[segment])
            for evidence, segment in native["extractable_segments"]
        ),
        password_segment=(
            (evidences[password[0]], evidences[password[0]].segments[password[1]])
            if password is not None
            else None
        ),
        missing_volume_evidence=native["missing_volume_evidence"],
    )
