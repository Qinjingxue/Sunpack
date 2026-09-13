from __future__ import annotations

from typing import Any

from sunpack.analysis.request import AnalysisRequest
from sunpack.analysis.observation import FormatObservation
from sunpack.analysis.probes.compression_stream import (
    CompressionStreamProbeOptions,
    probe_compression_stream_path,
    probe_compression_stream_view,
)
from sunpack.analysis.probes.rar import RarProbeOptions, probe_rar_view
from sunpack.analysis.probes.seven_zip import SevenZipProbeOptions, probe_seven_zip_view
from sunpack.analysis.probes.tar import TarProbeOptions, probe_tar_view
from sunpack.analysis.probes.zip import (
    ZipDeepProbeOptions,
    ZipEocdProbeOptions,
    probe_zip_directory_consistency_path,
    probe_zip_eocd_view,
    probe_zip_local_header_view,
    probe_zip_structure_graph_path,
)
from sunpack.analysis.result import ArchiveAnalysisReport
from sunpack.analysis.engine import AnalysisEngine
from sunpack.analysis.source import (
    AnalysisSource,
    FileAnalysisSource,
    MultiVolumeAnalysisSource,
    analysis_source,
)


class ArchiveAnalyzer:
    """Public, policy-free facade for archive analysis capabilities."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        executor_pool=None,
        engine: AnalysisEngine | None = None,
    ):
        self._engine = engine or AnalysisEngine(config, executor_pool=executor_pool)

    def analyze(
        self,
        source: AnalysisSource | str | list[Any] | tuple[Any, ...],
        request: AnalysisRequest | None = None,
    ) -> ArchiveAnalysisReport:
        resolved = analysis_source(source)
        effective_request = request or AnalysisRequest()
        capabilities = effective_request.capabilities
        initial_prepass = effective_request.initial_prepass
        embedded_scan_allowed = bool(effective_request.embedded_scan_allowed)
        if isinstance(resolved, FileAnalysisSource):
            return self._engine.analyze_path(
                resolved.path,
                report_path=resolved.report_path,
                initial_prepass=initial_prepass,
                capabilities=capabilities,
                embedded_scan_allowed=embedded_scan_allowed,
            )
        if isinstance(resolved, MultiVolumeAnalysisSource):
            return self._engine.analyze_paths(
                resolved.volumes,
                report_path=resolved.report_path or None,
                initial_prepass=initial_prepass,
                capabilities=capabilities,
                embedded_scan_allowed=embedded_scan_allowed,
            )
        raise TypeError(f"unsupported analysis source: {type(resolved).__name__}")

    def probe_seven_zip(
        self,
        source: AnalysisSource | str | list[Any] | tuple[Any, ...],
        options: SevenZipProbeOptions | None = None,
    ) -> FormatObservation:
        return probe_seven_zip_view(self._view_for_source(analysis_source(source)), options)

    def probe_rar(
        self,
        source: AnalysisSource | str | list[Any] | tuple[Any, ...],
        options: RarProbeOptions | None = None,
    ) -> FormatObservation:
        return probe_rar_view(self._view_for_source(analysis_source(source)), options)

    def probe_tar(
        self,
        source: AnalysisSource | str | list[Any] | tuple[Any, ...],
        options: TarProbeOptions | None = None,
    ) -> FormatObservation:
        return probe_tar_view(self._view_for_source(analysis_source(source)), options)

    def probe_compression_stream(
        self,
        source: AnalysisSource | str | list[Any] | tuple[Any, ...],
        options: CompressionStreamProbeOptions | None = None,
    ) -> FormatObservation:
        resolved = analysis_source(source)
        effective_options = options or CompressionStreamProbeOptions()
        if isinstance(resolved, FileAnalysisSource):
            return probe_compression_stream_path(resolved.path, effective_options)
        return probe_compression_stream_view(self._view_for_source(resolved), effective_options)

    def probe_zip_local_header(
        self,
        source: AnalysisSource | str | list[Any] | tuple[Any, ...],
        *,
        offset: int = 0,
    ) -> FormatObservation:
        return probe_zip_local_header_view(self._view_for_source(analysis_source(source)), offset)

    def probe_zip_eocd(
        self,
        source: AnalysisSource | str | list[Any] | tuple[Any, ...],
        options: ZipEocdProbeOptions | None = None,
    ) -> FormatObservation:
        return probe_zip_eocd_view(self._view_for_source(analysis_source(source)), options)

    def probe_zip_directory_consistency(
        self,
        source: FileAnalysisSource | str,
        options: ZipDeepProbeOptions | None = None,
    ) -> FormatObservation:
        resolved = analysis_source(source)
        if not isinstance(resolved, FileAnalysisSource):
            raise TypeError("ZIP directory consistency currently requires a file source")
        return probe_zip_directory_consistency_path(resolved.path, options)

    def probe_zip_structure_graph(
        self,
        source: FileAnalysisSource | str,
        options: ZipDeepProbeOptions | None = None,
    ) -> FormatObservation:
        resolved = analysis_source(source)
        if not isinstance(resolved, FileAnalysisSource):
            raise TypeError("ZIP structure graph currently requires a file source")
        return probe_zip_structure_graph_path(resolved.path, options)

    def _view_for_source(self, source: AnalysisSource):
        if isinstance(source, FileAnalysisSource):
            return self._engine._build_single_view(source.path)
        if isinstance(source, MultiVolumeAnalysisSource):
            return self._engine._build_multi_volume_view(source.volumes)
        raise TypeError(f"unsupported analysis source: {type(source).__name__}")
