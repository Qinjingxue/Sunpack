from __future__ import annotations

from typing import Any

from sunpack_native import confirm_format_identity as _native_confirm_format_identity

from sunpack.core.analysis.request import AnalysisRequest
from sunpack.core.analysis.result import ArchiveAnalysisReport
from sunpack.core.analysis.engine import AnalysisEngine
from sunpack.core.analysis.source import (
    AnalysisSource,
    FileAnalysisSource,
    MultiVolumeAnalysisSource,
    analysis_source,
)


class ArchiveAnalyzer:
    """Public, policy-free facade for the native archive analysis report."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        engine: AnalysisEngine | None = None,
    ):
        self._engine = engine or AnalysisEngine(config)

    def analyze(
        self,
        source: AnalysisSource | str | list[Any] | tuple[Any, ...],
        request: AnalysisRequest | None = None,
    ) -> ArchiveAnalysisReport:
        resolved = analysis_source(source)
        effective_request = request or AnalysisRequest()
        capabilities = effective_request.capabilities
        initial_prepass = effective_request.initial_prepass
        if isinstance(resolved, FileAnalysisSource):
            return self._engine.analyze_path(
                resolved.path,
                report_path=resolved.report_path,
                initial_prepass=initial_prepass,
                capabilities=capabilities,
            )
        if isinstance(resolved, MultiVolumeAnalysisSource):
            return self._engine.analyze_paths(
                resolved.volumes,
                report_path=resolved.report_path or None,
                initial_prepass=initial_prepass,
                capabilities=capabilities,
            )
        raise TypeError(f"unsupported analysis source: {type(resolved).__name__}")

    @staticmethod
    def confirm_format_identity(path: str, archive_format: str) -> bool:
        """Confirm a routed single-file TAR or compression stream in Rust."""
        return bool(_native_confirm_format_identity(str(path), str(archive_format)))
