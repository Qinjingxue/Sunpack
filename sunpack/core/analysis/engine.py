from typing import Any

from sunpack.core.analysis.config import analysis_config
from sunpack.core.analysis.structure_pipeline.prepass import run_signature_prepass
from sunpack.core.analysis.structure_pipeline.registry import discover_analysis_modules, get_analysis_module_registry
from sunpack.core.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence
from sunpack.core.analysis.request import AnalysisCapability, DEFAULT_ANALYSIS_CAPABILITIES
from sunpack.core.analysis.view import MultiVolumeBinaryView, SharedBinaryView
from sunpack.core.support.module_config import enabled_module_configs


class AnalysisEngine:
    def __init__(self, config: dict[str, Any] | None = None, *, executor_pool=None):
        root_config = config or {}
        self.config = analysis_config(root_config)
        self.executor_pool = executor_pool
        discover_analysis_modules()

    def analyze_path(
        self,
        path: str,
        *,
        report_path: str | None = None,
        initial_prepass: dict | None = None,
        capabilities: frozenset[AnalysisCapability] | None = None,
    ) -> ArchiveAnalysisReport:
        return self.analyze_view(
            self._build_single_view(path),
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
        view = self._build_multi_volume_view(volumes)
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
        prepass_config = self.config.get("prepass") if isinstance(self.config.get("prepass"), dict) else {}
        prepass = dict(initial_prepass or {})
        needs_prepass = bool(requested & {
            AnalysisCapability.SIGNATURE_PREPASS,
            AnalysisCapability.FORMAT_STRUCTURE,
        })
        if not prepass and needs_prepass and prepass_config.get("enabled", True):
            prepass = run_signature_prepass(view, prepass_config)
        modules = self._selected_structure_modules(prepass) if AnalysisCapability.FORMAT_STRUCTURE in requested else []
        evidences = self._run_structure_modules(view, prepass, modules) if modules else []
        selected = self._selected_evidences(evidences)
        stats = view.stats()
        return ArchiveAnalysisReport(
            path=report_path or view.path,
            size=view.size,
            evidences=sorted(evidences, key=lambda item: item.confidence, reverse=True),
            selected=selected,
            prepass=prepass,
            read_bytes=stats.read_bytes,
            cache_hits=stats.cache_hits,
        )

    def _build_single_view(self, path: str) -> SharedBinaryView:
        cache_bytes = int(self.config.get("shared_cache_mb", 64) or 0) * 1024 * 1024
        max_read_mb = self.config.get("max_read_mb_per_archive", 256)
        max_read_bytes = None if max_read_mb is None else int(max_read_mb) * 1024 * 1024
        return SharedBinaryView(
            path,
            cache_bytes=cache_bytes,
            max_read_bytes=max_read_bytes,
            max_concurrent_reads=int(self.config.get("max_concurrent_reads", 1) or 1),
        )

    def _build_multi_volume_view(self, paths) -> MultiVolumeBinaryView:
        cache_bytes = int(self.config.get("shared_cache_mb", 64) or 0) * 1024 * 1024
        max_read_mb = self.config.get("max_read_mb_per_archive", 256)
        max_read_bytes = None if max_read_mb is None else int(max_read_mb) * 1024 * 1024
        return MultiVolumeBinaryView(
            paths,
            cache_bytes=cache_bytes,
            max_read_bytes=max_read_bytes,
            max_concurrent_reads=int(self.config.get("max_concurrent_reads", 1) or 1),
        )

    def _selected_structure_modules(self, prepass: dict):
        enabled_configs = enabled_module_configs(self.config)
        registry = get_analysis_module_registry()
        modules = []
        for name in enabled_configs:
            module = registry.get(name)
            if module is None:
                continue
            modules.append(module)
        return modules

    def _run_structure_modules(self, view: SharedBinaryView, prepass: dict, modules) -> list[ArchiveFormatEvidence]:
        module_configs = enabled_module_configs(self.config)
        if not modules:
            return []
        # File-level concurrency is owned by AsyncWorkBroker.  Spawning a
        # second executor here creates nested pools, oversubscribes the host,
        # and lets one archive consume all analysis slots.  A single archive's
        # modules therefore run deterministically inside its broker job.
        return [
            self._run_module(module, view, prepass, module_configs.get(module.spec.name, {}))
            for module in modules
        ]

    def _run_module(self, module, view: SharedBinaryView, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        try:
            return module.analyze(view, prepass, config)
        except Exception as exc:
            fmt = module.spec.formats[0] if module.spec.formats else module.spec.name
            return ArchiveFormatEvidence(
                format=fmt,
                confidence=0.0,
                status="error",
                warnings=[str(exc)],
            )

    def _selected_evidences(self, evidences: list[ArchiveFormatEvidence]) -> list[ArchiveFormatEvidence]:
        thresholds = self.config.get("thresholds") if isinstance(self.config.get("thresholds"), dict) else {}
        extractable = float(thresholds.get("extractable_confidence", 0.85))
        return [
            evidence
            for evidence in evidences
            if evidence.status == "extractable" and evidence.confidence >= extractable and evidence.segments
        ]
