from typing import Any

from sunpack.analysis.config import analysis_config, enabled_fuzzy_module_configs
from sunpack.analysis.fuzzy_pipeline.registry import discover_fuzzy_analysis_modules, get_fuzzy_analysis_module_registry
from sunpack.analysis.structure_pipeline.prepass import run_signature_prepass
from sunpack.analysis.structure_pipeline.registry import discover_analysis_modules, get_analysis_module_registry
from sunpack.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence
from sunpack.analysis.request import AnalysisCapability, DEFAULT_ANALYSIS_CAPABILITIES
from sunpack.analysis.view import MultiVolumeBinaryView, SharedBinaryView
from sunpack.support.module_config import enabled_module_configs


class AnalysisEngine:
    def __init__(self, config: dict[str, Any] | None = None, *, executor_pool=None):
        root_config = config or {}
        self.config = analysis_config(root_config)
        self.executor_pool = executor_pool
        discover_fuzzy_analysis_modules()
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
        fuzzy_requested = AnalysisCapability.FUZZY_PROFILE in requested
        # Structure modules already expose the information needed to decide
        # whether fuzzy profiling can add anything: selected status, segment
        # boundaries and damage flags.  Run those modules first and only pay
        # for byte-distribution profiling when that shared evidence is not a
        # complete, clean, whole-input archive proof.
        fuzzy = {}
        structure_context = dict(prepass)
        modules = self._selected_structure_modules(structure_context) if AnalysisCapability.FORMAT_STRUCTURE in requested else []
        evidences = self._run_structure_modules(view, structure_context, modules) if modules else []
        selected = self._selected_evidences(evidences)
        if fuzzy_requested and self._structure_requires_fuzzy(selected, int(view.size)):
            fuzzy = self._run_fuzzy_pipeline(view, prepass)
            if fuzzy and modules and self._fuzzy_affects_structure(fuzzy) and any(item.segments for item in evidences):
                structure_context = {**prepass, "fuzzy": fuzzy}
                evidences = self._run_structure_modules(view, structure_context, modules)
                selected = self._selected_evidences(evidences)
        stats = view.stats()
        return ArchiveAnalysisReport(
            path=report_path or view.path,
            size=view.size,
            evidences=sorted(evidences, key=lambda item: item.confidence, reverse=True),
            selected=selected,
            prepass=prepass,
            fuzzy=fuzzy,
            read_bytes=stats.read_bytes,
            cache_hits=stats.cache_hits,
        )

    @staticmethod
    def _structure_requires_fuzzy(selected: list[ArchiveFormatEvidence], file_size: int) -> bool:
        """Use format-module evidence; never perform an independent read/probe here."""
        if len(selected) != 1:
            return True
        evidence = selected[0]
        if evidence.status != "extractable" or len(evidence.segments) != 1:
            return True
        segment = evidence.segments[0]
        if segment.role != "primary" or segment.start_offset != 0:
            return True
        if segment.end_offset is None or int(segment.end_offset) < file_size:
            return True
        if segment.damage_flags:
            return True
        boundary_confidence = str(evidence.details.get("boundary_confidence") or "").lower()
        if boundary_confidence in {"none", "low", "unknown"}:
            return True
        return False

    @staticmethod
    def _fuzzy_affects_structure(fuzzy: dict[str, Any]) -> bool:
        profile = fuzzy.get("binary_profile") if isinstance(fuzzy.get("binary_profile"), dict) else fuzzy
        route_hints = {
            "carrier_prefix_likely",
            "trailing_text_junk_likely",
            "trailing_padding_likely",
            "entropy_boundary_shift",
        }
        if route_hints.intersection(str(item) for item in profile.get("hints") or []):
            return True
        return any(
            isinstance(item, dict)
            and item.get("kind") in {
                "carrier_prefix_end",
                "entropy_boundary",
                "trailing_junk_start",
                "tail_padding_start",
            }
            for item in profile.get("offset_hints") or []
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

    def _run_fuzzy_pipeline(self, view: SharedBinaryView | MultiVolumeBinaryView, prepass: dict) -> dict[str, Any]:
        fuzzy_config = self.config.get("fuzzy") if isinstance(self.config.get("fuzzy"), dict) else {}
        if not fuzzy_config.get("enabled", True):
            return {}
        module_configs = enabled_fuzzy_module_configs(self.config)
        registry = get_fuzzy_analysis_module_registry()
        results = {}
        warnings = []
        for name, module_config in module_configs.items():
            module = registry.get(name)
            if module is None:
                warnings.append(f"{name}: fuzzy analysis module is not registered")
                continue
            try:
                results[name] = module.analyze(view, prepass, module_config)
            except Exception as exc:
                warnings.append(f"{name}: {exc}")
        if warnings:
            results["warnings"] = warnings
        return results

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
