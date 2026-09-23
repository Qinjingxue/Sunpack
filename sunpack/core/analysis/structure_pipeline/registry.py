from sunpack.core.analysis.structure_pipeline.module import AnalysisModule
from sunpack.core.support.module_discovery import discover_package_modules
from sunpack.core.support.registry import NamedRegistry


class AnalysisModuleRegistry(NamedRegistry[AnalysisModule]):
    def __init__(self):
        super().__init__()

    def register(self, module: AnalysisModule):
        self.register_named(module.spec.name, module)

    def get(self, name: str) -> AnalysisModule | None:
        return self.get_named(name)

    def all(self) -> dict[str, AnalysisModule]:
        return self.all_named()


_global_registry = AnalysisModuleRegistry()


def register_analysis_module(module: AnalysisModule):
    _global_registry.register(module)
    return module


def get_analysis_module_registry() -> AnalysisModuleRegistry:
    return _global_registry


def discover_analysis_modules():
    discover_package_modules("sunpack.core.analysis.structure_pipeline.modules")
