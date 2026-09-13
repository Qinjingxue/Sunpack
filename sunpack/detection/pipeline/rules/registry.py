from typing import Dict, Type

from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.support.module_discovery import import_static_modules

_PRECHECK_RULE_MODULES = (
    "sunpack.detection.pipeline.rules.precheck.compression_stream_accept",
    "sunpack.detection.pipeline.rules.precheck.rar_structure_accept",
    "sunpack.detection.pipeline.rules.precheck.seven_zip_structure_accept",
    "sunpack.detection.pipeline.rules.precheck.tar_structure_accept",
    "sunpack.detection.pipeline.rules.precheck.zip_structure_accept",
    "sunpack.detection.pipeline.rules.precheck.embedded_payload_identity",
)

class RuleRegistry:
    def __init__(self):
        self._rules: Dict[str, Dict[str, Type[RuleBase]]] = {
            "precheck": {},
        }

    def register(self, layer: str, name: str, rule_cls: Type[RuleBase]):
        if layer not in self._rules:
            raise ValueError(f"Unknown layer: {layer}")
        self._rules[layer][name] = rule_cls

    def get_rule(self, layer: str, name: str) -> Type[RuleBase]:
        return self._rules.get(layer, {}).get(name)

    def get_all_rules(self, layer: str) -> Dict[str, Type[RuleBase]]:
        return self._rules.get(layer, {})

_global_rule_registry = RuleRegistry()
_discovered = False

def register_rule(name: str, layer: str):
    def decorator(cls: Type[RuleBase]):
        _global_rule_registry.register(layer, name, cls)
        return cls
    return decorator

def get_rule_registry() -> RuleRegistry:
    return _global_rule_registry

def discover_rules():
    global _discovered
    if _discovered:
        return

    import_static_modules(_PRECHECK_RULE_MODULES)

    _discovered = True
