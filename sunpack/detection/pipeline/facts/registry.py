from typing import Any, Callable, Dict
from sunpack.detection.pipeline.facts.schema import get_fact_schema, register_fact_schema
from sunpack.support.module_discovery import import_static_modules

_COLLECTOR_MODULES = (
    "sunpack.detection.pipeline.facts.collectors.file_facts",
    "sunpack.detection.pipeline.facts.collectors.magic_bytes",
)

FactCollectorFunc = Callable[[str], Any]

class FactRegistry:
    def __init__(self):
        self._collectors: Dict[str, FactCollectorFunc] = {}
        self._schemas: Dict[str, dict[str, Any]] = {}

    def register(self, fact_name: str, collector: FactCollectorFunc, schema: dict[str, Any] | None = None):
        existing_schema = get_fact_schema(fact_name) or {}
        normalized_schema = dict(existing_schema)
        if schema:
            normalized_schema.update(schema)
        if "type" not in normalized_schema:
            raise ValueError(f"Fact collector {fact_name} must declare schema type")
        if "description" not in normalized_schema:
            raise ValueError(f"Fact collector {fact_name} must declare schema description")
        normalized_schema.setdefault("producer", collector.__module__)
        self._collectors[fact_name] = collector
        self._schemas[fact_name] = normalized_schema
        register_fact_schema(fact_name, normalized_schema)

    def get_collector(self, fact_name: str) -> FactCollectorFunc:
        return self._collectors.get(fact_name)

    def get_schema(self, fact_name: str) -> dict[str, Any] | None:
        return self._schemas.get(fact_name) or get_fact_schema(fact_name)

    def get_all_collectors(self) -> Dict[str, FactCollectorFunc]:
        return dict(self._collectors)

    def get_all_schemas(self) -> Dict[str, dict[str, Any]]:
        return dict(self._schemas)

_global_registry = FactRegistry()

def register_fact(
    fact_name: str,
    *,
    type: str | list[str] | None = None,
    description: str | None = None,
    schema: dict[str, Any] | None = None,
    context: bool = False,
):
    def decorator(func: FactCollectorFunc):
        fact_schema = dict(schema or {})
        if type is not None:
            fact_schema["type"] = type
        if description is not None:
            fact_schema["description"] = description
        setattr(func, "_fact_accepts_context", bool(context))
        _global_registry.register(fact_name, func, fact_schema)
        return func
    return decorator


def get_registry() -> FactRegistry:
    return _global_registry

def discover_collectors():
    import_static_modules(_COLLECTOR_MODULES)
