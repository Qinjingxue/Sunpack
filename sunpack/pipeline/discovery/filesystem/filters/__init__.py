import importlib
import pkgutil
from typing import Any

from sunpack.core.config.detection_view import scan_filters_enabled
from sunpack.pipeline.discovery.filesystem.filters.base import ScanFilter


_FILTER_CLASSES = {}
_DISCOVERED = False


def register_filter(name: str, filter_cls):
    _FILTER_CLASSES[name] = filter_cls


def discover_filters():
    global _DISCOVERED
    if _DISCOVERED:
        return
    package = importlib.import_module(f"{__name__}.modules")
    for module_info in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
        module = importlib.import_module(module_info.name)
        for value in module.__dict__.values():
            name = getattr(value, "name", None)
            stage = getattr(value, "stage", None)
            from_config = getattr(value, "from_config", None)
            if isinstance(name, str) and isinstance(stage, str) and callable(from_config):
                register_filter(name, value)
    _DISCOVERED = True


def build_filters(config: dict[str, Any] | None = None) -> list[ScanFilter]:
    discover_filters()
    if isinstance(config, dict) and not scan_filters_enabled(config):
        return []
    filters_config = []
    if isinstance(config, dict):
        filesystem_config = config.get("filesystem")
        if isinstance(filesystem_config, dict) and isinstance(filesystem_config.get("scan_filters"), list):
            filters_config = filesystem_config.get("scan_filters") or []

    filters: list[ScanFilter] = []
    for item in filters_config:
        if not isinstance(item, dict) or not item.get("enabled", False):
            continue
        name = item.get("name")
        filter_cls = _FILTER_CLASSES.get(name)
        if filter_cls is None:
            raise ValueError(f"Unknown filesystem scan filter: {name}")
        filters.append(filter_cls.from_config(item))
    return filters
