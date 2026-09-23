import importlib
import pkgutil
from functools import lru_cache


@lru_cache(maxsize=32)
def discover_package_modules(package_name: str, *, recursive: bool = False) -> None:
    package = importlib.import_module(package_name)
    iterator = pkgutil.walk_packages if recursive else pkgutil.iter_modules
    for module_info in iterator(package.__path__, package.__name__ + "."):
        importlib.import_module(module_info.name)


@lru_cache(maxsize=32)
def import_static_modules(module_names: tuple[str, ...]) -> None:
    """Import a fixed registry manifest once per process.

    Runtime package walking is useful for extensible entry points, but the built-in
    detection pipeline is closed over modules shipped with SunPack.  Keeping its
    manifest explicit avoids filesystem scans on every fresh Python process while
    retaining import-time decorator registration and deterministic ordering.
    """
    for module_name in module_names:
        importlib.import_module(module_name)
