import importlib
import pkgutil
from functools import lru_cache


@lru_cache(maxsize=32)
def discover_package_modules(package_name: str, *, recursive: bool = False) -> None:
    package = importlib.import_module(package_name)
    iterator = pkgutil.walk_packages if recursive else pkgutil.iter_modules
    for module_info in iterator(package.__path__, package.__name__ + "."):
        importlib.import_module(module_info.name)
