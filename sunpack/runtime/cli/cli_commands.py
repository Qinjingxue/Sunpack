import importlib
import pkgutil
import threading
from types import ModuleType

from sunpack.runtime.cli import commands


_COMMAND_CACHE_LOCK = threading.Lock()
_COMMAND_MODULE_CACHE: tuple[ModuleType, ...] | None = None
_COMMAND_MODULE_NAMES = {
    "extract": "sunpack.runtime.cli.commands.extract", "watch": "sunpack.runtime.cli.commands.watch",
    "scan": "sunpack.runtime.cli.commands.scan", "inspect": "sunpack.runtime.cli.commands.inspect_command",
    "passwords": "sunpack.runtime.cli.commands.passwords", "config": "sunpack.runtime.cli.commands.config",
}


def discover_command_modules(command: str | None = None) -> list[ModuleType]:
    global _COMMAND_MODULE_CACHE
    if command in _COMMAND_MODULE_NAMES:
        return [importlib.import_module(_COMMAND_MODULE_NAMES[command])]
    with _COMMAND_CACHE_LOCK:
        if _COMMAND_MODULE_CACHE is not None:
            return list(_COMMAND_MODULE_CACHE)
    modules: list[ModuleType] = []
    seen: set[str] = set()
    for module_info in pkgutil.iter_modules(commands.__path__, commands.__name__ + "."):
        module = importlib.import_module(module_info.name)
        command = getattr(module, "COMMAND", None)
        if not isinstance(command, str) or not command.strip():
            raise ValueError(f"CLI command module {module_info.name} must declare COMMAND")
        if command in seen:
            raise ValueError(f"Duplicate CLI command name: {command}")
        if not callable(getattr(module, "register", None)):
            raise ValueError(f"CLI command module {module_info.name} must declare register(subparsers, ctx)")
        if not callable(getattr(module, "handle", None)):
            raise ValueError(f"CLI command module {module_info.name} must declare handle(args, ctx)")
        seen.add(command)
        modules.append(module)
    modules.sort(key=lambda module: (getattr(module, "ORDER", 1000), getattr(module, "COMMAND")))
    with _COMMAND_CACHE_LOCK:
        _COMMAND_MODULE_CACHE = tuple(modules)
    return modules


def command_map(modules: list[ModuleType] | None = None) -> dict[str, ModuleType]:
    return {module.COMMAND: module for module in (modules or discover_command_modules())}

