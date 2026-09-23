from __future__ import annotations

import ast
from importlib.util import resolve_name
from pathlib import Path


_PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "sunpack"
_LAYERS = {"core", "pipeline", "runtime"}


def _module_package(path: Path) -> str:
    relative = path.relative_to(_PACKAGE_ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(("sunpack", *parts))


def _layer_for(module: str) -> str | None:
    parts = module.split(".")
    if len(parts) >= 2 and parts[0] == "sunpack" and parts[1] in _LAYERS:
        return parts[1]
    return None


def _import_targets(node: ast.AST, package: str) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if not isinstance(node, ast.ImportFrom):
        return []

    if node.level:
        relative = "." * node.level + (node.module or "")
        base = resolve_name(relative, package)
    else:
        base = node.module or ""

    targets = [base] if base else []
    if base == "sunpack":
        targets.extend(f"sunpack.{alias.name}" for alias in node.names)
    return targets


def test_top_level_packages_are_grouped_by_architectural_layer() -> None:
    packages = {
        path.name
        for path in _PACKAGE_ROOT.iterdir()
        if path.is_dir() and (path / "__init__.py").is_file()
    }
    assert packages == _LAYERS


def test_imports_follow_runtime_pipeline_core_direction() -> None:
    violations: list[str] = []
    for path in _PACKAGE_ROOT.rglob("*.py"):
        source_layer = _layer_for(_module_package(path))
        if source_layer is None:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            targets = _import_targets(node, _module_package(path))
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value.startswith("sunpack."):
                    targets.append(node.value)
            for target in targets:
                target_layer = _layer_for(target)
                if source_layer == "core" and target_layer in {"pipeline", "runtime"}:
                    violations.append(f"{path}: core imports {target}")
                elif source_layer == "pipeline" and target_layer == "runtime":
                    violations.append(f"{path}: pipeline imports {target}")

    assert not violations, "\n".join(violations)


def test_removed_migration_adapters_do_not_return() -> None:
    forbidden_paths = (
        _PACKAGE_ROOT / "pipeline" / "discovery" / "relations" / "stage.py",
        _PACKAGE_ROOT / "pipeline" / "extraction" / "internal" / "workflow" / "split_entry.py",
    )
    assert not any(path.exists() for path in forbidden_paths)

    forbidden_tokens = (
        "SplitArchiveInfo",
        "ensure_archive_state",
        "module_executor_pool",
        "output_inventory_payload",
    )
    violations = []
    for path in _PACKAGE_ROOT.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            if token in source:
                violations.append(f"{path}: retired adapter token {token}")
    assert not violations, "\n".join(violations)
