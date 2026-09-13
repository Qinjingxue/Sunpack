from __future__ import annotations

import ast
from pathlib import Path


FORBIDDEN_PREFIXES = (
    "sunpack.coordinator",
    "sunpack.detection",
    "sunpack.contracts.tasks",
)


def test_analysis_has_no_application_dependencies():
    root = Path(__file__).parents[2] / "sunpack" / "analysis"
    violations = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            modules = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                if module.startswith(FORBIDDEN_PREFIXES):
                    violations.append(f"{path.relative_to(root)}:{node.lineno}: {module}")
    assert violations == []


def test_analysis_no_longer_exposes_a_business_scheduler():
    import sunpack.analysis as analysis

    assert not hasattr(analysis, "ArchiveAnalysisScheduler")
