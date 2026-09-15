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


def test_segment_ends_never_come_from_raw_signature_hits():
    """Segment ends come from format structure, validated candidates, or the input EOF.

    A now deleted helper turned raw signature hits into segment boundaries.  The gzip and
    bzip2 magics are three bytes long and occur by chance inside encrypted payloads, so
    that fallback truncated healthy carrier archives into damaged extractions.  Keep both
    the helper and the raw-hit-as-boundary concept out of the analysis layer.
    """
    modules_root = (
        Path(__file__).parents[2] / "sunpack" / "analysis" / "structure_pipeline" / "modules"
    )
    assert not (modules_root / "_boundaries.py").exists()

    sources = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(modules_root.rglob("*.py"))
    )
    assert "next_archive_boundary" not in sources
    assert "ARCHIVE_SIGNATURE_HIT_NAMES" not in sources
