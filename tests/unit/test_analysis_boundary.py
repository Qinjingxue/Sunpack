from __future__ import annotations

import ast
from pathlib import Path


FORBIDDEN_PREFIXES = (
    "sunpack.pipeline.coordinator",
    "sunpack.pipeline.discovery.detection",
    "sunpack.core.contracts.tasks",
)


def test_analysis_has_no_application_dependencies():
    root = Path(__file__).parents[2] / "sunpack" / "core" / "analysis"
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
    import sunpack.core.analysis as analysis

    assert not hasattr(analysis, "ArchiveAnalysisScheduler")


def test_segment_ends_never_come_from_raw_signature_hits():
    """Segment ends come from format structure, validated candidates, or the input EOF.

    A now deleted helper turned raw signature hits into segment boundaries.  The gzip and
    bzip2 magics are three bytes long and occur by chance inside encrypted payloads, so
    that fallback truncated healthy carrier archives into damaged extractions.  Keep the
    raw-hit-as-boundary concept out of the native analysis report.
    """
    report = (
        Path(__file__).parents[2]
        / "native" / "sunpack_native" / "src" / "analysis_native" / "view" / "report.rs"
    ).read_text(encoding="utf-8")
    assert "next_archive_boundary" not in report
    assert "ARCHIVE_SIGNATURE_HIT_NAMES" not in report


NATIVE_ANALYSIS_ENTRY_POINTS = (
    ".signature_prepass(",
    ".probe_zip_local_header(",
    ".locate_zip_eocd(",
    ".probe_zip(",
    ".probe_rar(",
    ".probe_seven_zip(",
    ".probe_tar(",
    ".probe_compression_stream(",
    ".probe_compressed_tar(",
    "inspect_compression_stream_identity",
    "inspect_compression_stream_structure",
)


def test_python_never_interprets_format_probes():
    """Archive analysis is decided once, in the native report.

    Python may run the report and project its result, but it must not call
    the per-format probes and re-derive formats, confidences, or segments.
    """
    root = Path(__file__).parents[2] / "sunpack"
    analysis = root / "core" / "analysis"
    assert not (analysis / "probes").exists()
    assert not (analysis / "structure_pipeline").exists()
    violations = [
        f"{path.relative_to(root)}: {name}"
        for path in sorted(root.rglob("*.py"))
        for name in NATIVE_ANALYSIS_ENTRY_POINTS
        if name in path.read_text(encoding="utf-8")
    ]
    assert violations == []
