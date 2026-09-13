"""Reusable synthetic corpora for behavioural tests and opt-in benchmarks."""

from __future__ import annotations

import zipfile
from pathlib import Path

from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_minimal_7z, make_zip


def pressure_scan_config() -> dict:
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, processors=[
        {"name": "embedded_archive", "enabled": True},
        {"name": "pe_overlay_structure", "enabled": True},
        {"name": "executable_carrier", "enabled": True},
        {"name": "zip_eocd_structure", "enabled": True},
    ], precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
        {"name": "blacklist", "enabled": True, "blocked_extensions": [".jar", ".docx", ".apk", ".xlsx"]},
        {"name": "embedded_payload_identity", "enabled": True, "deep_scan_single_candidate_ratio": 1e-9},
        {"name": "zip_structure_accept", "enabled": True},
    ])


def write_large_resource(path: Path, label: str, size: int = 128 * 1024) -> None:
    chunk = (f"PRESSURE::{label}::".encode("ascii") * 4096)[:8192]
    with path.open("wb") as handle:
        remaining = size
        while remaining > 0:
            piece = chunk[: min(len(chunk), remaining)]
            handle.write(piece)
            remaining -= len(piece)


def create_container(path: Path, kind: str) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        if kind == "jar":
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            archive.writestr("com/example/App.class", b"\xca\xfe\xba\xbe")
        elif kind == "docx":
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document />")
        elif kind == "apk":
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
            archive.writestr("classes.dex", b"dex\n035\x00")
        elif kind == "xlsx":
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("xl/workbook.xml", "<workbook />")
        else:
            raise ValueError(kind)


def build_pressure_corpus(root: Path) -> list[str]:
    normal_exts = [".jpg", ".png", ".mp4", ".dll", ".pak", ".bin", ".dat", ".log"]
    for index in range(32):
        write_large_resource(root / f"bulk_asset_{index:03d}{normal_exts[index % len(normal_exts)]}", f"normal-{index}")
    expected = []
    for index in range(3):
        archive = root / f"real_archive_{index:02d}.zip"
        archive.write_bytes(make_zip({f"marker_{index}.txt": f"real::{index}"}))
        expected.append(archive.name)
    for index in range(2):
        disguised = root / f"masked_archive_{index:02d}.jpg"
        disguised.write_bytes(b"\xff\xd8synthetic-image\xff\xd9" + make_minimal_7z())
        expected.append(disguised.name)
    for index, kind in enumerate(["jar", "docx", "apk", "xlsx"]):
        create_container(root / f"container_{index:02d}.{kind}", kind)
    write_large_resource(root / "ordinary_tool.exe", "ordinary-tool", size=32 * 1024)
    write_large_resource(root / "ordinary_tool.part1.rar", "ordinary-part", size=32 * 1024)
    return sorted(expected)
