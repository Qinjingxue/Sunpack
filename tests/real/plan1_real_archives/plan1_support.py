from __future__ import annotations

import hashlib
from pathlib import Path

from sunpack.config.schema import normalize_config
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.detection_probe import detect_archive_hits
from tests.helpers.marker_utils import marker_was_extracted
from tests.helpers.pipeline_engine import execute_pipeline
from tests.helpers.real_archives import ArchiveCase


# 第 1 条：扫描时顶层检测到的格式。tar 变体的顶层是外层流格式，
# 内容靠 recur=* 递归解出（与运行时覆盖配置 recursive_extract=* 等价）。
EXPECTED_DETECTED_EXT = {
    "zip": ".zip",
    "rar": ".rar",
    "7z": ".7z",
    "tar": ".tar",
    "tar.gz": ".gz",
    "tar.bz2": ".bz2",
    "tar.xz": ".xz",
    "tar.zst": ".zst",
    "gzip": ".gz",
    "bzip2": ".bz2",
    "xz": ".xz",
    "zstd": ".zst",
}

PLAIN_FORMATS = list(EXPECTED_DETECTED_EXT)


def plan1_config(passwords: list[str] | None = None) -> dict:
    """第 1 条测试统一配置：所有 tar 递归使用 recur=*。

    raw 值 "*" 会在 normalize_config 时变成 infinite 模式，
    等价于运行时覆盖配置里 recursive_extract=*。
    """
    return normalize_config(
        with_detection_pipeline(
            {
                "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
                "recursive_extract": "*",
                "extraction": {"content_requirement": "complete"},
                "post_extract": {
                    "archive_cleanup_mode": "k",
                    "flatten_single_directory": False,
                },
                "verification": {"enabled": True},
                "user_passwords": passwords or [],
                "builtin_passwords": [],
            },
            processors=[
                {"name": "embedded_archive", "enabled": True},
                {"name": "pe_overlay_structure", "enabled": True},
                {"name": "executable_carrier", "enabled": True},
                {"name": "zip_eocd_structure", "enabled": True},
                {"name": "tar_header_structure", "enabled": True},
                {"name": "compression_stream_structure", "enabled": True},
                {"name": "seven_zip_structure", "enabled": True},
                {"name": "rar_structure", "enabled": True},
            ],
            precheck=[
                {"name": "size_range", "enabled": True, "gte": 0},
                {"name": "zip_structure_accept", "enabled": True},
                {"name": "tar_structure_accept", "enabled": True},
                {"name": "seven_zip_structure_accept", "enabled": True},
                {"name": "rar_structure_accept", "enabled": True},
                {"name": "compression_stream_accept", "enabled": True},
                {"name": "embedded_payload_identity", "enabled": True},
            ],
        )
    )


def run_plan1_pipeline(target: Path, passwords: list[str] | None = None):
    return execute_pipeline(plan1_config(passwords=passwords), str(target))


def marker_text_contained(root: Path, marker_text: str) -> bool:
    """Return whether marker text appears inside any extracted file (substring)."""
    needle = marker_text.encode("utf-8")
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            if needle in path.read_bytes():
                return True
        except OSError:
            continue
    return False


def _expected_files_extracted(case: ArchiveCase, root: Path) -> dict[str, dict[str, object]]:
    """Validate every known fixture member by size and SHA-256, not only its marker."""
    expected_files = case.metadata.get("expected_files") or {}
    validation: dict[str, dict[str, object]] = {}
    for member_name, expected in expected_files.items():
        normalized_name = str(member_name).replace("\\", "/")
        expected_size = int(expected["size"])
        expected_sha256 = str(expected["sha256"])
        matches = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            name_matches = (
                case.archive_format in {"gzip", "bzip2", "xz", "zstd"}
                or relative == normalized_name
                or relative.endswith(f"/{normalized_name}")
                or path.name == Path(normalized_name).name
            )
            if not name_matches:
                continue
            try:
                if path.stat().st_size != expected_size:
                    continue
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                continue
            if digest == expected_sha256:
                matches.append(str(path))
        validation[normalized_name] = {
            "expected_size": expected_size,
            "expected_sha256": expected_sha256,
            "matches": matches,
            "ok": bool(matches),
        }
    return validation


def assert_expected_files_extracted(case: ArchiveCase, root: Path) -> None:
    validation = _expected_files_extracted(case, root)
    missing_files = [
        name for name, result in validation.items() if not result["ok"]
    ]
    assert not missing_files, f"expected extracted members missing or corrupted: {missing_files}"


def assert_plan1_success(
    case: ArchiveCase,
    expected_ext: str,
    *,
    expected_container: str | None = None,
    expected_member_count: int | None = None,
    error_info: dict | None = None,
    passwords: list[str] | None = None,
) -> None:
    hits = detect_archive_hits(case.entry_path)
    actual_ext = hits[0].fact_bag.get("file.detected_ext") if hits else None
    if error_info is not None:
        error_info["expected_detected_ext"] = expected_ext
        error_info["actual_detected_ext"] = actual_ext
        error_info["detection_hit_count"] = len(hits)
        error_info["detection_hits"] = [
            {
                "detected_ext": hit.fact_bag.get("file.detected_ext"),
                "container_type": hit.fact_bag.get("file.container_type"),
                "member_paths": len(hit.fact_bag.get("candidate.member_paths") or []),
                "probe_offset": hit.fact_bag.get("file.probe_offset"),
            }
            for hit in hits
        ]
    assert len(hits) == 1, (
        f"expected exactly one detection hit for {case.entry_path.name}, got {len(hits)}"
    )
    assert actual_ext == expected_ext, (
        f"detected format mismatch: expected {expected_ext}, got {actual_ext}"
    )
    if expected_container is not None:
        actual_container = hits[0].fact_bag.get("file.container_type")
        if error_info is not None:
            error_info["expected_container_type"] = expected_container
            error_info["actual_container_type"] = actual_container
        assert actual_container == expected_container, (
            f"container type mismatch: expected {expected_container}, got {actual_container}"
        )
    if expected_member_count is not None:
        actual_members = len(hits[0].fact_bag.get("candidate.member_paths") or [])
        if error_info is not None:
            error_info["expected_member_count"] = expected_member_count
            error_info["actual_member_count"] = actual_members
        assert actual_members == expected_member_count, (
            f"member count mismatch: expected {expected_member_count}, got {actual_members}"
        )

    summary = run_plan1_pipeline(case.archive_dir, passwords=passwords)
    expected_file_validation = _expected_files_extracted(case, case.archive_dir)
    extracted = marker_was_extracted(case.archive_dir, case.marker_name, case.marker_text)
    if error_info is not None:
        error_info.update(
            {
                "pipeline_success_count": summary.success_count,
                "pipeline_partial_success_count": summary.partial_success_count,
                "pipeline_failed_tasks": [str(item) for item in summary.failed_tasks],
                "marker_extracted": extracted,
                "expected_file_validation": expected_file_validation,
            }
        )
    assert summary.failed_tasks == [], f"pipeline reported failures: {summary.failed_tasks}"
    assert summary.partial_success_count == 0, (
        f"pipeline reported partial successes: {summary.partial_success_count}"
    )
    assert_expected_files_extracted(case, case.archive_dir)
    assert extracted, f"marker {case.marker_name!r} was not extracted for {case.entry_path.name}"
