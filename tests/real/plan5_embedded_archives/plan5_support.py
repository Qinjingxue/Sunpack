from __future__ import annotations

import hashlib
import os
import random
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sunpack.core.analysis.embedded import scan_embedded_archives
from tests.real.diagnostics import (
    case_snapshot,
    environment_snapshot,
    marker_locations,
    password_summary,
    pipeline_snapshot,
    record_exception,
    snapshot_path,
)
from tests.helpers.marker_utils import marker_was_extracted
from tests.helpers.real_archives import (
    ArchiveFixtureFactory,
    create_encrypted_7z_archive,
    create_encrypted_rar_archive,
    create_encrypted_zip_archive,
    create_rar4_archive,
)
from tests.helpers.tool_config import get_optional_rar, get_test_tools
from tests.real.plan1_real_archives.plan1_support import run_plan1_pipeline


PASSWORD = "sunpack-plan5-acceptance"
CASE_ID = "plan5_mixed"
FILE_NAME = "plan5_embedded.bin"
PAYLOAD_SIZE = 8 * 1024
JUNK_MIN = 192
JUNK_MAX = 6 * 1024
MAX_ASSEMBLY_ATTEMPTS = 40
LARGE_SEGMENT_COUNT = 128
LARGE_JUNK_MIN = 24
LARGE_JUNK_MAX = 96
LARGE_MAX_ASSEMBLY_ATTEMPTS = 12


# 段顺序刻意打散：相邻段避免同格式，且加密段与非加密段交错，
# 让"下一段签名"这类边界推断无法依赖相邻格式。
SEGMENT_ORDER: tuple[dict[str, Any], ...] = (
    {"format": "zip", "variant": "zipcrypto", "encrypted": True, "creator": "zip", "params": {"encryption": "ZipCrypto"}},
    {"format": "7z", "variant": "7z-header-on", "encrypted": True, "creator": "7z", "params": {"header_encrypt": True}},
    {"format": "rar", "variant": "rar5-header", "encrypted": True, "creator": "rar", "params": {"rar4": False, "header_encrypt": True}},
    {"format": "tar", "variant": "tar", "encrypted": False, "creator": "factory", "params": {}},
    {"format": "gzip", "variant": "gzip", "encrypted": False, "creator": "factory", "params": {}},
    {"format": "bzip2", "variant": "bzip2", "encrypted": False, "creator": "factory", "params": {}},
    {"format": "xz", "variant": "xz", "encrypted": False, "creator": "factory", "params": {}},
    {"format": "zstd", "variant": "zstd", "encrypted": False, "creator": "factory", "params": {}},
    {"format": "zip", "variant": "zip-aes256", "encrypted": True, "creator": "zip", "params": {"encryption": "AES256"}},
    {"format": "7z", "variant": "7z-header-off", "encrypted": True, "creator": "7z", "params": {"header_encrypt": False}},
    {"format": "rar", "variant": "rar5-data", "encrypted": True, "creator": "rar", "params": {"rar4": False, "header_encrypt": False}},
    {"format": "rar", "variant": "rar4-header", "encrypted": True, "creator": "rar", "params": {"rar4": True, "header_encrypt": True}},
    {"format": "rar", "variant": "rar4-data", "encrypted": True, "creator": "rar", "params": {"rar4": True, "header_encrypt": False}},
)


@dataclass(frozen=True)
class EmbeddedSegmentSpec:
    position: int
    archive_format: str
    variant: str
    encrypted: bool
    password: str | None
    marker_name: str
    marker_text: str
    offset: int
    length: int
    source_name: str


@dataclass(frozen=True)
class EmbeddedMixedCase:
    case_id: str
    file_path: Path
    segments: tuple[EmbeddedSegmentSpec, ...]
    password: str
    junk_blocks: tuple[tuple[int, str], ...]
    skipped_formats: tuple[str, ...]


FACTORY = ArchiveFixtureFactory()


# The large embedded fixture cycles through this matrix until it contains 128
# independent archives.  Every item gets a unique marker and source archive,
# so the test exercises many real container/codec combinations without
# making the assertion depend on internal candidate bookkeeping.
LARGE_SEGMENT_MATRIX: tuple[dict[str, Any], ...] = (
    {"format": "zip", "variant": "zip-copy", "creator": "factory", "params": {"compression_method": "Copy", "compression_level": 0}},
    {"format": "zip", "variant": "zip-deflate", "creator": "factory", "params": {"compression_method": "Deflate", "compression_level": 5}},
    {"format": "zip", "variant": "zip-deflate64", "creator": "factory", "params": {"compression_method": "Deflate64", "compression_level": 9}},
    {"format": "zip", "variant": "zip-bzip2", "creator": "factory", "params": {"compression_method": "BZip2", "compression_level": 1}},
    {"format": "zip", "variant": "zip-lzma", "creator": "factory", "params": {"compression_method": "LZMA", "compression_level": 5}},
    {"format": "zip", "variant": "zip-ppmd", "creator": "factory", "params": {"compression_method": "PPMd", "compression_level": 9}},
    {"format": "7z", "variant": "7z-copy-nonsolid", "creator": "factory", "params": {"compression_method": "Copy", "compression_level": 0, "solid": False}},
    {"format": "7z", "variant": "7z-lzma2-solid", "creator": "factory", "params": {"compression_method": "LZMA2", "compression_level": 5, "solid": True}},
    {"format": "7z", "variant": "7z-lzma2-nonsolid", "creator": "factory", "params": {"compression_method": "LZMA2", "compression_level": 1, "solid": False}},
    {"format": "7z", "variant": "7z-lzma-solid", "creator": "factory", "params": {"compression_method": "LZMA", "compression_level": 9, "solid": True}},
    {"format": "7z", "variant": "7z-ppmd-solid", "creator": "factory", "params": {"compression_method": "PPMd", "compression_level": 5, "solid": True}},
    {"format": "7z", "variant": "7z-bzip2-solid", "creator": "factory", "params": {"compression_method": "BZip2", "compression_level": 1, "solid": True}},
    {"format": "7z", "variant": "7z-deflate-solid", "creator": "factory", "params": {"compression_method": "Deflate", "compression_level": 9, "solid": True}},
    {"format": "rar", "variant": "rar5-store-nonsolid", "creator": "factory", "params": {"compression_level": 0, "solid": False}},
    {"format": "rar", "variant": "rar5-fast-nonsolid", "creator": "factory", "params": {"compression_level": 1, "solid": False}},
    {"format": "rar", "variant": "rar5-normal-solid", "creator": "factory", "params": {"compression_level": 3, "solid": True}},
    {"format": "rar", "variant": "rar5-maximum-solid", "creator": "factory", "params": {"compression_level": 5, "solid": True}},
    {"format": "rar", "variant": "rar4-fast-nonsolid", "creator": "rar4", "params": {"compression_level": 1, "solid": False}},
    {"format": "rar", "variant": "rar4-normal-solid", "creator": "rar4", "params": {"compression_level": 3, "solid": True}},
    {"format": "rar", "variant": "rar4-maximum-solid", "creator": "rar4", "params": {"compression_level": 5, "solid": True}},
    {"format": "tar", "variant": "tar", "creator": "factory", "params": {}},
    {"format": "gzip", "source_format": "tar.gz", "variant": "tar-gzip", "creator": "factory", "params": {}},
    {"format": "bzip2", "source_format": "tar.bz2", "variant": "tar-bzip2", "creator": "factory", "params": {}},
    {"format": "xz", "source_format": "tar.xz", "variant": "tar-xz", "creator": "factory", "params": {}},
    {"format": "zstd", "source_format": "tar.zst", "variant": "tar-zstd", "creator": "factory", "params": {}},
    {"format": "gzip", "variant": "gzip-a", "creator": "factory", "params": {}},
    {"format": "gzip", "variant": "gzip-b", "creator": "factory", "params": {}},
    {"format": "bzip2", "variant": "bzip2-a", "creator": "factory", "params": {}},
    {"format": "bzip2", "variant": "bzip2-b", "creator": "factory", "params": {}},
    {"format": "xz", "variant": "xz-a", "creator": "factory", "params": {}},
    {"format": "xz", "variant": "xz-b", "creator": "factory", "params": {}},
    {"format": "xz", "variant": "xz-c", "creator": "factory", "params": {}},
    {"format": "zstd", "variant": "zstd-a", "creator": "factory", "params": {}},
    {"format": "zstd", "variant": "zstd-b", "creator": "factory", "params": {}},
)


def available_segment_specs() -> list[dict[str, Any]]:
    """按可用工具过滤段定义；rar 依赖 Rar.exe，zstd 依赖 zstd.exe。"""
    rar_available = get_optional_rar() is not None
    zstd_tool = get_test_tools().get("zstd_exe")
    zstd_available = bool(zstd_tool and zstd_tool.is_file())
    return [
        spec
        for spec in SEGMENT_ORDER
        if not (spec["format"] == "rar" and not rar_available)
        and not (spec["format"] == "zstd" and not zstd_available)
    ]


def _create_archive_bytes(
    scratch: Path,
    spec: dict[str, Any],
    password: str,
    payload_size: int,
) -> tuple[Path, str, str]:
    case_id = f"p5_{spec['variant']}"
    creator = spec["creator"]
    if creator == "factory":
        factory_kwargs = {
            "payload_size": payload_size,
            "payload_profile": str(spec.get("payload_profile", "default")),
        }
        factory_kwargs.update(dict(spec.get("params", {})))
        case = FACTORY.create(
            scratch,
            case_id,
            str(spec.get("source_format", spec["format"])),
            **factory_kwargs,
        )
        return case.entry_path, case.marker_name, case.marker_text
    if creator == "zip":
        case = create_encrypted_zip_archive(
            scratch,
            case_id,
            password=password,
            encryption=str(spec["params"]["encryption"]),
            payload_size=payload_size,
        )
        return case.entry_path, case.marker_name, case.marker_text
    if creator == "7z":
        case = create_encrypted_7z_archive(
            scratch,
            case_id,
            password=password,
            header_encrypt=bool(spec["params"]["header_encrypt"]),
            payload_size=payload_size,
        )
        return case.entry_path, case.marker_name, case.marker_text
    if creator == "rar":
        case = create_encrypted_rar_archive(
            scratch,
            case_id,
            password=password,
            rar4=bool(spec["params"]["rar4"]),
            header_encrypt=bool(spec["params"]["header_encrypt"]),
            payload_size=payload_size,
        )
        return case.entry_path, case.marker_name, case.marker_text
    if creator == "rar4":
        case = create_rar4_archive(
            scratch,
            case_id,
            payload_size=payload_size,
            payload_profile=str(spec.get("payload_profile", "default")),
            **dict(spec.get("params", {})),
        )
        return case.entry_path, case.marker_name, case.marker_text
    raise ValueError(f"unknown plan5 segment creator: {creator}")


def _assemble(segments: list[dict[str, Any]], salt: int, junk_min: int, junk_max: int):
    """按 [垃圾][压缩段]…[垃圾] 组装字节流；每个垃圾块用独立种子随机生成。"""
    blob = bytearray()
    junk_blocks: list[tuple[int, str]] = []
    offset = 0
    for index, segment in enumerate(segments):
        rng = random.Random((0x5A17C0DE ^ (index * 0x9E3779B9) ^ ((salt + 1) * 0x2545F491)) & 0xFFFFFFFF)
        junk_len = rng.randrange(junk_min, junk_max + 1)
        junk = bytes(rng.getrandbits(8) for _ in range(junk_len))
        blob.extend(junk)
        junk_blocks.append((junk_len, hashlib.sha256(junk).hexdigest()))
        offset += junk_len

        segment["offset"] = offset
        blob.extend(segment["bytes"])
        segment["length"] = len(segment["bytes"])
        offset += len(segment["bytes"])

    tail_rng = random.Random((0xDEADBEEF ^ (salt * 0x9E3779B9)) & 0xFFFFFFFF)
    tail_len = tail_rng.randrange(junk_min, junk_max + 1)
    tail = bytes(tail_rng.getrandbits(8) for _ in range(tail_len))
    blob.extend(tail)
    junk_blocks.append((tail_len, hashlib.sha256(tail).hexdigest()))
    return bytes(blob), junk_blocks


def _candidate_offsets(path: Path) -> set[tuple[str, int]]:
    result = scan_embedded_archives(str(path), expected_size=path.stat().st_size)
    return {(candidate.format, candidate.offset) for candidate in result.candidates}


def build_embedded_mixed_case(
    root: Path,
    *,
    password: str = PASSWORD,
    payload_size: int = PAYLOAD_SIZE,
    junk_min: int = JUNK_MIN,
    junk_max: int = JUNK_MAX,
    max_attempts: int = MAX_ASSEMBLY_ATTEMPTS,
    error_info: dict[str, Any] | None = None,
) -> EmbeddedMixedCase:
    """构造第 5 条测试文件：[垃圾][压缩段][垃圾][压缩段]…[垃圾]。

    垃圾块全部随机生成（每个块独立种子、长度可变），组装后立刻用
    scan_embedded_archives 验证每个构造段都能被识别；随机垃圾若撞出
    可验证签名导致缺段，则换盐值重新组装（有界重试）。
    """
    root = Path(root)
    scratch = root / "_plan5_sources"
    mixed_dir = root / "plan5_mixed"
    mixed_dir.mkdir(parents=True, exist_ok=True)
    file_path = mixed_dir / FILE_NAME

    selected = available_segment_specs()
    if not selected:
        raise RuntimeError("plan5 has no segments to build: Rar.exe and zstd.exe are both unavailable")
    skipped = tuple(
        format_name
        for format_name in ("rar", "zstd")
        if not any(spec["format"] == format_name for spec in selected)
    )

    segments: list[dict[str, Any]] = []
    for spec in selected:
        archive_path, marker_name, marker_text = _create_archive_bytes(
            scratch, spec, password, payload_size
        )
        segments.append({
            **spec,
            "bytes": archive_path.read_bytes(),
            "source_name": archive_path.name,
            "marker_name": marker_name,
            "marker_text": marker_text,
            "password": password if spec["encrypted"] else None,
        })

    attempts: list[dict[str, Any]] = []
    for salt in range(max_attempts):
        assembled, junk_blocks = _assemble(segments, salt, junk_min, junk_max)
        tmp_path = mixed_dir / ".plan5_embedded.tmp"
        tmp_path.write_bytes(assembled)
        found = _candidate_offsets(tmp_path)
        missing = [
            str(segment["variant"])
            for segment in segments
            if (segment["format"], int(segment["offset"])) not in found
        ]
        digests = [digest for _length, digest in junk_blocks]
        if not missing and len(set(digests)) == len(digests):
            file_path.write_bytes(assembled)
            tmp_path.unlink(missing_ok=True)
            shutil.rmtree(scratch, ignore_errors=True)
            spec_objects = tuple(
                EmbeddedSegmentSpec(
                    position=index,
                    archive_format=str(segment["format"]),
                    variant=str(segment["variant"]),
                    encrypted=bool(segment["encrypted"]),
                    password=str(segment["password"]) if segment["password"] else None,
                    marker_name=str(segment["marker_name"]),
                    marker_text=str(segment["marker_text"]),
                    offset=int(segment["offset"]),
                    length=int(segment["length"]),
                    source_name=str(segment["source_name"]),
                )
                for index, segment in enumerate(segments)
            )
            return EmbeddedMixedCase(
                case_id=CASE_ID,
                file_path=file_path,
                segments=spec_objects,
                password=password,
                junk_blocks=tuple(junk_blocks),
                skipped_formats=skipped,
            )
        attempts.append({
            "salt": salt,
            "missing_variants": missing,
            "junk_collision": len(set(digests)) != len(digests),
        })
        tmp_path.unlink(missing_ok=True)

    shutil.rmtree(scratch, ignore_errors=True)
    if error_info is not None:
        error_info["plan5_build_attempts"] = attempts
    raise RuntimeError(
        f"plan5 fixture could not assemble a file covering every segment "
        f"after {max_attempts} attempts; last missing={attempts[-1] if attempts else None}"
    )


def build_large_embedded_case(
    root: Path,
    *,
    count: int = LARGE_SEGMENT_COUNT,
    password: str = PASSWORD,
    payload_size: int = 64,
    junk_min: int = LARGE_JUNK_MIN,
    junk_max: int = LARGE_JUNK_MAX,
    max_attempts: int = LARGE_MAX_ASSEMBLY_ATTEMPTS,
    error_info: dict[str, Any] | None = None,
) -> EmbeddedMixedCase:
    """构造百级真实嵌入归档：[无效数据][压缩包][无效数据]循环。"""
    if count < 100:
        raise ValueError("large embedded case must contain at least 100 archives")
    if get_optional_rar() is None:
        raise RuntimeError("large embedded case requires Rar.exe")
    zstd_tool = get_test_tools().get("zstd_exe")
    if not zstd_tool or not zstd_tool.is_file():
        raise RuntimeError("large embedded case requires zstd.exe")

    root = Path(root)
    scratch = root / "_plan5_large_sources"
    mixed_dir = root / "plan5_large_mixed"
    mixed_dir.mkdir(parents=True, exist_ok=True)
    file_path = mixed_dir / f"plan5_large_{count}.bin"

    selected = []
    for index in range(count):
        base = LARGE_SEGMENT_MATRIX[index % len(LARGE_SEGMENT_MATRIX)]
        selected.append({
            **base,
            "variant": f"{base['variant']}-{index:03d}",
            "payload_profile": "structured",
        })

    segments: list[dict[str, Any]] = []
    for spec in selected:
        archive_path, marker_name, marker_text = _create_archive_bytes(
            scratch, spec, password, payload_size
        )
        segments.append({
            **spec,
            "bytes": archive_path.read_bytes(),
            "source_name": archive_path.name,
            "marker_name": marker_name,
            "marker_text": marker_text,
            "password": None,
        })

    attempts: list[dict[str, Any]] = []
    for salt in range(max_attempts):
        assembled, junk_blocks = _assemble(segments, salt, junk_min, junk_max)
        tmp_path = mixed_dir / ".plan5_large_embedded.tmp"
        tmp_path.write_bytes(assembled)
        found = _candidate_offsets(tmp_path)
        missing = [
            str(segment["variant"])
            for segment in segments
            if (segment["format"], int(segment["offset"])) not in found
        ]
        digests = [digest for _length, digest in junk_blocks]
        if not missing and len(set(digests)) == len(digests):
            file_path.write_bytes(assembled)
            tmp_path.unlink(missing_ok=True)
            shutil.rmtree(scratch, ignore_errors=True)
            spec_objects = tuple(
                EmbeddedSegmentSpec(
                    position=index,
                    archive_format=str(segment["format"]),
                    variant=str(segment["variant"]),
                    encrypted=False,
                    password=None,
                    marker_name=str(segment["marker_name"]),
                    marker_text=str(segment["marker_text"]),
                    offset=int(segment["offset"]),
                    length=int(segment["length"]),
                    source_name=str(segment["source_name"]),
                )
                for index, segment in enumerate(segments)
            )
            return EmbeddedMixedCase(
                case_id=f"plan5_large_{count}",
                file_path=file_path,
                segments=spec_objects,
                password=password,
                junk_blocks=tuple(junk_blocks),
                skipped_formats=(),
            )
        attempts.append({
            "salt": salt,
            "missing_variants": missing,
            "junk_collision": len(set(digests)) != len(digests),
        })
        tmp_path.unlink(missing_ok=True)

    shutil.rmtree(scratch, ignore_errors=True)
    if error_info is not None:
        error_info["plan5_large_build_attempts"] = attempts
    raise RuntimeError(
        f"large plan5 fixture could not assemble {count} archives after "
        f"{max_attempts} attempts; last missing={attempts[-1] if attempts else None}"
    )


def _segment_table(case: EmbeddedMixedCase) -> list[dict[str, Any]]:
    return [
        {
            "position": segment.position,
            "format": segment.archive_format,
            "variant": segment.variant,
            "encrypted": segment.encrypted,
            "offset": segment.offset,
            "length": segment.length,
            "marker_name": segment.marker_name,
            "source_name": segment.source_name,
        }
        for segment in case.segments
    ]


def _marker_status(
    case: EmbeddedMixedCase,
    root: Path,
    *,
    include_locations: bool = False,
) -> list[dict[str, Any]]:
    return [
        {
            "position": segment.position,
            "variant": segment.variant,
            "format": segment.archive_format,
            "encrypted": segment.encrypted,
            "marker_extracted": marker_was_extracted(
                root, segment.marker_name, segment.marker_text
            ),
            **(
                {"matches": marker_locations(root, segment.marker_name, segment.marker_text)}
                if include_locations
                else {}
            ),
        }
        for segment in case.segments
    ]


def assert_plan5_native_scan_coverage(
    case: EmbeddedMixedCase,
    *,
    error_info: dict[str, Any] | None = None,
) -> None:
    """native 全流扫描必须命中每个构造段（格式 + 起始偏移）。"""
    result = scan_embedded_archives(str(case.file_path), expected_size=case.file_path.stat().st_size)
    found = {(candidate.format, candidate.offset) for candidate in result.candidates}
    expected = {(segment.archive_format, segment.offset) for segment in case.segments}
    missing = [segment for segment in case.segments if (segment.archive_format, segment.offset) not in found]
    extras = [
        {"format": candidate.format, "offset": candidate.offset}
        for candidate in result.candidates
        if (candidate.format, candidate.offset) not in expected
    ]
    if error_info is not None:
        error_info["native_candidate_count"] = len(result.candidates)
        error_info["native_candidates"] = [
            {
                "format": candidate.format,
                "offset": candidate.offset,
                "end_offset": candidate.end_offset,
                "confidence": candidate.confidence,
                "validation": candidate.validation,
            }
            for candidate in result.candidates
        ]
        error_info["missing_segments"] = [
            {"format": segment.archive_format, "variant": segment.variant, "offset": segment.offset}
            for segment in missing
        ]
        error_info["unexpected_candidates"] = extras
    assert not missing, (
        f"embedded scan missed constructed segments: "
        f"{[(s.archive_format, s.variant, s.offset) for s in missing]}"
    )


def assert_plan5_single_task_scan(
    case: EmbeddedMixedCase,
    *,
    error_info: dict[str, Any] | None = None,
) -> None:
    """整个混合文件在扫描阶段必须恰好成为一个待处理任务。"""
    from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
    from tests.real.plan1_real_archives.plan1_support import plan1_config

    provider = ArchiveTaskProvider(plan1_config())
    tasks = provider.scan_targets([str(case.file_path.parent)])
    expected = os.path.normcase(os.path.abspath(str(case.file_path)))
    actual = [os.path.normcase(os.path.abspath(str(task.main_path))) for task in tasks]
    if error_info is not None:
        error_info["scan_task_count"] = len(tasks)
        error_info["scan_task_paths"] = actual
        error_info["expected_task_path"] = expected
    assert actual == [expected], (
        f"expected exactly one scan task for the mixed file, got {actual}"
    )


def assert_plan5_success(
    case: EmbeddedMixedCase,
    *,
    passwords: list[str] | None = None,
    error_info: dict[str, Any] | None = None,
    detailed_diagnostics: bool = False,
) -> None:
    """第 5 条主断言：给出正确密码后，所有嵌入压缩段分别解压成功。"""
    effective = list(passwords) if passwords is not None else [case.password]
    diagnostics = (
        error_info.setdefault("diagnostics", {})
        if error_info is not None and detailed_diagnostics
        else None
    )
    if diagnostics is not None:
        diagnostics["environment"] = environment_snapshot()
        diagnostics["case"] = {
            **case_snapshot(case),
            "file_path": str(case.file_path),
            "file_size": case.file_path.stat().st_size,
            "segment_count": len(case.segments),
        }
        diagnostics["passwords"] = password_summary(effective)
        diagnostics["input_before_pipeline"] = snapshot_path(case.file_path.parent)
        try:
            native_scan = scan_embedded_archives(
                str(case.file_path),
                expected_size=case.file_path.stat().st_size,
            )
            expected = {
                (segment.archive_format, segment.offset): segment.variant
                for segment in case.segments
            }
            diagnostics["native_scan_before_pipeline"] = {
                "candidate_count": len(native_scan.candidates),
                "candidates": [
                    {
                        "format": candidate.format,
                        "offset": candidate.offset,
                        "end_offset": candidate.end_offset,
                        "confidence": candidate.confidence,
                        "validation": candidate.validation,
                    }
                    for candidate in native_scan.candidates
                ],
                "expected_segments": [
                    {
                        "format": archive_format,
                        "offset": offset,
                        "variant": variant,
                    }
                    for (archive_format, offset), variant in expected.items()
                ],
                "missing_expected_segments": [
                    {
                        "format": archive_format,
                        "offset": offset,
                        "variant": variant,
                    }
                    for (archive_format, offset), variant in expected.items()
                    if not any(
                        candidate.format == archive_format
                        and candidate.offset == offset
                        for candidate in native_scan.candidates
                    )
                ],
            }
        except BaseException as exc:
            record_exception(error_info, "native_scan_before_pipeline", exc)
            raise

    summary = None
    try:
        summary = run_plan1_pipeline(case.file_path, passwords=effective)
    except BaseException as exc:
        if diagnostics is not None:
            record_exception(error_info, "pipeline", exc)
            pipeline_snapshot(
                error_info,
                phase="pipeline_exception",
                roots=(case.file_path.parent,),
            )
        raise

    if diagnostics is not None:
        pipeline_snapshot(
            error_info,
            phase="pipeline_returned",
            summary=summary,
            roots=(case.file_path.parent,),
        )

    try:
        marker_status = _marker_status(
            case,
            case.file_path.parent,
            include_locations=detailed_diagnostics,
        )
    except BaseException as exc:
        if diagnostics is not None:
            record_exception(error_info, "marker_scan", exc)
            pipeline_snapshot(
                error_info,
                phase="marker_scan_exception",
                summary=summary,
                roots=(case.file_path.parent,),
            )
        raise

    missing_markers = [
        item
        for item in marker_status
        if not item["marker_extracted"]
    ]
    if error_info is not None:
        error_info.update({
            "password_list": effective,
            "pipeline_success_count": summary.success_count,
            "pipeline_partial_success_count": summary.partial_success_count,
            "pipeline_failed_tasks": [str(item) for item in summary.failed_tasks],
            "failure_kinds": [str(failure.kind) for failure in summary.failures],
            "marker_status": marker_status,
        })
        if diagnostics is not None:
            diagnostics["marker_status"] = marker_status
            pipeline_snapshot(
                error_info,
                phase="before_assertions",
                summary=summary,
                roots=(case.file_path.parent,),
            )
    assert summary.failed_tasks == [], (
        f"pipeline reported failures: {[str(item) for item in summary.failed_tasks]}"
    )
    # Recursive extraction reports independently successful nested archives as
    # additional successes.  The user-visible contract here is that the
    # carrier succeeds and every marker is present, not a fixed task count.
    assert summary.success_count >= 1, (
        f"expected at least the carrier success, got {summary.success_count}"
    )
    assert not missing_markers, (
        f"markers missing for segments: "
        f"{[(item['position'], item['variant']) for item in missing_markers]}"
    )


def assert_plan5_wrong_password_partial(
    case: EmbeddedMixedCase,
    *,
    error_info: dict[str, Any] | None = None,
) -> None:
    """全错密码下：加密段必须失败并报密码错误，非加密段仍应解出。"""
    wrong = [f"wrong-{index:03d}-plan5" for index in range(20)]
    summary = run_plan1_pipeline(case.file_path, passwords=wrong)
    marker_status = _marker_status(case, case.file_path.parent)
    plain_extracted = [
        item for item in marker_status
        if not item["encrypted"] and item["marker_extracted"]
    ]
    encrypted_leaked = [
        item for item in marker_status
        if item["encrypted"] and item["marker_extracted"]
    ]
    if error_info is not None:
        error_info.update({
            "password_list_size": len(wrong),
            "pipeline_success_count": summary.success_count,
            "pipeline_partial_success_count": summary.partial_success_count,
            "pipeline_failed_tasks": [str(item) for item in summary.failed_tasks],
            "failure_kinds": [str(failure.kind) for failure in summary.failures],
            "password_failure_reported": any(
                failure.is_password_failure for failure in summary.failures
            ),
            "marker_status": marker_status,
        })
    assert summary.failed_tasks, "all-wrong passwords must leave failed tasks"
    assert any(failure.is_password_failure for failure in summary.failures), (
        f"no password failure reported; kinds={[str(f.kind) for f in summary.failures]}"
    )
    assert len(plain_extracted) == sum(1 for item in marker_status if not item["encrypted"]), (
        "plain (non-encrypted) segments must still extract with wrong passwords; "
        f"extracted={[item['variant'] for item in plain_extracted]}"
    )
    assert not encrypted_leaked, (
        f"encrypted markers must not extract with wrong passwords: "
        f"{[item['variant'] for item in encrypted_leaked]}"
    )


__all__ = [
    "PASSWORD",
    "CASE_ID",
    "FILE_NAME",
    "PAYLOAD_SIZE",
    "JUNK_MIN",
    "JUNK_MAX",
    "LARGE_SEGMENT_COUNT",
    "LARGE_SEGMENT_MATRIX",
    "SEGMENT_ORDER",
    "EmbeddedSegmentSpec",
    "EmbeddedMixedCase",
    "available_segment_specs",
    "build_embedded_mixed_case",
    "build_large_embedded_case",
    "assert_plan5_native_scan_coverage",
    "assert_plan5_single_task_scan",
    "assert_plan5_success",
    "assert_plan5_wrong_password_partial",
    "_segment_table",
]
