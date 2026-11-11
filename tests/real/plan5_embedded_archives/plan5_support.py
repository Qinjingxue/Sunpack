from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tests.helpers.native_fixture import assemble_carrier
from tests.helpers.real_archives import (
    ArchiveFixtureFactory,
    create_encrypted_7z_archive,
    create_encrypted_rar_archive,
    create_encrypted_zip_archive,
    create_rar4_archive,
)
from tests.helpers.tool_config import get_optional_rar, get_test_tools


PASSWORD = "sunpack-plan5-acceptance"
FILE_NAME = "plan5_embedded.bin"
PAYLOAD_SIZE = 8 * 1024
JUNK_MIN = 192
JUNK_MAX = 6 * 1024
LARGE_SEGMENT_COUNT = 128
LARGE_JUNK_MIN = 24
LARGE_JUNK_MAX = 96


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
    archive_format: str
    variant: str
    encrypted: bool
    marker_text: str
    offset: int
    length: int


@dataclass(frozen=True)
class EmbeddedMixedCase:
    file_path: Path
    segments: tuple[EmbeddedSegmentSpec, ...]
    password: str


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


def _create_segment_archive(
    scratch: Path,
    spec: dict[str, Any],
    password: str,
    payload_size: int,
) -> tuple[Path, str]:
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
        return case.entry_path, case.marker_text
    if creator == "zip":
        case = create_encrypted_zip_archive(
            scratch,
            case_id,
            password=password,
            encryption=str(spec["params"]["encryption"]),
            payload_size=payload_size,
        )
        return case.entry_path, case.marker_text
    if creator == "7z":
        case = create_encrypted_7z_archive(
            scratch,
            case_id,
            password=password,
            header_encrypt=bool(spec["params"]["header_encrypt"]),
            payload_size=payload_size,
        )
        return case.entry_path, case.marker_text
    if creator == "rar":
        case = create_encrypted_rar_archive(
            scratch,
            case_id,
            password=password,
            rar4=bool(spec["params"]["rar4"]),
            header_encrypt=bool(spec["params"]["header_encrypt"]),
            payload_size=payload_size,
        )
        return case.entry_path, case.marker_text
    if creator == "rar4":
        case = create_rar4_archive(
            scratch,
            case_id,
            payload_size=payload_size,
            payload_profile=str(spec.get("payload_profile", "default")),
            **dict(spec.get("params", {})),
        )
        return case.entry_path, case.marker_text
    raise ValueError(f"unknown plan5 segment creator: {creator}")


def _build_carrier(
    file_path: Path,
    selected: list[dict[str, Any]],
    *,
    scratch: Path,
    password: str,
    payload_size: int,
    seed: int,
    junk_min: int,
    junk_max: int,
) -> EmbeddedMixedCase:
    # The independent fixture tool reports the offsets of the bytes it wrote.
    try:
        segments = [
            _create_segment_archive(scratch, spec, password, payload_size)
            for spec in selected
        ]
        layout = assemble_carrier(
            file_path, [path for path, _ in segments],
            seed=seed, junk_min=junk_min, junk_max=junk_max,
        )
        specs = tuple(
            EmbeddedSegmentSpec(
                archive_format=spec["format"],
                variant=spec["variant"],
                encrypted=spec.get("encrypted", False),
                marker_text=marker,
                offset=extent["offset"],
                length=extent["length"],
            )
            for spec, (_, marker), extent in zip(selected, segments, layout["segments"], strict=True)
        )
        return EmbeddedMixedCase(file_path=file_path, segments=specs, password=password)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def build_embedded_mixed_case(
    root: Path,
    *,
    password: str = PASSWORD,
    payload_size: int = PAYLOAD_SIZE,
    junk_min: int = JUNK_MIN,
    junk_max: int = JUNK_MAX,
    seed: int = 0x5A17C0DE,
) -> EmbeddedMixedCase:
    """构造第 5 条测试文件：[垃圾][压缩段][垃圾][压缩段]…[垃圾]。

    Rust 按固定种子一次性流式组装，预期偏移由写入位置决定。
    扫描漏段必须在断言中失败，禁止换输入掩盖漏检。
    """
    root = Path(root)
    scratch = root / "_plan5_sources"
    mixed_dir = root / "plan5_mixed"
    mixed_dir.mkdir(parents=True, exist_ok=True)
    file_path = mixed_dir / FILE_NAME

    selected = available_segment_specs()
    if not selected:
        raise RuntimeError("plan5 has no segments to build: Rar.exe and zstd.exe are both unavailable")
    return _build_carrier(
        file_path, selected, scratch=scratch, password=password, payload_size=payload_size,
        seed=seed, junk_min=junk_min, junk_max=junk_max,
    )


def build_large_embedded_case(
    root: Path,
    *,
    count: int = LARGE_SEGMENT_COUNT,
    password: str = PASSWORD,
    payload_size: int = 64,
    junk_min: int = LARGE_JUNK_MIN,
    junk_max: int = LARGE_JUNK_MAX,
    seed: int = 0x1285A17C0DE,
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

    return _build_carrier(
        file_path, selected, scratch=scratch, password=password, payload_size=payload_size,
        seed=seed, junk_min=junk_min, junk_max=junk_max,
    )



