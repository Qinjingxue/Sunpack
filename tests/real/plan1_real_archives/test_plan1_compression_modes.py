from __future__ import annotations

import subprocess

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory, create_rar4_archive
from tests.helpers.tool_config import (
    get_optional_rar,
    get_optional_rar_sfx,
    require_7z,
)
from tests.real.plan1_real_archives.plan1_support import assert_plan1_success


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None
RAR_SFX_AVAILABLE = get_optional_rar_sfx() is not None


def _listed_methods(path) -> list[str]:
    result = subprocess.run(
        [str(require_7z()), "l", "-slt", str(path)],
        cwd=str(path.parent),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return [
        line.split("=", 1)[1].strip()
        for line in result.stdout.splitlines()
        if line.startswith("Method =") and line.split("=", 1)[1].strip()
    ]


ZIP_METHOD_CASES = [
    pytest.param("Copy", 0, "Store", id="copy"),
    pytest.param("Deflate", 5, "Deflate", id="deflate"),
    pytest.param("Deflate64", 5, "Deflate64", id="deflate64"),
    pytest.param("BZip2", 5, "BZip2", id="bzip2"),
    pytest.param("LZMA", 5, "LZMA", id="lzma"),
    pytest.param("PPMd", 5, "PPMd", id="ppmd"),
]


@pytest.mark.parametrize(("method", "level", "listed_method"), ZIP_METHOD_CASES)
def test_plan1_zip_compression_methods_extract_all_members(
    tmp_path, method, level, listed_method, plan1_error
):
    case = FACTORY.create(
        tmp_path,
        f"zip_method_{method.lower()}",
        "zip",
        payload_size=256,
        payload_profile="structured",
        compression_method=method,
        compression_level=level,
    )
    plan1_error.update(
        {
            "case_id": case.case_id,
            "archive_format": "zip",
            "compression_method": method,
            "compression_level": level,
            "listed_methods": _listed_methods(case.entry_path),
        }
    )
    assert any(value.startswith(listed_method) for value in plan1_error["listed_methods"])
    assert_plan1_success(case, ".zip", error_info=plan1_error)


SEVEN_ZIP_METHOD_CASES = [
    pytest.param("Copy", 0, False, "Copy", id="copy-nonsolid"),
    pytest.param("LZMA2", 5, True, "LZMA2", id="lzma2-solid"),
    pytest.param("LZMA2", 5, False, "LZMA2", id="lzma2-nonsolid"),
    pytest.param("LZMA", 5, True, "LZMA", id="lzma-solid"),
    pytest.param("PPMd", 5, True, "PPMd", id="ppmd-solid"),
    pytest.param("BZip2", 5, True, "BZip2", id="bzip2-solid"),
    pytest.param("Deflate", 5, True, "Deflate", id="deflate-solid"),
    pytest.param("LZ4", 1, True, "04F71104", id="lz4-solid"),
    pytest.param("LZ4", 1, False, "04F71104", id="lz4-nonsolid"),
]


@pytest.mark.parametrize(
    ("method", "level", "solid", "listed_method"), SEVEN_ZIP_METHOD_CASES
)
def test_plan1_seven_zip_compression_methods_and_solid_modes_extract_all_members(
    tmp_path, method, level, solid, listed_method, plan1_error
):
    case = FACTORY.create(
        tmp_path,
        f"7z_method_{method.lower()}_{'solid' if solid else 'nonsolid'}",
        "7z",
        payload_size=256,
        payload_profile="structured",
        compression_method=method,
        compression_level=level,
        solid=solid,
    )
    methods = _listed_methods(case.entry_path)
    plan1_error.update(
        {
            "case_id": case.case_id,
            "archive_format": "7z",
            "compression_method": method,
            "compression_level": level,
            "solid": solid,
            "listed_methods": methods,
        }
    )
    assert any(value.lower().startswith(listed_method.lower()) for value in methods)
    assert_plan1_success(case, ".7z", error_info=plan1_error)


RAR_MODE_CASES = [
    pytest.param(0, False, "m0", id="store-nonsolid"),
    pytest.param(5, False, "m5", id="maximum-nonsolid"),
    pytest.param(5, True, "m5", id="maximum-solid"),
]


@pytest.mark.parametrize(("level", "solid", "listed_method"), RAR_MODE_CASES)
def test_plan1_rar_compression_levels_and_solid_modes_extract_all_members(
    tmp_path, level, solid, listed_method, plan1_error
):
    if not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    case = FACTORY.create(
        tmp_path,
        f"rar_mode_{level}_{'solid' if solid else 'nonsolid'}",
        "rar",
        payload_size=256,
        payload_profile="structured",
        compression_level=level,
        solid=solid,
    )
    methods = _listed_methods(case.entry_path)
    plan1_error.update(
        {
            "case_id": case.case_id,
            "archive_format": "rar",
            "compression_level": level,
            "solid": solid,
            "listed_methods": methods,
        }
    )
    assert any(listed_method in value for value in methods)
    assert_plan1_success(case, ".rar", error_info=plan1_error)


@pytest.mark.parametrize(
    ("level", "solid", "listed_method"),
    [
        pytest.param(1, False, "m1", id="rar4-compressed-nonsolid"),
        pytest.param(5, True, "m5", id="rar4-compressed-solid"),
    ],
)
def test_plan1_rar4_compression_modes_extract_all_members(
    tmp_path, level, solid, listed_method, plan1_error
):
    if not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    case = create_rar4_archive(
        tmp_path,
        f"rar4_mode_{level}_{'solid' if solid else 'nonsolid'}",
        payload_size=256,
        payload_profile="structured",
        compression_level=level,
        solid=solid,
    )
    methods = _listed_methods(case.entry_path)
    plan1_error.update(
        {
            "case_id": case.case_id,
            "archive_format": "rar",
            "rar4": True,
            "compression_level": level,
            "solid": solid,
            "listed_methods": methods,
        }
    )
    assert any(listed_method in value for value in methods)
    assert_plan1_success(case, ".rar", error_info=plan1_error)


def test_plan1_rar4_compressed_split_extracts_all_members(tmp_path, plan1_error):
    if not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    case = create_rar4_archive(
        tmp_path,
        "rar4_compressed_split",
        split=True,
        split_volume_size=32 * 1024,
        payload_size=96 * 1024,
        payload_profile="structured",
        compression_level=5,
        solid=True,
    )
    methods = _listed_methods(case.entry_path)
    plan1_error.update(
        {
            "case_id": case.case_id,
            "archive_format": "rar",
            "rar4": True,
            "compression_level": 5,
            "solid": True,
            "split": True,
            "listed_methods": methods,
        }
    )
    assert any("m5" in value for value in methods)
    assert_plan1_success(case, ".rar", error_info=plan1_error)


COMPRESSED_COMBINATIONS = [
    pytest.param("7z", "LZMA2", 5, True, id="7z-lzma2"),
    pytest.param("zip", "Deflate", 5, None, id="zip-deflate"),
    pytest.param("rar", None, 5, True, id="rar-m5"),
]


@pytest.mark.parametrize(("archive_format", "method", "level", "solid"), COMPRESSED_COMBINATIONS)
@pytest.mark.parametrize(
    ("variant", "sfx", "split"),
    [
        pytest.param("sfx", True, False, id="sfx"),
        pytest.param("split", False, True, id="split"),
        pytest.param("sfx-split", True, True, id="sfx-split"),
    ],
)
def test_plan1_compressed_sfx_and_split_combinations(
    tmp_path,
    archive_format,
    method,
    level,
    solid,
    variant,
    sfx,
    split,
    plan1_error,
):
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    if archive_format == "rar" and sfx and not RAR_SFX_AVAILABLE:
        pytest.skip("RAR SFX generator is not configured")
    case = FACTORY.create(
        tmp_path,
        f"compressed_{archive_format}_{variant}",
        archive_format,
        sfx=sfx,
        split=split,
        split_volume_size=32 * 1024,
        payload_size=96 * 1024,
        payload_profile="structured",
        compression_method=method,
        compression_level=level,
        solid=solid,
    )
    plan1_error.update(
        {
            "case_id": case.case_id,
            "archive_format": archive_format,
            "compression_method": method,
            "compression_level": level,
            "solid": solid,
            "sfx": sfx,
            "split": split,
            "variant": variant,
        }
    )
    assert_plan1_success(
        case,
        f".{archive_format}",
        expected_container="pe" if sfx else None,
        error_info=plan1_error,
    )
