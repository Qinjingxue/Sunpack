from __future__ import annotations

import pytest

from tests.helpers.native_fixture import native_fixture
from tests.helpers.real_archives import run_cmd
from tests.helpers.seven_zip_lz4 import create_7z_lz4_case
from tests.helpers.tool_config import require_7z_zstd
from tests.real.plan1_real_archives.plan1_support import assert_plan1_success


@pytest.mark.parametrize("options", [
    {}, {"solid": False}, {"branch": "BCJ"}, {"branch": "BCJ2"},
    {"password": "secret", "header_encrypt": False},
    {"password": "secret"}, {"split": True},
    {"split": True, "password": "secret"}, {"disguise": True},
    {"payload_size": 16}, {"payload_size": 9 * 1024 * 1024},
], ids=["solid", "nonsolid", "bcj", "bcj2", "encrypted-data", "encrypted-header",
        "split", "encrypted-split", "disguised", "small", "multichunk-large"])
def test_plan1_seven_zip_lz4_interoperability(tmp_path, options, plan1_error):
    case = create_7z_lz4_case(tmp_path, "interop", **options)
    # The independent writer must also accept every fixture before SunPack runs.
    run_cmd([str(require_7z_zstd()), "t", "-y", *(["-psecret"] if case.password else []),
             str(case.entry_path)], case.archive_dir)
    assert_plan1_success(case, ".7z", passwords=["wrong", "secret"], error_info=plan1_error)


def test_plan1_lz4_encoded_header_uses_native_analysis_and_worker(tmp_path, plan1_error):
    case = create_7z_lz4_case(tmp_path, "raw_header", header_compress=False)
    encoded = case.entry_path.with_name("lz4_header.7z")
    native_fixture("seven_zip_lz4_header", source=str(case.entry_path), output=str(encoded))
    case.entry_path.unlink()
    case.entry_path = encoded
    run_cmd([str(require_7z_zstd()), "t", str(encoded)], case.archive_dir)
    assert_plan1_success(case, ".7z", error_info=plan1_error)
