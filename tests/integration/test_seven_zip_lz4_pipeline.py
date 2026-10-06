from __future__ import annotations

import asyncio
import shutil

import pytest

from sunpack.pipeline.coordinator.engine import PipelineEngine
from tests.helpers.native_fixture import assemble_carrier, native_fixture
from tests.helpers.seven_zip_lz4 import create_7z_lz4_case
from tests.helpers.real_archives import create_7z_archive
from tests.real.plan1_real_archives.plan1_support import assert_expected_files_extracted, plan1_config


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("container", ["nested", "carrier", "disguised-encrypted-split"])
def test_seven_zip_lz4_reuses_pipeline_and_input_shapes(tmp_path, origin, container):
    split = container == "disguised-encrypted-split"
    case = create_7z_lz4_case(tmp_path / "fixtures", "inner", password="secret",
                               split=split, disguise=split)
    source = case.entry_path
    if container == "nested":
        wrapper = tmp_path / "wrapper"
        wrapper.mkdir()
        shutil.copyfile(source, wrapper / "inner.payload")
        source = tmp_path / "outer.7z"
        create_7z_archive(wrapper, source)
    elif container == "carrier":
        source = tmp_path / "carrier.photo"
        assemble_carrier(source, [case.entry_path], seed=0x7A04, decoys=True)
    config = plan1_config(["wrong", "secret"])
    output = tmp_path / "out"
    config["output"] = {"root": str(output)}

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(case.archive_dir if split else source)], origin=origin)

    response = asyncio.run(run())
    assert not response.summary.failed_tasks, response.summary.failures
    assert response.summary.partial_success_count == 0
    assert response.summary.success_count == (2 if container == "nested" else 1)
    assert_expected_files_extracted(case, output)


def test_corrupt_lz4_coder_retains_input_and_reports_failure(tmp_path):
    case = create_7z_lz4_case(tmp_path, "corrupt", header_compress=False)
    native_fixture("flip", path=str(case.entry_path), offset=70)
    config = plan1_config()
    config["output"] = {"root": str(tmp_path / "out")}
    config["post_extract"]["archive_cleanup_mode"] = "delete"

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(case.entry_path)])

    response = asyncio.run(run())
    assert response.summary.failed_tasks
    assert response.summary.success_count == 0
    assert case.entry_path.is_file()
