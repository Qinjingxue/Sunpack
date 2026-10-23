from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest

from tests.helpers.native_fixture import assemble_carrier, assert_exact_tree, file_inventory, native_fixture
from tests.helpers.tool_config import get_optional_rar, get_optional_winrar
from sunpack.core.contracts.results import OutcomeKind
from sunpack.pipeline.coordinator.engine import PipelineEngine
from tests.real.plan1_real_archives.plan1_support import plan1_config, run_plan1_pipeline
from scripts.generate_real_structure_corpus import STRUCTURE_CASES, generate


SAMPLE_PARAMETERS = [pytest.param(case, id=case[0]) for case in STRUCTURE_CASES]


@pytest.fixture(scope="module", params=SAMPLE_PARAMETERS)
def external_sample(request, tmp_path_factory):
    case = request.param
    if case[2] == "rar5" and get_optional_rar() is None:
        pytest.skip("Rar.exe writer is required")
    if case[2] == "winrar-zip" and get_optional_winrar() is None:
        pytest.skip("WinRAR ZIP writer is required")
    assert shutil.which("tar.exe"), "Windows tar.exe must be available"
    # Samples are generated once per writer/structure and reused across the
    # container variants. No local ignored corpus or detector-selected bytes
    # are prerequisites for collecting or executing tests in a clean checkout.
    corpus = tmp_path_factory.mktemp(case[0])
    return corpus, generate(corpus, cases=(case,))[0]


@pytest.mark.parametrize("container", ["plain", "disguised", "carrier"])
def test_external_writer_structure_extracts_exact_members(tmp_path, plan_error, external_sample, container):
    corpus, sample = external_sample
    source = corpus / sample["file"]
    assert file_inventory(corpus)[source.name] == sample["archive"], "corpus bytes changed between container variants"
    archive = tmp_path / (sample["file"] if container == "plain" else "payload.unrelated")
    if container == "carrier":
        layout = assemble_carrier(archive, [source], seed=0xC0A905, decoys=True)
        plan_error["layout"] = layout
    else:
        shutil.copyfile(source, archive)
    plan_error.update({"sample": sample["id"], "creator": sample["creator"], "container": container})
    summary = run_plan1_pipeline(archive)
    assert not summary.failed_tasks, summary.failures
    assert summary.partial_success_count == 0
    assert summary.success_count == 1
    result = next(item for item in summary.target_results if Path(item.input_path) == archive)
    assert result.output_dir
    output_dir = Path(result.output_dir)
    assert output_dir.is_dir()
    assert_exact_tree(output_dir, sample["expected_files"])


@pytest.fixture(scope="module")
def empty_zip_sample(tmp_path_factory):
    corpus = tmp_path_factory.mktemp("empty-zip-output")
    sample = generate(corpus, cases=(("bsdtar-empty-zip", "zip", "zip-empty"),))[0]
    assert sample["expected_files"] == {}
    return corpus / sample["file"]


def test_unicode_external_writer_preserves_names_under_cp1252(tmp_path):
    # The normal corpus uses the host's locale and cannot catch CP1252-only
    # regressions on Chinese development machines. Two tiny external archives
    # cover both affected writers, including names and content, at low cost.
    source = tmp_path / "原始目录"
    names = ("日本語/说明.txt", "nested/" + "long-name-" * 16 + "/payload.txt", "empty.bin")
    for name in names:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("" if name == "empty.bin" else "Unicode payload\n", encoding="utf-8")
    expected = file_inventory(source)
    for archive_format in ("pax", "zip"):
        archive = tmp_path / f"外部样本.{archive_format}"
        native_fixture("libarchive", root=str(source), output=str(archive), paths=list(names),
                       format=archive_format, locale="English_United States.1252")
        summary = run_plan1_pipeline(archive)
        assert not summary.failed_tasks, summary.failures
        assert summary.partial_success_count == 0
        assert summary.success_count == 1
        result = next(item for item in summary.target_results if Path(item.input_path) == archive)
        assert result.output_dir
        assert_exact_tree(Path(result.output_dir), expected)


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("container", ["plain", "disguised", "carrier"])
@pytest.mark.parametrize("flatten", [False, True])
def test_empty_archive_preserves_output_without_recursive_children(
    tmp_path, empty_zip_sample, origin, container, flatten,
):
    archive = tmp_path / ("empty.zip" if container == "plain" else "payload.unrelated")
    if container == "carrier":
        assemble_carrier(archive, [empty_zip_sample], seed=0xC0A905, decoys=True)
    else:
        shutil.copyfile(empty_zip_sample, archive)
    config = plan1_config()
    config["output"] = {"root": str(tmp_path / "out")}
    config["post_extract"]["flatten_single_directory"] = flatten

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(archive)], origin=origin)

    response = asyncio.run(run())
    assert not response.summary.failed_tasks, response.summary.failures
    assert len(response.summary.target_results) == 1
    result = response.summary.target_results[0]
    assert result.outcome_kind == OutcomeKind.COMPLETE_SUCCESS
    assert result.output_dir
    output = Path(result.output_dir)
    assert output.is_absolute() and output.is_dir()
    assert output.parent == tmp_path / "out"
    assert_exact_tree(output, {})
    assert archive.is_file()
