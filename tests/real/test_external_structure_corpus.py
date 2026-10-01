from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tests.helpers.native_fixture import assemble_carrier, assert_exact_tree, file_inventory
from tests.helpers.tool_config import get_optional_rar, get_optional_winrar
from tests.real.plan1_real_archives.plan1_support import run_plan1_pipeline
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
    output_dir = Path(result.output_dir)
    assert_exact_tree(output_dir, sample["expected_files"])
