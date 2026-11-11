from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scripts.generate_real_structure_corpus import STRUCTURE_CASES, generate
from tests.helpers.native_fixture import assemble_carrier, assert_exact_tree, file_inventory, native_fixture
from tests.helpers.tool_config import get_optional_rar, get_optional_winrar


@pytest.fixture(scope="module", params=[pytest.param(case, id=case[0]) for case in STRUCTURE_CASES])
def external_sample(request, tmp_path_factory):
    case = request.param
    if case[2] == "rar5" and get_optional_rar() is None:
        pytest.skip("Rar.exe writer is required")
    if case[2] == "winrar-zip" and get_optional_winrar() is None:
        pytest.skip("WinRAR ZIP writer is required")
    corpus = tmp_path_factory.mktemp(case[0])
    return corpus, generate(corpus, cases=(case,))[0]


def _stage(source: Path, folder: Path, container: str) -> Path:
    archive = folder / (source.name if container == "plain" else "payload.unrelated")
    if container == "carrier":
        assemble_carrier(archive, [source], seed=0xC0A905, decoys=True)
    else:
        shutil.copyfile(source, archive)
    return archive


def _single_output(root: Path) -> Path:
    outputs = list(root.iterdir())
    assert len(outputs) == 1 and outputs[0].is_dir(), outputs
    return outputs[0]


@pytest.mark.parametrize("container", ["plain", "disguised", "carrier"])
def test_external_writer_structure_extracts_exact_members(package, tmp_path, external_sample, container):
    corpus, sample = external_sample
    source = corpus / sample["file"]
    assert file_inventory(corpus)[source.name] == sample["archive"]
    archive = _stage(source, tmp_path, container)
    output = tmp_path / "out"
    report = package.json("extract", "-d", "-r", "1", "-c", "k", "-o", output, archive)
    assert report["summary"]["partial_success_count"] == 0, (sample["creator"], report)
    assert report["summary"]["success_count"] == 1, (sample["creator"], report)
    assert_exact_tree(_single_output(output), sample["expected_files"])


def test_unicode_external_writer_preserves_names_under_cp1252(package, tmp_path):
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
        output = tmp_path / f"out-{archive_format}"
        report = package.json("extract", "-d", "-r", "1", "-c", "k", "-o", output, archive)
        assert report["summary"]["success_count"] == 1, report
        assert_exact_tree(_single_output(output), expected)


@pytest.fixture(scope="module")
def empty_zip_sample(tmp_path_factory):
    corpus = tmp_path_factory.mktemp("empty-zip-output")
    sample = generate(corpus, cases=(("bsdtar-empty-zip", "zip", "zip-empty"),))[0]
    assert sample["expected_files"] == {}
    return corpus / sample["file"]


@pytest.mark.parametrize("origin", ["foreground", pytest.param("watch", marks=pytest.mark.requires_watch_broker)])
@pytest.mark.parametrize("container", ["plain", "disguised", "carrier"])
@pytest.mark.parametrize("flatten", [False, True])
def test_empty_archive_preserves_output_without_recursive_children(
    package, tmp_path, empty_zip_sample, origin, container, flatten,
):
    watched = tmp_path / "watched"
    watched.mkdir()
    archive = _stage(empty_zip_sample, watched, container)
    output = tmp_path / "out"
    package.configure(post_extract={"flatten_single_directory": flatten})
    if origin == "watch":
        package.json("watch", "add", "-d", "-o", output, watched)
        package.json("watch", "start", "--once", "--no-tray")
    else:
        report = package.json("extract", "-d", "-r", "*", "-c", "k", "-o", output, archive)
        assert report["summary"]["success_count"] == 1, report
    assert_exact_tree(_single_output(output), {})
    assert archive.is_file()
