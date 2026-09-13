from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.support.output_paths import default_output_dir_for_task


def _task(path):
    return ArchiveTask(
        fact_bag=FactBag(),
        main_path=str(path),
        all_parts=[str(path)],
        logical_name=path.stem,
    )


def test_default_output_dir_uses_archive_stem_when_available(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")

    assert default_output_dir_for_task(_task(archive)) == str(tmp_path / "sample")


def test_default_output_dir_avoids_existing_same_name_directory(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    (tmp_path / "sample").mkdir()

    assert default_output_dir_for_task(_task(archive)) == str(tmp_path / "sample_extracted")


def test_default_output_dir_increments_when_extracted_directory_exists(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    (tmp_path / "sample").mkdir()
    (tmp_path / "sample_extracted").mkdir()

    assert default_output_dir_for_task(_task(archive)) == str(tmp_path / "sample_extracted_2")


def test_default_output_dir_avoids_existing_same_name_file(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    (tmp_path / "sample").write_text("existing", encoding="utf-8")

    assert default_output_dir_for_task(_task(archive)) == str(tmp_path / "sample_extracted")


def test_nested_archive_under_output_root_keeps_generated_parent(tmp_path):
    input_root = tmp_path / "downloads"
    output_root = tmp_path / "probe" / "work"
    nested_archive = output_root / "outer" / "inner.zip"
    nested_archive.parent.mkdir(parents=True)
    nested_archive.write_bytes(b"zip")

    result = default_output_dir_for_task(
        _task(nested_archive),
        {"root": str(output_root), "common_root": str(input_root)},
    )

    assert result == str(output_root / "outer" / "inner")
