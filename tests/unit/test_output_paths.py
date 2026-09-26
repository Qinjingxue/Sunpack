from tests.helpers.archive_tasks import make_archive_task
from sunpack.core.support.output_paths import default_output_dir_for_task
from sunpack.core.support.output_reservation import build_output_dir_resolver


def _task(path):
    return make_archive_task(path, logical_name=path.stem)


def _resolved_output_dir(path):
    task = _task(path)
    return build_output_dir_resolver([task], default_output_dir_for_task)(task)


def test_default_output_dir_uses_archive_stem_when_available(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")

    assert default_output_dir_for_task(_task(archive)) == str(tmp_path / "sample")


def test_output_dir_uses_browser_numbering_when_source_occupies_output_name(tmp_path):
    archive = tmp_path / "sample"
    archive.write_bytes(b"archive")

    assert _resolved_output_dir(archive) == str(tmp_path / "sample(1)")


def test_output_dir_avoids_existing_same_name_directory(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    (tmp_path / "sample").mkdir()

    assert _resolved_output_dir(archive) == str(tmp_path / "sample(1)")


def test_output_dir_increments_when_extracted_directory_exists(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    (tmp_path / "sample").mkdir()
    (tmp_path / "sample(1)").mkdir()

    assert _resolved_output_dir(archive) == str(tmp_path / "sample(2)")


def test_output_dir_avoids_existing_same_name_file(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    (tmp_path / "sample").write_text("existing", encoding="utf-8")

    assert _resolved_output_dir(archive) == str(tmp_path / "sample(1)")


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
