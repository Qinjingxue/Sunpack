from tests.helpers.archive_tasks import make_archive_task
from sunpack.pipeline.coordinator.task_scan import direct_file_task
from sunpack.core.support.output_paths import default_output_dir_for_task
from sunpack.core.support.output_reservation import build_output_dir_resolver


def _task(path):
    return make_archive_task(path, logical_name=path.stem)


def _resolved_output_dir(path):
    task = _task(path)
    return build_output_dir_resolver([task], default_output_dir_for_task)(task)


def test_output_path_reservation_preserves_stem_and_skips_occupied_names(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.touch()
    assert default_output_dir_for_task(_task(archive)) == str(tmp_path / "sample")
    assert _resolved_output_dir(archive) == str(tmp_path / "sample")

    occupied = tmp_path / "sample"
    occupied.write_text("existing", encoding="utf-8")
    assert _resolved_output_dir(archive) == str(tmp_path / "sample(1)")
    occupied.unlink()
    occupied.mkdir()
    assert _resolved_output_dir(archive) == str(tmp_path / "sample(1)")
    (tmp_path / "sample(1)").mkdir()
    assert _resolved_output_dir(archive) == str(tmp_path / "sample(2)")


def test_output_dir_uses_browser_numbering_when_source_occupies_output_name(tmp_path):
    archive = tmp_path / "sample"
    archive.write_bytes(b"archive")

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


def test_direct_input_keeps_filename_separate_from_disguised_format(tmp_path):
    source = tmp_path / "release.v2.zip.txt"
    task = direct_file_task(str(source))

    assert task.logical_name == "release.v2"
    assert task.main_path == str(source)
    assert task.archive_input().format_hint == ""
    assert default_output_dir_for_task(task) == str(tmp_path / "release.v2")


def test_directory_numbering_appends_after_dotted_filename(tmp_path):
    archive = tmp_path / "release.v2.zip"
    (tmp_path / "release.v2").mkdir()
    (tmp_path / "release.v2(1)").mkdir()
    task = direct_file_task(str(archive))

    resolver = build_output_dir_resolver([task], default_output_dir_for_task)

    assert resolver(task) == str(tmp_path / "release.v2(2)")
