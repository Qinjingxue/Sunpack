from tests.helpers.archive_tasks import make_archive_task
from sunpack.core.support.output_paths import next_available_path
from sunpack.core.support.output_reservation import OutputReservationRegistry, build_output_dir_resolver


def test_detected_extensions_do_not_rename_source_files(tmp_path):
    split_first = tmp_path / "disguised.part1.rar.001"
    split_second = tmp_path / "disguised.part2.rar.002"
    fake_doc = tmp_path / "fake_doc.txt"
    split_first.touch()
    split_second.touch()
    fake_doc.touch()

    tasks = [
        make_archive_task(split_first, format_hint="rar", logical_name="disguised"),
        make_archive_task(fake_doc, format_hint="zip", logical_name="fake_doc"),
    ]

    assert split_first.exists()
    assert split_second.exists()
    assert fake_doc.exists()
    assert tasks[0].archive_input().format_hint == "rar"
    assert tasks[1].archive_input().format_hint == "zip"
    assert not (tmp_path / "disguised.part1.rar").exists()
    assert not (tmp_path / "fake_doc.zip").exists()


def test_embedded_carrier_keeps_physical_extension_and_detected_format(tmp_path):
    carrier = tmp_path / "carrier.jpg"
    carrier.touch()

    task = make_archive_task(
        carrier,
        format_hint="rar",
        logical_name="carrier",
        discovery_source="embedded",
    )
    assert carrier.exists()
    assert task.main_path == str(carrier)
    assert task.archive_input().format_hint == "rar"


def test_output_dir_resolver_disambiguates_duplicate_task_outputs(tmp_path):
    seven_zip = tmp_path / "collision.7z"
    zip_file = tmp_path / "collision.zip"
    existing_output = tmp_path / "collision_7z"
    seven_zip.touch()
    zip_file.touch()
    existing_output.write_text("existing file", encoding="utf-8")

    first = make_archive_task(seven_zip, logical_name="collision", format_hint="7z")
    second = make_archive_task(zip_file, logical_name="collision", format_hint="zip")

    def default_output_dir(task):
        return str(tmp_path / task.logical_name)

    resolver = build_output_dir_resolver([first, second], default_output_dir)

    assert resolver(first) == str(tmp_path / "collision")
    assert resolver(second) == str(tmp_path / "collision(1)")


def test_next_available_path_uses_browser_style_numbering(tmp_path):
    original = tmp_path / "report.txt"
    first = tmp_path / "report(1).txt"
    original.touch()
    first.touch()

    assert next_available_path(str(original)) == str(tmp_path / "report(2).txt")


def test_output_dir_resolver_avoids_existing_output_directory(tmp_path):
    archive = tmp_path / "photos.zip"
    archive.touch()
    (tmp_path / "photos").mkdir()
    (tmp_path / "photos(1)").mkdir()
    task = make_archive_task(archive, logical_name="photos", format_hint="zip")

    resolver = build_output_dir_resolver([task], lambda item: str(tmp_path / item.logical_name))

    assert resolver(task) == str(tmp_path / "photos(2)")


def test_output_reservations_disambiguate_concurrent_requests_before_directories_exist(tmp_path):
    registry = OutputReservationRegistry()
    first_task = make_archive_task(tmp_path / "a.zip", format_hint="zip")
    second_task = make_archive_task(tmp_path / "b.zip", format_hint="zip")
    default = lambda _task: str(tmp_path / "shared")

    first = build_output_dir_resolver([first_task], default, reservation_registry=registry, owner="first")
    second = build_output_dir_resolver([second_task], default, reservation_registry=registry, owner="second")

    assert first(first_task) == str(tmp_path / "shared")
    assert second(second_task) == str(tmp_path / "shared(1)")
    registry.release("first")
    third = build_output_dir_resolver([first_task], default, reservation_registry=registry, owner="third")
    assert third(first_task) == str(tmp_path / "shared")

