from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.rename.scheduler import OutputReservationRegistry, RenameScheduler
from sunpack.rename.conflicts import next_available_path
from sunpack.coordinator.task_scan import direct_file_task


def test_detected_extensions_do_not_rename_source_files(tmp_path):
    split_first = tmp_path / "disguised.part1.rar.001"
    split_second = tmp_path / "disguised.part2.rar.002"
    fake_doc = tmp_path / "fake_doc.txt"
    split_first.touch()
    split_second.touch()
    fake_doc.touch()

    split_bag = FactBag()
    split_bag.set("file.path", str(split_first))
    split_bag.set("file.detected_ext", ".rar")
    split_bag.set("file.split_role", "first")

    single_bag = FactBag()
    single_bag.set("file.path", str(fake_doc))
    single_bag.set("file.detected_ext", ".zip")

    tasks = [
        direct_file_task(str(split_first), all_parts=[str(split_first), str(split_second)]),
        ArchiveTask(fact_bag=single_bag, main_path=str(fake_doc), all_parts=[str(fake_doc)]),
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

    bag = FactBag()
    bag.set("file.path", str(carrier))
    bag.set("file.detected_ext", ".rar")
    bag.set("file.embedded_archive_found", True)
    bag.set("embedded_archive.analysis", {"found": True, "detected_ext": ".rar", "offset": 128})

    task = ArchiveTask(fact_bag=bag, main_path=str(carrier), all_parts=[str(carrier)])
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

    first = ArchiveTask(fact_bag=FactBag(), main_path=str(seven_zip), logical_name="collision")
    second = ArchiveTask(fact_bag=FactBag(), main_path=str(zip_file), logical_name="collision")

    def default_output_dir(task):
        return str(tmp_path / task.logical_name)

    resolver = RenameScheduler().build_output_dir_resolver([first, second], default_output_dir)

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
    task = ArchiveTask(fact_bag=FactBag(), main_path=str(archive), logical_name="photos")

    resolver = RenameScheduler().build_output_dir_resolver([task], lambda item: str(tmp_path / item.logical_name))

    assert resolver(task) == str(tmp_path / "photos(2)")


def test_output_reservations_disambiguate_concurrent_requests_before_directories_exist(tmp_path):
    registry = OutputReservationRegistry()
    first_task = ArchiveTask(fact_bag=FactBag(), main_path=str(tmp_path / "a.zip"))
    second_task = ArchiveTask(fact_bag=FactBag(), main_path=str(tmp_path / "b.zip"))
    default = lambda _task: str(tmp_path / "shared")

    first = RenameScheduler(registry, "first").build_output_dir_resolver([first_task], default)
    second = RenameScheduler(registry, "second").build_output_dir_resolver([second_task], default)

    assert first(first_task) == str(tmp_path / "shared")
    assert second(second_task) == str(tmp_path / "shared(1)")
    registry.release("first")
    third = RenameScheduler(registry, "third").build_output_dir_resolver([first_task], default)
    assert third(first_task) == str(tmp_path / "shared")

