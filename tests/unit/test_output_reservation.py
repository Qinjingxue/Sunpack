from tests.helpers.archive_tasks import make_archive_task
from concurrent.futures import ThreadPoolExecutor
from sunpack.core.support.output_paths import next_available_path
from sunpack.core.support.output_reservation import OutputReservationRegistry, build_output_dir_resolver


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


def test_concurrent_formats_share_numbered_directory_family(tmp_path):
    registry = OutputReservationRegistry()
    default = str(tmp_path / "release.v2")

    def reserve(index):
        fmt = "zip" if index % 2 else "7z"
        task = make_archive_task(tmp_path / f"release.v2.{fmt}", logical_name="release.v2", format_hint=fmt)
        resolver = build_output_dir_resolver(
            [task], lambda _task: default, reservation_registry=registry, owner=str(index),
        )
        return resolver(task), task.archive_input().format_hint

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(reserve, range(32)))

    assert {path for path, _ in results} == {
        default, *(str(tmp_path / f"release.v2({index})") for index in range(1, 32)),
    }
    assert {fmt for _, fmt in results} == {"zip", "7z"}
    for index in range(32):
        registry.release(str(index))
    assert registry.reserve(default, "next", set()) == default
