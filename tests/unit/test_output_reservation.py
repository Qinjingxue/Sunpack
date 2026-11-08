from tests.helpers.archive_tasks import make_archive_task
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import pytest
from sunpack.core.support.output_reservation import OutputReservationRegistry, build_output_dir_resolver


@pytest.mark.parametrize("child_first", [False, True])
@pytest.mark.parametrize("shared_request", [False, True])
def test_output_subtrees_isolate_jobs_but_allow_owned_recursion(tmp_path, child_first, shared_request):
    # Exact-name collision tests cannot catch parent cleanup deleting another
    # job, or a tree lock incorrectly moving recursive work out of its parent.
    # One small reservation/cleanup lifecycle covers both orders and ownership.
    registry = OutputReservationRegistry()
    parent = str(tmp_path / "out" / "parent")
    child = str(Path(parent) / "child")
    owners = ("parent", "parent" if shared_request else "child")
    paths = [parent, child]
    for index in ((1, 0) if child_first else (0, 1)):
        paths[index] = registry.reserve(paths[index], owners[index])
    roots = [Path(path) for path in paths]
    assert not roots[0].is_relative_to(roots[1]) and not roots[1].is_relative_to(roots[0])
    for root in roots:
        root.mkdir(parents=True)
        (root / "payload").write_text("kept", encoding="utf-8")
    generated = roots[0] / "inner.zip"
    nested = registry.reserve(str(roots[0] / "inner"), owners[0], input_path=str(generated))
    assert Path(nested).parent == roots[0]
    foreign = registry.reserve(str(roots[0] / "foreign"), "foreign", input_path=str(generated))
    assert not Path(foreign).is_relative_to(roots[0])
    with pytest.raises(FileExistsError):
        registry.reserve(str(roots[0] / "continued"), "foreign", reuse_existing=True)
    shutil.rmtree(roots[0])
    assert (roots[1] / "payload").read_text(encoding="utf-8") == "kept"
    for owner in set((*owners, "foreign")):
        registry.release(owner)
    assert not registry.contains(nested)
    assert registry.clear_idle_cache()["slots"] == 0


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
        results = list(executor.map(reserve, range(320)))

    assert {path for path, _ in results} == {
        default, *(str(tmp_path / f"release.v2({index})") for index in range(1, 320)),
    }
    assert {fmt for _, fmt in results} == {"zip", "7z"}
    # executor.map returns results in input order, but reservations acquire
    # the lock in an arbitrary order. Keep whichever owner got the base path.
    base_owner = next(str(index) for index, (path, _) in enumerate(results) if path == default)
    for index in range(320):
        if str(index) != base_owner:
            registry.release(str(index))
    assert registry.reserve(default, "reused") == str(tmp_path / "release.v2(1)")
    registry.release("reused")
    registry.release(base_owner)
    assert registry.reserve(default, "next") == default


def test_evicted_numbering_history_preserves_active_owners_and_reuses_releases(tmp_path, monkeypatch):
    # Small same-family reservations do not exercise live references after LRU
    # eviction. Old numbering hints must disappear even while owners stay live.
    import os
    import sunpack.core.support.output_paths as output_paths
    monkeypatch.setattr(output_paths.os.path, "exists", lambda path: os.path.basename(path) == "archive")
    registry = OutputReservationRegistry()
    base = str(tmp_path / "archive")
    first = registry.reserve(base, "first")
    second = registry.reserve(first, "second")
    third = registry.reserve(base, "third")
    assert (first, second, third) == tuple(str(tmp_path / f"archive({i})") for i in (1, 2, 3))
    for index in range(300):
        registry.reserve(str(tmp_path / str(index) / "archive"), str(index))
    assert len(registry._allocator._slots) == len(registry._allocator._numbers)
    registry.release("second")
    assert registry.reserve(base, "reuse") == second
    registry.release("first")
    registry.release("third")
    registry.release("reuse")
    for index in range(300):
        registry.release(str(index))
    assert registry.reserve(base, "next") == first
