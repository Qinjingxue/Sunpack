import pytest

from sunpack.pipeline.coordinator.target_scan import build_candidates_for_targets
from sunpack.pipeline.coordinator.task_scan import direct_file_task
from tests.helpers.config_factory import make_config
from tests.helpers.real_archives import ArchiveFixtureFactory


def test_selected_directory_and_file_inside_it_are_deduped(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\0" * 18)

    candidates = build_candidates_for_targets([str(tmp_path), str(archive)], config=make_config())

    matching = [candidate for candidate in candidates if candidate.entry_path == str(archive)]
    assert len(matching) == 1


def test_selected_split_member_without_structural_proof_stays_single_candidate(tmp_path):
    first = tmp_path / "payload.7z.001"
    second = tmp_path / "payload.7z.002"
    first.write_bytes(b"7z\xbc\xaf\x27\x1c")
    second.write_bytes(b"part")

    candidates = build_candidates_for_targets([str(second)], config=make_config())

    assert len(candidates) == 1
    assert candidates[0].entry_path == str(second)
    assert candidates[0].archive_input.part_paths() == [str(second)]
    assert candidates[0].is_split is False
    assert candidates[0].entry_path == str(second)
    assert candidates[0].archive_input.part_paths() == [str(second)]


def test_direct_file_task_preserves_explicit_zero_based_split_volumes(tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path, "payload", "zip", split=True,
        payload_size=4 * 1024, split_volume_size=1024,
    )
    parts = [source.replace(case.archive_dir / f"payload.zip.{index:04d}")
        for index, source in enumerate(sorted(case.archive_dir.iterdir()))]
    assert len(parts) > 1

    task = direct_file_task(str(parts[0]), all_parts=[str(part) for part in parts])
    assert task.main_path == str(parts[0])
    assert task.all_parts == [str(part) for part in parts]
    assert task.archive_input().open_mode == "native_volumes"


def test_explicit_multi_volume_input_requires_structure_not_only_names(tmp_path):
    parts = [tmp_path / f"payload.zip.{index:04d}" for index in range(3)]
    for part in parts:
        part.write_text("unrelated data", encoding="utf-8")
    with pytest.raises(ValueError, match="represented structurally"):
        direct_file_task(str(parts[0]), all_parts=[str(part) for part in parts])
