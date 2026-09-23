from pathlib import Path

from sunpack.coordinator.task_scan import direct_file_task
from sunpack.coordinator.target_scan import build_candidates_for_targets


def test_selected_directory_and_file_inside_it_are_deduped(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\0" * 18)

    candidates = build_candidates_for_targets([str(tmp_path), str(archive)])

    matching = [candidate for candidate in candidates if candidate.entry_path == str(archive)]
    assert len(matching) == 1


def test_selected_split_member_without_structural_proof_stays_single_candidate(tmp_path):
    first = tmp_path / "payload.7z.001"
    second = tmp_path / "payload.7z.002"
    first.write_bytes(b"7z\xbc\xaf\x27\x1c")
    second.write_bytes(b"part")

    candidates = build_candidates_for_targets([str(second)])

    assert len(candidates) == 1
    assert candidates[0].entry_path == str(second)
    assert candidates[0].member_paths == (str(second),)
    assert candidates[0].relation_kind == "file"
    assert candidates[0].entry_path == str(second)
    assert candidates[0].member_paths == (str(second),)


def test_direct_file_task_preserves_explicit_zero_based_split_volumes(tmp_path):
    parts = [
        tmp_path / "payload.zip.0000",
        tmp_path / "payload.zip.0001",
        tmp_path / "payload.zip.0002",
    ]
    for index, part in enumerate(parts):
        part.write_bytes(f"part-{index}".encode())

    task = direct_file_task(str(parts[0]), all_parts=[str(part) for part in parts])
    assert task.main_path == str(parts[0])
    assert task.all_parts == [str(part) for part in parts]
    assert task.split_info.is_split
