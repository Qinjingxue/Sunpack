from pathlib import Path

from sunpack.coordinator.task_scan import _group_explicit_split_paths, direct_file_task
from sunpack.coordinator.target_scan import build_fact_bags_for_targets


def test_selected_directory_and_file_inside_it_are_deduped(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\0" * 18)

    bags = build_fact_bags_for_targets([str(tmp_path), str(archive)])

    matching = [bag for bag in bags if bag.get("file.path") == str(archive)]
    assert len(matching) == 1


def test_selected_split_member_without_structural_proof_stays_single_candidate(tmp_path):
    first = tmp_path / "payload.7z.001"
    second = tmp_path / "payload.7z.002"
    first.write_bytes(b"7z\xbc\xaf\x27\x1c")
    second.write_bytes(b"part")

    bags = build_fact_bags_for_targets([str(second)])

    assert len(bags) == 1
    assert bags[0].get("file.path") == str(second)
    assert (bags[0].get("file.split_members") or []) == []
    assert bags[0].get("candidate.kind") == "file"
    assert bags[0].get("candidate.entry_path") == str(second)
    assert bags[0].get("candidate.member_paths") == [str(second)]


def test_direct_file_arguments_group_explicit_zero_based_split_volumes_without_directory_scan(tmp_path):
    parts = [
        tmp_path / "payload.zip.0000",
        tmp_path / "payload.zip.0001",
        tmp_path / "payload.zip.0002",
    ]
    for index, part in enumerate(parts):
        part.write_bytes(f"part-{index}".encode())

    grouped = _group_explicit_split_paths([str(parts[2]), str(parts[0]), str(parts[1])])

    assert grouped == [[str(parts[0]), str(parts[1]), str(parts[2])]]
    task = direct_file_task(grouped[0][0], all_parts=grouped[0])
    assert task.main_path == str(parts[0])
    assert task.all_parts == [str(part) for part in parts]
    assert task.split_info.is_split
