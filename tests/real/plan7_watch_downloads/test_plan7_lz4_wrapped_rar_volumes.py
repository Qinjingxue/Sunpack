from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from tests.helpers.native_fixture import create_lz4_frames, file_inventory
from tests.helpers.real_archives import create_encrypted_rar_archive
from tests.real.plan1_real_archives.plan1_support import assert_expected_files_extracted
from tests.real.plan7_watch_downloads.plan7_support import (
    PASSWORD,
    arrive_interleaved,
    drive_watch_until,
    marker_text_extracted,
    start_watch,
)


@pytest.mark.parametrize("write_mode", ["rename_commit", "direct_final_path"])
@pytest.mark.parametrize("cleanup_mode", ["keep", "delete"])
def test_plan7_four_lz4_wrapped_encrypted_rar_volumes_extract_automatically(
    tmp_path, write_mode, cleanup_mode, plan7_error,
):
    case = create_encrypted_rar_archive(
        tmp_path / "fixtures", "lz4_wrapped_rar", password=PASSWORD,
        header_encrypt=True, split=True,
        split_volume_size=100 * 1024, payload_size=320 * 1024,
    )
    parts = sorted(case.archive_dir.glob("*.rar"))
    assert len(parts) == 4, f"fixture must contain exactly four RAR volumes: {parts}"
    assert parts[0] == case.entry_path
    expected_volumes = file_inventory(case.archive_dir)
    wrappers = tmp_path / "lz4_inputs"
    wrappers.mkdir()
    inputs = []
    for part in parts:
        wrapped = wrappers / f"{part.name}.lz4"
        create_lz4_frames(wrapped, [part])
        inputs.append(wrapped)
    plan7_error.update({
        "write_mode": write_mode,
        "cleanup_mode": cleanup_mode,
        "lz4_inputs": [str(path) for path in inputs],
        "rar_volumes": expected_volumes,
        "expected_files": case.metadata["expected_files"],
    })

    # Only the four outer streams arrive. Inner volumes and their retries must
    # be discovered automatically, using the password supplied before arrival.
    harness = start_watch(
        tmp_path, f"wrapped-rar-{write_mode}", passwords=[PASSWORD],
        cleanup_mode=cleanup_mode, flatten_single_directory=cleanup_mode == "delete",
    )
    try:
        # Inner volumes are promoted by the pipeline, not by the arrival helper;
        # this scenario explicitly needs the real filesystem observer.
        harness.watcher.start()
        arrive_interleaved(harness, list(reversed(inputs)), write_mode=write_mode)
        drive_watch_until(
            harness.watcher,
            lambda: marker_text_extracted(harness.output_root, case.marker_name, case.marker_text),
        )
        assert not harness.watcher.state.entries
        assert_expected_files_extracted(case, harness.output_root)

        # Blocked inputs are promoted to the input root, where Relations groups
        # them again. Keep-source mode retains this complete physical retry set.
        inventory = file_inventory(harness.output_root)
        volume_inventory = file_inventory(harness.watch_root)
        recovered = {}
        for name, expected in expected_volumes.items():
            matches = [
                path for path, actual in volume_inventory.items()
                if Path(path).name == name and actual == expected
            ]
            if cleanup_mode == "keep":
                assert len(matches) == 1, f"missing, corrupt or duplicate volume {name}: {matches}"
                recovered[name] = str(Path(matches[0]).parent)
            else:
                assert not matches, f"successful RAR cleanup retained {name}"
        if cleanup_mode == "keep":
            assert len(set(recovered.values())) == 1, recovered
        else:
            assert not list(harness.watch_root.glob("*.rar*")), "successful cleanup must remove all sources"

        # Each expected member is extracted exactly once, including payload.bin
        # which requires the complete volume set rather than just the head.
        for name in case.metadata["expected_files"]:
            matches = [path for path in inventory if Path(path).name == name]
            assert len(matches) == 1, f"duplicate extracted member {name}: {matches}"
        submissions = Counter(
            Path(path).name
            for event in harness.submission_events for path in event.paths
        )
        assert all(submissions[path.name] == 1 for path in inputs), submissions
        events = (tmp_path / f"wrapped-rar-{write_mode}" / "events.jsonl").read_text(encoding="utf-8")
        assert '"event":"failed_terminal"' not in events
        assert '"event":"error"' not in events
    finally:
        plan7_error["output_files"] = file_inventory(harness.output_root)
        plan7_error["watch_entries"] = repr(harness.watcher.state.entries)
        plan7_error["submission_events"] = [
            {"paths": event.paths, "at": event.at} for event in harness.submission_events
        ]
        harness.close()


def test_plan7_lz4_wrapped_rar_volumes_arriving_in_separate_directories_extract_automatically(
    tmp_path, plan7_error,
):
    """Recursive Watch must regroup split volumes that arrive in different subdirectories.

    A real download can scatter one multi-volume upload across several folders.
    Each outer LZ4 wrapper arrives in its own recursive Watch subdirectory, so
    the inner RAR volumes are only related by name across directories.
    """
    case = create_encrypted_rar_archive(
        tmp_path / "fixtures", "lz4_wrapped_rar_split_dirs", password=PASSWORD,
        header_encrypt=True, split=True,
        split_volume_size=100 * 1024, payload_size=320 * 1024,
    )
    parts = sorted(case.archive_dir.glob("*.rar"))
    assert len(parts) == 4, f"fixture must contain exactly four RAR volumes: {parts}"
    assert parts[0] == case.entry_path
    expected_volumes = file_inventory(case.archive_dir)
    wrappers = tmp_path / "lz4_inputs"
    inputs = []
    for index, part in enumerate(parts):
        directory = wrappers / f"volume_{index}"
        directory.mkdir(parents=True)
        wrapped = directory / f"{part.name}.lz4"
        create_lz4_frames(wrapped, [part])
        inputs.append(wrapped)
    # Reverse the arrival order so the volume head does not arrive first.
    arrival_sources = list(reversed(inputs))
    plan7_error.update({
        "case": "lz4_wrapped_rar_volumes_in_separate_directories",
        "lz4_inputs": [str(path) for path in inputs],
        "rar_volumes": expected_volumes,
        "expected_files": case.metadata["expected_files"],
    })

    harness = start_watch(
        tmp_path, "wrapped-rar-split-dirs", passwords=[PASSWORD], recursive=True,
    )
    try:
        assert next(iter(harness.watcher.root_entries.values())).recursive
        harness.watcher.start()
        arrive_interleaved(
            harness,
            arrival_sources,
            write_mode="rename_commit",
            destination_dirs=[
                harness.watch_root / f"download_{index}"
                for index in range(len(arrival_sources))
            ],
        )
        drive_watch_until(
            harness.watcher,
            lambda: marker_text_extracted(harness.output_root, case.marker_name, case.marker_text),
        )
        assert not harness.watcher.state.entries, {
            path: {
                "status": entry.status,
                "error": entry.last_error,
                "failure": entry.failure_payload,
            }
            for path, entry in harness.watcher.state.entries.items()
        }
        assert_expected_files_extracted(case, harness.output_root)

        # Each inner volume must be regrouped exactly once and the final data
        # must exist exactly once, even though every volume arrived separately.
        volume_inventory = file_inventory(harness.watch_root)
        volume_dirs = set()
        for name in expected_volumes:
            matches = [
                path for path, actual in volume_inventory.items()
                if Path(path).name == name and actual == expected_volumes[name]
            ]
            assert len(matches) == 1, f"missing, corrupt or duplicate volume {name}: {matches}"
            volume_dirs.add(Path(matches[0]).parent)
        assert len(volume_dirs) == len(expected_volumes), (
            f"volumes must stay split across directories: {volume_dirs}"
        )
        inventory = file_inventory(harness.output_root)
        for name in case.metadata["expected_files"]:
            matches = [path for path in inventory if Path(path).name == name]
            assert len(matches) == 1, f"duplicate extracted member {name}: {matches}"
        submissions = Counter(
            Path(path).name
            for event in harness.submission_events for path in event.paths
        )
        assert all(submissions[path.name] == 1 for path in inputs), submissions
        events = (tmp_path / "wrapped-rar-split-dirs" / "events.jsonl").read_text(encoding="utf-8")
        assert '"event":"failed_terminal"' not in events
        assert '"event":"error"' not in events
    finally:
        plan7_error["output_files"] = file_inventory(harness.output_root)
        plan7_error["watch_entries"] = repr(harness.watcher.state.entries)
        plan7_error["submission_events"] = [
            {"paths": event.paths, "at": event.at} for event in harness.submission_events
        ]
        harness.close()
