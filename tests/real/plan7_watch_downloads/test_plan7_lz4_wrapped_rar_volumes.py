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
        tmp_path, f"wrapped-rar-{write_mode}", passwords=[PASSWORD], initial_scan=True,
        cleanup_mode=cleanup_mode, flatten_single_directory=cleanup_mode == "delete",
    )
    try:
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
