import pytest

from tests.helpers.worker_events import worker_result


@pytest.mark.parametrize("statuses, declared_complete, declared_count, complete", [
    ([1, 1], True, 2, True),
    ([], True, 0, True),
    ([1, 0], True, 2, False),
    ([1, 2], True, 2, False),
    ([1, 1], False, 2, False),
    ([1, 1], True, 3, False),
])
def test_worker_inventory_completeness_controls_scan_reuse(
    tmp_path, statuses, declared_complete, declared_count, complete,
):
    # Summary-only tests cannot detect bypassing the output scan with
    # incomplete rows. Check the snapshot consumed by recursive discovery.
    from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
    from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner

    (tmp_path / "actual.txt").write_text("actual", encoding="utf-8")
    result = worker_result(
        status="ok",
        manifest_rows=[
            [index, f"reported-{index}.txt", "", 3, 3, 0, 0, 0, 0, 0, status, 0, 0, b""]
            for index, status in enumerate(statuses)
        ],
        verified_manifest={
            "validated": True,
            "inventory": [int(declared_complete), declared_count, 0, len(statuses) * 3, 0],
        },
    )
    native = result["verified_manifest"]["native_rows"]

    inventory = collect_output_inventory(str(tmp_path), result)
    assert native.complete is complete
    assert inventory.worker_inventory_complete is complete
    assert native.to_output_inventory(str(tmp_path)).worker_inventory_complete is complete
    snapshot = DirectoryScanner.snapshot_from_output_inventory(
        inventory, scan_options=DirectoryScanner.compile_scan_options(),
    )
    paths, _, _ = snapshot.raw_native_snapshot.file_columns()
    assert [path.rsplit("\\", 1)[-1] for path in paths] == (
        [f"reported-{index}.txt" for index in range(len(statuses))]
        if complete else ["actual.txt"]
    )
