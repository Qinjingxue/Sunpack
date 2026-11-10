import pytest

from sunpack_native import output_inventory_from_serialized

from sunpack.pipeline.extraction.output_inventory import OutputInventory
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
    # Paging tests construct inventories directly. They cannot detect a
    # summary incorrectly bypassing the output scan with incomplete rows.
    from sunpack.pipeline.extraction.output_inventory import collect_output_inventory

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
    assert [row["path"] for row in inventory.file_page()] == (
        [f"reported-{index}.txt" for index in range(len(statuses))]
        if complete else ["actual.txt"]
    )


def _inventory(root, files, *, worker_inventory_complete=False, identity_paths=False):
    return OutputInventory.from_native(output_inventory_from_serialized(
        str(root), files, True, True, len(files), 0,
        sum(int(item.get("bytes_written", item.get("size", 0)) or 0) for item in files),
        0, worker_inventory_complete, identity_paths,
    ))


def test_native_inventory_details_are_paged_without_full_materialization(tmp_path):
    files = [
        {"index": index, "path": f"file-{index}.txt", "size": index + 1}
        for index in range(6)
    ]
    inventory = _inventory(tmp_path, files)

    page = inventory.file_page(offset=2, limit=2)

    assert [item["path"] for item in page] == ["file-2.txt", "file-3.txt"]
