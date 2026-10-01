import subprocess
import zlib
from concurrent.futures import ThreadPoolExecutor

from sunpack_native import output_inventory_from_serialized

from sunpack.pipeline.extraction.output_inventory import OutputInventory


def test_native_manifest_and_inventory_can_be_shared_across_concurrent_matches(tmp_path):
    from sunpack_native import archive_state_zip_manifest_native

    from tests.helpers.tool_config import require_7z

    source = tmp_path / "source"
    source.mkdir()
    names = ["é.txt", "e\u0301.txt", "A.txt", "a-other.txt", "nested.txt"]
    for name in names:
        (source / name).write_text("abc", encoding="utf-8")
    archive = tmp_path / "source.disguised"
    subprocess.run(
        [str(require_7z()), "a", "-tzip", "-mm=Store", "-bso0", "-bsp0", str(archive), "."],
        cwd=source, check=True, capture_output=True,
    )
    manifest = archive_state_zip_manifest_native({"entry_path": str(archive)})
    entries = manifest.entry_page(0, 10)
    inventory = _inventory(
        tmp_path / "absent-output",
        [
            {"index": index, "path": item["path"], "size": item["size"],
             "bytes_written": item["size"], "has_output_crc": True,
             "output_crc32": item["crc32"], "status": "complete"}
            for index, item in enumerate(entries)
        ],
    )

    def match(_):
        return inventory.verification_match(
            manifest, verify_crc=True, include_observations=True, detail_limit=10,
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(match, range(32)))
    assert all(result == results[0] for result in results)
    assert results[0]["coverage"]["complete_files"] == len(names)
    assert results[0]["crc_files_read"] == results[0]["mismatch_count"] == 0
    assert {item["path"] for item in results[0]["observations"]} == set(names)


def _inventory(root, files, *, worker_crc_available=False, worker_inventory_complete=False, identity_paths=False):
    return OutputInventory.from_native(output_inventory_from_serialized(
        str(root), files, True, True, len(files), 0,
        sum(int(item.get("bytes_written", item.get("size", 0)) or 0) for item in files),
        0, worker_crc_available, worker_inventory_complete, identity_paths,
    ))


def test_native_inventory_details_are_paged_without_full_materialization(tmp_path):
    files = [
        {"index": index, "path": f"file-{index}.txt", "size": index + 1}
        for index in range(6)
    ]
    inventory = _inventory(tmp_path, files)

    page = inventory.file_page(offset=2, limit=2)

    assert [item["path"] for item in page] == ["file-2.txt", "file-3.txt"]


def test_native_verification_preserves_rewrite_partial_and_failed_states(tmp_path):
    (tmp_path / "renamed.bin").write_bytes(b"12345")
    (tmp_path / "failed.bin").write_bytes(b"xx")
    inventory = _inventory(tmp_path, [
        {
            "index": 0,
            "path": "original.bin",
            "output_path": "renamed.bin",
            "size": 10,
            "bytes_written": 5,
            "has_crc": True,
            "crc32": 123,
            "status": "unverified",
        },
        {
            "index": 1,
            "path": "failed.bin",
            "size": 2,
            "bytes_written": 2,
            "status": "failed",
        },
    ])

    result = inventory.verification_match(
        [
            {
                "path": "original.bin",
                "output_path": "renamed.bin",
                "size": 10,
                "has_crc": True,
                "crc32": 123,
            },
            {"path": "failed.bin", "size": 2},
        ],
        verify_crc=True,
        include_observations=True,
        detail_limit=8,
    )

    assert result["coverage"]["matched_files"] == 2
    assert result["coverage"]["partial_files"] == 1
    assert result["coverage"]["failed_files"] == 1
    assert result["coverage"]["matched_bytes"] == 7
    assert result["mismatch_count"] == 0
    assert result["crc_files_read"] == 0
    assert [item["state"] for item in result["observations"]] == ["partial", "failed"]
    assert result["observations"][0]["path"] == "renamed.bin"


def test_native_crc_match_reads_only_missing_output_crc_and_not_source_crc(tmp_path):
    payload = b"actual-output"
    path = tmp_path / "payload.bin"
    path.write_bytes(payload)
    expected_crc = zlib.crc32(b"expected-output") & 0xFFFFFFFF
    inventory = _inventory(tmp_path, [{
        "index": 0,
        "path": "payload.bin",
        "size": len(payload),
        "bytes_written": len(payload),
        "has_crc": True,
        "crc32": expected_crc,
        "status": "complete",
    }], worker_crc_available=True)

    result = inventory.verification_match(
        [{
            "path": "payload.bin",
            "size": len(payload),
            "has_crc": True,
            "crc32": expected_crc,
        }],
        verify_crc=True,
        max_issue_items=4,
    )

    assert result["crc_files_read"] == 1
    assert result["used_worker_crc"] is False
    assert result["mismatch_count"] == 1
    assert result["coverage"]["failed_files"] == 1
    assert result["mismatches"][0]["actual_crc32"] == (zlib.crc32(payload) & 0xFFFFFFFF)


def test_native_crc_match_reuses_worker_output_crc_without_reading_file(tmp_path):
    payload = b"worker-verified"
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    inventory = _inventory(tmp_path, [{
        "index": 0,
        "path": "payload.bin",
        "size": len(payload),
        "bytes_written": len(payload),
        "has_crc": True,
        "crc32": crc,
        "has_output_crc": True,
        "output_crc32": crc,
        "crc_ok": True,
        "status": "complete",
    }], worker_crc_available=True, worker_inventory_complete=True, identity_paths=True)

    result = inventory.verification_match(
        [{
            "path": "payload.bin",
            "size": len(payload),
            "has_crc": True,
            "crc32": crc,
        }],
        verify_crc=True,
    )

    assert result["crc_files_read"] == 0
    assert result["used_worker_crc"] is True
    assert result["mismatch_count"] == 0
    assert result["coverage"]["complete_files"] == 1


def test_native_verification_reports_summary_and_one_detail_page(tmp_path):
    files = []
    expected = []
    for index in range(10):
        name = f"item-{index}.bin"
        size = index + 1
        (tmp_path / name).write_bytes(b"x" * size)
        files.append({"index": index, "path": name, "size": size})
        expected.append({"path": name, "size": size})
    inventory = _inventory(tmp_path, files)

    result = inventory.verification_match(
        expected,
        include_observations=True,
        detail_offset=3,
        detail_limit=4,
    )

    assert result["coverage"]["expected_files"] == 10
    assert result["coverage"]["complete_files"] == 10
    assert result["detail_total"] == 10
    assert result["detail_offset"] == 3
    assert result["detail_count"] == 4
    assert result["detail_truncated"] is True
    assert [item["archive_path"] for item in result["observations"]] == [
        "item-3.bin",
        "item-4.bin",
        "item-5.bin",
        "item-6.bin",
    ]
