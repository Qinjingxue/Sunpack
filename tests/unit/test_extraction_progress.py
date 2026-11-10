from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
from sunpack.pipeline.extraction.progress import (
    build_extraction_progress_manifest,
    iter_progress_files,
)
from tests.helpers.worker_events import worker_result, worker_trace_item


def _trace_result(items, **fields):
    return worker_result(
        trace_items=[worker_trace_item(**item) for item in items],
        **fields,
    )


def test_progress_manifest_preserves_archive_path_and_numbered_output_path(tmp_path):
    manifest = build_extraction_progress_manifest(
        archive=str(tmp_path / "source.zip"),
        output_inventory=collect_output_inventory(str(tmp_path / "out")),
        diagnostics={"result": _trace_result([{
            "path": "report.txt",
            "output_path": "report(1).txt",
            "bytes_written": 6,
            "expected_size": 6,
        }], status="ok")},
    )

    [item] = manifest.file_page(0, 10)
    assert item["archive_path"] == "report.txt"
    assert item["path"] == str(tmp_path / "out" / "report(1).txt")
    assert item["status"] == "complete"


def test_progress_manifest_classifies_trace_items_and_skips_directories(tmp_path):
    out_dir = tmp_path / "out"
    manifest = build_extraction_progress_manifest(
        archive="a.7z",
        output_inventory=collect_output_inventory(str(out_dir)),
        diagnostics={"result": _trace_result([
            {"path": "dir", "is_dir": True},
            {"path": "dir/ok.bin", "bytes_written": 4, "expected_size": 4},
            {"path": "dir/cut.bin", "bytes_written": 2, "expected_size": 8, "failed": True},
            {"path": "dir/none.bin", "bytes_written": 0, "expected_size": 8, "failed": True},
            {"path": "pending.bin", "done": False},
            {"path": "unfinished.bin", "bytes_written": 3, "done": False},
            {"path": "bad-result.bin", "operation_result": 2},
        ], status="failed", failure_kind="checksum_error")},
    )

    assert manifest.summary == {"complete": 1, "partial": 2, "failed": 2, "skipped": 0, "unverified": 1, "total": 6}
    assert manifest.failure_kind == "checksum_error"
    assert manifest.partial_outputs is True
    assert manifest.files_written == 3
    assert manifest.bytes_written == 9
    assert [item["archive_path"] for item in iter_progress_files(manifest, page_size=1)] == [
        "dir/ok.bin", "dir/cut.bin", "dir/none.bin", "pending.bin", "unfinished.bin", "bad-result.bin",
    ]


def test_progress_manifest_from_worker_rows_keeps_complete_bytes_written(tmp_path):
    result = worker_result(
        status="failed",
        manifest_rows=[
            [0, "done.bin", "", 5, 5, 1, 7, 1, 7, 1, 1, 0, 0, b""],
            [1, "cut.bin", "", 9, 4, 1, 7, 0, 0, 0, 2, 0, 0, b""],
        ],
        verified_manifest={"inventory": [0, 2, 0, 14, 1]},
    )
    manifest = build_extraction_progress_manifest(
        archive=str(tmp_path / "source.zip"),
        output_inventory=collect_output_inventory(str(tmp_path / "out")),
        diagnostics={"result": result},
    )

    by_archive_path = {item["archive_path"]: item for item in iter_progress_files(manifest)}
    assert by_archive_path["done.bin"]["status"] == "complete"
    assert by_archive_path["done.bin"]["bytes_written"] == 5
    assert by_archive_path["cut.bin"]["status"] == "failed"
    assert by_archive_path["cut.bin"]["bytes_written"] == 4
    assert manifest.bytes_written == 9


def test_progress_manifest_adds_untraced_output_files(tmp_path):
    out_dir = tmp_path / "out"
    (out_dir / ".sunpack").mkdir(parents=True)
    (out_dir / "traced.txt").write_bytes(b"abc")
    (out_dir / ".sunpack" / "extraction_manifest.json").write_bytes(b"hello")
    inventory = collect_output_inventory(str(out_dir))
    # A new scan would see different sizes. The manifest uses the inventory
    # that was already captured for downstream verification.
    (out_dir / ".sunpack" / "extraction_manifest.json").write_bytes(b"changed after snapshot")

    manifest = build_extraction_progress_manifest(
        archive="a.zip",
        output_inventory=inventory,
        diagnostics={"result": _trace_result(
            [{"path": "traced.txt", "bytes_written": 3, "expected_size": 3}],
            status="failed",
        )},
    )

    by_archive_path = {item["archive_path"]: item for item in iter_progress_files(manifest)}
    assert set(by_archive_path) == {"traced.txt", ".sunpack/extraction_manifest.json"}
    extra = by_archive_path[".sunpack/extraction_manifest.json"]
    assert extra["status"] == "unverified"
    assert extra["bytes_written"] == 5
    assert extra["path"] == str(out_dir / ".sunpack" / "extraction_manifest.json")
    assert "not reported" in extra["message"]


def test_complete_worker_inventory_uses_summary_only_manifest(tmp_path):
    result = worker_result(
        status="ok",
        bytes_written=6,
        manifest_rows=[
            [0, "a.txt", "", 3, 3, 1, 7, 1, 7, 1, 1, 0, 0, b""],
            [1, "b.txt", "", 3, 3, 1, 7, 1, 7, 1, 1, 0, 0, b""],
        ],
        verified_manifest={"validated": True, "inventory": [1, 2, 0, 6, 1]},
    )

    manifest = build_extraction_progress_manifest(
        archive="a.zip",
        output_inventory=collect_output_inventory(str(tmp_path / "out"), result),
        diagnostics={"result": result},
    )

    assert len(manifest) == 0
    assert manifest.summary["total"] == 2
    assert manifest.files_written == 2
    assert manifest.bytes_written == 6
