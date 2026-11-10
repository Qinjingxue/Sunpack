import pytest

from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
from sunpack.pipeline.extraction.progress import build_extraction_progress_manifest
from tests.helpers.worker_events import worker_result, worker_trace_item


@pytest.mark.parametrize("source", ["trace", "rows"])
@pytest.mark.parametrize("worker_ok", [False, True])
def test_progress_pages_preserve_duplicates_and_untraced_suffix(tmp_path, source, worker_ok):
    """The native row-storage split must not change pages, counts, or row fields."""
    out_dir = tmp_path / "out"
    (out_dir / "dir").mkdir(parents=True)
    (out_dir / "dir" / "traced.bin").write_bytes(b"abc")
    (out_dir / "untraced.bin").write_bytes(b"extra")
    result = worker_result(
        status="ok" if worker_ok else "failed",
        failure_stage="item_extract",
        failure_kind="checksum_error",
        manifest_rows=[
            [0, "first.bin", "dir/./traced.bin", 3, 3, 1, 7, 1, 7, 1, 1, 0, 0, b""],
            [1, "second.bin", "dir/traced.bin", 5, 1, 1, 7, 0, 0, 0, 2, 0, 0, b""],
        ],
        verified_manifest={"inventory": [0, 2, 0, 8, 0]},
        trace_items=[
            worker_trace_item(path="first.bin", output_path="dir/./traced.bin", bytes_written=3, expected_size=3),
            worker_trace_item(path="second.bin", output_path="dir/traced.bin", bytes_written=1, expected_size=5, failed=True),
        ] if source == "trace" else [],
    )
    manifest = build_extraction_progress_manifest(
        archive="source.zip",
        output_inventory=collect_output_inventory(str(out_dir)),
        diagnostics={"result": result},
    )

    rows = manifest.file_page()
    expected = [
        dict(path=str(out_dir / "dir" / "traced.bin"), archive_path="first.bin", status="complete",
             bytes_written=3, expected_size=3, progress=1.0, crc_ok=None if source == "trace" else True,
             failure_stage="", failure_kind="", message=""),
        dict(path=str(out_dir / "dir" / "traced.bin"), archive_path="second.bin",
             status="partial" if source == "trace" else "failed", bytes_written=1, expected_size=5,
             progress=0.2, crc_ok=None if source == "trace" else False,
             failure_stage="", failure_kind="", message=""),
        dict(path=str(out_dir / "untraced.bin"), archive_path="untraced.bin",
             status="complete" if worker_ok else "unverified", bytes_written=5, expected_size=None,
             progress=1.0 if worker_ok else None, crc_ok=None, failure_stage="", failure_kind="",
             message="file was present after extraction but was not reported by worker output trace"),
    ]
    assert rows == expected
    assert len(manifest) == 3
    assert manifest.file_page(0, 1) == expected[:1]
    assert manifest.file_page(1, 2) == expected[1:]
    assert manifest.file_page(2, 100) == expected[2:]
    assert manifest.file_page(3, 100) == []
    assert manifest.file_page(0, 0) == []
    assert manifest.summary == {
        "complete": 1 + worker_ok, "partial": int(source == "trace"),
        "failed": int(source == "rows"), "unverified": int(not worker_ok), "skipped": 0, "total": 3,
    }
    assert manifest.files_written == 1 + worker_ok + (source == "trace")
    assert manifest.bytes_written == 9
    assert manifest.failure_stage == "item_extract"
    assert manifest.failure_kind == "checksum_error"
