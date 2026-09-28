import json

from sunpack_native import load_progress_manifest, worker_manifest_from_rows

from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import parse_worker_json_line
from sunpack.pipeline.extraction.progress import (
    build_extraction_progress_manifest,
    iter_progress_files,
    write_extraction_progress_manifest_payload,
)


def _trace_result(items, **fields):
    return parse_worker_json_line(json.dumps({
        "type": "result",
        **fields,
        "diagnostics": {"output_trace": {"items": items}},
    }))


def test_progress_manifest_preserves_archive_path_and_numbered_output_path(tmp_path):
    manifest = build_extraction_progress_manifest(
        archive=str(tmp_path / "source.zip"),
        out_dir=str(tmp_path / "out"),
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
        out_dir=str(out_dir),
        diagnostics={"result": _trace_result([
            {"path": "dir", "is_dir": True},
            {"path": "dir/ok.bin", "bytes_written": 4, "expected_size": 4},
            {"path": "dir/cut.bin", "bytes_written": 2, "expected_size": 8, "failed": True},
            {"path": "dir/none.bin", "bytes_written": 0, "expected_size": 8, "failed": True},
        ], status="failed", failure_kind="checksum_error")},
    )

    assert manifest.summary == {"complete": 1, "partial": 1, "failed": 1, "skipped": 0, "unverified": 0, "total": 3}
    assert manifest.failure_kind == "checksum_error"
    assert manifest.partial_outputs is True
    assert manifest.files_written == 2
    assert manifest.bytes_written == 6
    assert round(manifest.completeness(), 6) == round((1 + 0.25 + 0) / 3, 6)
    coverage = manifest.coverage()
    assert coverage["expected_bytes"] == 20
    assert coverage["matched_bytes"] == 6
    assert coverage["matched_files"] == 2
    assert [item["archive_path"] for item in iter_progress_files(manifest, page_size=1)] == [
        "dir/ok.bin", "dir/cut.bin", "dir/none.bin",
    ]


def test_progress_manifest_from_worker_rows_keeps_complete_bytes_written(tmp_path):
    rows = worker_manifest_from_rows(
        [
            [0, "done.bin", "", 5, 5, 1, 7, 1, 7, 1, 1, 0, 0, ""],
            [1, "cut.bin", "", 9, 4, 1, 7, 0, 0, 0, 2, 0, 0, ""],
        ],
        False, 2, 0, 14, True,
    )
    manifest = build_extraction_progress_manifest(
        archive=str(tmp_path / "source.zip"),
        out_dir=str(tmp_path / "out"),
        diagnostics={"result": {"status": "failed", "verified_manifest": {"native_rows": rows}}},
    )

    by_archive_path = {item["archive_path"]: item for item in iter_progress_files(manifest)}
    assert by_archive_path["done.bin"]["status"] == "complete"
    assert by_archive_path["done.bin"]["bytes_written"] == 5
    assert by_archive_path["cut.bin"]["status"] == "failed"
    assert by_archive_path["cut.bin"]["bytes_written"] == 4
    assert manifest.bytes_written == 9


def test_progress_manifest_adds_untraced_output_files(tmp_path):
    out_dir = tmp_path / "out"
    (out_dir / "sub").mkdir(parents=True)
    (out_dir / "traced.txt").write_bytes(b"abc")
    (out_dir / "sub" / "extra.txt").write_bytes(b"hello")

    manifest = build_extraction_progress_manifest(
        archive="a.zip",
        out_dir=str(out_dir),
        diagnostics={"result": _trace_result(
            [{"path": "traced.txt", "bytes_written": 3, "expected_size": 3}],
            status="failed",
        )},
    )

    by_archive_path = {item["archive_path"]: item for item in iter_progress_files(manifest)}
    assert set(by_archive_path) == {"traced.txt", "sub/extra.txt"}
    extra = by_archive_path["sub/extra.txt"]
    assert extra["status"] == "unverified"
    assert extra["bytes_written"] == 5
    assert extra["path"] == str(out_dir / "sub" / "extra.txt")
    assert "not reported" in extra["message"]


def test_progress_manifest_file_round_trips_through_rust(tmp_path):
    out_dir = tmp_path / "out"
    path, manifest = write_extraction_progress_manifest_payload(
        archive="a.zip",
        out_dir=str(out_dir),
        diagnostics={"result": _trace_result(
            [{"path": "雪.txt", "bytes_written": 1, "expected_size": 2, "failed": True}],
            status="failed",
        )},
        write_file=True,
    )

    payload = json.loads((out_dir / ".sunpack" / "extraction_manifest.json").read_text(encoding="utf-8"))
    assert path == str(out_dir / ".sunpack" / "extraction_manifest.json")
    assert payload["version"] == 1
    assert payload["summary"]["partial"] == 1
    assert payload["files"][0]["archive_path"] == "雪.txt"
    loaded = load_progress_manifest(path)
    assert loaded.summary == manifest.summary
    assert loaded.file_page(0, 1) == manifest.file_page(0, 1)
    assert load_progress_manifest(str(tmp_path / "missing.json")) is None


def test_complete_worker_inventory_uses_summary_only_manifest(tmp_path):
    result = parse_worker_json_line(json.dumps({
        "type": "result",
        "status": "ok",
        "bytes_written": 6,
        "verified_manifest": {
            "version": 3,
            "validated": True,
            "inventory": [1, 2, 0, 6, 1],
            "rows": [
                [0, "a.txt", "", 3, 3, 1, 7, 1, 7, 1, 1, 0, 0, ""],
                [1, "b.txt", "", 3, 3, 1, 7, 1, 7, 1, 1, 0, 0, ""],
            ],
        },
    }))

    path, manifest = write_extraction_progress_manifest_payload(
        archive="a.zip",
        out_dir=str(tmp_path / "out"),
        diagnostics={"result": result},
    )

    assert path == ""
    assert len(manifest) == 0
    assert manifest.summary["total"] == 2
    assert manifest.files_written == 2
    assert manifest.bytes_written == 6
    assert manifest.completeness() == 1.0
