import json

from sunpack.pipeline.extraction.progress import build_extraction_progress_manifest, filter_extraction_manifest_payload, filter_extraction_outputs


def test_progress_manifest_preserves_archive_path_and_numbered_output_path(tmp_path):
    manifest = build_extraction_progress_manifest(
        archive=str(tmp_path / "source.zip"),
        out_dir=str(tmp_path / "out"),
        diagnostics={
            "result": {
                "status": "ok",
                "diagnostics": {
                    "output_trace": {
                        "items": [{
                            "path": "report.txt",
                            "output_path": "report(1).txt",
                            "bytes_written": 6,
                            "expected_size": 6,
                        }],
                    },
                },
            },
        },
    )

    item = manifest["files"][0]
    assert item["archive_path"] == "report.txt"
    assert item["path"] == str(tmp_path / "out" / "report(1).txt")


def test_filter_extraction_outputs_discards_incomplete_when_complete_exists(tmp_path):
    good = tmp_path / "good.txt"
    partial = tmp_path / "partial.bin"
    failed = tmp_path / "failed.bin"
    good.write_text("good", encoding="utf-8")
    partial.write_bytes(b"part")
    failed.write_bytes(b"")
    manifest = _write_manifest(tmp_path, [
        {"path": str(good), "archive_path": "good.txt", "status": "complete", "bytes_written": 4},
        {"path": str(partial), "archive_path": "partial.bin", "status": "partial", "bytes_written": 4},
        {"path": str(failed), "archive_path": "failed.bin", "status": "failed", "bytes_written": 0},
    ])

    updated = filter_extraction_outputs(str(manifest))

    assert good.exists()
    assert not partial.exists()
    assert not failed.exists()
    assert [item["archive_path"] for item in updated["files"]] == ["good.txt"]
    assert len(updated["discarded_files"]) == 2


def test_filter_extraction_outputs_keeps_best_partial_without_complete(tmp_path):
    best = tmp_path / "same-best.bin"
    worse = tmp_path / "same-worse.bin"
    tiny = tmp_path / "tiny.bin"
    best.write_bytes(b"x" * 100)
    worse.write_bytes(b"x" * 50)
    tiny.write_bytes(b"x" * 5)
    manifest = _write_manifest(tmp_path, [
        {"path": str(best), "archive_path": "same.bin", "status": "partial", "bytes_written": 100},
        {"path": str(worse), "archive_path": "same.bin", "status": "partial", "bytes_written": 50},
        {"path": str(tiny), "archive_path": "tiny.bin", "status": "partial", "bytes_written": 5},
    ])

    updated = filter_extraction_outputs(str(manifest), partial_keep_ratio=0.2)

    assert best.exists()
    assert not worse.exists()
    assert not tiny.exists()
    assert [item["path"] for item in updated["files"]] == [str(best)]
    assert updated["files"][0]["retention"] == "kept_best_partial"


def test_filter_extraction_manifest_payload_does_not_require_manifest_file(tmp_path):
    good = tmp_path / "good.txt"
    partial = tmp_path / "partial.bin"
    good.write_text("good", encoding="utf-8")
    partial.write_bytes(b"part")
    manifest = {
        "files": [
            {"path": str(good), "archive_path": "good.txt", "status": "complete", "bytes_written": 4},
            {"path": str(partial), "archive_path": "partial.bin", "status": "partial", "bytes_written": 4},
        ]
    }

    updated = filter_extraction_manifest_payload(manifest)

    assert good.exists()
    assert not partial.exists()
    assert [item["archive_path"] for item in updated["files"]] == ["good.txt"]


def _write_manifest(tmp_path, files):
    manifest = tmp_path / ".sunpack" / "extraction_manifest.json"
    manifest.parent.mkdir()
    manifest.write_text(json.dumps({"files": files}, ensure_ascii=False), encoding="utf-8")
    return manifest
