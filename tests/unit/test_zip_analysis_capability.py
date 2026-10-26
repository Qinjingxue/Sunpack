import struct
import zipfile

from sunpack_native import AnalysisBinaryView, inspect_zip_directory_consistency, inspect_zip_structure_graph

from sunpack.core.analysis import ArchiveAnalyzer


def _zip_path(tmp_path):
    path = tmp_path / "archive.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.txt", "payload")
    return path


def test_zip_capabilities_preserve_detection_and_graph_payloads(tmp_path):
    path = _zip_path(tmp_path)

    local = dict(AnalysisBinaryView(str(path)).probe_zip_local_header(0))
    report = ArchiveAnalyzer().analyze(str(path))
    eocd = next(item for item in report.evidences if item.format == "zip").details
    consistency = dict(inspect_zip_directory_consistency(str(path), 128))
    graph = dict(inspect_zip_structure_graph(str(path), 128))

    assert local["plausible"] is True
    assert local["compression_method"] == 8
    assert eocd["plausible"] is True
    assert eocd["central_directory_walk_ok"] is True
    assert eocd["local_header_links_ok"] is True
    assert eocd["boundary_confidence"] == "high"
    assert report.best_selected.format == "zip"
    assert consistency["error"] == ""
    assert consistency["cd_parseable"] is True
    assert {"nodes", "edges", "violations", "relation_violations", "explanations", "summary"} <= graph.keys()


def test_zip_local_header_uses_supported_method_table(tmp_path):
    path = tmp_path / "unknown-method.zip"
    name = b"a"
    path.write_bytes(struct.pack(
        "<4sHHHHHIIIHH",
        b"PK\x03\x04",
        20,
        0,
        50,
        0,
        0,
        0,
        0,
        0,
        len(name),
        0,
    ) + name)

    raw = dict(AnalysisBinaryView(str(path)).probe_zip_local_header(0))

    assert raw["magic_matched"] is True
    assert raw["plausible"] is False
    assert raw["compression_method"] == 50
    assert raw["error"] == "unknown_compression_method"


def test_large_directory_analysis_does_not_retain_the_walk_in_shared_cache(tmp_path):
    # Small ZIPs cannot expose retaining every visited block across inputs.
    # This covers the unbounded lifetime, without requiring host memory pressure.
    from concurrent.futures import ThreadPoolExecutor
    from sunpack_native import reader_cache_stats

    paths = [tmp_path / f"{index}.zip" for index in range(4)]
    with zipfile.ZipFile(paths[0], "w") as archive:
        for index in range(12000):
            archive.writestr(f"entry-{index:06d}", b"")
    body = paths[0].read_bytes()
    for path in paths[1:]:
        path.write_bytes(body)
    def retained_bytes():
        stats = reader_cache_stats()
        return stats["hot_cache_bytes"] + stats["general_cache_bytes"]
    before = retained_bytes()
    def inspect_directory(path):
        view = AnalysisBinaryView(str(path))
        try:
            return view.probe_zip(len(body) - 22)
        finally:
            view.close()
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(inspect_directory, paths))
    assert all(result["plausible"] for result in results)
    assert all(result["central_directory_entries_checked"] == 12000 for result in results)
    assert retained_bytes() - before < len(body)
    # Diagnostic presentation limits do not truncate the full directory count.
    details = inspect_zip_directory_consistency(str(paths[0]), 3)
    assert details["cd_entries_parseable"] == 12000
    assert details["cd_entries_checked"] == 3
