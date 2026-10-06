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
    assert "schema_version" not in consistency
    assert "schema_version" not in graph
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
