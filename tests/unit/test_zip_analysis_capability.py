import struct
import zipfile

from sunpack.core.analysis import ArchiveAnalyzer, ZipDeepProbeOptions, ZipEocdProbeOptions


def _zip_path(tmp_path):
    path = tmp_path / "archive.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.txt", "payload")
    return path


def test_public_zip_capabilities_preserve_detection_and_graph_payloads(tmp_path):
    path = _zip_path(tmp_path)
    analyzer = ArchiveAnalyzer()

    local = analyzer.probe_zip_local_header(str(path)).to_raw_dict()
    eocd = analyzer.probe_zip_eocd(
        str(path),
        ZipEocdProbeOptions(max_cd_entries_to_walk=16),
    ).to_raw_dict()
    consistency = analyzer.probe_zip_directory_consistency(
        str(path),
        ZipDeepProbeOptions(max_entries=128),
    ).to_raw_dict()
    graph = analyzer.probe_zip_structure_graph(
        str(path),
        ZipDeepProbeOptions(max_entries=128),
    ).to_raw_dict()

    assert local["plausible"] is True
    assert local["compression_method"] == 8
    assert eocd["plausible"] is True
    assert eocd["central_directory_walk_ok"] is True
    assert eocd["local_header_links_ok"] is True
    assert consistency["error"] == ""
    assert consistency["cd_parseable"] is True
    assert {"nodes", "edges", "violations", "relation_violations", "explanations", "summary"} <= graph.keys()


def test_public_zip_local_header_uses_supported_method_table(tmp_path):
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

    raw = ArchiveAnalyzer().probe_zip_local_header(str(path)).to_raw_dict()

    assert raw["magic_matched"] is True
    assert raw["plausible"] is False
    assert raw["compression_method"] == 50
    assert raw["error"] == "unknown_compression_method"
