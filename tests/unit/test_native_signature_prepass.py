from io import BytesIO
import zipfile

import pytest
from sunpack_native import AnalysisBinaryView, AnalysisMultiVolumeView


@pytest.fixture
def signature_paths(tmp_path):
    # A standard signature crossing a physical volume boundary must still
    # be at the logical origin. Interior signatures are payload.
    data = b"7z\xbc\xaf\x27\x1c" + b"x" * 54 + b"PK\x03\x04\x1f\x8b\x08Rar!\x1a\x07\x01\x00"
    paths = [tmp_path / "disguised.bin", tmp_path / "first.any", tmp_path / "second.any"]
    for path, content in zip(paths, [data, data[:3], data[3:]]):
        path.write_bytes(content)
    return list(map(str, paths))


def test_standard_prepass_reuses_logical_origin_across_volumes(signature_paths):
    single = AnalysisBinaryView(signature_paths[0], cache_bytes=0)
    split = AnalysisMultiVolumeView(signature_paths[1:], cache_bytes=0)
    try:
        actual = single.signature_prepass()
        assert actual == split.signature_prepass()
        assert [(hit["name"], hit["offset"]) for hit in actual["hits"]] == [("7z", 0)]
        assert actual["tail_bytes"] == 0
        assert single.stats()["read_bytes"] == split.stats()["read_bytes"] == 32
    finally:
        single.close()
        split.close()


@pytest.mark.parametrize("marker", [b"", b"PK00", b"PK\x07\x08"])
def test_standard_zip_prepass_handles_maximum_comment_without_scanning_comment_signatures(tmp_path, marker):
    # A maximum comment puts the real EOCD at the exact search limit;
    # embedded-looking bytes in the comment must remain data.
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("entry", b"7z\xbc\xaf\x27\x1c")
        archive.comment = b"Rar!\x1a\x07\x01\x00" + b"x" * (65535 - 8)
    path = tmp_path / "standard.any"
    data = marker + stream.getvalue()
    path.write_bytes(data)
    view = AnalysisBinaryView(str(path), cache_bytes=0)
    try:
        result = view.signature_prepass()
        assert list(result["formats"]) == ["zip"]
        assert [(hit["name"], hit["offset"]) for hit in result["hits"]] == [
            ("zip_local", len(marker)), ("zip_eocd", len(data) - 65557),
        ]
        assert result["tail_bytes"] == 65557
    finally:
        view.close()
    # An unknown origin does not search for the ZIP inside its carrier.
    path.write_bytes(b"x" * 600 + stream.getvalue() + b"suffix")
    view = AnalysisBinaryView(str(path), cache_bytes=0)
    try:
        result = view.signature_prepass()
        assert list(result["hits"]) == []
        assert result["head_bytes"] == 512 and result["tail_bytes"] == 0
    finally:
        view.close()


@pytest.mark.parametrize("multivolume", [False, True])
def test_analysis_operations_preserve_closed_view_contract(signature_paths, multivolume):
    view = (AnalysisMultiVolumeView(signature_paths[1:], cache_bytes=0)
            if multivolume else AnalysisBinaryView(signature_paths[0], cache_bytes=0))
    try:
        view.signature_prepass()
    finally:
        view.close()
    for operation, args in (
        (view.signature_prepass, ()),
        (view.read_at, (0, 0)),
        (view.read_tail, (0,)),
        (view.stats, ()),
        (view.locate_zip_eocd, (0,)),
        (view.probe_zip_local_header, (0,)),
        (view.probe_zip, (0,)),
        (view.probe_rar, (0,)),
        (view.probe_seven_zip, (0,)),
    ):
        with pytest.raises(RuntimeError, match="closed"):
            operation(*args)
