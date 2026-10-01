import base64
import subprocess

import pytest
from sunpack_native import AnalysisBinaryView, AnalysisMultiVolumeView


@pytest.fixture
def signature_paths(tmp_path):
    data = bytearray(b"x" * 128)
    for offset, signature in [(5, b"PK\x03\x04"), (60, b"7z\xbc\xaf\x27\x1c"),
                              (100, b"\x1f\x8b\x08"), (119, b"Rar!\x1a\x07\x01\x00")]:
        data[offset:offset + len(signature)] = signature
    paths = [tmp_path / "disguised.bin", tmp_path / "first.any", tmp_path / "second.any"]
    statements = ["$ErrorActionPreference='Stop'"]
    for path, content in zip(paths, [data, data[:62], data[62:]]):
        literal = str(path).replace("'", "''")
        encoded = base64.b64encode(content).decode("ascii")
        statements.append(f"[IO.File]::WriteAllBytes('{literal}',[Convert]::FromBase64String('{encoded}'))")
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ";".join(statements)],
                   check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    return list(map(str, paths))


@pytest.mark.parametrize("head,tail,offsets", [
    (32, 16, [5, 119]), (80, 80, [5, 60, 100, 119]),
    (64, 64, [5, 60, 100, 119]), (0, 0, []), (20, 0, [5]),
])
def test_single_and_split_prepass_agree_on_ranges_and_cross_volume_signatures(signature_paths, head, tail, offsets):
    single = AnalysisBinaryView(signature_paths[0], cache_bytes=0)
    split = AnalysisMultiVolumeView(signature_paths[1:], cache_bytes=0)
    try:
        actual = single.signature_prepass(head, tail)
        assert actual == split.signature_prepass(head, tail)
        assert [hit["offset"] for hit in actual["hits"]] == offsets
        assert actual["head_bytes"] == min(head, 128)
        assert actual["tail_bytes"] == min(tail, 128)
        expected_reads = 128 if head + tail >= 128 else head + tail
        assert single.stats()["read_bytes"] == split.stats()["read_bytes"] == expected_reads
    finally:
        single.close()
        split.close()


@pytest.mark.parametrize("multivolume", [False, True])
def test_prepass_preserves_read_budget_errors_and_closed_view_contract(signature_paths, multivolume):
    view = (AnalysisMultiVolumeView(signature_paths[1:], cache_bytes=0, max_read_bytes=16)
            if multivolume else AnalysisBinaryView(signature_paths[0], cache_bytes=0, max_read_bytes=16))
    try:
        with pytest.raises(RuntimeError, match="read budget exceeded"):
            view.signature_prepass(32, 16)
    finally:
        view.close()
    with pytest.raises(RuntimeError, match="closed"):
        view.signature_prepass(0, 0)
