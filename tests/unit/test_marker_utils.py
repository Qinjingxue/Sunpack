from sunpack.pipeline.postprocess.internal.blocked_input import promote_blocked_input
from tests.helpers import marker_utils


def test_marker_polling_allows_live_output_promotion(tmp_path, monkeypatch):
    marker = "已完成\n"
    opened = []
    original_open = marker_utils._open_marker_text
    destination = tmp_path / "promoted"
    destination.mkdir()

    def promote_while_reading(path):
        reader = original_open(path)
        try:
            moved = promote_blocked_input([str(path)], str(destination))
            assert moved.path_map and not path.exists()
            # The observation's handle must permit deletion as well as rename.
            (destination / path.name).unlink()
        except BaseException:
            reader.close()
            raise
        opened.append(reader)
        return reader

    monkeypatch.setattr(marker_utils, "_open_marker_text", promote_while_reading)
    # Both named markers and stream outputs with changed names retain exact
    # content checks. A pending binary volume must never obstruct publication.
    for name, payload, expected in (
        ("marker.txt", marker.encode(), "found"),
        ("renamed.bin", marker.encode(), "found"),
        ("part2.rar", b"Rar!\xff" * 20000, "missing"),
        ("extra.txt", (marker + "extra").encode(), "missing"),
    ):
        root = tmp_path / name
        root.mkdir()
        (root / name).write_bytes(payload)
        assert marker_utils.marker_scan_state(root, "marker.txt", marker) == expected
        assert opened[-1].closed
    assert marker_utils.marker_scan_state(tmp_path / "absent", "marker.txt", marker) == "missing"
