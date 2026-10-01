from pathlib import Path

from sunpack_native import scan_watch_candidates, watch_candidate_for_path


def test_native_watch_scan_preserves_rows_and_recursion_policy(tmp_path):
    (tmp_path / "nested").mkdir()
    first = tmp_path / "a.disguised"
    second = tmp_path / "nested" / "b.part"
    first.write_text("first", encoding="utf-8")
    second.write_text("second", encoding="utf-8")
    empty = tmp_path / "empty"
    empty.touch()

    shallow = scan_watch_candidates([str(tmp_path)], False)
    recursive = scan_watch_candidates([str(tmp_path), str(tmp_path / "missing")], True)
    assert [Path(row["path"]).name for row in shallow] == [first.name]
    assert {Path(row["path"]).name for row in recursive} == {first.name, second.name}
    assert [row["path"] for row in recursive] == sorted(row["path"] for row in recursive)
    assert scan_watch_candidates([str(first)], False) == shallow
    for row in recursive:
        assert row == watch_candidate_for_path(row["path"])
        assert row["file_id"] and row["change_usn"] > 0 and row["mtime"] > 0
        assert set(row) == {"path", "size", "mtime", "file_id", "change_usn", "change_reasons",
                            "change_reasons_without_close", "change_reasons_known", "change_reason_error"}
    assert watch_candidate_for_path(str(empty)) is None
    assert watch_candidate_for_path(str(tmp_path)) is None
    assert watch_candidate_for_path(str(tmp_path / "missing")) is None
