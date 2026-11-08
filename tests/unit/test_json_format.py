from sunpack.core.support.json_format import (
    json_safe,
    load_json_file,
    to_json_text,
)


def test_json_safe_normalizes_cli_payload_values():
    assert json_safe({1: {b"\x01\x02"}, "items": ("a", b"\xff")}) == {
        "1": ["0102"],
        "items": ["a", "ff"],
    }


def test_to_json_text_keeps_unicode_and_supports_compact_mode():
    pretty = to_json_text({"name": "测试"})
    compact = to_json_text({"name": "测试"}, pretty=False)

    assert "测试" in pretty
    assert "\n" in pretty
    assert compact == '{"name": "测试"}'


def test_load_json_file_reads_utf8(tmp_path):
    path = tmp_path / "payload.json"
    path.write_text(to_json_text({"name": "测试"}), encoding="utf-8")
    assert load_json_file(path) == {"name": "测试"}
