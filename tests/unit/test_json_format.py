from sunpack.core.support.json_format import (
    json_safe,
    load_json_file,
    parse_jsonish,
    to_json_text,
    write_json_file,
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


def test_write_and_load_json_file_use_project_format(tmp_path):
    path = tmp_path / "nested" / "payload.json"

    write_json_file(path, {"name": "测试"})

    assert path.read_text(encoding="utf-8").endswith("\n")
    assert load_json_file(path) == {"name": "测试"}


def test_parse_jsonish_falls_back_to_raw_string():
    assert parse_jsonish('["a", 1]') == ["a", 1]
    assert parse_jsonish("plain-text") == "plain-text"
