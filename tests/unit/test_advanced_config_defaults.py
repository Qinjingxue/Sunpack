import json
from pathlib import Path

from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.core.config.schema import config_fields, get_config_value


ROOT = Path(__file__).resolve().parents[2]


def _advanced_config() -> dict:
    return json.loads((ROOT / "sunpack_advanced_config.json").read_text(encoding="utf-8"))


def test_registered_config_defaults_are_sourced_from_advanced_config():
    payload = _advanced_config()
    for field in config_fields().values():
        if field.default is not None:
            assert field.default == get_config_value(payload, field.path)


def test_detection_config_has_only_a_master_switch():
    assert _advanced_config()["detection"] == {"enabled": True}


def test_advanced_default_values_are_returned_as_independent_copies():
    first = advanced_config_value(("watch",))
    second = advanced_config_value(("watch",))
    first["roots"].append("changed")
    assert second["roots"] == []
