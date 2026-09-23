import json

from sunpack.core.config import cli_settings, loader


def _write_json(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_cli_language_load_uses_raw_payload_without_full_validation(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, {"cli": {"language": "en"}})
    _write_json(simple, {"cli": {"language": "zh"}})

    def candidate_paths(filename):
        return [simple if filename == loader.SIMPLE_CONFIG_FILENAME else advanced]

    monkeypatch.setattr(loader, "_candidate_config_paths", candidate_paths)
    monkeypatch.setattr(
        loader,
        "_validate_pipeline",
        lambda _payload: (_ for _ in ()).throw(AssertionError("language bootstrap must not validate the full config")),
    )
    loader.clear_config_cache()
    try:
        assert cli_settings.load_cli_language_from_config() == "zh"
    finally:
        loader.clear_config_cache()
