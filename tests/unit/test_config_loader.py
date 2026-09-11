import json
from pathlib import Path

import pytest

from sunpack.config import loader
from sunpack.detection.scheduler import DetectionScheduler


def _write_json(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


def _verification_config():
    return {
        "enabled": True, "max_retries": 2, "cleanup_failed_output": True,
        "complete_accept_threshold": 0.999, "partial_accept_threshold": 0.2,
        "retry_on_verification_failure": True,
        "methods": [{"name": "extraction_exit_signal", "enabled": True}, {"name": "output_presence", "enabled": True}],
    }


def _layered_config_paths(simple, advanced):
    def candidate_paths(filename):
        return [simple if filename == loader.SIMPLE_CONFIG_FILENAME else advanced]
    return candidate_paths


def _prepared_precheck_config(config, name):
    scheduler = DetectionScheduler(config)
    for rule in scheduler.rule_manager._prepare_rules("precheck"):
        if rule.name == name:
            return rule.config
    return None


def _advanced_payload(precheck=None):
    return {
        "cli": {"language": "en"},
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
        "recursive_extract": "*",
        "post_extract": {"archive_cleanup_mode": "r", "flatten_single_directory": True},
        "filesystem": {"directory_scan_mode": "*", "scan_filters_enabled": True, "scan_filters": []},
        "performance": {"worker": {"initial_active_jobs": 0, "watchdog_no_progress_timeout_seconds": 180}},
        "verification": _verification_config(),
        "detection": {
            "enabled": True,
            "fact_collectors": [{"name": "file_facts", "enabled": True}],
            "processors": [],
            "rule_pipeline": {
                "precheck": precheck or [],
                "scoring": [{"name": "zip_structure_identity", "enabled": True}],
            },
        },
    }


def test_load_config_merges_simple_config_over_advanced_config(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    payload = _advanced_payload()
    payload["filesystem"]["scan_filters"] = [{"name": "size_range", "enabled": True, "range": "r >= 1 MB"}]
    _write_json(advanced, payload)
    _write_json(simple, {
        "cli": {"language": "zh"},
        "filesystem": {"scan_filters": [{"name": "size_range", "enabled": True, "range": "r >= 2 MB"}]},
        "performance": {"worker": {"initial_active_jobs": 3}},
    })
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))
    config = loader.load_config()
    assert config["cli"]["language"] == "zh"
    assert config["filesystem"]["directory_scan_mode"] == "recursive"
    assert config["filesystem"]["scan_filters"][0]["range"] == "r >= 2 MB"
    assert config["performance"]["worker"]["watchdog_no_progress_timeout_seconds"] == 180
    assert config["performance"]["worker"]["initial_active_jobs"] == 3


def test_load_config_uses_explicit_request_cwd(tmp_path, monkeypatch):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    _write_json(first_root / "sunpack_advanced_config.json", _advanced_payload())
    _write_json(second_root / "sunpack_advanced_config.json", _advanced_payload())
    _write_json(first_root / "sunpack_config.json", {"cli": {"language": "zh"}})
    _write_json(second_root / "sunpack_config.json", {"cli": {"language": "en"}})

    monkeypatch.setattr(
        loader,
        "candidate_resource_paths",
        lambda filename, request_cwd=None: [Path(request_cwd) / filename],
    )
    loader.clear_config_cache()
    try:
        assert loader.load_config(first_root)["cli"]["language"] == "zh"
        assert loader.load_config(second_root)["cli"]["language"] == "en"
        assert loader.config_source_key(first_root) != loader.config_source_key(second_root)
    finally:
        loader.clear_config_cache()


def test_load_config_requires_external_verification_config(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    payload = _advanced_payload()
    payload.pop("verification")
    _write_json(advanced, payload)
    _write_json(simple, {})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))
    with pytest.raises(loader.ConfigError, match="verification"):
        loader.load_effective_config_payload()


def test_config_loaders_validate_external_schema_once(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, _advanced_payload())
    _write_json(simple, {})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))

    original_validate = loader.validate_external_config
    calls = []

    def counted_validate(payload):
        calls.append(payload)
        return original_validate(payload)

    monkeypatch.setattr(loader, "validate_external_config", counted_validate)
    try:
        for load in (loader.load_config, loader.load_effective_config_payload):
            loader.clear_config_cache()
            calls.clear()
            load()
            assert len(calls) == 1
    finally:
        loader.clear_config_cache()


def test_effective_config_payload_returns_merged_external_config(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, _advanced_payload())
    _write_json(simple, {"recursive_extract": "2"})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))
    path, payload = loader.load_effective_config_payload()
    assert path == simple
    assert payload["recursive_extract"] == "2"
    assert payload["filesystem"]["directory_scan_mode"] == "*"


def test_embedded_single_candidate_ratio_simple_config_overrides_advanced(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, _advanced_payload([{
        "name": "embedded_payload_identity", "enabled": True,
        "deep_scan_single_candidate_ratio": 0.3,
    }]))
    _write_json(simple, {"detection": {"rule_pipeline": {"precheck": [{
        "name": "embedded_payload_identity", "deep_scan_single_candidate_ratio": 0.8,
    }]}}})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))
    prepared = _prepared_precheck_config(loader.load_config(), "embedded_payload_identity")
    assert prepared["deep_scan_single_candidate_ratio"] == 0.8


def test_obsolete_embedded_scan_configuration_is_rejected():
    config = _advanced_payload([{
        "name": "embedded_payload_identity", "enabled": True,
        "embedded_payload_scan_level": "deep",
    }])
    with pytest.raises(ValueError, match="embedded_payload_scan_level"):
        _prepared_precheck_config(config, "embedded_payload_identity")


def test_removed_analysis_full_scan_configuration_is_rejected(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    payload = _advanced_payload()
    payload.setdefault("analysis", {})["prepass"] = {
        "enabled": True,
        "head_bytes": 1024,
        "tail_bytes": 1024,
        "deep_scan": True,
    }
    _write_json(advanced, payload)
    _write_json(simple, {})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))

    with pytest.raises(loader.ConfigError, match="Removed analysis.prepass fields: deep_scan"):
        loader.load_config()


def test_load_config_applies_inline_env_override_last(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, _advanced_payload())
    _write_json(simple, {
        "filesystem": {"scan_filters": [
            {"name": "size_range", "enabled": True, "range": "r >= 2 MB"},
            {"name": "blacklist", "enabled": True, "blocked_extensions": [".tmp"]},
        ]},
    })
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))
    monkeypatch.setenv(loader.OVERRIDES_ENV_VAR, json.dumps({
        "filesystem": {"scan_filters": [{"name": "size_range", "enabled": False}]},
    }))

    config = loader.load_config()
    filters = {item["name"]: item for item in config["filesystem"]["scan_filters"]}

    assert filters["size_range"]["enabled"] is False
    assert filters["size_range"]["range"] == "r >= 2 MB"
    assert filters["blacklist"]["enabled"] is True


def test_load_config_applies_override_file_last(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, _advanced_payload())
    _write_json(simple, {})
    override_path = tmp_path / "override.json"
    _write_json(override_path, {"recursive_extract": "1"})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))
    monkeypatch.setenv(loader.OVERRIDES_ENV_VAR, str(override_path))

    _path, config = loader.load_raw_config_payload()

    assert config["recursive_extract"] == "1"


def test_load_config_rejects_invalid_override_payload(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, _advanced_payload())
    _write_json(simple, {})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))

    monkeypatch.setenv(loader.OVERRIDES_ENV_VAR, "{not json")
    with pytest.raises(loader.ConfigError, match="invalid JSON"):
        loader.load_config()

    monkeypatch.setenv(loader.OVERRIDES_ENV_VAR, json.dumps([1, 2]))
    with pytest.raises(loader.ConfigError, match="must contain a JSON object"):
        loader.load_config()

    monkeypatch.setenv(loader.OVERRIDES_ENV_VAR, str(tmp_path / "missing-override.json"))
    with pytest.raises(loader.ConfigError, match="inline JSON object or an existing JSON file"):
        loader.load_config()


def test_load_config_rejects_unknown_override_section(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, _advanced_payload())
    _write_json(simple, {})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))
    monkeypatch.setenv(loader.OVERRIDES_ENV_VAR, json.dumps({"filsystem": {"scan_filters": []}}))

    with pytest.raises(loader.ConfigError, match="unknown config sections: filsystem"):
        loader.load_config()


def test_changing_override_invalidates_config_cache(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    _write_json(advanced, _advanced_payload())
    _write_json(simple, {})
    monkeypatch.setattr(loader, "_candidate_config_paths", _layered_config_paths(simple, advanced))

    monkeypatch.setenv(loader.OVERRIDES_ENV_VAR, json.dumps({"recursive_extract": "1"}))
    assert loader.load_raw_config_payload()[1]["recursive_extract"] == "1"

    monkeypatch.setenv(loader.OVERRIDES_ENV_VAR, json.dumps({"recursive_extract": "2"}))
    assert loader.load_raw_config_payload()[1]["recursive_extract"] == "2"
