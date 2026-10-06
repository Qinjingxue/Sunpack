import pytest

from sunpack.core.config.schema import ConfigSchemaError, normalize_config
from sunpack.runtime.cli.cli_runtime import (
    apply_runtime_config_overrides,
    build_effective_config,
)
from sunpack.runtime.config_validation import validate_config_payload
from tests.helpers.config_factory import make_config


def _payload():
    return {"detection": {"enabled": True}, "verification": {}}


def test_config_validate_checks_embedded_ratio_type():
    payload = _payload()
    payload["embedded_scan"] = {"recursive_candidate_ratio": "many"}
    with pytest.raises(ConfigSchemaError, match="recursive_candidate_ratio"):
        normalize_config(payload)


@pytest.mark.parametrize(("override", "field"), [
    ({"recursive_extract": {"mode": "infinite"}}, "recursive_extract"),
    ({"post_extract": {"archive_cleanup_mode": "recycle"}}, "archive_cleanup_mode"),
    ({"filesystem": {"directory_scan_mode": "recursive"}}, "directory_scan_mode"),
])
def test_normalization_rejects_internal_values_in_external_shorthand_fields(override, field):
    with pytest.raises(ConfigSchemaError, match=field):
        normalize_config({**_payload(), **override})


def test_config_validate_checks_verification_methods_are_registered():
    payload = _payload()
    payload["verification"] = {
        "methods": [
            {"name": "output_presence", "enabled": True},
            {"name": "missing_verification_method", "enabled": False},
        ],
    }

    result = validate_config_payload(normalize_config(payload))

    assert not result["ok"]
    assert "output_presence" in result["available_verification_methods"]
    assert any("Unknown verification method" in error for error in result["errors"])


def test_write_manifest_override_enables_extraction_manifest_files():
    class Args:
        recursive_extract = None
        archive_cleanup_mode = None
        flatten_single_directory = None
        write_progress_manifest = True

    config = {}
    overrides = apply_runtime_config_overrides(config, Args())

    assert overrides["write_progress_manifest"] is True
    assert config["extraction"]["write_progress_manifest"] is True


def test_output_dir_override_is_relative_to_the_request_cwd(tmp_path):
    class Args:
        recursive_extract = None
        archive_cleanup_mode = None
        output_dir = "output"
        flatten_single_directory = None
        write_progress_manifest = False
        allow_partial = False
        directory_passwords = None

    config = {}

    apply_runtime_config_overrides(config, Args(), base_dir=str(tmp_path))

    assert config["output"]["root"] == str(tmp_path / "output")


def test_omitted_output_dir_keeps_default_beside_archive_behavior(tmp_path):
    class Args:
        recursive_extract = None
        archive_cleanup_mode = None
        output_dir = None
        flatten_single_directory = None
        write_progress_manifest = False
        allow_partial = False
        directory_passwords = None

    config = {}
    overrides = apply_runtime_config_overrides(config, Args(), base_dir=str(tmp_path))

    assert "output_dir" not in overrides
    assert "output" not in config or "root" not in config["output"]


def test_effective_config_includes_native_worker_and_format_switch():
    config = _payload()
    config["filesystem"] = {
        "directory_scan_mode": "-",
        "scan_filters": [
            {"name": "size_range", "enabled": True, "gte": 1048576}
        ]
    }
    config["performance"] = {
        "worker": {
            "thread_capacity": 0,
            "minimum_available_memory_ratio": 0.1,
        }
    }

    effective = build_effective_config(make_config(config))

    assert effective["size_range_min_bytes"] == 1048576
    assert effective["filesystem"]["directory_scan_mode"] == "current_dir_only"
    assert effective["worker"]["controller"] == "native_worker"
    assert effective["worker"]["sizing"] == "selected_by_worker"
    assert effective["detection"] == {"enabled": True}
