import pytest

from sunpack.cli.cli_runtime import (
    apply_runtime_config_overrides,
    build_effective_config,
)
from sunpack.config.config_validator import validate_config_payload
from tests.helpers.detection_config import with_detection_pipeline


def _payload():
    return with_detection_pipeline(
        precheck=[{"name": "embedded_payload_identity", "enabled": True}],
    )


def test_config_validate_checks_rule_schema_types_even_when_disabled():
    payload = _payload()
    payload["detection"]["rule_pipeline"]["precheck"][0]["enabled"] = False
    payload["detection"]["rule_pipeline"]["precheck"][0]["deep_scan_single_candidate_ratio"] = "many"

    result = validate_config_payload(payload)

    assert not result["ok"]
    assert any("Invalid type" in error for error in result["errors"])


def test_config_validate_rejects_obsolete_cumulative_deep_scan_ratio():
    payload = _payload()
    payload["detection"]["rule_pipeline"]["precheck"][0]["deep_scan_size_coverage_ratio"] = 0.5

    result = validate_config_payload(payload)

    assert not result["ok"]
    assert any("deep_scan_size_coverage_ratio" in error for error in result["errors"])


def test_config_validate_rejects_normalized_config_values_in_external_shorthand_fields():
    payload = _payload()
    payload["recursive_extract"] = {"mode": "infinite", "max_rounds": 999}
    payload["post_extract"] = {"archive_cleanup_mode": "recycle"}
    payload["filesystem"] = {"directory_scan_mode": "recursive", "scan_filters": []}

    result = validate_config_payload(payload)

    assert not result["ok"]
    assert any("recursive_extract must" in error for error in result["errors"])
    assert any("archive_cleanup_mode must" in error for error in result["errors"])
    assert any("directory_scan_mode must" in error for error in result["errors"])


def test_config_validate_checks_verification_methods_are_registered():
    payload = _payload()
    payload["verification"] = {
        "methods": [
            {"name": "output_presence", "enabled": True},
            {"name": "missing_verification_method", "enabled": False},
        ],
    }

    result = validate_config_payload(payload)

    assert not result["ok"]
    assert "output_presence" in result["available_verification_methods"]
    assert any("Unknown verification method" in error for error in result["errors"])


def test_config_validate_rejects_removed_worker_profile():
    payload = _payload()
    payload["performance"] = {"worker": {"profile": "auto"}}

    result = validate_config_payload(payload)

    assert not result["ok"]
    assert any("performance.worker.profile was removed" in error for error in result["errors"])


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


def test_effective_config_includes_native_worker_and_rule_pipeline():
    config = _payload()
    config["filesystem"] = {
        "directory_scan_mode": "-",
        "scan_filters": [
            {"name": "size_range", "enabled": True, "gte": 1048576}
        ]
    }
    config["performance"] = {"worker": {"thread_capacity": 0, "initial_active_jobs": 0}}

    effective = build_effective_config(config)

    assert effective["size_range_min_bytes"] == 1048576
    assert effective["filesystem"]["directory_scan_mode"] == "current_dir_only"
    assert effective["worker"]["controller"] == "native_worker"
    assert effective["worker"]["sizing"] == "selected_by_worker"
    assert effective["detection"]["rule_pipeline"]["precheck"][0]["name"] == "embedded_payload_identity"
