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


def test_rule_preflight_uses_native_syntax_for_direct_and_persistent_input():
    """GUI persistence tests use a CLI double; only this boundary catches engine
    syntax drift or lost stdin forwarding, with no archive/worker startup cost.
    """
    import io
    import json
    import asyncio
    from types import SimpleNamespace
    from sunpack.runtime.cli.cli_context import CliContext
    from sunpack.runtime.cli.cli_reporter import CliReporter
    from sunpack.runtime.cli.commands import config

    args = SimpleNamespace(config_action="validate", scan_rule_stdin=True)
    for streamed in (False, True):
        for value, regex, valid in (("报告[最终版]+.zip", False, True),
                                    (r"\.(?:zip|7z|rar)\z", True, True),
                                    ("(", False, True), ("(", True, False),
                                    (r"(?<=a)b", True, False)):
            payload = json.dumps({"files": [{"value": value, "regex": regex}]})
            ctx = CliContext(stdin=io.StringIO(payload), reporter=CliReporter(stdout=io.StringIO(), stderr=io.StringIO()))
            if streamed:
                ctx.input_reader = lambda _prompt: payload
            code, result = asyncio.run(config.handle(args, ctx))
            assert (code == 0) is valid
            if not valid:
                assert result.errors


def test_output_dir_override_is_relative_to_the_request_cwd(tmp_path):
    class Args:
        recursive_extract = None
        archive_cleanup_mode = None
        output_dir = "output"
        flatten_single_directory = None
        allow_partial = False

    config = {}

    apply_runtime_config_overrides(config, Args(), base_dir=str(tmp_path))

    assert config["output"]["root"] == str(tmp_path / "output")


def test_omitted_output_dir_keeps_default_beside_archive_behavior(tmp_path):
    class Args:
        recursive_extract = None
        archive_cleanup_mode = None
        output_dir = None
        flatten_single_directory = None
        allow_partial = False

    config = {}
    overrides = apply_runtime_config_overrides(config, Args(), base_dir=str(tmp_path))

    assert "output_dir" not in overrides
    assert "output" not in config or "root" not in config["output"]


def test_effective_config_includes_native_worker_and_format_switch():
    config = _payload()
    config["filesystem"] = {
        "scan_filters": [
            {"name": "size_range", "enabled": True, "min_bytes": 1048576}
        ]
    }
    config["performance"] = {
        "worker": {
            "thread_capacity": 0,
            "memory_reserve_bytes": 268435456,
        }
    }

    effective = build_effective_config(make_config(config))

    assert effective["size_range_min_bytes"] == 1048576
    assert "directory_scan_mode" not in effective["filesystem"]
    assert effective["worker"]["controller"] == "native_worker"
    assert effective["worker"]["sizing"] == "selected_by_worker"
    assert effective["detection"] == {"enabled": True}
