"""Early failures retain main's input receipts without exposing passwords."""
import json
import zipfile

import pytest


@pytest.mark.parametrize("command", ["scan", "extract"])
def test_password_file_error_preserves_original_paths(package, tmp_path, command):
    archive = tmp_path / "input.zip"
    with zipfile.ZipFile(archive, "w") as payload:
        payload.writestr("member.txt", "payload")
    arguments = [command, archive.name, "--pw-file", "absent.txt", "--json"]
    result = package.run(*arguments, cwd=tmp_path)
    assert result.returncode == 2, (result.stdout, result.stderr)
    receipt = json.loads(result.stdout)
    assert receipt["inputs"] == {"paths": [archive.name]}
    assert receipt["errors"]


@pytest.mark.parametrize("command", ["scan", "extract"])
@pytest.mark.parametrize("password", [False, True])
def test_cold_invalid_runtime_configuration_preserves_safe_argv(package, command, password):
    # No earlier CLI request may prime a last-good normalized configuration.
    package.configure(runtime={"process_mode": 42})
    arguments = [command, "input.zip", "--json"]
    if password:
        arguments.extend(["--password", "not-for-the-error-receipt"])
    result = package.run(*arguments)
    assert result.returncode == 3, (result.stdout, result.stderr)
    receipt = json.loads(result.stdout)
    assert receipt["errors"]
    if password:
        assert "not-for-the-error-receipt" not in result.stdout + result.stderr
        assert receipt["inputs"] == {}
    else:
        assert receipt["inputs"] == {"argv": arguments}


@pytest.mark.parametrize("action", ["show", "validate"])
def test_cold_config_schema_failure_keeps_empty_command_context(package, action):
    package.configure(runtime={"process_mode": 42})
    receipt = package.json("config", action, code=2)
    assert receipt["inputs"] == {}
    assert receipt["summary"] == {}
    assert receipt["items"] == []
    assert receipt["errors"] == [
        "Operation failed: runtime.process_mode must be background, normal, or high",
    ]
