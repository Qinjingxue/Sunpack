import json
import shutil
import zipfile

import pytest


@pytest.mark.parametrize("name", ["blacklist", "whitelist"])
def test_doctor_validates_disabled_regex_without_disabling_runtime(package, tmp_path, name):
    # Existing malformed-config tests cannot distinguish runtime parsing from
    # explicit validation: those configurations are invalid in both modes.
    rule = {"name": name, "enabled": False,
            "full_names": [{"value": "[", "regex": False}]}
    package.configure(filesystem={"scan_filters": [rule]})
    before = json.loads(package.run("doctor", "--json").stdout)
    assert next(row for row in before["items"] if row["name"] == "config")["status"] == "ok"

    rule["full_names"][0]["regex"] = True
    package.configure(filesystem={"scan_filters": [rule]})
    validation = package.json("config", "validate", code=2)
    assert validation["errors"]
    doctor = package.json("doctor", code=1)
    config_check = next(row for row in doctor["items"] if row["name"] == "config")
    assert config_check["status"] == "fail"
    assert config_check["detail"]

    source = tmp_path / "source"
    source.mkdir()
    archive = source / "input.zip"
    with zipfile.ZipFile(archive, "w") as payload:
        payload.writestr("member.txt", "payload")
    assert package.json("scan", source)["summary"]["archive_count"] == 1
    assert package.json("extract", source)["summary"]["success_count"] == 1


def test_malformed_performance_tuning_keeps_pipeline_available(package, tmp_path):
    package.configure(performance={
        "persistent_server_idle_seconds": "invalid",
        "worker": {
            "space_poll_interval_ms": [],
            "space_status_report_interval_ms": "invalid",
        },
    })
    assert package.json("config", "validate")["items"][0]["ok"]

    archive = tmp_path / "input.zip"
    with zipfile.ZipFile(archive, "w") as payload:
        payload.writestr("member.txt", "payload")
    assert package.json("extract", archive)["summary"]["success_count"] == 1


def test_unknown_active_scan_filter_does_not_widen_discovery(package, tmp_path):
    package.configure(filesystem={
        "scan_filters": [{"name": "unrecognized_filter", "enabled": True}],
    })
    source = tmp_path / "source"
    source.mkdir()
    archive = source / "input.zip"
    with zipfile.ZipFile(archive, "w") as payload:
        payload.writestr("member.txt", "payload")

    validation = package.json("config", "validate", code=2)
    assert "unrecognized_filter" in str(validation["errors"])
    result = package.run("extract", source, "--json")
    assert result.returncode != 0
    assert "unrecognized_filter" in result.stdout + result.stderr
    assert not (source / "input").exists()
    assert package.json("scan", "--deep-detect", source)["summary"]["archive_count"] == 1


def test_unreadable_builtin_password_source_does_not_abort_request(package):
    path = package.data / "builtin_passwords.json"
    path.unlink()
    path.mkdir()

    result = package.json("passwords", "-p", "explicit")
    assert result["items"][0]["combined_passwords"] == ["explicit"]
    assert path.is_dir()


def test_unreadable_simple_config_cannot_fall_back_to_advanced_config(package):
    path = package.data / "sunpack_config.json"
    path.unlink()
    path.mkdir()

    assert package.json("config", "validate", code=2)["errors"]


def test_password_file_cannot_authenticate_a_truncated_candidate(package, repo_root, tmp_path):
    encrypted = tmp_path / "cipher.enc"
    shutil.copyfile(repo_root / "tests" / "data" / "enc_parallel" / "algorithm_0.enc", encrypted)
    passwords = tmp_path / "passwords.txt"
    passwords.write_bytes(b"sunpack-test\x00different\n")

    result = package.json("extract", "--no-bpw", "--pw-file", passwords, encrypted, code=2)
    assert "NUL" in str(result["errors"])
    assert not (tmp_path / "cipher").exists()
