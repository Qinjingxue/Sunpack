import json
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

    # main's explicit validator compiles path rules only; unknown filters fail
    # when actually selected by discovery, not during configuration inspection.
    assert package.json("config", "validate")["items"][0]["ok"]
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


def test_password_text_sources_preserve_nul_candidates(package, tmp_path):
    passwords = tmp_path / "passwords.txt"
    passwords.write_bytes(b"before\nbad\x00candidate\nafter\n")
    result = package.json("passwords", "--no-bpw", "-p", "good", "-P", passwords)
    assert result["items"][0]["combined_passwords"] == [
        "good", "before", "bad\x00candidate", "after",
    ]
    interactive = package.run("passwords", "--no-bpw", "-a", input="bad\x00candidate\n\n")
    assert interactive.returncode == 0, interactive.stderr
    assert "bad\x00candidate" in interactive.stdout


def test_enabled_invalid_regex_only_blocks_filtered_scans_and_reports_all_rules(package, tmp_path):
    package.configure(filesystem={"scan_filters": [
        {"name": name, "enabled": enabled,
         "full_names": [{"value": "[", "regex": True}]}
        for name, enabled in [("blacklist", True), ("whitelist", False)]
    ]})
    assert package.json("config", "show")["items"]
    assert package.json("passwords", "--no-bpw", "-p", "good")["items"][0]["combined_passwords"] == ["good"]
    validation = package.json("config", "validate", code=2)
    errors = validation["items"][0]["errors"]
    assert len(errors) == 2
    assert all(f"filesystem.scan_filters[{index}]" in error for index, error in enumerate(errors))
    source = tmp_path / "source"
    source.mkdir()
    with zipfile.ZipFile(source / "input.zip", "w") as payload:
        payload.writestr("member.txt", "payload")
    assert package.json("scan", "-d", source)["summary"]["archive_count"] == 1
    result = package.run("scan", source, "--json")
    assert result.returncode != 0


def test_deep_extract_defers_bad_filters_until_recursive_output_scan(package, tmp_path):
    package.configure(filesystem={"scan_filters": [{
        "name": "blacklist", "enabled": True,
        "full_names": [{"value": "[", "regex": True}],
    }]})
    # Neither an empty initial scan nor a first-level failure reaches normal
    # recursive discovery. Both must remain independent of scan-rule syntax.
    source = tmp_path / "empty"
    source.mkdir()
    empty = package.json("extract", "-d", "-r", "1", source)
    assert not empty["errors"]
    broken = source / "broken.zip"
    broken.write_bytes(b"PK\x03\x04broken")
    failed = package.run("extract", "-d", "-r", "1", source, "--json")
    assert "regex" not in failed.stdout + failed.stderr
    with zipfile.ZipFile(source / "valid.zip", "w") as payload:
        payload.writestr("member.txt", "payload")
    recursive = package.run("extract", "-d", "-r", "1", source, "--json")
    assert recursive.returncode != 0
    assert "regex" in recursive.stdout + recursive.stderr
