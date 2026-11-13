import json
import subprocess
import zipfile
from contextlib import nullcontext

import pytest

from tests.helpers.marker_utils import open_shared_file


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
    assert config_check["errors"] == validation["items"][0]["errors"]
    assert config_check["detail"] == "; ".join(config_check["errors"])
    assert config_check["config_path"] == str(package.data / "sunpack_config.json")

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


def test_scan_rule_validation_reads_complete_redirected_json(package):
    command = ("config", "validate", "--scan-rule-stdin", "--json")
    payload = json.dumps({"files": [{"value": "sample", "regex": False}]}, indent=2)
    result = package.run(*command, input=payload)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert json.loads(result.stdout)["summary"]["valid"]
    invalid = package.run(*command, input=payload + "\n{}")
    assert invalid.returncode == 2
    assert json.loads(invalid.stdout)["errors"]


def test_password_text_sources_preserve_nul_candidates(package, tmp_path):
    passwords = tmp_path / "passwords.txt"
    passwords.write_bytes(b"before\nbad\x00candidate\nafter\n")
    result = package.json("passwords", "--no-bpw", "-p", "good", "-P", passwords)
    assert result["items"][0]["combined_passwords"] == [
        "good", "before", "bad\x00candidate", "after",
    ]
    interactive = package.run("passwords", "--no-bpw", "-a", input="bad\x00candidate\n\n")
    assert interactive.returncode == 0, interactive.stderr
    assert "bad\\x00candidate" in interactive.stdout


def test_rejected_password_candidate_keeps_resolution_details(package, tmp_path):
    (tmp_path / "secret.txt").write_bytes(b"secret")
    archive = tmp_path / "locked.7z"
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", "-pfixture-secret",
         str(archive), "secret.txt"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    result = package.json("extract", "--no-bpw", "-p", "wrong", archive, code=1)
    failure, = result["tasks"][0]["failures"]
    assert (failure["kind"], failure["stage"]) == ("wrong_password", "password_resolution")
    assert failure["details"]["diagnostic"] == ""
    assert failure["details"]["read_error"] is None


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
    # Main counts the initial extraction as round 1; round 2 admits nested scans.
    recursive = package.run("extract", "-d", "-r", "2", source, "--json")
    assert recursive.returncode != 0
    assert "regex" in recursive.stdout + recursive.stderr


@pytest.mark.parametrize("operation", ["scan", "extract"])
@pytest.mark.parametrize("failure", ["config", "worker", "worker_start", "password_file"])
def test_archive_infrastructure_failures_keep_main_exit_classification(package, tmp_path, operation, failure):
    archive = tmp_path / "input.zip"
    with zipfile.ZipFile(archive, "w") as payload:
        payload.writestr("member.txt", "payload")
    args = [operation, archive]
    lock = nullcontext()
    if failure == "config":
        # No previous normalized snapshot exists in this fresh runtime.
        path = package.data / "sunpack_config.json"
        path.unlink()
        path.mkdir()
        code = 3
    elif failure in {"worker", "worker_start"}:
        worker = package.launcher.parent.parent / "tools" / "sunpack_sevenzip_worker.exe"
        if failure == "worker_start":
            # Lock a private copy so launching the valid PE fails without
            # showing Windows' unsupported application dialog.
            executable = worker.read_bytes()
            worker.unlink()
            worker.write_bytes(executable)
            lock = open_shared_file(worker, "rb", share=0)
        else:
            worker.unlink()
        code = 1
    else:
        args += ["-P", tmp_path / "absent-passwords.txt"]
        code = 2
    with lock:
        result = package.run(*args, "--json")
    assert result.returncode == code, (result.stdout, result.stderr)
    assert json.loads(result.stdout)["errors"]


def test_show_validates_runtime_fields_but_preserves_raw_values(package):
    package.configure(recursive_extract=0)
    for action in ("show", "validate"):
        assert package.json("config", action, code=2)["errors"]
        text = package.run("config", action)
        assert text.returncode == 2, (text.stdout, text.stderr)

    # Show performs runtime validation, not validate-only regex compilation,
    # and returns the saved document rather than normalized enum spellings.
    package.configure(recursive_extract=1, runtime={"process_mode": "NORMAL"},
                      filesystem={"scan_filters": [{"name": "blacklist", "enabled": False,
                          "full_names": [{"value": "[", "regex": True}]}]})
    assert package.json("config", "show")["items"][0]["runtime"]["process_mode"] == "NORMAL"
    assert package.json("config", "validate", code=2)["errors"]


@pytest.mark.parametrize("mapping", ["default", "configured", "cli", "mirrored"])
def test_saved_output_mapping_and_cli_override(package, tmp_path, mapping):
    source = tmp_path / "Downloads"
    parent = source / "set"
    parent.mkdir(parents=True)
    archive = parent / "a.zip"
    with zipfile.ZipFile(archive, "w") as payload:
        payload.writestr("member.txt", "payload")
    saved = tmp_path / "saved"
    override = tmp_path / "override"
    # The fixture is one directory below the selected input; main requires -R.
    args = ["extract", "-R", source]
    if mapping == "default":
        expected = parent / "a"
    else:
        # Use the ordinary saved JSON path. output is not an environment
        # override field in main's configuration schema.
        package.configure(output={"root": str(saved), "fixed_root": mapping != "mirrored"})
        expected = saved / "a"
        if mapping == "cli":
            args += ["-o", override]
            expected = override / "a"
        elif mapping == "mirrored":
            expected = saved / "set" / "a"
    assert package.json(*args)["summary"]["success_count"] == 1
    assert (expected / "member.txt").read_text() == "payload"
    if mapping != "default":
        assert not (parent / "a").exists()
    if mapping == "cli":
        assert not saved.exists()
        assert not (override / "set").exists()


def test_relative_override_file_uses_service_cwd_not_request_cwd(package, tmp_path):
    service = package.launcher.parent.parent
    request = tmp_path / "request"
    request.mkdir()
    name = "relative-override.json"
    (service / name).write_text(json.dumps({"runtime": {"process_mode": "NORMAL"}}), encoding="utf-8")
    (request / name).write_text(json.dumps({"runtime": {"process_mode": "BACKGROUND"}}), encoding="utf-8")
    package.env["SUNPACK_CONFIG_OVERRIDES"] = name
    assert package.json("config", "show", cwd=request)["items"][0]["runtime"]["process_mode"] == "NORMAL"
    (request / name).unlink()
    assert package.json("config", "show", cwd=request)["items"][0]["runtime"]["process_mode"] == "NORMAL"
    (service / name).unlink()
    (request / name).write_text("{}", encoding="utf-8")
    assert package.json("config", "show", cwd=request, code=2)["errors"]


def test_explicit_config_checks_reject_bom_without_losing_last_valid_snapshot(package, tmp_path):
    override = tmp_path / "override.json"
    override.write_text('{"cli":{"language":"en"}}', encoding="utf-8")
    package.env["SUNPACK_CONFIG_OVERRIDES"] = str(override)
    assert package.json("passwords", "--no-bpw", "-p", "example")["items"][0]["user_passwords"] == ["example"]

    override.write_text("{}", encoding="utf-8-sig")
    for action in ("show", "validate"):
        result = package.json("config", action, code=2)
        assert "Unexpected UTF-8 BOM" in result["errors"][0]
    doctor = package.json("doctor", code=1)
    config_check = next(row for row in doctor["items"] if row["name"] == "config")
    assert config_check["status"] == "fail"
    assert "Unexpected UTF-8 BOM" in config_check["detail"]
    assert package.json("passwords", "--no-bpw", "-p", "example")["items"][0]["user_passwords"] == ["example"]


def test_cli_null_language_uses_english_with_explicit_cli_section(package):
    package.configure(cli={"language": None})
    result = package.run("passwords", "--no-bpw", "-p", "example")
    assert result.returncode == 0
    assert "[CLI] Password source summary:" in result.stdout


def test_config_checks_report_resolved_config_path_through_junction(package, tmp_path):
    alias = tmp_path / "ProgramDataAlias"
    subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(package.data.parent)],
        check=True,
        capture_output=True,
    )
    package.env["PROGRAMDATA"] = str(alias)
    expected = str(package.data / "sunpack_config.json")
    assert package.json("config", "show")["summary"]["config_path"] == expected
    doctor = json.loads(package.run("doctor", "--json").stdout)
    check = next(row for row in doctor["items"] if row["name"] == "config")
    assert check["detail"] == expected
