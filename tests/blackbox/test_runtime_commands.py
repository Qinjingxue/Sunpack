import json
import os
import subprocess
import time
import zipfile
from pathlib import Path

import pytest


def test_config_reload_and_literal_password_sources(package, tmp_path):
    password_file = tmp_path / "密码.txt"
    password_file.write_bytes("  spaces  \r\n#literal\n\n中文\n".encode())
    report = package.json("passwords", "--no-builtin-pw", "-p", "  spaces  ", "--pw-file", password_file)
    assert report["items"][0]["combined_passwords"] == ["  spaces  ", "#literal", "中文"]

    before = package.json("config", "show")
    assert before["items"][0]["cli"]["language"] == "en"
    config_file = package.data / "sunpack_config.json"
    config = json.loads(config_file.read_text(encoding="utf-8"))
    config["cli"]["language"] = "zh"
    pending = config_file.with_suffix(".tmp")
    pending.write_text(json.dumps(config), encoding="utf-8")
    pending.replace(config_file)
    after = package.json("config", "show")
    assert after["items"][0]["cli"]["language"] == "zh"
    assert not after["summary"]["changed"]


@pytest.mark.requires_watch_broker
def test_watch_once_consumes_archive_and_persists_completion(package, tmp_path):
    if "SUNPACK_WATCH_BROKER_PIPE_NAME" not in package.env:
        pytest.skip("The isolated Watch Broker service is required")
    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "watch-output"
    source = watched / "package.wrapped"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("received.txt", b"watch payload")
    package.json("watch", "add", watched, "-o", output)
    assert package.json("watch", "list")["summary"]["count"] == 1
    package.json("watch", "start", "--once", "--no-tray")
    assert next(output.rglob("received.txt")).read_bytes() == b"watch payload"
    assert source.is_file()
    assert package.run("--persistent-shutdown").returncode == 0
    package.json("watch", "start", "--once", "--no-tray")
    assert len(list(output.rglob("received.txt"))) == 1


def _await_watch(predicate, description):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.025)
    pytest.fail(description)


@pytest.mark.requires_watch_broker
def test_continuous_watch_retries_promoted_nested_input_after_password_edit(package, tmp_path):
    if "SUNPACK_WATCH_BROKER_PIPE_NAME" not in package.env:
        pytest.skip("The isolated Watch Broker service is required")

    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "out"
    marker = tmp_path / "recovered.txt"
    marker.write_bytes(b"blocked nested payload")
    inner = tmp_path / "inner.7z"
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", "-pnested-key",
         str(inner), marker.name],
        cwd=tmp_path, check=True, capture_output=True,
    )
    incoming = tmp_path / "outer.dat"
    with zipfile.ZipFile(incoming, "w") as archive:
        archive.write(inner, inner.name)
    settings_path = package.data / "sunpack_config.json"
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    settings["post_extract"]["archive_cleanup_mode"] = "d"
    settings["recursive_extract"] = "*"
    settings_path.write_text(json.dumps(settings), encoding="utf-8")
    package.json("watch", "add", watched, "-o", output, "--deep-detect")
    started = package.json("watch", "start", "--no-tray")["summary"]
    assert started["started"] and started["running"]
    assert package.json("watch", "reload")["summary"]["reloaded"]
    same_root = package.json("watch", "add", watched, "--deep-detect")["summary"]
    assert same_root["apply"]["applied"] is False
    assert same_root["apply"]["generation"] == started["generation"]

    source = watched / incoming.name
    promoted = watched / inner.name
    incoming.replace(source)
    _await_watch(
        lambda: not source.exists() and promoted.is_file(),
        "Watch did not retain the blocked nested input before removing its parent",
    )
    assert not list(output.rglob(marker.name))

    passwords = package.data / "builtin_passwords.json"
    updated = passwords.with_suffix(".tmp")
    updated.write_text(json.dumps({"passwords": [{"value": "nested-key"}]}), encoding="utf-8")
    updated.replace(passwords)
    _await_watch(
        lambda: not promoted.exists() and any(output.rglob(marker.name)),
        "Editing the password table did not resume the promoted nested archive",
    )
    assert package.json("watch", "start", "--once")["summary"]["exit_code"] == 0
    status = package.json("watch", "status")["summary"]
    assert status["running"] and status["generation"] == started["generation"]
    assert package.json("watch", "stop")["summary"]["stopped"]
    extracted = list(output.rglob(marker.name))
    assert len(extracted) == 1
    assert extracted[0].read_bytes() == marker.read_bytes()


def test_gui_password_edits_are_visible_to_running_runtime(package):
    binary = os.environ.get("SUNPACK_GUI_TEST_BINARY")
    if not binary:
        pytest.skip("Build the GUI test binary")
    assert Path(binary).is_file()
    path = package.data / "builtin_passwords.json"
    assert package.json("passwords")["items"][0]["builtin_passwords"] == []
    result = subprocess.run(
        [binary, "--password-add", str(path), " GUI # 中文 "],
        capture_output=True, check=True, timeout=30,
    )
    assert result.returncode == 0
    assert package.json("passwords")["items"][0]["builtin_passwords"] == [" GUI # 中文 "]
