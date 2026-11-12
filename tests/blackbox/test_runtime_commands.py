import io
import json
import os
import subprocess
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from pathlib import Path

import psutil
import pytest


def test_config_reload_and_literal_password_sources(package, tmp_path):
    password_file = tmp_path / "密码.txt"
    long = "长" * 23000  # Cross the native reader's 64 KiB buffer.
    password_file.write_bytes(f"\ufeffbom\r\n  spaces  \r#literal\n\n中文\u2028next\n{long}".encode())
    report = package.json("passwords", "--no-builtin-pw", "-p", "  spaces  ", "--pw-file", password_file)
    assert report["items"][0]["combined_passwords"] == ["  spaces  ", "\ufeffbom", "#literal", "中文", "next", long]

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


@pytest.mark.parametrize("invalid", [
    '{"cli":',
    '{"embedded_scan":{"recursive_candidate_ratio":"many"}}',
    '{"runtime":{"process_mode":42}}',
    '{"extraction":{"content_requirement":true}}',
])
def test_invalid_config_diagnostics_preserve_last_good_request_settings(package, tmp_path, invalid):
    archive = tmp_path / "input.zip"
    with zipfile.ZipFile(archive, "w") as payload:
        payload.writestr("member.txt", "payload")
    assert package.json("scan", archive)["summary"]["archive_count"] == 1
    path = package.data / "sunpack_config.json"
    good = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(invalid, encoding="utf-8")

    for action in ("show", "validate"):
        assert package.json("config", action, code=2)["errors"]
    doctor = package.json("doctor", code=1)
    assert next(row for row in doctor["items"] if row["name"] == "config")["status"] == "fail"
    assert package.json("scan", archive)["summary"]["archive_count"] == 1

    good["embedded_scan"] = {"enabled": False}
    path.write_text(json.dumps(good), encoding="utf-8")
    assert package.json("config", "show")["items"][0]["embedded_scan"]["enabled"] is False
    assert package.json("config", "validate")["items"][0]["ok"]
    assert package.json("scan", archive)["summary"]["archive_count"] == 1


def test_cli_password_values_and_noninteractive_prompt_contract(package):
    missing = package.run("passwords", "--json", "--password", "--no-bpw")
    assert missing.returncode == 2 and not missing.stdout
    assert "--password" in missing.stderr

    report = package.json("passwords", "--no-bpw", "--password=--no-bpw", "-p", "-42")
    assert report["items"][0]["user_passwords"] == ["--no-bpw", "-42"]
    assert not report["items"][0]["use_builtin_passwords"]

    prompt = package.json("passwords", "--ask-pw", code=2)
    assert prompt["inputs"]["argv"] == ["passwords", "--ask-pw", "--json"]
    assert prompt["errors"] == ["interactive password input is unavailable in JSON mode"]
    rejected = package.run("passwords", "--json", "--ask-pw", "--password", "do-not-report")
    assert rejected.returncode == 2 and "do-not-report" not in rejected.stdout

    result = package.run("passwords", "--ask-pw", "--no-bpw", input="  secret  \rquietQpassword\n\n")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "['  secret  ', 'quietQpassword']" in result.stdout
    invalid = package.run("passwords", "--ask-pw", input="truncated\x00suffix\n\n")
    assert invalid.returncode == 2 and "NUL" in invalid.stderr


def test_running_cli_keeps_last_passwords_until_valid_edit_or_deletion(package):
    path = package.data / "builtin_passwords.json"
    path.write_bytes(b'{"passwords":[{"value":"first"}]}')
    assert package.json("passwords")["items"][0]["builtin_passwords"] == ["first"]

    path.write_bytes(b'{"passwords":[{"value":"\xff"}]}')
    assert package.json("passwords")["items"][0]["builtin_passwords"] == ["first"]

    # Replace a file with the same length and last-write time while the same
    # runtime is running. The file identity must also invalidate its snapshot.
    path.write_bytes(b'{"passwords":[{"value":"first"}]}')
    assert package.json("passwords")["items"][0]["builtin_passwords"] == ["first"]
    before = path.stat()
    replacement = path.with_suffix(".tmp")
    replacement.write_bytes(b'{"passwords":[{"value":"other"}]}')
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    replacement.replace(path)
    assert package.json("passwords")["items"][0]["builtin_passwords"] == ["other"]

    path.unlink()
    assert package.json("passwords")["items"][0]["builtin_passwords"] == []
    assert not path.exists()


def test_launcher_preserves_flag_like_operands_and_validates_pause_flags(package, tmp_path):
    archive = tmp_path / "--pause"
    flag_like = tmp_path / "--_sunpack-terminal-size=80x24"
    for source in (archive, flag_like):
        with zipfile.ZipFile(source, "w") as payload:
            payload.writestr("member.txt", "payload")
    report = package.run("scan", "--json", "--", archive.name, flag_like.name, cwd=tmp_path)
    assert report.returncode == 0, (report.stdout, report.stderr)
    assert json.loads(report.stdout)["summary"]["archive_count"] == 2

    conflict = package.run("scan", archive, "--pause", "--no-pause")
    assert conflict.returncode == 2
    assert "mutually exclusive" in conflict.stderr


def test_version_uses_package_metadata_only(package, tmp_path):
    assert package.run("version").stdout.strip() == "test"
    package.launcher.parent.parent.joinpath("VERSION.txt").unlink()
    (tmp_path / "VERSION.txt").write_text("version=unrelated\n", encoding="utf-8")
    missing = package.run("version", cwd=tmp_path)
    assert missing.returncode == 3 and not missing.stdout


def test_drive_relative_path_uses_request_directory(package, tmp_path):
    archive = tmp_path / "relative.zip"
    with zipfile.ZipFile(archive, "w") as payload:
        payload.writestr("member.txt", "payload")
    report = package.json("scan", f"{tmp_path.drive.lower()}{archive.name}", cwd=tmp_path)
    assert [Path(item["main_path"]) for item in report["items"]] == [archive]


def test_concurrent_cold_start_clients_share_one_runtime(package):
    # Unlike warm concurrent requests, this starts every launcher with no state
    # file. A losing bootstrap child must not make its client fail.
    package.configure(performance={"persistent_server_idle_seconds": 60})
    for _ in range(3):
        assert package.run("--persistent-shutdown").returncode == 0
        for state in package.data.glob("runtime-*.state"):
            try:
                psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3])).wait(timeout=10)
            except (FileNotFoundError, psutil.NoSuchProcess):
                pass
        gate = Barrier(8)

        def show_config(_):
            gate.wait(timeout=10)
            return package.json("config", "show", timeout=30)

        with ThreadPoolExecutor(max_workers=8) as clients:
            reports = list(clients.map(show_config, range(8)))
        assert all(report["items"][0]["cli"]["language"] == "en" for report in reports)
        state, = package.data.glob("runtime-*.state")
        assert psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3])).is_running()


def test_cold_start_releases_startup_ownership_before_prompt_completion(package):
    assert package.run("--persistent-shutdown").returncode == 0
    for state in package.data.glob("runtime-*.state"):
        try:
            psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3])).wait(timeout=10)
        except (FileNotFoundError, psutil.NoSuchProcess):
            pass
    prompt = subprocess.Popen(
        [str(package.launcher), "passwords", "--ask-pw", "--no-bpw"],
        cwd=package.data, env=package.env, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        # Its pending stdin keeps the first command alive while a second client
        # must still be able to connect and finish through the same host.
        with ThreadPoolExecutor(max_workers=1) as reader:
            first_output = reader.submit(prompt.stdout.read, 1)
            try:
                assert first_output.result(timeout=15)
                assert prompt.poll() is None
                assert package.json("config", "show", timeout=15)["items"]
                prompt.stdin.write(b"\n")
                prompt.stdin.flush()
            except BaseException:
                prompt.kill()  # Unblock the reader before its executor joins.
                raise
        _, error = prompt.communicate(timeout=15)
        assert prompt.returncode == 0, error
    finally:
        if prompt.poll() is None:
            prompt.kill()
            prompt.communicate(timeout=10)


def test_existing_runtime_uses_latest_archive_request_idle_setting(package, tmp_path):
    archive = tmp_path / "input.zip"
    with zipfile.ZipFile(archive, "w") as payload:
        payload.writestr("member.txt", "payload")
    package.configure(performance={"persistent_server_idle_seconds": 60})
    assert package.json("scan", archive)["summary"]["archive_count"] == 1
    state, = package.data.glob("runtime-*.state")
    owner = psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3]))

    package.configure(performance={"persistent_server_idle_seconds": 0})
    assert package.json("scan", archive)["summary"]["archive_count"] == 1
    owner.wait(timeout=10)
    assert not state.exists()


def test_extract_reports_invalid_input_and_filesystem_errors_separately(package, tmp_path):
    missing = tmp_path / "missing.zip"
    report = package.json("extract", "--direct-file", tmp_path, missing, code=1)
    assert report["summary"]["failed_count"] == 0
    assert report["summary"]["input_error_count"] == 1
    assert report["summary"]["scan_error_count"] == 1
    assert report["tasks"][0]["failures"][0]["kind"] == "invalid_input"

    result = package.run("extract", "--direct-file", tmp_path, missing)
    assert result.returncode == 1
    assert all(label in result.stderr for label in ("[Input error]", "[Scan error]", "[Scan incomplete]"))


def test_text_extract_keeps_nested_archive_under_its_carrier_segment(package, tmp_path):
    def zipped(name, data):
        with io.BytesIO() as buffer:
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr(name, data)
            return buffer.getvalue()

    carrier = tmp_path / "carrier.opaque"
    carrier.write_bytes(
        b"prefix" + zipped("one.txt", b"one") + b"between" +
        zipped("nested.zip", zipped("two.txt", b"two")) + b"trailer"
    )
    output = tmp_path / "output"
    result = package.run("extract", "-d", "-r", "*", "-c", "k", "-o", output, carrier)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "\x1b" not in result.stdout
    assert result.stdout.index("├─ Segment 1 (zip)") < result.stdout.index("└─ Segment 2 (zip)")
    assert result.stdout.index("└─ Segment 2 (zip)") < result.stdout.index("   └─ nested.zip")
    assert result.stdout.count("[Complete] [####################] 100%") == 3


def test_watch_action_help_lists_available_options(package):
    help_text = package.run("watch", "add", "--help")
    assert help_text.returncode == 0
    assert all(option in help_text.stdout for option in ("paths", "--out-dir", "--start", "--deep-detect"))


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


@pytest.mark.requires_watch_broker
def test_idle_watch_releases_reader_handles_after_foreground_scan(package, tmp_path):
    settings_path = package.data / "sunpack_config.json"
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    settings["watch"]["runtime_cache_cleanup_idle_seconds"] = 0.25
    settings_path.write_text(json.dumps(settings), encoding="utf-8")
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for number in range(128):
        with zipfile.ZipFile(inputs / f"archive-{number}.zip", "w") as archive:
            archive.writestr("payload.txt", str(number))

    package.json("watch", "start", "--no-tray")
    runtime = package.launcher.parent.parent / "sunpack-runtime.exe"
    owner = next(
        process for process in psutil.process_iter(["exe"])
        if process.info["exe"] and Path(process.info["exe"]) == runtime
    )
    idle_handles = owner.num_handles()
    assert package.json("scan", inputs)["summary"]["archive_count"] == 128
    # Allow worker transport and its threads to remain warm. Idle Watch must
    # release the archive readers even when all archive work came from CLI.
    _await_watch(
        lambda: owner.num_handles() <= idle_handles + 48,
        "Watch retained reader handles after foreground archive work became idle",
    )


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
