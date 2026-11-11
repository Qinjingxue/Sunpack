import json
import os
import subprocess
import zipfile
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path

import pytest


def _zip_bytes(entries):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _two_payload_carrier(package, workspace, carrier):
    fixtures = workspace / "fixtures"
    fixtures.mkdir()

    def encrypted(label, password):
        payload = fixtures / f"{label}.txt"
        content = f"contents of {label}\n".encode()
        payload.write_bytes(content)
        archive = fixtures / f"{label}.7z"
        subprocess.run(
            [str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", f"-p{password}",
             str(archive), payload.name],
            cwd=fixtures, check=True, capture_output=True,
        )
        return archive.read_bytes(), content

    first, first_content = encrypted("first", "first-key")
    second, second_content = encrypted("second", "second-key")
    carrier.write_bytes(b"carrier prefix\0" + first + b"between archives\0" + second + b"suffix")
    return first_content, second_content


def _only_output(output, name, content):
    paths = list(output.rglob(name))
    assert len(paths) == 1, paths
    assert paths[0].read_bytes() == content
    return paths[0]


def test_extract_password_retry_resumes_one_logical_input_in_a_carrier(package, tmp_path):
    carrier = tmp_path / "wrapped.data"
    output = tmp_path / "out"
    first, second = _two_payload_carrier(package, tmp_path, carrier)

    # Both archive identities have the same physical path and format.
    result = package.run(
        "extract", "-d", "-c", "d", "-o", output, "--no-builtin-pw", "--no-pause",
        "-p", "first-key", carrier, input="y\nsecond-key\n\n",
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    first_path = _only_output(output, "first.txt", first)
    second_path = _only_output(output, "second.txt", second)
    assert first_path.relative_to(output).parts[0] == second_path.relative_to(output).parts[0]
    assert not carrier.exists()


@pytest.mark.requires_watch_broker
def test_watch_password_retry_recovers_the_failed_sibling_after_restart(package, tmp_path):
    if "SUNPACK_WATCH_BROKER_PIPE_NAME" not in package.env:
        pytest.skip("The isolated Watch Broker service is required")
    watched = tmp_path / "watched"
    watched.mkdir()
    carrier = watched / "wrapped.data"
    output = tmp_path / "out"
    first, second = _two_payload_carrier(package, tmp_path, carrier)
    passwords = package.data / "builtin_passwords.json"
    passwords.write_text(json.dumps({"passwords": [{"value": "first-key"}]}), encoding="utf-8")
    package.json("watch", "add", "-d", "-o", output, watched)

    blocked = package.run("watch", "start", "--once", "--no-tray", "--json")
    assert blocked.returncode in (0, 1), (blocked.stdout, blocked.stderr)
    first_path = _only_output(output, "first.txt", first)
    assert not list(output.rglob("second.txt"))
    assert carrier.is_file()

    assert package.run("--persistent-shutdown").returncode == 0
    # Reopening the successful sibling would now fail its password probe.
    passwords.write_text(json.dumps({"passwords": [{"value": "second-key"}]}), encoding="utf-8")
    package.json("watch", "start", "--once", "--no-tray")
    assert _only_output(output, "first.txt", first) == first_path
    second_path = _only_output(output, "second.txt", second)
    assert first_path.relative_to(output).parts[0] == second_path.relative_to(output).parts[0]


def test_deep_discovery_restores_nested_filters_and_consumes_only_generated_archives(package, tmp_path):
    settings = package.data / "sunpack_config.json"
    config = json.loads(settings.read_text(encoding="utf-8"))
    config["recursive_authorization"] = {"enabled": False}
    config["filesystem"] = {
        "scan_filters_enabled": True,
        "scan_filters": [{
            "name": "blacklist",
            "enabled": True,
            "extensions": [{"value": extension, "regex": False} for extension in ("bin", "apk")],
        }],
    }
    settings.write_text(json.dumps(config), encoding="utf-8")

    apk = _zip_bytes({"resource.txt": b"APK payload"})
    inner = _zip_bytes({"payload.txt": b"nested payload"})
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"carrier prefix" * 20 + _zip_bytes({
        "client.apk": apk,
        "wrapper/inner.zip": inner,
    }) + b"carrier suffix")
    empty = tmp_path / "empty(1).zip"
    empty.write_bytes(_zip_bytes({}))
    output = tmp_path / "out"
    (output / "empty(1)").mkdir(parents=True)

    report = package.json("extract", "-d", "-r", "*", "-c", "k", "-o", output, carrier, empty)
    assert report["summary"]["success_count"] == 3
    assert report["summary"]["failed_count"] == 0
    assert (output / "empty(2)").is_dir()
    _only_output(output, "payload.txt", b"nested payload")
    _only_output(output, "client.apk", apk)
    assert not list(output.rglob("inner.zip"))
    assert not list(output.rglob("resource.txt"))
    assert carrier.is_file()
    assert empty.is_file()


def test_password_retry_deletes_promoted_nested_archive_under_keep_mode(package, tmp_path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    payload = fixtures / "secret.txt"
    payload.write_bytes(b"nested secret")
    inner = fixtures / "locked.7z"
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", "-pfixture-key",
         str(inner), payload.name],
        cwd=fixtures, check=True, capture_output=True,
    )
    nested_dir = tmp_path / "nested"
    nested_dir.mkdir()
    outer = nested_dir / "outer.zip"
    outer.write_bytes(_zip_bytes({"wrapper/locked.7z": inner.read_bytes()}))
    sibling = tmp_path / "plain.zip"
    sibling.write_bytes(_zip_bytes({"plain.txt": b"plain payload"}))
    output = tmp_path / "out"

    def wait_for_retry_prompt(stream):
        marker = "Enter new passwords and retry extraction?"
        tail = ""
        while character := stream.read(1):
            tail = (tail + character)[-len(marker):]
            if tail == marker:
                return True
        return False

    command = [str(package.launcher), "extract", "-r", "*", "-c", "k", "-o", str(output),
               "--no-builtin-pw", "--no-pause", "-p", "wrong", str(outer), str(sibling)]
    with ThreadPoolExecutor(max_workers=1) as executor, subprocess.Popen(
        command, cwd=package.data, env=package.env, encoding="utf-8",
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) as process:
        try:
            prompt = executor.submit(wait_for_retry_prompt, process.stdout)
            assert prompt.result(timeout=60)
            busy = package.json("scan", outer, code=1)
            assert busy["summary"]["status"] == "busy"
            stdout, stderr = process.communicate("y\nstill-wrong\n\ny\nfixture-key\n\n", timeout=60)
            assert process.returncode == 0, (stdout, stderr)
        finally:
            if process.poll() is None:
                process.kill()

    assert _only_output(output, "secret.txt", b"nested secret").parent == output / "nested" / "locked"
    _only_output(output, "plain.txt", b"plain payload")
    assert outer.is_file()
    assert not (nested_dir / inner.name).exists()


def test_partial_recovery_recurses_into_the_verified_nested_archive(package, tmp_path):
    settings = package.data / "sunpack_config.json"
    config = json.loads(settings.read_text(encoding="utf-8"))
    config["extraction"] = {"content_requirement": "allow_partial"}
    config["recursive_authorization"] = {"enabled": False}
    settings.write_text(json.dumps(config), encoding="utf-8")

    carrier = tmp_path / "damaged.zip"
    with zipfile.ZipFile(carrier, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("nested.zip", _zip_bytes({"recovered.txt": b"verified payload"}))
        archive.writestr("damaged.txt", b"will fail verification")
        bad = archive.getinfo("damaged.txt")
    content = bytearray(carrier.read_bytes())
    content[bad.header_offset + 30 + len(bad.filename)] ^= 1
    carrier.write_bytes(content)

    output = tmp_path / "out"
    report = package.json("extract", "--direct-file", "-r", "*", "-c", "d", "-o", output, carrier)
    assert report["summary"]["success_count"] == 1
    assert report["summary"]["partial_success_count"] == 1
    _only_output(output, "recovered.txt", b"verified payload")
    assert carrier.is_file()
    assert not list(output.rglob("nested.zip"))


def test_scan_bounds_filesystem_diagnostics_across_targets_and_subtrees(package, tmp_path):
    archive = tmp_path / "good.wrapped"
    archive.write_bytes(_zip_bytes({"payload.txt": b"valid archive"}))
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"ordinary text")
    missing = [tmp_path / f"missing-{index:02d}.zip" for index in range(96)]
    roots = [tmp_path / "first-root", tmp_path / "second-root"]
    principal = os.environ["USERNAME"]
    denied = []
    try:
        for root in roots:
            for index in range(3):
                blocked = root / f"blocked-{index}"
                blocked.mkdir(parents=True)
                subprocess.run(["icacls", blocked, "/deny", f"{principal}:(RD)"],
                               check=True, capture_output=True)
                denied.append(blocked)
        inside = roots[0] / "selected.zip"
        inside.write_bytes(_zip_bytes({"inside.txt": b"selected directory"}))
        unselected = tmp_path / "unselected.zip"
        unselected.write_bytes(_zip_bytes({"unselected.txt": b"relation context only"}))
        report = package.json("scan", "-R", archive, plain, *missing, *roots, code=1)
    finally:
        for blocked in denied:
            subprocess.run(["icacls", blocked, "/remove:d", principal],
                           check=True, capture_output=True)

    assert report["summary"] == {
        "archive_count": 2,
        "failed_count": 0,
        "input_error_count": 0,
        "scan_error_count": 102,
    }
    assert {Path(item["main_path"]) for item in report["items"]} == {archive, inside}
    assert len(report["errors"]) == 101
    assert any(missing[0].name in message for message in report["errors"])
    assert any(message.startswith("Cannot read directory:") and "blocked-" in message
               for message in report["errors"])
    assert report["errors"][-1] == "Additional filesystem scan errors omitted from this report: 2"
