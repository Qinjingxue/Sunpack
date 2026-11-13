import json
import os
import subprocess
import zipfile
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path

import psutil
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


def test_carrier_keeps_each_segments_directory_tree(package, tmp_path):
    package.configure(post_extract={"flatten_single_directory": True})
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(
        b"prefix" + _zip_bytes({"wrapper/one.txt": b"first"})
        + b"between" + _zip_bytes({"wrapper/two.txt": b"second"}) + b"suffix"
    )
    output = tmp_path / "out"

    package.json("extract", "-d", "-r", "1", "-o", output, carrier)

    first = _only_output(output, "one.txt", b"first")
    second = _only_output(output, "two.txt", b"second")
    assert first.parent.name == second.parent.name == "wrapper"
    assert first.parent.parent != second.parent.parent
    assert first.parent.parent.parent == second.parent.parent.parent == output / "carrier"


@pytest.mark.parametrize("nested", [False, True], ids=["root-carrier", "promoted-carrier"])
def test_extract_password_retry_resumes_one_logical_input_in_a_carrier(package, tmp_path, nested):
    carrier = tmp_path / "wrapped.data"
    output = tmp_path / "out"
    fixture = tmp_path / "carrier.fixture" if nested else carrier
    first, second = _two_payload_carrier(package, tmp_path, fixture)
    source = carrier
    if nested:
        source = tmp_path / "outer.zip"
        source.write_bytes(_zip_bytes({carrier.name: fixture.read_bytes(), "note.txt": b"outer"}))
        package.configure(recursive_authorization={"enabled": False})

    # Both archive identities have the same physical path and format.
    result = package.run(
        "extract", "-d", "-r", "*", "-c", "d", "-o", output, "--no-builtin-pw", "--no-pause",
        "-p", "first-key", source, input="y\nsecond-key\n\n",
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    first_path = _only_output(output, "first.txt", first)
    second_path = _only_output(output, "second.txt", second)
    assert first_path.relative_to(output).parts[0] == second_path.relative_to(output).parts[0]
    assert not carrier.exists()


@pytest.mark.requires_watch_broker
@pytest.mark.parametrize("nested", [False, True], ids=["root-carrier", "promoted-carrier"])
def test_watch_password_retry_recovers_the_failed_sibling_after_hard_crash(package, tmp_path, nested):
    if "SUNPACK_WATCH_BROKER_PIPE_NAME" not in package.env:
        pytest.skip("The isolated Watch Broker service is required")
    watched = tmp_path / "watched"
    watched.mkdir()
    carrier = watched / "wrapped.jpg"
    output = tmp_path / "out"
    fixture = tmp_path / carrier.name if nested else carrier
    first, second = _two_payload_carrier(package, tmp_path, fixture)
    if nested:
        # The successful receipt is under an outer output. Promotion changes
        # both the source owner and the preferred output of the retry.
        (watched / "outer.zip").write_bytes(_zip_bytes({
            carrier.name: fixture.read_bytes(),
            "note.txt": b"outer archive",
        }))
        package.configure(
            recursive_authorization={"enabled": False},
            post_extract={"archive_cleanup_mode": "k", "flatten_single_directory": False},
        )
    passwords = package.data / "builtin_passwords.json"
    passwords.write_text(json.dumps({"passwords": [{"value": "first-key"}]}), encoding="utf-8")
    package.json("watch", "add", "-d", "-o", output, watched)

    blocked = package.run("watch", "start", "--once", "--no-tray", "--json")
    assert blocked.returncode in (0, 1), (blocked.stdout, blocked.stderr)
    first_path = _only_output(output, "first.txt", first)
    assert not list(output.rglob("second.txt"))
    assert carrier.is_file()

    # Unlike graceful shutdown, TerminateProcess cannot flush or retire state.
    # The completed sibling and the password blocker must already be durable.
    state, = package.data.glob("runtime-*.state")
    owner = psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3]))
    workers = owner.children(recursive=True)
    owner.kill()
    owner.wait(timeout=30)
    for worker in workers:
        worker.wait(timeout=30)
    # Reopening the successful sibling would now fail its password probe.
    passwords.write_text(json.dumps({"passwords": [{"value": "second-key"}]}), encoding="utf-8")
    package.json("watch", "start", "--once", "--no-tray")
    assert _only_output(output, "first.txt", first) == first_path
    second_path = _only_output(output, "second.txt", second)
    assert first_path.parent.parent == second_path.parent.parent
    if nested:
        assert not carrier.exists()
        assert (watched / "outer.zip").is_file()


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




@pytest.mark.parametrize("requirement,nested", [("allow_partial", False), ("allow_partial", True), ("complete", False)])
def test_failed_nonempty_output_is_retained_without_partial_success(package, tmp_path, requirement, nested):
    # Unlike verified-member recovery, a lone CRC-failed member must remain a
    # failure. Its damaged bytes are still useful; retaining them must neither
    # recurse into their ZIP contents nor delete the failed archive source.
    payload = _zip_bytes({"must-not-extract.txt": b"damaged member is not verified"})
    data = BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("damaged.zip", payload)
        member = archive.getinfo("damaged.zip")
    damaged = bytearray(data.getvalue())
    # Alter the stored CRC, leaving a valid nested archive as the failed payload.
    damaged[member.header_offset + 14] ^= 1
    central = damaged.index(b"PK\x01\x02", member.header_offset + 30 + len(member.filename) + len(payload))
    damaged[central + 16] ^= 1
    source = tmp_path / "source.zip"
    source.write_bytes(_zip_bytes({"inner.zip": damaged}) if nested else damaged)
    package.configure(
        extraction={"content_requirement": requirement},
        recursive_authorization={"enabled": False},
        post_extract={"flatten_single_directory": False},
    )
    output = tmp_path / "out"
    report = package.json("extract", "--direct-file", "-r", "*", "-c", "d", "-o", output, source, code=1)
    assert report["summary"]["failed_count"] == 1, report
    assert report["summary"]["partial_success_count"] == 0, report
    assert report["summary"]["success_count"] == int(nested), report
    assert source.exists() == (not nested)
    if nested:
        _only_output(output, "inner.zip", damaged)
    if requirement == "allow_partial":
        _only_output(output, "damaged.zip", payload)
    else:
        assert not list(output.rglob("damaged.zip"))
    assert not list(output.rglob("must-not-extract.txt"))


@pytest.mark.parametrize("requirement,cleanup", [("complete", "d"), ("allow_partial", "d"), ("complete", "k")])
def test_nested_failure_does_not_revoke_outer_source_cleanup(package, tmp_path, requirement, cleanup):
    # Existing recovery tests retain a damaged *outer* source. This inverse
    # boundary catches coupling its successful extraction to a failed child,
    # while checking that cleanup still retains that child's physical source.
    inner = BytesIO()
    with zipfile.ZipFile(inner, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("good.txt", b"verified inner member")
        archive.writestr("bad.txt", b"damaged inner member")
        bad = archive.getinfo("bad.txt")
    damaged = bytearray(inner.getvalue())
    damaged[bad.header_offset + 30 + len(bad.filename)] ^= 1
    source = tmp_path / "outer.zip"
    source.write_bytes(_zip_bytes({"inner.zip": damaged, "outer.txt": b"outer success"}))
    package.configure(
        extraction={"content_requirement": requirement},
        recursive_authorization={"enabled": False},
        post_extract={"flatten_single_directory": False},
    )
    output = tmp_path / "out"
    report = package.json(
        "extract", "--direct-file", "-r", "*", "-c", cleanup, "-o", output, source,
        code=0 if requirement == "allow_partial" else 1,
    )
    assert report["summary"]["success_count"] == 1, report
    assert report["summary"]["partial_success_count"] == (requirement == "allow_partial"), report
    assert report["summary"]["failed_count"] == (requirement == "complete"), report
    assert source.exists() == (cleanup == "k")
    _only_output(output, "outer.txt", b"outer success")
    _only_output(output, "inner.zip", damaged)
    if requirement == "allow_partial":
        _only_output(output, "good.txt", b"verified inner member")
    else:
        assert not list(output.rglob("good.txt"))

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


def test_distinct_volume_requests_do_not_expand_original_busy_claim(package, tmp_path):
    # The retry prompt is an observable request-lifetime barrier: the first
    # request has discovered the entire family but still owns its original
    # admission claim. A second physical entry must not become an initial busy.
    payload = tmp_path / "payload.bin"
    content = bytes(range(256)) * 32
    payload.write_bytes(content)
    archive = tmp_path / "family.7z"
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mx=0", "-v1k",
         "-mhe=on", "-pfixture-key", str(archive), payload.name],
        cwd=tmp_path, check=True, capture_output=True,
    )
    parts = sorted(tmp_path.glob("family.7z.*"))
    assert len(parts) >= 2
    first_output = tmp_path / "first-output"
    second_output = tmp_path / "second-output"

    def wait_for_prompt(stream):
        marker = "Enter new passwords and retry extraction?"
        tail = ""
        while character := stream.read(1):
            tail = (tail + character)[-len(marker):]
            if tail == marker:
                return True
        return False

    command = [str(package.launcher), "extract", "-c", "k", "-o", str(first_output),
               "--no-builtin-pw", "--no-pause", "-p", "wrong", str(parts[0])]
    with ThreadPoolExecutor(max_workers=1) as executor, subprocess.Popen(
        command, cwd=package.data, env=package.env, encoding="utf-8",
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) as process:
        try:
            assert executor.submit(wait_for_prompt, process.stdout).result(timeout=60)
            duplicate = package.json("scan", parts[0], code=1)
            assert duplicate["summary"]["status"] == "busy"
            second = package.json("extract", "-c", "k", "-o", second_output,
                                  "--no-builtin-pw", "-p", "fixture-key", parts[1])
            assert second["summary"]["success_count"] == 1
            stdout, stderr = process.communicate("y\nfixture-key\n\n", timeout=60)
            assert process.returncode == 0, (stdout, stderr)
        finally:
            if process.poll() is None:
                process.kill()
    _only_output(first_output, payload.name, content)
    _only_output(second_output, payload.name, content)
    assert all(part.is_file() for part in parts)
