import json
import subprocess

import pytest


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
