import io
import json
import random
import subprocess
import tarfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def _zip(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return stream.getvalue()


def test_scan_and_extract_nested_carrier_through_launcher(package, tmp_path):
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    outer = _zip({"nested.opaque": _zip({"中文.txt": b"nested payload"})})
    prefix = b"unrelated prefix data" * 13
    carrier = input_dir / "载体.dat"
    carrier.write_bytes(prefix + outer + b"trailer" * 3)
    archive = input_dir / "plain.unrecognized"
    archive.write_bytes(_zip({"ordinary.txt": b"ordinary payload"}))
    before = {path: path.read_bytes() for path in input_dir.iterdir()}

    report = package.json("scan", "--deep-detect", str(input_dir))
    assert report["command"] == "scan"
    assert report["summary"]["archive_count"] == 2, report
    items = {Path(item["main_path"]).name: item for item in report["items"]}
    assert items[carrier.name]["offset"] == len(prefix)
    assert items[archive.name]["format"] == "zip"
    assert "password_used" not in items[archive.name]
    assert {path: path.read_bytes() for path in input_dir.iterdir()} == before

    output = tmp_path / "output"
    report = package.json("extract", "-d", "-r", "*", "-c", "k", "-o", output, input_dir)
    assert report["command"] == "extract"
    assert report["summary"]["success_count"] >= 2
    assert next(output.rglob("中文.txt")).read_bytes() == b"nested payload"
    assert next(output.rglob("ordinary.txt")).read_bytes() == b"ordinary payload"
    assert {path: path.read_bytes() for path in input_dir.iterdir()} == before


def test_password_candidates_apply_only_to_their_directory(package, tmp_path):
    allowed = tmp_path / "allowed" / "child"
    denied = tmp_path / "denied"
    allowed.mkdir(parents=True)
    denied.mkdir()
    payload = tmp_path / "payload.txt"
    payload.write_text("password probe", encoding="utf-8")
    encrypted = allowed / "hidden.wrapped"
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", "-ppinned secret", str(encrypted), str(payload)],
        check=True, capture_output=True,
    )
    # A second name for the same file also exercises physical-generation
    # password cache reuse across directory scopes.
    (denied / encrypted.name).hardlink_to(encrypted)
    (package.data / "builtin_passwords.json").write_text(json.dumps({
        "passwords": [{"value": "pinned secret", "scopes": [str(allowed.parent)]}],
    }), encoding="utf-8")

    report = package.json("scan", encrypted)
    assert report["items"][0]["password_used"] == "pinned secret"
    result = package.run("scan", denied / encrypted.name, "--json", "--no-pause")
    assert result.returncode != 0, result.stdout
    rejected = json.loads(result.stdout)
    assert rejected["items"][0]["password_used"] is None
    assert not (denied / "hidden").exists()


def test_extracts_disguised_enc_and_compressed_tar_in_one_request(package, tmp_path, repo_root):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    vectors = repo_root / "tests" / "data" / "enc_parallel"
    encrypted = inputs / "cipher.wrapped"
    encrypted.write_bytes((vectors / "algorithm_0.enc").read_bytes())
    compressed = inputs / "bundle.tar.gz"
    content = b"compressed TAR payload"
    with tarfile.open(compressed, "w:gz") as archive:
        entry = tarfile.TarInfo("bundle.txt")
        entry.size = len(content)
        archive.addfile(entry, io.BytesIO(content))

    output = tmp_path / "output"
    report = package.json("extract", "-d", "-r", "*", "-c", "k", "-p", "sunpack-test",
                          "-o", output, inputs)
    assert report["summary"]["failed_count"] == 0, report
    assert next(output.rglob("bundle.txt")).read_bytes() == content
    expected = (vectors / "large.expected").read_bytes()
    assert any(path.read_bytes() == expected for path in output.rglob("*")
               if path.is_file() and path.stat().st_size == len(expected))


def test_missing_split_volume_blocks_source_cleanup(package, tmp_path):
    inputs = tmp_path / "volumes"
    inputs.mkdir()
    payload = tmp_path / "payload.txt"
    content = random.Random(35).randbytes(4500)
    payload.write_bytes(content)
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mx=0", "-v1k",
         str(inputs / "series.7z"), str(payload)],
        check=True, capture_output=True,
    )
    parts = sorted(inputs.glob("series.7z.*"))
    assert len(parts) >= 3
    removed = parts[1].read_bytes()
    parts[1].unlink()
    before = {path: path.read_bytes() for path in inputs.iterdir()}
    output = tmp_path / "output"
    blocked = package.run("extract", "-c", "d", "-o", output, parts[0], "--json", "--no-pause")
    assert blocked.returncode != 0, blocked.stdout
    assert {path: path.read_bytes() for path in inputs.iterdir()} == before
    parts[1].write_bytes(removed)

    report = package.json("extract", "-c", "k", "-o", output, parts[0])
    assert report["summary"]["success_count"] == 1
    assert next(output.rglob("payload.txt")).read_bytes() == content


def test_concurrent_launcher_requests_reserve_distinct_outputs(package, tmp_path):
    # Start one server before the two clients race for the same output name.
    assert package.run("--help").returncode == 0
    paths = []
    for name in ("first", "second"):
        folder = tmp_path / name
        folder.mkdir()
        archive = folder / "same.zip"
        archive.write_bytes(_zip({"payload.txt": name.encode()}))
        paths.append(archive)
    output = tmp_path / "output"

    def extract(path):
        return package.json("extract", "-c", "k", "-o", output, path)

    with ThreadPoolExecutor(max_workers=2) as executor:
        reports = list(executor.map(extract, paths))

    assert all(report["summary"]["success_count"] == 1 for report in reports)
    assert sorted(path.read_bytes() for path in output.rglob("payload.txt")) == [b"first", b"second"]


def test_partial_content_policy_uses_verified_members_and_retains_source(package, tmp_path):
    source = tmp_path / "damaged.wrapped"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("good.txt", b"good")
        archive.writestr("bad.txt", b"damaged")
        bad = archive.getinfo("bad.txt")
        payload_offset = bad.header_offset + 30 + len(bad.filename)
    content = bytearray(source.read_bytes())
    content[payload_offset] ^= 1
    source.write_bytes(content)
    settings_path = package.data / "sunpack_config.json"
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    settings["extraction"] = {"content_requirement": "allow_partial"}
    settings["recursive_extract"] = 1
    settings_path.write_text(json.dumps(settings), encoding="utf-8")

    output = tmp_path / "partial"
    report = package.json("extract", "--direct-file", "-c", "d", "-o", output, source)
    assert report["summary"]["partial_success_count"] == 1
    assert report["summary"]["success_count"] == report["summary"]["failed_count"] == 0
    assert next(output.rglob("good.txt")).read_bytes() == b"good"
    assert source.is_file()

    settings["extraction"]["content_requirement"] = "complete"
    settings_path.write_text(json.dumps(settings), encoding="utf-8")
    rejected_output = tmp_path / "complete"
    result = package.run("extract", "--direct-file", "-c", "d", "-o", rejected_output, source, "--json")
    assert result.returncode != 0
    assert source.is_file()
    assert not list(rejected_output.rglob("good.txt"))
