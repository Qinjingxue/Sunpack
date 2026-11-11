import subprocess
import zipfile

import pytest


def _damage_stored_member(path, member, encryption_header=0):
    with zipfile.ZipFile(path) as archive:
        entry = archive.getinfo(member)
    content = bytearray(path.read_bytes())
    start = entry.header_offset
    name_size = int.from_bytes(content[start + 26:start + 28], "little")
    extra_size = int.from_bytes(content[start + 28:start + 30], "little")
    content[start + 30 + name_size + extra_size + encryption_header] ^= 1
    path.write_bytes(content)


def test_password_retry_reuses_partially_recovered_carrier_segment(package, tmp_path):
    package.configure(extraction={"content_requirement": "allow_partial"})
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    damaged = fixtures / "damaged.zip"
    with zipfile.ZipFile(damaged, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("good.txt", b"verified payload")
        archive.writestr("bad.txt", b"checksum failure")
    _damage_stored_member(damaged, "bad.txt")
    locked = fixtures / "locked.7z"
    (fixtures / "locked.txt").write_bytes(b"encrypted payload")
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", "-pknown-key", str(locked), "locked.txt"],
        cwd=fixtures, check=True, capture_output=True,
    )
    source = tmp_path / "carrier.bin"
    source.write_bytes(b"prefix" + damaged.read_bytes() + b"between" + locked.read_bytes() + b"suffix")
    output = tmp_path / "output"

    result = package.run(
        "extract", "-d", "-r", "1", "-c", "d", "-o", output, "--no-builtin-pw",
        "--no-pause", "-p", "wrong-key", source, input="y\nknown-key\n\n",
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert [path.name for path in output.iterdir()] == ["carrier"]
    assert [path.read_bytes() for path in output.rglob("good.txt")] == [b"verified payload"]
    assert [path.read_bytes() for path in output.rglob("locked.txt")] == [b"encrypted payload"]
    assert source.exists()


def test_output_file_parent_does_not_block_other_archives(package, tmp_path):
    inputs = tmp_path / "inputs"
    bad = inputs / "blocked/bad.zip"
    good = inputs / "ready/good.zip"
    for source in (bad, good):
        source.parent.mkdir(parents=True)
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr(f"{source.stem}.txt", b"payload")
    output = tmp_path / "output"
    output.mkdir()
    blocked = output / "blocked"
    blocked.write_bytes(b"user file")

    report = package.json("extract", "-c", "d", "-o", output, bad, good, code=1)

    assert report["summary"]["success_count"] == report["summary"]["failed_count"] == 1
    assert report["tasks"][0]["failures"][0]["kind"] == "filesystem_error"
    assert (output / "ready/good/good.txt").read_bytes() == b"payload"
    assert blocked.read_bytes() == b"user file"
    assert bad.exists() and not good.exists()


@pytest.mark.parametrize("select_directory", [False, True], ids=["file", "directory"])
def test_extract_deduplicates_the_same_archive_through_a_junction(package, tmp_path, select_directory):
    real = tmp_path / "real"
    real.mkdir()
    source = real / "archive.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("item.txt", b"payload")
    alias = tmp_path / "alias"
    subprocess.run(
        [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "New-Item -ItemType Junction -Path $env:SUNPACK_TEST_ALIAS -Target $env:SUNPACK_TEST_REAL",
        ],
        env={**package.env, "SUNPACK_TEST_ALIAS": str(alias), "SUNPACK_TEST_REAL": str(real)},
        check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    output = tmp_path / "output"

    try:
        report = package.json(
            "extract", "-c", "k", "-o", output,
            real if select_directory else source, alias / source.name,
        )
    finally:
        alias.rmdir()

    assert report["summary"]["success_count"] == 1
    assert [path.read_bytes() for path in output.rglob("item.txt")] == [b"payload"]


def test_damaged_zipcrypto_remembers_password_proved_by_earlier_member(package, tmp_path):
    source = tmp_path / "damaged.zip"
    (tmp_path / "first.txt").write_bytes(b"verified content")
    (tmp_path / "second.txt").write_bytes(b"damaged content")
    subprocess.run(
        [
            str(package.tools / "7z.exe"), "a", "-tzip", "-mx=0", "-mem=ZipCrypto",
            "-pproof-key", str(source), "first.txt", "second.txt",
        ],
        cwd=tmp_path, check=True, capture_output=True,
    )
    _damage_stored_member(source, "second.txt", encryption_header=12)

    report = package.json(
        "extract", "--direct-file", "--no-builtin-pw", "-p", "proof-key",
        "-o", tmp_path / "output", source, code=1,
    )

    assert report["tasks"][0]["failures"][0]["kind"] == "damaged"
    assert report["items"][0]["recent_passwords"] == ["proof-key"]
