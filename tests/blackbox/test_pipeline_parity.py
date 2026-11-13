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


def test_explicit_outer_archive_keeps_nested_failure_beside_it(package, tmp_path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "secret.txt").write_text("encrypted payload")
    inner = fixtures / "locked.7z"
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on",
         "-punknown-key", str(inner), "secret.txt"],
        cwd=fixtures, check=True, capture_output=True,
    )
    root = tmp_path / "inputs"
    outer = root / "sub" / "outer.zip"
    outer.parent.mkdir(parents=True)
    with zipfile.ZipFile(outer, "w") as archive:
        archive.write(inner, inner.name)
    package.configure(
        recursive_authorization={"enabled": False},
        filesystem={"scan_filters": [{"name": "size_range", "enabled": False}]},
    )

    report = package.json("extract", "-R", "-r", "*", "--no-builtin-pw", root, outer, code=1)

    promoted = outer.with_name(inner.name)
    assert promoted.read_bytes() == inner.read_bytes()
    assert not (root / inner.name).exists()
    assert str(promoted) in report["errors"][0]


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


def test_direct_fallback_does_not_force_unproven_signature_format(package, tmp_path):
    package.configure(embedded_scan={"enabled": False})
    source = tmp_path / "disguised.bin"
    # Invalid 7z start-header CRC, followed by an ordinary ZIP. With embedded
    # scanning disabled only the worker's direct auto-detection can open it.
    source.write_bytes(b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\xff" * 24)
    with zipfile.ZipFile(source, "a") as archive:
        archive.writestr("payload.txt", b"direct fallback")
    output = tmp_path / "out"
    report = package.json("extract", "--direct-file", "-r", "1", "-o", output, source)
    assert report["summary"]["success_count"] == 1
    assert [p.read_bytes() for p in output.rglob("payload.txt")] == [b"direct fallback"]


def test_failed_first_segment_keeps_its_output_name_for_password_retry(package, tmp_path):
    package.configure(post_extract={"flatten_single_directory": False})
    (tmp_path / "secret.txt").write_bytes(b"secret")
    locked = tmp_path / "locked.7z"
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", "-pknown-key",
         str(locked), "secret.txt"], cwd=tmp_path, check=True, capture_output=True,
    )
    plain = tmp_path / "plain.zip"
    with zipfile.ZipFile(plain, "w") as archive:
        archive.writestr("ordinary.txt", b"ordinary")
    source = tmp_path / "carrier.bin"
    source.write_bytes(b"prefix" + locked.read_bytes() + b"between" + plain.read_bytes())
    output = tmp_path / "out"
    result = package.run(
        "extract", "-d", "-r", "1", "-c", "k", "-o", output, "--no-builtin-pw",
        "--no-pause", "-p", "wrong-key", source, input="y\nknown-key\n\n",
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    secret, = output.rglob("secret.txt")
    ordinary, = output.rglob("ordinary.txt")
    assert secret.read_bytes() == b"secret"
    assert ordinary.read_bytes() == b"ordinary"
    assert ordinary.parent.name == secret.parent.name + "(1)"
    assert ordinary.parent.parent == secret.parent.parent == output / "carrier"
