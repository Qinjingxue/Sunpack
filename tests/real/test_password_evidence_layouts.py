"""Password evidence can occupy middle volumes, not just archive ends."""

import random
import struct
from shutil import copyfile

import pytest

from tests.helpers.native_fixture import assemble_carrier
from tests.helpers.real_archives import run_cmd
from tests.helpers.tool_config import require_7z
from tests.real.archive_boundary import extract_report


VOLUME_SIZE = 40 * 1024
PASSWORD = "evidence-key"


def test_zip_tail_password_and_authenticator_belong_to_same_layout(package, tmp_path):
    member = tmp_path / "member.bin"
    member.write_bytes(random.Random(7140).randbytes(8192))
    passwords = ["other-tail", "selected-tail"]
    archives = []
    for index, password in enumerate(passwords):
        archive = tmp_path / f"original-{index}.zip"
        run_cmd([str(require_7z()), "a", "-tzip", "-mx=0", "-mem=AES256",
                 f"-p{password}", str(archive), member.name], tmp_path)
        archives.append(archive.read_bytes())
    name_len, extra_len = struct.unpack_from("<HH", archives[0], 26)
    split = 30 + name_len + extra_len
    assert archives[0][:split] == archives[1][:split]
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    head = inputs / "split.zip.001"
    head.write_bytes(archives[0][:split])
    # Both verifiers are valid, but the preferred tail fails its member MAC.
    decoy = bytearray(archives[0][split:])
    decoy[16 + 2] ^= 1
    (inputs / "split.zip.002").write_bytes(decoy)
    (inputs / "split.zip.002.图片").write_bytes(archives[1][split:])
    output = tmp_path / "out"
    report = extract_report(package, head, output, passwords=passwords)
    assert report["summary"]["success_count"] == 1, report
    extracted, = output.rglob(member.name)
    assert extracted.read_bytes() == member.read_bytes()


def _archive(tmp_path, files, *, header):
    source = tmp_path / "source"
    source.mkdir()
    for name, data in files.items():
        (source / name).write_bytes(data)
    original = tmp_path / "original"
    original.mkdir()
    run_cmd([
        str(require_7z()), "a", str(original / "evidence.7z"),
        "-y", "-m0=Copy", "-ms=off", "-mhc=off", f"-mhe={'on' if header else 'off'}",
        f"-p{PASSWORD}", f"-v{VOLUME_SIZE}b", *files,
    ], source)
    parts = sorted(original.glob("evidence.7z.*"))
    assert len(parts) == 3
    run_cmd([str(require_7z()), "t", str(parts[0]), f"-p{PASSWORD}"], original)
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    return parts, inputs


def _extract_exact(package, head, tmp_path, expected, *, fixed_password_evidence=False):
    candidates = ["wrong-before", PASSWORD, "wrong-after"]
    if fixed_password_evidence:
        scan = package.json(
            "scan", "-d", "-npa",
            *[arg for password in candidates for arg in ("-p", password)], head,
        )
        assert scan["summary"]["failed_count"] == 0, scan
        assert scan["summary"]["archive_count"] == 1, scan
        assert scan["items"][0]["password_used"] == PASSWORD, scan
    output = tmp_path / "output"
    report = extract_report(
        package, head, output,
        passwords=candidates,
    )
    assert report["summary"]["success_count"] == 1, report
    assert report["summary"]["failed_count"] == 0, report
    actual = {path.name: path.read_bytes() for path in output.rglob("*") if path.is_file()}
    assert actual == expected


@pytest.mark.parametrize("extra_decoy_bytes", [0, 97], ids=["same-length", "different-length"])
def test_7z_data_evidence_in_alternative_middle(package, tmp_path, extra_decoy_bytes):
    # Copy's smallest CRC-verifiable substream is the 256-byte second file.
    # It lies in the middle disk, while its descriptor lives in the final disk.
    rng = random.Random(7117)
    files = {
        "00-before.bin": rng.randbytes(VOLUME_SIZE),
        "01-small.bin": rng.randbytes(256),
        "02-after.bin": rng.randbytes(64 * 1024),
    }
    parts, inputs = _archive(tmp_path, files, header=False)
    head, middle, tail = parts
    delivered = inputs / head.name
    copyfile(head, delivered)
    copyfile(tail, inputs / tail.name)
    copyfile(middle, inputs / f"{middle.name}.图片")
    damaged = bytearray(middle.read_bytes())
    # Data begins at logical 32, placing the small stream at middle offset 32.
    damaged[32] ^= 0xFF
    damaged.extend(b"decoy-padding" * (extra_decoy_bytes // 13) + b"x" * (extra_decoy_bytes % 13))
    decoy = inputs / middle.name
    decoy.write_bytes(damaged)
    _extract_exact(package, delivered, tmp_path, files)
    assert decoy.read_bytes() == damaged


@pytest.mark.parametrize("carrier", [False, True], ids=["ordinary", "carrier-head"])
def test_7z_encrypted_header_crosses_alternative_middle_and_tail(package, tmp_path, carrier):
    # A single AES/Copy payload ends 16 bytes before disk three. Consequently
    # the encrypted header starts in disk two and continues into disk three.
    payload_size = 2 * VOLUME_SIZE - 32 - 16
    files = {"payload.bin": random.Random(7118).randbytes(payload_size)}
    parts, inputs = _archive(tmp_path, files, header=True)
    head, middle, tail = parts
    delivered = inputs / (head.name + (".图片" if carrier else ""))
    if carrier:
        assemble_carrier(delivered, [head], prefix_lengths=[137], seed=7118)
    else:
        copyfile(head, delivered)
    copyfile(tail, inputs / tail.name)
    copyfile(middle, inputs / f"{middle.name}.图片")
    full = b"".join(part.read_bytes() for part in parts)
    next_offset = 32 + int.from_bytes(full[12:20], "little")
    encrypted_header_start = 32 + payload_size
    assert encrypted_header_start < 2 * VOLUME_SIZE < next_offset
    damaged = bytearray(middle.read_bytes())
    damaged[encrypted_header_start - VOLUME_SIZE] ^= 0xFF
    decoy = inputs / middle.name
    decoy.write_bytes(damaged)
    _extract_exact(package, delivered, tmp_path, files)
    assert decoy.read_bytes() == damaged


def test_7z_correct_tail_trailing_junk_and_corrupt_alternative(package, tmp_path):
    files = {"payload.bin": random.Random(7119).randbytes(104 * 1024)}
    parts, inputs = _archive(tmp_path, files, header=True)
    head, middle, tail = parts
    delivered = inputs / head.name
    copyfile(head, delivered)
    copyfile(middle, inputs / middle.name)
    # Only the correct tail has trailing junk; right-aligning both physical
    # extents to NextHeader.end would discard that valid password evidence.
    correct = inputs / f"{tail.name}.图片"
    correct.write_bytes(tail.read_bytes() + b"unrelated trailing carrier bytes" * 5)
    full = b"".join(part.read_bytes() for part in parts)
    next_offset = 32 + int.from_bytes(full[12:20], "little")
    damaged = bytearray(tail.read_bytes())
    damaged[next_offset - 16 - 2 * VOLUME_SIZE] ^= 0xFF
    decoy = inputs / tail.name
    decoy.write_bytes(damaged)
    _extract_exact(package, delivered, tmp_path, files)
    assert decoy.read_bytes() == damaged


def test_7z_fixed_header_proves_password_with_unresolved_data_middle(package, tmp_path):
    # The encrypted header and its public descriptor are wholly in the fixed
    # tail. Alternatives in the middle affect payload extraction, not this
    # independently sufficient password proof.
    files = {"payload.bin": random.Random(7120).randbytes(104 * 1024)}
    parts, inputs = _archive(tmp_path, files, header=True)
    head, middle, tail = parts
    delivered = inputs / head.name
    copyfile(head, delivered)
    copyfile(tail, inputs / tail.name)
    copyfile(middle, inputs / f"{middle.name}.图片")
    damaged = bytearray(middle.read_bytes())
    damaged[len(damaged) // 2] ^= 0xFF
    decoy = inputs / middle.name
    decoy.write_bytes(damaged)
    _extract_exact(package, delivered, tmp_path, files, fixed_password_evidence=True)
    assert decoy.read_bytes() == damaged
