"""RAR4 data-only split members cannot use a fragment CRC as a password check."""
import random

import pytest

from tests.helpers.native_fixture import assemble_carrier
from tests.helpers.real_archives import run_cmd
from tests.helpers.tool_config import get_optional_rar
from tests.real.archive_boundary import extract_report, failure_kinds, require_generator


@pytest.mark.parametrize("carrier", [False, True, "ambiguous"],
                         ids=["ordinary", "carrier-disguised", "ambiguous-tail"])
def test_rar4_stored_first_member_crosses_volumes(package, tmp_path, carrier):
    # Existing encrypted-volume fixtures encrypt headers or start with a small
    # marker. This forces the first password-verifiable member across volumes.
    require_generator("rar")
    source = tmp_path / "source"
    source.mkdir()
    payload = random.Random(7304).randbytes(192 * 1024 + 7)
    (source / "large.bin").write_bytes(payload)
    original = tmp_path / "original"
    original.mkdir()
    run_cmd([str(get_optional_rar()), "a", "-ma4", "-m0", "-psecret", "-ep", "-y",
             "-v48k", str(original / "archive.rar"), "large.bin"], source)
    parts = sorted(original.glob("*.rar"))
    assert len(parts) > 1
    run_cmd([str(get_optional_rar()), "t", "-psecret", "-y", str(parts[0])], original)
    inputs = original
    if carrier:
        inputs = tmp_path / "inputs"
        inputs.mkdir()
        for index, part in enumerate(parts):
            assemble_carrier(inputs / (part.name + ".jpg"), [part],
                             prefix_lengths=[137 + index * 29], seed=7304 + index)
    if carrier == "ambiguous":
        # Same metadata and final CRC, but a different ciphertext tail. The
        # preferred canonical name must not reject a password which opens the
        # later carrier choice. The final fragment has no packed-data CRC.
        decoy = bytearray(parts[-1].read_bytes())
        main_size = int.from_bytes(decoy[12:14], "little")
        file_offset = 7 + main_size
        header_size = int.from_bytes(decoy[file_offset + 5:file_offset + 7], "little")
        decoy[file_offset + header_size] ^= 0xFF
        (inputs / parts[-1].name).write_bytes(decoy)
        inputs = inputs / (parts[0].name + ".jpg")
    wrong = ["wrong-a", "wrong-b", "wrong-c", "wrong-d"]
    rejected = extract_report(package, inputs, tmp_path / "rejected", passwords=wrong, code=1)
    assert failure_kinds(rejected) == ({"password_inconclusive"} if carrier == "ambiguous" else {"wrong_password"}), rejected
    candidates = [*wrong[:2], "secret", *wrong[2:]]
    scan = package.json("scan", "-d", "-npa",
                        *[arg for password in candidates for arg in ("-p", password)], inputs)
    assert scan["summary"]["failed_count"] == 0, scan
    assert scan["summary"]["archive_count"] == 1, scan
    if carrier == "ambiguous":
        # The selected member authenticates the key. Scan retains the still
        # untested volume choices until full extraction validates the archive.
        item = scan["items"][0]
        assert item["password_used"] == "secret", scan
        assert item["volume_completeness"] == "pending", scan
        assert item["volume_attempts"]["layouts"] and item["volume_attempts"]["sources"], scan
    else:
        assert scan["items"][0]["password_used"] == "secret", scan
    output = tmp_path / "output"
    report = extract_report(package, inputs, output, passwords=candidates)
    assert report["summary"]["success_count"] == 1, report
    member, = output.rglob("large.bin")
    assert member.read_bytes() == payload


def test_rar4_tiny_crc_collision_requires_later_member_confirmation(package, tmp_path, repo_root):
    # RAR 6.22: -ma4 -m0 -ds -ep -psecret, a.bin=K then z.bin=Z*2048.
    # rar-collision-287 also decrypts a.bin to K, but fails z.bin's CRC.
    # This fixed fixture was independently verified with RAR t: wrong key
    # reports a.bin OK / z.bin checksum error; secret reports All OK.
    archive = tmp_path / "tiny-crc.rar"
    archive.write_bytes((repo_root / "tests/data/rar4_tiny_crc_collision.rar").read_bytes())
    bad = "rar-collision-287"
    rejected = package.json("scan", "-d", "-npa", "-p", bad, archive, code=1)
    assert rejected["items"][0]["error_kind"] == "wrong_password", rejected
    scan = package.json("scan", "-d", "-npa", "-p", bad, "-p", "secret", archive)
    assert scan["items"][0]["password_used"] == "secret", scan
    package.configure(post_extract={"flatten_single_directory": False})
    for existing in (False, True):
        assert package.run("--persistent-shutdown").returncode == 0
        output = tmp_path / ("existing" if existing else "fresh")
        sentinel = output / "tiny-crc" / "keep.txt"
        if existing:
            sentinel.parent.mkdir(parents=True)
            sentinel.write_text("user content", encoding="utf-8")
        report = package.json("extract", "-d", "-npa", "-nf", "-c", "k", "-o", output,
                              "-p", bad, "-p", "secret", archive)
        assert report["summary"]["success_count"] == 1, report
        assert report["summary"]["failed_count"] == 0, report
        for name, expected in {"a.bin": b"K", "z.bin": b"Z" * 2048}.items():
            assert [path.read_bytes() for path in output.rglob(name)] == [expected]
        if existing:
            assert sentinel.read_text(encoding="utf-8") == "user content"


def test_rar4_encrypted_solid_ppmd_extracts_across_model_growth(package, tmp_path):
    require_generator("rar")
    source = tmp_path / "source"
    source.mkdir()
    rng = random.Random(4108)
    words = [f"{rng.getrandbits(40):010x}" for _ in range(8192)]
    payloads = {
        name: ("\n".join(" ".join(rng.choices(words, k=32)) for _ in range(3000)) + "\n").encode()
        for name in ("a.txt", "b.txt")
    }
    for name, payload in payloads.items():
        (source / name).write_bytes(payload)
    archive = tmp_path / "solid-text.rar"
    run_cmd([str(get_optional_rar()), "a", "-ma4", "-m5", "-mc8:1t+", "-s",
             "-psecret", "-ep", "-y", str(archive), *payloads], source)
    output = tmp_path / "output"
    report = extract_report(package, archive, output, passwords=["wrong", "secret"])
    assert report["summary"]["success_count"] == 1, report
    for name, payload in payloads.items():
        assert [path.read_bytes() for path in output.rglob(name)] == [payload]
