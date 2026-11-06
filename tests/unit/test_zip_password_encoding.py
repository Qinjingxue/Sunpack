import ctypes
import json
import struct
import subprocess
import zlib

import pytest

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor

from sunpack.core.passwords.verifier.zip_fast import ZipFastVerifier
from sunpack.core.support.resources import get_sevenzip_bridge_worker_path


PASSWORD = "密码"
PAYLOAD = b"gbk zipcrypto payload"


def _require_gbk_ansi_codepage():
    if ctypes.windll.kernel32.GetACP() != 936:
        pytest.skip("fixture password bytes assume the GBK (936) ANSI codepage")


def _crc_table():
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ 0xEDB88320 if value & 1 else value >> 1
        table.append(value)
    return table


_CRC_TABLE = _crc_table()


class _ZipCryptoEncryptor:
    def __init__(self, password: bytes):
        self.keys = [0x12345678, 0x23456789, 0x34567890]
        for byte in password:
            self._update(byte)

    def _crc(self, crc: int, byte: int) -> int:
        return (crc >> 8) ^ _CRC_TABLE[(crc ^ byte) & 0xFF]

    def _update(self, byte: int) -> None:
        self.keys[0] = self._crc(self.keys[0], byte)
        self.keys[1] = ((self.keys[1] + (self.keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.keys[2] = self._crc(self.keys[2], self.keys[1] >> 24)

    def encrypt(self, data: bytes) -> bytes:
        output = bytearray()
        for byte in data:
            temp = (self.keys[2] | 2) & 0xFFFF
            output.append(byte ^ (((temp * (temp ^ 1)) >> 8) & 0xFF))
            self._update(byte)
        return bytes(output)


def _write_ansi_password_zip(path, name: str = "secret.txt", *, password_bytes=None):
    """Build a stored ZipCrypto entry keyed by the ANSI (GBK) password bytes,
    as WinRAR/Bandizip/Explorer produce on Chinese Windows."""
    crc = zlib.crc32(PAYLOAD) & 0xFFFFFFFF
    header = bytes(range(1, 12)) + bytes([crc >> 24])
    encrypted = _ZipCryptoEncryptor(password_bytes or PASSWORD.encode("gbk")).encrypt(header + PAYLOAD)
    raw_name = name.encode("ascii")
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50, 20, 1, 0, 0, 0, crc,
        len(encrypted), len(PAYLOAD), len(raw_name), 0,
    ) + raw_name + encrypted
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50, 20, 20, 1, 0, 0, 0, crc,
        len(encrypted), len(PAYLOAD), len(raw_name),
        0, 0, 0, 0, 0, 0,
    ) + raw_name
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    path.write_bytes(local + central + eocd)


def test_fast_verifier_matches_non_ascii_password_with_ansi_bytes(tmp_path):
    _require_gbk_ansi_codepage()
    archive = tmp_path / "gbk-password.zip"
    _write_ansi_password_zip(archive)

    verification = ZipFastVerifier().verify_batch(str(archive), ["wrong", PASSWORD])

    assert verification.status == "match"
    assert 1 in verification.matched_indices


def test_worker_extracts_with_the_password_the_fast_verifier_accepts(tmp_path):
    _require_gbk_ansi_codepage()
    try:
        worker = get_sevenzip_bridge_worker_path()
    except Exception as exc:
        pytest.skip(f"sunpack_sevenzip_worker.exe is required: {exc}")
    archive = tmp_path / "gbk-password.zip"
    _write_ansi_password_zip(archive)
    out_dir = tmp_path / "out"

    result = subprocess.run(
        [worker],
        input=json.dumps(
            {
                "job_id": "gbk-password",
                "archive_input": ArchiveInputDescriptor.from_parts(archive_path=str(archive), format_hint="zip").to_dict(),
                "output_dir": str(out_dir),
                "password": PASSWORD,
            },
            ensure_ascii=False,
        ),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert (out_dir / "secret.txt").read_bytes() == PAYLOAD


@pytest.mark.parametrize("layout", ["file", "carrier", "raw_split", "spanned"])
def test_eocd_signatures_in_comments_preserve_planned_password_input(tmp_path, layout):
    # One fixture covers logical coordinate reuse and the shared pre-planning
    # fallback. Plain encryption tests cannot find this valid-comment failure.
    from sunpack.core.config.loader import load_config
    from sunpack.pipeline.coordinator.task_scan import direct_file_task
    from sunpack.pipeline.discovery.detection.input_planning import ArchiveInputPlanningStage
    from sunpack.core.support import archive_knowledge_projection as knowledge_view
    from sunpack_native import zip_fast_verify_passwords

    password = "comment-secret"
    seed = tmp_path / "seed.zip"
    _write_ansi_password_zip(seed, password_bytes=password.encode())
    data = seed.read_bytes()
    comment = b"PK\x05\x06" + b"comment data" * 4 + b"PK\x05\x06 end"
    payload = data[:-2] + struct.pack("<H", len(comment)) + comment
    parts = []
    if layout == "carrier":
        archive = tmp_path / "carrier.dat"
        archive.write_bytes(b"carrier-prefix" + payload + b"carrier-suffix")
    elif layout == "raw_split":
        archive = tmp_path / "raw.dat.001"
        second = tmp_path / "raw.dat.002"
        split = len(payload) // 2
        archive.write_bytes(payload[:split])
        second.write_bytes(payload[split:])
        parts = [str(archive), str(second)]
    elif layout == "spanned":
        archive = tmp_path / "split.z01"
        second = tmp_path / "split.zip"
        central = payload.index(b"PK\x01\x02")
        last = bytearray(payload[central:])
        eocd = len(data) - 22 - central
        struct.pack_into("<HH", last, eocd + 4, 1, 1)
        struct.pack_into("<I", last, eocd + 16, 0)
        archive.write_bytes(payload[:central])
        second.write_bytes(last)
        parts = [str(archive), str(second)]
    else:
        archive = tmp_path / "plain.dat"
        archive.write_bytes(payload)
        assert zip_fast_verify_passwords(str(archive), ["wrong", password])["status"] == "match"
    task = direct_file_task(str(archive), all_parts=parts or [str(archive)])
    ArchiveInputPlanningStage(load_config()).plan_task(task)
    descriptor = (task.password_probe_input or task.archive_input()).to_dict()
    assert "zip_eocd_offset" in descriptor.get("analysis", {}), descriptor
    outcome = ZipFastVerifier().verify_batch(str(archive), ["wrong", password],
        part_paths=parts or None, archive_input=descriptor)
    assert outcome.status == "match", outcome
    assert 1 in outcome.matched_indices
