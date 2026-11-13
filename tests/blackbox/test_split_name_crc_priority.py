"""Actual RAR5 CRC failure after strong password verification, without fallback."""
import pytest


@pytest.mark.parametrize("name,kind", [("damaged.rar", "wrong_password"), ("damaged.part1.rar", "damaged"), ("damaged.001", "damaged")])
def test_standalone_encrypted_zero_output_crc_uses_main_filename_priority(package, tmp_path, name, kind):
    # Rar.exe -ma5 -pfixture-secret empty.txt; flip file CRC only and recompute
    # header CRC. Password-check material and encrypted empty payload are intact.
    archive = tmp_path / name
    archive.write_bytes(bytes.fromhex("526172211a0701003392b5e50a010506000501018080008a62226f5602033c900004800020f3fb9d3480030009656d7074792e747874300100030fc158f9f72a8a60deac71c55038893cb96cb382897dc38faecfa30178159a57fef8b9270f906fe93e7b7fc00e0a0302a407e8858873dd013379d310ce9749ee7cfcdda57d3390581d77565103050400"))
    result = package.json("extract", archive, "--direct", "-p", "fixture-secret", "--no-bpw",
                          "-o", tmp_path / "output", code=1)
    assert result["tasks"][0]["failures"][0]["kind"] == kind
    assert result["summary"]["password_retry_count"] == 0
    assert result["summary"]["success_count"] == 0
    assert result["summary"]["failed_count"] == 1
    assert result["tasks"][0]["wrong_password_failure"] == (kind == "wrong_password")
