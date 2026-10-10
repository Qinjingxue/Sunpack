import struct

import pytest
from sunpack_native import (
    AnalysisBinaryView,
    inspect_zip_directory_consistency,
    inspect_zip_eocd_structure,
    inspect_zip_structure_graph,
)

from sunpack.core.analysis import ArchiveAnalyzer


def _zip_details(volumes) -> dict:
    report = ArchiveAnalyzer().analyze(volumes)
    return next(item for item in report.evidences if item.format == "zip").details


def _local(name=b"a"):
    return struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, 0, 0, 0, len(name), 0) + name


def _central(name=b"a", *, local_offset=0, disk_start=0, extra=b""):
    return struct.pack(
        "<4sHHHHHHIIIHHHHHII",
        b"PK\x01\x02", 20, 20, 0, 0, 0, 0, 0, 0, 0,
        len(name), len(extra), 0, disk_start, 0, 0, local_offset,
    ) + name + extra


def test_zip_probe_maps_spanned_disk_relative_offsets(tmp_path):
    first = tmp_path / "archive.z01"
    last = tmp_path / "archive.zip"
    first.write_bytes(_local())
    central = _central(disk_start=0)
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 1, 1, 1, 1, len(central), 0, 0)
    last.write_bytes(central + eocd)
    result = _zip_details([
        {"path": str(first), "number": 1, "style": "zip_spanned"},
        {"path": str(last), "number": 2, "style": "zip_spanned"},
    ])

    assert result["error"] == ""
    assert result["plausible"] is True
    assert result["is_multi_disk"] is True
    assert result["central_directory_disk"] == 1
    assert result["declared_total_disks"] == 2
    assert result["local_header_links_ok"] is True
    assert "zip:multi_disk_offsets" in result["evidence"]


@pytest.mark.parametrize("layout", ["plain", "carrier", "split_carrier"])
@pytest.mark.parametrize("invalid_field", [None, "locator", "size", "offset", "sum"])
def test_zip64_bounds_are_shared_by_analysis_and_inspectors(tmp_path, layout, invalid_field):
    # Unique coverage: malformed ZIP64 declarations must not become plausible
    # through carrier scanning or split mapping. Normal archive tests cannot
    # catch that false acceptance; these tiny fixtures cost only bounded reads.
    local = _local()
    central = _central()
    zip64_offset = len(local) + len(central)
    cd_size = len(central)
    cd_offset = len(local)
    locator_offset = zip64_offset
    if invalid_field == "locator":
        locator_offset = 1 << 63
    elif invalid_field == "size":
        cd_size = 1 << 63
    elif invalid_field == "offset":
        cd_offset = 1 << 63
    elif invalid_field == "sum":
        cd_offset = (1 << 63) - cd_size
    zip64 = struct.pack(
        "<4sQHHIIQQQQ",
        b"PK\x06\x06", 44, 45, 45, 0, 0, 1, 1, cd_size, cd_offset,
    )
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, locator_offset, 1)
    eocd = struct.pack(
        # Non-sentinel classic fields must not mask an invalid ZIP64 record.
        "<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1,
        len(central), len(local), 0,
    )
    prefix = b"carrier-prefix" if layout != "plain" else b""
    suffix = b"carrier-suffix" if layout != "plain" else b""
    payload = prefix + local + central + zip64 + locator + eocd + suffix
    path = tmp_path / "disguised.jpg"
    path.write_bytes(payload)
    view = AnalysisBinaryView(str(path))
    try:
        probe = dict(view.probe_zip(len(payload) - len(suffix) - len(eocd), 16))
    finally:
        view.close()
    expected_error = (
        "zip64_locator_offset_overflow" if invalid_field == "locator"
        else "zip64_central_directory_overflow" if invalid_field else ""
    )
    assert probe["plausible"] is (invalid_field is None)
    assert probe["error"] == expected_error

    if layout == "plain":
        for inspect in (
            inspect_zip_eocd_structure,
            inspect_zip_directory_consistency,
            inspect_zip_structure_graph,
        ):
            assert dict(inspect(str(path), 16))["error"] == expected_error
    if layout == "split_carrier":
        # The ZIP64 fields themselves straddle a raw split boundary.
        split = len(prefix) + zip64_offset + 43
        first = tmp_path / "disguised.jpg.0000"
        last = tmp_path / "disguised.jpg.0001"
        first.write_bytes(payload[:split])
        last.write_bytes(payload[split:])
        source = [
            {"path": str(first), "number": 1, "style": "zip_zero_numbered"},
            {"path": str(last), "number": 2, "style": "zip_zero_numbered"},
        ]
    else:
        source = str(path)
    report = ArchiveAnalyzer().analyze(source)
    details = [item.details for item in report.evidences if item.format == "zip"]
    if invalid_field is None:
        assert any(item.get("plausible") is True for item in details)
    else:
        assert not any(item.get("plausible") is True for item in details)


def test_zip_probe_resolves_zip64_tail_and_central_extra_across_raw_splits(tmp_path):
    local = _local()
    zip64_values = struct.pack("<QQQ", 0, 0, 0)
    extra = struct.pack("<HH", 0x0001, len(zip64_values)) + zip64_values
    central = _central(local_offset=0xFFFFFFFF, extra=extra)
    zip64_offset = len(local) + len(central)
    zip64 = struct.pack(
        "<4sQHHIIQQQQ",
        b"PK\x06\x06", 44, 45, 45, 0, 0, 1, 1, len(central), len(local),
    )
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, zip64_offset, 1)
    eocd = struct.pack(
        "<4sHHHHIIH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0,
    )
    archive = local + central + zip64 + locator + eocd
    split = len(local) + 7
    first = tmp_path / "archive.zip.0000"
    second = tmp_path / "archive.zip.0001"
    first.write_bytes(archive[:split])
    second.write_bytes(archive[split:])
    result = _zip_details([
        {"path": str(first), "number": 1, "style": "zip_zero_numbered"},
        {"path": str(second), "number": 2, "style": "zip_zero_numbered"},
    ])

    assert result["error"] == ""
    assert result["plausible"] is True
    assert result["zip64"] is True
    assert result["central_directory_offset"] == len(local)
    assert result["total_entries"] == 1
    assert result["local_header_links_ok"] is True
