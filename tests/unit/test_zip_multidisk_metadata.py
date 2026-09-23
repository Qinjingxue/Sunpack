import struct

from sunpack.core.analysis.view import MultiVolumeBinaryView, _probe_zip_view


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
    view = MultiVolumeBinaryView([
        {"path": str(first), "number": 1, "style": "zip_spanned"},
        {"path": str(last), "number": 2, "style": "zip_spanned"},
    ])

    result = _probe_zip_view(view, len(_local()) + len(central), 32)

    assert result["error"] == ""
    assert result["plausible"] is True
    assert result["is_multi_disk"] is True
    assert result["central_directory_disk"] == 1
    assert result["declared_total_disks"] == 2
    assert result["local_header_links_ok"] is True
    assert "zip:multi_disk_offsets" in result["evidence"]


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
    view = MultiVolumeBinaryView([
        {"path": str(first), "number": 1, "style": "zip_zero_numbered"},
        {"path": str(second), "number": 2, "style": "zip_zero_numbered"},
    ])

    result = _probe_zip_view(view, len(archive) - len(eocd), 32)

    assert result["error"] == ""
    assert result["plausible"] is True
    assert result["zip64"] is True
    assert result["central_directory_offset"] == len(local)
    assert result["total_entries"] == 1
    assert result["local_header_links_ok"] is True
