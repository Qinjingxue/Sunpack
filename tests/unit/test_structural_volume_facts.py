from __future__ import annotations

import struct
from pathlib import Path
from zlib import crc32

from sunpack.core.analysis.volume_anchor import probe_volume_anchor_paths
from sunpack.pipeline.discovery.relations.scheduler import RelationsScheduler


def _vint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _rar5(body, suffix=b""):
    header = _vint(len(body)) + body
    return b"Rar!\x1a\x07\x01\x00" + struct.pack("<I", crc32(header)) + header + suffix


def _local(name, payload=b"data", extra=b""):
    return struct.pack("<4s5H3L2H", b"PK\x03\x04", 20, 0, 0, 0, 0,
                       crc32(payload), len(payload), len(payload), len(name), len(extra)) + name + extra + payload


def test_variable_headers_and_malformed_rar_numbers_do_not_lose_or_invent_identity(tmp_path):
    """Covers declared-header completion and out-of-header/overflow identities;
    the short-header anchor tests cannot detect either failure. Tiny fixtures
    exercise both positive and negative sides without archive extraction.
    """
    metadata = b"\x02\x01" + _vint(600) + b"a" * 600
    extra = _vint(len(metadata)) + metadata
    cases = {
        "long-rar": (_rar5(b"\x01\x01" + _vint(len(extra)) + b"\x03\x02" + extra), "rar", 3),
        "long-zip": (b"PK\x07\x08" + _local(b"x", extra=struct.pack("<HH", 0xcafe, 600) + b"x" * 600), "zip", 1),
        "rar-outside": (_rar5(b"\x01\x00\x03", b"\x07"), "", None),
        "rar-wrap": (_rar5(b"\x01\x00\x03" + _vint(0x100000001)), "", None),
        "rar-vint-overflow": (_rar5(b"\x01\x00\x03" + b"\xff" * 9 + b"\x02"), "", None),
        "false-rar-header": (b"Rar!\x1a\x07\x01\x00" + bytes(4) + _vint(5000) + bytes(600), "", None),
    }
    invalid = bytearray(_local(b"x", extra=struct.pack("<HH", 0xcafe, 600) + b"x" * 600))
    invalid[4:6] = b"\xff\xff"
    cases["bad-zip-header"] = (bytes(invalid) + b"x" * 70_000, "", None)
    paths = []
    for name, (data, _, _) in cases.items():
        path = tmp_path / name
        path.write_bytes(data)
        paths.append(str(path))
    facts = probe_volume_anchor_paths(paths)
    for path in paths:
        fact = facts.get(path)
        _, expected_format, expected_number = cases[Path(path).name]
        assert (fact.format, fact.internal_volume_number) == (expected_format, expected_number)
        assert fact.error == ""
        if Path(path).name == "bad-zip-header":
            assert fact.bytes_read <= 512 + 65_557


def test_zip_directory_numbers_override_names_and_keep_carrier_extent(tmp_path):
    """Only this case has false names on multiple physical local-header disks
    plus a terminal hidden outside the EOCD window. It also checks that a
    duplicate physical candidate cannot silently steal a directory identity.
    """
    from sunpack.pipeline.discovery.relations.internal.archive_input import archive_input_for_group

    names = [b"first", b"middle", b"last"]
    paths = [tmp_path / f"shared.part{n}.opaque" for n in (9, 8, 7, 6)]
    paths[0].write_bytes(b"PK\x07\x08" + _local(names[0]))
    paths[1].write_bytes(_local(names[1]))
    paths[2].write_bytes(_local(names[2]))
    directory = b"".join(
        struct.pack("<4s6H3L5H2L", b"PK\x01\x02", 20, 20, 0, 0, 0, 0,
                    crc32(b"data"), 4, 4, len(name), 0, 0, disk, 0, 0, 4 if disk == 0 else 0) + name
        for disk, name in enumerate(names)
    )
    terminal = directory + struct.pack("<4s4H2LH", b"PK\x05\x06", 3, 3, 3, 3, len(directory), 0, 0)
    paths[3].write_bytes(terminal + b"carrier-padding" * 6000)
    scheduler = RelationsScheduler()
    group = scheduler.resolve_volume_once([str(paths[0])], [str(p) for p in paths], format_hint="zip")
    assert group is not None and group.head_metadata.get("volume_set_incomplete") is not True
    assert [(part.path, part.number) for part in group.split_volumes] == [(str(p), n) for n, p in enumerate(paths, 1)]
    descriptor = archive_input_for_group(group)
    assert descriptor.parts[-1].extent.end == len(terminal)
    duplicate = tmp_path / "shared.noise"
    duplicate.write_bytes(paths[1].read_bytes())
    group = scheduler.resolve_volume_once([str(paths[0])], [str(p) for p in [*paths, duplicate]], format_hint="zip")
    assert group is not None and group.volume_attempts
    plan = archive_input_for_group(group).volume_attempts
    for layout in plan.layouts:
        slots = {slot.number: {plan.sources[i].path for i in slot.choices} for slot in layout}
        assert slots == {1: {str(paths[0])}, 2: {str(paths[1]), str(duplicate)},
                         3: {str(paths[2])}, 4: {str(paths[3])}}
    assert next(source for source in plan.sources if source.path == str(paths[3])).end == len(terminal)


def test_zip64_long_comment_retains_terminal_number(tmp_path):
    """The existing ZIP64 case has no comment, so cannot notice a locator
    outside the EOCD window. One small terminal tests that independent gap.
    """
    prefix = b"x" * 2000
    end64 = struct.pack("<4sQ2H2I4Q", b"PK\x06\x06", 44, 45, 45, 70000, 69999, 0, 0, 0, 0)
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 70000, len(prefix), 70001)
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 65535, 65535, 0, 0, 0, 0, 65535) + b"a" * 65535
    path = tmp_path / "terminal.opaque"
    path.write_bytes(prefix + end64 + locator + end)
    fact = probe_volume_anchor_paths([str(path)]).get(str(path))
    assert fact.error == "" and fact.internal_volume_number == 70001


def test_seven_zip_next_header_constrains_names_and_checks_cross_volume_crc(tmp_path):
    """Equal-size chunks defeat size-only validation. Two competing name
    channels require terminal structure, then a header spanning chunks checks
    the independent mapped-range path; mutation must invalidate that mapping.
    """
    paths = [tmp_path / name for name in ("shared.part1.chunk1", "shared.part3.chunk2", "shared.part2.chunk3")]

    def write_parts(next_header):
        start = struct.pack("<QQI", 384 - 32 - len(next_header), len(next_header), crc32(next_header))
        archive = b"7z\xbc\xaf'\x1c\x00\x04" + struct.pack("<I", crc32(start)) + start
        archive += b"x" * (384 - len(archive) - len(next_header)) + next_header
        # Compressed continuation bytes may resemble a truncated foreign head.
        # This must remain a usable opaque 7z member, even during refinement.
        fake = b"Rar!\x1a\x07\x01\x00" + bytes(4) + _vint(5000)
        archive = archive[:128] + fake + archive[128 + len(fake):]
        for i, path in enumerate(paths):
            path.write_bytes(archive[i * 128:(i + 1) * 128])

    scheduler = RelationsScheduler()
    write_parts(b"\x01\x00")
    group = scheduler.resolve_volume_once([str(paths[0])], [str(p) for p in paths], format_hint="7z")
    assert group is not None and group.head_metadata.get("volume_set_incomplete") is not True
    assert [part.path for part in group.split_volumes] == [str(p) for p in paths]
    for n, path in enumerate(paths, 1):
        target = tmp_path / f"shared.7z.{n:03}"
        path.rename(target)
        paths[n - 1] = target
    write_parts(b"\x01" + b"x" * 159)
    group = scheduler.resolve_volume_once([str(paths[0])], [str(p) for p in paths], format_hint="7z")
    assert group is not None and group.head_metadata.get("volume_set_incomplete") is not True
    data = bytearray(paths[1].read_bytes())
    data[-1] ^= 1
    paths[1].write_bytes(data)
    group = scheduler.resolve_volume_once([str(paths[0])], [str(p) for p in paths], format_hint="7z")
    assert group is None or group.head_metadata.get("volume_set_incomplete") is True
