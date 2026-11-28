"""Read view selection through public scan, extraction and durable Watch recovery."""
import bz2
import gzip
import io
import itertools
import lzma
import random
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from tests.blackbox.test_format_volume_matrix import _carrier, _one_marker, PASSWORD
from tests.helpers.real_archives import (
    ArchiveFixtureFactory, create_encrypted_rar_archive, create_zip_multidisk_archive,
)


def _apate(data, mask):
    return mask + data[len(mask):] + data[:len(mask)][::-1] + len(mask).to_bytes(4, "little")


def test_stream_routes_share_formats_and_offsets_across_readers(package, tmp_path):
    package.configure(filesystem={"read_views": ["plain", "apate:1"]})
    sources = tmp_path / "sources"
    sources.mkdir()
    expected = {}
    frame = bz2.compress(b"one registered stream" * 31)
    for mapped in (False, True):
        for prefix in (b"", b"carrier prefix" * 4):
            path = sources / f"sample-{int(mapped)}-{len(prefix)}.blob"
            data = prefix + frame
            path.write_bytes(_apate(data, bytes(len(data))) if mapped else data)
            expected[path.name] = ("bzip2", len(prefix) or None, len(data) if prefix else None,
                                   [{"method": "apate", "depth": 1}] if mapped else None)
    for flags in [(), ("-d",)]:
        items = package.json("scan", *flags, sources)["items"]
        assert len(items) == len(expected)
        assert {Path(item["main_path"]).name: (item["format"], item.get("offset"),
                item.get("end_offset"), item.get("views")) for item in items} == expected


def test_exact_depth_and_multi_volume_scan_summary(package, tmp_path):
    package.configure(filesystem={"read_views": ["apate:2"]}, embedded_scan={"enabled": False})
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("inside.txt", b"two exact layers")
    path = tmp_path / "unknown.blob"
    masked = _apate(archive.getvalue(), bytes(1024))
    path.write_bytes(masked)
    assert package.json("scan", path)["items"] == []
    path.write_bytes(_apate(masked, b"mask"))
    entry, = package.json("scan", path)["items"]
    assert entry["views"] == [{"method": "apate", "depth": 2}]
    output = tmp_path / "extracted"
    package.json("extract", "-o", output, "-c", "k", path)
    inside, = output.rglob("inside.txt")
    assert inside.read_bytes() == b"two exact layers"

    parent = tmp_path / "container.zip"
    with zipfile.ZipFile(parent, "w") as outer:
        outer.writestr("child.blob", path.read_bytes())
    assert package.json("scan", parent)["items"] == []
    package.configure(filesystem={"read_views": ["plain", "apate:2"]}, embedded_scan={"enabled": True})
    nested = tmp_path / "nested"
    package.json("extract", "-r", "2", "-o", nested, "-c", "k", parent)
    inside, = nested.rglob("inside.txt")
    assert inside.read_bytes() == b"two exact layers"

    package.configure(filesystem={"read_views": ["plain", "apate:1", "apate:2"]})
    case, parts = _carrier(tmp_path, "zip-spanned", PASSWORD)
    for index, part in enumerate(parts[1:]):
        data = _apate(part.read_bytes(), b"JPEG")
        part.write_bytes(_apate(data, b"another mask") if index % 2 else data)
    result = package.json("scan", "-d", "-p", PASSWORD, parts[0])
    sibling, = (item for item in result["items"] if "views" not in item)
    assert sibling["format"] == "zip"
    group, = (item for item in result["items"] if "views" in item)
    assert group["views"] == [{"method": "plain"}, {"method": "apate", "depth": 1}, {"method": "apate", "depth": 2}]
    assert all("view" not in src for src in group.get("volume_attempts", {}).get("sources", []))
    output = tmp_path / "volumes"
    package.json("extract", "-d", "-p", PASSWORD, "-o", output, "-c", "k", parts[0])
    _one_marker(output, case)


def test_transformed_7z_continuation_replaces_missing_volume_result(package, tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path, "parts", "7z", split=True, compression_level=0,
        payload_size=64 * 1024, split_volume_size=24 * 1024,
    )
    last = max(case.archive_dir.iterdir())
    masked = last.with_suffix(last.suffix + ".jpg")
    last.rename(masked)
    mask = io.BytesIO()
    with gzip.GzipFile("mask.txt", "wb", fileobj=mask, mtime=0) as writer:
        writer.write(b"mask on opaque continuation")
    masked.write_bytes(_apate(masked.read_bytes(), mask.getvalue()))
    package.configure(filesystem={"read_views": ["plain", "apate:1"]})
    alias = case.archive_dir / "parts.fake"
    alias.write_bytes(b"filtered alias")
    package.configure(filesystem={"scan_filters_enabled": True, "scan_filters": [
        {"name": "blacklist", "enabled": True, "full_names": [{"value": alias.name, "regex": False}]},
    ]})
    for target, label in [(case.entry_path, "head"), (case.archive_dir, "directory"), (alias, "alias")]:
        output = tmp_path / label
        result = package.json("extract", "-o", output, "-c", "k", target)
        assert result["summary"]["failed_count"] == 0
        marker, = output.rglob(case.marker_name)
        assert marker.read_text(encoding="utf-8") == case.marker_text
        mask_entry, = output.rglob("mask.txt")
        assert mask_entry.read_bytes() == b"mask on opaque continuation"


def test_selected_mixed_carrier_keeps_ordinary_peers_and_restored_siblings(package, tmp_path):
    case, parts = _carrier(tmp_path, "rar5", PASSWORD)
    head = parts[0].read_bytes()
    parts[0].write_bytes(_apate(head, bytes(len(head))))
    for path in parts[1:]:
        path.write_bytes(bytes(1024) + path.read_bytes() + bytes(100))

    mask = io.BytesIO()
    with zipfile.ZipFile(mask, "w") as writer:
        writer.writestr("mask-sibling.txt", b"ordinary ZIP mask")
    parts[1].write_bytes(_apate(parts[1].read_bytes(), mask.getvalue()))

    # The same stem nominates this file for inspection but gives it no ownership.
    with zipfile.ZipFile(case.archive_dir / "shared.unrelated", "w") as writer:
        writer.writestr("unrelated.txt", b"another archive")
    package.configure(filesystem={"read_views": ["plain", "apate:1"]})
    for source, flags in [(parts[0], ()), (parts[1], ("-d",))]:
        output = tmp_path / ("out-" + source.name)
        result = package.json("extract", *flags, "-p", PASSWORD, "-c", "k", "-o", output, source)
        assert result["summary"]["failed_count"] == 0
        _one_marker(output, case)
        sibling, = output.rglob("mask-sibling.txt")
        assert sibling.read_bytes() == b"ordinary ZIP mask"
        assert not list(output.rglob("unrelated.txt"))


def test_two_depths_expose_one_reversed_embedded_archive(package, tmp_path):
    package.configure(filesystem={"read_views": ["apate:1", "apate:2"]})
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as writer:
        writer.writestr("shared.txt", b"one physical archive")
    child = _apate(bytes(64) + archive.getvalue() + bytes(43), b"JPG")
    source = tmp_path / "shared.blob"
    source.write_bytes(_apate(child, bytes(len(child))))
    output = tmp_path / "out"
    package.json("extract", "-d", "-o", output, "-c", "k", source)
    shared, = output.rglob("shared.txt")
    assert shared.read_bytes() == b"one physical archive"

    # The four trailing bytes also declare a one-byte mask, either via the
    # directory offset or the comment. The next view clips the verified EOCD
    # but keeps the second local header.
    for comment in (b"", b"long comment\x01\0\0\0"):
        ordinary = io.BytesIO()
        with zipfile.ZipFile(ordinary, "w", compression=zipfile.ZIP_STORED) as writer:
            writer.writestr("first.bin", bytes(72000))
            writer.writestr("second.txt", b"second member")
            writer.comment = comment
        assert ordinary.getvalue()[-4:] == b"\x01\0\0\0"
        source.write_bytes(_apate(ordinary.getvalue(), b"mask"))
        report = package.json("scan", "-d", source)
        item, = report["items"]
        assert item["format"] == "zip" and item["views"] == [{"method": "apate", "depth": 1}]


def test_deep_scan_rechecks_changed_chunks_after_plain_scan(package, tmp_path):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as writer:
        writer.writestr("seam.txt", b"restored across the mask boundary")
    # The local header straddles the changed prefix and the identical middle.
    # Its EOCD and several signature-free IOCP chunks survive in both views.
    mask = bytes(1024 * 1024)
    data = bytes(len(mask) - 2) + archive.getvalue() + bytes(4 * 1024 * 1024)
    source = tmp_path / "seam.blob"
    source.write_bytes(_apate(data, mask))
    package.configure(filesystem={"read_views": ["plain", "apate:1"]})
    out = tmp_path / "out"
    package.json("extract", "-d", "-c", "k", "-o", out, source)
    member, = out.rglob("seam.txt")
    assert member.read_bytes() == b"restored across the mask boundary"


def test_intermediate_stream_masks_use_their_own_boundary(package, tmp_path):
    from tests.real.enc_support import ENC_PASSWORD, ENC_VECTOR, ENC_MARKER_TEXT

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as writer:
        writer.writestr("payload.txt", b"restored ZIP")
    source = tmp_path / "carrier.blob"
    package.configure(filesystem={"read_views": ["apate:1", "apate:2"]})
    masks = [
        (lzma.compress(b"first") + bytes(8) + lzma.compress(b"second") + bytes(4), (),
         b"firstsecond"),
        (b"embedded prefix" + ENC_VECTOR.read_bytes(), ("-d", "-p", ENC_PASSWORD),
         ENC_VECTOR.with_name("expected.zip").read_bytes()),
    ]
    for i, (mask, flags, expected) in enumerate(masks):
        source.write_bytes(_apate(_apate(archive.getvalue(), mask), b"outer mask"))
        output = tmp_path / str(i)
        report = package.json("extract", *flags, "-o", output, "-c", "k", source)
        assert report["summary"]["failed_count"] == 0
        assert sorted(p.read_bytes() for p in output.rglob("*") if p.is_file()) == sorted([expected, b"restored ZIP"])

    # The mask has a declared end even when the restored data has no archive.
    opaque = b"not an archive" * 200
    for i, (views, source_bytes, flags) in enumerate([
        (["plain", "apate:1"], _apate(opaque, ENC_VECTOR.read_bytes()), ()),
        (["apate:1", "apate:2"], _apate(_apate(opaque, ENC_VECTOR.read_bytes()), b"JPG"), ("-d",)),
    ]):
        package.configure(filesystem={"read_views": views})
        source.write_bytes(source_bytes)
        output = tmp_path / f"opaque-{i}"
        package.json("extract", *flags, "-p", ENC_PASSWORD, "-c", "k", "-o", output, source)
        decoded, = [p for p in output.rglob("*") if p.is_file()]
        expected = ENC_MARKER_TEXT.encode() if "plain" in views else ENC_VECTOR.with_name("expected.zip").read_bytes()
        assert decoded.read_bytes() == expected

    # The physical gzip member can continue into the unchanged middle of an
    # Apate carrier. Its validated end then lies beyond the declared mask.
    stream = gzip.compress(b"cross-boundary gzip", mtime=0)
    source.write_bytes(_apate(bytes(8) + stream[8:] + archive.getvalue(), stream[:8]))
    package.configure(filesystem={"read_views": ["plain", "apate:1"]})
    output = tmp_path / "crossed"
    report = package.json("extract", "-o", output, "-c", "k", source)
    assert report["summary"]["failed_count"] == 0
    assert sorted(p.read_bytes() for p in output.rglob("*") if p.is_file()) == [b"cross-boundary gzip", b"restored ZIP"]


def test_raw_zip_volume_views_with_indistinguishable_local_headers(package, tmp_path):
    package.configure(filesystem={"read_views": ["plain", "apate:1"]}, embedded_scan={"enabled": False})
    files = {"one.txt": b"a" * 2048, "two.txt": b"b" * 3072}
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zipper:
        for name, payload in files.items():
            zipper.writestr(name, payload)
        second = zipper.getinfo("two.txt").header_offset
    data = archive.getvalue()
    parts = tmp_path / "parts"
    parts.mkdir()
    # Both views expose the same first local record. The directory fixes
    # the prefix length, and disk two begins at another valid local header.
    (parts / "image.001.blob").write_bytes(_apate(data[:second], data[:4]))
    (parts / "image.002.blob").write_bytes(data[second:second + 2048])
    (parts / "image.003.blob").write_bytes(_apate(data[second + 2048:], b"mask"))
    for flags, label in [((), "normal"), (("-d",), "deep")]:
        out = tmp_path / label
        result = package.json("extract", *flags, "-o", out, "-c", "k", parts)
        assert result["summary"]["failed_count"] == 0
        assert sorted((p.name, p.read_bytes()) for p in out.rglob("*.txt")) == sorted(files.items())


@pytest.mark.parametrize("kind", ["7z", "zip", "zip-spanned", "rar4", "rar5"])
def test_three_volume_view_permutations(package, tmp_path, kind):
    package.configure(filesystem={"read_views": ["plain", "apate:1", "apate:2"]})
    options = dict(password=PASSWORD, payload_size=150 * 1024, split_volume_size=64 * 1024)
    if kind == "zip-spanned":
        case = create_zip_multidisk_archive(tmp_path, kind, **options)
    elif kind in ("rar4", "rar5"):
        case = create_encrypted_rar_archive(
            tmp_path, kind, rar4=kind == "rar4", header_encrypt=True, split=True, **options)
    else:
        case = ArchiveFixtureFactory().create(
            tmp_path, kind, kind, compression_level=0, split=True, **options)
    parts = sorted(case.archive_dir.iterdir(), key=lambda p: (kind == "zip-spanned" and p.suffix == ".zip", p.name))
    assert len(parts) == 3
    disks = [part.read_bytes() for part in parts]
    parts = [p.rename(p.with_name(f"mixed.{i:03d}.blob")) for i, p in enumerate(parts, 1)]
    expected = sorted((name, meta["size"], meta["crc32"])
                      for name, meta in case.metadata["expected_files"].items())
    cases = list(itertools.product(range(3), repeat=3))
    if kind in ("7z", "zip", "zip-spanned"):
        cases.extend([(0, 1, 2), (1, 1, 0)])
    for index, depths in enumerate(cases):
        opaque = index >= 27
        if depths == (2, 2, 1):
            package.configure(filesystem={"read_views": ["apate:1", "apate:2"]})
        if index == 27:
            package.configure(filesystem={"read_views": ["plain", "apate:1", "apate:2"]})
            # Selecting an anonymous interior chunk must discover an embedded
            # first disk through the original filename-stem peer scope.
            parts = [p.rename(p.with_name(name)) for p, name in zip(parts, ("mixed.b", "mixed.a", "mixed.c"))]
            disks[0] = b"carrier prefix" * 17 + disks[0]
        for part, disk, depth in zip(parts, disks, depths):
            data = disk
            for layer in range(depth):
                # Include masks that preserve valid local headers and masks
                # that erase all of the disk's physical signatures.
                mask = (data[:8], bytes(len(data)), b"JPEG mask")[(index + layer) % 3]
                data = _apate(data, mask)
            part.write_bytes(data)
        target = [*parts, case.archive_dir][index % 4]
        flags = ("-d",) if index % 2 else ()
        if opaque:
            target = parts[1]
            flags = () if index == 27 else ("-d",)
        passwords = ("-p", "wrong-password", "-p", PASSWORD)
        if sorted(depths) == [0, 1, 2]:
            item, = package.json("scan", *flags, *passwords, target)["items"]
            assert item["views"] == [{"method": "plain"}, {"method": "apate", "depth": 1},
                                     {"method": "apate", "depth": 2}], (kind, depths, item)
            if opaque:
                assert item["offset"] == len(b"carrier prefix" * 17), (kind, depths, item)
        out = tmp_path / f"out-{index}"
        report = package.json("extract", *flags, *passwords, "-c", "k", "-o", out, target)
        assert report["summary"]["failed_count"] == 0, (kind, depths)
        assert _output_inventory(out) == expected, (kind, depths, target)


def _output_inventory(directory):
    return sorted((p.name, p.stat().st_size, zlib.crc32(p.read_bytes()))
                  for p in directory.rglob("*") if p.is_file())


def test_three_anonymous_interior_disks_require_independent_choices(package, tmp_path):
    package.configure(filesystem={"read_views": ["plain", "apate:1", "apate:3"]})
    case = create_zip_multidisk_archive(tmp_path, "anonymous", password=PASSWORD,
        payload_size=246 * 1024, split_volume_size=56 * 1024)
    parts = sorted(case.archive_dir.iterdir(), key=lambda p: (p.suffix == ".zip", p.name))
    assert len(parts) == 5
    renamed = []
    for part, suffix, depth in zip(parts, "edbac", (0, 1, 3, 0, 1)):
        path = part.rename(part.with_name(f"opaque.{suffix}"))
        data = path.read_bytes()
        for layer in range(depth):
            data = _apate(data, b"mask" + bytes([layer]))
        path.write_bytes(data)
        renamed.append(path)
    output = tmp_path / "out"
    package.json("extract", "-d", "-p", "wrong", "-p", PASSWORD, "-c", "k", "-o", output, renamed[2])
    assert _output_inventory(output) == sorted(
        (name, info["size"], info["crc32"]) for name, info in case.metadata["expected_files"].items())


@pytest.mark.parametrize("kind", ["zip", "zip-spanned", "7z"])
def test_two_volume_sets_with_shared_names_and_mask_disks(package, tmp_path, kind):
    package.configure(filesystem={"read_views": ["plain", "apate:1", "apate:3"]})
    disks = []
    inventories = []
    for name in ("first", "other"):
        options = dict(password=PASSWORD, payload_size=150 * 1024, split_volume_size=64 * 1024)
        if kind == "zip-spanned":
            case = create_zip_multidisk_archive(tmp_path, name, **options)
        else:
            case = ArchiveFixtureFactory().create(tmp_path, name, kind, split=True, compression_level=0, **options)
        parts = sorted(case.archive_dir.iterdir(),
                       key=lambda p: (kind == "zip-spanned" and p.suffix == ".zip", p.name))
        assert len(parts) == 3
        disks.append([p.read_bytes() for p in parts])
        inventories.append(sorted((name, info["size"], info["crc32"])
                                  for name, info in case.metadata["expected_files"].items()))

    expected = sorted(itertools.chain.from_iterable(inventories))
    inputs = tmp_path / "carriers"
    inputs.mkdir()
    for i, (first, other) in enumerate(zip(*disks), 1):
        if i == 1:
            first = b"prefix" + first
            other = b"padding" + other
        (inputs / f"shared.{i:03}.blob").write_bytes(_apate(first, other))
    passwords = ("-p", "wrong", "-p", PASSWORD)
    output = tmp_path / "shared-out"
    package.json("extract", "-d", *passwords, "-c", "k", "-o", output, inputs)
    assert _output_inventory(output) == expected

    if kind == "7z":
        return
    # Distinct terminal directories still have to share the unnamed candidate
    # pool when the two sets occupy six different files under the same stem.
    separate = tmp_path / "separate"
    separate.mkdir()
    for label, members, depths in zip(("alpha", "bravo"), disks, ((1, 0, 3), (0, 3, 1))):
        for i, (data, depth) in enumerate(zip(members, depths), 1):
            for _ in range(depth):
                data = _apate(data, bytes(len(data)))
            (separate / f"shared.{label}.{i:03}.blob").write_bytes(data)
    output = tmp_path / "separate-out"
    package.json("extract", *passwords, "-c", "k", "-o", output, separate)
    assert _output_inventory(output) == expected

    # Both terminal directories match the same head. The payload CRC
    # distinguishes the damaged first candidate from the valid tail.
    competing = tmp_path / "competing"
    competing.mkdir()
    head, middle, tail = disks[0]
    (competing / "set.001").write_bytes(_apate(head, b"AAAAA"))
    (competing / "set.002").write_bytes(middle)
    (competing / "set.003.a").write_bytes(bytes([tail[0] ^ 1]) + tail[1:])
    (competing / "set.003.b").write_bytes(_apate(tail, b"JPG"))
    output = tmp_path / "competing-out"
    package.json("extract", "-d", *passwords, "-c", "k", "-o", output, competing)
    assert _output_inventory(output) == inventories[0]


def test_recursive_ratio_keeps_selected_disks_peers(package, tmp_path):
    package.configure(filesystem={"read_views": ["plain", "apate:1", "apate:3"]},
                      embedded_scan={"recursive_candidate_ratio": 0.35})
    case = ArchiveFixtureFactory().create(tmp_path, "inner", "7z", split=True, password=PASSWORD,
        payload_size=150 * 1024, split_volume_size=64 * 1024, compression_level=0)
    parts = sorted(case.archive_dir.iterdir())
    assert len(parts) == 3
    small = io.BytesIO()
    with zipfile.ZipFile(small, "w") as sibling:
        sibling.writestr("unrelated.txt", b"below recursive threshold")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        for i, (part, depth) in enumerate(zip(parts, (1, 3, 1)), 1):
            data = part.read_bytes()
            for _ in range(depth):
                data = _apate(data, bytes(len(data)))
            archive.writestr(f"vol.{i:03}.blob", data)
        archive.writestr("unrelated.blob", _apate(small.getvalue(), b"mask"))
    output = tmp_path / "nested-out"
    package.json("extract", "-d", "-r", "*", "-p", PASSWORD, "-c", "k", "-o", output, outer)
    files = _output_inventory(output)
    assert [(n, s, c) for n, s, c in files if n != "unrelated.blob"] == sorted(
        (name, info["size"], info["crc32"]) for name, info in case.metadata["expected_files"].items())
    assert any(n == "unrelated.blob" for n, _, _ in files)

    # Normal mode discovers this head inside an admitted carrier. Its smaller
    # disks also contain prefixes, so geometry alone cannot recover the set.
    case, disks = _carrier(tmp_path / "prefixed", "rar5", PASSWORD)
    outer = tmp_path / "nested-rar.blob"
    packed = io.BytesIO()
    with zipfile.ZipFile(packed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index, part in enumerate(disks):
            data = (bytes(300000) if index == 0 else b"prefix" * 32) + part.read_bytes()
            archive.writestr(part.name, _apate(data, b"mask"))
    package.configure(filesystem={"read_views": ["apate:1"]})
    outer.write_bytes(_apate(packed.getvalue(), b"mask"))
    output = tmp_path / "prefixed-out"
    package.json("extract", "-r", "2", "-p", PASSWORD, "-o", output, "-c", "k", outer)
    _one_marker(output, case)


@pytest.mark.requires_watch_broker
def test_watch_restores_views_after_missing_volume_restart(package, tmp_path):
    case, parts = _carrier(tmp_path, "rar5", PASSWORD)
    for i, part in enumerate(parts):
        data = _apate(part.read_bytes(), b"header")
        part.write_bytes(_apate(data, bytes(64)) if i % 2 else data)
    missing = parts[1].read_bytes()
    parts[1].unlink()
    output = tmp_path / "out"
    package.configure(filesystem={"read_views": ["plain", "apate:1", "apate:2"]},
                      user_passwords=[PASSWORD], post_extract={"archive_cleanup_mode": "k"})
    package.json("watch", "add", "-d", "-o", output, case.archive_dir)
    with package.watch_session():
        package.await_watch_event("suspended_missing_volume", root=case.archive_dir)
    sibling, = output.rglob("sibling.txt")
    original = sibling.stat()
    assert package.run("--persistent-shutdown").returncode == 0
    parts[1].write_bytes(missing)
    with package.watch_session():
        package.await_watch_event("done", root=case.archive_dir)
    saved = _one_marker(output, case).stat()
    assert (saved.st_ino, saved.st_mtime_ns) == (original.st_ino, original.st_mtime_ns)

def test_zip_discovery_and_missing_parity(package, tmp_path):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as writer:
        writer.writestr("payload.txt", b"a" * 2048)
    data = archive.getvalue()
    path = tmp_path / "vol.001"
    for tag in ("plain", "apate:1"):
        def store(payload):
            path.write_bytes(_apate(payload, b"JPEG") if tag == "apate:1" else payload)

        package.configure(filesystem={"read_views": [tag]}, embedded_scan={"enabled": False})
        store(data + bytes(64))
        output = tmp_path / tag[:1]
        package.json("extract", "-c", "k", "-o", output, path)
        payload, = output.rglob("payload.txt")
        assert payload.read_bytes() == b"a" * 2048

        store(data + data)
        entry, = package.json("scan", path)["items"]
        assert entry["format"] == "zip"

        package.configure(embedded_scan={"enabled": True})
        for prefix in (b"", b"carrier" * 80):
            store(prefix + data[:1024])
            for flags in [(), ("-d",)]:
                item, = package.json("scan", *flags, path, code=1)["items"]
                assert item["volume_completeness"] == "missing"


@pytest.mark.parametrize("spanned", [False, True])
def test_zip_shared_head_with_independent_directories(package, tmp_path, spanned):
    def disks(letter):
        archive = io.BytesIO()
        legacy = ("新しい世界の物語" + letter + ".txt").encode("shift_jis")
        placeholder = b"x" * len(legacy)
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as writer:
            writer.writestr(zipfile.ZipInfo("shared.txt"), b"common")
            writer.writestr(zipfile.ZipInfo(placeholder.decode()), letter.encode() * 16384)
        data = bytearray(archive.getvalue().replace(placeholder, legacy))
        chunk = 7000
        if spanned:
            end = data.rindex(b"PK\x05\x06")
            central = struct.unpack_from("<I", data, end + 16)[0]
            last = end // chunk
            struct.pack_into("<HH", data, end + 4, last, last)
            struct.pack_into("<I", data, end + 16, central % chunk)
        return [data[i:i + chunk] for i in range(0, len(data), chunk)]

    parts = tmp_path / "parts"
    parts.mkdir()
    for i, (a, b) in enumerate(zip(disks("A"), disks("B")), 1):
        (parts / f"set.{i:03}.blob").write_bytes(_apate(b, a))
    package.configure(filesystem={"read_views": ["plain", "apate:1"]})
    items = package.json("scan", "-d", parts)["items"]
    assert len({item["input_id"] for item in items}) == 2
    out = tmp_path / "out"
    package.json("extract", "-d", "-c", "k", "-o", out, parts)
    for letter in "AB":
        item, = out.rglob("新しい世界の物語" + letter + ".txt")
        assert item.read_bytes() == letter.encode() * 16384


@pytest.mark.parametrize("spanned", [False, True])
def test_zip_directory_crosses_view_boundary(package, tmp_path, spanned):
    name = "新しい世界の物語.txt"
    legacy = name.encode("shift_jis")
    placeholder = "j" * len(legacy)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as writer:
        writer.writestr(placeholder, b"1" * 12000)
        writer.writestr("second.txt", b"2" * 8000)
    data = bytearray(archive.getvalue().replace(placeholder.encode(), legacy))
    first_cd = data.index(b"PK\x01\x02")
    last_cd = data.index(b"PK\x01\x02", first_cd + 1)
    cut = 5000
    if spanned:
        eocd = data.rindex(b"PK\x05\x06")
        struct.pack_into("<HHH", data, eocd + 4, 2, 1, 1)
        struct.pack_into("<I", data, eocd + 16, first_cd - cut)
        second_local = struct.unpack_from("<I", data, last_cd + 42)[0]
        struct.pack_into("<H", data, last_cd + 34, 1)
        struct.pack_into("<I", data, last_cd + 42, second_local - cut)
    parts = tmp_path / "parts"
    parts.mkdir()
    for i, disk in enumerate((data[:cut], data[cut:last_cd], data[last_cd:]), 1):
        (parts / f"set.{i:03}.blob").write_bytes(_apate(disk, b"MASK") if i == 2 else disk)
    package.configure(filesystem={"read_views": ["plain", "apate:1"]})
    out = tmp_path / "out"
    package.json("extract", "-d", "-c", "k", "-o", out, parts)
    assert {f.name: f.read_bytes() for f in out.rglob("*") if f.is_file()} == {
        name: b"1" * 12000, "second.txt": b"2" * 8000,
    }

def test_missing_numbered_disk_in_mixed_view_directory(package, tmp_path):
    case = create_zip_multidisk_archive(tmp_path, "family", password=PASSWORD,
        payload_size=190 * 1024, split_volume_size=54 * 1024)
    parts = sorted(case.archive_dir.iterdir(), key=lambda p: (p.suffix == ".zip", p.name))
    assert len(parts) == 4
    for depth, part in zip((1, 4, 1, 4), parts):
        disk = part.read_bytes()
        for _ in range(depth):
            disk = _apate(disk, b"MASK")
        part.write_bytes(disk)
    parts[1].unlink()
    package.configure(filesystem={"read_views": ["apate:1", "apate:4"]})
    for flags in [(), ("-d",)]:
        item, = package.json("scan", *flags, "-p", PASSWORD, case.archive_dir, code=1)["items"]
        assert item["volume_completeness"] == "missing"


def test_recursive_ratio_counts_only_residual_views(package, tmp_path):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as writer:
        writer.writestr("small.txt", b"hit")
    carrier = b"carrier prefix" * 16 + archive.getvalue() + bytes(50)
    large = gzip.compress(random.Random(99).randbytes(100000), mtime=0)
    package.configure(filesystem={"read_views": ["plain", "apate:1", "apate:2"]},
                      embedded_scan={"enabled": True, "recursive_candidate_ratio": 0.35})
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_DEFLATED) as writer:
        writer.comment = b"end!"
        writer.writestr("large.blob", _apate(_apate(large, b"mask"), b"mask"))
        writer.writestr("small.blob", carrier)
    out = tmp_path / "out"
    package.json("extract", "-r", "2", "-o", out, "-c", "k", outer)
    small, = out.rglob("small.txt")
    assert small.read_bytes() == b"hit"

    # The medium file qualifies only when its two valid views count as one
    # physical file. A unique third depth must not admit the tiny carrier.
    package.configure(filesystem={"read_views": ["apate:1", "apate:2", "apate:3"]},
                      recursive_authorization={"enabled": False})
    tiny = io.BytesIO()
    with zipfile.ZipFile(tiny, "w") as writer:
        writer.writestr("below.txt", b"below threshold")
    parent = io.BytesIO()
    with zipfile.ZipFile(parent, "w", compression=zipfile.ZIP_DEFLATED) as writer:
        writer.writestr("large.blob", _apate(bytes(30000), b"mask"))
        writer.writestr("medium.blob", _apate(_apate(bytes(27000) + carrier, b"mask"), b"mask"))
        below = b"padding" * 16 + tiny.getvalue()
        for _ in range(3):
            below = _apate(below, b"mask")
        writer.writestr("tiny.blob", below)
    outer.write_bytes(_apate(parent.getvalue(), b"mask"))
    for flags, label in [((), "normal"), (("-d",), "deep")]:
        output = tmp_path / label
        package.json("extract", *flags, "-r", "2", "-o", output, "-c", "k", outer)
        marker, = output.rglob("small.txt")
        assert marker.read_bytes() == b"hit"
        assert not list(output.rglob("below.txt"))
