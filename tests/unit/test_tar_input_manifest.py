import io
import tarfile

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.pipeline.verification.archive_input_manifest import archive_input_manifest
from sunpack.pipeline.verification.methods._archive_output_match import coverage_from_archive_and_output


def _input(path):
    return ArchiveInputDescriptor(
        entry_path=str(path),
        format_hint="tar",
    )


def _pax_record(key: str, value: str) -> bytes:
    body = f" {key}={value}\n".encode("utf-8")
    length = len(body) + 1
    while True:
        record = str(length).encode("ascii") + body
        if len(record) == length:
            return record
        length = len(record)


def test_tar_source_manifest_walks_beyond_probe_budget(tmp_path):
    path = tmp_path / "many.tar"
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for index in range(65):
            payload = bytes([index])
            info = tarfile.TarInfo(f"item-{index:03d}.bin")
            info.size = 1
            archive.addfile(info, io.BytesIO(payload))

    manifest = archive_input_manifest(_input(path), max_items=1000)

    assert manifest.ok is True
    assert manifest.archive_walk_complete is True
    assert manifest.file_count == 65
    assert len(manifest.files) == 65


def test_tar_duplicate_members_preserve_history_and_worker_output_names(tmp_path):
    path = tmp_path / "duplicates.tar"
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for payload in (b"old", b"replacement"):
            info = tarfile.TarInfo("same.txt")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))

    manifest = archive_input_manifest(_input(path), max_items=100)

    assert manifest.ok is True
    assert manifest.item_count >= 2
    assert manifest.file_count == 2
    assert len(manifest.files) == 2
    assert manifest.files[0]["path"] == "same.txt"
    assert manifest.files[1]["path"] == "same(1).txt"
    assert manifest.files[0]["archive_path"] == "same.txt"
    assert manifest.files[1]["archive_path"] == "same.txt"
    assert manifest.files[1]["size"] == len(b"replacement")

    coverage = coverage_from_archive_and_output(
        manifest.files,
        [
            {"path": "same.txt", "size": len(b"old"), "status": "complete"},
            {"path": "same(1).txt", "size": len(b"replacement"), "status": "complete"},
        ],
        method="test",
    )
    assert coverage.expected_files == 2
    assert coverage.complete_files == 2


def test_tar_pax_long_path_is_applied_to_target_member(tmp_path):
    path = tmp_path / "pax.tar"
    long_path = "nested/" + "a" * 180 + "/payload.txt"
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        payload = b"payload"
        info = tarfile.TarInfo(long_path)
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
        second = tarfile.TarInfo("second.txt")
        second.size = 1
        archive.addfile(second, io.BytesIO(b"2"))

    manifest = archive_input_manifest(_input(path), max_items=100)

    assert manifest.ok is True
    assert manifest.expected_names == [long_path, "second.txt"]
    assert manifest.files[0]["size"] == len(b"payload")
    assert manifest.files[1]["size"] == 1


def test_tar_manifest_rejects_overlapping_pax_sparse_extents(tmp_path):
    pax_payload = b"".join((
        _pax_record("GNU.sparse.map", "10,5,12,2"),
        _pax_record("GNU.sparse.realsize", "20"),
    ))
    pax = tarfile.TarInfo("PaxHeaders/sparse")
    pax.type = tarfile.XHDTYPE
    pax.size = len(pax_payload)
    target = tarfile.TarInfo("sparse.bin")
    target.size = 0
    data = (
        pax.tobuf(format=tarfile.USTAR_FORMAT)
        + pax_payload + b"\0" * (-len(pax_payload) % 512)
        + target.tobuf(format=tarfile.USTAR_FORMAT)
        + b"\0" * 1024
    )
    path = tmp_path / "bad-sparse.tar"
    path.write_bytes(data)

    manifest = archive_input_manifest(_input(path), max_items=100)

    assert manifest.damaged is True
    assert "sparse extent" in manifest.message


def test_tar_manifest_applies_gnu_longname_and_longlink_to_next_member(tmp_path):
    path = tmp_path / "gnu-long.tar"
    long_name = "nested/" + "n" * 160 + "/link"
    long_link = "target/" + "t" * 180
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as archive:
        info = tarfile.TarInfo(long_name)
        info.type = tarfile.SYMTYPE
        info.linkname = long_link
        archive.addfile(info)

    manifest = archive_input_manifest(_input(path), max_items=100)

    assert manifest.ok is True
    assert manifest.expected_names == [long_name]
    assert manifest.files[0]["linkpath"] == long_link
    assert manifest.files[0]["typeflag"] == "2"
