import io
import tarfile

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
from sunpack.pipeline.verification.archive_input_manifest import archive_input_manifest
from sunpack.pipeline.verification.methods._archive_output_match import (
    coverage_from_native_inventory,
)


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
    assert manifest.retained_file_count == 65


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
    entries = manifest.entries.entry_page(0, 10)
    assert len(entries) == 2
    assert entries[0]["path"] == "same.txt"
    assert entries[1]["path"] == "same(1).txt"
    assert entries[0]["archive_path"] == "same.txt"
    assert entries[1]["archive_path"] == "same.txt"
    assert entries[1]["size"] == len(b"replacement")

    out_dir = tmp_path / "duplicates-out"
    out_dir.mkdir()
    (out_dir / "same.txt").write_bytes(b"old")
    (out_dir / "same(1).txt").write_bytes(b"replacement")
    coverage, raw = coverage_from_native_inventory(
        manifest,
        collect_output_inventory(str(out_dir)),
        method="test",
    )
    assert raw["source"] == "native_output_inventory"
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
    assert [item["size"] for item in manifest.entries.entry_page(0, 10)] == [len(b"payload"), 1]
    assert manifest.total_unpacked_size == len(b"payload") + 1


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


def test_tar_manifest_applies_gnu_longname_and_skips_longlink_payload(tmp_path):
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
    assert manifest.entries.entry_page(0, 10)[0]["size"] == 0


def test_truncated_manifest_view_keeps_full_unpacked_size(tmp_path):
    from sunpack.core.contracts.extraction import ExtractionResult
    from sunpack.pipeline.verification.archive_input_manifest import (
        archive_input_manifest_for_evidence,
        configure_archive_input_manifest_cache,
    )
    from sunpack.pipeline.verification.evidence import build_verification_evidence
    from tests.helpers.archive_tasks import make_task_from_descriptor

    path = tmp_path / "large.tar"
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for index in range(30):
            info = tarfile.TarInfo(f"item-{index:03d}.bin")
            info.size = 3
            archive.addfile(info, io.BytesIO(b"abc"))
    evidence = build_verification_evidence(
        make_task_from_descriptor(_input(path)),
        ExtractionResult(success=True, out_dir=str(tmp_path / "out")),
    )
    configure_archive_input_manifest_cache(evidence, max_items=1000)

    view = archive_input_manifest_for_evidence(evidence, max_items=10)

    assert view.retained_file_count == 10
    assert len(view.expected_names) == 10
    assert view.entries_truncated is True
    assert view.file_count == 30
    assert view.total_unpacked_size == 90
    full = archive_input_manifest_for_evidence(evidence, max_items=1000)
    assert full.total_unpacked_size == 90
    # Views share the cached Rust entry table instead of copying entries.
    assert full.entries is view.entries
    assert full.retained_file_count == 30


def test_tar_manifest_counts_all_files_beyond_retained_entry_limit(tmp_path):
    path = tmp_path / "capped.tar"
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for index in range(12):
            info = tarfile.TarInfo(f"item-{index:03d}.bin")
            info.size = 2
            archive.addfile(info, io.BytesIO(b"ab"))

    manifest = archive_input_manifest(_input(path), max_items=5)

    assert manifest.file_count == 12
    assert manifest.retained_file_count == 5
    assert manifest.entries_truncated is True
    assert manifest.total_unpacked_size == 24
