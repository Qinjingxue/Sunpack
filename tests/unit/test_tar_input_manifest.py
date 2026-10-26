import io
import tarfile
import pytest

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


def test_tar_source_manifest_walks_beyond_probe_budget(tmp_path):
    path = tmp_path / "many.tar"
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for index in range(65):
            payload = bytes([index])
            info = tarfile.TarInfo(f"item-{index:03d}.bin")
            info.size = 1
            archive.addfile(info, io.BytesIO(payload))

    manifest = archive_input_manifest(_input(path))

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

    manifest = archive_input_manifest(_input(path))

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

    manifest = archive_input_manifest(_input(path))

    assert manifest.ok is True
    assert manifest.expected_names == [long_path, "second.txt"]
    assert [item["size"] for item in manifest.entries.entry_page(0, 10)] == [len(b"payload"), 1]
    assert manifest.total_unpacked_size == len(b"payload") + 1


@pytest.mark.parametrize("tar_format", [tarfile.GNU_FORMAT, tarfile.PAX_FORMAT])
def test_tar_manifest_applies_long_metadata_and_link_output_sizes(tmp_path, tar_format):
    # Strict size matching must preserve valid link entries too; source headers
    # store zero payload size while the worker emits the link target bytes.
    path = tmp_path / "gnu-long.tar"
    long_name = "nested/" + "n" * 160 + "/link"
    long_link = "target/目标/" + "t" * 180
    with tarfile.open(path, "w", format=tar_format) as archive:
        info = tarfile.TarInfo(long_name)
        info.type = tarfile.SYMTYPE
        info.linkname = long_link
        archive.addfile(info)

    manifest = archive_input_manifest(_input(path))

    assert manifest.ok is True
    assert manifest.expected_names == [long_name]
    assert manifest.entries.entry_page(0, 10)[0]["size"] == len(long_link.encode("utf-8"))
    from tests.helpers.config_factory import make_config
    from tests.helpers.pipeline_engine import execute_pipeline

    summary = execute_pipeline(make_config({
        "cli": {"quiet": True}, "recursive_extract": 1,
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    }), str(path))
    assert summary.success_count == 1
    assert (tmp_path / "gnu-long" / long_name).read_bytes() == long_link.encode("utf-8")


def test_manifest_views_share_full_native_entries_and_unpacked_size(tmp_path):
    from sunpack.core.contracts.extraction import ExtractionResult
    from sunpack.pipeline.verification.archive_input_manifest import (
        archive_input_manifest_for_evidence,
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

    view = archive_input_manifest_for_evidence(evidence)

    assert view.retained_file_count == 30
    assert len(view.expected_names) == 30
    assert view.file_count == 30
    assert view.total_unpacked_size == 90
    full = archive_input_manifest_for_evidence(evidence)
    assert full.total_unpacked_size == 90
    # Views share the cached Rust entry table instead of copying entries.
    assert full.entries is view.entries
    assert full.retained_file_count == 30


def test_tar_manifest_preserves_all_pax_members_across_parts(tmp_path):
    # Later metadata and PAX records split across physical parts must both
    # survive the walk; ordinary member-count tests miss either boundary.
    from sunpack_native import archive_state_tar_manifest_native

    path = tmp_path / "members.tar"
    body = bytearray()
    for index in range(12):
        info = tarfile.TarInfo(f"item-{index:03d}.bin")
        info.size = 4096 if index % 2 else 0
        info.pax_headers = {"size": "2"}
        body.extend(info.tobuf(format=tarfile.PAX_FORMAT) + b"ab" + bytes(510))
    body.extend(bytes(1024))
    path.write_bytes(body)

    manifest = archive_input_manifest(_input(path))

    assert manifest.file_count == 12
    assert manifest.retained_file_count == 12
    assert manifest.total_unpacked_size == 24

    first, second = tmp_path / "part.001", tmp_path / "part.002"
    first.write_bytes(body[:517])
    second.write_bytes(body[517:])
    source = {"entry_path": str(first), "parts": [{"path": str(first)}, {"path": str(second)}]}
    joined = archive_state_tar_manifest_native(source)
    assert joined.archive_walk_complete
    assert (joined.file_count, joined.total_unpacked_size) == (12, 24)
    assert joined.entry_page(0, 10) == manifest.entries.entry_page(0, 10)
    incomplete = archive_state_tar_manifest_native({'entry_path': str(first)})
    assert not incomplete.archive_walk_complete
