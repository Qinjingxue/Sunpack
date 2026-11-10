from concurrent.futures import ThreadPoolExecutor

import pytest

from sunpack_native import probe_volume_anchors
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.coordinator.target_scan import build_native_table_for_targets
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.pipeline.discovery.relations import RelationsScheduler
from tests.helpers.config_factory import make_config
from tests.helpers.fs_builder import make_minimal_7z, make_minimal_pe, make_zip


def _config():
    return make_config({
        "embedded_scan": {"enabled": True},
        "filesystem": {"scan_filters": [{"name": "size_range", "enabled": True, "min_bytes": 0}]},
    })


@pytest.mark.parametrize("filename", ["image.jpg", "image.bin", "image.EXE", "image.dll"])
@pytest.mark.parametrize("pe_offset", [0x80, 0x180, 0x800])
@pytest.mark.parametrize("pe64", [False, True])
def test_pe_facts_reach_native_residual_regardless_of_filename(tmp_path, filename, pe_offset, pe64):
    image = make_minimal_pe(pe_offset=pe_offset, pe64=pe64)
    path = tmp_path / filename
    path.write_bytes(image + make_minimal_7z() + b"trailing junk")

    [group] = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path), config=_config()).scan())
    assert group.head_metadata["pe_structure"] is True
    assert group.head_metadata["sfx"] is False
    assert group.head_metadata.get("relation_confirmed") is not True

    # Both file and directory target paths consume native refined residuals.
    for target in [path, tmp_path]:
        ordinary = ArchiveTaskProvider(_config()).discover_targets([str(target)])
        assert ordinary.tasks == []
        assert ordinary.scan_failures == []
        deep = ArchiveTaskProvider(_config(), EmbeddedOptions(force_scan=True)).discover_targets([str(target)])
        [task] = deep.tasks
        assert task.discovery_source == "embedded"
        assert task.archive_input().primary_extent.start == len(image)


@pytest.mark.parametrize("prefix", [
    pytest.param(b"carrier junk", id="ordinary-carrier"),
    pytest.param(b"MZ" + b"x" * 62, id="invalid-dos-header"),
    pytest.param(
        make_minimal_pe(pe_offset=0x800).replace(b"PE\x00\x00", b"NO\x00\x00"),
        id="candidate-refined-to-none",
    ),
])
def test_non_pe_exe_carrier_is_scanned(tmp_path, prefix):
    path = tmp_path / "disguised.exe"
    path.write_bytes(prefix + make_minimal_7z() + b"trailing junk")
    [task] = ArchiveTaskProvider(_config()).discover_targets([str(path)]).tasks
    assert task.discovery_source == "embedded"
    assert task.archive_input().primary_extent.start == len(prefix)


@pytest.mark.parametrize("pe_offset", [0x80, 0x800])
def test_disguised_sfx_remains_owned_by_relations(tmp_path, pe_offset):
    path = tmp_path / "self_extracting.jpg"
    image = make_minimal_pe(b"7-Zip SFX", pe_offset=pe_offset)
    path.write_bytes(image + make_minimal_7z())
    for force in [False, True]:
        [task] = ArchiveTaskProvider(_config(), EmbeddedOptions(force_scan=force)).discover_targets([str(path)]).tasks
        assert task.discovery_source == "relations"
        assert task.archive_input().primary_extent.start == len(image)


def test_concurrent_scan_lifetimes_keep_pe_and_sfx_facts_independent(tmp_path):
    (tmp_path / "ordinary.jpg").write_bytes(make_minimal_pe(pe_offset=0x800) + make_minimal_7z())
    (tmp_path / "sfx.bin").write_bytes(make_minimal_pe(b"7-Zip SFX") + make_minimal_7z())
    (tmp_path / "carrier.exe").write_bytes(b"carrier" + make_minimal_7z())

    def discover(force):
        result = ArchiveTaskProvider(_config(), EmbeddedOptions(force_scan=force)).discover_targets([str(tmp_path)])
        sources = sorted(task.discovery_source for task in result.tasks)
        assert sources == (["embedded", "embedded", "relations"] if force else ["embedded", "relations"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(discover, [False, True] * 8))


@pytest.mark.parametrize("pe_offset", [0x80, 0x800])
def test_native_embedded_reuses_confirmed_residual_without_reopening_pe(tmp_path, pe_offset):
    path = tmp_path / "image.jpg"
    path.write_bytes(make_minimal_pe(pe_offset=pe_offset))
    table = build_native_table_for_targets([str(path)], config=_config())
    batch = table.prepare_embedded(table.resolve())
    path.unlink()
    # If Candidate refinement were lost, Embedded would attempt PE I/O and
    # report an I/O error. Confirmed facts must survive in the native residual.
    assert type(batch).scan_pages([(table, batch)]) == []


@pytest.mark.parametrize("pe_offset", [0x80, 0x800])
@pytest.mark.parametrize("sections,characteristics", [
    (1, 0), (1, 0x2000), (97, 0x0002), (65535, 0x0002),
])
def test_invalid_coff_carriers_are_scanned_instead_of_skipped(tmp_path, pe_offset, sections, characteristics):
    image = bytearray(make_minimal_pe(b"7-Zip SFX", pe_offset=pe_offset))
    image[pe_offset + 6:pe_offset + 8] = sections.to_bytes(2, "little")
    image[pe_offset + 22:pe_offset + 24] = characteristics.to_bytes(2, "little")
    path = tmp_path / "invalid_image.exe"
    path.write_bytes(image + make_minimal_7z() + b"trailing junk")
    [task] = ArchiveTaskProvider(_config()).discover_targets([str(path)]).tasks
    assert task.discovery_source == "embedded"
    assert task.archive_input().primary_extent.start == len(image)


@pytest.mark.parametrize("pe_offset", [0x80, 0x800])
@pytest.mark.parametrize("archive_format,payload", [
    ("7z", make_minimal_7z()), ("zip", make_zip({"payload.txt": "contents"})),
], ids=["7z", "zip"])
def test_deep_anchor_does_not_discover_nonleading_archives(tmp_path, pe_offset, archive_format, payload):
    image = make_minimal_pe(pe_offset=pe_offset)
    path = tmp_path / "image.jpg"
    path.write_bytes(image + payload)
    [anchor] = probe_volume_anchors([str(path)])
    assert anchor["structure_offset"] is None
    assert anchor["standalone"] is False
    assert anchor["multivolume"] is False
    assert anchor["sfx"] is False


@pytest.mark.parametrize("archive_format,payload", [
    ("7z", make_minimal_7z()), ("zip", make_zip({"payload.txt": "contents"})),
], ids=["7z", "zip"])
def test_deep_anchor_candidate_refined_to_none_does_not_authorize_archive_search(tmp_path, archive_format, payload):
    image = make_minimal_pe(pe_offset=0x800).replace(b"PE\x00\x00", b"NO\x00\x00")
    path = tmp_path / "invalid_image.jpg"
    path.write_bytes(image + payload)
    [anchor] = probe_volume_anchors([str(path)])
    assert anchor["pe_structure"] is False
    assert anchor["structure_offset"] is None
    assert anchor["standalone"] is False
    assert anchor["sfx"] is False
