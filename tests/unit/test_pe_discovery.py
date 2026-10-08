from concurrent.futures import ThreadPoolExecutor

import pytest

from sunpack_native import inspect_pe_image, inspect_pe_overlay_structure, probe_volume_anchors
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.coordinator.target_scan import build_native_table_for_targets
from sunpack.pipeline.discovery.embedded.discovery import EmbeddedDiscovery
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.pipeline.discovery.relations import RelationsScheduler
from tests.helpers.config_factory import make_config
from tests.helpers.fs_builder import make_minimal_7z, make_minimal_pe, make_zip


def _config():
    return make_config({
        "embedded_scan": {"enabled": True},
        "filesystem": {"scan_filters": [{"name": "size_range", "enabled": True, "gte": 0}]},
    })


def _candidate(path):
    return DiscoveryCandidate(
        archive_input=ArchiveInputDescriptor.from_parts(archive_path=str(path), logical_name=path.name),
        carrier_path=str(path), cleanup_paths=(str(path),), route="residual",
        size=path.stat().st_size,
    )


@pytest.mark.parametrize("filename", ["image.jpg", "image.bin", "image.EXE", "image.dll"])
@pytest.mark.parametrize("pe_offset", [0x80, 0x180, 0x800])
@pytest.mark.parametrize("pe64", [False, True])
def test_pe_facts_reach_native_residual_regardless_of_filename(tmp_path, filename, pe_offset, pe64, monkeypatch):
    image = make_minimal_pe(pe_offset=pe_offset, pe64=pe64)
    path = tmp_path / filename
    path.write_bytes(image + make_minimal_7z() + b"trailing junk")
    assert inspect_pe_image(str(path)) is True
    overlay = inspect_pe_overlay_structure(str(path))
    assert overlay["is_pe"] is True
    assert overlay["overlay_offset"] == len(image)

    [group] = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path), config=_config()).scan())
    assert group.head_metadata["pe_structure"] is True
    assert group.head_metadata["sfx"] is False
    assert group.head_metadata.get("relation_confirmed") is not True

    # Both file and directory target paths consume native refined residuals.
    # Python fallback PE detection must never run for their precomputed scans.
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.inspect_pe_image",
        lambda *_: pytest.fail("native residual facts must not pass through Python PE detection"),
    )
    for target in [path, tmp_path]:
        ordinary = ArchiveTaskProvider(_config()).discover_targets([str(target)])
        assert ordinary.resolved_tasks == []
        assert any(trace.reason == "embedded_executable_skipped" for trace in ordinary.traces)
        deep = ArchiveTaskProvider(_config(), EmbeddedOptions(force_scan=True)).discover_targets([str(target)])
        [task] = deep.resolved_tasks
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
def test_non_pe_exe_carrier_is_scanned_in_native_and_fallback_paths(tmp_path, prefix):
    path = tmp_path / "disguised.exe"
    path.write_bytes(prefix + make_minimal_7z() + b"trailing junk")
    assert inspect_pe_image(str(path)) is False
    for result in [
        ArchiveTaskProvider(_config()).discover_targets([str(path)]),
        EmbeddedDiscovery(_config()).discover([_candidate(path)]),
    ]:
        [task] = result.resolved_tasks
        assert task.discovery_source == "embedded"
        assert task.archive_input().primary_extent.start == len(prefix)


@pytest.mark.parametrize("pe_offset", [0x80, 0x800])
def test_python_fallback_uses_canonical_pe_policy(tmp_path, pe_offset):
    path = tmp_path / "disguised.jpg"
    path.write_bytes(make_minimal_pe(pe_offset=pe_offset) + make_minimal_7z())
    result = EmbeddedDiscovery(_config()).discover([_candidate(path)])
    assert result.resolved_tasks == []
    assert any(trace.reason == "embedded_executable_skipped" for trace in result.traces)
    deep = EmbeddedDiscovery(_config(), EmbeddedOptions(force_scan=True)).discover([_candidate(path)])
    assert len(deep.resolved_tasks) == 1


@pytest.mark.parametrize("pe_offset", [0x80, 0x800])
def test_disguised_sfx_remains_owned_by_relations(tmp_path, pe_offset):
    path = tmp_path / "self_extracting.jpg"
    image = make_minimal_pe(b"7-Zip SFX", pe_offset=pe_offset)
    path.write_bytes(image + make_minimal_7z())
    for force in [False, True]:
        [task] = ArchiveTaskProvider(_config(), EmbeddedOptions(force_scan=force)).discover_targets([str(path)]).resolved_tasks
        assert task.discovery_source == "relations"
        assert task.archive_input().primary_extent.start == len(image)


def test_concurrent_scan_lifetimes_keep_pe_and_sfx_facts_independent(tmp_path):
    (tmp_path / "ordinary.jpg").write_bytes(make_minimal_pe(pe_offset=0x800) + make_minimal_7z())
    (tmp_path / "sfx.bin").write_bytes(make_minimal_pe(b"7-Zip SFX") + make_minimal_7z())
    (tmp_path / "carrier.exe").write_bytes(b"carrier" + make_minimal_7z())

    def discover(force):
        result = ArchiveTaskProvider(_config(), EmbeddedOptions(force_scan=force)).discover_targets([str(tmp_path)])
        sources = sorted(task.discovery_source for task in result.resolved_tasks)
        assert sources == (["embedded", "embedded", "relations"] if force else ["embedded", "relations"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(discover, [False, True] * 8))


@pytest.mark.parametrize("pe_offset", [0x80, 0x800])
def test_native_embedded_reuses_confirmed_residual_without_reopening_pe(tmp_path, pe_offset):
    path = tmp_path / "image.jpg"
    path.write_bytes(make_minimal_pe(pe_offset=pe_offset))
    table = build_native_table_for_targets([str(path)], config=_config())
    batch = table.scan_embedded(table.resolve())
    path.unlink()
    # If Candidate refinement were lost, Embedded would attempt PE I/O and
    # report an I/O error. Confirmed facts must survive in the native residual.
    [(index, status, reason, scan)] = batch.scan_page(table)
    assert status == 0
    assert reason == "embedded_executable_skipped"
    assert scan is None


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
    assert inspect_pe_image(str(path)) is False
    for result in [
        ArchiveTaskProvider(_config()).discover_targets([str(path)]),
        EmbeddedDiscovery(_config()).discover([_candidate(path)]),
    ]:
        [task] = result.resolved_tasks
        assert task.discovery_source == "embedded"
        assert task.archive_input().primary_extent.start == len(image)


@pytest.mark.parametrize("pe_offset", [0x80, 0x800])
@pytest.mark.parametrize("archive_format,payload", [
    ("7z", make_minimal_7z()), ("zip", make_zip({"payload.txt": "contents"})),
], ids=["7z", "zip"])
def test_deep_anchor_reuses_pe_facts_for_nonleading_archives(tmp_path, pe_offset, archive_format, payload):
    image = make_minimal_pe(pe_offset=pe_offset)
    path = tmp_path / "image.jpg"
    path.write_bytes(image + payload)
    [anchor] = probe_volume_anchors([str(path)])
    assert anchor["pe_structure"] is True
    assert anchor["format"] == archive_format
    assert anchor["structure_offset"] == len(image)
    assert anchor["sfx"] is False


@pytest.mark.parametrize("archive_format,payload", [
    ("7z", make_minimal_7z()), ("zip", make_zip({"payload.txt": "contents"})),
], ids=["7z", "zip"])
def test_deep_anchor_candidate_refined_to_none_does_not_authorize_archive_search(tmp_path, archive_format, payload):
    image = make_minimal_pe(pe_offset=0x800).replace(b"PE\x00\x00", b"NO\x00\x00")
    path = tmp_path / "invalid_image.jpg"
    path.write_bytes(image + payload)
    [anchor] = probe_volume_anchors([str(path)], tail_limit=0)
    assert anchor["pe_structure"] is False
    assert anchor["format"] == ""
    assert anchor["sfx"] is False
