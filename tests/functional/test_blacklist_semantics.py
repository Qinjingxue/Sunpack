from pathlib import Path

from sunpack.coordinator.output_scan_policy import NestedOutputScanPolicy as OutputScanPolicy
from sunpack.coordinator.scanner import ScanOrchestrator
from sunpack.detection import DetectionScheduler
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_zip


def scan_config(blocked_files=None, blocked_extensions=None):
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "filesystem": {
            "directory_scan_mode": "recursive",
        },
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
        {
            "name": "blacklist",
            "enabled": True,
            "blocked_files": blocked_files or [],
            "blocked_extensions": blocked_extensions or [],
        },
        {"name": "embedded_payload_identity", "enabled": True},
        {"name": "zip_structure_accept", "enabled": True},
    ])


def decisions_for(root: Path, config: dict):
    detector = DetectionScheduler(config)
    from sunpack.coordinator.target_scan import build_fact_bags_for_targets
    bags = build_fact_bags_for_targets([str(root)], config=config)
    decisions = detector.evaluate_pool(bags)
    return {Path(bag.get("file.path")).relative_to(root).as_posix(): decisions[bag] for bag in bags}


def test_blacklist_does_not_filter_directories_or_paths(tmp_path):
    weapon_dir = tmp_path / "FBX" / "weapon"
    weapon_dir.mkdir(parents=True)
    (weapon_dir / "payload.zip").write_bytes(make_zip({"payload.txt": "payload"}))
    (tmp_path / "keep.zip").write_bytes(make_zip({"payload.txt": "payload"}))

    decisions = decisions_for(tmp_path, scan_config(blocked_files=["weapon"]))

    assert decisions["keep.zip"].should_extract
    assert decisions["FBX/weapon/payload.zip"].should_extract


def test_blacklist_filters_exact_file_names_anywhere(tmp_path):
    nested = tmp_path / "FBX" / "weapon"
    nested.mkdir(parents=True)
    archive_bytes = make_zip({"payload.txt": "payload"})
    (tmp_path / "demo.zip").write_bytes(archive_bytes)
    (nested / "demo.zip").write_bytes(archive_bytes)
    (tmp_path / "keep.zip").write_bytes(archive_bytes)

    decisions = decisions_for(tmp_path, scan_config(blocked_files=["demo.zip"]))

    assert decisions["keep.zip"].should_extract
    assert "demo.zip" not in decisions
    assert "FBX/weapon/demo.zip" not in decisions


def test_filename_blacklist_filters_single_rename_candidate_before_planning(tmp_path):
    archive = tmp_path / "asset.foo"
    archive.write_bytes(make_zip({"payload.txt": "payload"}))

    results = ScanOrchestrator(scan_config(blocked_files=["asset.foo"])).scan(str(tmp_path))

    assert results == []


def test_filename_blacklist_filters_series_rename_candidate_before_planning(tmp_path):
    first = tmp_path / "bundle.part01.rar.jpg"
    second = tmp_path / "bundle.part02.rar.jpg"
    first.write_bytes(b"Rar!" + b"x" * 128)
    second.write_bytes(b"x" * 128)

    results = ScanOrchestrator(scan_config(blocked_files=["bundle.part01.rar.jpg"])).scan(str(tmp_path))

    assert results == []


def test_blocked_semantic_extension_stops_magic_archive_in_generic_directory(tmp_path):
    archive = tmp_path / "asset.unitypackage"
    archive.write_bytes(b"\x1f\x8b" + b"x" * 128)

    decisions = decisions_for(tmp_path, scan_config(blocked_extensions=[".unitypackage"]))

    assert "asset.unitypackage" not in decisions


def test_docx_semantic_container_is_not_promoted_to_extract_task(tmp_path):
    archive = tmp_path / "sample.docx"
    archive.write_bytes(b"PK\x03\x04" + b"x" * 128)

    results = ScanOrchestrator(scan_config(blocked_extensions=[".docx"])).scan(str(tmp_path))
    decisions = decisions_for(tmp_path, scan_config(blocked_extensions=[".docx"]))

    assert results == []
    assert "sample.docx" not in decisions


def test_output_dir_scan_preserves_explicit_filesystem_blacklist(tmp_path):
    archive = tmp_path / "asset.unitypackage"
    archive.write_bytes(b"\x1f\x8b" + b"x" * 128)

    config = scan_config(blocked_extensions=[".unitypackage"])

    assert not OutputScanPolicy(config).should_scan_output_dir(str(tmp_path))
    assert ScanOrchestrator(config).scan(str(tmp_path)) == []


