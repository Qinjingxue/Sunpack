from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.pipeline.coordinator.output_scan_policy import NestedOutputScanPolicy as OutputScanPolicy
from sunpack.pipeline.coordinator.target_scan import build_candidates_for_targets
from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
from tests.helpers.detection_config import with_detection_pipeline
from sunpack_native import worker_manifest_from_rows


def _config():
    return with_detection_pipeline()


def test_output_scan_policy_schedules_disguised_archive_for_full_scan(tmp_path):
    candidate = tmp_path / "K社27作.ISO"
    candidate.write_bytes(b"7z\xbc\xaf'\x1c" + b"payload")

    policy = OutputScanPolicy(_config())

    assert policy.should_scan_output_dir(str(tmp_path))
    assert policy.prepare_scan([str(tmp_path)]).roots == (str(tmp_path.resolve()),)


def test_output_scan_policy_finds_nested_archive_when_initial_scan_is_current_dir_only(tmp_path):
    segment_dir = tmp_path / "embedded_00_rar"
    segment_dir.mkdir()
    nested = segment_dir / "payload.ISO"
    nested.write_bytes(b"7z" + b"x" * (1024 * 1024))
    config = _config()
    config.setdefault("filesystem", {})["directory_scan_mode"] = "current_dir_only"

    policy = OutputScanPolicy(config)

    assert policy.should_scan_output_dir(str(tmp_path))
    assert policy.prepare_scan([str(tmp_path)]).roots == (str(tmp_path.resolve()),)


def test_output_scan_policy_projects_normal_archive_as_one_logical_root(tmp_path):
    output_dir = tmp_path / "normal"
    output_dir.mkdir()
    archive = output_dir / "nested.zip"
    archive.write_bytes(b"PK\x03\x04payload")
    result = ExtractionResult(
        success=True,

        out_dir=str(output_dir),

    )

    projected = OutputScanPolicy.project_logical_scan_roots(str(output_dir), result)

    assert [root for root, _inventory in projected] == [str(output_dir)]


def test_output_scan_policy_projects_each_confirmed_embedded_segment(tmp_path):
    carrier_dir = tmp_path / "carrier_extracted"
    segment_one = carrier_dir / "embedded_00_zip"
    segment_two = carrier_dir / "embedded_01_tar"
    segment_one.mkdir(parents=True)
    segment_two.mkdir()
    (segment_one / "one.zip").write_bytes(b"PK\x03\x04one")
    (segment_two / "two.tar").write_bytes(b"ustar" + b"x" * 512)
    child_one = ExtractionResult(
        success=True,

        out_dir=str(segment_one),

        output_inventory=collect_output_inventory(str(segment_one)),
    )
    child_two = ExtractionResult(
        success=True,

        out_dir=str(segment_two),

        output_inventory=collect_output_inventory(str(segment_two)),
    )
    result = ExtractionResult(
        success=True,

        out_dir=str(carrier_dir),

        embedded_results=[
            ({"segment_id": "embedded_00_zip"}, child_one),
            ({"segment_id": "embedded_01_tar"}, child_two),
        ],
    )

    projected = OutputScanPolicy.project_logical_scan_roots(str(carrier_dir), result)

    assert [root for root, _inventory in projected] == [str(segment_one), str(segment_two)]
    assert projected[0][1] is child_one.output_inventory
    assert projected[1][1] is child_two.output_inventory


def test_output_scan_policy_scans_projected_embedded_roots_with_their_inventories(tmp_path):
    carrier_dir = tmp_path / "carrier_extracted"
    segment_one = carrier_dir / "embedded_00_zip"
    segment_two = carrier_dir / "embedded_01_tar"
    segment_one.mkdir(parents=True)
    segment_two.mkdir()
    first = segment_one / "first.zip"
    second = segment_two / "second.tar.gz"
    first.write_bytes(b"PK\x03\x04first")
    second.write_bytes(b"\x1f\x8bsecond")
    inventory_one = collect_output_inventory(str(segment_one))
    inventory_two = collect_output_inventory(str(segment_two))
    policy = OutputScanPolicy(_config())

    work = policy.prepare_scan(
        [str(carrier_dir)],
        inventories={
            str(segment_one.resolve()).lower(): inventory_one,
            str(segment_two.resolve()).lower(): inventory_two,
        },
        logical_roots=[str(segment_one), str(segment_two)],
    )
    roots = list(work.roots)
    assert roots == [str(segment_one.resolve()), str(segment_two.resolve())]
    assert work.session is not None
    candidates = build_candidates_for_targets(roots, session=work.session, config=_config())
    assert {candidate.entry_path for candidate in candidates} == {str(first.resolve()), str(second.resolve())}


def test_output_scan_policy_reuses_extraction_inventory(tmp_path, monkeypatch):
    segment_dir = tmp_path / "embedded_00_rar"
    segment_dir.mkdir()
    nested = segment_dir / "payload.ISO"
    payload = b"PK" + b"x" * (1024 * 1024)
    nested.write_bytes(payload)
    inventory = collect_output_inventory(str(tmp_path))

    monkeypatch.setattr(
        "sunpack.pipeline.coordinator.output_scan_policy.DirectoryScanner.scan",
        lambda _self: (_ for _ in ()).throw(AssertionError("directory must not be rescanned")),
    )
    policy = OutputScanPolicy(_config())
    work = policy.prepare_scan(
        [str(tmp_path)],
        inventories={str(tmp_path.resolve()).lower(): inventory.to_dict()},
    )
    roots = list(work.roots)
    assert roots == [str(tmp_path.resolve())]
    assert work.session is not None
    assert work.session.include_raw_snapshots is True
    candidates = build_candidates_for_targets(roots, session=work.session, config=_config())
    assert [candidate.entry_path for candidate in candidates] == [str(nested.resolve())]


def test_output_scan_policy_inventory_batch_primes_file_heads(tmp_path, monkeypatch):
    archive = tmp_path / "nested.zip"
    archive.write_bytes(b"PK\x03\x04" + b"x" * (1024 * 1024))
    inventory = collect_output_inventory(str(tmp_path))
    policy = OutputScanPolicy(_config())
    work = policy.prepare_scan(
        [str(tmp_path)],
        inventories={str(tmp_path.resolve()).lower(): inventory.to_dict()},
    )
    roots = list(work.roots)
    session = work.session
    assert session is not None

    monkeypatch.setattr(
        "sunpack.pipeline.coordinator.scan_session._native_batch_file_head_facts",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("file heads must be cached")),
    )
    facts = session.file_head_facts_for_paths([str(archive)], magic_size=16)

    row = facts[next(iter(facts))]
    assert row["size"] == archive.stat().st_size
    assert row["magic"].startswith(b"PK\x03\x04")


def test_output_scan_policy_uses_worker_magic_without_reopening_files(tmp_path, monkeypatch):
    archive = tmp_path / "nested.bin"
    payload = b"PK\x03\x04" + b"payload"
    archive.write_bytes(payload)
    stat = archive.stat()
    worker_result = {
        "status": "ok",
        "verified_manifest": {
            "version": 3,
            "validated": True,
            "inventory": {
                "complete": True,
                "file_count": 1,
                "dir_count": 0,
                "total_size": len(payload),
                "identity_paths": True,
            },
            "native_rows": worker_manifest_from_rows(
                [[0, archive.name, "", len(payload), len(payload), 0, 0, 0, 0, 1, 1,
                  1, stat.st_mtime_ns, payload[:16].hex()]],
                True, 1, 0, len(payload), True,
            ),
        },
    }
    inventory = collect_output_inventory(str(tmp_path), worker_result)
    monkeypatch.setattr(
        "sunpack.pipeline.coordinator.scan_session._native_batch_file_head_facts",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("worker facts must avoid reopen")),
    )
    monkeypatch.setattr(
        "sunpack.pipeline.extraction.output_inventory.OutputInventory.file_head_columns",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("worker head columns must stay native")),
    )
    monkeypatch.setattr(
        "sunpack.pipeline.extraction.output_inventory.OutputInventory.file_columns",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("worker file columns must stay native")),
    )
    monkeypatch.setattr(
        "sunpack.pipeline.coordinator.output_scan_policy.DirectoryScanner.inventory_file_indices",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Python inventory filtering must be bypassed")),
    )
    monkeypatch.setattr(
        "sunpack.pipeline.coordinator.output_scan_policy.DirectoryScanner.snapshot_from_entries",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Python snapshot rebuilding must be bypassed")),
    )

    policy = OutputScanPolicy(_config())
    work = policy.prepare_scan(
        [str(tmp_path)],
        inventories={str(tmp_path.resolve()).lower(): inventory},
    )
    roots = list(work.roots)
    session = work.session
    assert session is not None
    facts = session.file_head_facts_for_paths([str(archive)], magic_size=16)

    row = facts[next(iter(facts))]
    assert row["magic"] == payload[:16]
    assert row["mtime_ns"] == stat.st_mtime_ns


def test_worker_inventory_fused_snapshot_preserves_raw_entries_and_rejects_escape(tmp_path):
    allowed = tmp_path / "nested.bin"
    allowed.write_bytes(b"PK\x03\x04payload")
    stat = allowed.stat()
    rows = [
        [0, allowed.name, "", stat.st_size, stat.st_size, 0, 0, 0, 0, 1, 1,
         1, stat.st_mtime_ns, b"PK\x03\x04payload".hex()],
        [1, "ignored.tmp", "", 4, 4, 0, 0, 0, 0, 1, 1,
         1, stat.st_mtime_ns, b"temp".hex()],
        [2, "escape.bin", "../escape.bin", 4, 4, 0, 0, 0, 0, 1, 1,
         1, stat.st_mtime_ns, b"evil".hex()],
    ]
    worker_result = {
        "status": "ok",
        "verified_manifest": {
            "version": 3,
            "validated": True,
            "inventory": {
                "complete": True,
                "file_count": 3,
                "dir_count": 0,
                "total_size": stat.st_size + 8,
                "identity_paths": True,
            },
            "native_rows": worker_manifest_from_rows(
                rows, True, 3, 0, stat.st_size + 8, True,
            ),
        },
    }
    inventory = collect_output_inventory(str(tmp_path), worker_result)
    config = with_detection_pipeline(precheck=[{
        "name": "blacklist",
        "enabled": True,
        "blocked_extensions": [".tmp"],
    }])
    policy = OutputScanPolicy(config)

    work = policy.prepare_scan(
        [str(tmp_path)],
        inventories={str(tmp_path.resolve()).lower(): inventory},
    )
    roots = list(work.roots)
    session = work.session
    assert session is not None
    snapshot = session.snapshot_for_directory(str(tmp_path))
    filtered_paths = set(snapshot.native_snapshot.materialize_columns()[0])
    raw_paths = set(snapshot.raw_native_snapshot.materialize_columns()[0])

    assert str(allowed) in filtered_paths
    assert str(tmp_path / "ignored.tmp") not in filtered_paths
    assert str(tmp_path / "ignored.tmp") in raw_paths
    assert str(tmp_path.parent / "escape.bin") not in raw_paths


def test_worker_inventory_fused_snapshot_applies_mtime_after_directory_projection(tmp_path):
    old_dir = tmp_path / "old"
    new_dir = tmp_path / "new"
    old_dir.mkdir()
    new_dir.mkdir()
    old_file = old_dir / "old.zip"
    new_file = new_dir / "new.zip"
    old_file.write_bytes(b"old")
    new_file.write_bytes(b"new")
    cutoff_ns = 2_000_000_000
    rows = [
        [0, "old/old.zip", "", 3, 3, 0, 0, 0, 0, 1, 1, 1, cutoff_ns - 1, b"old".hex()],
        [1, "new/new.zip", "", 3, 3, 0, 0, 0, 0, 1, 1, 1, cutoff_ns, b"new".hex()],
    ]
    worker_result = {
        "status": "ok",
        "verified_manifest": {
            "version": 3,
            "validated": True,
            "inventory": {
                "complete": True,
                "file_count": 2,
                "dir_count": 2,
                "total_size": 6,
                "identity_paths": True,
            },
            "native_rows": worker_manifest_from_rows(rows, True, 2, 2, 6, True),
        },
    }
    inventory = collect_output_inventory(str(tmp_path), worker_result)
    config = {
        "filesystem": {
            "scan_filters": [
                {"name": "mtime_range", "enabled": True, "gte": cutoff_ns},
            ],
        },
    }
    policy = OutputScanPolicy(config)

    work = policy.prepare_scan(
        [str(tmp_path)],
        inventories={str(tmp_path.resolve()).lower(): inventory},
    )
    roots = list(work.roots)
    assert work.session is not None
    snapshot = work.session.snapshot_for_directory(str(tmp_path))
    paths, is_dirs, _sizes, _mtimes = snapshot.native_snapshot.materialize_columns()
    filtered = dict(zip(paths, is_dirs))
    raw_paths = set(snapshot.raw_native_snapshot.materialize_columns()[0])

    assert str(old_file) not in filtered
    assert filtered[str(old_dir)] is True
    assert filtered[str(new_file)] is False
    assert {str(old_file), str(new_file)} <= raw_paths
