
from sunpack.core.contracts.input_plan import LogicalArchiveInput
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
import pytest

from sunpack.core.contracts.extraction import ExtractionResult, InputExecutionResult
from sunpack.core.contracts.filesystem import DirectorySnapshot
from sunpack.pipeline.coordinator.output_scan_policy import (
    NestedOutputScanPolicy as OutputScanPolicy,
)
from sunpack.pipeline.coordinator.target_scan import build_candidates_for_targets
from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
from tests.helpers.config_factory import make_config
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_minimal_7z
from tests.helpers.worker_events import worker_result


def _config():
    return make_config(with_detection_pipeline())


def test_output_scan_policy_parent_roots_bypass_file_column_materialization(tmp_path, monkeypatch):
    first_dir = tmp_path / "one"
    second_dir = tmp_path / "two"
    first_dir.mkdir()
    second_dir.mkdir()
    (first_dir / "a.bin").write_bytes(b"a")
    (second_dir / "b.bin").write_bytes(b"b")

    monkeypatch.setattr(
        DirectorySnapshot,
        "iter_file_columns",
        lambda _self: (_ for _ in ()).throw(
            AssertionError("parent-root projection must stay in native code")
        ),
    )

    policy = OutputScanPolicy(_config())
    roots = policy._candidate_parent_roots(str(tmp_path))

    assert set(roots) == {str(first_dir.resolve()), str(second_dir.resolve())}


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

        input_results=[
            InputExecutionResult(LogicalArchiveInput(ArchiveInputDescriptor("carrier", format_hint="zip")), child_one),
            InputExecutionResult(LogicalArchiveInput(ArchiveInputDescriptor("carrier", format_hint="tar")), child_two),
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


@pytest.mark.parametrize("has_inventory", [True, False], ids=["inventory", "native-scan"])
def test_output_scan_policy_reuses_extraction_inventory(tmp_path, monkeypatch, has_inventory):
    segment_dir = tmp_path / "embedded_00_rar"
    segment_dir.mkdir()
    nested = segment_dir / "payload.ISO"
    payload = b"PK" + b"x" * (1024 * 1024)
    nested.write_bytes(payload)
    inventories = {}
    if has_inventory:
        inventories[str(tmp_path.resolve()).lower()] = collect_output_inventory(str(tmp_path))
    config = _config()
    policy = OutputScanPolicy(config)
    if has_inventory:
        monkeypatch.setattr(
            policy, "_scan_output",
            lambda *_args: (_ for _ in ()).throw(AssertionError("directory must not be rescanned")),
        )
    work = policy.prepare_scan(
        [str(tmp_path)],
        inventories=inventories,
    )
    roots = list(work.roots)
    assert roots == [str(tmp_path.resolve())]
    assert work.session is not None
    candidates = build_candidates_for_targets(roots, session=work.session, config=config)
    assert [candidate.entry_path for candidate in candidates] == [str(nested.resolve())]


def test_output_scan_policy_uses_worker_magic_without_reopening_files(tmp_path, monkeypatch):
    archive = tmp_path / "nested.bin"
    payload = make_minimal_7z()
    archive.write_bytes(payload)
    stat = archive.stat()
    result = worker_result(
        status="ok",
        manifest_rows=[
            [0, archive.name, "", len(payload), len(payload), 0, 0, 0, 0, 1, 1,
             1, stat.st_mtime_ns, payload],
        ],
        verified_manifest={
            "validated": True,
            "inventory": [1, 1, 0, len(payload), 1],
        },
    )
    inventory = collect_output_inventory(str(tmp_path), result)
    monkeypatch.setattr(
        "sunpack.pipeline.coordinator.output_scan_policy.DirectoryScanner.inventory_file_indices",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Python inventory filtering must be bypassed")),
    )
    monkeypatch.setattr(
        "sunpack.pipeline.coordinator.output_scan_policy.DirectoryScanner.snapshot_from_entries",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Python snapshot rebuilding must be bypassed")),
    )

    # Test the snapshot used by real discovery after the source disappears;
    # a separate file-head cache could pass while that snapshot reopened files.
    archive.unlink()
    policy = OutputScanPolicy(_config())
    work = policy.prepare_scan(
        [str(tmp_path)],
        inventories={str(tmp_path.resolve()).lower(): inventory},
    )
    session = work.session
    assert session is not None
    snapshot = session.snapshot_for_directory(str(tmp_path)).native_snapshot
    paths, is_dirs, sizes, mtimes = snapshot.materialize_columns()
    assert paths == [str(archive)]
    assert is_dirs == [False]
    assert sizes == [len(payload)]
    assert mtimes == [stat.st_mtime_ns]
    [(path, size, anchor)] = snapshot.relation_anchor_rows()
    assert path == str(archive) and size == len(payload)
    assert anchor["format"] == "7z"
    assert anchor["confidence"] == "strong"


def test_worker_inventory_fused_snapshot_preserves_raw_entries_and_rejects_escape(tmp_path):
    allowed = tmp_path / "nested.bin"
    allowed.write_bytes(b"PK\x03\x04payload")
    stat = allowed.stat()
    rows = [
        [0, allowed.name, "", stat.st_size, stat.st_size, 0, 0, 0, 0, 1, 1,
         1, stat.st_mtime_ns, b"PK\x03\x04payload"],
        [1, "ignored.tmp", "", 4, 4, 0, 0, 0, 0, 1, 1,
         1, stat.st_mtime_ns, b"temp"],
        [2, "escape.bin", "../escape.bin", 4, 4, 0, 0, 0, 0, 1, 1,
         1, stat.st_mtime_ns, b"evil"],
        [3, "alias.bin", allowed.name, 4, 4, 0, 0, 0, 0, 1, 1,
         1, stat.st_mtime_ns, b"last"],
    ]
    allowed.write_bytes(b"last")
    result = worker_result(
        status="ok",
        manifest_rows=rows,
        verified_manifest={
            "validated": True,
            "inventory": [1, 4, 0, stat.st_size + 12, 0],
        },
    )
    inventory = collect_output_inventory(str(tmp_path), result)
    config = make_config(with_detection_pipeline(precheck=[{'name': 'blacklist', 'enabled': True, 'extensions': [{'value': 'tmp', 'regex': False}]}]))
    policy = OutputScanPolicy(config)

    work = policy.prepare_scan(
        [str(tmp_path)],
        inventories={str(tmp_path.resolve()).lower(): inventory},
    )
    session = work.session
    assert session is not None
    snapshot = session.snapshot_for_directory(str(tmp_path))
    filtered_paths = set(snapshot.native_snapshot.materialize_columns()[0])
    raw_paths = set(snapshot.raw_native_snapshot.materialize_columns()[0])

    assert str(allowed) in filtered_paths
    assert str(tmp_path / "ignored.tmp") not in filtered_paths
    assert str(tmp_path / "ignored.tmp") in raw_paths
    assert str(tmp_path.parent / "escape.bin") not in raw_paths
    # Manifest aliases use the final record for the same output path. Ordinary
    # directory scans cannot expose this filtered-row remapping regression.
    paths, _dirs, sizes, _mtimes = snapshot.native_snapshot.materialize_columns()
    assert [size for path, size in zip(paths, sizes) if path == str(allowed)] == [4, 4]


def test_worker_inventory_fused_snapshot_applies_mtime_after_directory_projection(tmp_path):
    old_dir = tmp_path / "old"
    new_dir = tmp_path / "new"
    old_dir.mkdir()
    new_dir.mkdir()
    old_file = old_dir / "old.zip"
    new_file = new_dir / "new.zip"
    old_file.write_bytes(b"old")
    new_file.write_bytes(b"new")
    cutoff_ns = 60_000_000_000
    rows = [
        [0, "old/old.zip", "", 3, 3, 0, 0, 0, 0, 1, 1, 1, cutoff_ns - 1, b"old"],
        [1, "new/new.zip", "", 3, 3, 0, 0, 0, 0, 1, 1, 1, cutoff_ns, b"new"],
    ]
    result = worker_result(
        status="ok",
        manifest_rows=rows,
        verified_manifest={
            "validated": True,
            "inventory": [1, 2, 2, 6, 1],
        },
    )
    inventory = collect_output_inventory(str(tmp_path), result)
    config = make_config({
        "filesystem": {
            "scan_filters": [
                {"name": "mtime_range", "enabled": True, "start_utc": "1970-01-01T00:01Z"},
            ],
        },
    })
    policy = OutputScanPolicy(config)

    work = policy.prepare_scan(
        [str(tmp_path)],
        inventories={str(tmp_path.resolve()).lower(): inventory},
    )
    assert work.session is not None
    snapshot = work.session.snapshot_for_directory(str(tmp_path))
    paths, is_dirs, _sizes, _mtimes = snapshot.native_snapshot.materialize_columns()
    filtered = dict(zip(paths, is_dirs))
    raw_paths = set(snapshot.raw_native_snapshot.materialize_columns()[0])

    assert str(old_file) not in filtered
    assert filtered[str(old_dir)] is True
    assert filtered[str(new_file)] is False
    assert {str(old_file), str(new_file)} <= raw_paths
