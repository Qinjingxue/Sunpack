"""Scope boundaries through real native planning, output routing and recovery.

These cases cover cross-directory execution and persistent directory identity;
existing shallow relation and in-memory output tests cannot detect either gap.
They reuse the small archive factory and WAL rather than a format Cartesian suite.
"""
import asyncio
import shutil
from pathlib import Path

import pytest

from sunpack.core.contracts.discovery_scope import DiscoveryScope
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.coordinator.output_ownership import OutputOwnership
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.runtime.watch.roots import WatchRootEntry
from tests.helpers.config_factory import make_config
from tests.helpers.real_archives import ArchiveFixtureFactory


@pytest.mark.parametrize("archive_format", ["7z", "zip", "rar"])
def test_cross_directory_parts_share_one_scope_and_execute_beside_entry(tmp_path, archive_format):
    case = ArchiveFixtureFactory().create(tmp_path / "fixture", "scope", archive_format,
        split=True, payload_size=256 * 1024, split_volume_size=100 * 1024,
        compression_level=0)
    root = tmp_path / "input"
    paths = []
    for index, part in enumerate(sorted(case.archive_dir.iterdir())):
        if not part.is_file():
            continue
        parent = root / str(index)
        parent.mkdir(parents=True)
        destination = parent / part.name
        shutil.copyfile(part, destination)
        paths.append(str(destination))
    assert len(paths) > 1
    config = make_config({"recursive_extract": "1", "post_extract": {"archive_cleanup_mode": "k"}})
    provider = ArchiveTaskProvider(config)
    assert not provider.scan_targets([str(root)])
    session = DiscoveryScanSession(config=config, recursive=True)
    tasks = provider.scan_targets([str(root)], scan_session=session)
    assert len(tasks) == 1 and set(tasks[0].all_parts) == set(paths)
    task = tasks[0]
    # The same range must survive the missing-volume retry boundary.
    group = provider.resolve_volume_once([task.main_path], task.runtime["discovery_scope"], format_hint=archive_format)
    assert group is not None and set(group.input_paths) == set(paths)

    async def execute():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(root)], recursive=True)

    result = asyncio.run(execute()).summary
    assert result.success_count == 1 and not result.failed_tasks
    output = Path(result.target_results[0].output_dir)
    assert output.parent == Path(task.main_path).parent
    marker = next(output.rglob(case.marker_name))
    assert marker.read_text(encoding="utf-8") == case.marker_text


def test_catalog_and_output_identity_survive_restart_and_do_not_inherit_names(tmp_path, monkeypatch):
    import sunpack.runtime.watch.service as service
    root = tmp_path / "input"
    root.mkdir()
    (root / "sample.part1.fake").write_bytes(b"external")
    monkeypatch.setattr(service, "_read_watch_root_entries", lambda: [WatchRootEntry(str(root), recursive=True)])
    config = make_config({"watch": {"state_dir": str(tmp_path / "state")}})
    owner = OutputOwnership(config)
    store = owner.state_for()
    scope = DiscoveryScope(str(root), recursive=True)
    options = DirectoryScanner.compile_scan_options(config)
    operations, errors = options.catalog_update(store._native, scope.native)
    assert not errors
    store.commit_runtime(operations, durable=True)
    generated = root / "generated"
    owner.begin(str(generated), "request")
    (generated / "sample.part2.fake").write_bytes(b"generated")
    operations, errors = options.catalog_update(store._native, scope.native)
    assert not errors
    store.commit_runtime(operations, durable=True)
    _, raw = options.catalog_snapshot(store._native, scope.native, str(root / "sample.part1.fake"))
    assert raw.file_columns()[0] == [str(root / "sample.part1.fake")]
    owner.finish("request")
    relocated = root / "moved"
    generated.rename(relocated)
    owner.relocate(str(generated), str(relocated))
    generated.mkdir()
    assert not owner.protected(str(generated / "new.zip"))
    assert owner.protected(str(relocated / "sample.part2.fake"))
    owner.close()
    restarted = OutputOwnership(config)
    try:
        assert restarted.protected(str(relocated / "sample.part2.fake"))
        shutil.rmtree(relocated)
        relocated.mkdir()
        restarted.reconcile(str(relocated))
        assert not restarted.protected(str(relocated / "new.zip"))
    finally:
        restarted.close()
