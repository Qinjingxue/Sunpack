from __future__ import annotations

from sunpack.pipeline.coordinator.output_ownership import OutputOwnership

from types import SimpleNamespace
import asyncio
import pytest

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, InputExtent
from sunpack.core.contracts.pipeline import PipelineDiscovery
from sunpack.pipeline.coordinator.engine import _CompletedWatchOutput, _PathLeaseRegistry, _RequestRuntime
from sunpack.runtime.watch.scheduler import _response_claimed_paths
from tests.helpers.archive_tasks import make_task_from_descriptor


def test_output_publication_and_final_watch_lease_share_one_authority(tmp_path, monkeypatch):
    """Exercise both race orders, explicit CLI access and released lifetimes.

    Existing source-only lease tests do not include worker-thread output intents;
    one synchronized scenario covers that missing correctness boundary.
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor
    import sunpack.pipeline.coordinator.engine as engine_module
    from sunpack.pipeline.coordinator.output_ownership import OutputOwnership
    from sunpack_native import watch_path_identity

    root = tmp_path / "generated"
    root.mkdir()
    source = root / "inner.disguised"
    source.write_bytes(b"payload")
    ownership = OutputOwnership({})
    ownership.state_for(str(tmp_path / "state.json"))
    registry = _PathLeaseRegistry(ownership)
    volume, identity, _ = watch_path_identity(str(root))
    snapshot_ready = threading.Event()
    published = threading.Event()
    snapshot = engine_module._snapshot_lease_path

    def before_claim(path):
        prepared = snapshot(path)
        if path == str(source) and not published.is_set():
            snapshot_ready.set()
            assert published.wait(10)
        return prepared

    def publish():
        assert snapshot_ready.wait(10)
        try:
            ownership.begin(str(root), "producer", identities=[f"{volume}|{identity}"])
        finally:
            published.set()

    async def scenario():
        with ThreadPoolExecutor(max_workers=1) as pool:
            publisher = pool.submit(publish)
            with monkeypatch.context() as patch:
                patch.setattr(engine_module, "_snapshot_lease_path", before_claim)
                with pytest.raises(engine_module._ProtectedWatchInput):
                    await registry.acquire("watch", [str(source)], external_watch=True)
            publisher.result(timeout=10)
        assert not registry._owned
        await registry.acquire("explicit-cli", [str(source)])
        await registry.release("explicit-cli")
        await registry.acquire("authorized-recovery", [str(source)], external_watch=False)
        await registry.release("authorized-recovery")
        ownership.finish("producer")
        assert not ownership._active_owners
        await registry.acquire("admitted-watch", [str(source)], external_watch=True)
        with pytest.raises(FileExistsError, match="active input"):
            ownership.begin(str(root), "late-producer", identities=[f"{volume}|{identity}"])
        assert not ownership.protected(str(source))
        await registry.release("admitted-watch")
        with pytest.raises(FileExistsError):
            ownership.begin(str(root), "failed-mkdir")
        assert not ownership._active_owners
        assert not registry._prefix_owners and not registry._exact_owners

    try:
        asyncio.run(scenario())
    finally:
        ownership.close()


def test_watch_consumes_pipeline_claimed_paths_without_reconstructing_membership(tmp_path):
    first = tmp_path / "archive.7z.001"
    second = tmp_path / "archive.7z.002"
    response = SimpleNamespace(
        discovery=PipelineDiscovery(
            entry_paths=(str(second),),
            claimed_paths=(str(first), str(second)),
        )
    )

    assert _response_claimed_paths(response, str(second)) == [
        str(first),
        str(second),
    ]


def test_watch_completed_generation_records_complete_physical_family(tmp_path):
    first = str(tmp_path / "archive.7z.001")
    second = str(tmp_path / "archive.7z.002")
    version = (("first", 1, 2, 3, 4), ("second", 1, 2, 3, 4))
    calls = []

    runtime = object.__new__(_RequestRuntime)
    runtime.submission = SimpleNamespace(origin="watch", request_id="request")
    runtime.path_leases = SimpleNamespace(
        ownership_version_for=lambda owner, paths: calls.append((owner, paths)) or version,
    )

    descriptor = SimpleNamespace(part_paths=lambda: (first, second))
    data_task = SimpleNamespace(
        archive_input=lambda: descriptor,
        carrier_path=first,
    )
    launcher_task = SimpleNamespace(
        archive_input=lambda: descriptor,
        carrier_path=str(tmp_path / "archive.exe"),
    )

    assert runtime._watch_generation_for_task(data_task, depth=1) == version
    assert calls == [("request", (first, second))]
    assert runtime._watch_generation_for_task(launcher_task, depth=1) == version
    assert runtime._watch_generation_for_task(data_task, depth=2) == ()


def test_retry_checks_completed_final_family_after_acquiring_lease(tmp_path):
    async def scenario():
        parts = [tmp_path / "a.001", tmp_path / "a.002"]
        for path in parts:
            path.write_text("part")
        output = tmp_path / "output"
        output.mkdir()
        registry = _PathLeaseRegistry(OutputOwnership({"watch": {}}))
        registry.output_ownership.remember_completed(registry.input_version_for(map(str, parts)), str(output))
        runtime = object.__new__(_RequestRuntime)
        runtime.path_leases = registry
        runtime.config = {}
        runtime.submission = SimpleNamespace(origin="watch", request_id="retry",
            detection_options=SimpleNamespace(force_scan=False))
        runtime.source_cleanup = SimpleNamespace(register=lambda tasks: None)
        runtime._report_progress = lambda task, event: None
        task = make_task_from_descriptor(ArchiveInputDescriptor(
            str(parts[0]), open_mode="concat_ranges", logical_name="a.7z",
            extents=[InputExtent(str(path)) for path in parts],
        ))
        with pytest.raises(_CompletedWatchOutput) as stopped:
            await runtime._ensure_task_lease(task)
        assert stopped.value.output_dir == str(output)
        await registry.release("retry")
        # A changed physical member invalidates the entire completed generation.
        parts[1].write_text("changed part")
        await runtime._ensure_task_lease(task)
        await registry.release("retry")

    asyncio.run(scenario())


def test_consumed_family_generation_rejects_changed_surviving_member(tmp_path):
    registry = _PathLeaseRegistry(OutputOwnership({"watch": {}}))
    first, second = tmp_path / "a.001", tmp_path / "a.002"
    first.write_text("first")
    second.write_text("second")
    paths = [str(first), str(second)]
    original = registry.input_version_for(paths)
    first.unlink()
    assert registry.input_version_for(paths, departed_version=original) == original
    second.write_text("changed second")
    assert registry.input_version_for(paths, departed_version=original) == ()


def test_late_completed_generation_lookup_preserves_newer_record(tmp_path):
    registry = _PathLeaseRegistry(OutputOwnership({"watch": {}}))
    path = tmp_path / "a.001"
    path.write_text("generation A")
    first = registry.input_version_for([str(path)])
    output_a, output_b = tmp_path / "out-a", tmp_path / "out-b"
    output_a.mkdir()
    output_b.mkdir()
    registry.output_ownership.remember_completed(first, str(output_a))
    path.write_text("generation B with different bytes")
    second = registry.input_version_for([str(path)])
    assert first != second
    registry.output_ownership.remember_completed(second, str(output_b))
    # A delayed commit from the previous owner must not replace this generation.
    registry.output_ownership.remember_completed(first, str(output_a))
    assert registry.completed_watch_output(first) == ""
    assert registry.completed_watch_output(second) == str(output_b)
    output_b.rmdir()
    assert registry.completed_watch_output(second) == ""

