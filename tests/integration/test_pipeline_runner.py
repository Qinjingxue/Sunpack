from pathlib import Path
import asyncio

import sunpack.coordinator.engine as engine_module
from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.async_work import CancellationToken
from sunpack.config.schema import normalize_config
from sunpack.contracts.extraction import ExtractionResult
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_zip


def _configure_request_runtime(engine, callback):
    factory = engine._request_runtime_factory

    def configured(*args):
        runtime = factory(*args)
        callback(runtime)
        return runtime

    engine._request_runtime_factory = configured


def test_pipeline_runner_passes_native_worker_overrides():
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "performance": {
            "worker": {
                "watchdog_no_progress_timeout_seconds": 180,
                "thread_capacity": 3,
            },
        },
    }))

    engine = PipelineEngine(config)
    captured = {}
    _configure_request_runtime(engine, lambda runtime: captured.update(
        extractor=runtime.extractor.process_config,
    ))
    async def run():
        async with engine:
            await engine.run(["missing.zip"])
    asyncio.run(run())

    assert captured["extractor"]["watchdog_no_progress_timeout_seconds"] == 180
    assert captured["extractor"]["thread_capacity"] == 3


def test_pipeline_progress_observer_receives_extract_ready_before_native_progress(tmp_path):
    archive = tmp_path / "ready.zip"
    archive.write_bytes(make_zip({"payload.bin": b"payload" * 4096}))
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "output": {"root": str(tmp_path / "out")},
        "repair": {"enabled": False},
        "verification": {"enabled": False, "methods": []},
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
    }))
    events = []

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run(
                [str(archive)],
                direct=True,
                progress_callback=lambda task, event: events.append((task, event)),
            )

    response = asyncio.run(run())

    assert response.summary.success_count == 1
    ready_indices = [
        index
        for index, (_task, event) in enumerate(events)
        if event.get("type") == "semantic" and event.get("event") == "extract_ready"
    ]
    assert ready_indices
    native_indices = [
        index
        for index, (_task, event) in enumerate(events)
        if event.get("type") == "progress"
    ]
    assert not native_indices or ready_indices[0] < native_indices[0]


def test_pipeline_runner_uses_tmp_path_and_applies_success_postprocess(tmp_path, monkeypatch):
    archive = tmp_path / "payload.zip"
    archive.write_bytes(make_zip({"inside.txt": "hello"}))

    config = normalize_config(with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": "1",
        "repair": {"enabled": False},
        "verification": {"enabled": False, "methods": []},
        "post_extract": {
            "archive_cleanup_mode": "d",
            "flatten_single_directory": True,
        },
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
        {"name": "zip_structure_accept", "enabled": True},
    ], scoring=[
        {"name": "zip_structure_identity", "enabled": True},
    ]))

    engine = PipelineEngine(config)
    call_order = []
    postprocess_actions = engine_module.PostProcessActions

    class TrackedPostProcessActions:
        def __init__(self, *args, **kwargs):
            self._delegate = postprocess_actions(*args, **kwargs)

        def apply(self, **kwargs):
            call_order.append("postprocess")
            return self._delegate.apply(**kwargs)

    monkeypatch.setattr(engine_module, "PostProcessActions", TrackedPostProcessActions)

    def fake_extract(task, out_dir):
        out_path = tmp_path / "payload" / "inside.txt"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("hello", encoding="utf-8")
        return ExtractionResult(
            success=True,
            archive=task.main_path,
            out_dir=out_dir,
            all_parts=task.all_parts,
        )

    async def fake_extract_asyncio(_broker, task, out_dir, **_kwargs):
        return fake_extract(task, out_dir)

    def configure(runtime):
        original_close = runtime.extractor.close

        def tracked_close():
            original_close()
            call_order.append("close")

        monkeypatch.setattr(runtime.extractor, "inspect", lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})())
        monkeypatch.setattr(runtime.batch_runner.resource_inspector, "inspect", lambda task: task)
        monkeypatch.setattr(runtime.extractor, "extract", fake_extract)
        monkeypatch.setattr(runtime.extractor, "extract_asyncio", fake_extract_asyncio)
        monkeypatch.setattr(runtime.extractor, "close", tracked_close)

    _configure_request_runtime(engine, configure)

    async def run():
        async with engine:
            return (await engine.run([str(tmp_path)])).summary
    summary = asyncio.run(run())

    assert summary.success_count == 1
    assert summary.failed_tasks == []
    assert not archive.exists()
    assert (tmp_path / "payload" / "inside.txt").exists()
    # Source archives are cleaned per task, so postprocess now runs before the
    # extractor is closed at the end of the request.
    assert call_order[:2] == ["postprocess", "close"]


def test_pipeline_runner_exposes_recent_passwords_without_password_manager():
    engine = PipelineEngine(normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "repair": {"enabled": False},
        "verification": {"enabled": False, "methods": []},
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "user_passwords": ["secret"],
        "builtin_passwords": [],
    })))
    _configure_request_runtime(
        engine,
        lambda runtime: runtime.extractor.password_store.remember_success("secret"),
    )
    async def run():
        async with engine:
            await engine.run(["missing.zip"])
            assert engine.recent_passwords == ["secret"]
    asyncio.run(run())


def test_batch_does_not_treat_existing_same_name_directory_as_output(tmp_path, monkeypatch):
    archive = tmp_path / "payload.zip"
    nested = tmp_path / "payload" / "inner.zip"
    archive.write_bytes(b"parent")
    nested.parent.mkdir()
    nested.write_bytes(b"nested")

    engine = PipelineEngine(normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "repair": {"enabled": False},
        "verification": {"enabled": False, "methods": []},
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
    })))
    extracted = []

    def task_for(path):
        bag = FactBag()
        return ArchiveTask(fact_bag=bag, score=10, main_path=str(path), all_parts=[str(path)])

    def fake_extract(task, out_dir):
        extracted.append(task.main_path)
        return ExtractionResult(success=True, archive=task.main_path, out_dir=out_dir, all_parts=task.all_parts)

    async def fake_extract_asyncio(_broker, task, out_dir, **_kwargs):
        return fake_extract(task, out_dir)

    captured = {}
    def configure(runtime):
        captured["runtime"] = runtime
        monkeypatch.setattr(runtime.extractor, "inspect", lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})())
        monkeypatch.setattr(runtime.batch_runner.resource_inspector, "inspect", lambda task: task)
        monkeypatch.setattr(runtime.extractor, "extract", fake_extract)
        monkeypatch.setattr(runtime.extractor, "extract_asyncio", fake_extract_asyncio)

    _configure_request_runtime(engine, configure)
    async def run():
        async with engine:
            await engine.run([str(tmp_path / "missing.zip")])
            await captured["runtime"].batch_runner.execute_async(
                [task_for(archive), task_for(nested)],
                broker=engine.work_broker,
                cancellation=CancellationToken(),
            )
    asyncio.run(run())

    assert set(extracted) == {str(archive), str(nested)}


def test_output_root_preserves_tree_and_recursive_scan_uses_success_outputs(tmp_path, monkeypatch):
    input_root = tmp_path / "input"
    archive = input_root / "sub" / "payload.zip"
    output_root = tmp_path / "out"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"parent")

    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "2",
        "repair": {"enabled": False},
        "verification": {"enabled": False, "methods": []},
        "output": {
            "root": str(output_root),
            "common_root": str(input_root),
        },
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
    }))
    engine = PipelineEngine(config)
    task = ArchiveTask(fact_bag=FactBag(), score=10, main_path=str(archive), all_parts=[str(archive)], logical_name="payload")

    def fake_extract(item, out_dir):
        nested = Path(out_dir) / "nested.zip"
        nested.parent.mkdir(parents=True, exist_ok=True)
        nested.write_bytes(b"nested")
        return ExtractionResult(success=True, archive=item.main_path, out_dir=out_dir, all_parts=item.all_parts)

    async def fake_extract_asyncio(_broker, item, out_dir, **_kwargs):
        return fake_extract(item, out_dir)

    captured = {}
    def configure(runtime):
        captured["runtime"] = runtime
        monkeypatch.setattr(runtime.extractor, "inspect", lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})())
        monkeypatch.setattr(runtime.batch_runner.resource_inspector, "inspect", lambda item: item)
        monkeypatch.setattr(runtime.extractor, "extract", fake_extract)
        monkeypatch.setattr(runtime.extractor, "extract_asyncio", fake_extract_asyncio)

    _configure_request_runtime(engine, configure)

    async def run():
        async with engine:
            await engine.run([str(input_root / "missing.zip")])
            return await captured["runtime"].batch_runner.execute_async(
                [task],
                broker=engine.work_broker,
                cancellation=CancellationToken(),
            )
    scan_roots = asyncio.run(run())

    expected_out_dir = output_root / "sub" / "payload"
    assert expected_out_dir.exists()
    assert scan_roots == [str(expected_out_dir)]
