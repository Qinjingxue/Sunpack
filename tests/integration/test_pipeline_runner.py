from pathlib import Path
import asyncio

import sunpack.pipeline.coordinator.engine as engine_module
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.core.config.schema import normalize_config
from sunpack.core.contracts.extraction import ExtractionResult
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
        "verification": {"enabled": False, "methods": []},
        "post_extract": {
            "archive_cleanup_mode": "d",
            "flatten_single_directory": True,
        },
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
        {"name": "zip_structure_accept", "enabled": True},
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

            out_dir=out_dir,

        )

    async def fake_extract_asyncio(_broker, task, out_dir, **_kwargs):
        return fake_extract(task, out_dir)

    def configure(runtime):
        original_close = runtime.extractor.close

        def tracked_close():
            original_close()
            call_order.append("close")

        monkeypatch.setattr(runtime.extractor, "inspect", lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})())
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
    # Source cleanup and subtree flattening both finish before the request closes.
    assert call_order[-1] == "close"
    assert call_order.count("postprocess") >= 1


def test_pipeline_runner_exposes_recent_passwords_without_password_manager():
    engine = PipelineEngine(normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
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


def test_independent_jobs_do_not_treat_existing_same_name_directory_as_output(tmp_path, monkeypatch):
    archive = tmp_path / "payload.zip"
    nested = tmp_path / "payload" / "inner.zip"
    archive.write_bytes(b"parent")
    nested.parent.mkdir()
    nested.write_bytes(b"nested")

    engine = PipelineEngine(normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "verification": {"enabled": False, "methods": []},
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
    })))
    extracted = []

    def fake_extract(task, out_dir):
        extracted.append(task.main_path)
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        return ExtractionResult(success=True, out_dir=out_dir)

    async def fake_extract_asyncio(_broker, task, out_dir, **_kwargs):
        return fake_extract(task, out_dir)

    def configure(runtime):
        monkeypatch.setattr(
            runtime.extractor,
            "inspect",
            lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})(),
        )
        monkeypatch.setattr(runtime.extractor, "extract", fake_extract)
        monkeypatch.setattr(runtime.extractor, "extract_asyncio", fake_extract_asyncio)

    _configure_request_runtime(engine, configure)

    async def run():
        async with engine:
            await engine.run([str(archive), str(nested)], direct=True)

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
    extracted = []

    def fake_extract(item, out_dir):
        extracted.append(item.main_path)
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        if item.main_path == str(archive):
            (out_path / "nested.zip").write_bytes(make_zip({"leaf.txt": b"leaf"}))
        return ExtractionResult(success=True, out_dir=out_dir)

    async def fake_extract_asyncio(_broker, item, out_dir, **_kwargs):
        return fake_extract(item, out_dir)

    def configure(runtime):
        monkeypatch.setattr(
            runtime.extractor,
            "inspect",
            lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})(),
        )
        monkeypatch.setattr(runtime.extractor, "extract", fake_extract)
        monkeypatch.setattr(runtime.extractor, "extract_asyncio", fake_extract_asyncio)

    _configure_request_runtime(engine, configure)

    async def run():
        async with engine:
            return await engine.run([str(archive)], direct=True)

    response = asyncio.run(run())

    expected_out_dir = output_root / "sub" / "payload"
    nested_archive = expected_out_dir / "nested.zip"
    assert expected_out_dir.exists()
    assert str(archive) in extracted
    assert str(nested_archive) in extracted
    assert response.summary.success_count == 2



def test_fast_job_recurses_before_slow_sibling_finishes(tmp_path, monkeypatch):
    slow = tmp_path / "slow.zip"
    fast = tmp_path / "fast.zip"
    slow.write_bytes(make_zip({"slow.txt": b"slow"}))
    fast.write_bytes(make_zip({"fast.txt": b"fast"}))
    output_root = tmp_path / "out"

    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "2",
        "verification": {"enabled": False, "methods": []},
        "output": {"root": str(output_root)},
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
    }))

    slow_release = asyncio.Event()
    nested_started = asyncio.Event()
    nested_paths = []

    async def run():
        async with PipelineEngine(config) as engine:
            def configure(runtime):
                async def fake_extract_asyncio(_broker, task, out_dir, **_kwargs):
                    out_path = Path(out_dir)
                    out_path.mkdir(parents=True, exist_ok=True)
                    if task.main_path == str(slow):
                        await slow_release.wait()
                    elif task.main_path == str(fast):
                        nested = out_path / "nested.zip"
                        nested.write_bytes(make_zip({"leaf.txt": b"leaf"}))
                        nested_paths.append(str(nested))
                    elif task.main_path in nested_paths:
                        nested_started.set()
                        slow_release.set()
                    return ExtractionResult(success=True, out_dir=out_dir)

                monkeypatch.setattr(
                    runtime.extractor,
                    "inspect",
                    lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})(),
                )
                monkeypatch.setattr(runtime.extractor, "extract_asyncio", fake_extract_asyncio)

            _configure_request_runtime(engine, configure)
            response = await asyncio.wait_for(
                engine.run([str(slow), str(fast)], direct=True),
                timeout=5,
            )
            return response

    response = asyncio.run(run())

    assert nested_started.is_set()
    assert response.summary.success_count == 3
