from pathlib import Path
import asyncio
import io

import sunpack.pipeline.coordinator.engine as engine_module
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.core.config.schema import normalize_config
from sunpack.core.contracts.extraction import ExtractionResult
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_zip


def test_unicode_inputs_and_output_collisions_across_concurrent_origins(tmp_path):
    """Cover distinct NTFS names and non-ASCII output collisions together.

    Existing ASCII/canonical-Unicode cases miss both failures; four small real
    carrier requests justify their cost by checking discovery through cleanup.
    """
    from sunpack.core.contracts.pipeline import PipelineTarget
    from tests.helpers.config_factory import make_config

    jobs = []
    for origin in ("foreground", "watch"):
        sources = tmp_path / origin
        sources.mkdir()
        for index, name in enumerate(("İ.bin", "i\u0307.bin")):
            archive = sources / name
            entries = {
                "É.txt": f"{origin}-{index}-upper".encode(),
                "é.txt": f"{origin}-{index}-lower".encode(),
                "İ.txt": b"single code point",
                "i\u0307.txt": b"two code points",
            }
            archive.write_bytes(b"carrier prefix\0" * 20 + make_zip(entries) + b"carrier tail" * 20)
            jobs.append((origin, archive, entries))
    config = make_config({
        "recursive_extract": 1,
        "post_extract": {"archive_cleanup_mode": "d", "flatten_single_directory": False},
    })

    async def run():
        async with PipelineEngine(config) as engine:
            return await asyncio.gather(*(
                engine.run(
                    [PipelineTarget(str(archive), {"root": str(tmp_path / "out" / origin)})],
                    origin=origin, stdout=io.StringIO(), stderr=io.StringIO(),
                )
                for origin, archive, _entries in jobs
            ))

    for (_origin, archive, entries), response in zip(jobs, asyncio.run(run())):
        assert response.summary.success_count == 1
        result = response.summary.target_results[0]
        assert result.input_path == str(archive)
        assert not archive.exists()
        assert {path.name: path.read_bytes() for path in Path(result.output_dir).iterdir()} == {
            "É.txt": entries["É.txt"], "é(1).txt": entries["é.txt"],
            "İ.txt": entries["İ.txt"], "i\u0307.txt": entries["i\u0307.txt"],
        }


def test_sunpack_payload_recurses_across_concurrent_origins(tmp_path):
    # One real pipeline case covers scan, matching, nested authorization and
    # generated-output ownership together; individual inventory tests cannot.
    payload = b"nested payload" * 1024
    inner = make_zip({"payload.bin": payload})
    archives = []
    for origin in ("foreground", "watch"):
        archive = tmp_path / f"{origin}.dat"
        archive.write_bytes(make_zip({
            ".sunpack/inner.dat": inner,
            ".sunpack/extraction_manifest.json": b"ordinary user content",
            "assets.sunpack/cache.bin": b"cache",
        }))
        archives.append((origin, archive))
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "2",
        "output": {"root": str(tmp_path / "out")},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    }))

    async def run():
        async with PipelineEngine(config) as engine:
            return await asyncio.gather(*(
                engine.run([str(archive)], origin=origin,
                           stdout=io.StringIO(), stderr=io.StringIO())
                for origin, archive in archives
            ))

    responses = asyncio.run(run())
    for response in responses:
        assert not response.summary.failed_tasks
        assert response.summary.success_count == 2
        outer = next(item for item in response.summary.target_results
                     if Path(item.input_path).parent == tmp_path)
        output = Path(outer.output_dir)
        assert (output / ".sunpack" / "extraction_manifest.json").read_bytes() == b"ordinary user content"
        assert (output / "assets.sunpack" / "cache.bin").read_bytes() == b"cache"
        leaf = next(item for item in response.summary.target_results if item is not outer)
        assert (Path(leaf.output_dir) / "payload.bin").read_bytes() == payload
        assert not (Path(leaf.output_dir) / ".sunpack").exists()


def test_deep_detect_only_applies_to_initial_round_in_real_pipeline(tmp_path):
    """Deep must find the initial carrier without unpacking its APK/PE outputs."""
    from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
    from tests.helpers.config_factory import make_config
    from tests.helpers.fs_builder import make_minimal_pe

    apk_bytes = make_zip({"apk-only.txt": b"apk resource"})
    exe_bytes = make_minimal_pe() + make_zip({"exe-only.txt": b"exe resource"})
    nested_bytes = make_zip({"nested-only.txt": b"ordinary archive"})
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"non-archive prefix" * 16 + make_zip({
        "client.apk": apk_bytes,
        "launcher.exe": exe_bytes,
        "nested.zip": nested_bytes,
    }))
    output_root = tmp_path / "out"
    config = make_config({
        "recursive_extract": "2",
        "recursive_authorization": {"enabled": False},
        "filesystem": {
            "scan_filters_enabled": True,
            "scan_filters": [{
                "name": "blacklist",
                "enabled": True,
                "blocked_extensions": [".bin", ".apk"],
            }],
        },
        "output": {"root": str(output_root)},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    })

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run(
                [str(carrier)],
                detection_options=EmbeddedOptions(force_scan=True),
                stdout=io.StringIO(),
                stderr=io.StringIO(),
            )

    response = asyncio.run(run())
    assert response.summary.failed_tasks == []
    assert response.summary.success_count == 2
    assert {Path(item.input_path).name for item in response.summary.target_results} == {
        "carrier.bin", "nested.zip",
    }
    assert [path.read_bytes() for path in output_root.rglob("client.apk")] == [apk_bytes]
    assert [path.read_bytes() for path in output_root.rglob("launcher.exe")] == [exe_bytes]
    assert [path.read_bytes() for path in output_root.rglob("nested-only.txt")] == [b"ordinary archive"]
    assert not list(output_root.rglob("apk-only.txt"))
    assert not list(output_root.rglob("exe-only.txt"))


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
                "max_queue_jobs": 256,
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

    assert captured["extractor"]["max_queue_jobs"] == 256
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
        {"name": "size_range", "enabled": True, "min_bytes": 0},
        {"name": "zip_structure_accept", "enabled": True},
    ]))

    engine = PipelineEngine(config)
    call_order = []
    postprocess_actions = engine_module.PostProcessActions

    class TrackedPostProcessActions:
        def __init__(self, *args, **kwargs):
            self._delegate = postprocess_actions(*args, **kwargs)
            self.flattener = self._delegate.flattener

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
    archive.write_bytes(make_zip({"parent.txt": b"parent"}))

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


def test_encrypted_comment_zip_in_nested_carriers_runs_for_both_origins(tmp_path):
    # Verifier-only and unmapped nesting tests miss routing children back to
    # the mapped root. Reuse this real encrypted carrier for three levels and
    # both concurrent origins; exact paths add coverage without another fixture.
    import struct
    from sunpack.core.contracts.pipeline import PipelineTarget
    from tests.unit.test_zip_password_encoding import _write_ansi_password_zip, PAYLOAD
    seed = tmp_path / "seed.zip"
    _write_ansi_password_zip(seed, password_bytes=b"comment-secret")
    data = seed.read_bytes()
    comment = b"ordinary PK\x05\x06 comment"
    carrier = b"carrier prefix" + data[:-2] + struct.pack("<H", len(comment)) + comment + b"carrier suffix"
    sources = []
    for origin in ("foreground", "watch"):
        input_root = tmp_path / origin
        source = input_root / "sub" / "outer.dat"
        source.parent.mkdir(parents=True)
        source.write_bytes(make_zip({"folder/middle.blob": make_zip({"child/inner.jpg": carrier})}))
        mapping = {"root": str(tmp_path / "out" / origin), "common_root": str(input_root),
                   "fixed_root": origin == "watch"}
        sources.append((origin, source, mapping))
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "3", "user_passwords": ["wrong", "comment-secret"],
        "builtin_passwords": [],
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    }))
    async def run():
        async with PipelineEngine(config) as engine:
            return await asyncio.gather(*(
                engine.run([PipelineTarget(str(source), mapping)], origin=origin,
                           stdout=io.StringIO(), stderr=io.StringIO())
                for origin, source, mapping in sources
            ))
    for (origin, source, mapping), response in zip(sources, asyncio.run(run())):
        assert not response.summary.failed_tasks
        assert response.summary.success_count == 3
        root = Path(mapping["root"])
        outer_output = root / "outer" if origin == "watch" else root / "sub" / "outer"
        middle_output = outer_output / "folder" / "middle"
        leaf_output = middle_output / "child" / "inner"
        assert {Path(item.input_path): Path(item.output_dir) for item in response.summary.target_results} == {
            source: outer_output,
            outer_output / "folder" / "middle.blob": middle_output,
            middle_output / "child" / "inner.jpg": leaf_output,
        }
        assert list(root.rglob("secret.txt")) == [leaf_output / "secret.txt"]
        assert (leaf_output / "secret.txt").read_bytes() == PAYLOAD
        assert {path.name for path in root.iterdir()} == {"outer" if origin == "watch" else "sub"}


def test_real_native_zip_progress_stays_complete_after_watch_semantic_finish(tmp_path):
    """Extract a real ZIP through the native worker and retain final UI state.

    Watch emits task_output_finished after task_finished; it must not reset the
    terminal's completed row to extracting/0%, even without byte fields.
    """
    from tests.helpers.config_factory import make_config

    payload = b"native progress payload" * 16384
    archive = tmp_path / "real-progress.zip"
    archive.write_bytes(make_zip({"payload.bin": payload}))
    config = make_config({
        "recursive_extract": "1",
        "output": {"root": str(tmp_path / "out")},
        "verification": {"enabled": False, "methods": []},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    })
    output = io.StringIO()
    output.isatty = lambda: True
    output.supports_terminal_updates = True
    output.terminal_columns = 100
    events = []
    reporters = []

    engine = PipelineEngine(config)
    _configure_request_runtime(engine, lambda runtime: reporters.append(runtime.reporter))

    async def run():
        async with engine:
            return await engine.run(
                [str(archive)], direct=True, origin="watch", stdout=output,
                progress_callback=lambda task, event: events.append(dict(event)),
            )

    response = asyncio.run(run())
    assert response.summary.success_count == 1
    assert (Path(response.summary.target_results[0].output_dir) / "payload.bin").read_bytes() == payload
    assert any(event.get("type") == "progress" for event in events)
    assert any(event.get("event") == "extract_ready" for event in events)
    assert any(event.get("event") == "task_output_finished" for event in events)
    reporter = reporters[0]
    rows = list(reporter._task_rows.values())
    assert len(rows) == 1
    assert rows[0]["state"] == "complete"
    assert rows[0]["progress_known"] is True
    assert rows[0]["progress"] == 1.0
    assert "100%" in output.getvalue()
