from __future__ import annotations

import asyncio
import shutil
import subprocess
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from sunpack.core.contracts.failures import FailureKind
from sunpack.core.contracts.results import OutcomeKind
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.pipeline.coordinator.scanner import ScanOrchestrator
from sunpack.runtime.cli.cli_context import CliContext
from sunpack.runtime.cli.cli_reporter import CliReporter
from sunpack.runtime.cli.commands import extract
from sunpack.runtime.watch import scheduler as scheduler_module
from sunpack.runtime.watch.scheduler import WatchScheduler
from tests.helpers.config_factory import make_config
from tests.helpers.native_fixture import assemble_carrier
from tests.helpers.passwords import write_password_json
from tests.helpers.real_archives import ArchiveFixtureFactory, create_encrypted_rar_archive
from tests.helpers.tool_config import get_optional_rar, require_7z


@pytest.fixture
def nested_failures(tmp_path):
    if get_optional_rar() is None:
        pytest.skip("RAR fixture generator is required")
    password = f"discovery-recovery-{uuid.uuid4().hex}"
    rar = create_encrypted_rar_archive(tmp_path, "carrier_payload", password=password)
    encrypted = ArchiveFixtureFactory().create(
        tmp_path, "encrypted_payload", "7z", password=password, payload_size=4096,
    )
    split = ArchiveFixtureFactory().create(
        tmp_path, "split_payload", "7z", split=True,
        payload_size=65536, split_volume_size=32768,
    )
    wrapper = tmp_path / "fixture" / "wrapper"
    wrapper.mkdir(parents=True)
    carrier = wrapper / "carrier.jpg"
    assemble_carrier(carrier, [rar.entry_path])
    shutil.copy2(encrypted.entry_path, wrapper / "encrypted.opaque")
    parts = sorted(split.archive_dir.iterdir())
    for number, part in enumerate(parts[:-1], start=1):
        shutil.copy2(part, wrapper / f"split.7z.{number:03d}.photo")
    tail_name = f"split.7z.{len(parts):03d}.photo"
    watch_root = tmp_path / "watch"
    watch_root.mkdir()
    outer = watch_root / "outer.zip"
    subprocess.run(
        [str(require_7z()), "a", "-tzip", "-mx=0", str(outer), "wrapper"],
        cwd=wrapper.parent, check=True, capture_output=True,
    )
    config = make_config({
        "recursive_extract": 3, "builtin_passwords": [], "user_passwords": [],
        "output": {"root": str(tmp_path / "out")},
        "embedded_scan": {"recursive_candidate_ratio": 1e-9},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": True},
        "watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0},
        "cli": {"quiet": True},
    })
    return SimpleNamespace(
        outer=outer, carrier=carrier, password=password, config=config,
        tail=parts[-1], tail_name=tail_name, watch_root=watch_root,
        markers={case.marker_name: case.marker_text for case in (rar, encrypted, split)},
    )


def test_watch_recovers_concurrent_discovery_and_execution_failures_after_restart(
    tmp_path, monkeypatch, nested_failures,
):
    # Single-target password tests cannot detect lost ownership when an outer
    # success has multiple scan and extraction failures, or a volume arrives later.
    case = nested_failures
    monkeypatch.setattr(scheduler_module, "validate_ntfs_watch_roots", lambda roots: None)
    from sunpack.core.passwords.internal import builtin

    responses, notices = [], []

    async def scenario():
        async with PipelineEngine(case.config) as engine:
            run = engine.run

            async def record(*args, **kwargs):
                response = await run(*args, **kwargs)
                responses.append(response)
                return response

            monkeypatch.setattr(engine, "run", record)

            def scheduler():
                watcher = WatchScheduler(
                    case.config, [str(case.watch_root)],
                    output_roots={str(case.watch_root): str(tmp_path / "out")},
                    state_path=str(tmp_path / "state.snapshot"), cold_start_seconds=0,
                    pipeline_engine=engine,
                )
                watcher._notify = lambda *args: notices.append(args)
                return watcher

            watcher = scheduler()
            try:
                watcher.enqueue(str(case.outer))
                await watcher.run_once()
                first = await watcher.drain()
                assert first.failed == 1
                summary = responses[0].summary
                assert not summary.scan_failures
                failed = [r for r in summary.target_results if r.outcome_kind == OutcomeKind.FAILURE]
                assert len(failed) == 3
                assert sum(r.failure.is_password_failure for r in failed) == 2
                assert sum(r.failure.kind == FailureKind.MISSING_VOLUME for r in failed) == 1
                assert all(Path(r.input_path).parent == case.watch_root for r in failed)
                assert all(r.failure.details["promoted_nested_input"] for r in failed)
                assert all(Path(r.input_path).is_file() for r in failed)
                assert sorted(e.status for e in watcher.state.entries.values()) == [
                    "failed_password", "failed_password", "suspended_missing_volume",
                ]
                assert all(n[0] != "failed" for n in notices)
                watcher.state.flush()
            finally:
                await watcher.aclose()

            watcher = scheduler()
            try:
                watcher._reconcile_persisted_blockers()
                write_password_json(builtin.builtin_password_path(), scopes=[(case.password, [str(case.watch_root)])])
                watcher.notify_password_source_changed("builtin_password_file")
                await watcher.run_once()
                await watcher.drain()
                assert [e.status for e in watcher.state.entries.values()] == ["suspended_missing_volume"]
                tail = case.watch_root / case.tail_name
                shutil.copy2(case.tail, tail)
                scheduler_module._WatchEventHandler(watcher)._handle_path(str(tail), event_type="created")
                await watcher.run_once()
                await watcher.drain()
                assert not watcher.state.entries
                assert not watcher._inflight_requests
                assert watcher.pending_count == 0
            finally:
                await watcher.aclose()

    asyncio.run(scenario())
    for name, text in case.markers.items():
        outputs = list((tmp_path / "out").rglob(name))
        assert len(outputs) == 1 and outputs[0].read_text(encoding="utf-8") == text
    assert sorted(p.name for p in case.watch_root.iterdir()) == ["outer.zip"]


@pytest.mark.parametrize("provide_password", [False, True], ids=["prompt-and-retry", "missing-volume-only"])
def test_cli_scan_failure_prompts_only_for_password_and_reports_missing_volume(
    tmp_path, monkeypatch, nested_failures, provide_password,
):
    # Existing CLI mocks never exercise scan failures becoming retry targets.
    # The password-present case also proves missing volumes finish without input.
    case = nested_failures
    report = ScanOrchestrator(case.config).scan_report([str(case.carrier)])
    assert report.tasks == [] and report.findings
    assert all(f.reason == "embedded_password_required" for f in report.findings)
    responses, prompts = [], []

    class RecordingEngine(PipelineEngine):
        async def run(self, paths, **kwargs):
            response = await super().run(paths, **kwargs)
            responses.append((list(paths), response))
            return response

    def read_input(prompt):
        assert not provide_password, "missing-volume errors must never request console input"
        prompts.append(prompt)
        return next(answers)

    answers = iter(["y", case.password, ""])
    monkeypatch.setattr(extract, "load_request_config", lambda cwd: case.config)
    monkeypatch.setattr(extract, "pipeline_engine", RecordingEngine)
    monkeypatch.setattr(extract, "collect_clipboard_passwords", lambda cfg: [])
    args = SimpleNamespace(
        paths=[str(case.outer)], password=[case.password] if provide_password else ["wrong-candidate"],
        password_file=None, prompt_passwords=False, no_builtin_passwords=True,
        recursive_extract=None, archive_cleanup_mode=None, flatten_single_directory=None,
        json=False, quiet=False, verbose=False, recursive=False,
    )
    code, result = asyncio.run(extract.handle(args, CliContext(
        language="en", reporter=CliReporter(quiet=True), cwd=str(tmp_path), input_reader=read_input,
    )))
    assert code != 0 and len(result.errors) == 1
    assert result.summary["failed_count"] == 1
    assert result.summary["password_retry_count"] == (0 if provide_password else 1)
    last = responses[-1][1].summary
    if provide_password:
        assert not prompts and len(responses) == 1
        assert [r.failure.kind for r in last.target_results if r.failure] == [FailureKind.MISSING_VOLUME]
    else:
        assert prompts and len(responses) == 2
        assert {Path(p).name for p in responses[1][0]} == {"carrier.jpg", "encrypted.opaque"}
        assert last.success_count == 2
        first_errors = [r.failure for r in responses[0][1].summary.target_results if r.failure]
        assert any(f.kind == FailureKind.WRONG_PASSWORD and f.stage == "embedded_boundary" for f in first_errors)
    assert not (tmp_path / "watch" / "carrier.jpg").exists()
