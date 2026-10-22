from __future__ import annotations

import asyncio
import io
import json
import os
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path

import pytest

from sunpack.core.contracts.failures import FailureInfo, FailureKind
from tests.helpers.passwords import write_password_json
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.runtime.watch.scheduler import WatchScheduler
from tests.helpers.failure_assertions import assert_failure_kind
from tests.helpers.marker_utils import marker_was_extracted
from tests.helpers.real_archives import ArchiveFixtureFactory, create_zip_multidisk_archive
from tests.helpers.tool_config import get_optional_rar
from tests.real.plan1_real_archives.plan1_support import (
    assert_expected_files_extracted,
    plan1_config,
)
from tests.real.plan4_missing_volumes.plan4_support import SCENARIOS, apply_missing_volume_scenario


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("encryption", ["ZipCrypto", "AES256"])
def test_real_pkzip_disks_classify_wrong_password_and_missing_volumes(
    tmp_path, origin, encryption, plan_error,
):
    # Generic .zip.001 fixtures cannot exercise PKZIP disk-relative readers.
    # One coarse test per cipher/origin checks both classifications, with a
    # successful extraction as the real-input control. Dual faults can surface
    # in either order; the watch lifecycle test checks eventual recovery.
    password = "correct-spanned-password"
    case = create_zip_multidisk_archive(
        tmp_path, "spanned", password=password, encryption=encryption,
        payload_size=170000, split_volume_size=65536,
    )
    if encryption == "AES256":
        paths = []
        for path in case.metadata["volume_paths"]:
            renamed = path.with_name(path.name + ".图片")
            path.rename(renamed)
            paths.append(renamed)
        case.metadata["volume_paths"] = paths
        case.entry_path = paths[0]
    originals = {path: path.read_bytes() for path in case.metadata["volume_paths"]}

    async def run(passwords, phase):
        plan_error.update(origin=origin, encryption=encryption, phase=phase)
        config = plan1_config(passwords=passwords)
        output = tmp_path / f"out-{phase}"
        config["output"] = {"root": str(output)}
        async with PipelineEngine(config) as engine:
            response = await engine.run(
                [str(case.archive_dir)], origin=origin,
                stdout=io.StringIO(), stderr=io.StringIO(),
            )
        summary = response.summary
        plan_error["failures"] = [item.to_dict() for item in summary.failures]
        return summary, output

    async def exercise():
        summary, output = await run(["wrong", password], "complete-correct")
        assert summary.success_count == 1 and not summary.failed_tasks
        assert not summary.failures and summary.partial_success_count == 0
        assert_expected_files_extracted(case, output)

        summary, output = await run(["wrong-one", "wrong-two"], "complete-wrong")
        assert summary.success_count == summary.partial_success_count == 0
        assert len(summary.failed_tasks) == 1
        assert_failure_kind(summary.failures, FailureKind.WRONG_PASSWORD)
        assert not marker_was_extracted(output, case.marker_name, case.marker_text)

        for scenario in SCENARIOS:
            plan_error["phase"] = f"{scenario}-discovery"
            apply_missing_volume_scenario(case, scenario)
            try:
                config = plan1_config(passwords=[password])
                discovered = ArchiveTaskProvider(config).discover_targets([str(case.archive_dir)])
                # Only headless fragments which discovery cannot recognize
                # may be ignored. Any recognized archive must report missing
                # volumes; recognizing more headless sets remains valid.
                unrecognized_headless = (
                    scenario in {"missing_head", "only_middle", "only_tail"}
                    and not discovered.resolved_tasks
                )
                if scenario == "missing_middle":
                    assert [[part.volume_number for part in task.archive_input().parts]
                            for task in discovered.resolved_tasks] == [[1, 3]]
                for label, passwords in (
                    ("correct", ["wrong", password]),
                    ("wrong", ["wrong-one", "wrong-two"]),
                ):
                    summary, output = await run(passwords, f"{scenario}-{label}")
                    assert summary.success_count == summary.partial_success_count == 0
                    if unrecognized_headless:
                        assert not summary.target_results and not summary.scan_failures
                    else:
                        assert len(summary.failed_tasks) == 1
                        expected = (
                            (FailureKind.MISSING_VOLUME, FailureKind.WRONG_PASSWORD)
                            if label == "wrong" else FailureKind.MISSING_VOLUME
                        )
                        assert_failure_kind(summary.failures, expected)
                    assert not marker_was_extracted(output, case.marker_name, case.marker_text)
            finally:
                for path, data in originals.items():
                    if not path.exists():
                        path.write_bytes(data)

    asyncio.run(exercise())


def _mixed_nested_carrier(tmp_path):
    fixtures = tmp_path / "fixtures"
    healthy = ArchiveFixtureFactory().create(
        fixtures, "healthy", "zip", password="known", split=True,
        payload_size=170000, split_volume_size=65536,
    )
    wrong = create_zip_multidisk_archive(
        fixtures, "wrong", password="unknown", encryption="AES256",
        payload_size=170000, split_volume_size=65536,
    )
    missing = create_zip_multidisk_archive(
        fixtures, "missing", password="known", payload_size=170000, split_volume_size=65536,
    )
    cases = (healthy, wrong, missing)
    apply_missing_volume_scenario(missing, "missing_middle")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for case in cases:
            for path in case.archive_dir.iterdir():
                archive.writestr(path.name + ".图片", path.read_bytes())
    watch_root = tmp_path / "inputs"
    watch_root.mkdir()
    outer = watch_root / "nested-carrier.opaque"
    outer.write_bytes(b"opaque-prefix" + buffer.getvalue() + b"opaque-tail")
    return outer, cases


def _assert_mixed_outputs(cases, output):
    healthy, wrong, missing = cases
    assert_expected_files_extracted(healthy, output)
    for blocked in (wrong, missing):
        assert not marker_was_extracted(output, blocked.marker_name, blocked.marker_text)


def test_cli_nested_disguised_split_groups_keep_failure_classifications(tmp_path, plan_error):
    # One real CLI run combines nested/carrier/disguised input and concurrent
    # healthy, wrong-password and missing-volume siblings. Isolated tests
    # cannot detect classification leaking between sibling tasks.
    outer, cases = _mixed_nested_carrier(tmp_path)
    output = tmp_path / "out"
    root = Path(__file__).resolve().parents[2]
    overrides = {
        "filesystem": {"scan_filters": [{"name": "size_range", "enabled": False}]},
        "embedded_scan": {"enabled": True},
        "verification": {"enabled": True},
        "post_extract": {"flatten_single_directory": False},
        "extraction": {"content_requirement": "complete"},
    }
    # The resident CLI owns its startup environment. Isolate its namespace
    # and close it even on failure, rather than reusing a developer's server.
    bootstrap = [sys.executable, "-B", str(root / "sunpack.py")]
    runtime_id = f"v2-{uuid.uuid4().hex[:16]}"
    identity = f"--_sunpack-runtime-id={runtime_id}"
    environment = {**os.environ, "SUNPACK_CONFIG_OVERRIDES": json.dumps(overrides)}
    try:
        result = subprocess.run(
            [*bootstrap, "extract", identity, "--json", "--no-pause",
             "--no-builtin-pw", "--cleanup", "k", "--recur", "*", "--deep-detect",
             "--out-dir", str(output), "-p", "wrong-candidate", "-p", "known", str(outer)],
            cwd=root, env=environment,
            capture_output=True, text=True, encoding="utf-8", timeout=30,
        )
    finally:
        closed = subprocess.run(
            [*bootstrap, "--persistent-shutdown", identity], cwd=root, env=environment,
            capture_output=True, text=True, encoding="utf-8", timeout=15,
        )
        assert closed.returncode == 0, closed.stdout + closed.stderr
        for suffix in (".state", ".state.events.jsonl", ".state.lock"):
            (root / f"runtime-{runtime_id}{suffix}").unlink(missing_ok=True)
    plan_error.update(stdout=result.stdout, stderr=result.stderr)
    assert result.returncode == 1, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["summary"]["success_count"] == 2
    assert report["summary"]["failed_count"] == 2
    assert report["summary"]["partial_success_count"] == 0
    failures = [FailureInfo.from_dict(item) for item in report["tasks"][0]["failures"]]
    assert len(failures) == 2
    for kind in (FailureKind.WRONG_PASSWORD, FailureKind.MISSING_VOLUME):
        matching = [item for item in failures if item.contains(kind)]
        assert len(matching) == 1, report
        assert_failure_kind(matching, kind)
    _assert_mixed_outputs(cases, output)


def test_watch_nested_split_groups_persist_distinct_blockers(tmp_path, monkeypatch, plan_error):
    # Exercise the actual engine, native discovery, worker and state journal.
    # Only the installed-service admission preflight is bypassed; files are
    # already stable when enqueued and no archive/task result is mocked.
    import sunpack.runtime.watch.scheduler as scheduler_module

    monkeypatch.setattr(scheduler_module, "validate_ntfs_watch_roots", lambda _roots: None)
    outer, cases = _mixed_nested_carrier(tmp_path)
    output = tmp_path / "out"
    config = plan1_config(passwords=["wrong-candidate", "known"])
    config["watch"]["clipboard_monitor_enabled"] = False

    async def exercise():
        async with PipelineEngine(config) as engine:
            watcher = WatchScheduler(
                config, [str(outer.parent)], out_dir=str(output),
                state_path=str(tmp_path / "state.json"), cold_start_seconds=0,
                pipeline_engine=engine,
            )
            try:
                watcher.enqueue(str(outer))
                await watcher.run_once()
                await watcher.drain()
                assert watcher.pending_count == 0
                entries = list(watcher.state.entries.values())
                plan_error["state"] = [entry.__dict__ for entry in entries]
                assert len(entries) == 2
                expected = {
                    "wrong.z01.图片": ("failed_password", FailureKind.WRONG_PASSWORD, "password"),
                    "missing.z01.图片": ("suspended_missing_volume", FailureKind.MISSING_VOLUME, "missing_volume"),
                }
                assert {Path(entry.path).name for entry in entries} == set(expected)
                for entry in entries:
                    status, kind, blocker = expected[Path(entry.path).name]
                    assert entry.status == status
                    assert entry.failure_kind == kind.value
                    assert_failure_kind([FailureInfo.from_dict(entry.failure_payload)], kind)
                    assert (entry.failure_payload or {}).get("blockers") == [blocker]
                    assert Path(entry.path).is_file(), "retry input must survive promotion"
                _assert_mixed_outputs(cases, output)
            finally:
                await watcher.aclose()

    asyncio.run(asyncio.wait_for(exercise(), timeout=30))


@pytest.mark.parametrize(("archive_kind", "missing_position"), [
    ("pkzip-ZipCrypto", "middle"), ("pkzip-AES256", "middle"),
    ("zip", "middle"), ("7z", "middle"), ("rar", "middle"), ("rar", "tail"),
])
def test_watch_dual_faults_resume_after_each_blocker_is_resolved(
    tmp_path, monkeypatch, archive_kind, missing_position, plan_error,
):
    # Existing classification tests stop at the first failure. Only a real
    # three-attempt lifecycle catches stale blockers/readers or retries lost
    # between the missing-volume and password states. One small set per input
    # reader/cipher keeps the independent coverage inexpensive.
    import sunpack.runtime.watch.scheduler as scheduler_module

    if archive_kind == "rar" and get_optional_rar() is None:
        pytest.skip("RAR generator is not configured")
    monkeypatch.setattr(scheduler_module, "validate_ntfs_watch_roots", lambda _roots: None)
    password = "correct-retry-password"
    if archive_kind.startswith("pkzip-"):
        case = create_zip_multidisk_archive(
            tmp_path / "inputs", "retry", password=password,
            encryption=archive_kind.removeprefix("pkzip-"),
            payload_size=170000, split_volume_size=65536,
        )
        parts = case.metadata["volume_paths"]
    else:
        case = ArchiveFixtureFactory().create(
            tmp_path / "inputs", "retry", archive_kind, password=password,
            split=True, payload_size=170000, split_volume_size=65536,
        )
        parts = sorted(case.archive_dir.iterdir())
    disguised = []
    for path in parts:
        disguised.append(path.rename(path.with_name(path.name + ".图片")))
    case.entry_path = disguised[0]
    missing = disguised[-1] if missing_position == "tail" else disguised[len(disguised) // 2]
    missing_data = missing.read_bytes()
    missing.unlink()
    output = tmp_path / "out"
    config = plan1_config(passwords=["wrong-one", "wrong-two"])
    config["cli"]["quiet"] = True
    config["watch"].update(clipboard_monitor_enabled=False, password_retry_debounce_seconds=0)

    async def exercise():
        async with PipelineEngine(config) as engine:
            watcher = WatchScheduler(
                config, [str(case.archive_dir)], out_dir=str(output),
                state_path=str(tmp_path / "state.json"), cold_start_seconds=0,
                pipeline_engine=engine,
            )
            async def settle():
                started = await watcher.run_once()
                completed = await watcher.drain()
                assert watcher.pending_count == 0
                return started.succeeded + completed.succeeded

            def blocked(expected):
                entries = list(watcher.state.entries.values())
                plan_error.update(
                    archive_kind=archive_kind, missing_position=missing_position,
                    state=[item.__dict__ for item in entries],
                )
                assert len(entries) == 1
                entry = entries[0]
                kind = FailureKind(entry.failure_kind)
                assert kind in expected, entry
                status, blocker = {
                    FailureKind.WRONG_PASSWORD: ("failed_password", "password"),
                    FailureKind.MISSING_VOLUME: ("suspended_missing_volume", "missing_volume"),
                }[kind]
                assert entry.status == status
                assert (entry.failure_payload or {}).get("blockers") == [blocker]
                assert_failure_kind([FailureInfo.from_dict(entry.failure_payload)], kind)
                assert not marker_was_extracted(output, case.marker_name, case.marker_text)
                return kind

            def resolve(kind):
                if kind == FailureKind.MISSING_VOLUME:
                    missing.write_bytes(missing_data)
                    watcher.enqueue(str(missing), event_type="created")
                else:
                    table = watcher._password_file_source.path
                    write_password_json(table, scopes=[(password, [str(case.archive_dir)])])
                    watcher.notify_password_source_changed("builtin_password_file")

            try:
                watcher.enqueue(str(case.entry_path))
                assert await settle() == 0
                remaining = {FailureKind.WRONG_PASSWORD, FailureKind.MISSING_VOLUME}
                first = blocked(remaining)
                resolve(first)
                assert await settle() == 0
                remaining.remove(first)
                second = blocked(remaining)
                resolve(second)
                assert await settle() == 1
                assert not watcher.state.entries
                assert_expected_files_extracted(case, output)
                assert all(path.is_file() for path in disguised)
            finally:
                await watcher.aclose()

    asyncio.run(asyncio.wait_for(exercise(), timeout=30))
