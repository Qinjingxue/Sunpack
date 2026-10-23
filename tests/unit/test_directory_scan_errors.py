import io
import json
import os
import subprocess
import sys
import zipfile
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from sunpack_native import NativeDirectoryScanOptions, scan_directory_snapshot, classify_scan_targets, scan_watch_candidates

from sunpack.core.config.schema import normalize_config
from sunpack.core.contracts.failures import FailureKind
from sunpack.core.contracts.run_state import RunState
from sunpack.core.contracts.discovery_scope import DiscoveryScope
from sunpack.core.i18n import I18nContext
from sunpack.core.i18n.context import validate_catalog
from sunpack.core.support.filesystem_scan_errors import filesystem_scan_error_count
from sunpack.pipeline.coordinator.output_scan_policy import NestedOutputScanPolicy
from sunpack.pipeline.coordinator.task_scan import ArchiveTaskScanner
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.runtime.cli.cli_context import CliContext
from sunpack.runtime.cli.cli_reporter import CliReporter
from sunpack.runtime.cli.commands import inspect_command, scan
from sunpack.runtime.watch.scheduler import WatchScheduler
from sunpack.runtime.watch.roots import WatchRootEntry
from sunpack.runtime.watch.state import WatchStateStore
from sunpack.core.support.path_keys import path_key


@contextmanager
def deny_directory_listing(path):
    principal = os.environ["USERNAME"]
    subprocess.run(["icacls", str(path), "/deny", principal + ":(RD)"], capture_output=True, check=True)
    try:
        yield
    finally:
        subprocess.run(["icacls", str(path), "/remove:d", principal], capture_output=True, check=True)


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("language", ["en", "zh"])
def test_unreadable_subtree_is_reported_without_losing_readable_archives(tmp_path, monkeypatch, request, json_mode, language):
    # Covers real native I/O failures through discovery, CLI and Watch reporting;
    # existing tests inject provider failures and cannot catch swallowed OS errors.
    root = tmp_path / "inputs"
    blocked = root / "blocked"
    blocked.mkdir(parents=True)
    for archive in (root / "good.blob", blocked / "hidden.blob"):
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("payload.txt", "payload")
    config = normalize_config({"verification": {}, "cli": {"language": language}, "filesystem": {
        "scan_filters": [{"name": "size_range", "enabled": False}],
    }})
    monkeypatch.setattr(scan, "load_request_config", lambda _cwd: config)
    stderr = io.StringIO()
    context = CliContext(language=language, cwd=str(tmp_path), reporter=CliReporter(
        json_mode=json_mode, stdout=io.StringIO(), stderr=stderr,
    ))
    notifications = []
    log_events = []
    scheduler = object.__new__(WatchScheduler)
    scheduler.watch_roots = [str(root)]
    scheduler.scopes = {path_key(root): DiscoveryScope(str(root), recursive=True)}
    scheduler.root_entries = {path_key(root): WatchRootEntry(str(root), recursive=True)}
    scheduler._scan_options = DirectoryScanner.compile_scan_options(config)
    scheduler.state = WatchStateStore(str(tmp_path / "scan-state.json"))
    request.addfinalizer(scheduler.state.close)
    scheduler.i18n = I18nContext(language)
    scheduler.log = SimpleNamespace(write=lambda event, **fields: log_events.append((event, fields)))
    scheduler._notify = lambda *args: notifications.append(args)
    scheduler.enqueue = lambda *_args, **_kwargs: pytest.fail("scan errors must not enqueue retries")

    with deny_directory_listing(blocked):
        with pytest.raises(PermissionError):
            list(os.scandir(blocked))
        native = NativeDirectoryScanOptions([], [], [], [], [], [], [])
        filtered, raw = native.scan(str(root), None)
        assert filtered.scan_errors() == raw.scan_errors()
        assert len(raw.scan_errors()) == 1 and str(blocked) in raw.scan_errors()[0]
        single = scan_directory_snapshot(str(blocked), None, [], [], [], [], [], [], [])
        assert not single and len(single.scan_errors()) == 1
        state = RunState()
        tasks = ArchiveTaskScanner(config, state).scan_targets([str(root)], scan_session=DiscoveryScanSession(config=config,recursive=True))
        assert len(tasks) == 1 and tasks[0].main_path == str(root / "good.blob")
        assert state.scan_failures[0].kind == FailureKind.FILESYSTEM_ERROR
        code, result = scan.handle(SimpleNamespace(recursive=True, paths=[str(root)], deep_detect=False, json=json_mode), context)
        assert code != 0 and result.summary["task_count"] == 1
        assert result.summary["scan_error_count"] == 1
        assert len(result.errors) == 1 and str(blocked) in result.errors[0]
        expected = "无法读取目录：" if language == "zh" else "Cannot read directory: "
        assert result.errors[0].startswith(expected)
        assert "read_dir:" not in result.errors[0]
        validate_catalog()
        assert bool(stderr.getvalue()) is not json_mode
        if not json_mode:
            assert stderr.getvalue().startswith("[扫描错误]" if language == "zh" else "[Scan error]")
            assert ("[扫描不完整]" if language == "zh" else "[Scan incomplete]") in stderr.getvalue()
        nested = NestedOutputScanPolicy(config).prepare_scan([str(blocked)])
        assert not nested.roots and nested.session is not None
        assert len(nested.session.take_scan_errors()) == 1
        candidates, _errors = scheduler._scan_candidates([str(root)], recursive=True)
        assert len(candidates) == 1 and candidates[0].path == str(root / "good.blob")
        assert not notifications
        assert log_events[-1][0] == "filesystem_scan_failed"
        assert str(blocked) in log_events[-1][1]["errors"][0]
    scheduler.state.close()


@pytest.mark.parametrize("command, count_key", [(scan, "task_count"), (inspect_command, "resolved_items")])
def test_explicit_missing_target_keeps_valid_input_and_reports_metadata_failure(tmp_path, monkeypatch, command, count_key):
    # Unlike subtree failures, root metadata failures used to disappear before
    # native discovery, or prevent the CLI from processing any valid input.
    good = tmp_path / "good.blob"
    missing = tmp_path / "missing"
    with zipfile.ZipFile(good, "w") as output:
        output.writestr("payload.txt", "payload")
    config = normalize_config({"verification": {}, "cli": {"language": "zh"}})
    monkeypatch.setattr(command, "load_request_config", lambda _cwd: config)
    context = CliContext(language="zh", cwd=str(tmp_path), reporter=CliReporter(
        json_mode=True, stdout=io.StringIO(), stderr=io.StringIO(),
    ))
    code, result = command.handle(SimpleNamespace(recursive=True, paths=[str(missing), str(good)], deep_detect=False, json=True,
                                                analyze=False, archives_only=False), context)
    assert code != 0 and result.summary[count_key] == 1
    assert len(result.errors) == 1 and str(missing) in result.errors[0]
    assert result.errors[0].startswith("无法读取文件或目录信息：")
    state = RunState()
    tasks = ArchiveTaskScanner(config, state).direct_file_tasks([str(missing), str(good)])
    assert len(tasks) == 1 and tasks[0].main_path == str(good)
    assert len(state.scan_failures) == 1
    assert state.scan_failures[0].details["operation"] == "metadata"


@pytest.mark.parametrize("direct", [False, True])
@pytest.mark.parametrize("mode", ["text", "quiet", "json"])
def test_extract_cli_keeps_valid_archive_when_an_explicit_target_is_missing(tmp_path, direct, mode):
    # Extraction has its own CLI admission and request path; scan-only checks
    # cannot catch an early return there or loss of errors in its final result.
    archive = tmp_path / "good.blob"
    missing = tmp_path / "missing"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("payload.txt", "payload")
    options = ["--direct-file"] if direct else []
    invalid = tmp_path / "directory-input"
    invalid.mkdir()
    paths = [str(missing), str(archive), *([str(invalid)] if direct else [])]
    if mode != "text":
        options.append("--" + mode)
    completed = subprocess.run([
        sys.executable, "-B", str(Path(__file__).resolve().parents[2] / "sunpack.py"),
        "extract", "--no-pause", "--cleanup", "k", *options, *paths,
    ], capture_output=True, text=True, encoding="utf-8", cwd=tmp_path)
    assert completed.returncode != 0
    if mode == "json":
        result = json.loads(completed.stdout)
        assert result["summary"]["success_count"] == 1, completed.stderr
        assert result["summary"]["failed_count"] == 0
        assert result["summary"]["scan_error_count"] == 1
        assert len(result["summary"]["scan_failures"]) == 1
        assert result["summary"]["input_error_count"] == int(direct)
        assert result["tasks"][0]["scan_error_count"] == 1
        assert len(result["errors"]) == 1 + int(direct)
        assert any(str(missing) in error for error in result["errors"])
        if direct:
            assert any(failure["kind"] == "invalid_input" for failure in result["tasks"][0]["failures"])
        assert completed.stderr == ""
    else:
        label = "[扫描错误]" if "[扫描错误]" in completed.stderr else "[Scan error]"
        assert completed.stderr.count(label) == 1 and str(missing) in completed.stderr
        if direct:
            assert ("[输入错误]" if label == "[扫描错误]" else "[Input error]") in completed.stderr
            assert str(invalid) in completed.stderr
        assert label not in completed.stdout
        if mode == "quiet":
            assert completed.stdout == ""
        else:
            assert any(counts in completed.stdout for counts in ("解压失败：0  扫描错误：1", "Extraction failed: 0  Scan errors: 1"))
    assert (tmp_path / "good" / "payload.txt").read_text() == "payload"


def test_nested_scan_error_overflow_keeps_each_root_and_registers_once(tmp_path):
    # Two overflowing scans expose lost omitted counts. Reusing their primed
    # session also checks that nested discovery does not register errors twice.
    roots = [tmp_path / "first", tmp_path / "second"]
    blocked_dirs = []
    for root in roots:
        root.mkdir()
        for index in range(22):
            blocked = root / str(index)
            blocked.mkdir()
            blocked_dirs.append(blocked)
        with zipfile.ZipFile(root / "good.blob", "w") as output:
            output.writestr("payload.txt", "payload")
    config = normalize_config({"verification": {}, "cli": {"language": "en"}, "filesystem": {
        "scan_filters": [{"name": "size_range", "enabled": False}],
    }})
    with ExitStack() as permissions:
        for blocked in blocked_dirs:
            permissions.enter_context(deny_directory_listing(blocked))
        work = NestedOutputScanPolicy(config).prepare_scan(map(str, roots))
        state = RunState()
        scanner = ArchiveTaskScanner(config, state)
        scanner.record_scan_errors(work.session)
        initial_errors = tuple(state.scan_failures)
        tasks = scanner.discover_targets(list(work.roots), scan_session=work.session, is_recursive_scan=True)
        assert len(tasks) == 2
        assert tuple(state.scan_failures) == initial_errors
        omitted = [failure for failure in state.scan_failures if failure.details["operation"] == "omitted"]
        assert {failure.details["path"] for failure in omitted} == {str(root) for root in roots}
        assert all(failure.message_params["error"] == "2" for failure in omitted)
        assert len(state.scan_failures) == 42
        assert filesystem_scan_error_count(state.scan_failures) == 44


def test_report_budget_bounds_native_batches_and_nested_handoffs(tmp_path):
    # A root cap alone misses large explicit batches and accumulation across
    # nested sessions. Check both native entry points and the report boundary.
    good = tmp_path / "good.blob"
    with zipfile.ZipFile(good, "w") as output:
        output.writestr("payload.txt", "payload")
    missing = [str(tmp_path / f"missing-{index}") for index in range(225)]
    kinds, errors = classify_scan_targets([*missing, str(good)])
    assert kinds == bytes(225) + b"\x01"
    candidates, watch_errors = scan_watch_candidates([*missing, str(good)])
    assert [row["path"] for row in candidates] == [str(good)]
    for diagnostics in (errors, watch_errors):
        assert len(diagnostics) == 101
        assert diagnostics[-1] == ("report_omitted", "", "125")

    combined = DiscoveryScanSession()
    state = RunState()
    for offset in range(0, 225, 75):
        _, partial = classify_scan_targets(missing[offset:offset + 75])
        combined.add_scan_errors(partial)
        separate = DiscoveryScanSession()
        separate.add_scan_errors(partial)
        state.record_scan_errors(separate.take_scan_errors(), "en")
    pending = combined.take_scan_errors()
    assert len(pending) == 101 and pending[-1] == ("report_omitted", "", "125")
    assert not combined.take_scan_errors()
    assert len(state.scan_failures) == 101
    assert filesystem_scan_error_count(state.scan_failures) == 225
