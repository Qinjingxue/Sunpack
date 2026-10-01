import asyncio
import io
import json
from types import SimpleNamespace

import pytest

from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.results import ArchiveCleanupResult, OutcomeKind, RunSummary, TargetRunResult
from sunpack.runtime.cli.cli_context import CliContext
from sunpack.runtime.cli.cli_reporter import CliReporter
from sunpack.runtime.cli.cli_runtime import build_password_summary
from sunpack.runtime.cli.commands import extract
from tests.helpers.fake_pipeline_engine import FakePipelineEngine


def test_wrong_password_failure_detection():
    wrong = FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "rejected")
    damaged = FailureInfo(FailureKind.DAMAGED, "extraction", "damaged")
    assert extract.has_password_failure([wrong]) is True
    assert extract.has_password_failure([damaged]) is False


@pytest.mark.parametrize("mode", ["delete", "flatten"])
def test_existing_cli_json_includes_postprocess_failure(tmp_path, monkeypatch, mode):
    source = tmp_path / "archive.disguised"
    source.write_text("source")
    warning = ArchiveCleanupResult(str(tmp_path / "output.work"), mode, "failed", message="postprocess failed")

    class Engine(FakePipelineEngine):
        async def run(self, *args, **kwargs):
            from dataclasses import replace
            response = await super().run(*args, **kwargs)
            return replace(response, summary=replace(response.summary, cleanup_results=(warning,)))

    class Runner:
        recent_passwords = []

        def __init__(self, config):
            pass

        def run_targets(self, paths):
            return RunSummary(target_results=(TargetRunResult(paths[0], OutcomeKind.COMPLETE_SUCCESS),))

    monkeypatch.setattr(extract, "pipeline_engine", lambda config: Engine(Runner))
    monkeypatch.setattr(extract, "collect_clipboard_passwords", lambda config: [])
    args = SimpleNamespace(
        paths=[str(source)], password=[], password_file=None, prompt_passwords=False,
        no_builtin_passwords=True, recursive_extract=None, archive_cleanup_mode=None,
        flatten_single_directory=None, json=True, quiet=False, verbose=False,
    )
    output = io.StringIO()
    reporter = CliReporter(json_mode=True, stdout=output)
    ctx = CliContext(language="en", reporter=reporter)
    code, result = asyncio.run(extract.handle(args, ctx))
    reporter.emit_result(result)
    serialized = json.loads(output.getvalue())
    assert code == 0
    assert serialized["summary"]["success_count"] == 1
    assert serialized["summary"]["cleanup_results"][0]["mode"] == mode
    assert serialized["summary"]["cleanup_results"][0]["path"] == warning.path
    assert serialized["summary"]["cleanup_results"][0]["message"] == warning.message


def test_extract_config_combines_clipboard_passwords_for_engine():
    password_summary = build_password_summary(
        ["cli-secret", "shared-secret"],
        use_builtin_passwords=False,
        clipboard_passwords=["clipboard-secret", "shared-secret"],
    )
    config = extract._extract_run_config({}, password_summary)

    assert config["user_passwords"] == ["cli-secret", "shared-secret", "clipboard-secret"]


def test_extract_preserves_scan_failure_when_target_succeeds(tmp_path, monkeypatch):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"archive")

    class FakeRunner:
        def __init__(self, _config):
            self.recent_passwords = []

        def run_targets(self, _target_paths):
            return RunSummary(
                target_results=(
                    TargetRunResult(str(target), OutcomeKind.COMPLETE_SUCCESS),
                ),
                scan_failed_tasks=("unreadable.bin [discovery failed]",),
            )

    monkeypatch.setattr(extract, "pipeline_engine", lambda _config: FakePipelineEngine(FakeRunner))
    monkeypatch.setattr(extract, "collect_clipboard_passwords", lambda _config: [])

    args = SimpleNamespace(
        paths=[str(target)],
        password=[],
        password_file=None,
        prompt_passwords=False,
        no_builtin_passwords=True,
        recursive_extract=None,
        archive_cleanup_mode=None,
        flatten_single_directory=None,
        json=False,
        quiet=False,
        verbose=False,
    )
    ctx = CliContext(language="en", reporter=CliReporter())

    exit_code, result = asyncio.run(extract.handle(args, ctx))

    assert exit_code != 0
    assert result.summary["success_count"] == 1
    assert result.errors == ["unreadable.bin [discovery failed]"]


def test_extract_prompts_for_password_retry_after_wrong_password(tmp_path, monkeypatch):
    target = tmp_path / "archives"
    target.mkdir()
    attempts = []

    class FakeRunner:
        def __init__(self, config):
            attempts.append(list(config.get("user_passwords", [])))
            self.recent_passwords = []

        def run_targets(self, _target_paths):
            if len(attempts) == 1:
                failure = FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "密码错误")
                return RunSummary(target_results=(
                    TargetRunResult(
                        str(target), OutcomeKind.FAILURE, task_key="secret",
                        error="密码错误", failure=failure,
                        failure_message="secret.zip [密码错误]",
                    ),
                ))
            self.recent_passwords = ["secret"]
            return RunSummary(target_results=(
                TargetRunResult(str(target), OutcomeKind.COMPLETE_SUCCESS, task_key="secret"),
            ))

    answers = iter(["y", "secret", ""])
    monkeypatch.setattr(extract, "pipeline_engine", lambda _config: FakePipelineEngine(FakeRunner))
    monkeypatch.setattr(extract, "collect_clipboard_passwords", lambda _config: [])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    args = SimpleNamespace(
        paths=[str(target)],
        password=[],
        password_file=None,
        prompt_passwords=False,
        no_builtin_passwords=True,
        recursive_extract=None,
        archive_cleanup_mode=None,
        flatten_single_directory=None,
        json=False,
        quiet=False,
        verbose=False,
    )
    ctx = CliContext(language="en", reporter=CliReporter())

    exit_code, result = asyncio.run(extract.handle(args, ctx))

    assert exit_code == 0
    assert attempts == [[], ["secret"]]
    assert result.summary["password_retry_count"] == 1
    assert result.summary["success_count"] == 1
    assert result.errors == []
