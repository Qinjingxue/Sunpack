import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from sunpack.cli.cli_context import CliContext
from sunpack.cli.cli_reporter import CliReporter
from sunpack.cli.commands import extract
from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.cli.cli_runtime import build_password_summary
from tests.helpers.fake_pipeline_engine import FakePipelineEngine


def test_wrong_password_failure_detection():
    wrong = FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "rejected")
    damaged = FailureInfo(FailureKind.DAMAGED, "extraction", "damaged")
    assert extract.has_password_failure([wrong]) is True
    assert extract.has_password_failure([damaged]) is False


def test_extract_config_combines_clipboard_passwords_for_engine():
    password_summary = build_password_summary(
        ["cli-secret", "shared-secret"],
        use_builtin_passwords=False,
        clipboard_passwords=["clipboard-secret", "shared-secret"],
    )
    config = extract._extract_run_config({}, password_summary)

    assert config["user_passwords"] == ["cli-secret", "shared-secret", "clipboard-secret"]


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
                return SimpleNamespace(
                    success_count=0,
                    failed_tasks=["secret.zip [密码错误]"],
                    processed_keys=["secret"],
                    failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "密码错误")],
                )
            self.recent_passwords = ["secret"]
            return SimpleNamespace(success_count=1, failed_tasks=[], processed_keys=["secret"], failures=[])

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
