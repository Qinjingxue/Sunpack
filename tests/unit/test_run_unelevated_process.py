from __future__ import annotations

import os

import pytest

from scripts import run_unelevated_process
from sunpack.platform.windows import process_launch


def test_explicit_environment_overrides_are_forwarded_to_child(monkeypatch):
    monkeypatch.setenv("SUNPACK_EXISTING_TEST_VALUE", "original")
    args = run_unelevated_process.parse_args(
        [
            "--cwd",
            ".",
            "--env",
            "SUNPACK_EXISTING_TEST_VALUE=overridden",
            "--env",
            r"SUNPACK_PIPE_TEST_VALUE=\\.\pipe\SunPack.Test",
            "--",
            "python",
        ]
    )

    environment = run_unelevated_process._child_environment(args)

    assert environment["SUNPACK_EXISTING_TEST_VALUE"] == "overridden"
    assert environment["SUNPACK_PIPE_TEST_VALUE"] == r"\\.\pipe\SunPack.Test"
    assert environment is not os.environ


def test_invalid_environment_override_is_rejected():
    with pytest.raises(SystemExit):
        run_unelevated_process.parse_args(
            ["--cwd", ".", "--env", "missing-separator", "--", "python"]
        )


def test_environment_block_is_sorted_and_double_nul_terminated():
    block = process_launch._environment_block(
        {"SUNPACK_Z_TEST_VALUE": "z", "SUNPACK_A_TEST_VALUE": "a"}
    )
    block_text = "".join(block)

    assert block_text.startswith(
        "SUNPACK_A_TEST_VALUE=a\x00SUNPACK_Z_TEST_VALUE=z\x00\x00"
    )
    assert block_text.rstrip("\x00") == (
        "SUNPACK_A_TEST_VALUE=a\x00SUNPACK_Z_TEST_VALUE=z"
    )


def test_environment_block_rejects_nul_characters():
    with pytest.raises(ValueError):
        process_launch._environment_block({"SUNPACK_TEST_VALUE": "bad\x00value"})


def test_elevated_runner_passes_complete_environment_to_unelevated_launcher(monkeypatch):
    monkeypatch.setenv(
        "SUNPACK_WATCH_BROKER_SERVICE_NAME",
        "SunPackWatchBrokerTest_from_parent",
    )

    captured: dict[str, object] = {}

    class _FakeProcess:
        def wait(self, timeout=None):
            return 0

        def close(self):
            return None

    def fake_launch(argv, *, cwd=None, env=None):
        captured["argv"] = argv
        captured["cwd"] = cwd
        captured["env"] = env
        return _FakeProcess()

    monkeypatch.setattr(run_unelevated_process, "is_process_elevated", lambda: True)
    monkeypatch.setattr(run_unelevated_process, "launch_unelevated", fake_launch)

    result = run_unelevated_process.main(
        [
            "--cwd",
            ".",
            "--env",
            "SUNPACK_EXPLICIT_TEST_VALUE=overridden",
            "--",
            "python",
            "-c",
            "pass",
        ]
    )

    assert result == 0
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert environment["SUNPACK_WATCH_BROKER_SERVICE_NAME"] == (
        "SunPackWatchBrokerTest_from_parent"
    )
    assert environment["SUNPACK_EXPLICIT_TEST_VALUE"] == "overridden"
    assert environment is not os.environ
