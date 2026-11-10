import asyncio
import json
import io
import subprocess
import sys
import tempfile
import unittest
import zipfile
from binascii import crc32
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.helpers.generated_fixtures import build_cli_pipeline_fixture
from sunpack.runtime.cli import cli, cli_runtime, runtime_state
from sunpack.runtime.cli.commands import watch
from sunpack.runtime.watch import startup


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def run_cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, "-B", str(PROJECT_ROOT / "sunpack.py"), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=cwd,
    )


class CliBasicTests(unittest.TestCase):
    def test_help_lists_basic_commands(self):
        result = run_cli("--help")

        self.assertEqual(result.returncode, 0)
        self.assertIn("extract", result.stdout)
        self.assertIn("watch", result.stdout)
        self.assertIn("scan", result.stdout)
        self.assertNotIn("inspect (", result.stdout)
        self.assertIn("passwords", result.stdout)
        self.assertIn("config", result.stdout)
        self.assertNotIn("models", result.stdout)

    def test_scan_json_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "plain.zip"
            with zipfile.ZipFile(fixture, "w") as archive:
                archive.writestr("payload", b"plain archive")
            before = fixture.read_bytes()
            result = run_cli("scan", "--json", str(fixture), "--no-pause")
            self.assertEqual(list(Path(tmp).iterdir()), [fixture])
            self.assertEqual(fixture.read_bytes(), before)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["command"], "scan")
        self.assertEqual(payload["summary"]["archive_count"], 1)
        self.assertEqual(payload["items"][0]["format"], "zip")
        self.assertNotIn("password_used", payload["items"][0])

    def test_passwords_json_shape(self):
        result = run_cli("passwords", "--json", "-p", "secret", "--no-builtin-pw")

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["command"], "passwords")
        self.assertEqual(payload["summary"]["user_password_count"], 1)
        self.assertEqual(payload["items"][0]["user_passwords"], ["secret"])
        self.assertEqual(payload["items"][0]["combined_passwords"][0], "secret")

    def test_json_mode_rejects_interactive_password_prompt_as_json(self):
        result = run_cli("passwords", "--json", "--ask-pw")

        self.assertNotEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertIn("JSON 模式不支持交互式密码输入", payload["errors"][0])

    def test_config_show_json_shape(self):
        result = run_cli("config", "--json", "show")

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["command"], "config")
        self.assertEqual(payload["inputs"]["action"], "show")
        self.assertFalse(payload["summary"]["changed"])

    def test_extract_out_dir_places_output_below_the_given_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "payload.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("marker.txt", "routed")
            out_dir = root / "elsewhere" / "out"

            result = run_cli(
                "extract",
                "--json",
                "--direct-file",
                "--out-dir",
                str(out_dir),
                "--cleanup",
                "k",
                str(archive),
                "--no-pause",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["summary"]["success_count"], 1)
            self.assertTrue(payload["inputs"]["direct_file"])
            self.assertEqual(
                Path(payload["inputs"]["config_overrides"]["output_dir"]).resolve(),
                out_dir.resolve(),
            )
            self.assertEqual(
                (out_dir / "payload" / "marker.txt").read_text(encoding="utf-8"),
                "routed",
            )
            self.assertFalse((root / "payload").exists())

    def test_extract_out_dir_is_resolved_to_an_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = build_cli_pipeline_fixture(root)
            request_dir = root / "request"
            request_dir.mkdir()

            result = run_cli(
                "extract",
                "--json",
                "--out-dir",
                "relative-out",
                "--no-pause",
                str(fixture),
                cwd=str(request_dir),
            )

            payload = json.loads(result.stdout)
            self.assertEqual(
                Path(payload["inputs"]["config_overrides"]["output_dir"]).resolve(),
                (request_dir / "relative-out").resolve(),
            )

@pytest.mark.parametrize("active", [False, True])
def test_watch_status_commands_render_state_and_keep_json(monkeypatch, tmp_path, active):
    monkeypatch.setattr(cli, "_should_submit_to_persistent_server", lambda _: False)
    monkeypatch.setattr(cli, "load_cli_language_from_config", lambda _: "zh")
    monkeypatch.setattr(runtime_state, "_HOST", SimpleNamespace(watch_status=lambda: {"running": active}))
    monkeypatch.setattr(watch, "list_watch_roots", lambda: ("roots.txt", []))
    monkeypatch.setattr(watch, "service_state_dir", lambda: str(tmp_path))
    monkeypatch.setattr(startup, "startup_status", lambda: (active, "watch start" if active else ""))

    cases = (
        (["w", "status"], "running", "监控服务正在运行" if active else "监控服务已停止"),
        (["w", "startup", "status"], "enabled", "开机自启动已启用" if active else "开机自启动未启用"),
    )
    for argv, key, message in cases:
        output = io.StringIO()
        assert asyncio.run(cli.async_main(argv, cwd=str(tmp_path), stdout=output)) == 0
        assert output.getvalue().splitlines() == [message]
        output = io.StringIO()
        assert asyncio.run(cli.async_main([*argv, "-j"], cwd=str(tmp_path), stdout=output)) == 0
        assert json.loads(output.getvalue())["summary"][key] is active


def test_passwords_text_displays_builtins_as_a_list(monkeypatch, tmp_path):
    from sunpack.core.passwords.internal.builtin import read_builtin_password_file
    from sunpack.runtime.cli.commands import passwords

    path = tmp_path / "passwords.json"
    path.write_text('{"passwords":[{"value":"sample-key"}]}', encoding="utf-8")
    snapshot = read_builtin_password_file(path)
    monkeypatch.setattr(cli_runtime, "password_file_source", lambda: SimpleNamespace(snapshot=snapshot))
    monkeypatch.setattr(passwords, "collect_clipboard_passwords", lambda _: [])
    monkeypatch.setattr(cli, "_should_submit_to_persistent_server", lambda _: False)
    monkeypatch.setattr(cli, "load_cli_language_from_config", lambda _: "zh")
    output = io.StringIO()

    assert asyncio.run(cli.async_main(["pw"], cwd=str(tmp_path), stdout=output)) == 0
    assert "  内置密码：['sample-key']" in output.getvalue().splitlines()


if __name__ == "__main__":
    unittest.main()
