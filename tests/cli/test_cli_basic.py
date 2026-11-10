import json
import io
import subprocess
import sys
import tempfile
import unittest
import zipfile
from binascii import crc32
from pathlib import Path

from tests.helpers.generated_fixtures import build_cli_pipeline_fixture


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

if __name__ == "__main__":
    unittest.main()
