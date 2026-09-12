import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
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
        self.assertIn("inspect", result.stdout)
        self.assertIn("passwords", result.stdout)
        self.assertIn("config", result.stdout)
        self.assertNotIn("models", result.stdout)

    def test_scan_json_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = build_cli_pipeline_fixture(Path(tmp))
            result = run_cli("scan", "--json", str(fixture), "--no-pause")

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["command"], "scan")
        self.assertIn("task_count", payload["summary"])
        self.assertGreaterEqual(payload["summary"]["task_count"], 1)
        self.assertIn("tasks", payload)

    def test_inspect_json_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = build_cli_pipeline_fixture(Path(tmp))
            result = run_cli("inspect", "--json", str(fixture), "--no-pause")

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["command"], "inspect")
        self.assertIn("total_items", payload["summary"])
        self.assertGreaterEqual(payload["summary"]["total_items"], 1)
        self.assertIn("items", payload)
        first_item = payload["items"][0]
        self.assertIn("decision_stage", first_item)
        self.assertIn("discarded_at", first_item)
        self.assertIn("deciding_rule", first_item)
        self.assertIn("stop_reason", first_item)
        self.assertIn("score_breakdown", first_item)
        self.assertNotIn("confirmation", first_item)

    def test_inspect_analyze_json_shape_is_compact(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = build_cli_pipeline_fixture(Path(tmp))
            result = run_cli("inspect", "--json", "--analyze", str(fixture), "--no-pause")

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["summary"]["analyze"])
        analyzed = [item for item in payload["items"] if item.get("analysis")]
        self.assertGreaterEqual(len(analyzed), 1)
        analysis = analyzed[0]["analysis"]
        self.assertIn("status", analysis)
        self.assertIn("selected_format", analysis)
        self.assertIn("selected_confidence", analysis)
        self.assertIn("primary_segment", analysis)
        self.assertIn("candidates", analysis)
        self.assertLessEqual(len(analysis["candidates"]), 3)
        self.assertNotIn("prepass", analysis)
        self.assertNotIn("fuzzy", analysis)

    def test_inspect_archives_only_filters_output_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = build_cli_pipeline_fixture(Path(tmp))
            result = run_cli("inspect", "--json", "--archives-only", str(fixture), "--no-pause")

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["inputs"]["archives_only"])
        self.assertTrue(payload["summary"]["archives_only"])
        self.assertGreaterEqual(payload["summary"]["total_items"], payload["summary"]["displayed_items"])
        self.assertGreaterEqual(payload["summary"]["displayed_items"], 1)
        self.assertTrue(all(item["should_extract"] for item in payload["items"]))
        self.assertTrue(all(item["decision"] == "archive" for item in payload["items"]))

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

    def test_scan_help_does_not_expose_rule_internal_min_size_override(self):
        result = run_cli("scan", "-h")

        self.assertEqual(result.returncode, 0)
        self.assertNotIn("--min-size", result.stdout)

    def test_inspect_help_documents_archives_only_filter(self):
        result = run_cli("inspect", "-h")

        self.assertEqual(result.returncode, 0)
        self.assertIn("--archives-only", result.stdout)

    def test_extract_help_documents_runtime_overrides(self):
        result = run_cli("extract", "-h")

        self.assertEqual(result.returncode, 0)
        self.assertNotIn("--color", result.stdout)
        self.assertIn("--recur", result.stdout)
        self.assertNotIn("--worker-profile", result.stdout)
        self.assertIn("--cleanup", result.stdout)
        self.assertIn("--out-dir", result.stdout)
        self.assertIn("--write-manifest", result.stdout)
        self.assertIn("--direct-file", result.stdout)
        self.assertNotIn("--min-size", result.stdout)

    def test_extract_direct_file_bypasses_initial_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "payload.bin"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("marker.txt", "direct")
            out_dir = root / "out"

            result = run_cli(
                "extract",
                "--json",
                "--direct-file",
                "--out-dir",
                str(out_dir),
                "--cleanup",
                "k",
                "--recur",
                "1",
                str(archive),
                "--no-pause",
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["inputs"]["direct_file"])
        self.assertEqual(payload["summary"]["success_count"], 1)

    def test_inspect_help_documents_analyze_option(self):
        result = run_cli("inspect", "-h")

        self.assertEqual(result.returncode, 0)
        self.assertIn("--analyze", result.stdout)

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
            self.assertEqual(
                payload["inputs"]["config_overrides"]["output_dir"],
                str(out_dir.resolve()),
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
                payload["inputs"]["config_overrides"]["output_dir"],
                str((request_dir / "relative-out").resolve()),
            )

    def test_watch_help_documents_watchdog_options(self):
        result = run_cli("watch", "-h")

        self.assertEqual(result.returncode, 0)
        self.assertIn("add", result.stdout)
        self.assertIn("start", result.stdout)
        self.assertIn("list", result.stdout)
        self.assertIn("startup", result.stdout)

    def test_passwords_help_only_shows_password_relevant_options(self):
        result = run_cli("passwords", "-h")

        self.assertEqual(result.returncode, 0)
        self.assertIn("--json", result.stdout)
        self.assertIn("--password", result.stdout)
        self.assertNotIn("--clipboard-pw", result.stdout)
        self.assertNotIn("--quiet", result.stdout)
        self.assertNotIn("--verbose", result.stdout)
        self.assertNotIn("--pause", result.stdout)

    def test_config_help_only_exposes_show_and_validate(self):
        result = run_cli("config", "-h")

        self.assertEqual(result.returncode, 0)
        self.assertIn("{show,validate}", result.stdout)
        self.assertNotIn("blacklist", result.stdout)
        self.assertNotIn("{show,validate,set", result.stdout)
        self.assertNotIn("{show,validate,rule", result.stdout)
        self.assertNotIn("--verbose", result.stdout)
        self.assertNotIn("--pause", result.stdout)


if __name__ == "__main__":
    unittest.main()
