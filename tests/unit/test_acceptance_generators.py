"""Acceptance cannot silently omit a public real-format fixture family."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.helpers import tool_config


class AcceptanceGeneratorsTest(unittest.TestCase):
    def test_required_matrix_and_writer_capabilities(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = {
                "seven_zip": root / "7zip/7z.exe",
                "seven_zip_sfx": root / "7zip/7zCon.sfx",
                "seven_zip_zstd": root / "lz4/7z.exe",
                "rar_exe": root / "rar/Rar.exe",
                "winrar_exe": root / "rar/WinRAR.exe",
                "zstd_exe": root / "zstd/zstd.exe",
            }
            files = [*tools.values(), root / "7zip/7z.dll", root / "lz4/7z.dll", root / "rar/Default.SFX"]
            for path in files:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()

            outputs = {
                str(tools["rar_exe"]): (7, "RAR 6.22 x64"),
                str(tools["seven_zip_zstd"]): (0, " 0 ED 4F71104 LZ4\n"),
            }

            def probe(command, **kwargs):
                code, output = outputs.get(command[0], (0, ""))
                return subprocess.CompletedProcess(command, code, output)

            with patch.object(tool_config, "get_test_tools", return_value=tools), patch.object(
                tool_config.subprocess, "run", side_effect=probe,
            ):
                self.assertEqual(tool_config.acceptance_generator_errors(), [])
                # Every required generator/module must gate acceptance, rather
                # than leaving the corresponding real tests to skip/continue.
                for path in files:
                    with self.subTest(missing=path.name):
                        path.unlink()
                        self.assertTrue(tool_config.acceptance_generator_errors())
                        path.touch()
                outputs[str(tools["rar_exe"])] = (7, "RAR 7.00 x64")
                outputs[str(tools["seven_zip_zstd"])] = (0, " 0 D 4F71104 LZ4\n")
                outputs[str(tools["zstd_exe"])] = (1, "unusable")
                errors = tool_config.acceptance_generator_errors()
                self.assertEqual(len(errors), 3, errors)
                self.assertTrue(any("RAR4/RAR5" in error for error in errors))
                self.assertTrue(any("LZ4" in error for error in errors))
                self.assertTrue(any("Zstandard generator" in error for error in errors))

    def test_configured_paths_are_the_fixture_paths(self):
        # The gate and fixture writers must honor the very same overrides.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            overrides = {
                "sunpack_TEST_7Z": str(root / "7zip/7z.exe"),
                "sunpack_TEST_7Z_SFX": str(root / "7zip/7zCon.sfx"),
                "sunpack_TEST_7Z_ZSTD": str(root / "lz4/7z.exe"),
                "sunpack_TEST_RAR": str(root / "rar/Rar.exe"),
                "sunpack_TEST_WINRAR": str(root / "rar/WinRAR.exe"),
                "sunpack_TEST_ZSTD": str(root / "zstd/zstd.exe"),
            }
            with patch.dict(tool_config.os.environ, overrides), patch.object(tool_config.shutil, "which", return_value=None):
                errors = tool_config.acceptance_generator_errors()
            self.assertEqual(len(errors), 9, errors)
            for name, path in overrides.items():
                if name != "sunpack_TEST_WINRAR":
                    self.assertTrue(any(path in error for error in errors), path)
            self.assertTrue(any("WinRAR generator is missing" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
