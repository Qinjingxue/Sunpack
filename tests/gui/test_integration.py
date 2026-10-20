"""Cross-language file identity and tray launch contracts, absent from C++ tests."""
import os
import platform
import subprocess
import json
from pathlib import Path

import pytest

from sunpack.core.platform.windows.file_mutex import file_mutex, file_mutex_name
from sunpack.runtime.watch.service import watch_roots_mutex_name
from sunpack.runtime.gui import manager


def test_native_mutex_matches_runtime_for_windows_paths(tmp_path):
    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    binary = Path(os.environ.get("SUNPACK_GUI_TEST_BINARY", Path(__file__).resolve().parents[2] / ".cache" / f"gui-{arch}" / "Release" / "sunpack_gui_tests.exe"))
    if not binary.is_file():
        pytest.skip("Build the native GUI with scripts/build_gui.ps1")
    for path in (tmp_path / "builtin_passwords.json", Path("C:/混合İ/../中文/密码.json"), Path(r"\\server\share\密码.json"), "C:/Data/", "C:/", "//server/share/"):
        names = subprocess.check_output([str(binary), "--mutex", str(path)], text=True, encoding="utf-8").splitlines()
        assert names == [file_mutex_name(path), watch_roots_mutex_name(path)]


def test_native_edit_preserves_python_clipboard_update_under_same_mutex(tmp_path, monkeypatch):
    from sunpack.core.passwords.internal import builtin

    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    binary = Path(os.environ.get("SUNPACK_GUI_TEST_BINARY", Path(__file__).resolve().parents[2] / ".cache" / f"gui-{arch}" / "Release" / "sunpack_gui_tests.exe"))
    if not binary.is_file():
        pytest.skip("Build the native GUI with scripts/build_gui.ps1")
    path = tmp_path / "builtin_passwords.json"
    path.write_text(json.dumps({"passwords": [{"value": "initial"}], "clipboard_history": []}), encoding="utf-8")
    monkeypatch.setattr(builtin, "builtin_password_path", lambda: path)
    with file_mutex(path):
        process = subprocess.Popen([str(binary), "--password-add", str(path), " GUI # 中文 "], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert builtin.merge_watch_clipboard_passwords(["后台新密码"])
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 0, (stdout, stderr)
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document == {"passwords": [{"value": "initial"}, {"value": " GUI # 中文 "}], "clipboard_history": ["后台新密码"]}


def test_packaged_manager_launch_releases_native_process_handle(tmp_path, monkeypatch):
    executable = tmp_path / "sunpack-runtime.exe"
    (tmp_path / "SunPackGUI.exe").touch()
    monkeypatch.setattr(manager, "current_process_executable", lambda: executable)
    monkeypatch.setattr(manager, "is_packaged_process", lambda: True)
    monkeypatch.setattr(manager, "writable_data_dir", lambda: tmp_path)
    calls = []

    class Process:
        def close(self):
            calls.append("closed")

    def launch(argv, **kwargs):
        calls.append((argv, kwargs))
        return Process()

    monkeypatch.setattr(manager, "launch_unelevated", launch)
    manager.launch_manager()
    assert calls == [([str(tmp_path / "SunPackGUI.exe")], {"cwd": str(tmp_path)}), "closed"]


def test_gui_ranges_keep_runtime_boundaries_exact():
    """Native GUI serialization must survive the real config parsers, including
    a >2**53 byte boundary. C++ roundtrips cannot detect Python float rounding;
    one tiny existing test-binary process covers this language boundary.
    """
    from datetime import datetime
    from sunpack.pipeline.discovery.filesystem.filters.modules.size_range import NumericRange
    from sunpack.pipeline.discovery.filesystem.filters.modules.mtime_range import MtimeRangeScanFilter

    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    binary = Path(os.environ.get("SUNPACK_GUI_TEST_BINARY", Path(__file__).resolve().parents[2] / ".cache" / f"gui-{arch}" / "Release" / "sunpack_gui_tests.exe"))
    if not binary.is_file():
        pytest.skip("Build the native GUI with scripts/build_gui.ps1")
    expressions = json.loads(subprocess.check_output([str(binary), "--ranges"], text=True, encoding="utf-8"))
    size = NumericRange.from_config({"range": expressions["size"]})
    assert not size.allows(9007199254740992)
    assert size.allows(9007199254740993)
    assert not NumericRange.from_config({"range": expressions["size"], "lt": 9007199254740993}).allows(9007199254740993)
    time = MtimeRangeScanFilter.from_config({"date": expressions["time"]}).value_range
    lower = int(datetime(2024, 2, 29, 12, 34).timestamp() * 1_000_000_000)
    upper = int(datetime(2027, 1, 1).timestamp() * 1_000_000_000)
    assert time.allows(lower) and not time.allows(lower - 1)
    assert not time.allows(upper) and time.allows(upper - 1)
