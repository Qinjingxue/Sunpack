"""Exercise the installer field migration with Windows PowerShell 5.1.

Runtime configuration tests never execute this installer-only algorithm or
check its commit/failure behavior. One small combined fixture covers that independent
boundary without a test per schema field; deleting it loses that coverage.
"""
import json
import subprocess


def test_installer_field_upgrade_preserves_values_and_modules(tmp_path, repo_root):
    old = {
        "removed": {"value": 1}, "keep": {"false": True, "zero": 5, "empty": "default", "null": 2, "array": [1]},
        "absent": {"existing": 1},
        "filesystem": {"directory_scan_mode": "recursive", "scan_filters": [
            {"name": "keep", "removed": 1, "enabled": True, "rules": ["old"]},
            {"name": "deleted", "enabled": True},
        ]},
    }
    new = {
        "keep": {"false": False, "zero": 6, "empty": "new", "null": 3, "array": [2], "added": 8},
        "absent": {"existing": 2, "added": 9},
        "advanced_only": True, "new_null": 1,
        "filesystem": {"scan_filters": [
            {"name": "keep", "enabled": False, "rules": ["new"], "added": 4},
            {"name": "new", "enabled": True},
            {"name": "advanced_only", "enabled": True},
        ]},
    }
    template = {
        "keep": {"added": 80}, "absent": {"existing": 20, "added": 90}, "new_null": None,
        "filesystem": {"scan_filters": [
            {"name": "keep", "added": 40}, {"name": "new", "enabled": False},
        ]},
    }
    user = {
        "removed": {"value": "user"}, "unknown": {"value": 7},
        "keep": {"false": False, "zero": 0, "empty": "", "null": None, "array": []},
        "filesystem": {"directory_scan_mode": "recursive", "scan_filters": [
            {"name": "unknown", "rules": []},
            {"name": "keep", "enabled": False, "rules": ["user"], "removed": 99},
            {"name": "deleted", "enabled": False},
        ]},
    }
    paths = {}
    for name, value in (("old", old), ("new", new), ("template", template), ("user", user)):
        path = tmp_path / f"配置 {name}.json"
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        paths[name] = path

    command = [
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(repo_root / "scripts/upgrade_config.ps1"),
        "-OldAdvanced", str(paths["old"]), "-NewAdvanced", str(paths["new"]),
        "-Template", str(paths["template"]), "-UserConfig", str(paths["user"]),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    expected = {
        "unknown": {"value": 7}, "keep": {**user["keep"], "added": 80},
        "absent": {"added": 90}, "new_null": None,
        "filesystem": {"scan_filters": user["filesystem"]["scan_filters"]},
    }
    assert json.loads(paths["user"].read_text(encoding="utf-8")) == expected
    committed = paths["user"].read_bytes()
    repeated = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert repeated.returncode == 0, repeated.stdout + repeated.stderr
    assert paths["user"].read_bytes() == committed
    paths["new"].write_text("invalid JSON", encoding="utf-8")
    failed = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert failed.returncode != 0
    assert paths["user"].read_bytes() == committed
    assert not list(tmp_path.glob(".sunpack-config-*.tmp"))
