from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_release_package_uses_native_console_launcher_and_one_shared_gui_runtime():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")

    assert '$runtimeExeName = "sunpack-runtime.exe"' in build_script
    assert '$watchExeName' not in build_script
    assert "Packaged shared SunPack runtime executable" in build_script
    assert build_script.count("Invoke-NuitkaStandaloneBuild -PythonPath") == 1
    assert 'ConsoleMode "disable"' in build_script
    assert 'Assert-PathMissing -LiteralPath (Join-Path $distAppRoot "sunpack-watch.exe")' in build_script
