"""Exercise cache timestamp reuse and invalidation against a real Git checkout."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def cache_checkout(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "native").mkdir()
    script = tmp_path / "scripts" / "restore_native_cache_times.ps1"
    shutil.copyfile(ROOT / "scripts" / script.name, script)
    source = tmp_path / "native" / "source.cpp"
    source.write_text("int value = 1;\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "native", "scripts"], check=True, capture_output=True)

    def run(key, profile="ci", scope="native"):
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script),
             "-SourceKey", key, "-Arch", "x64", "-BuildProfile", profile,
             "-Scope", scope],
            check=False, capture_output=True, text=True, encoding="utf-8", timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    return tmp_path, source, run


def test_unchanged_native_cache_restores_checkout_times(cache_checkout):
    root, source, run = cache_checkout
    original = source.stat().st_mtime_ns
    run("same-inputs")
    os.utime(source, ns=(original + 60_000_000_000, original + 60_000_000_000))
    assert source.stat().st_mtime_ns > original
    assert "Restored 2 unchanged" in run("same-inputs")
    assert source.stat().st_mtime_ns == original
    state = json.loads((root / ".cache/native-source-times-x64-ci.json").read_text(encoding="utf-8-sig"))
    assert state["SourceKey"] == "same-inputs"


def test_changed_sources_and_other_profiles_keep_checkout_times(cache_checkout):
    root, source, run = cache_checkout
    original = source.stat().st_mtime_ns
    run("old-inputs")
    source.write_text("int value = 2;\n", encoding="utf-8")
    changed = original + 60_000_000_000
    os.utime(source, ns=(changed, changed))
    # A changed native source stays invalidated. An unchanged script retains
    # its blob fingerprint and is restored by a fallback cache even though
    # the aggregate key changed.
    script = root / "scripts" / "restore_native_cache_times.ps1"
    script_original = script.stat().st_mtime_ns
    os.utime(script, ns=(script_original + 60_000_000_000,) * 2)
    assert "Restored 1 unchanged" in run("new-inputs")
    assert script.stat().st_mtime_ns == script_original
    assert source.stat().st_mtime_ns == changed
    assert "Restored 0 unchanged" in run("new-inputs", profile="release")
    assert source.stat().st_mtime_ns == changed
    assert (root / ".cache/native-source-times-x64-release.json").is_file()


def test_gui_timestamps_are_independent_of_native_sources(cache_checkout):
    root, native_source, run = cache_checkout
    gui_source = root / "gui" / "src" / "window.cpp"
    gui_source.parent.mkdir(parents=True)
    gui_source.write_text("int ui = 1;\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "gui"], check=True, capture_output=True)

    native_original = native_source.stat().st_mtime_ns
    gui_original = gui_source.stat().st_mtime_ns
    assert "Restored 0 unchanged gui" in run("gui-only", scope="gui")
    run("native-only")
    # Updating a GUI source does not invalidate an unchanged native checkout.
    gui_source.write_text("int ui = 2;\n", encoding="utf-8")
    gui_changed = gui_original + 60_000_000_000
    os.utime(gui_source, ns=(gui_changed,) * 2)
    native_changed = native_original + 60_000_000_000
    os.utime(native_source, ns=(native_changed,) * 2)
    assert "Restored 2 unchanged native" in run("native-only")
    assert native_source.stat().st_mtime_ns == native_original
    # A changed GUI file is never restored, while its unchanged script can.
    assert "Restored 1 unchanged gui" in run("gui-other-key", scope="gui")
    assert gui_source.stat().st_mtime_ns == gui_changed
    assert (root / ".cache/gui-source-times-x64-ci.json").is_file()
