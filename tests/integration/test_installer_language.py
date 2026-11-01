"""Install-time language selection and preservation of existing user preferences."""
import json
import shutil
import subprocess

import pytest


def _run_initializer(repo_root, simple, advanced, language, *, first_install):
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Requires Windows PowerShell (installer runtime)")
    command = [
        powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-File",
        str(repo_root / "scripts" / "initialize_config_language.ps1"),
        "-UserConfig", str(simple), "-AdvancedConfig", str(advanced),
        "-Language", language,
    ]
    if first_install:
        command.append("-InitializeUserConfig")
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("language", ["en", "zh"])
def test_first_install_localizes_both_config_files(tmp_path, repo_root, language):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    originals = {}
    for path in (simple, advanced):
        original = (repo_root / path.name).read_text(encoding="utf-8")
        originals[path.name] = original
        path.write_text(original, encoding="utf-8")
    _run_initializer(repo_root, simple, advanced, language, first_install=True)
    for path in (simple, advanced):
        assert json.loads(path.read_text(encoding="utf-8"))["cli"]["language"] == language
        assert path.read_text(encoding="utf-8") == originals[path.name].replace(
            '"language": "zh"', f'"language": "{language}"', 1
        )


@pytest.mark.parametrize("stored_language,installer_language", [
    ("zh", "en"), ("en", "zh"),
])
def test_upgrade_preserves_user_language(tmp_path, repo_root, stored_language, installer_language):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    settings = json.loads((repo_root / simple.name).read_text(encoding="utf-8"))
    settings["cli"]["language"] = stored_language
    settings["user_extension"] = {"preserve": "unchanged"}
    original = json.dumps(settings, ensure_ascii=False, indent=2) + "\n"
    simple.write_text(original, encoding="utf-8")
    shutil.copyfile(repo_root / advanced.name, advanced)
    _run_initializer(repo_root, simple, advanced, installer_language, first_install=False)
    assert simple.read_text(encoding="utf-8") == original
    assert json.loads(advanced.read_text(encoding="utf-8"))["cli"]["language"] == stored_language


def test_installer_initializes_language_before_context_menu_registration(repo_root):
    installer = (repo_root / "installer" / "SunPack.iss").read_text(encoding="utf-8")
    build = (repo_root / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    assert "ActiveLanguage()" in installer
    assert "InitializeLanguageOnInstall := not FileExists(" in installer
    assert "initialize_config_language.ps1" in build
    assert any("initialize_config_language.ps1\"; DestDir: \"{tmp}" in line and
               "deleteafterinstall" in line for line in installer.splitlines())
    post_install = installer.split("procedure CurStepChanged(CurStep: TSetupStep);", 1)[1]
    assert post_install.index("UpgradeConfigurationFields;") < post_install.index(
        "InitializeInstalledLanguage;"
    ) < post_install.index("RunContextMenuScript(True)")
