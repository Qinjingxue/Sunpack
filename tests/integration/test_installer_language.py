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
    assert "ActiveLanguage = 'chinesesimplified'" in installer
    assert "InitializeLanguageOnInstall := not FileExists(" in installer
    assert "initialize_config_language.ps1" in build
    assert any("initialize_config_language.ps1\"; DestDir: \"{tmp}" in line and
               "deleteafterinstall" in line for line in installer.splitlines())
    post_install = installer.split("procedure CurStepChanged(CurStep: TSetupStep);", 1)[1]
    assert "UpgradeConfigurationFields" not in post_install
    assert post_install.index("InitializeInstalledLanguage;") < post_install.index(
        "ApplySelectedContextMenuState;"
    )
    prepare = installer.split("function PrepareToInstall", 1)[1].split("function InitializeUninstall", 1)[0]
    assert prepare.index("StopExistingProcessesAndWait") < prepare.index(
        "StopAndDeleteBrokerService"
    ) < prepare.index("UpgradeConfigurationFields")
    assert prepare.index("InitializeLanguageOnInstall := not FileExists(") < prepare.index(
        "UpgradeConfigurationFields"
    ) < prepare.index("RemoveMachinePath(ExistingApplicationDirectory)")
    # GUI preferences belong to HKCU, not to the shared configuration migration.
    # Only uninstall may remove them, through the original desktop-user helper
    # rather than the elevated installer's possibly different HKCU.
    install, uninstall = installer.split("procedure CurUninstallStepChanged", 1)
    assert "RemoveGuiPreferences" not in install
    assert "RunInstallerIntegration('RemoveGuiPreferences', ResultCode)" in uninstall
    integration = (repo_root / "installer/integration.ps1").read_text(encoding="utf-8")
    assert integration.index("exit (Invoke-AsShellUser $Action)") < integration.index("switch ($Action)")
    assert "'RemoveGuiPreferences' { Remove-Registration 'HKCU:\\Software\\SunPack\\GUI' }" in integration


def test_uninstall_removes_only_gui_preferences(tmp_path, repo_root):
    # The GUI registry tests do not execute the uninstall helper. Run its real
    # shell-user action against a unique test key and retain a sibling value.
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Requires Windows PowerShell (installer runtime)")
    import uuid
    import winreg

    path = "Software\\SunPackInstallerTests\\" + uuid.uuid4().hex
    script = (repo_root / "installer/integration.ps1").read_text(encoding="utf-8")
    target = "HKCU:\\Software\\SunPack\\GUI"
    assert script.count(target) == 1
    helper = tmp_path / "integration.ps1"
    helper.write_text(script.replace(target, "HKCU:\\" + path + "\\GUI"), encoding="utf-8-sig")
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
            winreg.SetValueEx(key, "Keep", 0, winreg.REG_DWORD, 1)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path + "\\GUI") as key:
            winreg.SetValueEx(key, "Theme", 0, winreg.REG_DWORD, 2)
        command = [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                   "-File", str(helper), "-Action", "RemoveGuiPreferences", "-ShellUser"]
        for _ in range(2):  # Already absent preferences must not fail uninstall.
            result = subprocess.run(command, capture_output=True, text=True)
            assert result.returncode == 0, result.stdout + result.stderr
        with pytest.raises(FileNotFoundError):
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, path + "\\GUI")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            assert winreg.QueryValueEx(key, "Keep")[0] == 1
    finally:
        for key in (path + "\\GUI", path):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
            except FileNotFoundError:
                pass
