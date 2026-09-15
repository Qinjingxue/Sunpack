from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
PREPARE_SCRIPT = ROOT / "scripts" / "prepare_winget_manifest.ps1"
VALIDATE_SCRIPT = ROOT / "scripts" / "validate_winget_manifest.ps1"
# Inno Setup AppId from installer/SunPack.iss, in the form Inno writes it to the
# uninstall registry key ("<ProductCode>_is1").
PRODUCT_CODE = "'{9E8C73E5-C540-4E68-93E0-1FBAAFB89713}'"


def _run_prepare(
    output_root: Path,
    version: str = "9.8.7",
    release_tag: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [
        "pwsh",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(PREPARE_SCRIPT),
        "-Version",
        version,
        "-X64Sha256",
        "a" * 64,
        "-Arm64Sha256",
        "b" * 64,
        "-OutputRoot",
        str(output_root),
    ]
    if release_tag is not None:
        command += ["-ReleaseTag", release_tag]
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def test_prepare_winget_manifest_emits_a_complete_multifile_set(tmp_path):
    result = _run_prepare(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    manifest_root = tmp_path / "q" / "Qinjingxue" / "SunPack" / "9.8.7"
    expected = {
        "Qinjingxue.SunPack.yaml",
        "Qinjingxue.SunPack.installer.yaml",
        "Qinjingxue.SunPack.locale.en-US.yaml",
    }
    assert {path.name for path in manifest_root.iterdir()} == expected

    version = (manifest_root / "Qinjingxue.SunPack.yaml").read_text(encoding="utf-8")
    installer = (manifest_root / "Qinjingxue.SunPack.installer.yaml").read_text(
        encoding="utf-8"
    )
    locale = (manifest_root / "Qinjingxue.SunPack.locale.en-US.yaml").read_text(
        encoding="utf-8"
    )

    assert "PackageVersion: 9.8.7" in version
    assert "ManifestType: version" in version
    assert "InstallerType: inno" in installer
    assert "Scope: machine" in installer
    assert "ElevationRequirement: elevationRequired" in installer
    assert "Silent: /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-" in installer
    assert "SilentWithProgress: /SILENT /SUPPRESSMSGBOXES /NORESTART /SP-" in installer
    assert "Architecture: x64" in installer
    assert "Architecture: arm64" in installer
    assert "DisplayName: SunPack 9.8.7 (x64)" in installer
    assert "DisplayName: SunPack 9.8.7 (arm64)" in installer
    assert "DisplayVersion: 9.8.7" in installer
    assert "InstallerSha256: " + "A" * 64 in installer
    assert "InstallerSha256: " + "B" * 64 in installer
    assert "PackageLocale: en-US" in locale
    assert "Publisher: SunPack" in locale


def test_prepare_winget_manifest_keeps_package_version_equal_to_the_release_tag(tmp_path):
    result = _run_prepare(tmp_path, version="v0.5.1")

    assert result.returncode == 0, result.stdout + result.stderr
    # The installers are built from the tag and report it verbatim, so the
    # package version, the manifest directory, and the installer URLs must all
    # carry the tag exactly, "v" prefix included.
    manifest_root = tmp_path / "q" / "Qinjingxue" / "SunPack" / "v0.5.1"
    installer = (manifest_root / "Qinjingxue.SunPack.installer.yaml").read_text(
        encoding="utf-8"
    )

    assert "PackageVersion: v0.5.1" in installer
    assert (
        "https://github.com/Qinjingxue/Sunpack/releases/download/v0.5.1/"
        "sunpack-windows-x64-v0.5.1-setup.exe"
    ) in installer
    assert (
        "https://github.com/Qinjingxue/Sunpack/releases/download/v0.5.1/"
        "sunpack-windows-arm64-v0.5.1-setup.exe"
    ) in installer
    assert "DisplayName: SunPack v0.5.1 (x64)" in installer
    assert "DisplayName: SunPack v0.5.1 (arm64)" in installer
    assert "DisplayVersion: v0.5.1" in installer


def test_prepare_winget_manifest_declares_the_inno_product_code(tmp_path):
    result = _run_prepare(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    installer = (
        tmp_path / "q" / "Qinjingxue" / "SunPack" / "9.8.7"
        / "Qinjingxue.SunPack.installer.yaml"
    ).read_text(encoding="utf-8")

    # Winget correlates the installed ARP entry through the Inno Setup AppId, and
    # it must be quoted because a bare leading brace parses as a YAML mapping.
    assert f"    ProductCode: {PRODUCT_CODE}" in installer
    assert f"        ProductCode: {PRODUCT_CODE}" in installer
    assert installer.count(PRODUCT_CODE) == 4


def test_prepare_winget_manifest_rejects_a_release_tag_that_differs_from_version(tmp_path):
    result = _run_prepare(tmp_path, version="9.8.7", release_tag="v9.8.7")

    assert result.returncode != 0
    assert "ReleaseTag must match Version" in (result.stdout or "") + (result.stderr or "")


def test_prepare_winget_manifest_records_the_tag_commit_date_when_available(tmp_path):
    result = _run_prepare(tmp_path, version="v0.5.1")

    assert result.returncode == 0, result.stdout + result.stderr
    locale = (
        tmp_path / "q" / "Qinjingxue" / "SunPack" / "v0.5.1"
        / "Qinjingxue.SunPack.locale.en-US.yaml"
    ).read_text(encoding="utf-8")

    assert "ReleaseDate: 20" in locale


def test_prepare_winget_manifest_does_not_overwrite_without_force(tmp_path):
    first = _run_prepare(tmp_path)
    second = _run_prepare(tmp_path)

    assert first.returncode == 0, first.stdout + first.stderr
    assert second.returncode != 0
    assert "-Force" in ((second.stdout or "") + (second.stderr or ""))


def test_validate_script_requires_the_complete_multifile_manifest_set():
    script = VALIDATE_SCRIPT.read_text(encoding="utf-8")

    assert '"$packageIdentifier.installer.yaml"' in script
    assert '"$packageIdentifier.locale.en-US.yaml"' in script
    assert "Resolve-Path -LiteralPath $ManifestRoot" in script
    assert "Test-Path -LiteralPath $resolvedRoot -PathType Container" in script
    assert "validate --manifest $resolvedRoot" in script
