from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
PREPARE_SCRIPT = ROOT / "scripts" / "prepare_winget_manifest.ps1"
VALIDATE_SCRIPT = ROOT / "scripts" / "validate_winget_manifest.ps1"


def _run_prepare(output_root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(PREPARE_SCRIPT),
            "-Version",
            "9.8.7",
            "-X64Sha256",
            "a" * 64,
            "-Arm64Sha256",
            "b" * 64,
            "-OutputRoot",
            str(output_root),
        ],
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
    assert "DisplayName: SunPack v9.8.7 (x64)" in installer
    assert "DisplayName: SunPack v9.8.7 (arm64)" in installer
    assert "DisplayVersion: v9.8.7" in installer
    assert "InstallerType: inno" in installer
    assert "InstallerSha256: " + "A" * 64 in installer
    assert "InstallerSha256: " + "B" * 64 in installer
    assert "PackageLocale: en-US" in locale
    assert "Publisher: SunPack" in locale


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
