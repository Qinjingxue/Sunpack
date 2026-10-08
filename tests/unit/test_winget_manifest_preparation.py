from pathlib import Path
import json
import subprocess


ROOT = Path(__file__).resolve().parents[2]
PREPARE_SCRIPT = ROOT / "scripts" / "prepare_winget_manifest.ps1"
# Inno Setup AppId from installer/SunPack.iss, in the form Inno writes it to the
# uninstall registry key ("<AppId>_is1").
PRODUCT_CODE = "'{9E8C73E5-C540-4E68-93E0-1FBAAFB89713}_is1'"


def _check_complete_multifile_set(tmp_path, result):

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
    assert "MinimumOSVersion: 10.0.14393.0" in installer
    assert "Scope: machine" in installer
    assert "ElevationRequirement: elevationRequired" in installer
    assert "Silent: /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-" in installer
    assert "SilentWithProgress: /SILENT /SUPPRESSMSGBOXES /NORESTART /SP-" in installer
    assert "Architecture: x64" in installer
    assert "Architecture: arm64" in installer
    assert "DisplayName: SunPack 9.8.7 (x64)" in installer
    assert "DisplayName: SunPack 9.8.7 (arm64)" in installer
    assert "DisplayVersion:" not in installer
    assert "InstallerSha256: " + "A" * 64 in installer
    assert "InstallerSha256: " + "B" * 64 in installer
    assert "PackageLocale: en-US" in locale
    assert "Publisher: SunPack" in locale


def _check_package_version(tmp_path, result):

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
    assert "DisplayVersion:" not in installer


def _check_product_code(tmp_path, result):

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


def _check_release_tag_differs(tmp_path, result):

    assert result.returncode != 0
    assert "ReleaseTag must match Version" in (result.stdout or "") + (result.stderr or "")


def _check_published_date(tmp_path, result):

    assert result.returncode == 0, result.stdout + result.stderr
    locale = (
        tmp_path / "q" / "Qinjingxue" / "SunPack" / "9.8.7"
        / "Qinjingxue.SunPack.locale.en-US.yaml"
    ).read_text(encoding="utf-8")

    installer = (
        tmp_path / "q" / "Qinjingxue" / "SunPack" / "9.8.7"
        / "Qinjingxue.SunPack.installer.yaml"
    ).read_text(encoding="utf-8")
    assert "ReleaseDate: 2026-10-03" in installer
    assert "ReleaseDate:" not in locale


def _check_unspecified_date(tmp_path, result):
    assert result.returncode == 0, result.stdout + result.stderr
    for path in (tmp_path / "q" / "Qinjingxue" / "SunPack" / "9.8.7").glob("*.yaml"):
        assert "ReleaseDate:" not in path.read_text(encoding="utf-8")


def _check_invalid_calendar_date(tmp_path, result):
    assert result.returncode != 0


def _check_does_not_overwrite(tmp_path, first, second):
    assert first.returncode == 0, first.stdout + first.stderr
    assert second.returncode != 0
    assert "-Force" in ((second.stdout or "") + (second.stderr or ""))


# One pytest item keeps worksteal from distributing cases to separate hosts.
# Subtests retain independent failure reporting and execute every assertion set.
CASES = [
    ("complete_multifile", _check_complete_multifile_set, {}),
    ("package_version", _check_package_version, {"Version": "v0.5.1"}),
    ("product_code", _check_product_code, {}),
    ("release_tag_differs", _check_release_tag_differs, {"ReleaseTag": "v9.8.7"}),
    ("published_date", _check_published_date, {"ReleaseDate": "2026-10-03"}),
    ("unspecified_date", _check_unspecified_date, {}),
    ("invalid_calendar_date", _check_invalid_calendar_date, {"ReleaseDate": "2026-02-30"}),
    ("does_not_overwrite", _check_does_not_overwrite, {}),
]


def test_prepare_winget_manifest_cases(tmp_path, subtests):
    requests = []
    for name, _check, overrides in CASES:
        arguments = {
            "Version": "9.8.7", "X64Sha256": "a" * 64, "Arm64Sha256": "b" * 64,
            "OutputRoot": str(tmp_path / name), **overrides,
        }
        requests.append({"id": name, "arguments": arguments})
    requests.append({"id": "overwrite_second", "arguments": requests[-1]["arguments"]})
    cases_path = tmp_path / "cases.json"
    results_path = tmp_path / "results.json"
    cases_path.write_text(json.dumps(requests), encoding="utf-8")
    host = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(ROOT / "tests/helpers/prepare_winget_cases.ps1"),
         "-PrepareScript", str(PREPARE_SCRIPT), "-CasesPath", str(cases_path),
         "-ResultsPath", str(results_path)],
        cwd=ROOT, text=True, capture_output=True, encoding="utf-8", errors="replace",
        check=False, timeout=120,
    )
    assert host.returncode == 0, host.stdout + host.stderr
    records = json.loads(results_path.read_text(encoding="utf-8"))
    assert [record["id"] for record in records] == [case["id"] for case in requests]
    results = {
        record["id"]: subprocess.CompletedProcess(
            args=record["id"], returncode=record["returncode"],
            stdout=record["stdout"], stderr=record["stderr"],
        ) for record in records
    }
    for name, check, _overrides in CASES:
        with subtests.test(msg=name):
            if name == "does_not_overwrite":
                check(tmp_path / name, results[name], results["overwrite_second"])
            else:
                check(tmp_path / name, results[name])
