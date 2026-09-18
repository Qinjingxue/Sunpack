# WinGet preparation

This directory is local staging for the `Qinjingxue.SunPack` submission. It is
intentionally outside the `manifests/` root used by `microsoft/winget-pkgs`, so a
draft cannot be mistaken for a ready upstream submission.

`v0.5.0` is deliberately not submitted; that release is known to contain bugs.
The first submitted version is `v0.5.1`.

## Package version equals the release tag

The installers are built from the tag (`build_windows.ps1 -Version <tag>`) and
report that value verbatim through Inno Setup's `AppVersion`, so the tag *is* the
version: `v0.5.1` installed from the release writes
`DisplayVersion = v0.5.1` to Add/Remove Programs.

`PackageVersion` therefore carries the tag exactly, `v` prefix included, and the
manifest directory is named `v0.5.1`. `-ReleaseTag` exists only as an explicit
assertion: when supplied it must equal `-Version`, and the script refuses to
generate a manifest where the version and the tag disagree.

Winget strips leading non-digit characters when ordering versions, so `v0.5.1`
sorts as `0.5.1`.

## Preparing a manifest

Prepare the three-file manifest from the hashes of that exact release:

```powershell
.\scripts\prepare_winget_manifest.ps1 `
    -Version v0.5.1 `
    -X64Sha256 <64-hex-character-sha256> `
    -Arm64Sha256 <64-hex-character-sha256>
```

The command writes the manifest set under
`packaging/winget/manifests/q/Qinjingxue/SunPack/<version>/` and refuses to
overwrite an existing set unless `-Force` is supplied. It derives the stable
GitHub release URLs from the repository and tag, records `ReleaseDate` from the
tag's own commit date when the tag is available locally, and emits the required
Inno Setup silent-install switches:

```text
/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
```

The release assets are the only source of truth for the hashes. The GitHub
Releases API reports them without downloading, which matters because the release
CDN is not always reachable:

```powershell
$release = Invoke-RestMethod `
    -Uri "https://api.github.com/repos/Qinjingxue/Sunpack/releases/tags/v0.5.1" `
    -Headers @{ 'User-Agent' = 'sunpack' }
$release.assets | ForEach-Object {
    [pscustomobject]@{
        Name   = $_.name
        Sha256 = ($_.digest -replace '^sha256:', '')
    }
}
```

## Product code

`installer/SunPack.iss` pins a single Inno Setup `AppId` for both architectures,
which Inno writes to the uninstall registry key as
`<AppId>_is1` and to Add/Remove Programs as the product code:

```text
{9E8C73E5-C540-4E68-93E0-1FBAAFB89713}
```

The generated installer manifest declares that value both as the installer
`ProductCode` and inside each `AppsAndFeaturesEntries` entry, because winget
reads product codes from both places. The value must stay quoted in YAML: a bare
leading `{` parses as a flow mapping instead of a string.

## Validation

Before any upstream submission, run `winget validate --manifest` against the
generated manifest directory (WinGet validates the complete multi-file set):

```powershell
.\scripts\validate_winget_manifest.ps1 `
    -ManifestRoot .\packaging\winget\manifests\q\Qinjingxue\SunPack\v0.5.1
```

The repository validates the installer through real Inno Setup compilation and
static installer contract tests; it does not run a machine-state-dependent
install/upgrade/uninstall smoke test. Submit only one package version and only
the three manifest files to `microsoft/winget-pkgs`.
