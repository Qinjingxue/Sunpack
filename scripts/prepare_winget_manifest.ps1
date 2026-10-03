[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$X64Sha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$Arm64Sha256,

    [string]$ReleaseTag,

    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$ReleaseDate,

    [string]$Repository = "Qinjingxue/Sunpack",

    [string]$OutputRoot,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$packageIdentifier = "Qinjingxue.SunPack"
$manifestVersion = "1.12.0"
# Inno Setup AppId from installer/SunPack.iss. Inno escapes a literal leading
# brace by doubling it, so the registry uninstall key is "<AppId>_is1" and the
# Add/Remove Programs product code is this full uninstall key name. Both
# architectures share this AppId. The value must stay quoted in YAML because a
# leading brace otherwise parses as a flow mapping rather than a string.
$productCode = "'{9E8C73E5-C540-4E68-93E0-1FBAAFB89713}_is1'"

function Normalize-PackageVersion {
    param([Parameter(Mandatory = $true)][string]$Value)

    # The release tag is the authoritative version, and installers built from a
    # tag report it verbatim through Inno Setup's AppVersion. A leading "v" is
    # therefore part of the version and must survive into PackageVersion so it
    # matches the tag and the Add/Remove Programs DisplayVersion exactly.
    $normalized = $Value.Trim()
    $numericPart = $normalized
    if ($numericPart.StartsWith("v", [System.StringComparison]::OrdinalIgnoreCase)) {
        $numericPart = $numericPart.Substring(1)
    }
    if ($numericPart -notmatch '^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?$') {
        throw "Version must be a release version such as v0.8.0, 0.8.0, or 0.8.0-rc.1: $Value"
    }
    return $normalized
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    if ((Test-Path -LiteralPath $Path) -and -not $Force) {
        throw "Refusing to overwrite an existing manifest. Re-run with -Force: $Path"
    }
    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

$packageVersion = Normalize-PackageVersion -Value $Version
# PackageVersion and the release tag are one and the same value. The installers
# are built from the tag (build_windows.ps1 -Version <tag>) and report it
# through AppVersion, so an independent -ReleaseTag could silently desync the
# manifest from the release it points at.
$tag = if ([string]::IsNullOrWhiteSpace($ReleaseTag)) { $packageVersion } else { $ReleaseTag.Trim() }
if ($tag -notmatch '^[^/\\]+$') {
    throw "ReleaseTag must not contain path separators: $tag"
}
if ($tag -ne $packageVersion) {
    throw "ReleaseTag must match Version because the package version and the release tag are the same value: Version=$packageVersion ReleaseTag=$tag"
}
if ($Repository -notmatch '^[^/\\]+/[^/\\]+$') {
    throw "Repository must have the owner/name form: $Repository"
}

$normalizedOutputRoot = if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    Join-Path $repoRoot "packaging\winget\manifests"
} else {
    [System.IO.Path]::GetFullPath($OutputRoot)
}
$manifestRoot = Join-Path $normalizedOutputRoot "q\Qinjingxue\SunPack\$packageVersion"
New-Item -ItemType Directory -Path $manifestRoot -Force | Out-Null

$encodedTag = [System.Uri]::EscapeDataString($tag)
$releaseBaseUrl = "https://github.com/$Repository/releases/download/$encodedTag"
$x64InstallerUrl = "$releaseBaseUrl/sunpack-windows-x64-$tag-setup.exe"
$arm64InstallerUrl = "$releaseBaseUrl/sunpack-windows-arm64-$tag-setup.exe"
$x64Hash = $X64Sha256.ToUpperInvariant()
$arm64Hash = $Arm64Sha256.ToUpperInvariant()

# Supply the published release date, not the tag commit date. The field is
# optional and belongs to the installer manifest.
$releaseDateLine = ""
if ($ReleaseDate) {
    $parsedReleaseDate = [datetime]::ParseExact($ReleaseDate, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    $releaseDateLine = "ReleaseDate: $($parsedReleaseDate.ToString('yyyy-MM-dd'))"
}

$versionManifest = @"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.version.$manifestVersion.schema.json
PackageIdentifier: $packageIdentifier
PackageVersion: $packageVersion
DefaultLocale: en-US
ManifestType: version
ManifestVersion: $manifestVersion
"@

$installerManifest = @"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.installer.$manifestVersion.schema.json
PackageIdentifier: $packageIdentifier
PackageVersion: $packageVersion
MinimumOSVersion: 10.0.14393.0
InstallerType: inno
Scope: machine
ElevationRequirement: elevationRequired
UpgradeBehavior: install
$releaseDateLine
InstallerSwitches:
  Silent: /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
  SilentWithProgress: /SILENT /SUPPRESSMSGBOXES /NORESTART /SP-
Installers:
  - Architecture: x64
    InstallerUrl: $x64InstallerUrl
    InstallerSha256: $x64Hash
    ProductCode: $productCode
    AppsAndFeaturesEntries:
      - DisplayName: SunPack $tag (x64)
        Publisher: SunPack
        ProductCode: $productCode
  - Architecture: arm64
    InstallerUrl: $arm64InstallerUrl
    InstallerSha256: $arm64Hash
    ProductCode: $productCode
    AppsAndFeaturesEntries:
      - DisplayName: SunPack $tag (arm64)
        Publisher: SunPack
        ProductCode: $productCode
ManifestType: installer
ManifestVersion: $manifestVersion
"@

$localeManifest = @"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.defaultLocale.$manifestVersion.schema.json
PackageIdentifier: $packageIdentifier
PackageVersion: $packageVersion
PackageLocale: en-US
Publisher: SunPack
PublisherUrl: https://github.com/Qinjingxue/Sunpack
PublisherSupportUrl: https://github.com/Qinjingxue/Sunpack/issues
PackageName: SunPack
PackageUrl: https://github.com/Qinjingxue/Sunpack
License: MIT
LicenseUrl: https://github.com/Qinjingxue/Sunpack/blob/main/LICENSE
ShortDescription: Windows archive detection, extraction, and verification tool
Description: SunPack identifies and processes archives by binary features, including disguised extensions, nested archives, encrypted archives, split volumes, and embedded archives.
Tags:
  - archive
  - compression
  - extraction
  - 7zip
  - rar
  - zip
ManifestType: defaultLocale
ManifestVersion: $manifestVersion
"@

Write-Utf8NoBom -Path (Join-Path $manifestRoot "$packageIdentifier.yaml") -Content $versionManifest
Write-Utf8NoBom -Path (Join-Path $manifestRoot "$packageIdentifier.installer.yaml") -Content $installerManifest
Write-Utf8NoBom -Path (Join-Path $manifestRoot "$packageIdentifier.locale.en-US.yaml") -Content $localeManifest

Write-Host "Prepared WinGet manifest:" -ForegroundColor Green
Write-Host "  Package: $packageIdentifier $packageVersion"
Write-Host "  Release: $tag"
Write-Host "  Directory: $manifestRoot"
