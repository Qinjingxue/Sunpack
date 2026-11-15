[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$GuiLicenseRoot,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][string]$Target,
    # Allows offline verification against the same cargo metadata schema.
    [string]$MetadataPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-LicenseText([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing license material: $Path" }
    $bytes = [IO.File]::ReadAllBytes($Path)
    try { $text = ([Text.UTF8Encoding]::new($false, $true)).GetString($bytes) }
    catch [Text.DecoderFallbackException] {
        # Upstream FreeType FTL.TXT uses Latin-1, including its copyright sign.
        $text = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
    }
    $text = $text.TrimStart([char]0xfeff).Replace("`r`n", "`n").Replace("`r", "`n").TrimEnd()
    if (-not $text) { throw "Empty license material: $Path" }
    return $text
}
$sections = [Collections.Generic.List[object]]::new()
$byText = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
function Add-License([string]$Label, [string]$Path) {
    $text = Read-LicenseText $Path
    if ($byText.ContainsKey($text)) { $byText[$text].Labels.Add($Label); return }
    $entry = [pscustomobject]@{ Text = $text; Labels = [Collections.Generic.List[string]]::new() }
    $entry.Labels.Add($Label)
    $sections.Add($entry)
    $byText.Add($text, $entry)
}
Add-License 'SunPack - repository LICENSE (MIT)' (Join-Path $RepoRoot 'LICENSE')
Add-License 'SunPack third-party component overview (source paths below refer to the source repository)' (Join-Path $RepoRoot 'THIRD_PARTY_NOTICES.md')
foreach ($name in @('7zip-license.txt', '7zip-source-license.txt', 'LGPL-2.1.txt', 'zlib-ng-license.txt', 'lz4-license.txt', 'twofish-license.txt', 'serpent-license.txt', 'threefish-license.txt', 'magma-license.txt', 'blowfish-license.txt', 'rc6-license.txt')) {
    if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot "licenses/$name") -PathType Leaf)) { throw "Missing required repository license: $name" }
}
foreach ($file in (Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'licenses') -File | Sort-Object Name)) {
    Add-License "SunPack source repository: licenses/$($file.Name)" $file.FullName
}
foreach ($name in @('core-ui.txt', 'nlohmann-json.txt', 'quickjs.txt', 'lunasvg.txt', 'plutovg.txt', 'freetype.txt', 'stb.txt', 'freetype-attribution.txt')) {
    if (-not (Test-Path -LiteralPath (Join-Path $GuiLicenseRoot $name) -PathType Leaf)) { throw "Missing required GUI license: $name" }
}
foreach ($file in (Get-ChildItem -LiteralPath $GuiLicenseRoot -File | Sort-Object Name)) {
    Add-License "GUI dependency: $($file.Name)" $file.FullName
}
if ($MetadataPath) { $metadata = Get-Content -LiteralPath $MetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json }
else {
    $json = & cargo metadata --locked --format-version 1 --filter-platform $Target --manifest-path (Join-Path $RepoRoot 'sunpack/Cargo.toml')
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed; license bundle was not generated' }
    $metadata = ($json -join "`n") | ConvertFrom-Json
}
$nodes = @{}
foreach ($node in $metadata.resolve.nodes) { $nodes[$node.id] = $node }
$included = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$pending = [Collections.Generic.Stack[string]]::new()
foreach ($id in $metadata.workspace_members) { $pending.Push($id) }
while ($pending.Count -gt 0) {
    $id = $pending.Pop()
    if (-not $included.Add($id)) { continue }
    if (-not $nodes.ContainsKey($id)) { throw "Missing resolved Cargo package: $id" }
    foreach ($dep in $nodes[$id].dependencies) { $pending.Push($dep) }
}
foreach ($package in ($metadata.packages | Where-Object { $included.Contains($_.id) -and $_.source } | Sort-Object name, version)) {
    $root = Split-Path -Parent $package.manifest_path
    $files = @(Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Name -match '^(licen[cs]e|copying|copyright|notice|unlicense|authors)($|[._-])' -or $_.Name -eq 'FTL.TXT' })
    if ($package.license_file) {
        $files += Get-Item -LiteralPath (Join-Path $root $package.license_file) -ErrorAction Stop
    }
    $files = @($files | Sort-Object FullName -Unique)
    if ($files.Count -eq 0) { throw "No license text found for Cargo package $($package.name) $($package.version)" }
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($root.Length).TrimStart([char[]]'\/').Replace('\', '/')
        Add-License "Cargo $($package.name) $($package.version); declared license: $($package.license); source: $($package.source); file: $relative" $file.FullName
    }
}
$builder = [Text.StringBuilder]::new()
[void]$builder.AppendLine('SUNPACK - LICENSES AND THIRD-PARTY NOTICES')
[void]$builder.AppendLine("Target: $Target")
[void]$builder.AppendLine('Source: https://github.com/Qinjingxue/Sunpack')
[void]$builder.AppendLine('This document consolidates original terms; it does not relicense third-party code.')
[void]$builder.AppendLine('Cargo entries include the resolved workspace dependency closure, including build/test tools; inclusion does not assert that every component is linked into the installed binaries. Package-internal terms apply only to the files specified by their original notices.')
[void]$builder.AppendLine('Source-file paths in the overview identify repository originals, reproduced below. Source license files are retained in the repository.')
[void]$builder.AppendLine('LGPL corresponding-source and modification/relinking obligations remain separate release requirements. This notice bundle alone does not satisfy them; see docs/licensing.md in the source repository.')
[void]$builder.AppendLine("`nCONTENTS")
for ($i = 0; $i -lt $sections.Count; $i++) {
    foreach ($label in $sections[$i].Labels) { [void]$builder.AppendLine("[$($i + 1)] $label") }
}
for ($i = 0; $i -lt $sections.Count; $i++) {
    [void]$builder.AppendLine("`n======================================================================")
    foreach ($label in $sections[$i].Labels) { [void]$builder.AppendLine("[$($i + 1)] $label") }
    [void]$builder.AppendLine("======================================================================`n")
    [void]$builder.AppendLine($sections[$i].Text)
}
# Write only once all required material has been validated; UTF-8 works in Notepad.
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), $builder.ToString().Replace("`r`n", "`n"), [Text.UTF8Encoding]::new($true))
