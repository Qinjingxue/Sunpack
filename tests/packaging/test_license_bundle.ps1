# Run with PowerShell 5.1+; no third-party test framework needed.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$temp = Join-Path ([IO.Path]::GetTempPath()) ('sunpack-licenses-' + [Guid]::NewGuid())
$gui = Join-Path $temp 'gui'
$crate = Join-Path $temp 'crate'
New-Item -ItemType Directory $gui, (Join-Path $crate 'nested') -Force | Out-Null
function Check([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
try {
    foreach ($name in @('core-ui', 'nlohmann-json', 'quickjs', 'lunasvg', 'plutovg', 'freetype', 'stb', 'freetype-attribution')) {
        [IO.File]::WriteAllText((Join-Path $gui "$name.txt"), "Full terms: $name")
    }
    [IO.File]::WriteAllBytes((Join-Path $gui 'freetype.txt'), [byte[]](67,111,112,121,114,105,103,104,116,32,169))
    [IO.File]::WriteAllText((Join-Path $crate 'LICENSE'), 'SHARED FULL TERMS')
    [IO.File]::WriteAllText((Join-Path $crate 'nested/NOTICE'), 'SHARED FULL TERMS')
    [IO.File]::WriteAllText((Join-Path $crate 'nested/AUTHORS'), 'Nested attribution')
    [IO.File]::WriteAllText((Join-Path $crate 'custom-terms'), 'Custom license_file contents')
    $metadata = @{ workspace_members = @('local'); resolve = @{ nodes = @(
        @{id='local';dependencies=@('dep')}, @{id='dep';dependencies=@()}
    ) }; packages = @(
        @{id='local';source=$null},
        @{id='dep';name='example';version='1.2.3';source='registry+example';license='MIT';license_file='custom-terms';manifest_path=(Join-Path $crate 'Cargo.toml')},
        @{id='unreachable';name='unused';version='9';source='registry+example'}
    ) }
    $metaPath = Join-Path $temp 'metadata.json'
    $metadata | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $metaPath -Encoding UTF8
    $output = Join-Path $temp 'THIRD_PARTY_LICENSES.txt'
    $arguments = @{ RepoRoot=$repo; GuiLicenseRoot=$gui; OutputPath=$output; Target='x86_64-pc-windows-msvc'; MetadataPath=$metaPath }
    $script = Join-Path $repo 'scripts/generate_license_bundle.ps1'
    & $script @arguments
    Check (([IO.File]::ReadAllText($output)).Contains('the source tree used to build this installer')) 'Local builds must identify their corresponding source'
    $arguments.CorrespondingSourceUrl = 'https://github.com/Qinjingxue/Sunpack/archive/0123456789012345678901234567890123456789.tar.gz'
    & $script @arguments
    $first = [IO.File]::ReadAllText($output)
    $summary = ($first -split '\nCONTENTS\n', 2)[0]
    Check ($summary.Contains('sunpack_sevenzip_worker.exe') -and $summary.Contains('sunpack-runtime.exe') -and
        $summary.Contains('GNU LGPL 2.1 or later') -and $summary.Contains($arguments.CorrespondingSourceUrl)) 'Both executables and the corresponding source must be prominent'
    & $script @arguments
    Check ($first -ceq [IO.File]::ReadAllText($output)) 'Generation must be deterministic'
    Check (([regex]::Matches($first, 'SHARED FULL TERMS')).Count -eq 1) 'Duplicate terms must occur once'
    Check ($first.Contains('file: LICENSE') -and $first.Contains('file: nested/NOTICE')) 'Dedup must preserve both sources'
    Check ($first.Contains('Nested attribution') -and $first.Contains('Custom license_file contents')) 'Nested and explicitly named material must survive'
    Check ($first.Contains(('Copyright ' + [char]169))) 'Latin-1 notice must not be corrupted'
    Check (-not $first.Contains('unreachable') -and -not $first.Contains($temp)) 'Do not include unreachable packages or build-machine paths'
    foreach ($path in @((Join-Path $repo 'LICENSE')) + @(Get-ChildItem (Join-Path $repo 'licenses') -File | ForEach-Object FullName)) {
        $original = [IO.File]::ReadAllText($path).Replace("`r`n", "`n").TrimEnd()
        Check ($first.Contains($original)) "Original terms missing: $path"
    }
    Remove-Item (Join-Path $gui 'stb.txt')
    $failed = $false
    try { & $script @arguments } catch { $failed = $true }
    Check $failed 'Missing required license must fail'
    Check ($first -ceq [IO.File]::ReadAllText($output)) 'Failed generation must not replace prior output'
    Write-Host 'License bundle tests passed.'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
